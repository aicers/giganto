use std::fmt;

use async_graphql::{InputValueError, InputValueResult, Scalar, ScalarType, Value};
use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A UTC datetime backed by [`jiff::Timestamp`].
///
/// Replaces `chrono::DateTime<Utc>` and provides the same RFC 3339
/// serialization format for both the GraphQL scalar and serde.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DateTime(Timestamp);

impl Default for DateTime {
    fn default() -> Self {
        Self(Timestamp::UNIX_EPOCH)
    }
}

#[Scalar]
impl ScalarType for DateTime {
    fn parse(value: Value) -> InputValueResult<Self> {
        if let Value::String(s) = &value {
            s.parse::<Timestamp>()
                .map(Self)
                .map_err(|_| InputValueError::custom(format!("invalid DateTime: {s}")))
        } else {
            Err(InputValueError::expected_type(value))
        }
    }

    fn to_value(&self) -> Value {
        Value::String(self.to_rfc3339())
    }
}

impl Serialize for DateTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for DateTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse::<Timestamp>()
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl DateTime {
    /// Returns the current UTC time.
    #[inline]
    pub fn now() -> Self {
        Self(Timestamp::now())
    }

    /// Creates a `DateTime` from nanoseconds since the Unix epoch.
    #[inline]
    pub fn from_timestamp_nanos(nanos: i64) -> Self {
        Self(
            Timestamp::from_nanosecond(i128::from(nanos))
                .expect("i64 nanoseconds should be within valid range"),
        )
    }

    /// Returns the nanoseconds since the Unix epoch, or `None` if the value
    /// overflows `i64`.
    #[inline]
    pub fn timestamp_nanos_opt(&self) -> Option<i64> {
        i64::try_from(self.0.as_nanosecond()).ok()
    }

    /// Minimum `DateTime` representable with `i64` nanoseconds.
    pub fn min_utc() -> Self {
        Self::from_timestamp_nanos(i64::MIN)
    }

    /// Maximum `DateTime` representable with `i64` nanoseconds.
    pub fn max_utc() -> Self {
        Self::from_timestamp_nanos(i64::MAX)
    }

    /// Formats the timestamp as RFC 3339, matching chrono's
    /// `DateTime<Utc>::to_rfc3339()` formatting behavior:
    ///
    /// * No fractional seconds when subsecond nanoseconds are zero.
    /// * 3 digits (millis) when subsecond nanoseconds are a multiple of
    ///   1,000,000.
    /// * 6 digits (micros) when subsecond nanoseconds are a multiple of 1,000.
    /// * 9 digits (nanos) otherwise.
    /// * Uses chrono-compatible year formatting, including negative years.
    /// * Always uses `+00:00` offset (not `Z`).
    pub fn to_rfc3339(self) -> String {
        let dt = self.0.to_zoned(jiff::tz::TimeZone::UTC).datetime();
        let (y, mo, d) = (dt.year(), dt.month(), dt.day());
        let (h, mi, s) = (dt.hour(), dt.minute(), dt.second());
        let nanos = dt.subsec_nanosecond();

        let year = if (0..=9999).contains(&y) {
            format!("{y:04}")
        } else {
            format!("{y:+05}")
        };

        let fraction = if nanos == 0 {
            String::new()
        } else if nanos % 1_000_000 == 0 {
            format!(".{:03}", nanos / 1_000_000)
        } else if nanos % 1_000 == 0 {
            format!(".{:06}", nanos / 1_000)
        } else {
            format!(".{nanos:09}")
        };

        format!("{year}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{fraction}+00:00")
    }

    /// Formats as `{unix_seconds}.{nanoseconds:09}`, matching chrono's
    /// `format("%s%.9f")`.
    pub fn format_unix_seconds_with_nanos(self) -> String {
        let nanos = self.0.as_nanosecond();
        let secs = nanos.div_euclid(1_000_000_000);
        let subsec = nanos.rem_euclid(1_000_000_000);
        format!("{secs}.{subsec:09}")
    }
}

impl From<Timestamp> for DateTime {
    fn from(ts: Timestamp) -> Self {
        Self(ts)
    }
}

impl From<DateTime> for Timestamp {
    fn from(dt: DateTime) -> Self {
        dt.0
    }
}

#[cfg(test)]
impl DateTime {
    /// Creates a `DateTime` from year, month, day, hour, minute, second in UTC.
    pub fn from_ymd_hms(year: i16, month: i8, day: i8, hour: i8, minute: i8, second: i8) -> Self {
        Self(
            jiff::civil::date(year, month, day)
                .at(hour, minute, second, 0)
                .to_zoned(jiff::tz::TimeZone::UTC)
                .expect("valid UTC datetime")
                .timestamp(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_no_fractional() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_000_000_000);
        let s = dt.to_rfc3339();
        assert_eq!(s, "2024-03-04T05:06:07+00:00");
    }

    #[test]
    fn rfc3339_millis() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_001_000_000);
        let s = dt.to_rfc3339();
        assert_eq!(s, "2024-03-04T05:06:07.001+00:00");
    }

    #[test]
    fn rfc3339_micros() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_000_001_000);
        let s = dt.to_rfc3339();
        assert_eq!(s, "2024-03-04T05:06:07.000001+00:00");
    }

    #[test]
    fn rfc3339_nanos() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_000_000_001);
        let s = dt.to_rfc3339();
        assert_eq!(s, "2024-03-04T05:06:07.000000001+00:00");
    }

    #[test]
    fn roundtrip_nanos() {
        let nanos = 1_709_528_767_123_456_789_i64;
        let dt = DateTime::from_timestamp_nanos(nanos);
        assert_eq!(dt.timestamp_nanos_opt(), Some(nanos));
    }

    #[test]
    fn min_max() {
        let min = DateTime::min_utc();
        let max = DateTime::max_utc();
        assert!(min < max);
        assert_eq!(min.timestamp_nanos_opt(), Some(i64::MIN));
        assert_eq!(max.timestamp_nanos_opt(), Some(i64::MAX));
    }

    #[test]
    fn format_epoch_nanos_output() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_000_000_000);
        assert_eq!(dt.format_unix_seconds_with_nanos(), "1709528767.000000000");
    }

    #[test]
    fn parse_rfc3339_with_z() {
        let ts: Timestamp = "2024-03-04T05:06:07Z".parse().unwrap();
        let dt = DateTime::from(ts);
        assert_eq!(dt.to_rfc3339(), "2024-03-04T05:06:07+00:00");
    }

    #[test]
    fn parse_rfc3339_with_offset() {
        let ts: Timestamp = "2024-03-04T05:06:07+00:00".parse().unwrap();
        let dt = DateTime::from(ts);
        assert_eq!(dt.to_rfc3339(), "2024-03-04T05:06:07+00:00");
    }

    #[test]
    fn serde_roundtrip() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_123_000_000);
        let json = serde_json::to_string(&dt).unwrap();
        assert_eq!(json, "\"2024-03-04T05:06:07.123+00:00\"");
        let parsed: DateTime = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, dt);
    }

    #[test]
    fn rfc3339_negative_nanos() {
        let dt = DateTime::from_timestamp_nanos(-1);
        assert_eq!(dt.to_rfc3339(), "1969-12-31T23:59:59.999999999+00:00");
    }

    #[test]
    fn format_epoch_nanos_negative_nanos() {
        let dt = DateTime::from_timestamp_nanos(-1);
        assert_eq!(dt.format_unix_seconds_with_nanos(), "-1.999999999");
    }

    #[test]
    fn parse_rfc3339_with_non_utc_offset() {
        let ts: Timestamp = "2024-03-04T14:06:07+09:00".parse().unwrap();
        let dt = DateTime::from(ts);
        assert_eq!(dt.to_rfc3339(), "2024-03-04T05:06:07+00:00");
    }

    #[test]
    fn rfc3339_negative_year() {
        let ts = jiff::civil::date(-1, 1, 1)
            .at(0, 0, 0, 0)
            .to_zoned(jiff::tz::TimeZone::UTC)
            .unwrap()
            .timestamp();
        let dt = DateTime::from(ts);
        assert_eq!(dt.to_rfc3339(), "-0001-01-01T00:00:00+00:00");
    }
}
