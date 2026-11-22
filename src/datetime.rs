use std::fmt;

use async_graphql::{InputValueError, InputValueResult, Scalar, ScalarType, Value};
use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A UTC datetime backed by [`jiff::Timestamp`].
///
/// The GraphQL scalar, serde and `Display` all print the same RFC 3339
/// form, [`DateTime::to_rfc3339`].
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

    /// Formats the timestamp as RFC 3339 using [`jiff::Timestamp`]'s
    /// `Display`:
    ///
    /// * Always uses the `Z` offset.
    /// * No fractional seconds when subsecond nanoseconds are zero;
    ///   otherwise the shortest fraction that keeps the value (`.12`, not
    ///   `.120`).
    /// * Years outside `0..=9999` use the signed six-digit extended form
    ///   (`-000001`).
    pub fn to_rfc3339(self) -> String {
        self.0.to_string()
    }

    /// Formats as `{unix_seconds}.{nanoseconds:09}`, with the seconds
    /// floored and the nanoseconds always nine digits.
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
mod tests {
    use super::*;

    #[test]
    fn rfc3339_no_fractional() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_000_000_000);
        let s = dt.to_rfc3339();
        assert_eq!(s, "2024-03-04T05:06:07Z");
    }

    #[test]
    fn rfc3339_millis() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_001_000_000);
        let s = dt.to_rfc3339();
        assert_eq!(s, "2024-03-04T05:06:07.001Z");
    }

    #[test]
    fn rfc3339_trims_trailing_zeros_of_fraction() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_120_000_000);
        assert_eq!(dt.to_rfc3339(), "2024-03-04T05:06:07.12Z");
    }

    #[test]
    fn rfc3339_micros() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_000_001_000);
        let s = dt.to_rfc3339();
        assert_eq!(s, "2024-03-04T05:06:07.000001Z");
    }

    #[test]
    fn rfc3339_nanos() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_000_000_001);
        let s = dt.to_rfc3339();
        assert_eq!(s, "2024-03-04T05:06:07.000000001Z");
    }

    #[test]
    fn timestamp_nanos_roundtrip_preserves_value() {
        let nanos = 1_709_528_767_123_456_789_i64;
        let dt = DateTime::from_timestamp_nanos(nanos);
        assert_eq!(dt.timestamp_nanos_opt(), Some(nanos));
    }

    #[test]
    fn min_max_utc_match_i64_nanosecond_bounds() {
        let min = DateTime::min_utc();
        let max = DateTime::max_utc();
        assert!(min < max);
        assert_eq!(min.timestamp_nanos_opt(), Some(i64::MIN));
        assert_eq!(max.timestamp_nanos_opt(), Some(i64::MAX));
    }

    #[test]
    fn format_unix_seconds_with_nanos_for_positive_timestamp() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_000_000_000);
        assert_eq!(dt.format_unix_seconds_with_nanos(), "1709528767.000000000");
    }

    #[test]
    fn timestamp_parse_with_z_formats_as_utc_rfc3339() {
        let ts: Timestamp = "2024-03-04T05:06:07Z".parse().unwrap();
        let dt = DateTime::from(ts);
        assert_eq!(dt.to_rfc3339(), "2024-03-04T05:06:07Z");
    }

    #[test]
    fn timestamp_parse_with_utc_offset_formats_as_utc_rfc3339() {
        let ts: Timestamp = "2024-03-04T05:06:07+00:00".parse().unwrap();
        let dt = DateTime::from(ts);
        assert_eq!(dt.to_rfc3339(), "2024-03-04T05:06:07Z");
    }

    #[test]
    fn serde_roundtrip() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_123_000_000);
        let json = serde_json::to_string(&dt).unwrap();
        assert_eq!(json, "\"2024-03-04T05:06:07.123Z\"");
        let parsed: DateTime = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, dt);
    }

    #[test]
    fn rfc3339_negative_nanos() {
        let dt = DateTime::from_timestamp_nanos(-1);
        assert_eq!(dt.to_rfc3339(), "1969-12-31T23:59:59.999999999Z");
    }

    #[test]
    fn format_unix_seconds_with_nanos_for_negative_timestamp() {
        let dt = DateTime::from_timestamp_nanos(-1);
        assert_eq!(dt.format_unix_seconds_with_nanos(), "-1.999999999");
    }

    #[test]
    fn timestamp_parse_with_non_utc_offset_normalizes_to_utc_rfc3339() {
        let ts: Timestamp = "2024-03-04T14:06:07+09:00".parse().unwrap();
        let dt = DateTime::from(ts);
        assert_eq!(dt.to_rfc3339(), "2024-03-04T05:06:07Z");
    }

    #[test]
    fn rfc3339_negative_year() {
        let ts = jiff::civil::date(-1, 1, 1)
            .at(0, 0, 0, 0)
            .to_zoned_datetime(jiff::tz::TimeZone::UTC)
            .unwrap()
            .timestamp();
        let dt = DateTime::from(ts);
        assert_eq!(dt.to_rfc3339(), "-000001-01-01T00:00:00Z");
    }

    #[test]
    fn graphql_to_value_matches_serde_serialization() {
        let dt = DateTime::from_timestamp_nanos(1_709_528_767_123_000_000);
        let graphql_value = <DateTime as ScalarType>::to_value(&dt);
        let serde_json = serde_json::to_string(&dt).unwrap();

        assert_eq!(
            graphql_value,
            Value::String("2024-03-04T05:06:07.123Z".to_string())
        );
        assert_eq!(serde_json, "\"2024-03-04T05:06:07.123Z\"");
    }

    #[test]
    fn graphql_to_value_serde_and_display_agree() {
        for nanos in [
            0,
            -1,
            1_709_528_767_000_000_000,
            1_709_528_767_120_000_000,
            1_709_528_767_123_456_789,
            i64::MIN,
            i64::MAX,
        ] {
            let dt = DateTime::from_timestamp_nanos(nanos);
            let display = dt.to_string();
            assert_eq!(
                <DateTime as ScalarType>::to_value(&dt),
                Value::String(display.clone())
            );
            assert_eq!(
                serde_json::to_string(&dt).unwrap(),
                format!("\"{display}\"")
            );
            assert_eq!(display, dt.to_rfc3339());
        }
    }

    #[test]
    fn rfc3339_i64_bounds_roundtrip() {
        for dt in [DateTime::min_utc(), DateTime::max_utc()] {
            let s = dt.to_rfc3339();
            assert!(s.ends_with('Z'), "{s}");
            let parsed: DateTime = serde_json::from_str(&format!("\"{s}\"")).unwrap();
            assert_eq!(parsed, dt);
            let parsed = <DateTime as ScalarType>::parse(Value::String(s)).unwrap();
            assert_eq!(parsed, dt);
        }
    }

    #[test]
    fn graphql_and_serde_parse_offsets_to_same_instant() {
        let expected = DateTime::from_timestamp_nanos(1_709_528_767_000_000_000);
        for input in [
            "2024-03-04T05:06:07Z",
            "2024-03-04T05:06:07+00:00",
            "2024-03-04T14:06:07+09:00",
        ] {
            let graphql =
                <DateTime as ScalarType>::parse(Value::String(input.to_string())).unwrap();
            assert_eq!(graphql, expected, "{input}");
            let serde: DateTime = serde_json::from_str(&format!("\"{input}\"")).unwrap();
            assert_eq!(serde, expected, "{input}");
        }
    }

    #[test]
    fn graphql_parse_string_value_succeeds() {
        let parsed =
            <DateTime as ScalarType>::parse(Value::String("2024-03-04T14:06:07+09:00".to_string()))
                .unwrap();

        assert_eq!(parsed.to_rfc3339(), "2024-03-04T05:06:07Z");
    }

    #[test]
    fn graphql_parse_non_string_value_fails() {
        let result = <DateTime as ScalarType>::parse(Value::from(123));

        let err = result.unwrap_err();
        let message = err.into_server_error(async_graphql::Pos::default()).message;
        assert_eq!(message, r#"Expected input type "DateTime", found 123."#);
    }

    #[test]
    fn graphql_parse_invalid_string_value_fails() {
        let result = <DateTime as ScalarType>::parse(Value::String("not-a-datetime".to_string()));

        let err = result.unwrap_err();
        let message = err.into_server_error(async_graphql::Pos::default()).message;
        assert_eq!(
            message,
            r#"Failed to parse "DateTime": invalid DateTime: not-a-datetime"#
        );
    }

    #[test]
    fn serde_deserialize_zulu_string_succeeds() {
        let parsed: DateTime = serde_json::from_str("\"2024-03-04T05:06:07Z\"").unwrap();

        assert_eq!(parsed.to_rfc3339(), "2024-03-04T05:06:07Z");
    }

    #[test]
    fn serde_deserialize_invalid_rfc3339_fails() {
        let result = serde_json::from_str::<DateTime>("\"not-a-datetime\"");

        let err = result.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("failed to parse four digit integer as year"));
    }

    #[test]
    fn serde_deserialize_non_string_json_fails() {
        let result = serde_json::from_str::<DateTime>("123");

        let err = result.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("invalid type"));
        assert!(message.contains("integer `123`"));
        assert!(message.contains("expected a string"));
    }
}
