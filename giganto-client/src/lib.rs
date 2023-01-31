pub mod connection;
pub mod frame;
pub mod ingest;
pub mod publish;
#[cfg(test)]
mod test;

use chrono::NaiveDateTime;

/// Convert the value of timestamp nanosecond(i64) to zeek's timestamp format.
#[must_use]
pub fn convert_time_format(timestamp: i64) -> String {
    const A_BILLION: i64 = 1_000_000_000;
    let nsecs = u32::try_from(timestamp % A_BILLION).unwrap_or_default();
    NaiveDateTime::from_timestamp_opt(timestamp / A_BILLION, nsecs)
        .map_or("-".to_string(), |s| s.format("%s%.6f").to_string())
}
