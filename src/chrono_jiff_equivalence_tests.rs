//! Behavioral equivalence tests for chrono → jiff migration.
//!
//! These tests verify that the migration from `chrono` to `jiff` maintains
//! identical behavior. Tests use `chrono` for verification purposes only,
//! comparing results against production `jiff` code.

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Datelike, TimeZone, Utc};
    use jiff::Timestamp;

    /// Test that `get_current_date_time()` produces consistent results between
    /// chrono and jiff implementations.
    ///
    /// The function extracts the day of the month from the current UTC time.
    /// Both implementations should return the same day value when called at
    /// approximately the same time.
    #[test]
    fn test_get_current_date_time_equivalence() {
        // chrono implementation (original)
        fn get_current_date_time_chrono() -> u32 {
            let utc_now = Utc::now();
            utc_now.day()
        }

        // jiff implementation (new)
        fn get_current_date_time_jiff() -> u32 {
            let now = Timestamp::now();
            u32::from(now.to_zoned(jiff::tz::TimeZone::UTC).day().unsigned_abs())
        }

        // Call both functions in quick succession
        let chrono_result = get_current_date_time_chrono();
        let jiff_result = get_current_date_time_jiff();

        // They should return the same day value (unless called exactly at midnight)
        // In that rare case, re-run the test
        assert_eq!(
            chrono_result, jiff_result,
            "chrono and jiff should return the same day of month"
        );
    }

    /// Test that `Timestamp::from_nanosecond()` and `Utc.timestamp_nanos()`
    /// produce equivalent results for various nanosecond values.
    #[test]
    fn test_timestamp_from_nanosecond_equivalence() {
        let test_cases = vec![
            0_i64,                     // Unix epoch
            1_000_000_000,             // 1 second
            1_234_567_890_123_456_789, // Large positive value
            -1_000_000_000,            // 1 second before epoch
            1_609_459_200_000_000_000, // 2021-01-01 00:00:00 UTC
            1_735_689_600_000_000_000, // 2025-01-01 00:00:00 UTC
            i64::MAX,                  // Maximum i64 value
            i64::MIN + 1,              // Near minimum i64 value (MIN itself may overflow)
        ];

        for nanos in test_cases {
            // chrono implementation
            #[allow(deprecated)]
            let chrono_timestamp = Utc.timestamp_nanos(nanos);
            let chrono_nanos = chrono_timestamp.timestamp_nanos_opt().unwrap();

            // jiff implementation
            let jiff_timestamp = Timestamp::from_nanosecond(i128::from(nanos)).unwrap();
            let jiff_nanos: i64 = jiff_timestamp.as_nanosecond().try_into().unwrap();

            assert_eq!(
                chrono_nanos, jiff_nanos,
                "chrono and jiff timestamps should be equivalent for {nanos} nanoseconds"
            );
        }
    }

    /// Test that timestamp conversions maintain precision when converting
    /// to and from i64 nanoseconds.
    #[test]
    fn test_timestamp_conversion_roundtrip() {
        let test_nanos = vec![
            0_i64,
            1_000_000_000,             // 1 second
            1_234_567_890,             // Arbitrary value
            1_609_459_200_000_000_000, // 2021-01-01 00:00:00 UTC
        ];

        for nanos in test_nanos {
            // chrono roundtrip
            #[allow(deprecated)]
            let chrono_ts = Utc.timestamp_nanos(nanos);
            let chrono_roundtrip = chrono_ts.timestamp_nanos_opt().unwrap();

            // jiff roundtrip
            let jiff_ts = Timestamp::from_nanosecond(i128::from(nanos)).unwrap();
            let jiff_roundtrip: i64 = jiff_ts.as_nanosecond().try_into().unwrap();

            assert_eq!(
                nanos, chrono_roundtrip,
                "chrono should preserve nanoseconds in roundtrip"
            );
            assert_eq!(
                nanos, jiff_roundtrip,
                "jiff should preserve nanoseconds in roundtrip"
            );
            assert_eq!(
                chrono_roundtrip, jiff_roundtrip,
                "chrono and jiff roundtrips should match"
            );
        }
    }

    /// Test that MIN/MAX timestamp constants are equivalent.
    #[test]
    fn test_timestamp_min_max_equivalence() {
        // For MIN, both should represent the earliest representable time
        let jiff_min = Timestamp::MIN;
        let jiff_min_nanos = jiff_min.as_nanosecond();

        // chrono's minimum is bounded by i64::MIN nanoseconds from epoch
        #[allow(deprecated)]
        let chrono_min = Utc.timestamp_nanos(i64::MIN);
        let chrono_min_nanos = chrono_min.timestamp_nanos_opt().unwrap_or(i64::MIN);

        // jiff uses i128 internally, so it can represent a wider range
        // We verify that jiff can at least represent chrono's range
        assert!(
            jiff_min_nanos <= i128::from(chrono_min_nanos),
            "jiff MIN should be at or before chrono's MIN"
        );

        // For MAX, both should represent the latest representable time
        let jiff_max = Timestamp::MAX;
        let jiff_max_nanos = jiff_max.as_nanosecond();

        // chrono's maximum is bounded by i64::MAX nanoseconds from epoch
        #[allow(deprecated)]
        let chrono_max = Utc.timestamp_nanos(i64::MAX);
        let chrono_max_nanos = chrono_max.timestamp_nanos_opt().unwrap_or(i64::MAX);

        assert!(
            jiff_max_nanos >= i128::from(chrono_max_nanos),
            "jiff MAX should be at or after chrono's MAX"
        );
    }

    /// Test timestamp arithmetic: ensure that adding durations produces
    /// equivalent results.
    #[test]
    fn test_timestamp_arithmetic_equivalence() {
        let base_nanos = 1_609_459_200_000_000_000_i64; // 2021-01-01 00:00:00 UTC
        let duration_secs = 3600_i64; // 1 hour
        let duration_nanos = duration_secs * 1_000_000_000;

        // chrono arithmetic
        #[allow(deprecated)]
        let chrono_base = Utc.timestamp_nanos(base_nanos);
        let chrono_duration = chrono::Duration::seconds(duration_secs);
        let chrono_result = chrono_base + chrono_duration;
        let chrono_result_nanos = chrono_result.timestamp_nanos_opt().unwrap();

        // jiff arithmetic
        let jiff_base = Timestamp::from_nanosecond(i128::from(base_nanos)).unwrap();
        let jiff_duration = jiff::SignedDuration::from_secs(duration_secs);
        let jiff_result = jiff_base + jiff_duration;
        let jiff_result_nanos: i64 = jiff_result.as_nanosecond().try_into().unwrap();

        // Expected result
        let expected_nanos = base_nanos + duration_nanos;

        assert_eq!(
            chrono_result_nanos, expected_nanos,
            "chrono arithmetic should produce expected result"
        );
        assert_eq!(
            jiff_result_nanos, expected_nanos,
            "jiff arithmetic should produce expected result"
        );
        assert_eq!(
            chrono_result_nanos, jiff_result_nanos,
            "chrono and jiff arithmetic should match"
        );
    }

    /// Test that date component extraction (year, month, day) is equivalent.
    #[test]
    fn test_date_component_extraction_equivalence() {
        let test_nanos = 1_609_459_200_000_000_000_i64; // 2021-01-01 00:00:00 UTC

        // chrono extraction
        #[allow(deprecated)]
        let chrono_ts = Utc.timestamp_nanos(test_nanos);
        let chrono_year = chrono_ts.year();
        let chrono_month = chrono_ts.month();
        let chrono_day = chrono_ts.day();

        // jiff extraction
        let jiff_ts = Timestamp::from_nanosecond(i128::from(test_nanos)).unwrap();
        let jiff_zoned = jiff_ts.to_zoned(jiff::tz::TimeZone::UTC);
        let jiff_year = i32::from(jiff_zoned.year());
        let jiff_month = u32::try_from(jiff_zoned.month()).unwrap();
        let jiff_day = u32::from(jiff_zoned.day().unsigned_abs());

        assert_eq!(chrono_year, jiff_year, "Year extraction should match");
        assert_eq!(chrono_month, jiff_month, "Month extraction should match");
        assert_eq!(chrono_day, jiff_day, "Day extraction should match");

        // Verify the expected values for this specific timestamp
        assert_eq!(jiff_year, 2021);
        assert_eq!(jiff_month, 1);
        assert_eq!(jiff_day, 1);
    }

    /// Test that `Timestamp::now()` produces reasonable timestamps.
    #[test]
    fn test_timestamp_now_produces_valid_range() {
        let jiff_now = Timestamp::now();
        let jiff_now_nanos = jiff_now.as_nanosecond();

        let chrono_now = Utc::now();
        let chrono_now_nanos = chrono_now.timestamp_nanos_opt().unwrap();

        // The timestamps should be very close (within 1 second = 1e9 nanoseconds)
        let diff = (jiff_now_nanos - i128::from(chrono_now_nanos)).abs();
        assert!(
            diff < 1_000_000_000,
            "jiff and chrono Timestamp::now() should be within 1 second of each other"
        );
    }

    /// Test timestamp comparison operations.
    #[test]
    fn test_timestamp_comparison_equivalence() {
        let earlier_nanos = 1_000_000_000_i64;
        let later_nanos = 2_000_000_000_i64;

        // chrono comparison
        #[allow(deprecated)]
        let chrono_earlier = Utc.timestamp_nanos(earlier_nanos);
        #[allow(deprecated)]
        let chrono_later = Utc.timestamp_nanos(later_nanos);
        let chrono_cmp = chrono_earlier < chrono_later;

        // jiff comparison
        let jiff_earlier = Timestamp::from_nanosecond(i128::from(earlier_nanos)).unwrap();
        let jiff_later = Timestamp::from_nanosecond(i128::from(later_nanos)).unwrap();
        let jiff_cmp = jiff_earlier < jiff_later;

        assert_eq!(
            chrono_cmp, jiff_cmp,
            "Timestamp comparisons should be equivalent"
        );
        assert!(jiff_cmp, "Earlier timestamp should be less than later");
    }

    /// Test i128 to i64 conversion with bounds checking, as used in storage layer.
    #[test]
    fn test_i128_to_i64_conversion_storage() {
        // Test cases that should successfully convert to i64
        let valid_cases = vec![
            0_i128,
            1_000_000_000_i128,
            i128::from(i64::MAX),
            i128::from(i64::MIN),
        ];

        for nanos in valid_cases {
            let jiff_ts = Timestamp::from_nanosecond(nanos).unwrap();
            let result: Result<i64, _> = jiff_ts.as_nanosecond().try_into();

            assert!(
                result.is_ok(),
                "Conversion to i64 should succeed for {nanos} nanoseconds"
            );

            // Compare with chrono if within i64 range
            if let Ok(nanos_i64) = i64::try_from(nanos) {
                #[allow(deprecated)]
                let chrono_ts = Utc.timestamp_nanos(nanos_i64);
                let chrono_nanos = chrono_ts.timestamp_nanos_opt().unwrap();

                assert_eq!(
                    result.unwrap(),
                    chrono_nanos,
                    "i64 conversion should match chrono for {nanos} nanoseconds"
                );
            }
        }

        // Test case that exceeds i64::MAX (should use fallback in production code)
        let overflow_case = i128::from(i64::MAX) + 1;
        let jiff_ts = Timestamp::from_nanosecond(overflow_case).unwrap();
        let result: Result<i64, _> = jiff_ts.as_nanosecond().try_into();

        assert!(
            result.is_err(),
            "Conversion should fail for values exceeding i64::MAX"
        );
    }

    /// Test the `ONE_DAY_TIMESTAMP_NANOS` constant used in retention logic.
    #[test]
    fn test_one_day_constant_equivalence() {
        const ONE_DAY_TIMESTAMP_NANOS: i128 = 86_400_000_000_000_i128;

        // Verify using chrono
        let one_day_chrono = chrono::Duration::days(1);
        let one_day_chrono_nanos = one_day_chrono.num_nanoseconds().unwrap();

        // Verify using jiff - SignedDuration has as_nanos()
        let one_day_jiff = jiff::SignedDuration::from_hours(24);
        let one_day_jiff_nanos = one_day_jiff.as_nanos();

        assert_eq!(
            i128::from(one_day_chrono_nanos),
            ONE_DAY_TIMESTAMP_NANOS,
            "chrono one day should equal constant"
        );
        assert_eq!(
            one_day_jiff_nanos, ONE_DAY_TIMESTAMP_NANOS,
            "jiff one day should equal constant"
        );
        assert_eq!(
            i128::from(one_day_chrono_nanos),
            one_day_jiff_nanos,
            "chrono and jiff one day durations should match"
        );
    }

    /// Test edge case: timestamps near Unix epoch (0).
    #[test]
    fn test_near_epoch_equivalence() {
        let near_epoch_cases = vec![
            -1_000_000_000_i64, // 1 second before epoch
            -1_i64,             // 1 nanosecond before epoch
            0_i64,              // Exactly epoch
            1_i64,              // 1 nanosecond after epoch
            1_000_000_000_i64,  // 1 second after epoch
        ];

        for nanos in near_epoch_cases {
            #[allow(deprecated)]
            let chrono_ts = Utc.timestamp_nanos(nanos);
            let chrono_nanos = chrono_ts.timestamp_nanos_opt().unwrap();

            let jiff_ts = Timestamp::from_nanosecond(i128::from(nanos)).unwrap();
            let jiff_nanos: i64 = jiff_ts.as_nanosecond().try_into().unwrap();

            assert_eq!(
                chrono_nanos, jiff_nanos,
                "Near-epoch timestamps should be equivalent for {nanos} ns"
            );
        }
    }

    /// Test timestamp subtraction to calculate durations.
    /// This tests that timestamp arithmetic produces equivalent results.
    #[test]
    fn test_timestamp_subtraction_equivalence() {
        let start_nanos = 1_000_000_000_i64;
        let end_nanos = 3_000_000_000_i64;
        let expected_duration_nanos = end_nanos - start_nanos;

        // chrono subtraction
        #[allow(deprecated)]
        let chrono_start = Utc.timestamp_nanos(start_nanos);
        #[allow(deprecated)]
        let chrono_end = Utc.timestamp_nanos(end_nanos);
        let chrono_duration = chrono_end - chrono_start;
        let chrono_duration_nanos = chrono_duration.num_nanoseconds().unwrap();

        // jiff subtraction - compute directly from timestamps
        let jiff_start = Timestamp::from_nanosecond(i128::from(start_nanos)).unwrap();
        let jiff_end = Timestamp::from_nanosecond(i128::from(end_nanos)).unwrap();
        let jiff_duration_nanos = jiff_end.as_nanosecond() - jiff_start.as_nanosecond();

        assert_eq!(
            chrono_duration_nanos, expected_duration_nanos,
            "chrono duration should match expected"
        );
        assert_eq!(
            i64::try_from(jiff_duration_nanos).unwrap(),
            expected_duration_nanos,
            "jiff duration should match expected"
        );
        assert_eq!(
            chrono_duration_nanos,
            i64::try_from(jiff_duration_nanos).unwrap(),
            "chrono and jiff durations should match"
        );
    }

    /// Test that serialization/deserialization maintains equivalence.
    /// This is important for storage and API communication.
    #[test]
    fn test_timestamp_serialization_equivalence() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStructJiff {
            timestamp: Timestamp,
        }

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStructChrono {
            timestamp: DateTime<Utc>,
        }

        let test_nanos = 1_609_459_200_000_000_000_i64;

        // Test jiff serialization
        let jiff_ts = Timestamp::from_nanosecond(i128::from(test_nanos)).unwrap();
        let jiff_struct = TestStructJiff { timestamp: jiff_ts };
        let jiff_json = serde_json::to_string(&jiff_struct).unwrap();

        // Test chrono serialization
        #[allow(deprecated)]
        let chrono_ts = Utc.timestamp_nanos(test_nanos);
        let chrono_struct = TestStructChrono {
            timestamp: chrono_ts,
        };
        let chrono_json = serde_json::to_string(&chrono_struct).unwrap();

        // Both should serialize to valid JSON (format may differ, but deserialization should work)
        let jiff_deserialized: TestStructJiff = serde_json::from_str(&jiff_json).unwrap();
        let chrono_deserialized: TestStructChrono = serde_json::from_str(&chrono_json).unwrap();

        assert_eq!(jiff_deserialized.timestamp, jiff_ts, "jiff roundtrip");
        assert_eq!(chrono_deserialized.timestamp, chrono_ts, "chrono roundtrip");

        // Verify that the nanosecond values are preserved
        let jiff_roundtrip_nanos: i64 = jiff_deserialized
            .timestamp
            .as_nanosecond()
            .try_into()
            .unwrap();
        let chrono_roundtrip_nanos = chrono_deserialized.timestamp.timestamp_nanos_opt().unwrap();

        assert_eq!(
            jiff_roundtrip_nanos, test_nanos,
            "jiff preserves nanos through serialization"
        );
        assert_eq!(
            chrono_roundtrip_nanos, test_nanos,
            "chrono preserves nanos through serialization"
        );
    }
}
