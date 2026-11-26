//! The version requirements Giganto checks data directories, peers and
//! clients against.

/// Expands to a version requirement whose lower bound is `MAJOR.MINOR.0` of
/// the crate's own version, followed by the upper bound `$upper`.
///
/// At 0.38.x, `version_req!("<0.40.0")` expands to `">=0.38.0,<0.40.0"`.
macro_rules! version_req {
    ($upper:literal) => {
        concat!(
            ">=",
            env!("CARGO_PKG_VERSION_MAJOR"),
            ".",
            env!("CARGO_PKG_VERSION_MINOR"),
            ".0,",
            $upper
        )
    };
}

pub(crate) use version_req;

/// Returns the first release of the minor release before the crate's own.
///
/// At 0.38.x this is 0.37.0. At `MAJOR.0.x` it is `(MAJOR-1).0.0`, which is
/// still earlier than every release of the current minor.
#[cfg(test)]
pub(crate) fn previous_minor_version() -> semver::Version {
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("valid crate version");
    if current.minor > 0 {
        semver::Version::new(current.major, current.minor - 1, 0)
    } else {
        semver::Version::new(current.major - 1, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    use semver::{Op, Version, VersionReq};

    use crate::comm::{
        ingest::INGEST_VERSION_REQ, peer::PEER_VERSION_REQ, publish::PUBLISH_VERSION_REQ,
    };
    use crate::storage::COMPATIBLE_VERSION_REQ;

    #[test]
    fn lower_bounds_follow_the_crate_minor_release() {
        let current = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        for (name, req) in [
            ("COMPATIBLE_VERSION_REQ", COMPATIBLE_VERSION_REQ),
            ("PEER_VERSION_REQ", PEER_VERSION_REQ),
            ("INGEST_VERSION_REQ", INGEST_VERSION_REQ),
            ("PUBLISH_VERSION_REQ", PUBLISH_VERSION_REQ),
        ] {
            let parsed = VersionReq::parse(req).unwrap();
            let lower = parsed
                .comparators
                .first()
                .unwrap_or_else(|| panic!("{name} has no comparator"));
            assert_eq!(lower.op, Op::GreaterEq, "{name}: {req}");
            assert_eq!(lower.major, current.major, "{name}: {req}");
            assert_eq!(lower.minor, Some(current.minor), "{name}: {req}");
            assert_eq!(lower.patch, Some(0), "{name}: {req}");
            assert!(lower.pre.is_empty(), "{name}: {req}");
            assert!(
                req.starts_with(&format!(">={}.{}.0,", current.major, current.minor)),
                "{name}: {req}"
            );
        }
    }
}
