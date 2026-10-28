use async_graphql::{InputType, Request, Variables, value};

use super::TestSchema;
use crate::graphql::{IpRange, check_address, network::tests::insert_conn_raw_event};

pub(crate) async fn assert_invalid_ip_ranges(
    schema: &TestSchema,
    field: &str,
    extra_filter: &str,
    selection: &str,
) {
    for address in ["origAddr", "respAddr"] {
        for bound in ["start", "end"] {
            for invalid in ["not-an-ip", "192.0.2.256", "2001:db8::xyz", ""] {
                let query = format!(
                    "query($ip: String!) {{ {field}(filter: {{ sensor: \"src1\", \
                     {extra_filter} {address}: {{ {bound}: $ip }} }}) {selection} }}"
                );
                let response = schema
                    .schema
                    .execute(
                        Request::new(query.clone())
                            .variables(Variables::from_value(value!({"ip": invalid}))),
                    )
                    .await;
                assert_eq!(response.errors.len(), 1, "{query}: {response:?}");
                assert!(
                    response.errors[0].message.contains("Invalid IP address"),
                    "{query}: {response:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn ip_range_rejects_invalid_query_bounds_with_empty_and_populated_stores() {
    let schema = TestSchema::new();
    for populated in [false, true] {
        if populated {
            insert_conn_raw_event(&schema.db.conn_store().unwrap(), "src1", 1);
        }
        for (field, extra, selection) in [
            ("connRawEvents", "", "{ edges { node { time } } }"),
            ("networkRawEvents", "", "{ edges { node { __typename } } }"),
            (
                "searchConnRawEvents",
                "times: [\"1970-01-01T00:00:00.000000001Z\"]",
                "",
            ),
            ("netflow5RawEvents", "", "{ edges { node { time } } }"),
            ("netflow9RawEvents", "", "{ edges { node { time } } }"),
            (
                "secuLogRawEvents",
                "kind: \"device\"",
                "{ edges { node { time } } }",
            ),
        ] {
            assert_invalid_ip_ranges(&schema, field, extra, selection).await;
        }
    }
}

#[tokio::test]
async fn ip_range_rejects_exports_before_registering_tasks() {
    let schema = TestSchema::new();
    // A registered task pauses before opening its store, so it cannot finish
    // before the pending-count assertion and hide an unintended admission.
    let control = std::sync::Arc::new(crate::graphql::ExportTestControl::new());
    let _registration =
        crate::graphql::register_export_test_control(schema.export_dir.path(), control);
    for populated in [false, true] {
        if populated {
            insert_conn_raw_event(&schema.db.conn_store().unwrap(), "src1", 1);
        }
        for protocol in [
            "conn",
            "dns",
            "malformed_dns",
            "http",
            "rdp",
            "smtp",
            "ntlm",
            "kerberos",
            "ssh",
            "dce rpc",
            "ftp",
            "mqtt",
            "ldap",
            "tls",
            "smb",
            "nfs",
            "bootp",
            "dhcp",
            "radius",
            "icmp",
            "network connect",
            "netflow5",
            "netflow9",
            "secu log",
        ] {
            for address in ["origAddr", "respAddr"] {
                for bound in ["start", "end"] {
                    let query = format!(
                        "{{ export(filter: {{ protocol: \"{protocol}\", sensorId: \"src1\", \
                         kind: {}, {address}: {{ {bound}: \"invalid\" }} }}, \
                         exportType: \"json\") }}",
                        if protocol == "secu log" {
                            "\"device\""
                        } else {
                            "null"
                        }
                    );
                    let response = schema.execute(&query).await;
                    assert_eq!(schema.top_level_tracker.pending_count(), 0, "{query}");
                    assert_eq!(response.errors.len(), 1, "{query}: {response:?}");
                    assert!(response.errors[0].message.contains("Invalid IP address"));
                    assert_eq!(
                        std::fs::read_dir(schema.export_dir.path()).unwrap().count(),
                        0
                    );
                }
            }
        }
    }
}

#[cfg(feature = "cluster")]
#[tokio::test]
async fn ip_range_rejects_invalid_bounds_before_cluster_forwarding() {
    let mut server = mockito::Server::new_async().await;
    let peer = server
        .mock("POST", "/graphql")
        .expect(0)
        .create_async()
        .await;
    let schema = TestSchema::new_with_graphql_peer(server.socket_address().port());
    for (field, extra, selection) in [
        ("connRawEvents", "", "{ edges { node { time } } }"),
        ("networkRawEvents", "", "{ edges { node { __typename } } }"),
        ("searchConnRawEvents", "times: []", ""),
        ("netflow5RawEvents", "", "{ edges { node { time } } }"),
        ("netflow9RawEvents", "", "{ edges { node { time } } }"),
        (
            "secuLogRawEvents",
            "kind: \"device\"",
            "{ edges { node { time } } }",
        ),
        ("export", "protocol: \"conn\"", ""),
    ] {
        for address in ["origAddr", "respAddr"] {
            for bound in ["start", "end"] {
                let (sensor, args) = if field == "export" {
                    ("sensorId", ", exportType: \"json\"")
                } else {
                    ("sensor", "")
                };
                let query = format!(
                    "{{ {field}(filter: {{ {sensor}: \"src 2\", {extra} \
                     {address}: {{ {bound}: \"invalid\" }} }}{args}) {selection} }}"
                );
                let response = schema.execute(&query).await;
                assert_eq!(response.errors.len(), 1, "{query}: {response:?}");
                assert!(response.errors[0].message.contains("Invalid IP address"));
            }
        }
    }
    peer.assert_async().await;
}

#[test]
fn ip_range_preserves_optional_strings_and_valid_range_semantics() {
    for (start, end, inside, outside) in [
        ("192.0.2.1", "192.0.2.3", "192.0.2.2", "192.0.2.0"),
        ("2001:db8::1", "2001:db8::3", "2001:db8::2", "2001:db8::"),
    ] {
        let range = IpRange::parse(Some(value!({"start": start, "end": end}))).unwrap();
        assert!(check_address(Some(&range), Some(start.parse().unwrap())).unwrap());
        assert!(check_address(Some(&range), Some(inside.parse().unwrap())).unwrap());
        assert!(!check_address(Some(&range), Some(end.parse().unwrap())).unwrap());
        assert!(!check_address(Some(&range), Some(outside.parse().unwrap())).unwrap());
        for value in [value!({"start": start}), value!({"end": end})] {
            let range = IpRange::parse(Some(value)).unwrap();
            assert!(check_address(Some(&range), Some(inside.parse().unwrap())).unwrap());
        }
    }
    for value in [value!({}), value!({"start": null, "end": null})] {
        let range = IpRange::parse(Some(value)).unwrap();
        assert!(range.start.is_none());
        assert!(range.end.is_none());
        for addr in ["192.0.2.1", "2001:db8::1"] {
            assert!(check_address(Some(&range), Some(addr.parse().unwrap())).unwrap());
        }
    }
}
