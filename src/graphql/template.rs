use std::{collections::HashMap, fs, path::Path};

use anyhow::Result;
use async_graphql::{Context, Object, SimpleObject};
use serde::Serialize;

const PROTOCOL_TEMPLATES: &[(&str, &[&str])] = &[
    // Network protocols
    (
        "conn",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "conn_state",
            "start_time",
            "end_time",
            "service",
            "orig_bytes",
            "resp_bytes",
            "orig_pkts",
            "resp_pkts",
            "orig_l2_bytes",
            "resp_l2_bytes",
        ],
    ),
    (
        "dns",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "query",
            "answer",
            "trans_id",
            "rtt",
            "qclass",
            "qtype",
            "rcode",
            "aa_flag",
            "tc_flag",
            "rd_flag",
            "ra_flag",
            "ttl",
        ],
    ),
    (
        "http",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "method",
            "host",
            "uri",
            "referer",
            "version",
            "user_agent",
            "request_len",
            "response_len",
            "status_code",
            "status_msg",
            "username",
            "password",
            "cookie",
            "content_encoding",
            "content_type",
            "cache_control",
            "filenames",
            "mime_types",
            "body",
            "state",
        ],
    ),
    (
        "rdp",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "cookie",
        ],
    ),
    (
        "smtp",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "mailfrom",
            "date",
            "from",
            "to",
            "subject",
            "agent",
            "state",
        ],
    ),
    (
        "ntlm",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "username",
            "hostname",
            "domainname",
            "success",
            "protocol",
        ],
    ),
    (
        "kerberos",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "client_time",
            "server_time",
            "error_code",
            "client_realm",
            "cname_type",
            "client_name",
            "realm",
            "sname_type",
            "service_name",
        ],
    ),
    (
        "ssh",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "client",
            "server",
            "cipher_alg",
            "mac_alg",
            "compression_alg",
            "kex_alg",
            "host_key_alg",
            "hassh_algorithms",
            "hassh",
            "hassh_server_algorithms",
            "hassh_server",
            "client_shka",
            "server_shka",
        ],
    ),
    (
        "dce rpc",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "rtt",
            "named_pipe",
            "endpoint",
            "operation",
        ],
    ),
    (
        "ftp",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "user",
            "password",
            "commands",
        ],
    ),
    (
        "mqtt",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "protocol",
            "version",
            "client_id",
            "connack_reason",
            "subscribe",
            "suback_reason",
        ],
    ),
    (
        "ldap",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "message_id",
            "version",
            "opcode",
            "result",
            "diagnostic_message",
            "object",
            "argument",
        ],
    ),
    (
        "tls",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "server_name",
            "alpn_protocol",
            "ja3",
            "version",
            "client_cipher_suites",
            "client_extensions",
            "cipher",
            "extensions",
            "ja3s",
            "serial",
            "subject_country",
            "subject_org_name",
            "subject_common_name",
            "validity_not_before",
            "validity_not_after",
            "subject_alt_name",
            "issuer_country",
            "issuer_org_name",
            "issuer_org_unit_name",
            "issuer_common_name",
            "last_alert",
        ],
    ),
    (
        "smb",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "command",
            "path",
            "service",
            "file_name",
            "file_size",
            "resource_type",
            "fid",
            "create_time",
            "access_time",
            "write_time",
            "change_time",
        ],
    ),
    (
        "nfs",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "read_files",
            "write_files",
        ],
    ),
    (
        "bootp",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "op",
            "htype",
            "hops",
            "xid",
            "ciaddr",
            "yiaddr",
            "siaddr",
            "giaddr",
            "chaddr",
            "sname",
            "file",
        ],
    ),
    (
        "dhcp",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "msg_type",
            "ciaddr",
            "yiaddr",
            "siaddr",
            "giaddr",
            "subnet_mask",
            "router",
            "domain_name_server",
            "req_ip_addr",
            "lease_time",
            "server_id",
            "param_req_list",
            "message",
            "renewal_time",
            "rebinding_time",
            "class_id",
            "client_id_type",
            "client_id",
        ],
    ),
    (
        "radius",
        &[
            "time",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "end_time",
            "id",
            "code",
            "resp_code",
            "auth",
            "resp_auth",
            "user_name",
            "user_passwd",
            "chap_passwd",
            "nas_ip",
            "nas_port",
            "state",
            "nas_id",
            "nas_port_type",
            "message",
        ],
    ),
    // Log protocols
    ("log", &["time", "sensor", "kind", "log"]),
    (
        "secu log",
        &[
            "time",
            "sensor",
            "kind",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "contents",
        ],
    ),
    ("op_log", &["time", "agent_id", "level", "contents"]),
    // Netflow protocols
    (
        "netflow5",
        &[
            "time",
            "sensor",
            "src_addr",
            "dst_addr",
            "next_hop",
            "input",
            "output",
            "d_pkts",
            "d_octets",
            "first",
            "last",
            "src_port",
            "dst_port",
            "tcp_flags",
            "prot",
            "tos",
            "src_as",
            "dst_as",
            "src_mask",
            "dst_mask",
            "sequence",
            "engine_type",
            "engine_id",
            "sampling_mode",
            "sampling_rate",
        ],
    ),
    (
        "netflow9",
        &[
            "time",
            "sequence",
            "source_id",
            "template_id",
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "contents",
        ],
    ),
    // Sysmon events
    (
        "process create",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "image",
            "file_version",
            "description",
            "product",
            "company",
            "original_file_name",
            "command_line",
            "current_directory",
            "user",
            "logon_guid",
            "logon_id",
            "terminal_session_id",
            "integrity_level",
            "hashes",
            "parent_process_guid",
            "parent_process_id",
            "parent_image",
            "parent_command_line",
            "parent_user",
        ],
    ),
    (
        "file create time",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "image",
            "target_filename",
            "creation_utc_time",
            "previous_creation_utc_time",
            "user",
        ],
    ),
    (
        "network connect",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "image",
            "user",
            "protocol",
            "initiated",
            "source_is_ipv6",
            "source_ip",
            "source_hostname",
            "source_port",
            "source_port_name",
            "destination_is_ipv6",
            "destination_ip",
            "destination_hostname",
            "destination_port",
            "destination_port_name",
        ],
    ),
    (
        "process terminate",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "image",
            "user",
        ],
    ),
    (
        "image load",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "image",
            "image_loaded",
            "file_version",
            "description",
            "product",
            "company",
            "original_file_name",
            "hashes",
            "signed",
            "signature",
            "signature_status",
            "user",
        ],
    ),
    (
        "file create",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "image",
            "target_filename",
            "creation_utc_time",
            "user",
        ],
    ),
    (
        "registry value set",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "event_type",
            "process_guid",
            "process_id",
            "image",
            "target_object",
            "details",
            "user",
        ],
    ),
    (
        "registry key rename",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "event_type",
            "process_guid",
            "process_id",
            "image",
            "target_object",
            "new_name",
            "user",
        ],
    ),
    (
        "file create stream hash",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "image",
            "target_filename",
            "creation_utc_time",
            "hash",
            "contents",
            "user",
        ],
    ),
    (
        "pipe event",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "event_type",
            "process_guid",
            "process_id",
            "pipe_name",
            "image",
            "user",
        ],
    ),
    (
        "dns query",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "query_name",
            "query_status",
            "query_results",
            "image",
            "user",
        ],
    ),
    (
        "file delete",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "user",
            "image",
            "target_filename",
            "hashes",
            "is_executable",
            "archived",
        ],
    ),
    (
        "process tamper",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "image",
            "tamper_type",
            "user",
        ],
    ),
    (
        "file delete detected",
        &[
            "time",
            "sensor",
            "agent_name",
            "agent_id",
            "process_guid",
            "process_id",
            "user",
            "image",
            "target_filename",
            "hashes",
            "is_executable",
        ],
    ),
    // Time series
    ("periodic time series", &["start", "id", "data"]),
    // Statistics
    ("statistics", &["time", "sensor", "core", "period", "stats"]),
];

/// Represents a protocol template with field format information
#[derive(Debug, Clone, Serialize, SimpleObject)]
pub struct ProtocolTemplate {
    /// Protocol name
    pub protocol: String,
    /// List of field names for this protocol
    pub fields: Vec<String>,
}

#[derive(Default)]
pub struct TemplateQuery;

#[Object]
#[allow(clippy::unused_async)]
impl TemplateQuery {
    /// Returns protocol templates for field format
    ///
    /// # Arguments
    ///
    /// * `protocol` - Optional protocol name filter. If provided, returns only the template for that protocol.
    ///                If None, returns templates for all protocols.
    ///
    /// # Returns
    ///
    /// Returns a vector of `ProtocolTemplate` objects containing field format information.
    async fn protocol_templates(
        &self,
        _ctx: &Context<'_>,
        protocol: Option<String>,
    ) -> Result<Vec<ProtocolTemplate>> {
        let templates: Vec<ProtocolTemplate> = if let Some(protocol_name) = protocol {
            // Return specific protocol template
            PROTOCOL_TEMPLATES
                .iter()
                .filter(|(name, _)| *name == protocol_name)
                .map(|(name, fields)| ProtocolTemplate {
                    protocol: (*name).to_string(),
                    fields: fields.iter().map(|f| (*f).to_string()).collect(),
                })
                .collect()
        } else {
            // Return all protocol templates
            PROTOCOL_TEMPLATES
                .iter()
                .map(|(name, fields)| ProtocolTemplate {
                    protocol: (*name).to_string(),
                    fields: fields.iter().map(|f| (*f).to_string()).collect(),
                })
                .collect()
        };

        Ok(templates)
    }

    /// Exports protocol templates to a file
    ///
    /// # Arguments
    ///
    /// * `export_type` - Export format: "json" or "csv"
    /// * `protocol` - Optional protocol name filter. If provided, exports only that protocol.
    ///
    /// # Returns
    ///
    /// Returns the path to the exported file.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The export format is not supported ("json" or "csv")
    /// * File creation or writing fails
    /// * The export directory is not accessible
    async fn export_protocol_templates(
        &self,
        ctx: &Context<'_>,
        export_type: String,
        protocol: Option<String>,
    ) -> Result<String> {
        // Validate export type
        if !matches!(export_type.as_str(), "json" | "csv") {
            return Err(anyhow::anyhow!(
                "Invalid export format. Supported formats: json, csv"
            ));
        }

        let export_path = ctx
            .data::<std::path::PathBuf>()
            .map_err(|e| anyhow::anyhow!("Failed to get export path: {:?}", e))?;

        // Ensure export directory exists
        if !export_path.exists() {
            fs::create_dir_all(export_path)?;
        }

        let templates: Vec<ProtocolTemplate> = if let Some(protocol_name) = &protocol {
            PROTOCOL_TEMPLATES
                .iter()
                .filter(|(name, _)| *name == protocol_name)
                .map(|(name, fields)| ProtocolTemplate {
                    protocol: (*name).to_string(),
                    fields: fields.iter().map(|f| (*f).to_string()).collect(),
                })
                .collect()
        } else {
            PROTOCOL_TEMPLATES
                .iter()
                .map(|(name, fields)| ProtocolTemplate {
                    protocol: (*name).to_string(),
                    fields: fields.iter().map(|f| (*f).to_string()).collect(),
                })
                .collect()
        };

        let filename = if let Some(ref protocol_name) = protocol {
            format!(
                "protocol_template_{}_{}.{}",
                protocol_name.replace(' ', "_"),
                chrono::Local::now().format("%Y%m%d_%H%M%S"),
                export_type
            )
        } else {
            format!(
                "protocol_templates_{}.{}",
                chrono::Local::now().format("%Y%m%d_%H%M%S"),
                export_type
            )
        };

        let file_path = export_path.join(&filename);

        match export_type.as_str() {
            "json" => {
                let json_content = serde_json::to_string_pretty(&templates)?;
                fs::write(&file_path, json_content)?;
            }
            "csv" => {
                export_templates_to_csv(&templates, &file_path)?;
            }
            _ => unreachable!(), // Already validated above
        }

        Ok(file_path.to_string_lossy().to_string())
    }
}

fn export_templates_to_csv(templates: &[ProtocolTemplate], file_path: &Path) -> Result<()> {
    use std::fmt::Write;

    let mut content = String::new();
    content.push_str("protocol,field_index,field_name\n");

    for template in templates {
        for (index, field) in template.fields.iter().enumerate() {
            writeln!(&mut content, "{},{},{}", template.protocol, index, field)
                .expect("Writing to String should not fail");
        }
    }

    fs::write(file_path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_templates_include_common_protocols() {
        let template_map: HashMap<&str, &[&str]> = PROTOCOL_TEMPLATES.iter().copied().collect();

        // Test that common network protocols are included
        assert!(template_map.contains_key("conn"));
        assert!(template_map.contains_key("dns"));
        assert!(template_map.contains_key("http"));
        assert!(template_map.contains_key("ssh"));

        // Test that log protocols are included
        assert!(template_map.contains_key("log"));
        assert!(template_map.contains_key("secu log"));

        // Test that sysmon events are included
        assert!(template_map.contains_key("process create"));
        assert!(template_map.contains_key("file create"));

        // Test that netflow protocols are included
        assert!(template_map.contains_key("netflow5"));
        assert!(template_map.contains_key("netflow9"));
    }

    #[test]
    fn test_protocol_template_fields() {
        let template_map: HashMap<&str, &[&str]> = PROTOCOL_TEMPLATES.iter().copied().collect();

        // Test conn protocol has expected basic fields
        let conn_fields = template_map.get("conn").unwrap();
        assert!(conn_fields.contains(&"time"));
        assert!(conn_fields.contains(&"orig_addr"));
        assert!(conn_fields.contains(&"resp_addr"));
        assert!(conn_fields.contains(&"proto"));

        // Test dns protocol has expected fields
        let dns_fields = template_map.get("dns").unwrap();
        assert!(dns_fields.contains(&"query"));
        assert!(dns_fields.contains(&"answer"));
        assert!(dns_fields.contains(&"qtype"));

        // Test log protocol has expected simple fields
        let log_fields = template_map.get("log").unwrap();
        assert!(log_fields.contains(&"time"));
        assert!(log_fields.contains(&"log"));
    }

    #[test]
    fn test_export_csv_format() {
        let templates = vec![ProtocolTemplate {
            protocol: "test".to_string(),
            fields: vec!["field1".to_string(), "field2".to_string()],
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.csv");

        export_templates_to_csv(&templates, &file_path).unwrap();

        let content = fs::read_to_string(&file_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines[0], "protocol,field_index,field_name");
        assert_eq!(lines[1], "test,0,field1");
        assert_eq!(lines[2], "test,1,field2");
    }
}
