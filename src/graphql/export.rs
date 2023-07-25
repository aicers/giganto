use super::{
    check_address, check_port,
    network::{IpRange, PortRange},
    RawEventFilter, TimeRange,
};
use crate::{
    ingest::implement::EventFilter,
    storage::{lower_closed_bound_key, upper_open_bound_key, Database, Direction, RawEventStore},
};
use anyhow::anyhow;
use async_graphql::{Context, InputObject, Object, Result};
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use giganto_client::ingest::{
    log::{Log, Oplog},
    network::{
        Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Qclass, Qtype, Rdp, Smb,
        Smtp, Ssh, Tls,
    },
    statistics::Statistics,
    timeseries::PeriodicTimeSeries,
    RecordType,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    borrow::Cow,
    fmt::Display,
    fs::{self, File},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};
use tracing::{error, info};

#[derive(Default)]
pub(super) struct ExportQuery;

#[derive(Serialize, Debug)]
struct ConnJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    duration: i64,
    service: String,
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize, Debug)]
struct DnsJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    query: String,
    answer: Vec<String>,
    trans_id: u16,
    rtt: i64,
    qclass: String,
    qtype: String,
    rcode: u16,
    aa_flag: bool,
    tc_flag: bool,
    rd_flag: bool,
    ra_flag: bool,
    ttl: Vec<String>,
}

#[derive(Serialize, Debug)]
struct HttpJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    method: String,
    host: String,
    uri: String,
    referrer: String,
    version: String,
    user_agent: String,
    request_len: usize,
    response_len: usize,
    status_code: u16,
    status_msg: String,
    username: String,
    password: String,
    cookie: String,
    content_encoding: String,
    content_type: String,
    cache_control: String,
    orig_filenames: Vec<String>,
    orig_mime_types: Vec<String>,
    resp_filenames: Vec<String>,
    resp_mime_types: Vec<String>,
}

#[derive(Serialize, Debug)]
struct RdpJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    cookie: String,
}

#[derive(Serialize, Debug)]
struct SmtpJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    mailfrom: String,
    date: String,
    from: String,
    to: String,
    subject: String,
    agent: String,
}

#[derive(Serialize, Debug)]
struct NtlmJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    username: String,
    hostname: String,
    domainname: String,
    server_nb_computer_name: String,
    server_dns_computer_name: String,
    server_tree_name: String,
    success: String,
}

#[derive(Serialize, Debug)]
struct KerberosJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    request_type: String,
    client: String,
    service: String,
    success: String,
    error_msg: String,
    from: i64,
    till: i64,
    cipher: String,
    forwardable: String,
    renewable: String,
    client_cert_subject: String,
    server_cert_subject: String,
}

#[derive(Serialize, Debug)]
struct SshJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    version: i64,
    auth_success: String,
    auth_attempts: i64,
    direction: String,
    client: String,
    server: String,
    cipher_alg: String,
    mac_alg: String,
    compression_alg: String,
    kex_alg: String,
    host_key_alg: String,
    host_key: String,
}

#[derive(Serialize, Debug)]
struct DceRpcJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    rtt: i64,
    named_pipe: String,
    endpoint: String,
    operation: String,
}

#[derive(Serialize, Debug)]
struct FtpJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    user: String,
    password: String,
    command: String,
    reply_code: String,
    reply_msg: String,
    data_passive: bool,
    data_orig_addr: String,
    data_resp_addr: String,
    data_resp_port: u16,
    file: String,
    file_size: u64,
    file_id: String,
}

#[derive(Serialize, Debug)]
struct MqttJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    protocol: String,
    version: u8,
    client_id: String,
    connack_reason: u8,
    subscribe: Vec<String>,
    suback_reason: Vec<String>,
}

#[derive(Serialize, Debug)]
struct LdapJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    message_id: u32,
    version: u8,
    opcode: Vec<String>,
    result: Vec<String>,
    diagnostic_message: Vec<String>,
    object: Vec<String>,
    argument: Vec<String>,
}

#[derive(Serialize, Debug)]
struct TlsJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    server_name: String,
    alpn_protocol: String,
    ja3: String,
    version: String,
    cipher: u16,
    ja3s: String,
    serial: String,
    subject_country: String,
    subject_org_name: String,
    subject_common_name: String,
    validity_not_before: i64,
    validity_not_after: i64,
    subject_alt_name: String,
    issuer_country: String,
    issuer_org_name: String,
    issuer_org_unit_name: String,
    issuer_common_name: String,
    last_alert: u8,
}

#[derive(Serialize, Debug)]
struct SmbJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    command: u8,
    path: String,
    service: String,
    file_name: String,
    file_size: u64,
    resource_type: u16,
    fid: u16,
    create_time: i64,
    access_time: i64,
    write_time: i64,
    change_time: i64,
}

#[derive(Serialize, Debug)]
struct NfsJsonOutput {
    timestamp: String,
    source: String,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    last_time: i64,
    read_files: Vec<String>,
    write_files: Vec<String>,
}

#[derive(Serialize, Debug)]
struct LogJsonOutput {
    timestamp: String,
    source: String,
    kind: String,
    log: String,
}

#[derive(Serialize, Debug)]
struct TimeSeriesJsonOutput {
    start: String,
    id: String,
    data: Vec<f64>,
}

#[derive(Serialize, Debug)]
struct OpLogJsonOutput {
    timestamp: String,
    agent_id: String,
    level: String,
    contents: String,
}

#[derive(Serialize, Debug)]
struct StatisticsJsonOutput {
    timestamp: String,
    source: String,
    core: u32,
    period: u16,
    stats: Vec<(RecordType, u64, u64)>,
}

pub trait JsonOutput<T>: Sized {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<T>;
}

macro_rules! convert_json_output {
    ($to:ident, $from:ty, $($fields:ident),*) => {
        impl JsonOutput<$to> for $from {
            fn convert_json_output(&self, timestamp:String, source:String) -> Result<$to> {
                Ok($to {
                    timestamp,
                    source,
                    orig_addr: self.orig_addr.to_string(),
                    orig_port: self.orig_port,
                    resp_addr: self.resp_addr.to_string(),
                    resp_port: self.resp_port,
                    proto: self.proto,
                    last_time: self.last_time,
                    $(
                        $fields: self.$fields.clone(),
                    )*
                })
            }
        }
    };
}

convert_json_output!(
    HttpJsonOutput,
    Http,
    method,
    host,
    uri,
    referrer,
    version,
    user_agent,
    request_len,
    response_len,
    status_code,
    status_msg,
    username,
    password,
    cookie,
    content_encoding,
    content_type,
    cache_control,
    orig_filenames,
    orig_mime_types,
    resp_filenames,
    resp_mime_types
);

convert_json_output!(RdpJsonOutput, Rdp, cookie);

convert_json_output!(
    SmtpJsonOutput,
    Smtp,
    mailfrom,
    date,
    from,
    to,
    subject,
    agent
);

convert_json_output!(
    NtlmJsonOutput,
    Ntlm,
    username,
    hostname,
    domainname,
    server_nb_computer_name,
    server_dns_computer_name,
    server_tree_name,
    success
);

convert_json_output!(
    KerberosJsonOutput,
    Kerberos,
    request_type,
    client,
    service,
    success,
    error_msg,
    from,
    till,
    cipher,
    forwardable,
    renewable,
    client_cert_subject,
    server_cert_subject
);

convert_json_output!(
    SshJsonOutput,
    Ssh,
    version,
    auth_success,
    auth_attempts,
    direction,
    client,
    server,
    cipher_alg,
    mac_alg,
    compression_alg,
    kex_alg,
    host_key_alg,
    host_key
);

convert_json_output!(
    DceRpcJsonOutput,
    DceRpc,
    rtt,
    named_pipe,
    endpoint,
    operation
);

convert_json_output!(
    LdapJsonOutput,
    Ldap,
    message_id,
    version,
    opcode,
    result,
    diagnostic_message,
    object,
    argument
);

convert_json_output!(
    TlsJsonOutput,
    Tls,
    server_name,
    alpn_protocol,
    ja3,
    version,
    cipher,
    ja3s,
    serial,
    subject_country,
    subject_org_name,
    subject_common_name,
    validity_not_before,
    validity_not_after,
    subject_alt_name,
    issuer_country,
    issuer_org_name,
    issuer_org_unit_name,
    issuer_common_name,
    last_alert
);

convert_json_output!(
    SmbJsonOutput,
    Smb,
    command,
    path,
    service,
    file_name,
    file_size,
    resource_type,
    fid,
    create_time,
    access_time,
    write_time,
    change_time
);

convert_json_output!(NfsJsonOutput, Nfs, read_files, write_files);

impl JsonOutput<ConnJsonOutput> for Conn {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<ConnJsonOutput> {
        Ok(ConnJsonOutput {
            timestamp,
            source,
            orig_addr: self.orig_addr.to_string(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.to_string(),
            resp_port: self.resp_port,
            proto: self.proto,
            duration: self.duration,
            service: self.service.clone(),
            orig_bytes: self.orig_bytes,
            resp_bytes: self.resp_bytes,
            orig_pkts: self.orig_pkts,
            resp_pkts: self.resp_pkts,
        })
    }
}

impl JsonOutput<DnsJsonOutput> for Dns {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<DnsJsonOutput> {
        Ok(DnsJsonOutput {
            timestamp,
            source,
            orig_addr: self.orig_addr.to_string(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.to_string(),
            resp_port: self.resp_port,
            proto: self.proto,
            last_time: self.last_time,
            query: self.query.clone(),
            answer: self.answer.clone(),
            trans_id: self.trans_id,
            rtt: self.rtt,
            qclass: Qclass::from(self.qclass).to_string(),
            qtype: Qtype::from(self.qtype).to_string(),
            rcode: self.rcode,
            aa_flag: self.aa_flag,
            tc_flag: self.tc_flag,
            rd_flag: self.rd_flag,
            ra_flag: self.ra_flag,
            ttl: to_vec_string(&self.ttl),
        })
    }
}

impl JsonOutput<LogJsonOutput> for Log {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<LogJsonOutput> {
        Ok(LogJsonOutput {
            timestamp,
            source,
            kind: self.kind.clone(),
            log: String::from_utf8_lossy(&self.log).to_string(),
        })
    }
}

impl JsonOutput<TimeSeriesJsonOutput> for PeriodicTimeSeries {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<TimeSeriesJsonOutput> {
        Ok(TimeSeriesJsonOutput {
            start: timestamp,
            id: source,
            data: self.data.clone(),
        })
    }
}

impl JsonOutput<OpLogJsonOutput> for Oplog {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<OpLogJsonOutput> {
        Ok(OpLogJsonOutput {
            timestamp,
            agent_id: source,
            level: self.log_level().unwrap_or_else(|| "-".to_string()),
            contents: self.contents.clone(),
        })
    }
}

impl JsonOutput<FtpJsonOutput> for Ftp {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<FtpJsonOutput> {
        Ok(FtpJsonOutput {
            timestamp,
            source,
            orig_addr: self.orig_addr.to_string(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.to_string(),
            resp_port: self.resp_port,
            proto: self.proto,
            last_time: self.last_time,
            user: self.user.clone(),
            password: self.password.clone(),
            command: self.command.clone(),
            reply_code: self.reply_code.clone(),
            reply_msg: self.reply_msg.clone(),
            data_passive: self.data_passive,
            data_orig_addr: self.data_orig_addr.to_string(),
            data_resp_addr: self.data_resp_addr.to_string(),
            data_resp_port: self.data_resp_port,
            file: self.file.clone(),
            file_size: self.file_size,
            file_id: self.file_id.clone(),
        })
    }
}

impl JsonOutput<MqttJsonOutput> for Mqtt {
    fn convert_json_output(&self, timestamp: String, source: String) -> Result<MqttJsonOutput> {
        Ok(MqttJsonOutput {
            timestamp,
            source,
            orig_addr: self.orig_addr.to_string(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.to_string(),
            resp_port: self.resp_port,
            proto: self.proto,
            last_time: self.last_time,
            protocol: self.protocol.clone(),
            version: self.version,
            client_id: self.client_id.clone(),
            connack_reason: self.connack_reason,
            subscribe: self.subscribe.clone(),
            suback_reason: to_vec_string(&self.suback_reason),
        })
    }
}

impl JsonOutput<StatisticsJsonOutput> for Statistics {
    fn convert_json_output(
        &self,
        timestamp: String,
        source: String,
    ) -> Result<StatisticsJsonOutput> {
        Ok(StatisticsJsonOutput {
            timestamp,
            source,
            core: self.core,
            period: self.period,
            stats: self.stats.clone(),
        })
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct ExportFilter {
    protocol: String,
    source_id: String,
    kind: Option<String>,
    time: Option<TimeRange>,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
}

impl RawEventFilter for ExportFilter {
    fn time(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }

    fn check(
        &self,
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
        _log_level: Option<String>,
        _log_contents: Option<String>,
        _text: Option<String>,
    ) -> Result<bool> {
        if check_address(&self.orig_addr, orig_addr)?
            && check_address(&self.resp_addr, resp_addr)?
            && check_port(&self.orig_port, orig_port)
            && check_port(&self.resp_port, resp_port)
        {
            return Ok(true);
        }
        Ok(false)
    }
}

#[Object]
impl ExportQuery {
    #[allow(clippy::unused_async)]
    async fn export(
        &self,
        ctx: &Context<'_>,
        export_type: String,
        filter: ExportFilter,
    ) -> Result<String> {
        if filter.protocol == "log"
            || filter.protocol == "periodic time series"
            || filter.protocol == "oplog"
            || filter.protocol == "statistics"
        {
            // check log/time_series protocol filter format
            if filter.orig_addr.is_some()
                || filter.resp_addr.is_some()
                || filter.orig_port.is_some()
                || filter.resp_port.is_some()
            {
                return Err(anyhow!("Invalid id/port input").into());
            }
        } else {
            // check network protocol filter format
            if filter.kind.is_some() {
                return Err(anyhow!("Invalid kind input").into());
            }
        }

        // check export file type
        if !(export_type.eq("csv") || export_type.eq("json")) {
            return Err(anyhow!("Invalid export file format").into());
        }

        let db = ctx.data::<Database>()?;
        let path = ctx.data::<PathBuf>()?;
        let mut key_prefix = export_key_prefix(&filter.source_id, &filter.kind);
        if filter.protocol == "statistics" {
            // TODO: Change the key prefix to include other core's statistics data
            key_prefix.extend(&(0_u32).to_be_bytes());
            key_prefix.push(0);
        }

        // set export file path
        if !path.exists() {
            fs::create_dir_all(path)?;
        }
        let filename = format!(
            "{}_{}.dump",
            &filter.protocol,
            Local::now().format("%Y%m%d_%H%M%S"),
        );
        let export_path = path.join(filename.replace(' ', ""));
        let download_path = export_path.display().to_string();

        export_by_protocol(db.clone(), key_prefix, filter, export_type, export_path)?;

        Ok(download_path)
    }
}

#[allow(clippy::too_many_lines)]
fn export_by_protocol(
    db: Database,
    key_prefix: Vec<u8>,
    filter: ExportFilter,
    export_type: String,
    export_path: PathBuf,
) -> Result<()> {
    match filter.protocol.as_str() {
        "conn" => tokio::spawn(async move {
            if let Ok(store) = db.conn_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "dns" => tokio::spawn(async move {
            if let Ok(store) = db.dns_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "http" => tokio::spawn(async move {
            if let Ok(store) = db.http_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "log" => tokio::spawn(async move {
            if let Ok(store) = db.log_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "rdp" => tokio::spawn(async move {
            if let Ok(store) = db.rdp_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "smtp" => tokio::spawn(async move {
            if let Ok(store) = db.smtp_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "periodic time series" => tokio::spawn(async move {
            if let Ok(store) = db.periodic_time_series_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "ntlm" => tokio::spawn(async move {
            if let Ok(store) = db.ntlm_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "kerberos" => tokio::spawn(async move {
            if let Ok(store) = db.kerberos_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "ssh" => tokio::spawn(async move {
            if let Ok(store) = db.ssh_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "dce rpc" => tokio::spawn(async move {
            if let Ok(store) = db.dce_rpc_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "oplog" => tokio::spawn(async move {
            if let Ok(store) = db.oplog_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "ftp" => tokio::spawn(async move {
            if let Ok(store) = db.ftp_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "mqtt" => tokio::spawn(async move {
            if let Ok(store) = db.mqtt_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "ldap" => tokio::spawn(async move {
            if let Ok(store) = db.ldap_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "tls" => tokio::spawn(async move {
            if let Ok(store) = db.tls_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "smb" => tokio::spawn(async move {
            if let Ok(store) = db.smb_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "nfs" => tokio::spawn(async move {
            if let Ok(store) = db.nfs_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        "statistics" => tokio::spawn(async move {
            if let Ok(store) = db.statistics_store() {
                match process_export(&store, &key_prefix, &filter, &export_type, &export_path) {
                    Ok(result) => {
                        info!("{}", result);
                    }
                    Err(e) => {
                        error!("Failed to export file: {:?}", e);
                    }
                }
            } else {
                error!("Failed to open db store");
            }
        }),
        none => {
            return Err(anyhow!("{}: Unknown protocol", none).into());
        }
    };
    Ok(())
}

fn process_export<T, N>(
    store: &RawEventStore<'_, T>,
    key_prefix: &[u8],
    filter: &impl RawEventFilter,
    export_type: &str,
    export_path: &Path,
) -> Result<String>
where
    T: DeserializeOwned + Display + EventFilter + JsonOutput<N> + Send + Serialize,
    N: Serialize,
{
    let (start, end) = filter.time();
    let iter = store.boundary_iter(
        &lower_closed_bound_key(key_prefix, start),
        &upper_open_bound_key(key_prefix, end),
        Direction::Forward,
    );
    export_file(iter, filter, export_type, export_path)
}

fn export_file<I, T, N>(
    iter: I,
    filter: &impl RawEventFilter,
    export_type: &str,
    path: &Path,
) -> Result<String>
where
    I: Iterator<Item = anyhow::Result<(Box<[u8]>, T)>> + Send,
    T: Display + EventFilter + JsonOutput<N> + Serialize,
    N: Serialize,
{
    // export file open
    let mut writer = File::create(path)?;

    // check filter condition & write file
    for item in iter {
        let (key, value) = item.map_err(|e| format!("Failed to read database: {e}"))?;
        match filter.check(
            value.orig_addr(),
            value.resp_addr(),
            value.orig_port(),
            value.resp_port(),
            value.log_level(),
            value.log_contents(),
            value.text(),
        ) {
            Ok(true) => {
                let (source, timestamp) = parse_key(&key)?;
                let timestamp = {
                    let secs = timestamp / 1_000_000_000;
                    let nanosecs =
                        u32::try_from(timestamp % 1_000_000_000).expect("< 1_000_000_000");
                    NaiveDateTime::from_timestamp_opt(secs, nanosecs)
                        .map_or("-".to_string(), |s| s.format("%s%.9f").to_string())
                };
                match export_type {
                    "csv" => {
                        writeln!(writer, "{timestamp}\t{source}\t{value}")?;
                    }
                    "json" => {
                        let json_data = value.convert_json_output(timestamp, source.to_string())?;
                        let json_data = serde_json::to_string(&json_data)?;
                        writeln!(writer, "{json_data}")?;
                    }
                    _ => {}
                }
            }
            Ok(false) | Err(_) => {}
        }
    }
    Ok(format!("export file success: {path:?}"))
}

fn export_key_prefix(source_id: &str, kind: &Option<String>) -> Vec<u8> {
    let mut prefix = Vec::new();
    prefix.extend_from_slice(source_id.as_bytes());
    prefix.push(0);
    if let Some(kind_val) = kind {
        prefix.extend_from_slice(kind_val.as_bytes());
        prefix.push(0);
    }
    prefix
}

fn parse_key(key: &[u8]) -> anyhow::Result<(Cow<str>, i64)> {
    if let Some(pos) = key.iter().position(|x| *x == 0) {
        if let Some(s) = key.get(..pos) {
            let source = String::from_utf8_lossy(s);
            if let Some(t) = key.get(key.len() - 8..) {
                let timestamp = i64::from_be_bytes(t.try_into()?);
                return Ok((source, timestamp));
            };
        }
    }
    Err(anyhow!("Invalid key"))
}

fn to_vec_string<T>(vec: &Vec<T>) -> Vec<String>
where
    T: Display,
{
    if vec.is_empty() {
        vec!["-".to_string()]
    } else {
        vec.iter().map(ToString::to_string).collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;
    use crate::storage::RawEventStore;
    use chrono::{Duration, Utc};
    use giganto_client::ingest::{
        log::{Log, OpLogLevel, Oplog},
        network::{
            Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
        },
        timeseries::PeriodicTimeSeries,
    };
    use std::mem;
    use std::net::IpAddr;

    #[tokio::test]
    async fn invalid_query() {
        let schema = TestSchema::new();

        // invalid filter combine1 (log + addr)
        let query = r#"
        {
            export(
                filter:{
                    protocol: "log",
                    sourceId: "src3",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "null");

        // invalid filter combine2 (network proto + kind)
        let query = r#"
        {
            export(
                filter:{
                    protocol: "conn",
                    sourceId: "src3",
                    kind: "log1"
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "null");

        // invalid export format
        let query = r#"
        {
            export(
                filter:{
                    protocol: "conn",
                    sourceId: "src3",
                }
                ,exportType:"ppt")
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "null");

        // invalid protocol format
        let query = r#"
         {
             export(
                 filter:{
                     protocol: "invalid_proto",
                     sourceId: "src3",
                 }
                 ,exportType:"json")
         }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "null");
    }

    #[tokio::test]
    async fn export_conn() {
        let schema = TestSchema::new();
        let store = schema.db.conn_store().unwrap();

        insert_conn_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_conn_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "conn",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46378, end: 46379 }
                    respPort: { start: 50, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("conn"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "conn",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46378, end: 46379 }
                    respPort: { start: 50, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("conn"));
    }

    fn insert_conn_raw_event(store: &RawEventStore<Conn>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let tmp_dur = Duration::nanoseconds(12345);
        let conn_body = Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            duration: tmp_dur.num_nanoseconds().unwrap(),
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
        };
        let ser_conn_body = bincode::serialize(&conn_body).unwrap();

        store.append(&key, &ser_conn_body).unwrap();
    }

    #[tokio::test]
    async fn export_dns() {
        let schema = TestSchema::new();
        let store = schema.db.dns_store().unwrap();

        insert_dns_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_dns_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "dns",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("dns"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "dns",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("dns"));
    }

    fn insert_dns_raw_event(store: &RawEventStore<Dns>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let dns_body = Dns {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            query: "Hello Server Hello Server Hello Server".to_string(),
            answer: vec!["1.1.1.1".to_string()],
            trans_id: 1,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![1; 5],
        };
        let ser_dns_body = bincode::serialize(&dns_body).unwrap();

        store.append(&key, &ser_dns_body).unwrap();
    }

    #[tokio::test]
    async fn export_http() {
        let schema = TestSchema::new();
        let store = schema.db.http_store().unwrap();

        insert_http_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_http_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "http",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("http"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "http",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("http"));
    }

    fn insert_http_raw_event(store: &RawEventStore<Http>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let http_body = Http {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            last_time: 1,
            method: "POST".to_string(),
            host: "einsis".to_string(),
            uri: "/einsis.gif".to_string(),
            referrer: "einsis.com".to_string(),
            version: String::new(),
            user_agent: "giganto".to_string(),
            request_len: 0,
            response_len: 0,
            status_code: 200,
            status_msg: String::new(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: String::new(),
            cache_control: String::new(),
            orig_filenames: Vec::new(),
            orig_mime_types: Vec::new(),
            resp_filenames: Vec::new(),
            resp_mime_types: Vec::new(),
        };
        let ser_http_body = bincode::serialize(&http_body).unwrap();

        store.append(&key, &ser_http_body).unwrap();
    }

    #[tokio::test]
    async fn export_rdp() {
        let schema = TestSchema::new();
        let store = schema.db.rdp_store().unwrap();

        insert_rdp_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_rdp_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "rdp",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("rdp"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "rdp",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("rdp"));
    }

    fn insert_rdp_raw_event(store: &RawEventStore<Rdp>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let rdp_body = Rdp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            last_time: 1,
            cookie: "rdp_test".to_string(),
        };
        let ser_rdp_body = bincode::serialize(&rdp_body).unwrap();

        store.append(&key, &ser_rdp_body).unwrap();
    }

    #[tokio::test]
    async fn export_smtp() {
        let schema = TestSchema::new();
        let store = schema.db.smtp_store().unwrap();

        insert_smtp_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_smtp_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "smtp",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("smtp"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "smtp",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("smtp"));
    }

    fn insert_smtp_raw_event(store: &RawEventStore<Smtp>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let smtp_body = Smtp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            last_time: 1,
            mailfrom: "mailfrom".to_string(),
            date: "date".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            subject: "subject".to_string(),
            agent: "agent".to_string(),
        };
        let ser_smtp_body = bincode::serialize(&smtp_body).unwrap();

        store.append(&key, &ser_smtp_body).unwrap();
    }

    #[tokio::test]
    async fn export_ntlm() {
        let schema = TestSchema::new();
        let store = schema.db.ntlm_store().unwrap();

        insert_ntlm_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_ntlm_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "ntlm",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46378, end: 46379 }
                    respPort: { start: 50, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("ntlm"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "ntlm",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46378, end: 46379 }
                    respPort: { start: 50, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("ntlm"));
    }

    fn insert_ntlm_raw_event(store: &RawEventStore<Ntlm>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let ntlm_body = Ntlm {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            last_time: 1,
            username: "bly".to_string(),
            hostname: "host".to_string(),
            domainname: "domain".to_string(),
            server_nb_computer_name: "NB".to_string(),
            server_dns_computer_name: "dns".to_string(),
            server_tree_name: "tree".to_string(),
            success: "tf".to_string(),
        };
        let ser_ntlm_body = bincode::serialize(&ntlm_body).unwrap();

        store.append(&key, &ser_ntlm_body).unwrap();
    }

    #[tokio::test]
    async fn export_kerberos() {
        let schema = TestSchema::new();
        let store = schema.db.kerberos_store().unwrap();

        insert_kerberos_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_kerberos_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "kerberos",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46378, end: 46379 }
                    respPort: { start: 50, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("kerberos"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "kerberos",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46378, end: 46379 }
                    respPort: { start: 50, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("kerberos"));
    }

    fn insert_kerberos_raw_event(store: &RawEventStore<Kerberos>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let kerberos_body = Kerberos {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            last_time: 1,
            request_type: "req_type".to_string(),
            client: "client".to_string(),
            service: "service".to_string(),
            success: "tf".to_string(),
            error_msg: "err_msg".to_string(),
            from: 5454,
            till: 2345,
            cipher: "cipher".to_string(),
            forwardable: "forwardable".to_string(),
            renewable: "renewable".to_string(),
            client_cert_subject: "client_cert".to_string(),
            server_cert_subject: "server_cert".to_string(),
        };
        let ser_kerberos_body = bincode::serialize(&kerberos_body).unwrap();

        store.append(&key, &ser_kerberos_body).unwrap();
    }

    #[tokio::test]
    async fn export_ssh() {
        let schema = TestSchema::new();
        let store = schema.db.ssh_store().unwrap();

        insert_ssh_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_ssh_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "ssh",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("ssh"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "ssh",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("ssh"));
    }
    fn insert_ssh_raw_event(store: &RawEventStore<Ssh>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let ssh_body = Ssh {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            last_time: 1,
            version: 01,
            auth_success: "auth_success".to_string(),
            auth_attempts: 3,
            direction: "direction".to_string(),
            client: "client".to_string(),
            server: "server".to_string(),
            cipher_alg: "cipher_alg".to_string(),
            mac_alg: "mac_alg".to_string(),
            compression_alg: "compression_alg".to_string(),
            kex_alg: "kex_alg".to_string(),
            host_key_alg: "host_key_alg".to_string(),
            host_key: "host_key".to_string(),
        };
        let ser_ssh_body = bincode::serialize(&ssh_body).unwrap();

        store.append(&key, &ser_ssh_body).unwrap();
    }

    #[tokio::test]
    async fn export_dce_rpc() {
        let schema = TestSchema::new();
        let store = schema.db.dce_rpc_store().unwrap();

        insert_dce_rpc_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_dce_rpc_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "dce rpc",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("dcerpc"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "dce rpc",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("dcerpc"));
    }
    fn insert_dce_rpc_raw_event(store: &RawEventStore<DceRpc>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let dce_rpc_body = DceRpc {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            last_time: 1,
            rtt: 3,
            named_pipe: "named_pipe".to_string(),
            endpoint: "endpoint".to_string(),
            operation: "operation".to_string(),
        };
        let ser_dce_rpc_body = bincode::serialize(&dce_rpc_body).unwrap();

        store.append(&key, &ser_dce_rpc_body).unwrap();
    }

    #[tokio::test]
    async fn export_log() {
        let schema = TestSchema::new();
        let store = schema.db.log_store().unwrap();

        insert_log_raw_event(
            &store,
            "src1",
            Utc::now().timestamp_nanos(),
            "kind1",
            b"log1",
        );
        insert_log_raw_event(
            &store,
            "src2",
            Utc::now().timestamp_nanos(),
            "kind2",
            b"log2",
        );

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "log",
                    sourceId: "src1",
                    kind: "kind1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("log"));

        // export json file
        let query = r#"
                {
                    export(
                        filter:{
                            protocol: "log",
                            sourceId: "src2",
                            kind: "kind2",
                            time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                        }
                        ,exportType:"json")
                }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("log"));
    }

    fn insert_log_raw_event(
        store: &RawEventStore<Log>,
        source: &str,
        timestamp: i64,
        kind: &str,
        body: &[u8],
    ) {
        let mut key: Vec<u8> = Vec::new();
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend_from_slice(kind.as_bytes());
        key.push(0);
        key.extend_from_slice(&timestamp.to_be_bytes());
        let log_body = Log {
            kind: kind.to_string(),
            log: body.to_vec(),
        };
        let value = bincode::serialize(&log_body).unwrap();
        store.append(&key, &value).unwrap();
    }

    #[tokio::test]
    async fn export_time_series() {
        let schema = TestSchema::new();
        let store = schema.db.periodic_time_series_store().unwrap();

        insert_time_series(&store, "1", Utc::now().timestamp_nanos(), vec![0.0; 12]);
        insert_time_series(&store, "2", Utc::now().timestamp_nanos(), vec![0.0; 12]);

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "periodic time series",
                    sourceId: "1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("periodictimeseries"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "periodic time series",
                    sourceId: "2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("periodictimeseries"));
    }

    fn insert_time_series(
        store: &RawEventStore<PeriodicTimeSeries>,
        id: &str,
        start: i64,
        data: Vec<f64>,
    ) {
        let mut key: Vec<u8> = Vec::new();
        key.extend_from_slice(id.as_bytes());
        key.push(0);
        key.extend_from_slice(&start.to_be_bytes());
        let time_series_data = PeriodicTimeSeries {
            id: id.to_string(),
            data,
        };
        let value = bincode::serialize(&time_series_data).unwrap();
        store.append(&key, &value).unwrap();
    }

    #[tokio::test]
    async fn export_oplog() {
        let schema = TestSchema::new();
        let store = schema.db.oplog_store().unwrap();

        insert_oplog_raw_event(&store, "agent1", 1);
        insert_oplog_raw_event(&store, "agent2", 1);

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "oplog",
                    sourceId: "agent1@src 1",
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("oplog"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "oplog",
                    sourceId: "agent2@src 1",
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("oplog"));
    }

    fn insert_oplog_raw_event(store: &RawEventStore<Oplog>, agent_name: &str, timestamp: i64) {
        let mut key: Vec<u8> = Vec::new();
        let agent_id = format!("{agent_name}@src 1");
        key.extend_from_slice(agent_id.as_bytes());
        key.push(0);
        key.extend_from_slice(&timestamp.to_be_bytes());

        let oplog_body = Oplog {
            agent_name: agent_id.to_string(),
            log_level: OpLogLevel::Info,
            contents: "oplog".to_string(),
        };

        let value = bincode::serialize(&oplog_body).unwrap();

        store.append(&key, &value).unwrap();
    }

    #[tokio::test]
    async fn export_ftp() {
        let schema = TestSchema::new();
        let store = schema.db.ftp_store().unwrap();

        insert_ftp_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_ftp_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "ftp",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("ftp"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "ftp",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("ftp"));
    }

    fn insert_ftp_raw_event(store: &RawEventStore<Ftp>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let ftp_body = Ftp {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            user: "einsis".to_string(),
            password: "aice".to_string(),
            command: "command".to_string(),
            reply_code: "500".to_string(),
            reply_msg: "reply_message".to_string(),
            data_passive: false,
            data_orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            data_resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            data_resp_port: 80,
            file: "ftp_file".to_string(),
            file_size: 100,
            file_id: "1".to_string(),
        };
        let ser_ftp_body = bincode::serialize(&ftp_body).unwrap();

        store.append(&key, &ser_ftp_body).unwrap();
    }

    #[tokio::test]
    async fn export_mqtt() {
        let schema = TestSchema::new();
        let store = schema.db.mqtt_store().unwrap();

        insert_mqtt_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_mqtt_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "mqtt",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("mqtt"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "mqtt",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("mqtt"));
    }

    fn insert_mqtt_raw_event(store: &RawEventStore<Mqtt>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let mqtt_body = Mqtt {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            protocol: "protocol".to_string(),
            version: 1,
            client_id: "client".to_string(),
            connack_reason: 1,
            subscribe: vec!["subscribe".to_string()],
            suback_reason: vec![1],
        };
        let ser_mqtt_body = bincode::serialize(&mqtt_body).unwrap();

        store.append(&key, &ser_mqtt_body).unwrap();
    }

    #[tokio::test]
    async fn export_ldap() {
        let schema = TestSchema::new();
        let store = schema.db.ldap_store().unwrap();

        insert_ldap_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_ldap_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "ldap",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("ldap"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "ldap",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("ldap"));
    }

    fn insert_ldap_raw_event(store: &RawEventStore<Ldap>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let ldap_body = Ldap {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            message_id: 1,
            version: 1,
            opcode: vec!["opcode".to_string()],
            result: vec!["result".to_string()],
            diagnostic_message: Vec::new(),
            object: Vec::new(),
            argument: Vec::new(),
        };
        let ser_ldap_body = bincode::serialize(&ldap_body).unwrap();

        store.append(&key, &ser_ldap_body).unwrap();
    }

    #[tokio::test]
    async fn export_tls() {
        let schema = TestSchema::new();
        let store = schema.db.tls_store().unwrap();

        insert_tls_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_tls_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "tls",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("tls"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "tls",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("tls"));
    }

    fn insert_tls_raw_event(store: &RawEventStore<Tls>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let tls_body = Tls {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            server_name: "server_name".to_string(),
            alpn_protocol: "alpn_protocol".to_string(),
            ja3: "ja3".to_string(),
            version: "version".to_string(),
            cipher: 10,
            ja3s: "ja3s".to_string(),
            serial: "serial".to_string(),
            subject_country: "sub_contry".to_string(),
            subject_org_name: "sub_org".to_string(),
            subject_common_name: "sub_comm".to_string(),
            validity_not_before: 11,
            validity_not_after: 12,
            subject_alt_name: "sub_alt".to_string(),
            issuer_country: "issuer_contry".to_string(),
            issuer_org_name: "issuer_org".to_string(),
            issuer_org_unit_name: "issuer_org_unit".to_string(),
            issuer_common_name: "issuer_comm".to_string(),
            last_alert: 13,
        };
        let ser_tls_body = bincode::serialize(&tls_body).unwrap();

        store.append(&key, &ser_tls_body).unwrap();
    }

    #[tokio::test]
    async fn export_smb() {
        let schema = TestSchema::new();
        let store = schema.db.smb_store().unwrap();

        insert_smb_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_smb_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "smb",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("smb"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "smb",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("smb"));
    }

    fn insert_smb_raw_event(store: &RawEventStore<Smb>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let smb_body = Smb {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            command: 0,
            path: "something/path".to_string(),
            service: "sevice".to_string(),
            file_name: "fine_name".to_string(),
            file_size: 10,
            resource_type: 20,
            fid: 30,
            create_time: 10000000,
            access_time: 20000000,
            write_time: 10000000,
            change_time: 20000000,
        };
        let ser_smb_body = bincode::serialize(&smb_body).unwrap();

        store.append(&key, &ser_smb_body).unwrap();
    }

    #[tokio::test]
    async fn export_nfs() {
        let schema = TestSchema::new();
        let store = schema.db.nfs_store().unwrap();

        insert_nfs_raw_event(&store, "src1", Utc::now().timestamp_nanos());
        insert_nfs_raw_event(&store, "src2", Utc::now().timestamp_nanos());

        // export csv file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "nfs",
                    sourceId: "src1",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"csv")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("nfs"));

        // export json file
        let query = r#"
        {
            export(
                filter:{
                    protocol: "nfs",
                    sourceId: "src2",
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                    origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 0, end: 200 }
                }
                ,exportType:"json")
        }"#;
        let res = schema.execute(query).await;
        assert!(res.data.to_string().contains("nfs"));
    }

    fn insert_nfs_raw_event(store: &RawEventStore<Nfs>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let nfs_body = Nfs {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 17,
            last_time: 1,
            read_files: vec![],
            write_files: vec![],
        };
        let ser_nfs_body = bincode::serialize(&nfs_body).unwrap();

        store.append(&key, &ser_nfs_body).unwrap();
    }
}
