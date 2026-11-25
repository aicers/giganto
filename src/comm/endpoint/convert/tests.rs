use std::collections::BTreeMap;

use pretty_assertions::assert_eq;
use senta_protocol::{
    host::OsInfo,
    telemetry::{ProcessKey, RecordBody},
};

use super::*;

const ENDPOINT_ID: Uuid = Uuid::from_u128(0x0b1c_2d3e_4f50_6172_8394_a5b6_c7d8_e9f0);
const ENDPOINT_ID_TEXT: &str = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0";
const STREAM: Uuid = Uuid::from_u128(0xf0e9_d8c7_b6a5_4493_8271_605f_4e3d_2c1b);
const SEQ: u64 = 42;
const HOSTNAME: &str = "host-01";
const OS_VERSION: &str = "10.0.22631";
const EVENT_TIME: i64 = 1_700_000_000_123_456_789;
const COLLECTED_AT: i64 = 1_700_000_001_000_000_001;
const MEASURED_AT: i64 = 1_699_999_990_000_000_002;
const PROCESS_KEY: [u8; 4] = [0x00, 0xab, 0x0f, 0xff];
const SCHEMA: u16 = 1;

const GUID_A: Uuid = Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
const GUID_A_TEXT: &str = "{01020304-0506-0708-090A-0B0C0D0E0F10}";
const GUID_B: Uuid = Uuid::from_u128(0xa1b2_c3d4_e5f6_0718_293a_4b5c_6d7e_8f90);
const GUID_B_TEXT: &str = "{A1B2C3D4-E5F6-0718-293A-4B5C6D7E8F90}";
const GUID_C: Uuid = Uuid::from_u128(0xdead_beef_0000_1111_2222_3333_4444_5555);
const GUID_C_TEXT: &str = "{DEADBEEF-0000-1111-2222-333344445555}";

const TIME_A: i64 = 1_600_000_000_000_000_001;
const TIME_B: i64 = 1_500_000_000_999_999_999;

fn ts(nanos: i64) -> Timestamp {
    Timestamp::from_nanosecond(i128::from(nanos)).expect("a time in range")
}

// A body field's value, which is always optional.
#[expect(clippy::unnecessary_wraps)]
fn s(value: &str) -> Option<String> {
    Some(value.to_owned())
}

fn header() -> RecordHeader {
    RecordHeader {
        endpoint_id: ENDPOINT_ID,
        stream: STREAM,
        seq: SEQ,
        event_time: ts(EVENT_TIME),
        collected_at: ts(COLLECTED_AT),
        clock_offset: Some(SentaClockOffset {
            offset_ms: -15,
            uncertainty_ms: 3,
            measured_at: ts(MEASURED_AT),
        }),
        hostname: HOSTNAME.to_owned(),
        ips: vec![
            "192.0.2.10".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ],
        default_route_ip: Some("192.0.2.10".parse().unwrap()),
        net_state_source: SentaNetStateSource::Observed,
        os: OsInfo {
            family: SentaOsFamily::Windows,
            version: OS_VERSION.to_owned(),
        },
        collection_mode: SentaCollectionMode::Extended,
        process_key: Some(ProcessKey {
            os: SentaOsFamily::Windows,
            value: PROCESS_KEY.to_vec(),
        }),
    }
}

fn expected_header() -> EndpointHeader {
    EndpointHeader {
        endpoint_id: ENDPOINT_ID,
        stream: STREAM,
        seq: SEQ,
        event_time: EVENT_TIME,
        collected_at: COLLECTED_AT,
        clock_offset: Some(ClockOffset {
            offset_ms: -15,
            uncertainty_ms: 3,
            measured_at: MEASURED_AT,
        }),
        hostname: HOSTNAME.to_owned(),
        ips: vec![
            "192.0.2.10".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ],
        default_route_ip: Some("192.0.2.10".parse().unwrap()),
        net_state_source: NetStateSource::Observed,
        os_family: OsFamily::Windows,
        os_version: OS_VERSION.to_owned(),
        collection_mode: CollectionMode::Extended,
        process_key: Some(PROCESS_KEY.to_vec()),
        schema: SCHEMA,
    }
}

/// A log record's header: a log kind carries no process key.
fn log_header() -> RecordHeader {
    RecordHeader {
        process_key: None,
        ..header()
    }
}

fn expected_log_header() -> EndpointHeader {
    EndpointHeader {
        process_key: None,
        ..expected_header()
    }
}

fn record(kind: u16, body: RecordBody) -> Record {
    Record {
        header: header(),
        kind,
        schema: SCHEMA,
        body,
    }
}

fn sysmon_record(body: impl Into<sysmon::Body>) -> Record {
    let body = body.into();
    record(
        body.kind(),
        body.to_record_body().expect("the body encodes"),
    )
}

fn log_record(body: &logs::LogBody) -> Record {
    Record {
        header: log_header(),
        ..record(body.kind(), body.to_body().expect("the body encodes"))
    }
}

fn agent_name() -> String {
    HOSTNAME.to_owned()
}

fn agent_id() -> String {
    ENDPOINT_ID_TEXT.to_owned()
}

/// Converts `record` and checks the result's kind, sensor and time.
fn convert_ok(record: Record, kind: RawEventKind) -> EndpointEvent {
    let converted = convert(record).expect("the record converts");
    assert_eq!(converted.kind(), kind);
    assert_eq!(converted.sensor, ENDPOINT_ID_TEXT);
    assert_eq!(converted.timestamp, EVENT_TIME);
    converted.event
}

// The value of a body's `hashes`, which is always optional.
#[expect(clippy::unnecessary_wraps)]
fn full_hashes() -> Option<Vec<HashEntry>> {
    Some(vec![
        HashEntry {
            algo: "SHA1".to_owned(),
            value: vec![0xab, 0xcd, 0x01],
        },
        HashEntry {
            algo: "MD5".to_owned(),
            value: vec![0x0f, 0xa0],
        },
    ])
}

fn expected_hashes() -> Vec<String> {
    vec!["SHA1=ABCD01".to_owned(), "MD5=0FA0".to_owned()]
}

// ---------------------------------------------------------------------------
// Every field of every kind
// ---------------------------------------------------------------------------

#[test]
fn process_create_converts_every_field() {
    let body = sysmon::ProcessCreate {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(4242),
        image: s(r"C:\Windows\System32\cmd.exe"),
        file_version: s("10.0.1"),
        description: s("Windows Command Processor"),
        product: s("Microsoft Windows"),
        company: s("Microsoft Corporation"),
        original_file_name: s("Cmd.Exe"),
        command_line: s("cmd.exe /c dir"),
        current_directory: s(r"C:\Users\a\"),
        user: s(r"HOST\a"),
        logon_guid: Some(GUID_B),
        logon_id: Some(0x3e7),
        terminal_session_id: Some(1),
        integrity_level: s("High"),
        hashes: full_hashes(),
        parent_process_guid: Some(GUID_C),
        parent_process_id: Some(1000),
        parent_image: s(r"C:\Windows\explorer.exe"),
        parent_command_line: s("explorer.exe"),
        parent_user: s(r"HOST\b"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::ProcessCreate),
        EndpointEvent::ProcessCreate(Box::new(ProcessCreate {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 4242,
            image: r"C:\Windows\System32\cmd.exe".to_owned(),
            file_version: "10.0.1".to_owned(),
            description: "Windows Command Processor".to_owned(),
            product: "Microsoft Windows".to_owned(),
            company: "Microsoft Corporation".to_owned(),
            original_file_name: "Cmd.Exe".to_owned(),
            command_line: "cmd.exe /c dir".to_owned(),
            current_directory: r"C:\Users\a\".to_owned(),
            user: r"HOST\a".to_owned(),
            logon_guid: GUID_B_TEXT.to_owned(),
            logon_id: 0x3e7,
            terminal_session_id: 1,
            integrity_level: "High".to_owned(),
            hashes: expected_hashes(),
            parent_process_guid: GUID_C_TEXT.to_owned(),
            parent_process_id: 1000,
            parent_image: r"C:\Windows\explorer.exe".to_owned(),
            parent_command_line: "explorer.exe".to_owned(),
            parent_user: r"HOST\b".to_owned(),
            endpoint: Some(expected_header()),
            logon_id_full: Some(0x3e7),
        }))
    );
}

#[test]
fn file_create_time_converts_every_field() {
    let body = sysmon::FileCreateTime {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(7),
        image: s("a.exe"),
        target_filename: s(r"C:\t.txt"),
        creation_utc_time: Some(ts(TIME_A)),
        previous_creation_utc_time: Some(ts(TIME_B)),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::FileCreateTime),
        EndpointEvent::FileCreateTime(Box::new(FileCreationTimeChanged {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 7,
            image: "a.exe".to_owned(),
            target_filename: r"C:\t.txt".to_owned(),
            creation_utc_time: TIME_A,
            previous_creation_utc_time: TIME_B,
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn network_connect_converts_every_field() {
    let body = sysmon::NetworkConnect {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(8),
        image: s("b.exe"),
        user: s("u"),
        protocol: s("tcp"),
        initiated: Some(true),
        source_is_ipv6: Some(false),
        source_ip: Some("192.0.2.1".parse().unwrap()),
        source_hostname: s("src"),
        source_port: Some(50_000),
        source_port_name: s("sp"),
        destination_is_ipv6: Some(true),
        destination_ip: Some("2001:db8::2".parse().unwrap()),
        destination_hostname: s("dst"),
        destination_port: Some(443),
        destination_port_name: s("https"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::NetworkConnect),
        EndpointEvent::NetworkConnect(Box::new(NetworkConnection {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 8,
            image: "b.exe".to_owned(),
            user: "u".to_owned(),
            protocol: "tcp".to_owned(),
            initiated: true,
            source_is_ipv6: false,
            source_ip: "192.0.2.1".parse().unwrap(),
            source_hostname: "src".to_owned(),
            source_port: 50_000,
            source_port_name: "sp".to_owned(),
            destination_is_ipv6: true,
            destination_ip: "2001:db8::2".parse().unwrap(),
            destination_hostname: "dst".to_owned(),
            destination_port: 443,
            destination_port_name: "https".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn process_terminate_converts_every_field() {
    let body = sysmon::ProcessTerminate {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(9),
        image: s("c.exe"),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::ProcessTerminate),
        EndpointEvent::ProcessTerminate(Box::new(ProcessTerminated {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 9,
            image: "c.exe".to_owned(),
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn driver_load_converts_every_field() {
    let body = sysmon::DriverLoad {
        rule_name: s("rule"),
        image_loaded: s(r"C:\d.sys"),
        hashes: full_hashes(),
        signed: s("true"),
        signature: s("Microsoft Windows"),
        signature_status: s("Valid"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::DriverLoad),
        EndpointEvent::DriverLoad(Box::new(DriverLoad {
            agent_name: agent_name(),
            agent_id: agent_id(),
            image_loaded: r"C:\d.sys".to_owned(),
            hashes: expected_hashes(),
            signed: true,
            signature: "Microsoft Windows".to_owned(),
            signature_status: "Valid".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn image_load_converts_every_field() {
    let body = sysmon::ImageLoad {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(10),
        image: s("d.exe"),
        image_loaded: s("e.dll"),
        file_version: s("1.2"),
        description: s("desc"),
        product: s("prod"),
        company: s("comp"),
        original_file_name: s("E.DLL"),
        hashes: full_hashes(),
        signed: s("TRUE"),
        signature: s("sig"),
        signature_status: s("Valid"),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::ImageLoad),
        EndpointEvent::ImageLoad(Box::new(ImageLoaded {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 10,
            image: "d.exe".to_owned(),
            image_loaded: "e.dll".to_owned(),
            file_version: "1.2".to_owned(),
            description: "desc".to_owned(),
            product: "prod".to_owned(),
            company: "comp".to_owned(),
            original_file_name: "E.DLL".to_owned(),
            hashes: expected_hashes(),
            signed: true,
            signature: "sig".to_owned(),
            signature_status: "Valid".to_owned(),
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn create_remote_thread_converts_every_field() {
    let body = sysmon::CreateRemoteThread {
        rule_name: s("rule"),
        source_process_guid: Some(GUID_A),
        source_process_id: Some(11),
        source_image: s("src.exe"),
        target_process_guid: Some(GUID_B),
        target_process_id: Some(12),
        target_image: s("dst.exe"),
        new_thread_id: Some(13),
        start_address: s("0xFFFF8000"),
        start_module: s("mod.dll"),
        start_function: s("fn"),
        source_user: s("su"),
        target_user: s("tu"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::CreateRemoteThread),
        EndpointEvent::CreateRemoteThread(Box::new(CreateRemoteThread {
            agent_name: agent_name(),
            agent_id: agent_id(),
            source_process_guid: GUID_A_TEXT.to_owned(),
            source_process_id: 11,
            source_image: "src.exe".to_owned(),
            target_process_guid: GUID_B_TEXT.to_owned(),
            target_process_id: 12,
            target_image: "dst.exe".to_owned(),
            new_thread_id: 13,
            start_address: "0xFFFF8000".to_owned(),
            start_module: "mod.dll".to_owned(),
            start_function: "fn".to_owned(),
            source_user: "su".to_owned(),
            target_user: "tu".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn raw_access_read_converts_every_field() {
    let body = sysmon::RawAccessRead {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(14),
        image: s("f.exe"),
        device: s(r"\Device\HarddiskVolume1"),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::RawAccessRead),
        EndpointEvent::RawAccessRead(Box::new(RawAccessRead {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 14,
            image: "f.exe".to_owned(),
            device: r"\Device\HarddiskVolume1".to_owned(),
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn process_access_converts_every_field() {
    let body = sysmon::ProcessAccess {
        rule_name: s("rule"),
        source_process_guid: Some(GUID_A),
        source_process_id: Some(15),
        source_thread_id: Some(16),
        source_image: s("src.exe"),
        target_process_guid: Some(GUID_B),
        target_process_id: Some(17),
        target_image: s("dst.exe"),
        granted_access: Some(0x1_0000_1410),
        call_trace: s("ntdll.dll+1"),
        source_user: s("su"),
        target_user: s("tu"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::ProcessAccess),
        EndpointEvent::ProcessAccess(Box::new(ProcessAccess {
            agent_name: agent_name(),
            agent_id: agent_id(),
            source_process_guid: GUID_A_TEXT.to_owned(),
            source_process_id: 15,
            source_thread_id: 16,
            source_image: "src.exe".to_owned(),
            target_process_guid: GUID_B_TEXT.to_owned(),
            target_process_id: 17,
            target_image: "dst.exe".to_owned(),
            granted_access: 0x1_0000_1410,
            call_trace: "ntdll.dll+1".to_owned(),
            source_user: "su".to_owned(),
            target_user: "tu".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn file_create_converts_every_field() {
    let body = sysmon::FileCreate {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(18),
        image: s("g.exe"),
        target_filename: s("t.txt"),
        creation_utc_time: Some(ts(TIME_A)),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::FileCreate),
        EndpointEvent::FileCreate(Box::new(FileCreate {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 18,
            image: "g.exe".to_owned(),
            target_filename: "t.txt".to_owned(),
            creation_utc_time: TIME_A,
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn registry_add_delete_converts_every_field() {
    let body = sysmon::RegistryAddDelete {
        rule_name: s("rule"),
        event_type: s("CreateKey"),
        process_guid: Some(GUID_A),
        process_id: Some(19),
        image: s("h.exe"),
        target_object: s(r"HKLM\Software\k"),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::RegistryObjectAddDel),
        EndpointEvent::RegistryObjectAddDel(Box::new(RegistryObjectAddDel {
            agent_name: agent_name(),
            agent_id: agent_id(),
            event_type: "CreateKey".to_owned(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 19,
            image: "h.exe".to_owned(),
            target_object: r"HKLM\Software\k".to_owned(),
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn registry_value_set_converts_every_field() {
    let body = sysmon::RegistryValueSet {
        rule_name: s("rule"),
        event_type: s("SetValue"),
        process_guid: Some(GUID_A),
        process_id: Some(20),
        image: s("i.exe"),
        target_object: s(r"HKLM\Software\v"),
        details: s("DWORD (0x00000001)"),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::RegistryValueSet),
        EndpointEvent::RegistryValueSet(Box::new(RegistryValueSet {
            agent_name: agent_name(),
            agent_id: agent_id(),
            event_type: "SetValue".to_owned(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 20,
            image: "i.exe".to_owned(),
            target_object: r"HKLM\Software\v".to_owned(),
            details: "DWORD (0x00000001)".to_owned(),
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn registry_rename_converts_every_field() {
    let body = sysmon::RegistryRename {
        rule_name: s("rule"),
        event_type: s("RenameKey"),
        process_guid: Some(GUID_A),
        process_id: Some(21),
        image: s("j.exe"),
        target_object: s(r"HKLM\old"),
        new_name: s(r"HKLM\new"),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::RegistryKeyRename),
        EndpointEvent::RegistryKeyRename(Box::new(RegistryKeyValueRename {
            agent_name: agent_name(),
            agent_id: agent_id(),
            event_type: "RenameKey".to_owned(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 21,
            image: "j.exe".to_owned(),
            target_object: r"HKLM\old".to_owned(),
            new_name: r"HKLM\new".to_owned(),
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn file_create_stream_hash_converts_every_field() {
    let body = sysmon::FileCreateStreamHash {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(22),
        image: s("k.exe"),
        target_filename: s("t.txt:Zone.Identifier"),
        creation_utc_time: Some(ts(TIME_A)),
        hash: s("SHA256=9f86d0,IMPHASH=00ab"),
        contents: s("[ZoneTransfer] ZoneId=3"),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::FileCreateStreamHash),
        EndpointEvent::FileCreateStreamHash(Box::new(FileCreateStreamHash {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 22,
            image: "k.exe".to_owned(),
            target_filename: "t.txt:Zone.Identifier".to_owned(),
            creation_utc_time: TIME_A,
            hash: vec!["SHA256=9f86d0,IMPHASH=00ab".to_owned()],
            contents: "[ZoneTransfer] ZoneId=3".to_owned(),
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn pipe_created_converts_every_field() {
    let body = sysmon::PipeCreated {
        rule_name: s("rule"),
        event_type: s("CreatePipe"),
        process_guid: Some(GUID_A),
        process_id: Some(23),
        pipe_name: s(r"\pipe\p"),
        image: s("l.exe"),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::PipeEvent),
        EndpointEvent::PipeEvent(Box::new(PipeEvent {
            agent_name: agent_name(),
            agent_id: agent_id(),
            event_type: "CreatePipe".to_owned(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 23,
            pipe_name: r"\pipe\p".to_owned(),
            image: "l.exe".to_owned(),
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn dns_query_converts_every_field() {
    let body = sysmon::DnsQuery {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(24),
        query_name: s("example.com"),
        query_status: s("9003"),
        query_results: s("type:  5 a.example;::ffff:192.0.2.3;"),
        image: s("m.exe"),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::DnsQuery),
        EndpointEvent::DnsQuery(Box::new(DnsEvent {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 24,
            query_name: "example.com".to_owned(),
            query_status: 9003,
            query_results: vec![
                "type:  5 a.example".to_owned(),
                "::ffff:192.0.2.3".to_owned(),
                String::new(),
            ],
            image: "m.exe".to_owned(),
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn file_delete_converts_every_field() {
    let body = sysmon::FileDelete {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(25),
        user: s("u"),
        image: s("n.exe"),
        target_filename: s("gone.txt"),
        hashes: full_hashes(),
        is_executable: Some(true),
        archived: s("True"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::FileDelete),
        EndpointEvent::FileDelete(Box::new(FileDelete {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 25,
            user: "u".to_owned(),
            image: "n.exe".to_owned(),
            target_filename: "gone.txt".to_owned(),
            hashes: expected_hashes(),
            is_executable: true,
            archived: true,
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn process_tampering_converts_every_field() {
    let body = sysmon::ProcessTampering {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(26),
        image: s("o.exe"),
        r#type: s("Image is replaced"),
        user: s("u"),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::ProcessTamper),
        EndpointEvent::ProcessTamper(Box::new(ProcessTampering {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 26,
            image: "o.exe".to_owned(),
            tamper_type: "Image is replaced".to_owned(),
            user: "u".to_owned(),
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn file_delete_detected_converts_every_field() {
    let body = sysmon::FileDeleteDetected {
        rule_name: s("rule"),
        process_guid: Some(GUID_A),
        process_id: Some(27),
        user: s("u"),
        image: s("p.exe"),
        target_filename: s("gone.exe"),
        hashes: full_hashes(),
        is_executable: Some(true),
    };
    assert_eq!(
        convert_ok(sysmon_record(body), RawEventKind::FileDeleteDetected),
        EndpointEvent::FileDeleteDetected(Box::new(FileDeleteDetected {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: GUID_A_TEXT.to_owned(),
            process_id: 27,
            user: "u".to_owned(),
            image: "p.exe".to_owned(),
            target_filename: "gone.exe".to_owned(),
            hashes: expected_hashes(),
            is_executable: true,
            endpoint: Some(expected_header()),
        }))
    );
}

#[test]
fn windows_event_log_converts_every_field() {
    let body = logs::LogBody::WindowsEventLog(logs::WindowsEventLogBody {
        channel: s("Security"),
        provider: s("Microsoft-Windows-Security-Auditing"),
        event_id: Some(4624),
        version: Some(2),
        level: Some(0),
        task: Some(12544),
        opcode: Some(0),
        keywords: Some(0x8020_0000_0000_0000),
        record_id: Some(123_456),
        computer: s("host-01.example"),
        user_sid: s("S-1-5-18"),
        event_data: Some(vec![
            logs::EventData {
                name: s("SubjectUserSid"),
                value: "S-1-5-18".to_owned(),
            },
            logs::EventData {
                name: None,
                value: "unnamed".to_owned(),
            },
            logs::EventData {
                name: s("Empty"),
                value: String::new(),
            },
        ]),
        user_data_xml: s("<UserData><X/></UserData>"),
    });
    assert_eq!(
        convert_ok(log_record(&body), RawEventKind::WindowsEventLog),
        EndpointEvent::WindowsEventLog(Box::new(WindowsEventLog {
            channel: s("Security"),
            provider: s("Microsoft-Windows-Security-Auditing"),
            event_id: Some(4624),
            version: Some(2),
            level: Some(0),
            task: Some(12544),
            opcode: Some(0),
            keywords: Some(0x8020_0000_0000_0000),
            record_id: Some(123_456),
            computer: s("host-01.example"),
            user_sid: s("S-1-5-18"),
            event_data: Some(vec![
                EventData {
                    name: s("SubjectUserSid"),
                    value: "S-1-5-18".to_owned(),
                },
                EventData {
                    name: None,
                    value: "unnamed".to_owned(),
                },
                EventData {
                    name: s("Empty"),
                    value: String::new(),
                },
            ]),
            user_data_xml: s("<UserData><X/></UserData>"),
            endpoint: expected_log_header(),
        }))
    );
}

#[test]
fn journald_converts_every_field() {
    let body = logs::LogBody::Journald(logs::JournaldBody {
        fields: Some(vec![
            logs::LogField {
                name: "MESSAGE".to_owned(),
                value: logs::LogValue::Text("Started session 3.".to_owned()),
            },
            logs::LogField {
                name: "_BOOT_ID".to_owned(),
                value: logs::LogValue::Bytes(vec![0xff, 0xfe, 0x00]),
            },
            logs::LogField {
                name: "MESSAGE".to_owned(),
                value: logs::LogValue::Text(String::new()),
            },
        ]),
    });
    assert_eq!(
        convert_ok(log_record(&body), RawEventKind::Journald),
        EndpointEvent::Journald(Box::new(Journald {
            fields: Some(vec![
                LogField {
                    name: "MESSAGE".to_owned(),
                    value: LogValue::Text("Started session 3.".to_owned()),
                },
                LogField {
                    name: "_BOOT_ID".to_owned(),
                    value: LogValue::Bytes(vec![0xff, 0xfe, 0x00]),
                },
                LogField {
                    name: "MESSAGE".to_owned(),
                    value: LogValue::Text(String::new()),
                },
            ]),
            endpoint: expected_log_header(),
        }))
    );
}

#[test]
fn auditd_converts_every_field() {
    let body = logs::LogBody::Auditd(logs::AuditdBody {
        serial: Some(31_337),
        records: Some(vec![
            logs::AuditRecord {
                record_type: "SYSCALL".to_owned(),
                fields: vec![
                    logs::LogField {
                        name: "arch".to_owned(),
                        value: logs::LogValue::Text("c000003e".to_owned()),
                    },
                    logs::LogField {
                        name: "syscall".to_owned(),
                        value: logs::LogValue::Text("59".to_owned()),
                    },
                ],
            },
            logs::AuditRecord {
                record_type: "PROCTITLE".to_owned(),
                fields: vec![logs::LogField {
                    name: "proctitle".to_owned(),
                    value: logs::LogValue::Bytes(b"ls\0-l".to_vec()),
                }],
            },
            logs::AuditRecord {
                record_type: "EOE".to_owned(),
                fields: Vec::new(),
            },
        ]),
    });
    assert_eq!(
        convert_ok(log_record(&body), RawEventKind::Auditd),
        EndpointEvent::Auditd(Box::new(Auditd {
            serial: Some(31_337),
            records: Some(vec![
                AuditRecord {
                    record_type: "SYSCALL".to_owned(),
                    fields: vec![
                        LogField {
                            name: "arch".to_owned(),
                            value: LogValue::Text("c000003e".to_owned()),
                        },
                        LogField {
                            name: "syscall".to_owned(),
                            value: LogValue::Text("59".to_owned()),
                        },
                    ],
                },
                AuditRecord {
                    record_type: "PROCTITLE".to_owned(),
                    fields: vec![LogField {
                        name: "proctitle".to_owned(),
                        value: LogValue::Bytes(b"ls\0-l".to_vec()),
                    }],
                },
                AuditRecord {
                    record_type: "EOE".to_owned(),
                    fields: Vec::new(),
                },
            ]),
            endpoint: expected_log_header(),
        }))
    );
}

// ---------------------------------------------------------------------------
// Empty bodies
// ---------------------------------------------------------------------------

/// The struct an empty body of `kind` converts to.
#[allow(clippy::too_many_lines)] // One struct literal per accepted kind.
fn empty_event(kind: u16) -> EndpointEvent {
    let endpoint = Some(expected_header());
    let unspecified = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    match kind {
        kind::SYSMON_PROCESS_CREATE => EndpointEvent::ProcessCreate(Box::new(ProcessCreate {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: String::new(),
            process_id: 0,
            image: String::new(),
            file_version: String::new(),
            description: String::new(),
            product: String::new(),
            company: String::new(),
            original_file_name: String::new(),
            command_line: String::new(),
            current_directory: String::new(),
            user: String::new(),
            logon_guid: String::new(),
            logon_id: 0,
            terminal_session_id: 0,
            integrity_level: String::new(),
            hashes: Vec::new(),
            parent_process_guid: String::new(),
            parent_process_id: 0,
            parent_image: String::new(),
            parent_command_line: String::new(),
            parent_user: String::new(),
            endpoint,
            logon_id_full: None,
        })),
        kind::SYSMON_FILE_CREATE_TIME => {
            EndpointEvent::FileCreateTime(Box::new(FileCreationTimeChanged {
                agent_name: agent_name(),
                agent_id: agent_id(),
                process_guid: String::new(),
                process_id: 0,
                image: String::new(),
                target_filename: String::new(),
                creation_utc_time: 0,
                previous_creation_utc_time: 0,
                user: String::new(),
                endpoint,
            }))
        }
        kind::SYSMON_NETWORK_CONNECT => {
            EndpointEvent::NetworkConnect(Box::new(NetworkConnection {
                agent_name: agent_name(),
                agent_id: agent_id(),
                process_guid: String::new(),
                process_id: 0,
                image: String::new(),
                user: String::new(),
                protocol: String::new(),
                initiated: false,
                source_is_ipv6: false,
                source_ip: unspecified,
                source_hostname: String::new(),
                source_port: 0,
                source_port_name: String::new(),
                destination_is_ipv6: false,
                destination_ip: unspecified,
                destination_hostname: String::new(),
                destination_port: 0,
                destination_port_name: String::new(),
                endpoint,
            }))
        }
        kind::SYSMON_PROCESS_TERMINATE => {
            EndpointEvent::ProcessTerminate(Box::new(ProcessTerminated {
                agent_name: agent_name(),
                agent_id: agent_id(),
                process_guid: String::new(),
                process_id: 0,
                image: String::new(),
                user: String::new(),
                endpoint,
            }))
        }
        kind::SYSMON_DRIVER_LOAD => EndpointEvent::DriverLoad(Box::new(DriverLoad {
            agent_name: agent_name(),
            agent_id: agent_id(),
            image_loaded: String::new(),
            hashes: Vec::new(),
            signed: false,
            signature: String::new(),
            signature_status: String::new(),
            endpoint,
        })),
        kind::SYSMON_IMAGE_LOAD => EndpointEvent::ImageLoad(Box::new(ImageLoaded {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: String::new(),
            process_id: 0,
            image: String::new(),
            image_loaded: String::new(),
            file_version: String::new(),
            description: String::new(),
            product: String::new(),
            company: String::new(),
            original_file_name: String::new(),
            hashes: Vec::new(),
            signed: false,
            signature: String::new(),
            signature_status: String::new(),
            user: String::new(),
            endpoint,
        })),
        kind::SYSMON_CREATE_REMOTE_THREAD => {
            EndpointEvent::CreateRemoteThread(Box::new(CreateRemoteThread {
                agent_name: agent_name(),
                agent_id: agent_id(),
                source_process_guid: String::new(),
                source_process_id: 0,
                source_image: String::new(),
                target_process_guid: String::new(),
                target_process_id: 0,
                target_image: String::new(),
                new_thread_id: 0,
                start_address: String::new(),
                start_module: String::new(),
                start_function: String::new(),
                source_user: String::new(),
                target_user: String::new(),
                endpoint,
            }))
        }
        kind::SYSMON_RAW_ACCESS_READ => EndpointEvent::RawAccessRead(Box::new(RawAccessRead {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: String::new(),
            process_id: 0,
            image: String::new(),
            device: String::new(),
            user: String::new(),
            endpoint,
        })),
        kind::SYSMON_PROCESS_ACCESS => EndpointEvent::ProcessAccess(Box::new(ProcessAccess {
            agent_name: agent_name(),
            agent_id: agent_id(),
            source_process_guid: String::new(),
            source_process_id: 0,
            source_thread_id: 0,
            source_image: String::new(),
            target_process_guid: String::new(),
            target_process_id: 0,
            target_image: String::new(),
            granted_access: 0,
            call_trace: String::new(),
            source_user: String::new(),
            target_user: String::new(),
            endpoint,
        })),
        kind::SYSMON_FILE_CREATE => EndpointEvent::FileCreate(Box::new(FileCreate {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: String::new(),
            process_id: 0,
            image: String::new(),
            target_filename: String::new(),
            creation_utc_time: 0,
            user: String::new(),
            endpoint,
        })),
        kind::SYSMON_REGISTRY_ADD_DELETE => {
            EndpointEvent::RegistryObjectAddDel(Box::new(RegistryObjectAddDel {
                agent_name: agent_name(),
                agent_id: agent_id(),
                event_type: String::new(),
                process_guid: String::new(),
                process_id: 0,
                image: String::new(),
                target_object: String::new(),
                user: String::new(),
                endpoint,
            }))
        }
        kind::SYSMON_REGISTRY_VALUE_SET => {
            EndpointEvent::RegistryValueSet(Box::new(RegistryValueSet {
                agent_name: agent_name(),
                agent_id: agent_id(),
                event_type: String::new(),
                process_guid: String::new(),
                process_id: 0,
                image: String::new(),
                target_object: String::new(),
                details: String::new(),
                user: String::new(),
                endpoint,
            }))
        }
        kind::SYSMON_REGISTRY_RENAME => {
            EndpointEvent::RegistryKeyRename(Box::new(RegistryKeyValueRename {
                agent_name: agent_name(),
                agent_id: agent_id(),
                event_type: String::new(),
                process_guid: String::new(),
                process_id: 0,
                image: String::new(),
                target_object: String::new(),
                new_name: String::new(),
                user: String::new(),
                endpoint,
            }))
        }
        kind::SYSMON_FILE_CREATE_STREAM_HASH => {
            EndpointEvent::FileCreateStreamHash(Box::new(FileCreateStreamHash {
                agent_name: agent_name(),
                agent_id: agent_id(),
                process_guid: String::new(),
                process_id: 0,
                image: String::new(),
                target_filename: String::new(),
                creation_utc_time: 0,
                hash: Vec::new(),
                contents: String::new(),
                user: String::new(),
                endpoint,
            }))
        }
        kind::SYSMON_PIPE_CREATED => EndpointEvent::PipeEvent(Box::new(PipeEvent {
            agent_name: agent_name(),
            agent_id: agent_id(),
            event_type: String::new(),
            process_guid: String::new(),
            process_id: 0,
            pipe_name: String::new(),
            image: String::new(),
            user: String::new(),
            endpoint,
        })),
        kind::SYSMON_DNS_QUERY => EndpointEvent::DnsQuery(Box::new(DnsEvent {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: String::new(),
            process_id: 0,
            query_name: String::new(),
            query_status: 0,
            query_results: Vec::new(),
            image: String::new(),
            user: String::new(),
            endpoint,
        })),
        kind::SYSMON_FILE_DELETE => EndpointEvent::FileDelete(Box::new(FileDelete {
            agent_name: agent_name(),
            agent_id: agent_id(),
            process_guid: String::new(),
            process_id: 0,
            user: String::new(),
            image: String::new(),
            target_filename: String::new(),
            hashes: Vec::new(),
            is_executable: false,
            archived: false,
            endpoint,
        })),
        kind::SYSMON_PROCESS_TAMPERING => {
            EndpointEvent::ProcessTamper(Box::new(ProcessTampering {
                agent_name: agent_name(),
                agent_id: agent_id(),
                process_guid: String::new(),
                process_id: 0,
                image: String::new(),
                tamper_type: String::new(),
                user: String::new(),
                endpoint,
            }))
        }
        kind::SYSMON_FILE_DELETE_DETECTED => {
            EndpointEvent::FileDeleteDetected(Box::new(FileDeleteDetected {
                agent_name: agent_name(),
                agent_id: agent_id(),
                process_guid: String::new(),
                process_id: 0,
                user: String::new(),
                image: String::new(),
                target_filename: String::new(),
                hashes: Vec::new(),
                is_executable: false,
                endpoint,
            }))
        }
        kind::WINDOWS_EVENT_LOG => EndpointEvent::WindowsEventLog(Box::new(WindowsEventLog {
            channel: None,
            provider: None,
            event_id: None,
            version: None,
            level: None,
            task: None,
            opcode: None,
            keywords: None,
            record_id: None,
            computer: None,
            user_sid: None,
            event_data: None,
            user_data_xml: None,
            endpoint: expected_log_header(),
        })),
        kind::JOURNALD => EndpointEvent::Journald(Box::new(Journald {
            fields: None,
            endpoint: expected_log_header(),
        })),
        kind::AUDITD => EndpointEvent::Auditd(Box::new(Auditd {
            serial: None,
            records: None,
            endpoint: expected_log_header(),
        })),
        other => panic!("kind {other} is not accepted"),
    }
}

/// The Giganto kind each accepted senta kind is stored as.
fn giganto_kind(kind: u16) -> RawEventKind {
    match kind {
        1 => RawEventKind::ProcessCreate,
        2 => RawEventKind::FileCreateTime,
        3 => RawEventKind::NetworkConnect,
        5 => RawEventKind::ProcessTerminate,
        6 => RawEventKind::DriverLoad,
        7 => RawEventKind::ImageLoad,
        8 => RawEventKind::CreateRemoteThread,
        9 => RawEventKind::RawAccessRead,
        10 => RawEventKind::ProcessAccess,
        11 => RawEventKind::FileCreate,
        12 => RawEventKind::RegistryObjectAddDel,
        13 => RawEventKind::RegistryValueSet,
        14 => RawEventKind::RegistryKeyRename,
        15 => RawEventKind::FileCreateStreamHash,
        17 => RawEventKind::PipeEvent,
        22 => RawEventKind::DnsQuery,
        23 => RawEventKind::FileDelete,
        25 => RawEventKind::ProcessTamper,
        26 => RawEventKind::FileDeleteDetected,
        1000 => RawEventKind::WindowsEventLog,
        1100 => RawEventKind::Journald,
        1101 => RawEventKind::Auditd,
        other => panic!("kind {other} is not accepted"),
    }
}

#[test]
fn every_kind_converts_an_empty_body_to_empty_values() {
    for kind in ACCEPTED_KINDS {
        let mut record = record(kind, RecordBody::default());
        if logs::KINDS.contains(&kind) {
            record.header = log_header();
        }
        let converted = convert(record).unwrap_or_else(|e| panic!("kind {kind}: {e}"));
        assert_eq!(converted.kind(), giganto_kind(kind), "kind {kind}");
        assert_eq!(converted.sensor, ENDPOINT_ID_TEXT, "kind {kind}");
        assert_eq!(converted.timestamp, EVENT_TIME, "kind {kind}");
        assert_eq!(converted.event, empty_event(kind), "kind {kind}");
    }
}

#[test]
fn giganto_kind_numbers_follow_the_table() {
    let numbers: Vec<u32> = ACCEPTED_KINDS
        .into_iter()
        .map(|kind| u32::from(giganto_kind(kind)))
        .collect();
    assert_eq!(
        numbers,
        [
            31, 32, 33, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 47, 52, 53, 55, 56, 80, 81, 82
        ]
    );
}

// ---------------------------------------------------------------------------
// Field rules
// ---------------------------------------------------------------------------

fn process_create(event: EndpointEvent) -> ProcessCreate {
    match event {
        EndpointEvent::ProcessCreate(event) => *event,
        other => panic!("not a ProcessCreate: {other:?}"),
    }
}

#[test]
fn guids_come_out_braced_uppercase() {
    assert_eq!(guid(Some(GUID_A)), GUID_A_TEXT);
    assert_eq!(
        guid(Some(Uuid::nil())),
        "{00000000-0000-0000-0000-000000000000}"
    );
    assert_eq!(
        guid(Some(Uuid::max())),
        "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}"
    );
    assert_eq!(guid(None), "");
}

#[test]
fn a_guid_from_sysmon_notation_comes_out_as_written() {
    let converted = sysmon::convert(
        kind::SYSMON_PROCESS_CREATE,
        &[
            ("ProcessGuid", GUID_A_TEXT),
            ("LogonGuid", GUID_B_TEXT),
            // Unbraced lowercase reads as well, and comes out in Sysmon's
            // notation.
            ("ParentProcessGuid", "deadbeef-0000-1111-2222-333344445555"),
        ],
    )
    .expect("the Sysmon fields convert");
    let event = process_create(convert_ok(
        sysmon_record(converted.body),
        RawEventKind::ProcessCreate,
    ));
    assert_eq!(event.process_guid, GUID_A_TEXT);
    assert_eq!(event.logon_guid, GUID_B_TEXT);
    assert_eq!(event.parent_process_guid, GUID_C_TEXT);
}

#[test]
fn hashes_come_out_as_algo_equals_uppercase_hex() {
    let converted = sysmon::convert(
        kind::SYSMON_PROCESS_CREATE,
        &[(
            "Hashes",
            "SHA1=a9993e364706816aba3e25717850c26c9cd0d89d,MD5=900150983cd24fb0d6963f7d28e17f72,\
             SHA256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08,\
             IMPHASH=00ff00FF00ff00ff00ff00ff00ff00ff",
        )],
    )
    .expect("the Sysmon fields convert");
    let event = process_create(convert_ok(
        sysmon_record(converted.body),
        RawEventKind::ProcessCreate,
    ));
    assert_eq!(
        event.hashes,
        [
            "SHA1=A9993E364706816ABA3E25717850C26C9CD0D89D",
            "MD5=900150983CD24FB0D6963F7D28E17F72",
            "SHA256=9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08",
            "IMPHASH=00FF00FF00FF00FF00FF00FF00FF00FF",
        ]
    );

    // The algorithm is kept as received, and an empty value is kept too.
    assert_eq!(
        hashes(Some(vec![
            HashEntry {
                algo: "sha256".to_owned(),
                value: vec![0x0a, 0xbc],
            },
            HashEntry {
                algo: "MD5".to_owned(),
                value: Vec::new(),
            },
        ])),
        ["sha256=0ABC", "MD5="]
    );
    assert_eq!(hashes(None), Vec::<String>::new());
    assert_eq!(hashes(Some(Vec::new())), Vec::<String>::new());
}

#[test]
fn stream_hash_is_the_raw_string_as_one_element() {
    let hash_of = |hash: Option<String>| {
        let body = sysmon::FileCreateStreamHash {
            hash,
            ..Default::default()
        };
        match convert_ok(sysmon_record(body), RawEventKind::FileCreateStreamHash) {
            EndpointEvent::FileCreateStreamHash(event) => event.hash,
            other => panic!("not a FileCreateStreamHash: {other:?}"),
        }
    };
    assert_eq!(
        hash_of(s("SHA1=abc,MD5=def,SHA256=0;IMPHASH=x")),
        ["SHA1=abc,MD5=def,SHA256=0;IMPHASH=x"]
    );
    assert_eq!(hash_of(s("Unknown")), ["Unknown"]);
    assert_eq!(hash_of(s("")), Vec::<String>::new());
    assert_eq!(hash_of(None), Vec::<String>::new());
}

#[test]
fn logon_id_beyond_u32_saturates_and_keeps_the_full_value() {
    let ids_of = |logon_id: Option<u64>| {
        let body = sysmon::ProcessCreate {
            logon_id,
            ..Default::default()
        };
        let event = process_create(convert_ok(sysmon_record(body), RawEventKind::ProcessCreate));
        (event.logon_id, event.logon_id_full)
    };
    let max = u64::from(u32::MAX);
    assert_eq!(ids_of(Some(max - 1)), (u32::MAX - 1, Some(max - 1)));
    assert_eq!(ids_of(Some(max)), (u32::MAX, Some(max)));
    assert_eq!(ids_of(Some(max + 1)), (u32::MAX, Some(max + 1)));
    assert_eq!(ids_of(Some(u64::MAX)), (u32::MAX, Some(u64::MAX)));
    assert_eq!(ids_of(Some(0)), (0, Some(0)));
    assert_eq!(ids_of(None), (0, None));
}

#[test]
fn a_missing_ip_is_unspecified_and_not_ipv6() {
    let ips_of = |body: sysmon::NetworkConnect| match convert_ok(
        sysmon_record(body),
        RawEventKind::NetworkConnect,
    ) {
        EndpointEvent::NetworkConnect(event) => (
            event.source_ip,
            event.source_is_ipv6,
            event.destination_ip,
            event.destination_is_ipv6,
        ),
        other => panic!("not a NetworkConnect: {other:?}"),
    };
    let unspecified = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let v6: IpAddr = "2001:db8::7".parse().unwrap();

    // A missing IP ignores the body's flag.
    assert_eq!(
        ips_of(sysmon::NetworkConnect {
            source_is_ipv6: Some(true),
            destination_is_ipv6: Some(true),
            ..Default::default()
        }),
        (unspecified, false, unspecified, false)
    );
    // A present IP takes the flag as sent, `false` when it is absent.
    assert_eq!(
        ips_of(sysmon::NetworkConnect {
            source_ip: Some(v6),
            source_is_ipv6: Some(true),
            destination_ip: Some(v6),
            ..Default::default()
        }),
        (v6, true, v6, false)
    );
}

#[test]
fn query_results_split_on_semicolons() {
    let results_of = |query_results: Option<String>| {
        let body = sysmon::DnsQuery {
            query_results,
            ..Default::default()
        };
        match convert_ok(sysmon_record(body), RawEventKind::DnsQuery) {
            EndpointEvent::DnsQuery(event) => event.query_results,
            other => panic!("not a DnsQuery: {other:?}"),
        }
    };
    assert_eq!(
        results_of(s("::ffff:192.0.2.1;type:  5 b.example;192.0.2.2")),
        ["::ffff:192.0.2.1", "type:  5 b.example", "192.0.2.2"]
    );
    assert_eq!(results_of(s("192.0.2.1;")), ["192.0.2.1", ""]);
    assert_eq!(results_of(s(";;")), ["", "", ""]);
    assert_eq!(results_of(s("")), [""]);
    assert_eq!(results_of(None), Vec::<String>::new());
}

#[test]
fn query_status_parses_decimal_and_falls_back_to_zero() {
    let status_of = |query_status: Option<String>| {
        let body = sysmon::DnsQuery {
            query_status,
            ..Default::default()
        };
        match convert_ok(sysmon_record(body), RawEventKind::DnsQuery) {
            EndpointEvent::DnsQuery(event) => event.query_status,
            other => panic!("not a DnsQuery: {other:?}"),
        }
    };
    assert_eq!(status_of(s("0")), 0);
    assert_eq!(status_of(s("9003")), 9003);
    assert_eq!(status_of(s("4294967295")), u32::MAX);
    for not_decimal in [
        "NXDOMAIN",
        "",
        "-1",
        "+5",
        " 5",
        "0x10",
        "4294967296",
        "1.5",
    ] {
        assert_eq!(status_of(s(not_decimal)), 0, "{not_decimal:?}");
    }
    assert_eq!(status_of(None), 0);
}

#[test]
fn archived_and_signed_are_true_only_for_true_in_any_case() {
    let cases = [
        (s("true"), true),
        (s("TRUE"), true),
        (s("True"), true),
        (s("tRuE"), true),
        (s("false"), false),
        (s("FALSE"), false),
        (s(""), false),
        (s("1"), false),
        (s("yes"), false),
        (s(" true"), false),
        (None, false),
    ];
    for (value, expected) in cases {
        let archived = match convert_ok(
            sysmon_record(sysmon::FileDelete {
                archived: value.clone(),
                ..Default::default()
            }),
            RawEventKind::FileDelete,
        ) {
            EndpointEvent::FileDelete(event) => event.archived,
            other => panic!("not a FileDelete: {other:?}"),
        };
        let image_signed = match convert_ok(
            sysmon_record(sysmon::ImageLoad {
                signed: value.clone(),
                ..Default::default()
            }),
            RawEventKind::ImageLoad,
        ) {
            EndpointEvent::ImageLoad(event) => event.signed,
            other => panic!("not an ImageLoad: {other:?}"),
        };
        let driver_signed = match convert_ok(
            sysmon_record(sysmon::DriverLoad {
                signed: value.clone(),
                ..Default::default()
            }),
            RawEventKind::DriverLoad,
        ) {
            EndpointEvent::DriverLoad(event) => event.signed,
            other => panic!("not a DriverLoad: {other:?}"),
        };
        assert_eq!(
            (archived, image_signed, driver_signed),
            (expected, expected, expected),
            "{value:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

fn converted_header(header: RecordHeader) -> EndpointHeader {
    let record = Record {
        header,
        ..record(kind::SYSMON_PROCESS_TERMINATE, RecordBody::default())
    };
    match convert(record).expect("the record converts").event {
        EndpointEvent::ProcessTerminate(event) => event.endpoint.expect("a header"),
        other => panic!("not a ProcessTerminate: {other:?}"),
    }
}

#[test]
fn header_without_optional_values() {
    let header = RecordHeader {
        clock_offset: None,
        ips: Vec::new(),
        default_route_ip: None,
        net_state_source: SentaNetStateSource::Unknown,
        process_key: None,
        ..header()
    };
    assert_eq!(
        converted_header(header),
        EndpointHeader {
            clock_offset: None,
            ips: Vec::new(),
            default_route_ip: None,
            net_state_source: NetStateSource::Unknown,
            process_key: None,
            ..expected_header()
        }
    );
}

#[test]
fn header_copies_the_record_schema() {
    let record = Record {
        schema: 7,
        ..record(kind::SYSMON_PROCESS_TERMINATE, RecordBody::default())
    };
    let converted = convert(record).expect("the record converts");
    match converted.event {
        EndpointEvent::ProcessTerminate(event) => {
            assert_eq!(event.endpoint.expect("a header").schema, 7);
        }
        other => panic!("not a ProcessTerminate: {other:?}"),
    }
}

#[test]
fn header_enums_map_to_the_variant_of_the_same_name() {
    let cases = [
        (
            SentaNetStateSource::Observed,
            SentaOsFamily::Windows,
            SentaCollectionMode::Extended,
            NetStateSource::Observed,
            OsFamily::Windows,
            CollectionMode::Extended,
        ),
        (
            SentaNetStateSource::Inferred,
            SentaOsFamily::Linux,
            SentaCollectionMode::Essential,
            NetStateSource::Inferred,
            OsFamily::Linux,
            CollectionMode::Essential,
        ),
        (
            SentaNetStateSource::Unknown,
            SentaOsFamily::Macos,
            SentaCollectionMode::Essential,
            NetStateSource::Unknown,
            OsFamily::Macos,
            CollectionMode::Essential,
        ),
        (
            SentaNetStateSource::Other("probed".to_owned()),
            SentaOsFamily::Other("freebsd".to_owned()),
            SentaCollectionMode::Other("minimal".to_owned()),
            NetStateSource::Other("probed".to_owned()),
            OsFamily::Other("freebsd".to_owned()),
            CollectionMode::Other("minimal".to_owned()),
        ),
        (
            SentaNetStateSource::Other(String::new()),
            SentaOsFamily::Other(String::new()),
            SentaCollectionMode::Other(String::new()),
            NetStateSource::Other(String::new()),
            OsFamily::Other(String::new()),
            CollectionMode::Other(String::new()),
        ),
    ];
    for (source, family, mode, expected_source, expected_family, expected_mode) in cases {
        let header = RecordHeader {
            ips: Vec::new(),
            default_route_ip: None,
            net_state_source: source,
            os: OsInfo {
                family,
                version: OS_VERSION.to_owned(),
            },
            collection_mode: mode,
            ..header()
        };
        let converted = converted_header(header);
        assert_eq!(
            (
                converted.net_state_source,
                converted.os_family,
                converted.collection_mode
            ),
            (expected_source, expected_family, expected_mode)
        );
    }
}

#[test]
fn an_unmatched_header_enum_takes_its_wire_tag() {
    assert_eq!(wire_tag(&SentaNetStateSource::Inferred), "inferred");
    assert_eq!(wire_tag(&SentaOsFamily::Macos), "macos");
    assert_eq!(wire_tag(&SentaCollectionMode::Essential), "essential");
    assert_eq!(wire_tag(&SentaOsFamily::Other("plan9".to_owned())), "plan9");
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn body_of(entries: &[(&str, &str)]) -> RecordBody {
    let map: BTreeMap<&str, &str> = entries.iter().copied().collect();
    RecordBody::encode(&map).expect("a map encodes")
}

#[test]
fn a_known_field_of_the_wrong_type_is_a_body_error() {
    let error = convert(record(
        kind::SYSMON_PROCESS_CREATE,
        body_of(&[("process_id", "4242")]),
    ))
    .expect_err("text is not an integer");
    assert!(
        matches!(error, ConvertError::Body { kind: 1, .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("record kind 1"), "{error}");

    let error = convert(Record {
        header: log_header(),
        ..record(kind::WINDOWS_EVENT_LOG, body_of(&[("event_id", "4624")]))
    })
    .expect_err("text is not an integer");
    assert!(
        matches!(error, ConvertError::Body { kind: 1000, .. }),
        "{error:?}"
    );

    // A GUID is a 16-byte byte string, not its text notation.
    let error = convert(record(
        kind::SYSMON_PROCESS_TERMINATE,
        body_of(&[("process_guid", "{01020304-0506-0708-090A-0B0C0D0E0F10}")]),
    ))
    .expect_err("a GUID is a byte string");
    assert!(
        matches!(error, ConvertError::Body { kind: 5, .. }),
        "{error:?}"
    );
}

#[test]
fn a_body_of_another_kind_is_not_refused() {
    // Unknown keys are ignored: a FileCreate body reads as a ProcessTerminate
    // with the fields they share.
    let body = sysmon::FileCreate {
        process_id: Some(5),
        target_filename: s("t.txt"),
        ..Default::default()
    };
    let record = record(
        kind::SYSMON_PROCESS_TERMINATE,
        sysmon::Body::from(body).to_record_body().unwrap(),
    );
    match convert_ok(record, RawEventKind::ProcessTerminate) {
        EndpointEvent::ProcessTerminate(event) => assert_eq!(event.process_id, 5),
        other => panic!("not a ProcessTerminate: {other:?}"),
    }
}

#[test]
fn a_kind_outside_the_table_is_unsupported() {
    for kind in [
        0,
        4,
        16,
        18,
        24,
        27,
        255,
        999,
        1001,
        1099,
        1102,
        1200,
        1300,
        u16::MAX,
    ] {
        assert_eq!(
            convert(record(kind, RecordBody::default())),
            Err(ConvertError::UnsupportedKind(kind)),
            "kind {kind}"
        );
    }
}

#[test]
fn a_header_time_out_of_range_is_an_error() {
    let mut header = header();
    header.event_time = Timestamp::MAX;
    let error = convert(Record {
        header,
        ..record(kind::SYSMON_PROCESS_CREATE, RecordBody::default())
    })
    .expect_err("event_time is out of range");
    assert_eq!(
        error,
        ConvertError::TimeOutOfRange {
            field: "event_time",
            time: Timestamp::MAX,
        }
    );

    let mut header = self::header();
    header.collected_at = Timestamp::MIN;
    let error = convert(Record {
        header,
        ..record(kind::SYSMON_PROCESS_CREATE, RecordBody::default())
    })
    .expect_err("collected_at is out of range");
    assert_eq!(
        error,
        ConvertError::TimeOutOfRange {
            field: "collected_at",
            time: Timestamp::MIN,
        }
    );

    let mut header = self::header();
    header.clock_offset = Some(SentaClockOffset {
        offset_ms: 0,
        uncertainty_ms: 0,
        measured_at: Timestamp::MAX,
    });
    let error = convert(Record {
        header,
        ..record(kind::JOURNALD, RecordBody::default())
    })
    .expect_err("measured_at is out of range");
    assert_eq!(
        error,
        ConvertError::TimeOutOfRange {
            field: "clock_offset.measured_at",
            time: Timestamp::MAX,
        }
    );
}

#[test]
fn a_body_time_out_of_range_is_an_error() {
    assert_eq!(
        body_nanos("creation_utc_time", Some(Timestamp::MAX)),
        Err(ConvertError::TimeOutOfRange {
            field: "creation_utc_time",
            time: Timestamp::MAX,
        })
    );
    assert_eq!(body_nanos("creation_utc_time", None), Ok(0));
    assert_eq!(body_nanos("creation_utc_time", Some(ts(-1))), Ok(-1));
    assert_eq!(
        body_nanos("creation_utc_time", Some(ts(i64::MAX))),
        Ok(i64::MAX)
    );
}

// ---------------------------------------------------------------------------
// Accepted kinds
// ---------------------------------------------------------------------------

#[test]
fn accepted_kinds_are_the_22_kinds_at_schema_1() {
    assert_eq!(
        accepted_kinds(),
        [
            1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 22, 23, 25, 26, 1000, 1100, 1101
        ]
        .into_iter()
        .map(|kind| AcceptedKind {
            kind,
            schema_min: 1,
            schema_max: 1,
        })
        .collect::<Vec<_>>()
    );
}

#[test]
fn the_accepted_kinds_are_exactly_the_converted_kinds() {
    let accepted = accepted_kinds();
    for kind in 0..=u16::MAX {
        let mut record = record(kind, RecordBody::default());
        if logs::KINDS.contains(&kind) {
            record.header = log_header();
        }
        let converts = convert(record).is_ok();
        let announced = senta_protocol::telemetry::kind::accepts(&accepted, kind, SCHEMA);
        assert_eq!(converts, announced, "kind {kind}");
        // Every kind senta defines is accepted, at its current schema.
        let defined = kind::info(kind);
        assert_eq!(defined.is_some(), announced, "kind {kind}");
        if let Some(info) = defined {
            assert_eq!(info.schema(), SCHEMA, "kind {kind}");
        }
    }
}

/// Appends `value` under `key` through the store module ingest uses for
/// `kind`.
fn append_through_kind_store(db: &crate::storage::Database, kind: RawEventKind, key: &[u8]) {
    let value = b"value";
    match kind {
        RawEventKind::ProcessCreate => db.process_create_store().unwrap().append(key, value),
        RawEventKind::FileCreateTime => db.file_create_time_store().unwrap().append(key, value),
        RawEventKind::NetworkConnect => db.network_connect_store().unwrap().append(key, value),
        RawEventKind::ProcessTerminate => db.process_terminate_store().unwrap().append(key, value),
        RawEventKind::DriverLoad => db.driver_load_store().unwrap().append(key, value),
        RawEventKind::ImageLoad => db.image_load_store().unwrap().append(key, value),
        RawEventKind::CreateRemoteThread => {
            db.create_remote_thread_store().unwrap().append(key, value)
        }
        RawEventKind::RawAccessRead => db.raw_access_read_store().unwrap().append(key, value),
        RawEventKind::ProcessAccess => db.process_access_store().unwrap().append(key, value),
        RawEventKind::FileCreate => db.file_create_store().unwrap().append(key, value),
        RawEventKind::RegistryObjectAddDel => db
            .registry_object_add_del_store()
            .unwrap()
            .append(key, value),
        RawEventKind::RegistryValueSet => db.registry_value_set_store().unwrap().append(key, value),
        RawEventKind::RegistryKeyRename => {
            db.registry_key_rename_store().unwrap().append(key, value)
        }
        RawEventKind::FileCreateStreamHash => db
            .file_create_stream_hash_store()
            .unwrap()
            .append(key, value),
        RawEventKind::PipeEvent => db.pipe_event_store().unwrap().append(key, value),
        RawEventKind::DnsQuery => db.dns_query_store().unwrap().append(key, value),
        RawEventKind::FileDelete => db.file_delete_store().unwrap().append(key, value),
        RawEventKind::ProcessTamper => db.process_tamper_store().unwrap().append(key, value),
        RawEventKind::FileDeleteDetected => {
            db.file_delete_detected_store().unwrap().append(key, value)
        }
        RawEventKind::WindowsEventLog => db
            .endpoint_windows_event_log_store()
            .unwrap()
            .append(key, value),
        RawEventKind::Journald => db.endpoint_journald_store().unwrap().append(key, value),
        RawEventKind::Auditd => db.endpoint_auditd_store().unwrap().append(key, value),
        other => panic!("{other:?} is not an endpoint kind"),
    }
    .expect("append through the kind's store");
}

#[test]
fn every_kind_is_stored_in_the_column_family_its_store_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = crate::storage::Database::open(dir.path(), &crate::storage::DbOptions::default())
        .expect("open the database");
    for (index, kind) in ACCEPTED_KINDS.into_iter().enumerate() {
        let event = empty_event(kind);
        let key = u64::try_from(index).unwrap().to_be_bytes();
        append_through_kind_store(&db, event.kind(), &key);
        assert_eq!(
            db.get_cf_for_test(event.column_family(), &key).unwrap(),
            Some(b"value".to_vec()),
            "kind {kind}"
        );
    }
}

#[test]
fn the_record_column_families_are_those_of_the_accepted_kinds() {
    let families: std::collections::BTreeSet<&str> = ACCEPTED_KINDS
        .into_iter()
        .map(|kind| empty_event(kind).column_family())
        .collect();
    let listed: std::collections::BTreeSet<&str> = RECORD_COLUMN_FAMILIES.into_iter().collect();
    assert_eq!(families, listed);
    assert_eq!(
        listed.len(),
        RECORD_COLUMN_FAMILIES.len(),
        "no family twice"
    );
    for family in RECORD_COLUMN_FAMILIES {
        assert!(
            crate::storage::RAW_DATA_COLUMN_FAMILY_NAMES.contains(&family),
            "{family}"
        );
    }
}

/// Decodes `bytes` as the bincode 1 of the struct `like` holds.
fn decode_like(like: &EndpointEvent, bytes: &[u8]) -> EndpointEvent {
    fn de<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Box<T> {
        Box::new(bincode::deserialize(bytes).expect("the bincode 1 of the kind's struct"))
    }
    match like {
        EndpointEvent::ProcessCreate(_) => EndpointEvent::ProcessCreate(de(bytes)),
        EndpointEvent::FileCreateTime(_) => EndpointEvent::FileCreateTime(de(bytes)),
        EndpointEvent::NetworkConnect(_) => EndpointEvent::NetworkConnect(de(bytes)),
        EndpointEvent::ProcessTerminate(_) => EndpointEvent::ProcessTerminate(de(bytes)),
        EndpointEvent::DriverLoad(_) => EndpointEvent::DriverLoad(de(bytes)),
        EndpointEvent::ImageLoad(_) => EndpointEvent::ImageLoad(de(bytes)),
        EndpointEvent::CreateRemoteThread(_) => EndpointEvent::CreateRemoteThread(de(bytes)),
        EndpointEvent::RawAccessRead(_) => EndpointEvent::RawAccessRead(de(bytes)),
        EndpointEvent::ProcessAccess(_) => EndpointEvent::ProcessAccess(de(bytes)),
        EndpointEvent::FileCreate(_) => EndpointEvent::FileCreate(de(bytes)),
        EndpointEvent::RegistryObjectAddDel(_) => EndpointEvent::RegistryObjectAddDel(de(bytes)),
        EndpointEvent::RegistryValueSet(_) => EndpointEvent::RegistryValueSet(de(bytes)),
        EndpointEvent::RegistryKeyRename(_) => EndpointEvent::RegistryKeyRename(de(bytes)),
        EndpointEvent::FileCreateStreamHash(_) => EndpointEvent::FileCreateStreamHash(de(bytes)),
        EndpointEvent::PipeEvent(_) => EndpointEvent::PipeEvent(de(bytes)),
        EndpointEvent::DnsQuery(_) => EndpointEvent::DnsQuery(de(bytes)),
        EndpointEvent::FileDelete(_) => EndpointEvent::FileDelete(de(bytes)),
        EndpointEvent::ProcessTamper(_) => EndpointEvent::ProcessTamper(de(bytes)),
        EndpointEvent::FileDeleteDetected(_) => EndpointEvent::FileDeleteDetected(de(bytes)),
        EndpointEvent::WindowsEventLog(_) => EndpointEvent::WindowsEventLog(de(bytes)),
        EndpointEvent::Journald(_) => EndpointEvent::Journald(de(bytes)),
        EndpointEvent::Auditd(_) => EndpointEvent::Auditd(de(bytes)),
    }
}

#[test]
fn every_kind_is_stored_as_the_bincode_of_its_struct() {
    for kind in ACCEPTED_KINDS {
        let event = empty_event(kind);
        let bytes = event
            .to_bincode()
            .unwrap_or_else(|e| panic!("kind {kind}: {e}"));
        assert_eq!(decode_like(&event, &bytes), event, "kind {kind}");
    }
}
