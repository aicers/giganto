pub mod log;
pub mod network;
pub mod statistics;
pub mod timeseries;

use crate::frame::{self, SendError};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, TryFromPrimitive, IntoPrimitive, PartialEq, Deserialize)]
#[repr(u32)]
pub enum RecordType {
    Conn = 0,
    Dns = 1,
    Log = 2,
    Http = 3,
    Rdp = 4,
    PeriodicTimeSeries = 5,
    Smtp = 6,
    Ntlm = 7,
    Kerberos = 8,
    Ssh = 9,
    DceRpc = 10,
    Statistics = 11,
    Oplog = 12,
    Packet = 13,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Packet {
    pub packet_timestamp: i64,
    pub packet: Vec<u8>,
}

/// Sends the record type. (`RecordType`)
///
/// # Errors
///
/// * `SendError::WriteError` if the message could not be written
pub async fn send_record_header(
    send: &mut SendStream,
    record_type: RecordType,
) -> Result<(), SendError> {
    frame::send_bytes(send, &u32::from(record_type).to_le_bytes()).await?;
    Ok(())
}

/// Sends the record data. (timestamp / record structure)
///
/// # Errors
///
/// * `SendError::WriteError` if the message could not be written
pub async fn send_event<T>(
    send: &mut SendStream,
    timestamp: i64,
    record_data: T,
) -> Result<(), SendError>
where
    T: Serialize,
{
    frame::send_bytes(send, &timestamp.to_le_bytes()).await?;
    let mut buf = Vec::new();
    frame::send(send, &mut buf, record_data).await?;
    Ok(())
}

/// Sends the ack timestamp. (big-endian)
///
/// # Errors
///
/// * `SendError::WriteError` if the message could not be written
pub async fn send_ack_timestamp(send: &mut SendStream, timestamp: i64) -> Result<(), SendError> {
    frame::send_bytes(send, &timestamp.to_be_bytes()).await?;
    Ok(())
}

/// Receives the record type. (`RecordType`)
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn receive_record_header(
    recv: &mut RecvStream,
    buf: &mut [u8],
) -> Result<(), quinn::ReadExactError> {
    frame::recv_bytes(recv, buf).await?;
    Ok(())
}

/// Receives the record data. (timestamp / record structure)
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn receive_event(recv: &mut RecvStream) -> Result<(Vec<u8>, i64), quinn::ReadExactError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;
    let timestamp = i64::from_le_bytes(ts_buf);

    let mut record_buf = Vec::new();
    frame::recv_raw(recv, &mut record_buf).await?;
    Ok((record_buf, timestamp))
}

/// Receives the ack timestamp. (big-endian)
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn receive_ack_timestamp(recv: &mut RecvStream) -> Result<i64, quinn::ReadExactError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;
    let timestamp = i64::from_be_bytes(ts_buf);
    Ok(timestamp)
}
