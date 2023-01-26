pub mod range;
pub mod stream;

use self::{
    range::{MessageCode, ResponseRangeData},
    stream::{NodeType, RequestStreamRecord},
};
use crate::frame::{self, recv_bytes, recv_raw, send_bytes, send_raw, RecvError, SendError};
use anyhow::{anyhow, Result};
pub use oinq::message::send_ok;
use quinn::{Connection, ConnectionError, RecvStream, SendStream};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{mem, net::IpAddr};
use thiserror::Error;

/// The error type for a publish failure.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Error)]
pub enum PublishError {
    #[error("Connection closed by peer")]
    ConnectionClosed,
    #[error("Connection lost")]
    ConnectionLost(#[from] ConnectionError),
    #[error("Cannot receive a publish message")]
    ReadError(#[from] quinn::ReadError),
    #[error("Cannot send a publish message")]
    WriteError(#[from] quinn::WriteError),
    #[error("Cannot serialize/deserialize a publish message")]
    SerialDeserialFailure(#[from] bincode::Error),
    #[error("Message is too large, so type casting failed")]
    MessageTooLarge,
    #[error("Invalid message type")]
    InvalidMessageType,
    #[error("Invalid message data")]
    InvalidMessageData,
}

impl From<frame::RecvError> for PublishError {
    fn from(e: frame::RecvError) -> Self {
        match e {
            RecvError::DeserializationFailure(e) => PublishError::SerialDeserialFailure(e),
            RecvError::ReadError(e) => match e {
                quinn::ReadExactError::FinishedEarly => PublishError::ConnectionClosed,
                quinn::ReadExactError::ReadError(e) => PublishError::ReadError(e),
            },
            RecvError::MessageTooLarge(_) => PublishError::MessageTooLarge,
        }
    }
}

impl From<frame::SendError> for PublishError {
    fn from(e: frame::SendError) -> Self {
        match e {
            SendError::SerializationFailure(e) => PublishError::SerialDeserialFailure(e),
            SendError::MessageTooLarge(_) => PublishError::MessageTooLarge,
            SendError::WriteError(e) => PublishError::WriteError(e),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pcapfilter {
    timestamp: i64,
    pub source: String,
    src_addr: IpAddr,
    src_port: u16,
    dst_addr: IpAddr,
    dst_port: u16,
    proto: u8,
    duration: i64,
}

/// Sends the stream request to giganto's publish module.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the stream-request data could not be serialized
/// * `PublishError::MessageTooLarge`: if the stream-request data is too large
/// * `PublishError::WriteError`: if the stream-request data could not be written
pub async fn send_stream_request<T>(
    send: &mut SendStream,
    record_type: RequestStreamRecord,
    node_type: NodeType,
    msg: T,
) -> Result<(), PublishError>
where
    T: Serialize,
{
    // send node type
    let node: u8 = node_type.into();
    send_bytes(send, &node.to_le_bytes()).await?;

    // send record type
    let record: u32 = record_type.into();
    send_bytes(send, &record.to_le_bytes()).await?;

    // send request record info
    let mut buf = Vec::new();
    frame::send(send, &mut buf, msg).await?;
    Ok(())
}

/// Sends the hog stream start message from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::WriteError`: if the hog's stream start message could not be written
pub async fn send_hog_stream_start_message(
    send: &mut SendStream,
    start_msg: RequestStreamRecord,
) -> Result<(), PublishError> {
    let record: u32 = start_msg.into();
    send_bytes(send, &record.to_le_bytes()).await?;
    Ok(())
}

/// Sends the crusher stream start message from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::MessageTooLarge`: if the crusher's stream start message is too large
/// * `PublishError::WriteError`: if the crusher's stream start message could not be written
pub async fn send_crusher_stream_start_message(
    send: &mut SendStream,
    start_msg: String,
) -> Result<(), PublishError> {
    send_raw(send, start_msg.as_bytes()).await?;
    Ok(())
}

/// Sends the record data. (timestamp /record structure)
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the stream record data could not be serialized
/// * `PublishError::MessageTooLarge`: if the  stream record data is too large
/// * `PublishError::WriteError`: if the stream record data could not be written
pub async fn send_crusher_data<T>(
    send: &mut SendStream,
    timestamp: i64,
    record_data: T,
) -> Result<(), PublishError>
where
    T: Serialize,
{
    frame::send_bytes(send, &timestamp.to_le_bytes()).await?;
    let mut buf = Vec::new();
    frame::send(send, &mut buf, record_data).await?;
    Ok(())
}

/// Sends the range data request to giganto's publish module.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the range-request data could not be serialized
/// * `PublishError::MessageTooLarge`: if the range-request data is too large
/// * `PublishError::WriteError`: if the range-request data could not be written
pub async fn send_range_data_request<T>(
    send: &mut SendStream,
    msg: MessageCode,
    request: T,
) -> Result<(), PublishError>
where
    T: Serialize,
{
    //send MessageCode
    let msg_code: u32 = msg.into();
    send_bytes(send, &msg_code.to_le_bytes()).await?;

    //send RequestRange/RequestTimeSeriesRange
    let mut buf = Vec::new();
    frame::send(send, &mut buf, request).await?;
    Ok(())
}

/// Sends the range data from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the range data could not be serialized
/// * `PublishError::MessageTooLarge`: if the range data is too large
/// * `PublishError::WriteError`: if the range data could not be written
pub async fn send_range_data<T>(
    send: &mut SendStream,
    data: Option<(T, i64, &str)>,
) -> Result<(), PublishError>
where
    T: ResponseRangeData,
{
    let send_buf = if let Some((val, timestamp, source)) = data {
        val.response_data(timestamp, source)
            .map_err(PublishError::SerialDeserialFailure)?
    } else {
        T::response_done().map_err(PublishError::SerialDeserialFailure)?
    };
    send_raw(send, &send_buf).await?;
    Ok(())
}

/// Receives the stream request sent to giganto's publish module.
///
/// # Errors
///
/// * `PublishError::ReadError`: if the stream-request data could not be read
/// * `PublishError::InvalidMessageType`: if the stream-request data could not be converted to valid type
/// * `PublishError::InvalidMessageData`: if the stream-request data could not be converted to valid data
pub async fn receive_stream_request(
    recv: &mut RecvStream,
) -> Result<(NodeType, RequestStreamRecord, Vec<u8>), PublishError> {
    // receive node type
    let mut node_buf = [0; mem::size_of::<u8>()];
    recv_bytes(recv, &mut node_buf).await?;
    let node_type = NodeType::try_from(u8::from_le_bytes(node_buf))
        .map_err(|_| PublishError::InvalidMessageType)?;

    // receive record type
    let mut record_buf = [0; mem::size_of::<u32>()];
    recv_bytes(recv, &mut record_buf).await?;
    let record_type = RequestStreamRecord::try_from(u32::from_le_bytes(record_buf))
        .map_err(|_| PublishError::InvalidMessageType)?;

    // receive request info
    let mut buf = Vec::new();
    recv_raw(recv, &mut buf).await?;
    Ok((node_type, record_type, buf))
}

/// Receives the hog stream start message sent from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::ReadError`: if the hog's stream start data could not be read
/// * `PublishError::InvalidMessageType`: if the hog's stream start data could not be converted to valid type
pub async fn receive_hog_stream_start_message(
    recv: &mut RecvStream,
) -> Result<RequestStreamRecord, PublishError> {
    let mut record_buf = [0; mem::size_of::<u32>()];
    recv_bytes(recv, &mut record_buf).await?;
    let start_msg = RequestStreamRecord::try_from(u32::from_le_bytes(record_buf))
        .map_err(|_| PublishError::InvalidMessageType)?;
    Ok(start_msg)
}

/// Receives the crusher stream start message sent from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::ReadError`: if the crusher's stream start data could not be read
/// * `PublishError::InvalidMessageData`: if the crusher's stream start data could not be converted to valid data
pub async fn receive_crusher_stream_start_message(
    recv: &mut RecvStream,
) -> Result<u32, PublishError> {
    let mut buf = Vec::new();
    recv_raw(recv, &mut buf).await?;
    let start_msg = String::from_utf8(buf)
        .map_err(|_| PublishError::InvalidMessageData)?
        .parse::<u32>()
        .map_err(|_| PublishError::InvalidMessageData)?;
    Ok(start_msg)
}

/// Receives the record data. (timestamp / record structure)
///
/// # Errors
///
/// * `PublishError::ReadError`: if the stream record data could not be read
pub async fn receive_crusher_data(recv: &mut RecvStream) -> Result<(Vec<u8>, i64), PublishError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;
    let timestamp = i64::from_le_bytes(ts_buf);

    let mut record_buf = Vec::new();
    frame::recv_raw(recv, &mut record_buf).await?;
    Ok((record_buf, timestamp))
}

/// Receives the timestamp/source/record data from giganto's publish module.
/// If you want to receive record data, source  and timestamp separately,
/// use `publish::receive_crusher_data`
///
/// # Errors
///
/// * `PublishError::ReadError`: if the stream record data could not be read
pub async fn receive_hog_data(recv: &mut RecvStream) -> Result<Vec<u8>, PublishError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;

    let mut source_buf = Vec::new();
    frame::recv_raw(recv, &mut source_buf).await?;

    let mut record_buf = Vec::new();
    frame::recv_raw(recv, &mut record_buf).await?;

    let mut result_buf: Vec<u8> = Vec::new();
    result_buf.extend_from_slice(&ts_buf);
    result_buf.extend_from_slice(&source_buf);
    result_buf.extend_from_slice(&record_buf);

    Ok(result_buf)
}

/// Receives the range data request sent to giganto's publish module.
///
/// # Errors
///
/// * `PublishError::ReadError`: if the range data could not be read
/// * `PublishError::InvalidMessageType`: if the range data could not be converted to valid type
pub async fn receive_range_data_request(
    recv: &mut RecvStream,
) -> Result<(MessageCode, Vec<u8>), PublishError> {
    // receive message code
    let mut buf = [0; mem::size_of::<u32>()];
    recv_bytes(recv, &mut buf).await?;
    let msg_type = MessageCode::try_from(u32::from_le_bytes(buf))
        .map_err(|_| PublishError::InvalidMessageType)?;

    // receive request info
    let mut buf = Vec::new();
    recv_raw(recv, &mut buf).await?;
    Ok((msg_type, buf))
}

/// Receives the range data sent from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the range data could not be
///   deserialized
/// * `PublishError::ReadError`: if the range data could not be read
pub async fn receive_range_data<T>(recv: &mut RecvStream) -> Result<T, PublishError>
where
    T: DeserializeOwned,
{
    let mut buf = Vec::new();
    Ok(frame::recv::<T>(recv, &mut buf).await?)
}

/// relay pcap extract request & request acknowledge.
///
/// # Errors
///
/// * `PublishError::ConnectionLost`: if quinn connection is lost
/// * `PublishError::MessageTooLarge`: if the extract request data is too large
/// * `PublishError::WriteError`: if the extract request/request ack data could not be written
/// * `PublishError::ReadError`: if the extract request data could not be read
pub async fn relay_pcap_extract_request(conn: &Connection, filter: &[u8]) -> Result<()> {
    //open target(piglet) source's channel
    let (mut send, mut recv) = conn.open_bi().await?;

    // send pacp extract request to piglet
    send_raw(&mut send, filter).await?;
    send.finish().await?;

    // receive pcap extract acknowledge from piglet
    let mut ack_buf = Vec::new();
    recv_raw(&mut recv, &mut ack_buf)
        .await
        .map_err(|e| anyhow!("failed to receive ACK: {e}"))?;

    Ok(())
}
