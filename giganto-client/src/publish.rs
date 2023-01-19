pub mod range;
pub mod stream;

use self::{
    range::{MessageCode, ResponseRangeData},
    stream::{NodeType, RequestStreamRecord},
};
use crate::frame::{self, recv_bytes, recv_raw, send_bytes, send_raw, SendError};
use anyhow::{anyhow, Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{mem, net::IpAddr};

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
/// * `SendError::WriteError` if the message could not be written
pub async fn send_stream_request<T>(
    send: &mut SendStream,
    record_type: RequestStreamRecord,
    node_type: NodeType,
    msg: T,
) -> Result<(), SendError>
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
/// * `SendError::WriteError` if the message could not be written
pub async fn send_hog_stream_start_message(
    send: &mut SendStream,
    start_msg: RequestStreamRecord,
) -> Result<(), SendError> {
    let record: u32 = start_msg.into();
    send_bytes(send, &record.to_le_bytes()).await?;
    Ok(())
}

/// Sends the crusher stream start message from giganto's publish module.
///
/// # Errors
///
/// * `SendError::WriteError` if the message could not be written
pub async fn send_crusher_stream_start_message(
    send: &mut SendStream,
    start_msg: String,
) -> Result<(), SendError> {
    send_raw(send, start_msg.as_bytes()).await?;
    Ok(())
}

/// Sends the record data. (timestamp / source / record structure)
///
/// # Errors
///
/// * `SendError::WriteError` if the message could not be written
pub async fn send_record_data<T>(
    send: &mut SendStream,
    timestamp: i64,
    source: String,
    record_data: T,
) -> Result<(), SendError>
where
    T: Serialize,
{
    frame::send_bytes(send, &timestamp.to_le_bytes()).await?;
    frame::send_raw(send, source.as_bytes()).await?;
    let mut buf = Vec::new();
    frame::send(send, &mut buf, record_data).await?;
    Ok(())
}

/// Sends the range data request to giganto's publish module.
///
/// # Errors
///
/// * `SendError::WriteError` if the message could not be written
pub async fn send_range_data_request<T>(
    send: &mut SendStream,
    msg: MessageCode,
    request: T,
) -> Result<(), SendError>
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
/// * `SendError::WriteError` if the message could not be written
pub async fn send_range_data<T>(
    send: &mut SendStream,
    data: Option<(T, i64, &str)>,
) -> Result<(), SendError>
where
    T: ResponseRangeData,
{
    let send_buf = if let Some((val, timestamp, source)) = data {
        val.response_data(timestamp, source)?
    } else {
        T::response_done()?
    };
    send_raw(send, &send_buf).await?;
    Ok(())
}

/// Receives the stream request sent to giganto's publish module.
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn receive_stream_request(
    recv: &mut RecvStream,
) -> Result<(NodeType, RequestStreamRecord, Vec<u8>)> {
    // receive node type
    let mut node_buf = [0; mem::size_of::<u8>()];
    recv_bytes(recv, &mut node_buf)
        .await
        .map_err(|e| anyhow!("Failed to read Node Type: {}", e))?;
    let node_type = NodeType::try_from(u8::from_le_bytes(node_buf)).context("unknown Node type")?;

    // receive record type
    let mut record_buf = [0; mem::size_of::<u32>()];
    recv_bytes(recv, &mut record_buf)
        .await
        .map_err(|e| anyhow!("Failed to read record type: {}", e))?;
    let record_type = RequestStreamRecord::try_from(u32::from_le_bytes(record_buf))
        .context("unknown record type")?;

    // receive request info
    let mut buf = Vec::new();
    recv_raw(recv, &mut buf)
        .await
        .map_err(|e| anyhow!("Failed to read request info: {}", e))?;
    Ok((node_type, record_type, buf))
}

/// Receives the hog stream start message sent from giganto's publish module.
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn receive_hog_stream_start_message(
    recv: &mut RecvStream,
) -> Result<RequestStreamRecord> {
    let mut record_buf = [0; mem::size_of::<u32>()];
    recv_bytes(recv, &mut record_buf).await?;
    let start_msg = RequestStreamRecord::try_from(u32::from_le_bytes(record_buf))?;
    Ok(start_msg)
}

/// Receives the crusher stream start message sent from giganto's publish module.
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn receive_crusher_stream_start_message(recv: &mut RecvStream) -> Result<u32> {
    let mut buf = Vec::new();
    recv_raw(recv, &mut buf).await?;
    let start_msg = String::from_utf8(buf)?.parse::<u32>()?;
    Ok(start_msg)
}

/// Receives the record data. (timestamp / source / record structure)
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn receive_record_data(
    recv: &mut RecvStream,
) -> Result<(Vec<u8>, i64), quinn::ReadExactError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;
    let timestamp = i64::from_le_bytes(ts_buf);

    let mut source_buf = Vec::new();
    frame::recv_raw(recv, &mut source_buf).await?;
    let _source = String::from_utf8_lossy(&source_buf).to_string();

    let mut record_buf = Vec::new();
    frame::recv_raw(recv, &mut record_buf).await?;
    Ok((record_buf, timestamp))
}

/// Receives the timestamp/record data from giganto's publish module.
/// If you want to receive record data, source  and timestamp separately,
/// use `publish::receive_record_data`
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn receive_stream_data(recv: &mut RecvStream) -> Result<Vec<u8>, quinn::ReadExactError> {
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
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn receive_range_data_request(recv: &mut RecvStream) -> Result<(MessageCode, Vec<u8>)> {
    // receive message code
    let mut buf = [0; mem::size_of::<u32>()];
    recv_bytes(recv, &mut buf)
        .await
        .map_err(|e| anyhow!("Failed to read message code: {}", e))?;
    let msg_type = MessageCode::try_from(u32::from_le_bytes(buf)).context("unknown record type")?;

    // receive request info
    let mut buf = Vec::new();
    recv_raw(recv, &mut buf)
        .await
        .map_err(|e| anyhow!("Failed to read request info: {}", e))?;
    Ok((msg_type, buf))
}

/// Receives the range data sent from giganto's publish module.
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn receive_range_data<T>(recv: &mut RecvStream) -> Result<T>
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
/// * `SendError::WriteError` if the message could not be written
/// * `quinn::ReadExactError`: if the message could not be read
/// * `RecvError::DeserializationFailure`: if the message could not be
pub async fn relay_pcap_extract_request(
    conn: &Connection,
    filter: &[u8],
    resp_send: &mut SendStream,
) -> Result<()> {
    //open target(piglet) source's channel
    let (mut send, mut recv) = conn.open_bi().await?;

    // send pacp extract request to piglet
    send_raw(&mut send, filter).await?;

    // receive pcap extract acknowledge from piglet
    let mut ack_buf = Vec::new();
    recv_raw(&mut recv, &mut ack_buf).await?;

    // response pcap extract ack to hog/reconverge
    send_raw(resp_send, &ack_buf).await?;
    Ok(())
}
