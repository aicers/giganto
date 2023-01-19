//! Functions and errors for handling length-delimited frames.

use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::{mem, num::TryFromIntError};
use thiserror::Error;

/// The error type for receiving and deserializing a frame.
#[derive(Debug, Error)]
pub enum RecvError {
    #[error("failed deserializing message")]
    DeserializationFailure(#[from] bincode::Error),
    #[error("failed to read from a stream")]
    ReadError(#[from] quinn::ReadExactError),
    #[error("failed to cast from receive buffer data")]
    CastError(#[from] TryFromIntError),
}

/// The error type for sending a message as a frame.
#[derive(Debug, Error)]
pub enum SendError {
    #[error("failed serializing message")]
    SerializationFailure(#[from] bincode::Error),
    #[error("message is too large")]
    MessageTooLarge(#[from] TryFromIntError),
    #[error("failed to write to a stream")]
    WriteError(#[from] quinn::WriteError),
}

/// Receives and deserializes a message with a little-endian 4-byte length header.
///
/// `buf` will be filled with the message data excluding the 4-byte length
/// header.
///
/// # Errors
///
/// * `RecvError::DeserializationFailure`: if the message could not be
///   deserialized
/// * `RecvError::ReadError`: if the message could not be read
pub async fn recv<'b, T>(recv: &mut RecvStream, buf: &'b mut Vec<u8>) -> Result<T, RecvError>
where
    T: Deserialize<'b>,
{
    recv_raw(recv, buf).await?;
    Ok(bincode::deserialize(buf)?)
}

/// Receives a sequence of bytes with a little-endian 4-byte length header.
///
/// `buf` will be filled with the message data excluding the 4-byte length
/// header.
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn recv_raw<'b>(
    recv: &mut RecvStream,
    buf: &mut Vec<u8>,
) -> Result<(), quinn::ReadExactError> {
    let mut len_buf = [0; mem::size_of::<u32>()];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    buf.resize(len, 0);
    recv.read_exact(buf.as_mut_slice()).await?;
    Ok(())
}

/// Receives a sequence of bytes with a little-endian 8-byte length header for handshake.
///
/// `buf` will be filled with the message data excluding the 8-byte length
/// header.
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn recv_handshake<'b>(recv: &mut RecvStream, buf: &mut Vec<u8>) -> Result<(), RecvError> {
    let mut len_buf = [0; mem::size_of::<u64>()];
    recv.read_exact(&mut len_buf).await?;
    let len: usize = u64::from_le_bytes(len_buf).try_into()?;
    buf.resize(len, 0);
    recv.read_exact(buf.as_mut_slice()).await?;
    Ok(())
}

/// Receives a sequence of bytes.
///
/// # Errors
///
/// * `quinn::ReadExactError`: if the message could not be read
pub async fn recv_bytes<'b>(
    recv: &mut RecvStream,
    buf: &mut [u8],
) -> Result<(), quinn::ReadExactError> {
    recv.read_exact(buf).await?;
    Ok(())
}

/// Sends a message as a stream of bytes with a little-endian 4-byte length header.
///
/// `buf` will be cleared after the message is sent.
///
/// # Errors
///
/// * `SendError::SerializationFailure`: if the message could not be serialized
/// * `SendError::MessageTooLarge`: if the message is too large
/// * `SendError::WriteError`: if the message could not be written
pub async fn send<T>(send: &mut SendStream, buf: &mut Vec<u8>, msg: T) -> Result<(), SendError>
where
    T: Serialize,
{
    buf.resize(mem::size_of::<u32>(), 0);
    bincode::serialize_into(&mut *buf, &msg)?;
    let len = u32::try_from(buf.len() - mem::size_of::<u32>())?;
    buf[..mem::size_of::<u32>()].clone_from_slice(&len.to_le_bytes());
    send.write_all(buf).await?;
    buf.clear();
    Ok(())
}

/// Sends a sequence of bytes with a little-endian 4-byte length header.
///
/// # Errors
///
/// * `SendError::MessageTooLarge`: if the message is too large
/// * `SendError::WriteError`: if the message could not be written
pub async fn send_raw(send: &mut SendStream, buf: &[u8]) -> Result<(), SendError> {
    let len = u32::try_from(buf.len())?;
    send.write_all(&len.to_le_bytes()).await?;
    send.write_all(buf).await?;
    Ok(())
}

/// Sends a sequence of bytes.
///
/// # Errors
///
/// * `SendError::WriteError`: if the message could not be written
pub async fn send_bytes(send: &mut SendStream, buf: &[u8]) -> Result<(), SendError> {
    send.write_all(buf).await?;
    Ok(())
}

/// Sends a sequence of bytes with a little-endian 8-byte length header for handshake.
///
/// # Errors
///
/// * `SendError::MessageTooLarge`: if the message is too large
/// * `SendError::WriteError`: if the message could not be written
pub async fn send_handshake(send: &mut SendStream, buf: &[u8]) -> Result<(), SendError> {
    let len = u64::try_from(buf.len())?;
    send.write_all(&len.to_le_bytes()).await?;
    send.write_all(buf).await?;
    Ok(())
}