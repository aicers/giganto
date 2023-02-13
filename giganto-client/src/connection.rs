//! Functions and errors for handling messages.

use crate::frame::{self, recv_handshake, send_handshake, RecvError, SendError};
use quinn::{Connection, ConnectionError, RecvStream, SendStream};
use semver::{Version, VersionReq};
use thiserror::Error;

/// The error type for a handshake failure.
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("Connection closed by peer")]
    ConnectionClosed,
    #[error("Connection lost")]
    ConnectionLost(#[from] ConnectionError),
    #[error("Cannot receive a message")]
    ReadError(#[from] quinn::ReadError),
    #[error("Cannot send a message")]
    WriteError(#[from] quinn::WriteError),
    #[error("Cannot serialize a message")]
    SerializationFailure(#[from] bincode::Error),
    #[error("Message is too large, so type casting failed")]
    MessageTooLarge,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Protocol version {0} is not supported")]
    IncompatibleProtocol(String),
}

impl From<SendError> for HandshakeError {
    fn from(e: SendError) -> Self {
        match e {
            SendError::SerializationFailure(e) => HandshakeError::SerializationFailure(e),
            SendError::MessageTooLarge(_) => HandshakeError::MessageTooLarge,
            SendError::WriteError(e) => HandshakeError::WriteError(e),
        }
    }
}

/// Sends a handshake request and processes the response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
pub async fn client_handshake(
    conn: &Connection,
    protocol_version: &str,
) -> Result<(SendStream, RecvStream), HandshakeError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut buf = Vec::new();
    if let Err(e) = frame::send_handshake(&mut send, protocol_version.as_bytes()).await {
        match e {
            SendError::SerializationFailure(e) => {
                return Err(HandshakeError::SerializationFailure(e))
            }
            SendError::MessageTooLarge(_) => return Err(HandshakeError::MessageTooLarge),
            SendError::WriteError(e) => return Err(HandshakeError::WriteError(e)),
        }
    }

    match frame::recv_handshake(&mut recv, &mut buf).await {
        Err(RecvError::ReadError(error)) => match error {
            quinn::ReadExactError::FinishedEarly => {
                return Err(HandshakeError::ConnectionClosed);
            }
            quinn::ReadExactError::ReadError(e) => {
                return Err(HandshakeError::ReadError(e));
            }
        },
        Err(RecvError::MessageTooLarge(_)) => {
            return Err(HandshakeError::MessageTooLarge);
        }
        Ok(_) | Err(_) => {}
    }

    bincode::deserialize::<Option<&str>>(&buf)
        .map_err(|_| HandshakeError::InvalidMessage)?
        .ok_or_else(|| HandshakeError::IncompatibleProtocol(protocol_version.to_string()))?;

    Ok((send, recv))
}

/// Processes a handshake message and sends a response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
pub async fn server_handshake(
    conn: &Connection,
    std_version: &str,
) -> Result<(SendStream, RecvStream, bool), HandshakeError> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(HandshakeError::ConnectionLost)?;

    let mut buf = Vec::new();
    recv_handshake(&mut recv, &mut buf)
        .await
        .map_err(|_| HandshakeError::InvalidMessage)?;

    let recv_version = String::from_utf8(buf).map_err(|_| HandshakeError::InvalidMessage)?;
    let version_req = VersionReq::parse(std_version).expect("valid version requirement");
    let protocol_version = Version::parse(&recv_version)
        .map_err(|_| HandshakeError::IncompatibleProtocol(recv_version))?;
    if version_req.matches(&protocol_version) {
        let is_reproduce = protocol_version.to_string().ends_with("reproduce");
        let resp_data = bincode::serialize::<Option<&str>>(&Some(std_version))?;
        send_handshake(&mut send, &resp_data)
            .await
            .map_err(HandshakeError::from)?;
        return Ok((send, recv, is_reproduce));
    }
    let resp_data = bincode::serialize::<Option<&str>>(&None)?;
    send_handshake(&mut send, &resp_data)
        .await
        .map_err(HandshakeError::from)?;
    send.finish().await.ok();
    Err(HandshakeError::IncompatibleProtocol(
        protocol_version.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use crate::test::{channel, TOKEN};

    #[tokio::test]
    async fn handshake() {
        const VERSION_REQ: &str = ">=0.7.0, <=0.8.0-alpha.1";
        const VERSION_STD: &str = "0.7.0";

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (mut server, client) = (channel.server, channel.client);

        let handle =
            tokio::spawn(async move { super::client_handshake(&client.conn, VERSION_STD).await });

        super::server_handshake(&mut server.conn, VERSION_REQ)
            .await
            .unwrap();

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn handshake_version_incompatible_err() {
        const VERSION_REQ: &str = ">=0.7.0, <=0.8.0-alpha.1";
        const VERSION_STD: &str = "0.9.0";

        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (mut server, client) = (channel.server, channel.client);

        let handle =
            tokio::spawn(async move { super::client_handshake(&client.conn, VERSION_STD).await });

        let res = super::server_handshake(&mut server.conn, VERSION_REQ).await;
        assert!(res.is_err());

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_err());
    }
}
