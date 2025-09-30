//! Data transfer module for forwarding events from local Giganto to cloud Giganto.
//!
//! This module implements the core functionality for transferring raw events from
//! local (edge) Giganto instances to cloud (central) Giganto instances using QUIC protocol.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use giganto_client::{RawEventKind, connection::client_handshake, frame::send_raw};
use quinn::{ClientConfig, Connection, Endpoint};
use tokio::{
    select,
    sync::{
        Notify,
        mpsc::{UnboundedReceiver, unbounded_channel},
    },
    time::sleep,
};
use tracing::{debug, error, info, warn};

use crate::server::{Certs, config_client};

const TRANSFER_VERSION_REQ: &str = ">=0.26.0-alpha.6,<0.26.0-alpha.7";
const TRANSFER_RETRY_INTERVAL: u64 = 5;

/// Represents a raw event to be transferred to the cloud.
#[derive(Debug, Clone)]
pub struct TransferEvent {
    /// The kind of raw event being transferred.
    pub kind: RawEventKind,
    /// The timestamp of the event.
    pub timestamp: i64,
    /// The serialized event data.
    pub data: Vec<u8>,
}

/// Configuration for the data transfer client.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Address of the cloud Giganto instance to transfer data to.
    pub cloud_address: SocketAddr,
    /// Local address to bind the client to.
    pub local_address: SocketAddr,
}

/// Client for transferring data from local to cloud Giganto instances.
pub struct TransferClient {
    client_config: ClientConfig,
    cloud_address: SocketAddr,
    local_address: SocketAddr,
}

impl TransferClient {
    /// Creates a new `TransferClient`.
    ///
    /// # Arguments
    ///
    /// * `config` - Transfer configuration
    /// * `certs` - TLS certificates for secure communication
    ///
    /// # Returns
    ///
    /// Returns a new `TransferClient` instance and a receiver for monitoring transfer events.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The client configuration cannot be created with the provided certificates
    pub fn new(
        config: &TransferConfig,
        certs: &Arc<Certs>,
    ) -> Result<(Self, UnboundedReceiver<TransferEvent>)> {
        let client_config = config_client(certs)
            .context("failed to create client configuration for data transfer")?;

        let (_event_sender, event_receiver) = unbounded_channel();

        Ok((
            Self {
                client_config,
                cloud_address: config.cloud_address,
                local_address: config.local_address,
            },
            event_receiver,
        ))
    }

    /// Runs the transfer client, continuously attempting to connect to the cloud
    /// and forward events.
    ///
    /// # Arguments
    ///
    /// * `event_receiver` - Channel receiver for events to be transferred
    /// * `notify_shutdown` - Notification signal for graceful shutdown
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The QUIC endpoint cannot be created
    /// * Fatal errors occur during operation (non-recoverable errors will be logged and retried)
    pub async fn run(
        self,
        mut event_receiver: UnboundedReceiver<TransferEvent>,
        notify_shutdown: Arc<Notify>,
    ) -> Result<()> {
        let client_socket = SocketAddr::new(self.local_address.ip(), 0);
        let mut endpoint = Endpoint::client(client_socket)
            .context("failed to create QUIC endpoint for data transfer")?;
        endpoint.set_default_client_config(self.client_config.clone());

        let cloud_address = self.cloud_address;

        info!(
            "Transfer client initialized, will forward events to {}",
            cloud_address
        );

        loop {
            select! {
                () = notify_shutdown.notified() => {
                    info!("Shutting down transfer client");
                    endpoint.close(0_u32.into(), &[]);
                    break;
                }
                () = Self::run_transfer_loop(cloud_address, &endpoint, &mut event_receiver, &notify_shutdown) => {
                    warn!("Transfer connection lost, retrying in {} seconds", TRANSFER_RETRY_INTERVAL);
                    sleep(Duration::from_secs(TRANSFER_RETRY_INTERVAL)).await;
                }
            }
        }

        Ok(())
    }

    /// Runs a single iteration of the transfer loop, establishing connection and forwarding events.
    async fn run_transfer_loop(
        cloud_address: SocketAddr,
        endpoint: &Endpoint,
        event_receiver: &mut UnboundedReceiver<TransferEvent>,
        notify_shutdown: &Arc<Notify>,
    ) {
        match Self::connect_and_transfer(cloud_address, endpoint, event_receiver, notify_shutdown)
            .await
        {
            Ok(()) => {
                info!("Transfer connection closed normally");
            }
            Err(e) => {
                error!("Transfer error: {:#}", e);
            }
        }
    }

    /// Establishes connection to cloud Giganto and transfers events.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * Connection to the cloud instance cannot be established
    /// * Handshake with the cloud instance fails
    /// * Event transmission fails
    async fn connect_and_transfer(
        cloud_address: SocketAddr,
        endpoint: &Endpoint,
        event_receiver: &mut UnboundedReceiver<TransferEvent>,
        notify_shutdown: &Arc<Notify>,
    ) -> Result<()> {
        info!("Connecting to cloud Giganto at {}", cloud_address);

        let connection = endpoint
            .connect(cloud_address, "localhost")
            .context("failed to initiate connection to cloud Giganto")?
            .await
            .context("failed to establish connection to cloud Giganto")?;

        info!(
            "Connected to cloud Giganto at {}",
            connection.remote_address()
        );

        // Perform version handshake
        client_handshake(&connection, TRANSFER_VERSION_REQ)
            .await
            .context("handshake with cloud Giganto failed")?;

        info!("Handshake with cloud Giganto completed successfully");

        // Transfer events
        Self::transfer_events(connection, event_receiver, notify_shutdown).await
    }

    /// Transfers events over the established connection.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * Opening a bidirectional stream fails
    /// * Sending event header or data fails
    async fn transfer_events(
        connection: Connection,
        event_receiver: &mut UnboundedReceiver<TransferEvent>,
        notify_shutdown: &Arc<Notify>,
    ) -> Result<()> {
        let mut event_streams: std::collections::HashMap<
            RawEventKind,
            (quinn::SendStream, quinn::RecvStream),
        > = std::collections::HashMap::new();

        loop {
            select! {
                () = notify_shutdown.notified() => {
                    debug!("Shutdown signal received during event transfer");
                    break;
                }
                Some(event) = event_receiver.recv() => {
                    if let Err(e) = Self::send_event(&connection, &mut event_streams, event).await {
                        error!("Failed to send event: {:#}", e);
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Sends a single event to the cloud Giganto instance.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * Opening a new stream for the event type fails
    /// * Sending the event header or data fails
    async fn send_event(
        connection: &Connection,
        event_streams: &mut std::collections::HashMap<
            RawEventKind,
            (quinn::SendStream, quinn::RecvStream),
        >,
        event: TransferEvent,
    ) -> Result<()> {
        // Get or create a stream for this event type
        let (send, _recv) = if let Some(streams) = event_streams.get_mut(&event.kind) {
            streams
        } else {
            debug!("Opening new stream for event type: {:?}", event.kind);
            let (send, recv) = connection
                .open_bi()
                .await
                .context("failed to open bidirectional stream for event")?;

            event_streams.insert(event.kind, (send, recv));
            event_streams.get_mut(&event.kind).expect("just inserted")
        };

        // Send event header (kind only)
        giganto_client::ingest::send_record_header(send, event.kind)
            .await
            .context("failed to send event header")?;

        // Send event with timestamp and data
        let timestamp_bytes = event.timestamp.to_le_bytes();
        let mut payload = Vec::with_capacity(timestamp_bytes.len() + event.data.len());
        payload.extend_from_slice(&timestamp_bytes);
        payload.extend_from_slice(&event.data);

        send_raw(send, &payload)
            .await
            .context("failed to send event data")?;

        debug!(
            "Transferred event: kind={:?}, timestamp={}, size={} bytes",
            event.kind,
            event.timestamp,
            event.data.len()
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_event_creation() {
        let event = TransferEvent {
            kind: RawEventKind::Conn,
            timestamp: 12345,
            data: vec![1, 2, 3, 4, 5],
        };

        assert_eq!(event.kind, RawEventKind::Conn);
        assert_eq!(event.timestamp, 12345);
        assert_eq!(event.data.len(), 5);
    }

    #[test]
    fn test_transfer_channel_creation() {
        use tokio::sync::mpsc::unbounded_channel;

        let (tx, mut rx) = unbounded_channel();

        let event = TransferEvent {
            kind: RawEventKind::Dns,
            timestamp: 67890,
            data: vec![10, 20, 30],
        };

        tx.send(event.clone()).expect("Failed to send event");

        let received = rx.blocking_recv().expect("Failed to receive event");
        assert_eq!(received.kind, event.kind);
        assert_eq!(received.timestamp, event.timestamp);
        assert_eq!(received.data, event.data);
    }
}
