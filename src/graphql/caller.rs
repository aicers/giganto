//! Who is calling: the service name in the caller's client certificate.
//!
//! The GraphQL HTTPS stream records each connection's service name when its
//! TLS handshake completes, in [`GraphqlCallers`], and the GraphQL endpoint
//! puts the connection's remote address and that table into every request's
//! data. Nothing here verifies a certificate: the verifier accepted it before
//! its service name was read.

use std::sync::Arc;

use async_graphql::{Context, Guard, Result};
use poem::web::RemoteAddr;

use crate::web::GraphqlCallers;

/// The service name in REview's certificate.
pub(crate) const REVIEW_SERVICE: &str = "review";

/// The service name in a Giganto node's certificate, which a peer's relayed
/// request carries.
pub(crate) const GIGANTO_SERVICE: &str = "giganto";

/// Returns the service name of the request's caller, or `None` when the
/// request carries no caller, the caller's connection is not recorded, or its
/// certificate carries no service name.
pub(crate) fn caller_service(ctx: &Context<'_>) -> Option<String> {
    let remote = ctx.data_opt::<RemoteAddr>()?.as_socket_addr().copied()?;
    ctx.data_opt::<Arc<GraphqlCallers>>()?.service_name(remote)
}

/// A guard that lets only REview call a field.
pub(crate) struct ReviewOnly;

impl Guard for ReviewOnly {
    fn check(&self, ctx: &Context<'_>) -> impl Future<Output = Result<()>> + Send {
        std::future::ready(if caller_service(ctx).as_deref() == Some(REVIEW_SERVICE) {
            Ok(())
        } else {
            Err("only REview may call this field".into())
        })
    }
}
