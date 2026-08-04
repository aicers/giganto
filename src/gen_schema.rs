#![allow(unused)]

mod comm;
mod datetime;
mod graphql;
mod server;
mod settings;
mod storage;
#[cfg(all(test, feature = "bootroot"))]
mod test_bootroot;
mod tls_reload;
mod web;

use std::fs;

use anyhow::{Context, Result};
use async_graphql::{EmptySubscription, Schema};

use crate::graphql::{SCHEMA_PATH, generate_schema};

fn main() -> Result<()> {
    fs::write(SCHEMA_PATH, generate_schema()).context("Failed to write the GraphQL schema")?;
    println!("Successfully exported the GraphQL schema");
    Ok(())
}
