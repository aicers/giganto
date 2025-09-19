#![allow(unused)]

mod bincode_utils;
mod comm;
mod graphql;
mod server;
mod settings;
mod storage;
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
