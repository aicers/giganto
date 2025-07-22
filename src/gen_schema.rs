#![allow(unused)]

mod comm;
mod graphql;
mod server;
mod settings;
mod storage;
mod web;

use std::fs;

use anyhow::{Context, Result};
use async_graphql::{EmptySubscription, Schema};

use crate::graphql::{Mutation, Query};

const GRAPHQL_SCHEMA_PATH: &str = "src/graphql/client/schema/schema.graphql";

fn main() -> Result<()> {
    fs::write(
        GRAPHQL_SCHEMA_PATH,
        Schema::build(Query::default(), Mutation::default(), EmptySubscription)
            .finish()
            .sdl(),
    )
    .context("Failed to write the GraphQL schema")?;
    println!("Successfully exported the GraphQL schema");
    Ok(())
}
