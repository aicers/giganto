use crate::{
    ingestion,
    storage::{gen_key, Database},
};
use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection, Edge},
    Context, Object, Result, SimpleObject,
};

use std::fmt::Debug;

use super::PagingType;

#[derive(SimpleObject, Debug)]
struct LogRawEvent {
    log: String,
}

#[derive(Default)]
pub(super) struct LogQuery;

impl From<ingestion::Log> for LogRawEvent {
    fn from(l: ingestion::Log) -> LogRawEvent {
        let (_, log) = l.log;
        LogRawEvent {
            log: base64::encode(log),
        }
    }
}

#[Object]
impl LogQuery {
    #[allow(clippy::too_many_arguments)]
    async fn log_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        source: String,
        kind: String,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, LogRawEvent>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_paging_type_log(ctx, &source, &kind, after, before, first, last)
            },
        )
        .await
    }
}

fn load_paging_type_log(
    ctx: &Context<'_>,
    source: &str,
    kind: &str,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, LogRawEvent>> {
    let db = ctx.data::<Database>()?;
    let paging_type = check_paging_type(after, before, first, last)?;

    let args: Vec<Vec<u8>> = vec![source.as_bytes().to_vec(), kind.as_bytes().to_vec()];
    let source_kind = String::from_utf8(gen_key(args))?;

    let (logs, prev, next) = db.log_store()?.log_events(&source_kind, paging_type);
    let mut connection: Connection<String, LogRawEvent> = Connection::new(prev, next);
    for log_data in logs {
        let (key, raw_data) = log_data;
        let de_log = bincode::deserialize::<ingestion::Log>(&raw_data)?;
        connection
            .edges
            .push(Edge::new(base64::encode(key), LogRawEvent::from(de_log)));
    }
    Ok(connection)
}

fn check_paging_type(
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> anyhow::Result<PagingType> {
    if let Some(val) = first {
        if let Some(cursor) = after {
            return Ok(PagingType::AfterFirst(cursor, val));
        }
        return Ok(PagingType::First(val));
    }
    if let Some(val) = last {
        if let Some(cursor) = before {
            return Ok(PagingType::BeforeLast(cursor, val));
        }
        return Ok(PagingType::Last(val));
    }
    Err(anyhow!("Invalid paging type"))
}
