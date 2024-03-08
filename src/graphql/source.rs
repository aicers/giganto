use crate::{peer::Peers, IngestSources};
use async_graphql::{Context, Object, Result};
use std::collections::HashSet;

#[derive(Default)]
pub(super) struct SourceQuery;

#[Object]
impl SourceQuery {
    async fn sources<'ctx>(&self, ctx: &Context<'ctx>) -> Result<Vec<String>> {
        let mut total_source_list = HashSet::new();
        // Add current giganto's sources
        let ingest_sources = ctx.data_opt::<IngestSources>();
        if let Some(ingest_sources) = ingest_sources {
            total_source_list.extend(ingest_sources.read().await.clone());
        }
        // Add peer giganto's sources
        let peers = ctx.data_opt::<Peers>();
        if let Some(peers) = peers {
            for peer in peers.read().await.values() {
                total_source_list.extend(peer.ingest_sources.clone());
            }
        }

        let mut sources: Vec<String> = total_source_list.into_iter().collect();
        sources.sort();
        Ok(sources)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::tests::TestSchema;
    #[tokio::test]
    async fn sources_test() {
        let schema = TestSchema::new();
        let query = r#"
        {
            sources
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{sources: [\"ingest src 1\",\"src 1\",\"src1\"]}"
        );
    }

    #[tokio::test]
    async fn sources_with_giganto_cluster() {
        const TEMP_PORT: u16 = 9999;
        let schema = TestSchema::new_with_graphql_peer(TEMP_PORT);
        let query = r#"
        {
            sources
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{sources: [\"ingest src 1\",\"ingest src 2\",\"src 1\",\"src 2\",\"src1\",\"src2\"]}"
        );
    }
}
