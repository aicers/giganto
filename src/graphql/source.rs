use crate::storage::Database;
use async_graphql::{Context, Object, Result};

#[derive(Default)]
pub(super) struct SourceQuery;

#[Object]
impl SourceQuery {
    #[allow(clippy::unused_async)]
    async fn sources<'ctx>(&self, ctx: &Context<'ctx>) -> Result<Vec<String>> {
        let db = ctx.data::<Database>()?;
        let source_store = db.sources_store()?;
        let names = source_store.names();
        let res: Vec<String> = names
            .iter()
            .map(|key| String::from_utf8(key.clone()).expect("from utf8"))
            .collect();
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;
    use chrono::Utc;

    #[tokio::test]
    async fn sources_test() {
        let schema = TestSchema::new();
        let store = schema.db.sources_store().unwrap();
        store.insert("src 1", Utc::now()).unwrap();
        store.insert("src 2", Utc::now()).unwrap();
        store.insert("src 1", Utc::now()).unwrap();
        store.insert("src 3", Utc::now()).unwrap();
        store.insert("src 1", Utc::now()).unwrap();

        let query = r#"
        {
            sources
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{sources: [\"src 1\",\"src 2\",\"src 3\"]}"
        );
    }
}
