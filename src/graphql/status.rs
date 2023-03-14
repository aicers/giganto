#[cfg(debug_assertions)]
use crate::storage::Database;
#[cfg(debug_assertions)]
use async_graphql::Context;
use async_graphql::{InputObject, Object, Result, SimpleObject};

#[derive(SimpleObject, Debug)]
struct GigantoStatus {
    name: String,
    cpu_usage: f32,
    total_memory: u64,
    used_memory: u64,
    total_disk_space: u64,
    used_disk_space: u64,
}

#[derive(InputObject)]
struct PropertyFilter {
    record_type: String,
}

#[derive(SimpleObject, Debug)]
struct Properties {
    estimate_live_data_size: u64,
    estimate_num_keys: u64,
    stats: String,
}

#[derive(Default)]
pub(super) struct GigantoStatusQuery;

#[Object]
impl GigantoStatusQuery {
    async fn giganto_status(&self) -> Result<GigantoStatus> {
        let usg = roxy::resource_usage().await;
        let host_name = roxy::hostname();
        let usg = GigantoStatus {
            name: host_name,
            cpu_usage: usg.cpu_usage,
            total_memory: usg.total_memory,
            used_memory: usg.used_memory,
            total_disk_space: usg.total_disk_space,
            used_disk_space: usg.used_disk_space,
        };
        Ok(usg)
    }

    #[allow(clippy::unused_async)]
    #[cfg(debug_assertions)]
    async fn properties_cf<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: PropertyFilter,
    ) -> Result<Properties> {
        let cfname = filter.record_type;
        let db = ctx.data::<Database>()?;

        let props = db.properties_cf(&cfname)?;

        Ok(Properties {
            estimate_live_data_size: props.estimate_live_data_size,
            estimate_num_keys: props.estimate_num_keys,
            stats: props.stats,
        })
    }
}
