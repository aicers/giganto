# Cluster 도입 이후의 GraphQL API 작성 가이드

## Giganto Cluster의 GraphQL API 동작 방식에 대한 사전 이해

- giganto cluster에 3개의 giganto가 존재한다고 가정
  - giganto 1번서버에는 ingest-src-[1|2|3] 의 데이터가 인입
  - giganto 2번서버에는 ingest-src-[4|5|6] 의 데이터가 인입
  - giganto 3번서버에는 ingest-src-[7|8|9] 의 데이터가 인입된다고 가정
- 대표적으로 2가지의 시나리오가 존재합니다.
  - [1] 유저가 1번서버에게 ingest-src-1 데이터를 달라고 요청하는 경우
    - [1-1] 이 경우, 1번서버는 해당 데이터를 보유하고 있으므로, DB에서 찾아서
      리턴합니다.
  - [2] 유저가 1번서버에게 ingest-src-8 데이터를 달라고 요청하는 경우
    - [2-1] 이 경우, 1번서버는 해당 데이터 보유하고 있지 않습니다. 데이터는
      3번서버에 있습니다.
    - [2-2] 1번서버는 3번서버에게 GraphQL 질의를 던집니다. (이 때, reqwest 및
      GraphQL 라이브러리 사용)
    - [2-3] 1번서버는 3번서버로부터 응답을 받은 것을 파싱하여, 유저에게
      최종적으로 응답합니다.
- 한편, 조금 더 복잡한 시나리오도 2가지 존재합니다.
  - [3] 유저가 1번서버에게 ingest-src-[1,4,5] 데이터를 달라고 요청하는 경우
    - 이 경우, 1번서버는 자신의 DB에서 데이터를 찾는 동시에, 2번서버에게 GraphQL
      질의를 던지고 응답을 받습니다. 1번서버는 위의 결과물을 합쳐서 유저에게
      최종적으로 응답합니다.
  - [4] 유저가 1번서버에게 모든 ingest-src-[] 데이터를 달라고 요청하는 경우
    - 이 경우, 1번서버는 자신의 DB에서 데이터를 찾는 동시에, 모든 서버에게
      GraphQL 질의를 던지고 응답을 받습니다. 1번서버는 결과물을 합쳐서 유저에게
      최종적으로 응답합니다.

## 신규 API 작성 시 확인할 CHECKPOINT

대표적인 2가지 시나리오를 기준으로 설명합니다. 복잡한 시나리오에 대해서는 복잡한
시나리오에 대한 이해 섹션을 추가적으로 참고해주세요.

### CHECKPOINT 0. macro 호출 필수

유저로부터 인입된 GraphQL API를 [1] 시나리오로 핸들링할지, [2] 시나리오로
핸들링할지에 대한 결정은 macro에 작성되어있습니다. 핸들링 시나리오에 대한 판단은
giganto cluster 의 동작의 근간이므로,

- `paged_events_in_cluster`
- `events_in_cluster` (또는 단순화된 `events_vec_in_cluster`)

위의 macro들 중 하나의 macro는 GraphQL API endpoint에서 호출되어야 합니다.
GraqhQl API가 `Connection`으로 paging을 지원하는 경우,
`paged_events_in_cluster`의 사용을, 그렇지 않은 경우 `events_[vec_]in_cluster`의
사용을 우선 고려해주세요.

위의 macro를 사용할 수 없는 상황인 경우, 직접 giganto cluster aware한 로직을
구성해주시면 됩니다.

### CHECKPOINT 1. 각 api endpoint 가 작성되어있는 파일들 (ex. network.rs, sysmon.rs)

[1-1] 에 명시된 작업을 giganto 서버가 처리하기 위한 코드를 다음과 같이 작성할
필요가 있습니다. after / before 비교를 통한 이해가 쉬우므로, 사례를 통해
설명드립니다.

```rust
// BEFORE : 변경 전에는 API endpoint 에 비지니스 코드를 작성하였습니다.
#[Object]
impl NetworkQuery {
    async fn conn_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ConnRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.conn_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }
}

// AFTER : 변경 후에는 이 부분을 통째로 함수/클로져 로 분리할 필요가 있습니다.
// `handle_paged_conn_raw_events` 이 함수는 과거의 로직을 그대로 들고 있는 함수입니다.
// 함수 body에서 호출되고 있는 `handle_result_of_connection_type` 는
// `async_graphql::connection::query` 함수에 대한 단순 wrapper 입니다.
async fn handle_paged_conn_raw_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, ConnRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.conn_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

#[Object]
impl NetworkQuery {
    async fn conn_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ConnRawEvent>> {

        // 별도로 분리한 함수를 handler 변수에 할당합니다.
        let handler = handle_paged_conn_raw_events;

        // `Connection` 을 사용하고 있으므로, `events_connection_in_cluster` macro를 호출합니다.
        // 이를 통해 현재 giganto가 cluster 내에서 API 요청을 처리하게 됩니다.
        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            ConnRawEvents,
            conn_raw_events::Variables,
            conn_raw_events::ResponseData,
            conn_raw_events
        )
    }
}
```

### CHECKPOINT 2. 어떤 giganto peer에게 GraphQL API 질의할지 판단

[2-1] 에서 "데이터는 3번서버에 있습니다." 에 대한 판단은 아래의 2개 macro에서
발생합니다.

- `paged_events_in_cluster`
- `events_in_cluster` (또는 단순화된 `events_vec_in_cluster`)

내부에서 `fn peer_in_charge_graphql_addr` 호출을 통해 3번서버가 담당자라는 것을
알아내는데, 구체적인 로직과 macro 호출방법은 macro 정의를 참고 부탁드립니다.

### CHECKPOINT 3. src/graphql/client/derives.rs

[2-2] 에 명시된 giganto <-> giganto 간의 질의를 위해 다음과 같은 정의가
필요합니다. 신규 API 작성 시 schema_path 파일은 "수정" 이 필요하고, query_path
파일은 "신규생성"이 필요합니다.

```rust
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/conn_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct ConnRawEvents;
```

### CHECKPOINT 4. Graphql response object 가 작성되어있는 파일들 (ex. network.rs, sysmon.rs)

[2-3] 에 명시된 파싱 작업을 위해 `ConvertGraphQLEdgesNode` 를 derive하고, 관련된
`graphql_client_type` 어트리뷰트를 세팅해주어야 합니다. 세팅할 대상은
async_graphql 응답 상 `Node` 로 활용되는 것입니다. (대표적으로 `Object`,
`SimpleObject`) `ConvertGraphQLEdgesNode`에 대한 보다 복잡한 사용방법은 lib.rs에
있습니다.

```rust
#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [
    conn_raw_events::ConnRawEventsConnRawEventsEdgesNode, ])]
struct ConnRawEvent {
    timestamp: DateTime<Utc>,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    duration: i64,
    service: String,
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
}
```

cf. `conn_raw_events::ConnRawEventsConnRawEventsEdgesNode` 값은 graphql_client의
naming 규칙에 의해 생성된 값입니다. 이 값이 무엇인지 확신하기 어려운 경우, `$
cargo expand graphql::client::derives` 명령어를 통해 생성된 코드를 바탕으로 확인
부탁드립니다.

### CHECKPOINT 5. test 작성 시 `TestSchema` 사용 상 참고사항

- CHECKPOINT 5-1

```rust
TestSchema::new()
```

로 생성하는 경우, `const CURRENT_GIGANTO_INGEST_SENSORS: [&str; 3] = ["src1",
"src 1", "ingest src 1"];` 인 것만 본인이 처리할 수 있는 sensor 로 인식됩니다.

```rust
TestSchema::new_with_graphql_peer(port)
```

로 생성하는 경우, new()와 동일하게 본인은 `CURRENT_GIGANTO_INGEST_SENSORS` 에
해당하는 것을 처리할 수 있고, peer giganto는 `const PEER_GIGANTO_INGEST_SENSORS:
[&str; 3] = ["src2", "src 2", "ingest src 2"];` 에 대한 sensor를 처리할 수
있도록 세팅됩니다.

- CHECKPOINT 5-2

[2-2] 에 명시된 giganto 간의 질의에 대해서는 mocking을 하고 있습니다.

## 복잡한 시나리오에 대한 이해

### CASE [3] 유저가 1번서버에게 ingest-src-[1,4,5] 데이터를 달라고 요청하는 경우

- 특징
  - GraphQL API 상 sensor에 대한 argument가 `sensors: Vec<String>` 처럼 여러개의
    sensor를 받을 수 있는 API입니다.
- Giganto Cluster 사용법
  - 다음과 같이 `multiple_sensors` 으로 시작하는 macro variant를 호출하면 됩니다.

```rust
#[Object]
impl StatisticsQuery {
    #[allow(clippy::unused_async)]
    async fn statistics(
        &self,
        ctx: &Context<'_>,
        sensors: Vec<String>,
        time: Option<TimeRange>,
        protocols: Option<Vec<String>>,
        request_from_peer: Option<bool>,
    ) -> Result<Vec<StatisticsRawEvent>> {
        let handler = handle_statistics;

        events_in_cluster!(
            multiple_sensors  // here!
            ctx,
            sensors,
            request_from_peer,
            handler,
            Stats,
            stats::Variables,
            stats::ResponseData,
            statistics,
            Vec<StatisticsRawEvent>,
            with_extra_handler_args (&time, &protocols),
            with_extra_query_args (
                time := time.clone().map(Into::into),
                protocols := protocols.clone()
            )
        )
    }
}
```

### CASE [4] 유저가 1번서버에게 모든 ingest-src-[1..=9] 데이터를 달라고 요청하는 경우

- 특징
  - 애초에 GraphQL API의 파라미터로 sensor에 대한 정보가 주어지지 않는 경우일
    수도 있고, GraphQL API argument 혹은 nested argument로 존재하는 `sensor`가
    `Option<String>` 이고 이 값이 `Option::None`인 경우, 이 API가 모든
    `sensor`에 대한 데이터를 응답해주도록 약속한 API인 경우일 수도 있습니다.
- Giganto Cluster 사용법
  - 다음과 같이 `request_all_peers` 또는 `request_all_peers_if_sensor_is_none`가
    표기된 macro variant를 호출하면 됩니다. 이 때, 전자는 `sensor`가 `Some`인지
    `None`인지를 막론하고 모든 peer giganto에게 질의를 던지는 것을 의미하고,
    후자는 sensor가 `None`인 경우에만 모든 peer giganto에게 질의를 던지는 것을
    의미합니다.

```rust
pub struct NetflowFilter {
    time: Option<TimeRange>,
    source: Option<String>,  // check!
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    contents: Option<String>,
}

impl NetflowQuery {
    #[allow(clippy::too_many_arguments)]
    async fn netflow5_raw_events(
        &self,
        ctx: &Context<'_>,
        filter: NetflowFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, Netflow5RawEvent>> {
        let handler = handle_netflow5_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_sensor_is_none  // here!
            ctx,
            filter,
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            Netflow5RawEvents,
            netflow5_raw_events::Variables,
            netflow5_raw_events::ResponseData,
            netflow5_raw_events
        )
    }
}
```
