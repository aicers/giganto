# 설정

## 주요 설정 항목 요약

- `ingest_srv_addr`: ingest QUIC 수신 주소, 기본값 `[::]:38370`
- `publish_srv_addr`: publish QUIC 수신 주소, 기본값 `[::]:38371`
- `graphql_srv_addr`: GraphQL 서버 주소, 기본값 `[::]:8443`
- `data_dir`: 이벤트 저장 디렉터리(필수), 사전에 생성
- `export_dir`: Export 파일 저장 디렉터리(필수), 기본값 없음
- `retention`: 데이터 보관 기간, 기본값 `100d`
- `ack_transmission`: ACK를 전송하는 기준값, 기본값 `1024`
- `max_open_files`: RocksDB 최대 오픈 파일 수, 기본값 `8000`
- `max_mb_of_level_base`: RocksDB Level 1 최대 크기 기준(MB), 기본값 `512`
- `num_of_thread`: DB 백그라운드 스레드 수, 기본값 `8`
- `max_subcompactions`: sub-compaction 수, 기본값 `2`
- `compression`: RocksDB 압축 사용 여부, 기본값 `false`
- `web_shutdown_timeout`: HTTPS GraphQL 서버의 정상 종료 대기 시간. 종료가
  시작되면 서버는 새 요청 수신을 멈추고, 이미 수락된 요청이 끝날 때까지 이
  시간만큼 기다린 뒤 여전히 진행 중인 요청을 종료합니다. 기본값 `30s`
- `drain_report_interval`: 종료 과정에서 아직 실행 중인 작업이 남아 있음을
  보고하는 주기. 타임아웃이 아니라 보고 주기입니다. 배출(drain)은 모든 작업이
  끝날 때까지 시간에 상관없이 기다리며, 이 값은 아직 기다리는 중이라는 사실을
  얼마나 자주 알릴지만 결정합니다. 0보다 커야 하며, 기본값 `5s`
- `peer_srv_addr`: 노드 간 통신 수신 주소, 기본값 없음
- `peers`: (클러스터) 연동 노드 목록, 기본값 없음

## 단일 노드 설정 예시

```toml
ingest_srv_addr = "0.0.0.0:38370"
publish_srv_addr = "0.0.0.0:38371"
graphql_srv_addr = "0.0.0.0:8443"

data_dir = "/path/to/giganto/data"
export_dir = "/path/to/giganto/export"

retention = "100d"
max_open_files = 8000
max_mb_of_level_base = 512
num_of_thread = 8
max_subcompactions = 2
ack_transmission = 1024

compression = false
web_shutdown_timeout = "30s"
drain_report_interval = "5s"
```

## 클러스터 설정 예시

```toml
peer_srv_addr = "10.0.0.10:38383"
peers = [
  { addr = "10.0.0.11:38383", hostname = "giganto-node-2" },
  { addr = "10.0.0.12:38383", hostname = "giganto-node-3" }
]
```

`peer_srv_addr`는 **유효한 주소가 설정된 경우에만** P2P 클러스터 모드로 동작합니다.
`peers` 주소와 호스트명은 실제 운영 네트워크와 인증서 정책에 맞춰 결정해야 합니다.

## 설정 파일 백업/복구

- Giganto는 설정 파일 업데이트 시 `<config>.toml.bak` 형태의 백업을 생성합니다.
- 실행 시 설정 파일을 읽지 못하면, `.toml.bak`가 존재하는 경우 백업으로 복구를 시도합니다.

## 압축 설정 시 주의사항

- Giganto는 DB 디렉터리(`data_dir`) 내 `COMPRESSION` 메타데이터 파일에 압축 설정을 저장하고,
  시작 시 현재 설정과 메타데이터가 불일치하면 오류를 내고 기동을 거부합니다.
- 한 번 생성된 DB에서 `compression` 옵션을 변경하는 것은 지원되지 않으며,
  변경하려면 DB를 재생성해야 합니다.
