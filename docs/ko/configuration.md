# 설정

## 주요 설정 항목 요약

- `ingest_srv_addr`: ingest QUIC 수신 주소, 기본값 `[::]:38370`
- `publish_srv_addr`: publish QUIC 수신 주소, 기본값 `[::]:38371`
- `graphql_srv_addr`: GraphQL 서버 주소, 기본값 `[::]:8443`
- `data_dir`: 이벤트 저장 디렉터리(선택, 기본값: `data`). 생략하면 시작 시 생성되며,
  명시적으로 설정한 디렉터리는 이미 존재해야 합니다.
- `export_dir`: Export 파일 저장 디렉터리(선택, 기본값: `export`), 첫 Export 시 생성
- `retention`: 데이터 보관 기간, 기본값 `100d`, 최대 `3650d`(일 단위로 쓰며
  `10y`는 이보다 깁니다)
- `oplog_retention`: 운영 로그(OpLog) 보관 기간, 기본값 `365d`, `1d`~`3650d`.
  다른 데이터는 `retention`을 따릅니다.
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
- `peer_srv_addr`: 노드 간 통신 수신 주소, 기본값 없음. 다른 노드가 이 노드에
  GraphQL 요청을 보내려면 `0.0.0.0`이나 `[::]`가 아닌 특정 주소여야 합니다
- `peers`: (클러스터) 연동 노드 목록, 기본값 없음

디스크 사용량이 95%를 넘으면 보존 작업은 사용량이 85% 아래로 내려가거나 더 지울
데이터가 없을 때까지 두 보관 기간을 하루씩 줄입니다.

상대 경로인 `data_dir`와 `export_dir`는 프로세스의 작업 디렉터리를 기준으로 합니다.

`updateConfig`로 변경된 설정을 저장하면 원래 생략했던 `data_dir`도 설정 파일에
기록됩니다. 이후에는 명시적으로 설정한 경로로 취급되므로 다음 시작 시 디렉터리가
이미 존재해야 합니다.

64비트 대상에서 RocksDB 설정의 유효 범위는 `max_open_files = 20..=C`,
`max_mb_of_level_base = 1..=262144`, `num_of_thread = 1..=128`,
`max_subcompactions = 1..=8`입니다. C는 시작 시 한 번 읽은 프로세스의 soft
`RLIMIT_NOFILE`을 사용한 `max(20, min(soft RLIMIT_NOFILE, i32::MAX))`이며,
읽기에 실패하면 `4194304`입니다. 스레드 상한은 제품 정책입니다.
이 범위는 유효성 제한이며 성능 튜닝 권장값이 아닙니다.

시작 시 범위를 벗어난 TOML 값은 가장 가까운 경계로 보정합니다. 단,
`max_open_files = -1`은 C로 보정합니다. 변경된 필드마다 파일 값, 적용 값,
유효 범위를 포함하는 WARN을 한 번 기록합니다. TOML은 수정하지 않으며,
RocksDB, `--repair`, `config` 쿼리는 보정된 값을 사용합니다.
범위 안의 값은 변경하지 않으며 보정 경고도 기록하지 않습니다.

`updateConfig`는 음수 `max_open_files`를 포함한 범위 밖의 값을 거부하며,
상태를 변경하거나 요청을 큐에 넣지 않습니다. 수락한 업데이트 이후 압축 메타데이터
검증, 데이터 디렉터리 마이그레이션, 데이터베이스 열기 중 실패하면 원인을 ERROR로
기록하고 이전 메모리 설정과 설정 파일을 복원한 뒤 한 번 재시작합니다.
복원은 업데이트 백업을 덮어쓰지 않습니다. 파일 복원에 실패하면 파일 확인이
필요하다는 ERROR를 기록하고 이전 메모리 설정으로 시작합니다.
복원한 세대도 실패하면 종료합니다. 최초 시작, 종료 처리, 저장소를 연 이후의
실패는 복구하지 않습니다. 적용 결과는 `config` 쿼리로 확인할 수 있습니다.

## 단일 노드 설정 예시

```toml
ingest_srv_addr = "0.0.0.0:38370"
publish_srv_addr = "0.0.0.0:38371"
graphql_srv_addr = "0.0.0.0:8443"

data_dir = "/path/to/giganto/data"
export_dir = "/path/to/giganto/export"

retention = "100d"
oplog_retention = "365d"
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
  { addr = "10.0.0.11:38383", hostname = "001.giganto.node2.example.com" },
  { addr = "10.0.0.12:38383", hostname = "001.giganto.node3.example.com" }
]
```

`peer_srv_addr`는 **유효한 주소가 설정된 경우에만** P2P 클러스터 모드로 동작합니다.
`peers` 주소는 실제 운영 네트워크에 맞춰 결정해야 합니다. `peers[].hostname`은
피어 인증서의 SAN DNS 이름이며, Giganto는 피어에 연결할 때 이 이름으로 피어
인증서를 검증합니다.

`peers[].hostname`, 또는 피어가 연결할 때 알린 이름은 Giganto가 그 피어에
GraphQL 요청을 보낼 때 쓰는 이름이기도 하며, Giganto는 이 이름으로 피어 인증서를
검증합니다. 주소는 그 이름에 기록된 `addr`에서, 포트는 피어의 GraphQL 포트에서
가져옵니다.

## 인증서 요구사항

Giganto가 다루는 모든 인증서(Giganto 자신의 인증서, 클러스터 피어의 인증서,
ingest 및 publish 클라이언트의 인증서)는 `<instance>.<service>.<host>.<domain>`
형식의 SAN DNS 이름(예: `001.giganto.node1.example.com`)을 가져야 합니다.
Giganto는 이 SAN에서 센서 이름, 노드 이름, 피어 식별자를 도출하며, 이 SAN이 없는
인증서는 거부합니다. `<service>@<host>` 형식의 CN만 있는 인증서는 허용되지
않습니다. 운영 환경에서는 Bootroot가 이러한 인증서를 발급하며, 테스트에서는 SAN을
갖춘 인증서라면 어떤 CA가 발급한 정적 인증서도 사용할 수 있습니다.

## 설정 파일 백업/복구

- Giganto는 설정 파일 업데이트 시 `<config>.toml.bak` 형태의 백업을 생성합니다.
- 실행 시 설정 파일을 읽지 못하면, `.toml.bak`가 존재하는 경우 백업으로 복구를 시도합니다.

## 압축 설정 시 주의사항

- Giganto는 DB 디렉터리(`data_dir`) 내 `COMPRESSION` 메타데이터 파일에 압축 설정을 저장하고,
  시작 시 현재 설정과 메타데이터가 불일치하면 오류를 내고 기동을 거부합니다.
- 한 번 생성된 DB에서 `compression` 옵션을 변경하는 것은 지원되지 않으며,
  변경하려면 DB를 재생성해야 합니다.
