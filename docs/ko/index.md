# 개요

Giganto는 raw-event 저장 시스템입니다. QUIC 채널을 통해 이벤트를 수신하고,
저장된 데이터를 GraphQL API로 조회할 수 있도록 제공합니다.

## 주요 특징

- 수집기에서 들어오는 원본 이벤트를 QUIC 채널로 받아 저장
- GraphQL API 제공
- 단일 노드(standalone) 모드 지원
- 다중 노드 클러스터(cluster) 모드 지원
  - 클러스터는 여러 Giganto 노드가 서로 통신하며 하나의 서비스처럼 동작하는 구성을 의미합니다.

## 보안 전제(mTLS)

Giganto의 GraphQL 서버는 **mTLS(클라이언트 인증서 기반 TLS)**를 전제로 동작합니다.

따라서 `/graphql` 및 `/graphql/playground` 접근에는 **클라이언트 인증서가 필요**하며,
서버는 실행 시 전달받은 `--ca-certs`를 이용해 클라이언트 인증서를 검증합니다.

## 매뉴얼 구성

- **설치 전 준비:** 인증서/키/CA와 `data_dir` 디렉터리를 준비합니다.
- **설정:** 서비스 주소, 저장 경로, 보관 기간을 설정하고, 필요시에는 다중 노드 설정을 환경에 맞게 작성합니다.
- **실행:** 설정 파일과 인증서 인자로 Giganto를 기동하고, 로그 및 mTLS 기반 접속 가능 여부를 확인합니다.
- **GraphQL:** 필터·페이지네이션을 기반으로 조회/검색·Export·통계 기능을 제공하며,
  운영 제어를 위한 Mutation(`updateConfig`/`stop`/`reboot`/`shutdown`)을 지원합니다.
- **문제 해결**: 자주 발생하는 오류와 대응 방법입니다.

## 빠른 시작 절차

1. `data_dir` 디렉터리 생성
2. `config.toml` 작성
3. Giganto 실행
4. mTLS 클라이언트 인증 후 `https://<HOST>:<PORT>/graphql/playground` 접속
5. 조회할 GraphQL query 확인 및 수정
