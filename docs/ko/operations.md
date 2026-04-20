# 실행

## 실행 커맨드

Giganto는 아래 형태로 실행합니다.

```bash
giganto -c <CONFIG_PATH> --cert <CERT_PATH> --key <KEY_PATH> --ca-certs \
<CA_CERT_PATH>[,<CA_CERT_PATH>,...] [--log-path <LOG_PATH>]
```

- `-c <CONFIG_PATH>`: TOML 설정 파일 경로 (필수)
- `--cert <CERT_PATH>`: 서버 인증서(PEM) (필수)
- `--key <KEY_PATH>`: 서버 개인키(PEM) (필수)
- `--ca-certs <CA_CERT_PATH>[,...]`: 클라이언트 인증 검증용 CA 인증서(PEM) 목록 (필수)
- `--log-path <LOG_PATH>`: 로그 파일 경로 (선택)

`--ca-certs` 입력 방식

- 콤마(,)로 여러 값을 한 번에 전달하거나, `--ca-certs` 옵션을 반복해 여러 CA를 지정할 수 있습니다.

`--log-path` 동작

- 미지정: stdout로 출력
- 지정 + 쓰기 가능: 해당 파일로 출력
- 지정 + 쓰기 불가: Giganto 종료
- 트레이싱 초기화 이전에 발생한 로그는 stdout/stderr로 직접 출력될 수 있습니다.

## 기본 실행

```bash
giganto -c /path/to/giganto/config.toml \
  --cert /path/to/giganto/certs/cert.pem \
  --key /path/to/giganto/certs/key.pem \
  --ca-certs /path/to/giganto/certs/ca_cert.pem
```

## 여러 CA 인증서 사용

여러 CA 인증서를 신뢰해야 하는 경우에는 아래 두 방식 중 하나를 사용할 수 있습니다.

```bash
# 쉼표로 구분
giganto -c /path/to/giganto/config.toml \
  --cert /path/to/giganto/certs/cert.pem \
  --key /path/to/giganto/certs/key.pem \
  --ca-certs /path/to/giganto/certs/ca1.pem,/path/to/giganto/certs/ca2.pem

# 인자 반복
giganto -c /path/to/giganto/config.toml \
  --cert /path/to/giganto/certs/server.crt \
  --key /path/to/giganto/certs/server.key \
  --ca-certs /path/to/giganto/certs/ca1.pem \
  --ca-certs /path/to/giganto/certs/ca2.pem
```

## 시작 직후 확인할 항목

- 프로세스가 즉시 종료되지 않는지 확인합니다.
- 로그에 GraphQL 서버 시작 메시지가 출력되는지 확인합니다.

## 피어 서브시스템 TLS 재적재

Giganto는 `SIGHUP` 신호를 받으면 디스크에서 인증서, 개인키, CA
파일을 다시 읽어 각 서브시스템으로 전달합니다. 피어 서브시스템은
이 신호에 대해 다음과 같이 원자적 준비/적용 절차를 수행합니다.

- 먼저 새 자재로 피어 서버용과 피어 클라이언트용 TLS 설정을
  각각 빌드합니다.
- 두 빌드가 모두 성공한 경우에만 한꺼번에 적용합니다. 피어 서버
  엔드포인트는 새 서버 설정으로 교체되고, 피어 클라이언트 설정
  슬롯도 새 값으로 대체됩니다.
- 둘 중 하나라도 빌드에 실패하면 교체를 중단하고 기존 피어 TLS
  상태를 보존합니다. 실패 사실은 로그로 남으며, 피어 서브시스템은
  이전 자재로 계속 동작합니다.

장수명 연결 처리 정책:

- **수립된 피어 서버 연결**은 재적재 이전에 이미 맺어진 경우
  원래 TLS 상태를 유지한 채 자연 종료되거나 대체될 때까지 계속
  동작합니다. 재적재 이후의 신규 인바운드 피어 핸드셰이크는
  새로운 서버 리프 인증서를 관찰합니다.
- **아웃바운드 피어 클라이언트 연결**도 이미 맺어져 있다면 원래
  TLS 상태로 유지됩니다. 이후의 재연결 시도는 새 피어 클라이언트
  설정을 사용해 새 리프 인증서를 관찰합니다.
