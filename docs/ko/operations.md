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
