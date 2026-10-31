# 실행

## 실행 커맨드

Giganto는 아래 형태로 실행합니다.

```bash
giganto -c <CONFIG_PATH> --cert <CERT_PATH> --key <KEY_PATH> --ca-certs \
<CA_CERT_PATH>[,<CA_CERT_PATH>,...]
```

- `-c <CONFIG_PATH>`: TOML 설정 파일 경로 (필수)
- `--cert <CERT_PATH>`: 서버 인증서(PEM) (필수)
- `--key <KEY_PATH>`: 서버 개인키(PEM) (필수)
- `--ca-certs <CA_CERT_PATH>[,...]`: 클라이언트 인증 검증용 CA 인증서(PEM) 목록 (필수)

`--ca-certs` 입력 방식

- 콤마(,)로 여러 값을 한 번에 전달하거나, `--ca-certs` 옵션을 반복해 여러 CA를 지정할 수 있습니다.

로그

- Giganto는 로그를 표준 출력에 씁니다.
- 수준은 `RUST_LOG`로 정하며 기본값은 `info`입니다.
- 표준 출력이나 표준 오류가 systemd 저널에 연결되어 있으면(`JOURNAL_STREAM`) 각
  이벤트를 syslog 우선순위(`<3>` 오류, `<4>` 경고, `<6>` 정보, `<7>` 디버그·트레이스)로
  시작하는 한 줄로, 타임스탬프와 색상 코드 없이 쓰고, 이벤트 안의 줄바꿈은 `\n`으로
  씁니다. 패닉은 오류 항목 하나로 기록합니다.
- 그 밖의 경우 색상 코드는 터미널에만 씁니다.
- `--log-path`는 제거되었으며 지정하면 시작이 거부됩니다.

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

Giganto는 인증서를 스스로 교체하지 않습니다. 운영자가 디스크의 파일을
교체한 뒤 `SIGHUP` 신호를 보내며, Giganto는 이 작업이 한 시간에 한 번
꼴로 반복되는 것까지 지원합니다. 재적재는 실행되는 시점의 파일을 다시
읽으므로, 여러 번 보낸 신호는 하나의 재적재로 합쳐지고 필요 이상으로
신호를 보내도 잃는 것은 없습니다.

Giganto는 `SIGHUP` 신호를 받으면 디스크에서 인증서, 개인키, CA
파일을 다시 읽어 피어 서브시스템에 전달합니다. 피어 서브시스템은
이를 다음과 같은 관찰 가능한 동작으로 적용합니다.

- 재적재가 성공하면, 이후 새 인바운드 피어 핸드셰이크와 아웃바운드
  재연결 시도는 갱신된 피어 TLS 자재를 관찰합니다.
- 갱신된 자재를 적용할 수 없는 경우(예: 인증서와 개인키가 유효한
  쌍을 이루지 않는 경우) 기존 피어 TLS 상태를 그대로 유지합니다.
  실패 사실은 로그로 남으며, 피어 서브시스템은 이전에 설치되어
  있던 자재로 계속 동작합니다.
- 피어 GraphQL 요청은 다음 요청부터 재적재된 인증서를 사용하며,
  이전 클라이언트가 풀에 보관하던 연결은 그 클라이언트와 함께
  닫힙니다.

장수명 연결 처리 정책:

- **수립된 피어 서버 연결**은 재적재 이전에 이미 맺어진 경우
  원래 TLS 상태를 유지한 채 자연 종료되거나 대체될 때까지 계속
  동작합니다. 재적재 이후의 신규 인바운드 피어 핸드셰이크는
  갱신된 서버 리프 인증서를 관찰합니다.
- **아웃바운드 피어 클라이언트 연결**도 이미 맺어져 있다면 원래
  TLS 상태로 유지됩니다. 이후의 재연결 시도는 갱신된 피어
  클라이언트 설정을 사용해 갱신된 리프 인증서를 관찰합니다.
