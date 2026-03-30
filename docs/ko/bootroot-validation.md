# Bootroot mTLS 검증 런북

이 문서는 Giganto(data-store)의 Bootroot 방식 mTLS를 위한 공유
검증 환경을 설명합니다. 다운스트림 저장소에서 전체 환경을 재정의하지
않고 이 설정을 재사용하여 클라이언트 연결을 검증할 수 있습니다.

관련 이슈:

- [aicers/giganto#1556][issue] — 이 이슈 (공유 검증 환경)
- [aicers/giganto#1555][1555] — Bootroot mTLS 사전 요구 변경사항

[issue]: https://github.com/aicers/giganto/issues/1556
[1555]: https://github.com/aicers/giganto/issues/1555

## 개요

검증 환경은 다음을 제공합니다:

- `leaf <- intermediate <- root` 형태의 Bootroot 인증서 체인
- `intermediate + root`를 포함하는 CA 번들
- 인증서 생성, 서버 시작, 스모크 체크를 위한 스크립트
- 로컬 생성 인증서와 실제 Bootroot 발급 인증서 오버라이드 지원

## 사전 요구사항

- OpenSSL CLI (인증서 생성용)
- curl (스모크 체크용)
- 빌드된 Giganto 바이너리 (`cargo build --release`) 또는
  `PATH`에 `giganto`
- **[aicers/giganto#1555][1555]**: 전체 CA 번들 지원을 위해
  Bootroot mTLS 사전 요구 변경사항이 머지되어야 합니다

## 빠른 시작

모든 스크립트는 `tools/bootroot-validation/`에 있습니다.

### 1. 인증서 픽스처 생성

```bash
cd tools/bootroot-validation
./generate-fixtures.sh
```

`checked-fixtures/`에 다음 파일이 생성됩니다:

| 파일                | 설명                           |
|--------------------|--------------------------------|
| `root.pem`         | 루트 CA 인증서                  |
| `root.key`         | 루트 CA 개인키                  |
| `intermediate.pem` | 중간 CA 인증서                  |
| `intermediate.key` | 중간 CA 개인키                  |
| `leaf.pem`         | 리프 인증서 (`CN=localhost`)    |
| `leaf.key`         | 리프 개인키                     |
| `ca-bundle.pem`    | CA 번들 (intermediate + root)   |

### 2. 검증 서버 시작

```bash
./start-validation.sh --generate
```

서버는 기본적으로 `https://localhost:8443`에서 수신합니다.

### 3. 스모크 체크 실행

별도의 터미널에서:

```bash
./smoke-check.sh
```

### 실제 Bootroot 인증서 사용

```bash
export REAL_BOOTROOT_LEAF_PEM=/path/to/real/leaf.pem
export REAL_BOOTROOT_KEY_PEM=/path/to/real/leaf.key
export REAL_BOOTROOT_CA_BUNDLE=/path/to/real/ca-bundle.pem

./start-validation.sh
./smoke-check.sh
```

자세한 내용은 영문 문서
`docs/en/bootroot-validation.md`를 참조하세요.
