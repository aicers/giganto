# GraphQL

## mTLS 요구사항

서버는 실행 시 전달된 `--ca-certs` 파일(들)을 읽어 클라이언트 인증서 검증에 사용합니다.
클라이언트는 TLS 단계에서 클라이언트 인증서를 제시할 수 있어야 접속이 성립합니다.

## Playground 접속 방법

Playground는 별도 예외 없이 GraphQL 서버 라우트에 포함되어 있으며,
서버가 mTLS를 요구하므로 브라우저도 클라이언트 인증서를 제시할 수 있어야 합니다.

GraphQL 서버는 `https://<HOST>:<PORT>/graphql/playground`로 접속 가능합니다.
