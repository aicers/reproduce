# 문제 해결

## 프로세스가 시작되지 않을 때

- 설정 파일 경로를 인자로 정확히 전달했는지 확인합니다(`reproduce <CONFIG>`).
- 인자를 두 개 이상 전달하지 않았는지 확인합니다.
- 인증서, 개인 키, CA 인증서 경로가 올바른지 확인합니다.
- `log_path`가 지정되었다면 해당 파일을 열 수 있는지 확인합니다.

## 설정 파일 오류가 발생할 때

- 필수 항목 `cert`, `key`, `ca_certs`, `giganto_ingest_srv_addr`,
  `giganto_name`, `kind`, `input`이 모두 있는지 확인합니다.
- `kind`가 빈 문자열이 아닌지 확인합니다.
- `report = true`인 경우 `report_dir`이 설정되어 있는지 확인합니다.

## Giganto에 연결되지 않을 때

- `giganto_ingest_srv_addr`의 IP와 포트가 맞는지 확인합니다.
- `giganto_name`이 Giganto 서버의 TLS 이름과 일치하는지 확인합니다.
- 인증서 검증에 필요한 CA 인증서가 맞는지 확인합니다.
- Giganto 서버 버전이 0.28.0 이상인지 확인합니다.

## 입력이 처리되지 않을 때

- `input` 경로가 올바른지, 파일/디렉터리가 존재하는지 확인합니다.
- 디렉터리 모드에서 `file_prefix`로 대상 파일이 걸러지지 않았는지 확인합니다.
- `transfer_skip_count`가 전체 데이터 양보다 크게 설정되지 않았는지 확인합니다.
- `last_transfer_line_suffix` 설정으로 생성된 checkpoint 저장 파일에도 실제
  데이터 양 이상의 숫자가 저장되지 않았는지 확인합니다.
- 새 데이터가 계속 들어오는 입력이라면 `polling_mode = true` 설정을 확인합니다.

## Netflow v9 데이터가 파싱되지 않을 때

- 환경 변수 `NETFLOW_TEMPLATES_PATH`가 올바른 템플릿 경로를 가리키는지 확인합니다.
- 빌드 시 `netflow` 기능이 활성화되어 있는지 확인합니다.

## Elastic 모드에서 데이터를 가져오지 못할 때

- `[elastic]` 섹션의 모든 필수 항목이 채워져 있는지 확인합니다.
- `url`, `elastic_auth`(`username:password`)가 올바른지 확인합니다.
- `indices`, `event_codes`, `start_time`/`end_time` 범위에 실제 데이터가 있는지 확인합니다.
- `dump_dir` 경로와 쓰기 권한이 올바른지 확인합니다.
