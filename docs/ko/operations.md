# 실행

## 실행 커맨드

REproduce는 TOML 설정 파일 경로 하나를 인자로 받아 실행합니다.

```bash
reproduce <CONFIG_PATH>
```

- `<CONFIG_PATH>`: TOML 설정 파일 경로(필수)
- `-h`, `--help`: 도움말 출력
- `-V`, `--version`: 버전 정보 출력

> **참고**
> 인자가 없거나 두 개 이상이면 오류 메시지를 출력하고 종료합니다.

## 파일 모드 실행

`input`에 단일 로그 파일 경로를 지정한 설정 파일로 실행합니다.

```bash
reproduce /path/to/config.toml
```

## 디렉터리 모드 실행

`input`에 디렉터리 경로를 지정하면 디렉터리 안의 로그 파일들을 처리합니다.
필요 시 `[directory]` 섹션에서 `file_prefix`로 대상 파일을 제한합니다.

`[file]`에 `last_transfer_line_suffix`가 설정되어 있으면, 파일명이
`_{last_transfer_line_suffix}`로 끝나는 파일은 파일별 checkpoint 전용으로
예약되며 디렉터리 스캔에서 무시됩니다. 실제 입력 파일명과 겹치지 않는
접미사를 선택하세요.

## Elastic 모드 실행

`input = "elastic"`로 지정하고 `[elastic]` 섹션을 작성한 설정 파일로 실행하면
Elasticsearch 서버에 질의해 데이터를 가져옵니다.

## 폴링 모드

`[file]` 또는 `[directory]` 섹션에서 `polling_mode = true`로 지정하면 파일이나
디렉터리에 새로 추가되는 내용을 계속 감시하며 전송합니다.

## 설정 다시 읽기(SIGHUP)

실행 중 프로세스에 `SIGHUP` 신호를 보내면 다음 재접속 시 Giganto 연결을 다시 설정합니다.
설정 파일 갱신 후 프로세스를 재시작하지 않고 반영할 때 사용합니다.

## 시작 직후 확인할 항목

- 프로세스가 즉시 종료되지 않는지 확인합니다.
- 인증서 또는 설정 파일에 오류가 없는지 확인합니다.
- Giganto 서버와 연결되는지 확인합니다.
- `"Data Broker started"` 로그가 출력되는지 확인합니다.
