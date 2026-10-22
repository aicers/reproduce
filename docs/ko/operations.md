# 실행

## 실행 커맨드

REproduce는 두 가지 형태로 실행합니다. TOML 설정 파일 경로 하나를 인자로 받아
실행하거나, 설정을 Central Manager에서 받는 원격 모드로 실행합니다(자세한
내용은 [원격 모드](remote-mode.md) 참고).

```bash
reproduce <CONFIG_PATH>
reproduce --cert <CERT_PATH> --key <KEY_PATH> --ca-certs <CA_PATHS> \
  --state-dir <DIR> <server_name>@<ip>:<port>
```

- `<CONFIG_PATH>`: TOML 설정 파일 경로
- `--cert`, `--key`, `--ca-certs`, `--state-dir`, `<server_name>@<ip>:<port>`:
  원격 모드로 실행(모두 필수)
- `-h`, `--help`: 도움말 출력
- `-V`, `--version`: 버전 정보 출력

> **참고**
> 인자가 없거나, 위치 인자가 두 개 이상이거나, 설정 파일 경로에 플래그를
> 섞었거나, 원격 모드 플래그나 Central Manager 주소가 빠졌거나, 원격 모드의
> 위치 인자가 Central Manager 주소가 아니거나, 다른 플래그가 주어지면 오류
> 메시지와 사용법을 출력하고 상태 코드 `1`로 종료합니다. `-h`와 `-V`는 단독
> 인자일 때만 동작합니다.
>
> `-`로 시작하는 인자는 모두 플래그로 처리되므로, `-`로 시작하는 설정 파일
> 경로는 `./-name.toml`처럼 디렉터리를 붙여 지정해야 합니다.

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
