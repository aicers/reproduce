# 설정 (TOML)

## 주요 설정 항목 요약

| 설정 항목 | 설명 | 기본값 |
| --- | --- | --- |
| `cert` | 인증서 파일 경로 | - |
| `key` | 개인키 파일 경로 | - |
| `ca_certs` | CA 인증서 파일 경로 목록 | - |
| `giganto_ingest_srv_addr` | Giganto ingest 서버 IP:포트 | - |
| `giganto_name` | Giganto 서버 이름(TLS 서버 이름) | - |
| `kind` | 처리할 데이터 종류 | - |
| `input` | 입력 소스(파일/디렉터리/elastic) | - |
| `report` | 전송 통계 리포트 활성화 여부 | `false` |
| `report_dir` | 리포트 저장 디렉터리. `report = true`일 때 필요 | - |
| `log_path` | 로그 파일 경로. 미지정 시 stdout으로 출력 | - |

## 항목별 상세 동작

### `kind` 동작

- 빈 문자열이거나 공백만으로 이루어진 값이면 설정 오류로 종료됩니다.
- 지원하는 `kind` 값은 아래와 같습니다.

#### 네트워크 이벤트

`conn`, `http`, `rdp`, `smtp`, `dns`, `ntlm`, `kerberos`, `ssh`, `dce_rpc`,
`ftp`, `mqtt`, `ldap`, `tls`, `smb`, `nfs`, `bootp`, `dhcp`, `radius`,
`malformed_dns`, `icmp`

#### Sysmon 이벤트

`process_create`(1), `file_create_time`(2), `network_connect`(3),
`process_terminate`(5), `image_load`(7), `file_create`(11),
`registry_value_set`(13), `registry_key_rename`(14),
`file_create_stream_hash`(15), `pipe_event`(17), `dns_query`(22),
`file_delete`(23), `process_tamper`(25),
`file_delete_detected`(26)

#### Netflow / 로그

- OpLog: `oplog`
- Netflow: `netflow5`, `netflow9`
- 보안 로그: `wapples_fw_6.0`, `mf2_ips_4.0`, `sniper_ips_8.0`, `aiwaf_waf_4.1`,
  `tg_ips_2.7`, `vforce_ips_4.6`, `srx_ips_15.1`, `sonicwall_fw_6.5`,
  `fgt_ips_6.2`, `shadowwall_ips_5.0`, `axgate_fw_2.1`
- OS 로그: `ubuntu_syslog_20.04`
- 웹 로그: `nginx_accesslog_1.25.2`
- 비정형 로그: 비어 있지 않은 임의의 문자열

> **참고**
> 비정형 로그는 `kind`가 비어 있지 않은 한 사용자가 정한 임의 값을 쓸 수 있습니다.
> 지정한 `kind`는 데이터 저장 및 조회 시 식별자로 사용됩니다.

### `log_path` 동작

- 미지정: stdout으로 출력
- 지정: 해당 파일로 로그 출력
- 지정한 파일을 열 수 없으면 오류로 종료됩니다.

### `report` / `report_dir` 동작

- `report = true`이면 `report_dir` 아래에 `{kind}.report` 파일로 전송 통계를 기록합니다.
  디렉터리가 없으면 자동으로 생성됩니다.
- `report = true`인데 `report_dir`이 없으면 설정 오류로 종료됩니다.
- `report = false`(기본값)이면 `report_dir`은 무시됩니다.
- 절대 경로와 상대 경로를 모두 사용할 수 있으나, 모호함을 피하기 위해 절대 경로 사용을 권장합니다.

## 파일 모드 선택 설정

단일 파일 입력에서 처리 범위, 폴링, Giganto export 파일 import 등을 설정할 때 사용합니다.

| 설정 항목 | 설명 | 기본값 |
| --- | --- | --- |
| `import_from_giganto` | Giganto export 파일 처리 활성화 | `false` |
| `polling_mode` | 파일 폴링 모드 활성화 여부 | `false` |
| `transfer_count` | 전송할 레코드 수 | - |
| `transfer_skip_count` | 전송 전에 건너뛸 레코드 수 | - |
| `last_transfer_line_suffix` | 마지막 전송 줄 저장 파일의 접미사 | - |

이 접미사를 설정하면 REproduce는 소스 파일 옆에
`{input}_{last_transfer_line_suffix}` 형식의 checkpoint 파일에 진행 상태를
저장합니다. 파일명이 `_{last_transfer_line_suffix}`로 끝나는 이름은 checkpoint
전용으로 예약됩니다.

> **참고**
> 디렉터리 모드에서는 파일명(basename)이 `_{last_transfer_line_suffix}`로
> 끝나는 파일을 디렉터리 스캔에서 건너뜁니다. 실제 입력 로그 이름이 같은
> 패턴을 쓰고 있다면, 입력 파일명과 겹치지 않는 접미사를 선택하세요.

## 디렉터리 모드 선택 설정

디렉터리 안의 파일을 필터링하거나 새 파일을 계속 감시할 때 사용합니다.

| 설정 항목 | 설명 | 기본값 |
| --- | --- | --- |
| `file_prefix` | 디렉터리 입력 시 대상 파일명 접두사 | - |
| `polling_mode` | 디렉터리 폴링 모드 활성화 여부 | `false` |

## Elastic 모드 추가 설정

Elasticsearch 서버에서 로그를 가져올 때 작성합니다. `input = "elastic"`일 때 모든 항목이 필수입니다.

| 설정 항목 | 설명 |
| --- | --- |
| `url` | Elasticsearch 서버 IP:포트 |
| `event_codes` | 대상 Sysmon 이벤트 코드 목록 |
| `indices` | 질의할 Elasticsearch 인덱스 목록 |
| `start_time` | 대상 이벤트 시작 시각 |
| `end_time` | 대상 이벤트 종료 시각 |
| `size` | 질의당 가져올 최대 레코드 수 |
| `dump_dir` | CSV 파일을 저장할 디렉터리 경로 |
| `elastic_auth` | Elasticsearch 인증 정보(`username:password`) |

## 설정 예시

### Zeek 로그 파일을 Giganto로 전송하는 예시

```toml
cert = "/opt/clumit/keys/reproduce_cert.pem"
key = "/opt/clumit/keys/reproduce_key.pem"
ca_certs = ["/opt/clumit/keys/manager_cert.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "data-store"
kind = "dns"
input = "/path/to/zeek_file"
```

### Elasticsearch에서 Sysmon 데이터 가져오는 예시

```toml
cert = "/opt/clumit/keys/reproduce_cert.pem"
key = "/opt/clumit/keys/reproduce_key.pem"
ca_certs = ["/opt/clumit/keys/manager_cert.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "data-store"
kind = "process_create"
input = "elastic"

[elastic]
url = "http://127.0.0.1:9200/"
event_codes = ["1", "7", "11", "17", "25", "26"]
indices = [".ds-winlogbeat-8.8.2-2023.11.29-000001"]
start_time = "2023-08-06T15:00:00.000Z"
end_time = "2023-09-07T02:00:00.000Z"
size = 100000
dump_dir = "/path/to/dump"
elastic_auth = "admin:admin"
```

### 리포트 활성화하는 예시

```toml
report = true
report_dir = "/var/lib/reproduce/reports"
```

### 파일 폴링 모드 예시

```toml
[file]
polling_mode = true
```

### 디렉터리 파일 접두사 필터 예시

```toml
[directory]
file_prefix = "dns"
polling_mode = true
```
