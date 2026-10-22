# 원격 모드

원격 모드에서 REproduce는 설정을 파일이 아닌 Central Manager(REview)에서
받습니다. 하나의 데이터 저장소(Giganto) 연결 위에서 1~64개의 로그 수집기를
실행하며, 각 수집기는 로그 파일 하나를 따라가며 모든 줄을 수집기의 kind를 가진
Giganto `Log` 레코드로 전송합니다.

원격 모드는 Linux에서 동작합니다. 보통 Host Agent가 설치하고 아래 커맨드로
실행하므로 직접 실행할 일은 드뭅니다.

## 실행 커맨드

```bash
reproduce --cert <CERT_PATH> --key <KEY_PATH> --ca-certs <CA_PATHS> \
  --state-dir <DIR> <server_name>@<ip>:<port>
```

<!-- markdownlint-disable MD013 -->

| 인자 또는 플래그 | 동작 |
| --- | --- |
| `--cert <CERT_PATH>` | Central Manager와 Giganto에 제시하는 인증서 |
| `--key <KEY_PATH>` | 인증서의 개인 키 |
| `--ca-certs <CA_PATHS>` | 신뢰할 CA 인증서 파일 목록(쉼표로 구분) |
| `--state-dir <DIR>` | 체크포인트를 두는 디렉터리. 없으면 모드 `0700`으로 생성 |
| `<server_name>@<ip>:<port>` | Central Manager의 TLS 서버 이름과 주소 |

<!-- markdownlint-enable MD013 -->

- 네 플래그와 Central Manager는 모두 필수입니다. IPv6 주소는
  `name@[::1]:38390`처럼 대괄호로 감쌉니다.
- Central Manager와 Giganto에 같은 인증서 하나를 사용합니다.
- 커맨드 라인이 올바르지 않거나, 상태 디렉터리를 만들거나 쓸 수 없거나,
  인증서·키·CA 파일을 읽을 수 없으면 상태 코드 `1`로 종료합니다.

## 원격 설정

Central Manager는 설정을 TOML로 제공합니다.

```toml
giganto_ingest_srv_addr = "10.0.0.5:38370"
giganto_name = "001.giganto.ds1.customer.example"

[[collectors]]
type = "log"
kind = "nginx_access"
path = "/var/log/nginx/access.log"
start = "end"
```

<!-- markdownlint-disable MD013 -->

| 키 | 필수 | 규칙 |
| --- | --- | --- |
| `giganto_ingest_srv_addr` | 예 | Giganto 수집 서버의 `IP:PORT` |
| `giganto_name` | 예 | 비어 있지 않은 Giganto TLS 서버 이름 |
| `collectors` | 예 | 테이블 배열, 1~64개 |
| `collectors.type` | 예 | `"log"`(유일한 값) |
| `collectors.kind` | 예 | `^[a-z0-9][a-z0-9_.-]{0,63}$`에 맞고, Giganto의 이름 있는 kind가 아니며, 설정 안에서 유일 |
| `collectors.path` | 예 | 아래 경로 규칙을 따르고, 설정 안에서 유일 |
| `collectors.start` | 아니요 | `"end"`(기본값) 또는 `"beginning"` |

<!-- markdownlint-enable MD013 -->

- 어느 수준에서든 알 수 없는 키가 있으면 거부하며, 빈 설정도 거부합니다.
- kind는 레이블입니다. 모든 수집기는 자기 kind로 `Log` 레코드를 보냅니다.
  `dns`, `conn`, `http`, `op_log`처럼 Giganto가 다른 원시 이벤트 종류로 읽는
  kind는 거부합니다. Clumit Security Web은 한 노드의 모든 수집기 사이에서도
  kind가 유일하도록 관리합니다.
- 경로는 절대 경로이고, 4096바이트 이하이며, NUL을 포함하지 않고, 비어 있거나
  `.` 또는 `..`인 구간과 끝의 `/`가 없어야 하며, `/etc/clumit-security`,
  `/var/lib/clumit-security`, `/opt/clumit-security`, `/proc` 아래에 있으면
  안 됩니다.
- 규칙을 어긴 설정은 오류로 기록하고 적용하지 않습니다. 이미 적용된 설정은
  계속 동작하고, 적용된 설정이 없으면 대기 상태를 유지합니다.

## 생명 주기

- **대기.** 설정이 없으면 아무것도 수집하지 않습니다. Central Manager 연결은
  5초마다 다시 시도하며 유지하고, Central Manager가 요청할 때, 다시 연결할
  때마다, 그리고 `SIGHUP`을 받으면 설정을 다시 가져옵니다. REproduce는 설정
  사본을 보관하지 않으므로, 재시작 후에는 Central Manager가 응답할 때까지
  대기합니다.
- **적용.** 새 설정은 차이만 적용합니다. 수집기는 kind와 경로로 식별합니다.
  두 설정에 모두 있는 수집기는 그대로 계속 동작하며, 바뀐 `start`는 적용되지
  않습니다. 제거된 수집기는 스트림을 닫고(종료 마커를 보내고 최종 확인 응답을
  모두 합쳐 최대 15초 기다림) 체크포인트를 삭제합니다. kind는 같고 경로가 바뀐
  수집기는 새 수집기로 처음부터 시작합니다.
- **Giganto 주소 변경.** `giganto_ingest_srv_addr`나 `giganto_name`이 바뀌면
  기존 연결을 즉시 끊고 새 주소로 연결합니다. 같은 설정으로 제거된 수집기는
  종료 마커 없이 멈추고, 나머지는 새 연결에서 확인된 위치부터 이어서 읽습니다.
- **장애.** Giganto 연결, TLS, 핸드셰이크 실패는 5초마다 다시 시도하며,
  Central Manager와의 연결이 끊겨도 수집기는 멈추지 않습니다. 어느 쪽도
  프로세스를 끝내지 않습니다.
- **수집기별 문제.** 파일이 없거나, 읽을 수 없거나, 거부되었거나, 일반 파일이
  아닌 것은 해당 수집기만의 문제입니다. 수집기의 상태가 바뀔 때 경고로 기록하고
  3초마다 다시 시도하며, 다른 수집기는 계속 동작합니다.

## 상태 디렉터리와 체크포인트

각 로그 수집기는 체크포인트를 `<state-dir>/checkpoints/log/<kind>.json`에
저장합니다.

```json
{"type":"log","kind":"nginx_access","path":"/var/log/nginx/access.log","dev":2049,"ino":131074,"offset":5120}
```

`dev`와 `ino`는 수집기가 읽던 파일을 가리키고, `offset`은 Giganto가 확인한
마지막 줄 바로 다음 바이트입니다.

- 체크포인트는 최대 1초에 한 번, 바뀐 뒤 1초 안에 저장하며, 정상 종료할 때와
  시작 위치를 정할 때에도 저장합니다.
- `<kind>.json.tmp`에 쓰고 디스크에 동기화한 뒤 `<kind>.json`으로 이름을
  바꿉니다. 중단된 저장이 남긴 임시 파일은 시작할 때 삭제합니다.
- kind의 다른 경로에 대한 체크포인트는 교체합니다.
- 손상되었거나 읽을 수 없는 체크포인트는 경고로 기록합니다. 체크포인트를 읽어
  들일 때 설정된 로그 경로의 메타데이터를 읽을 수 있으면 그 대신 로그의 현재
  끝을 사용하며, 이 위치는 `start`보다 우선하고 아무것도 보내기 전에
  저장합니다.
- 그 메타데이터를 읽을 수 없으면 대신 쓸 위치가 없으므로, 체크포인트가 없는
  수집기의 규칙(시작 위치 참고)대로 시작합니다. 기본적으로 파일 끝에서,
  `start = "beginning"`이면 처음부터 읽으며, 처음 열려고 할 때 없던 경로는
  `start`와 관계없이 나타났을 때 처음부터 읽습니다. 그러면 이미 보낸 파일을
  처음부터 다시 읽을 수 있습니다. `start = "beginning"`이면 그 파일을 읽을
  때마다 그렇고, `start = "end"`이면 체크포인트를 읽어 들일 때와 처음 열려고
  할 때 모두 설정된 경로가 없었고 나중에 이미 보낸 같은 파일이 복원된 경우에
  그렇습니다.
- 저장할 수 없는 체크포인트는 경고로 한 번 기록하고 3초마다 다시 시도하며,
  수집기는 계속 동작합니다.

## 시그널

- `SIGHUP`은 두 연결 모두에 TLS 파일 재로드를 표시하며, 각 연결은 다음에 다시
  연결할 때 파일을 다시 읽습니다. 대기 상태에서는 설정도 다시 가져옵니다.
- `SIGTERM`과 `SIGINT`는 모든 스트림을 종료 마커와 함께 닫고(최종 확인 응답을
  모두 합쳐 최대 15초 기다림), 모든 체크포인트를 저장한 뒤 상태 코드 `0`으로
  종료합니다.

## 시작 위치

- 체크포인트가 없을 때 `start = "end"`(기본값)는 파일 끝에서 시작해 기존
  내용을 건너뛰고, `start = "beginning"`은 처음부터 읽습니다.
- 수집기가 시작할 때 없던 파일은 `start`와 관계없이 나타났을 때 처음부터
  읽습니다.
- 시작 위치는 Giganto 연결 여부와 관계없이 수집기가 시작할 때 정하고, 어떤
  줄도 보내기 전에 저장하므로 첫 확인 응답 전에 재시작해도 줄을 건너뛰지
  않습니다. 저장하지 못하는 동안에는 아무것도 보내지 않습니다.
- 체크포인트가 있으면 `start`를 무시하고 체크포인트부터 이어서 읽습니다.
  손상되었거나 읽을 수 없는 체크포인트는, 읽어 들일 때 설정된 경로를 살펴볼
  수 있었으면 로그 끝의 체크포인트로, 그렇지 않으면 체크포인트가 없는 것으로
  처리합니다.

## 파일 따라가기

- **줄.** 줄은 `\n`에서 끝나며, 끝의 `\r`은 제거하고 빈 줄은 건너뜁니다.
  마지막 `\n` 뒤의 바이트는 `\n`이 올 때까지 보관합니다. 1MiB보다 긴 줄은
  1MiB 조각으로 나누어 보냅니다. 줄은 최대 1000줄 또는 4MiB씩 묶어 보냅니다.
- **확인.** 파일 끝에 도달하면 3초마다 경로를 확인합니다.
- **이름 변경 로테이션.** 경로가 새 파일을 가리키면, 기존 파일에 3초 동안 새
  바이트가 없을 때까지 기존 파일을 계속 읽고, 보관 중인 바이트를 마지막 줄로
  보낸 뒤 새 파일을 처음부터 읽습니다. 새 파일을 열 수 없는 동안에는 기존
  파일을 계속 읽으며, 보관 중인 바이트는 그 파일에서 줄을 마저 이룰 수
  있습니다. 기존 파일은 Giganto가 그 마지막 줄을 확인할 때까지 읽지 않은 채
  열어 둡니다. 그사이 또 로테이션이 일어나면 그 뒤에야 따라가므로, 수집기가
  여는 파일은 최대 두 개입니다.
- **복사 후 자르기(copy-truncate).** 파일이 수집기가 읽은 것보다 짧아지면
  보관 중인 바이트를 버리고, 새 위치를 저장한 뒤 파일을 처음부터 다시
  읽습니다.
- **경로 없음.** 경로가 없는 동안에는 열어 둔 파일을 계속 읽습니다.
- **심볼릭 링크.** 경로는 심볼릭 링크를 따라갑니다. 링크가 다른 파일을
  가리키게 되면 이름 변경 로테이션으로 처리합니다.
- **거부되는 파일.** 일반 파일이고, 실제 위치의 상위 디렉터리 중 어느 것도
  `/etc/clumit-security`, `/var/lib/clumit-security`, `/opt/clumit-security`,
  `/proc`이 아닐 때만 엽니다. 디렉터리는 식별자로 비교하므로 심볼릭 링크나
  옮겨진 제품 디렉터리도 거부합니다. FIFO나 장치 파일은 수집기를 멈추게 하지
  않고 거부합니다.

## 전송 보장

- 모든 줄은 적어도 한 번 전송됩니다. 각 수집기는 재연결, 스트림 오류, 비정상
  종료 후 Giganto가 확인한 위치부터 이어서 읽으므로, 실패한 스트림에 썼던 줄은
  다시 읽어 보냅니다. 확인 응답을 기다리는 줄이 있는 스트림이 실패하면, 파일이
  늘어나지 않아도 곧바로 스트림을 교체합니다.
- 그 위치의 파일 이름이 바뀌었으면 같은 디렉터리에서 찾아 나머지를 먼저 읽은
  뒤 경로를 읽습니다. 그런 파일이 있지만 열 수 없거나, 열기 전에 사라지거나,
  디렉터리의 파일을 살펴볼 수 없는 동안에는 넘어가지 않고 3초마다 다시
  시도하며, 그 위치를 담은 파일이 없을 때에만 경로를 처음부터 읽고 줄이
  유실되었을 수 있다고 기록합니다.
- 재연결이나 비정상 종료가 일어나면 수집기마다 확인 응답 창 하나만큼, 즉
  Giganto의 `ack_transmission` 줄 수(기본값 1024)와 전송 중이던 줄, 또는 60초
  분량의 줄을 다시 보낼 수 있습니다.
- 한 수집기 안에서 타임스탬프는 엄격하게 증가하므로 두 줄이 같은 Giganto 키를
  갖지 않습니다. 줄의 이벤트 시각은 전송한 시각입니다.

## 줄이 유실되거나 중복될 수 있는 경우

- **복사 후 자르기.** 수집기가 마지막으로 읽은 뒤 자르기 전까지 쓰인 줄은
  복사본에만 있어 유실됩니다. 3초 안에 파일이 이전 오프셋을 넘어 다시 커져
  자르기를 알아채지 못하면 그사이의 줄이 유실되며, 자르기를 알아챘지만 새 위치를
  저장하기 전에 멈춘 경우도 마찬가지입니다. 자르기를 알아채기 전에 보냈지만
  아직 확인되지 않은 줄은, 잘린 파일의 것이든 아직 열어 둔 로테이션 이전
  파일의 것이든, 그 뒤 스트림이 실패하면 유실됩니다.
- **같은 inode의 더 짧은 파일로 덮어쓴 경우**는 자르기로 처리합니다.
- **이름 변경 로테이션.** 두 번의 확인 사이에 두 번 로테이션된 파일은 읽지
  못합니다. 수집기가 새 파일로 옮긴 뒤 이름이 바뀐 파일에 쓰인 바이트는
  유실됩니다.
- **inode 재사용.** 관련 없는 파일이 같은 inode 번호를 재사용하면 잘못된
  오프셋에서 이어서 읽을 수 있습니다.
- **`\n`이 없는 마지막 줄**은 파일이 로테이션될 때까지 보관합니다. 종료할 때는
  보내지 않으며, 재시작 후 줄이 완성되면 보냅니다.
- **체크포인트 손상.** 체크포인트가 손상되었거나 읽을 수 없고 그것을 읽어
  들일 때 설정된 로그 경로를 살펴볼 수 없었으면, 이미 보낸 파일 전체를 다시
  보냅니다. `start = "beginning"`이면 그 파일을 읽을 때마다 그렇고,
  `start = "end"`이면 처음 열려고 할 때도 설정된 경로가 없었고 나중에 이미
  보낸 같은 파일이 복원된 경우에 그렇습니다.
- **중복.** 재연결이나 비정상 종료가 일어나면 수집기마다 확인 응답 창
  하나만큼을 다시 보낼 수 있습니다.

## 로그

<!-- markdownlint-disable MD013 -->

| 수준 | 로그 |
| --- | --- |
| `INFO` | `Started collector <kind> for <path>` |
| `INFO` | `Reading <file> for <kind>`(수집기가 파일을 열 때마다) |
| `INFO` | `<path> for <kind> was truncated; reading it again from its beginning` |
| `INFO` | `Resuming <file> for <kind> by its inode only` |
| `INFO` | `Stopped collector <kind> for <path> ...` |
| `WARN` | `Collector <kind> for <path>: <reason>; retrying every 3s` |
| `WARN` | `Cannot find the file <kind> was reading before <path>; lines may have been lost` |
| `WARN` | `Sending failed for <kind>: ...` |
| `INFO` | `Sending again for <kind>`(`Sending failed` 이후) |
| `WARN` | `Cannot save the checkpoint of <kind> to <file>: ...` |
| `INFO` | `Saved the checkpoint of <kind> again` |

<!-- markdownlint-enable MD013 -->

수집기의 `<reason>`은 다음 중 하나입니다.

- `the path does not exist`
- `the path is not a regular file`
- `the file lies under the refused directory <dir>`
- `cannot check where the file lies: ...`
- `cannot inspect the path: ...`
- `cannot open the file: ...`
- `cannot read the file: ...`
- `cannot start the reader: ...`
- `the predecessor candidate <candidate> disappeared before it could be opened`
