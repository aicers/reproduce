# 설치 전 준비

## 필수 준비 사항

- 인증서, 개인 키, 신뢰할 CA 인증서(PEM 형식)
- TOML 설정 파일
- Giganto 서버 0.27.0 이상

## Netflow v9 입력 사용 시 준비

Netflow v9 pcap에 데이터 레코드 해석에 필요한 템플릿이 함께 들어 있지 않은 경우에는 사전에 저장한
템플릿 파일을 사용할 수 있습니다. 템플릿 파일은 환경 변수 `NETFLOW_TEMPLATES_PATH`로 지정한
경로에서 읽어옵니다.

```bash
export NETFLOW_TEMPLATES_PATH=/path/to/netflow_templates
```

Netflow 파싱 기능은 빌드 시 `netflow` 기능(기본 활성화)이 켜져 있어야 사용할 수 있습니다.
