# PINO 오탐 규칙 (fp-rules)

PINO AVM 이 취약점 판정에서 **확인된 오탐**을 자동으로 예외 처리하는 데 쓰는 규칙 모음입니다.
`fp` 는 False Positive(오탐)의 약자입니다.

규칙 하나는 "**이 생태계의 이 패키지**에 붙은 **이 CVE 들**은 오탐이다"를 말합니다. 세 조건이 모두 맞을 때만 숨깁니다.

```yaml
id: FP-0001
status: active
cves: [CVE-2018-9116]
match:
  purl_type: cargo        # 생태계 (PURL 종류)
  purl_name: wiremock     # 패키지 이름
  versions: "*"           # "*" 또는 정확한 버전 목록
reason:
  ko: 이 CVE 는 Java 라이브러리 WireMock 의 취약점이다. Rust 크레이트 wiremock 과는 이름만 같은 다른 제품이다.
```

- PURL 이 없는 컴포넌트(바이너리에서 CPE 로만 찾은 것)에는 걸지 않습니다. 모르면 숨기지 않습니다.
- 고객 환경에 따라 달라지는 판단("그 기능을 쓰지 않는다", 네트워크 차단 등)은 규칙으로 만들지 않습니다.

## 받는 곳

PINO AVM 미러가 하루 한 번 최신 발행본을 받습니다. 주소는 늘 같습니다.

```
https://github.com/pinolike-co/fp-rules/releases/latest/download/version.txt
https://github.com/pinolike-co/fp-rules/releases/latest/download/fp-rules.json
```

고객사는 설정 › 시스템 상태 › 분석기의 **"PINO 오탐 규칙 사용"** 으로 언제든 전체를 끌 수 있습니다.

## 기여 (PINO 담당자)

```sh
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
cp rules/_template.yaml rules/FP-0002-<생태계>-<이름>.yaml   # 번호는 가장 큰 번호 + 1
cp tests/_template.yaml tests/FP-0002.yaml
make check
```

PR 을 열면 `check` 가 형식·중복·삭제·테스트를 검사해 댓글로 남깁니다. 작성자가 아닌 1명이 승인해 머지하면
`release` 가 `YYYY.MM.DD.N` 버전으로 GitHub Release 를 발행합니다. 규칙은 지우지 않고 `status: withdrawn` 으로 철회합니다.
