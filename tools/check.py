"""규칙 검사 — PR 마다 CI 가 돌리고, 작성자도 push 전에 `make check` 로 돌린다.

    python tools/check.py [--base origin/main] [--report report.md]

실패하면 종료 코드 1. --report 를 주면 PR 댓글용 마크다운을 쓴다.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict

from fprules import (RULES_DIR, TESTS_DIR, component_matches, corpus_components,
                     load_rules, load_yaml, rule_matches, validator)


def base_rule_ids(base: str) -> set[str]:
    """기준 브랜치에 있던 규칙 id. 규칙 파일은 지우지 않으므로 여기 있던 id 는 지금도 있어야 한다."""
    try:
        out = subprocess.run(["git", "ls-tree", "--name-only", base, "rules/"],
                             capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"경고: 기준 브랜치 {base} 를 읽지 못해 삭제 검사를 건너뜁니다", file=sys.stderr)
        return set()
    return {m.group(0) for line in out.splitlines() if (m := re.match(r"FP-[0-9]{4}", line.split("/")[-1]))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", help="비교할 기준 브랜치 (예: origin/main)")
    ap.add_argument("--report", help="PR 댓글용 마크다운을 쓸 경로")
    args = ap.parse_args()

    errors: list[str] = []
    v = validator()
    rules = load_rules()
    by_id: dict[str, dict] = {}

    # 1. 형식 · 파일 이름 · id 중복
    for path, rule in rules:
        for e in sorted(v.iter_errors(rule), key=lambda e: list(e.path)):
            loc = "/".join(str(p) for p in e.path) or "(최상위)"
            errors.append(f"{path.name}: {loc} — {e.message}")
        rid = rule.get("id", "")
        if not path.name.startswith(f"{rid}-") and path.name != f"{rid}.yaml":
            errors.append(f"{path.name}: 파일 이름은 '{rid}-' 로 시작해야 합니다")
        if rid in by_id:
            errors.append(f"{path.name}: id {rid} 가 다른 파일에도 있습니다")
        by_id[rid] = rule

    # 2. 지운 규칙 — 철회는 status: withdrawn 으로 한다
    if args.base:
        for rid in sorted(base_rule_ids(args.base) - set(by_id)):
            errors.append(f"{rid}: 기준 브랜치에 있던 규칙 파일이 사라졌습니다. 지우지 말고 status: withdrawn 으로 철회하세요")

    # 3. 활성 규칙끼리 겹침 — 같은 패키지·같은 CVE 를 두 규칙이 덮으면 어느 사유를 보여 줄지 모호하다
    seen: dict[tuple, str] = {}
    for rid, rule in by_id.items():
        if rule.get("status") != "active" or "match" not in rule:
            continue
        m = rule["match"]
        key = (m.get("purl_type"), (m.get("purl_namespace") or "").lower(), m.get("purl_name", "").lower())
        for cve in rule.get("cves", []):
            other = seen.get(key + (cve,))
            if other:
                errors.append(f"{rid}: {other} 와 같은 패키지·{cve} 를 덮습니다. 한 규칙으로 합치세요")
            seen[key + (cve,)] = rid

    # 4. 테스트 — 활성 규칙은 테스트 파일이 있어야 하고, 예시가 기대대로 걸려야 한다
    for rid, rule in by_id.items():
        tpath = TESTS_DIR / f"{rid}.yaml"
        if rule.get("status") != "active":
            continue
        if not tpath.exists():
            errors.append(f"{rid}: 테스트 파일 tests/{rid}.yaml 이 없습니다")
            continue
        t = load_yaml(tpath)
        if not t.get("should_match") or not t.get("should_not_match"):
            errors.append(f"{rid}: should_match 와 should_not_match 를 하나 이상씩 적어야 합니다")
        for case in t.get("should_match") or []:
            if not rule_matches(rule, case["purl"], case["cve"]):
                errors.append(f"{rid}: 걸려야 하는데 안 걸림 — {case['purl']} / {case['cve']}")
        for case in t.get("should_not_match") or []:
            if rule_matches(rule, case["purl"], case["cve"]):
                errors.append(f"{rid}: 걸리면 안 되는데 걸림 — {case['purl']} / {case['cve']}")

    # 5. 기준 SBOM 영향 — 실패 조건은 아니고 리뷰어가 볼 숫자다
    impact: dict[str, list[str]] = defaultdict(list)
    corpus = corpus_components()
    for rid, rule in by_id.items():
        if rule.get("status") != "active" or errors:
            continue
        for bom, purls in corpus.items():
            for purl in purls:
                if component_matches(rule, purl):
                    impact[rid].append(f"{bom}: `{purl}`")

    lines = ["## 오탐 규칙 검사 결과", ""]
    if errors:
        lines += ["**실패** — 아래를 고쳐 주세요.", ""] + [f"- {e}" for e in errors]
    else:
        active = sum(1 for r in by_id.values() if r.get("status") == "active")
        lines += [f"**통과** — 규칙 {len(by_id)}개(활성 {active}), 기준 SBOM {len(corpus)}개.", "",
                  "### 기준 SBOM 에서 규칙이 적용될 수 있는 컴포넌트", "",
                  "규칙의 CVE 가 실제로 붙어야 숨겨집니다. 의도보다 넓게 걸리는지 확인하세요.", ""]
        for rid in sorted(by_id):
            if by_id[rid].get("status") != "active":
                continue
            hits = impact.get(rid, [])
            lines.append(f"- **{rid}** — {len(hits)}건" + ("" if hits else " (기준 SBOM 에 해당 컴포넌트 없음)"))
            lines += [f"  - {h}" for h in hits[:20]]
            if len(hits) > 20:
                lines.append(f"  - … 외 {len(hits) - 20}건")
    report = "\n".join(lines) + "\n"
    print(report)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
