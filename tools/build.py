"""발행 묶음 만들기 — main 에 머지되면 release.yml 이 돌린다.

    python tools/build.py --version 2026.11.06.1 [--previous prev/fp-rules.json] [--out dist]

dist/ 에 fp-rules.json · version.txt · notes.md 를 쓴다.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from fprules import SCHEMA_VERSION, load_rules, validator

VERSION_RE = re.compile(r"^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$")


def version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--previous", help="직전 발행본 fp-rules.json (변경 내역용)")
    ap.add_argument("--out", default="dist")
    args = ap.parse_args()

    if not VERSION_RE.match(args.version):
        print(f"버전 형식이 아닙니다: {args.version} (예: 2026.11.06.1)", file=sys.stderr)
        return 1

    v = validator()
    rules = []
    for path, rule in load_rules():
        errs = list(v.iter_errors(rule))
        if errs:
            print(f"{path.name}: 형식 오류 — check.py 를 먼저 통과시키세요", file=sys.stderr)
            return 1
        rules.append(rule)
    rules.sort(key=lambda r: r["id"])

    prev_rules: dict[str, dict] = {}
    if args.previous and Path(args.previous).exists():
        prev = json.loads(Path(args.previous).read_text(encoding="utf-8"))
        if version_key(args.version) <= version_key(prev["version"]):
            print(f"새 버전 {args.version} 이 직전 {prev['version']} 보다 커야 합니다", file=sys.stderr)
            return 1
        prev_rules = {r["id"]: r for r in prev["rules"]}

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    bundle = {
        "schemaVersion": SCHEMA_VERSION,
        "version": args.version,
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rules": rules,
    }
    (out / "fp-rules.json").write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "version.txt").write_text(args.version + "\n", encoding="utf-8")

    added = [r for r in rules if r["id"] not in prev_rules]
    withdrawn = [r for r in rules if r["status"] == "withdrawn"
                 and prev_rules.get(r["id"], {}).get("status") == "active"]
    changed = [r for r in rules if r["id"] in prev_rules and r != prev_rules[r["id"]] and r not in withdrawn]
    notes = [f"# 오탐 규칙 {args.version}", "",
             f"규칙 {len(rules)}개 (활성 {sum(r['status'] == 'active' for r in rules)})", ""]
    for title, items in (("추가", added), ("변경", changed), ("철회", withdrawn)):
        if items:
            notes.append(f"## {title}")
            notes += [f"- {r['id']} `{r['match']['purl_type']}/{r['match']['purl_name']}` — "
                      f"{', '.join(r['cves'])}" for r in items]
            notes.append("")
    if not (added or changed or withdrawn):
        notes.append("규칙 내용 변경 없음 (도구·문서 변경)")
    (out / "notes.md").write_text("\n".join(notes) + "\n", encoding="utf-8")
    print((out / "notes.md").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
