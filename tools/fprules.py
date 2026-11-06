"""오탐 규칙 공용 함수 — check.py·build.py 가 함께 쓴다.

판정 규칙은 avm-core 의 적용 코드와 같아야 한다. 여기를 바꾸면 avm-core 도 같이 바꾼다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
TESTS_DIR = ROOT / "tests"
CORPUS_DIR = ROOT / "corpus"
SCHEMA_PATH = ROOT / "schema" / "rule.schema.json"
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str | None
    name: str
    version: str | None


def parse_purl(text: str) -> Purl | None:
    """pkg:type/namespace/name@version?qualifiers#subpath 를 나눈다. 형식이 아니면 None."""
    if not text or not text.startswith("pkg:"):
        return None
    rest = text[4:].split("#", 1)[0].split("?", 1)[0]
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)
    parts = [unquote(p) for p in rest.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    ptype = parts[0].lower()
    name = parts[-1]
    namespace = "/".join(parts[1:-1]) or None
    return Purl(ptype, namespace, name, version)


def _norm_name(ptype: str, name: str) -> str:
    """생태계별 이름 정규화. pypi 는 PEP 503(대소문자·_.- 무시), 나머지는 소문자 비교."""
    if ptype == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def rule_matches(rule: dict, purl_text: str, vuln_id: str) -> bool:
    """규칙이 이 컴포넌트·취약점에 걸리는가. 조건은 모두 AND."""
    if rule.get("status") != "active":
        return False
    if vuln_id not in rule["cves"]:
        return False
    return component_matches(rule, purl_text)


def component_matches(rule: dict, purl_text: str) -> bool:
    """CVE 를 빼고 컴포넌트 조건만 본다(기준 SBOM 영향 측정용)."""
    purl = parse_purl(purl_text)
    if purl is None:                       # PURL 이 없으면 걸지 않는다 — 모르면 숨기지 않는다
        return False
    m = rule["match"]
    if purl.type != m["purl_type"]:
        return False
    if _norm_name(purl.type, purl.name) != _norm_name(purl.type, m["purl_name"]):
        return False
    ns = m.get("purl_namespace")
    if ns is not None and (purl.namespace or "").lower() != ns.lower():
        return False
    versions = m.get("versions", "*")
    if versions != "*" and purl.version not in versions:
        return False
    return True


class _Loader(yaml.SafeLoader):
    """날짜(2026-10-02)를 date 객체가 아니라 문자열 그대로 읽는다 — JSON 으로 그대로 내보내기 위해."""


_Loader.yaml_implicit_resolvers = {
    k: [r for r in v if r[0] != "tag:yaml.org,2002:timestamp"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        data = yaml.load(f, Loader=_Loader)
    if not isinstance(data, dict):
        raise ValueError(f"{path.name}: YAML 최상위가 맵이 아닙니다")
    return data


def load_rules() -> list[tuple[Path, dict]]:
    return [(p, load_yaml(p)) for p in sorted(RULES_DIR.glob("FP-*.yaml"))]


def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


def corpus_components() -> dict[str, list[str]]:
    """기준 SBOM(CycloneDX JSON)별 PURL 목록. 하위 컴포넌트까지 펼친다."""
    result: dict[str, list[str]] = {}
    for path in sorted(CORPUS_DIR.glob("*.json")):
        bom = json.loads(path.read_text(encoding="utf-8"))
        purls: list[str] = []
        stack = list(bom.get("components", []))
        while stack:
            c = stack.pop()
            if c.get("purl"):
                purls.append(c["purl"])
            stack.extend(c.get("components", []))
        result[path.name] = purls
    return result
