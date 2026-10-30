"""Output formatters: pretty terminal, JSON, SARIF (GitHub code scanning)."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict
from typing import List

from . import __version__
from .rules import ALL_RULES, SEVERITY_ORDER
from .scanner import Finding, ScanResult

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[93m", "low": "\033[96m"}
DIM, BOLD, RESET, GREEN = "\033[2m", "\033[1m", "\033[0m", "\033[1;92m"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
REPO_URL = "https://github.com/Cyberspidey617/ghostprompt"


def pretty(result: ScanResult, findings: List[Finding], color: bool = True) -> str:
    c = (lambda code, s: f"{code}{s}{RESET}") if color else (lambda code, s: s)
    out = [c(BOLD, f"👻 GhostPrompt v{__version__}") + c(DIM, f"  scanned {result.files_scanned} file(s)"), ""]
    by_file = defaultdict(list)
    for f in findings:
        by_file[f.path].append(f)
    for path, items in by_file.items():
        out.append(c(BOLD, path))
        for f in items:
            sev = c(COLORS[f.severity], f" {f.severity.upper()} ")
            out.append(f"  {f.line}:{f.column}  {sev}  {c(BOLD, f.rule_id)} {f.name}")
            out.append(f"        {f.message}")
            out.append(c(DIM, f"        │ {f.snippet}"))
        out.append("")
    counts = Counter(f.severity for f in findings)
    if not findings:
        out.append(c(GREEN, "✔ No hidden prompt injections found."))
    else:
        parts = [f"{counts.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low")]
        out.append(c(BOLD, f"✖ {len(findings)} finding(s): ") + ", ".join(parts))
    return "\n".join(out)


def to_json(result: ScanResult, findings: List[Finding]) -> str:
    return json.dumps({
        "version": __version__,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "findings": [asdict(f) for f in findings],
    }, indent=2, ensure_ascii=False)


def to_sarif(result: ScanResult, findings: List[Finding]) -> str:
    rules = [{
        "id": r.id,
        "name": r.name,
        "shortDescription": {"text": r.description},
        "helpUri": f"{REPO_URL}#rules",
        "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
        "properties": {"security-severity": str({1: 3.0, 2: 5.5, 3: 7.5, 4: 9.5}[SEVERITY_ORDER[r.severity]])},
    } for r in ALL_RULES]
    results = [{
        "ruleId": f.rule_id,
        "level": SARIF_LEVEL[f.severity],
        "message": {"text": f.message},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.path.lstrip("./") if f.path.startswith("./") else f.path},
            "region": {"startLine": f.line, "startColumn": f.column},
        }}],
    } for f in findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "GhostPrompt", "version": __version__,
                                "informationUri": REPO_URL, "rules": rules}},
            "results": results,
        }],
    }, indent=2, ensure_ascii=False)
