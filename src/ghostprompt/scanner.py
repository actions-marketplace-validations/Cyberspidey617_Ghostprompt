"""Core scanning engine."""
from __future__ import annotations

import base64
import binascii
import bisect
import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

from .rules import PATTERN_RULES, RULES_BY_ID
from .unicode_checks import find_unicode, visible

SUPPRESS = re.compile(r"ghostprompt:\s*ignore", re.IGNORECASE)
DEFAULT_EXCLUDES = [
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache", "*.min.js",
]
B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
INVISIBLE_STYLE = re.compile(
    r"<(\w+)[^>]*style\s*=\s*[\"'][^\"']*"
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?![.\d]))"
    r"[^>]*>(.*?)</\1>",
    re.IGNORECASE | re.DOTALL,
)
HIDDEN_KEYWORDS = re.compile(
    r"\b(ignore|instructions?|system prompt|assistant|ai agent|language model|llm|you must)\b", re.IGNORECASE
)
UNICODE_RULE = {"tag": "GP201", "variation-selector": "GP202", "zero-width": "GP203", "bidi": "GP204"}


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    message: str
    path: str
    line: int
    column: int
    snippet: str


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0


def _short(s: str, n: int = 90) -> str:
    s = " ".join(visible(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def pattern_hits(text: str) -> List[str]:
    return [r.id for r in PATTERN_RULES if r.pattern is not None and r.pattern.search(text)]


def _try_b64(blob: str) -> Optional[str]:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
    return text if text and printable / len(text) > 0.9 else None


def scan_text(text: str, path: str = "<stdin>") -> List[Finding]:
    """Scan a string and return findings."""
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    findings: List[Finding] = []

    def add(rule_id: str, offset: int, message: str, severity: Optional[str] = None) -> None:
        idx = bisect.bisect_right(starts, offset) - 1
        line_start = starts[idx]
        line_end = text.find("\n", line_start)
        line = text[line_start: len(text) if line_end == -1 else line_end]
        if SUPPRESS.search(line):
            return
        col = offset - line_start
        window = line[max(0, col - 40):].strip()  # _short collapses + truncates
        rule = RULES_BY_ID[rule_id]
        findings.append(Finding(
            rule_id, rule.name, severity or rule.severity, message, path, idx + 1, col + 1, _short(window, 140)
        ))

    # 1. What the text says
    for rule in PATTERN_RULES:
        assert rule.pattern is not None
        for m in rule.pattern.finditer(text):
            add(rule.id, m.start(), f'{rule.description} Matched: "{_short(m.group(0))}"')

    # 2. Text hidden from human readers by markup
    for m in HTML_COMMENT.finditer(text):
        body = m.group(1)
        hits = pattern_hits(body)
        if hits or HIDDEN_KEYWORDS.search(body):
            add("GP108", m.start(),
                f'HTML comment (invisible when rendered) contains instruction-like text: "{_short(body)}"',
                "high" if hits else None)
    for m in INVISIBLE_STYLE.finditer(text):
        body = m.group(3)
        hits = pattern_hits(body)
        if hits or HIDDEN_KEYWORDS.search(body):
            add("GP108", m.start(),
                f'Element styled "{m.group(2)}" hides instruction-like text: "{_short(body)}"',
                "high" if hits else None)

    # 3. Text hidden by invisible Unicode
    for h in find_unicode(text):
        msg, sev = h.detail, None
        if h.decoded:
            msg += f' — hidden payload decodes to: "{_short(h.decoded)}"'
            hits = pattern_hits(h.decoded)
            if hits:
                sev = "critical"
                msg += f" (matches {', '.join(hits)})"
        add(UNICODE_RULE[h.kind], h.start, msg, sev)

    # 4. Text hidden by encoding
    for m in B64.finditer(text):
        decoded = _try_b64(m.group(0))
        if decoded:
            hits = pattern_hits(decoded)
            if hits:
                add("GP109", m.start(),
                    f'Base64 blob decodes to text matching {", ".join(hits)}: "{_short(decoded)}"')

    findings.sort(key=lambda f: (f.line, f.column, f.rule_id))
    return findings


def _excluded(path: Path, root: Path, patterns: List[str]) -> bool:
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        rel = path.as_posix()
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or any(fnmatch.fnmatch(part, pat) for part in path.parts):
            return True
    return False


def iter_files(paths: Iterable[str], excludes: List[str]) -> Iterable[Path]:
    for p in paths:
        root = Path(p)
        if root.is_file():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            d = Path(dirpath)
            dirnames[:] = sorted(x for x in dirnames if not _excluded(d / x, root, excludes))
            for name in sorted(filenames):
                f = d / name
                if not _excluded(f, root, excludes):
                    yield f


def scan_paths(paths: Iterable[str], excludes: Optional[List[str]] = None,
               max_size: int = 2_000_000) -> ScanResult:
    result = ScanResult()
    for f in iter_files(paths, DEFAULT_EXCLUDES + list(excludes or [])):
        try:
            if f.stat().st_size > max_size:
                result.files_skipped += 1
                continue
            data = f.read_bytes()
        except OSError:
            result.files_skipped += 1
            continue
        if b"\x00" in data[:8192]:  # binary
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        result.findings.extend(scan_text(data.decode("utf-8", errors="replace"), f.as_posix()))
    return result
