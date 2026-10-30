"""Detection and decoding of invisible / deceptive Unicode."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
}

BIDI = {
    0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
    0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
}


def is_tag(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def vs_value(cp: int) -> Optional[int]:
    """Map a variation selector to a byte value (0-255), else None."""
    if 0xFE00 <= cp <= 0xFE0F:
        return cp - 0xFE00
    if 0xE0100 <= cp <= 0xE01EF:
        return cp - 0xE0100 + 16
    return None


def is_invisible(cp: int) -> bool:
    return is_tag(cp) or cp in ZERO_WIDTH or cp in BIDI or vs_value(cp) is not None


def visible(s: str, collapse: int = 4) -> str:
    """Render invisible characters as <U+XXXX>; long runs become <N hidden chars>."""
    out, i, n = [], 0, len(s)
    while i < n:
        if not is_invisible(ord(s[i])):
            out.append(s[i])
            i += 1
            continue
        j = i
        while j < n and is_invisible(ord(s[j])):
            j += 1
        run = s[i:j]
        if len(run) > collapse:
            out.append(f"<{len(run)} hidden chars>")
        else:
            out.extend(f"<U+{ord(c):04X}>" for c in run)
        i = j
    return "".join(out)


@dataclass
class UnicodeHit:
    kind: str  # tag | variation-selector | zero-width | bidi
    start: int
    end: int
    detail: str
    decoded: Optional[str] = None


def _ascii(c: str) -> bool:
    return c != "" and ord(c) < 128


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isprintable() or c in "\n\t") / len(s)


def _decode_zw_binary(run: str) -> Optional[str]:
    """Try to decode zero-width steganography (two chars = 0/1 bits)."""
    chars = sorted(set(run))
    if len(chars) != 2 or len(run) < 16:
        return None
    best = None
    for zero, one in ((chars[0], chars[1]), (chars[1], chars[0])):
        bits = "".join("0" if c == zero else "1" for c in run)
        data = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
        text = data.decode("utf-8", errors="ignore")
        if _printable_ratio(text) > 0.9 and (best is None or len(text) > len(best)):
            best = text
    return best


def find_unicode(text: str) -> List[UnicodeHit]:
    hits: List[UnicodeHit] = []
    i, n = 0, len(text)
    while i < n:
        cp = ord(text[i])

        if is_tag(cp):
            j = i
            while j < n and is_tag(ord(text[j])):
                j += 1
            decoded = "".join(
                chr(ord(c) - 0xE0000) for c in text[i:j] if 0x20 <= ord(c) - 0xE0000 <= 0x7E
            )
            hits.append(UnicodeHit("tag", i, j, f"{j - i} invisible Unicode tag character(s)", decoded or None))
            i = j
            continue

        if vs_value(cp) is not None:
            j = i
            while j < n and vs_value(ord(text[j])) is not None:
                j += 1
            if j - i >= 3:  # legit emoji use a single selector
                data = bytes(vs_value(ord(c)) for c in text[i:j])  # type: ignore[misc]
                decoded = data.decode("utf-8", errors="replace")
                hits.append(UnicodeHit(
                    "variation-selector", i, j, f"{j - i} stacked variation selectors",
                    decoded if _printable_ratio(decoded) > 0.8 else None,
                ))
            i = j
            continue

        if cp in ZERO_WIDTH:
            if cp == 0xFEFF and i == 0:  # BOM
                i += 1
                continue
            j = i
            while j < n and ord(text[j]) in ZERO_WIDTH:
                j += 1
            run = text[i:j]
            prev = text[i - 1] if i > 0 else ""
            nxt = text[j] if j < n else ""
            # ZWJ / ZWNJ are legitimate in emoji sequences and many scripts
            # (Malayalam, Hindi, Persian, ...). Only flag them between ASCII.
            joiners_only = all(ord(c) in (0x200C, 0x200D) for c in run)
            if joiners_only and len(run) <= 2 and not (_ascii(prev) and _ascii(nxt)):
                i = j
                continue
            names = sorted({ZERO_WIDTH[ord(c)] for c in run})
            hits.append(UnicodeHit(
                "zero-width", i, j, f"{len(run)} zero-width character(s): {', '.join(names)}",
                _decode_zw_binary(run),
            ))
            i = j
            continue

        if cp in BIDI:
            # group every bidi control on this line into one finding
            line_end = text.find("\n", i)
            line_end = n if line_end == -1 else line_end
            found = [c for c in text[i:line_end] if ord(c) in BIDI]
            names = ", ".join(BIDI[ord(c)] for c in found)
            hits.append(UnicodeHit("bidi", i, line_end, f"{len(found)} bidirectional control character(s): {names}"))
            i = line_end
            continue

        i += 1
    return hits
