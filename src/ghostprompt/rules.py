"""Detection rules for GhostPrompt.

Pattern rules (GP1xx) look at what text *says*.
Unicode rules (GP2xx) look at what text *hides*.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    description: str
    pattern: Optional["re.Pattern[str]"] = None


def _rx(p: str) -> "re.Pattern[str]":
    return re.compile(p, re.IGNORECASE | re.MULTILINE)


PATTERN_RULES = [
    Rule(
        "GP101", "instruction-override", "high",
        "Text tries to override the model's prior instructions.",
        _rx(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,30}"
            r"\b(all|any|every|the|your|previous|prior|above|earlier|preceding|system)\b[^.\n]{0,30}"
            r"\b(instructions?|prompts?|rules|directions|guidelines)\b"),
    ),
    Rule(
        "GP102", "role-hijack", "high",
        "Attempts to reassign the model's identity or unlock a special 'mode'.",
        _rx(r"\b(you are now (an? )?(unrestricted|unfiltered|jailbroken|uncensored|dan|evil|free from|no longer bound)"
            r"|from now on,? you (are|will) (be |act as )?(an? )?(unrestricted|unfiltered|jailbroken|dan)"
            r"|act as an? (unrestricted|unfiltered|jailbroken)|(developer|god|dan|jailbreak) mode|new system prompt)\b"),
    ),
    Rule(
        "GP103", "fake-chat-markers", "high",
        "Contains chat-template delimiters used to forge system/assistant turns.",
        _rx(r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|assistant\|>|(?-i:\[/?INST\])|<<SYS>>"
            r"|</?system>|<\|endoftext\|>|^\s*#{1,3}\s*(system|assistant)\s*(prompt)?\s*:)"),
    ),
    Rule(
        "GP104", "concealment", "critical",
        "Asks the model to hide its actions from the user.",
        _rx(r"\b(do not|don't|never|without)\b[^.\n]{0,25}"
            r"\b(tell|telling|inform|informing|mention|mentioning|reveal|revealing|notify|notifying|alert|alerting)\b"
            r"[^.\n]{0,15}\buser\b|\bkeep (this|it) (a )?secret\b"),
    ),
    Rule(
        "GP105", "exfiltration", "critical",
        "Instructs sending conversation data or secrets to an external URL.",
        _rx(r"\b(send|post|upload|forward|exfiltrate|transmit|leak)\b[^\n]{0,40}"
            r"\b(conversation|chat|history|data|secrets?|credentials?|keys?|tokens?|passwords?|contents?|files?|messages?)\b"
            r"[^\n]{0,60}https?://"
            r"|!\[[^\]]*\]\(https?://[^)\s]*[?&][a-z_]*(data|secret|token|key|payload|content|conv|history)="),
    ),
    Rule(
        "GP106", "sensitive-file-access", "critical",
        "Tells the model to read or send credential files.",
        _rx(r"\b(read|cat|send|include|print|dump|upload|exfiltrate|output|paste)\b[^\n]{0,60}"
            r"(~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|~/\.netrc|~/\.npmrc|/etc/shadow|\.git-credentials)"),
    ),
    Rule(
        "GP107", "tool-coercion", "medium",
        "Forces the agent to call tools or run commands before answering.",
        _rx(r"\b(always|immediately)\b[^.\n]{0,20}\b(call|invoke|execute)\b[^.\n]{0,25}\b(tool|function)\b"
            r"|\b(before|prior to) (responding|answering|replying)\b[^.\n]{0,40}\b(call|run|execute|invoke|read)\b"),
    ),
    Rule(
        "GP110", "pipe-to-shell", "low",
        "Downloads and executes a remote script (curl | sh).",
        _rx(r"\b(curl|wget)\b[^\n|]{0,120}\|\s*(sudo\s+)?(ba|z)?sh\b"),
    ),
]

OTHER_RULES = [
    Rule("GP108", "hidden-markup", "medium",
         "Instruction-like text hidden in an HTML comment or invisible CSS (not shown when rendered)."),
    Rule("GP109", "encoded-payload", "critical",
         "A Base64 blob decodes to a prompt-injection payload."),
    Rule("GP201", "ascii-smuggling", "high",
         "Invisible Unicode tag characters (U+E0000-E007F) that LLMs can read but humans can't see."),
    Rule("GP202", "variation-selector-smuggling", "high",
         "A run of variation selectors used to hide bytes inside an emoji or character."),
    Rule("GP203", "zero-width-characters", "medium",
         "Zero-width characters in ASCII text, sometimes used to hide binary-encoded messages."),
    Rule("GP204", "bidi-trojan-source", "high",
         "Bidirectional control characters that make text display differently than it is read (CVE-2021-42574)."),
]

ALL_RULES = PATTERN_RULES + OTHER_RULES
RULES_BY_ID = {r.id: r for r in ALL_RULES}
