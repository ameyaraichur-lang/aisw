"""Deterministic text safety checks shared by recommendations and model output.

These are blunt on purpose: anything that reads like an instruction to run something, a compliance
attestation, or an unsourced lifecycle claim is flagged, because none of those may be produced by a
read-only assessment without evidence.
"""

from __future__ import annotations

import re

EXECUTABLE = re.compile(
    r"(`|\$\(|\bsudo\b|\brm\s+-|\bchmod\b|\bchown\b|\bcurl\b[^\n]*\|\s*(ba)?sh|\bwget\b|\biptables\b|\bkubectl\s+(delete|apply)\b|"
    r"\bterraform\s+(apply|destroy)\b|\baws\s+\w+\s+(delete|put|create|update)|\bssh\s+\S+@|\bdd\s+if=|\bmkfs\b|\bnc\s+-|\beval\s*\(|;\s*(rm|curl|wget|sh|bash)\b|&&\s*(rm|curl|wget|sh|bash)\b)",
    re.I,
)
COMPLIANCE = re.compile(
    r"\b(is|are|remains?)\s+(fully\s+)?(compliant|certified|secure|safe)\b|\bpass(es|ed)?\s+(the\s+)?audit\b|\bno\s+(remaining\s+)?(risk|vulnerabilit(y|ies))\b|\bfully\s+(secure|protected)\b|\bcertif(y|ies|ied)\b",
    re.I,
)
LIFECYCLE = re.compile(
    r"\bend[\s-]of[\s-](life|support|sale)\b|\bEOL\b|\bEOS\b|\bout of support\b|\bunsupported\b",
    re.I,
)
URL = re.compile(r"https?://", re.I)


def prohibited_content(text: str) -> list[str]:
    out: list[str] = []
    if EXECUTABLE.search(text):
        out.append("PROHIBITED_EXECUTABLE_CONTENT")
    if COMPLIANCE.search(text):
        out.append("UNSUPPORTED_COMPLIANCE_CLAIM")
    if LIFECYCLE.search(text):
        out.append("UNSOURCED_LIFECYCLE_CLAIM")
    return out
