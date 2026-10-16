"""Deterministic grounding checks for model output (the model is never the judge of itself).

Every identifier-like entity in the output (CVE, control, IP, URL, port, risk tier) must already
exist in the facts that were sent. Unknown references, prohibited content and hidden characters are
defects; any defect rejects the whole narrative.
"""

from __future__ import annotations

import re
import unicodedata

from aisw.agents.safety import prohibited_content
from aisw.llm.schema import NarrativeOutput, NarrativeSubject

_CVE = re.compile(
    r"\bCVE[-\u2010-\u2015_ ]\d{4}[-\u2010-\u2015_ ]\d+\b", re.I
)  # lenient on purpose
_CONTROL = [
    re.compile(r"\b[A-Z]{2,4}-\d{1,3}(?:\(\d+\))?(?![\d-])"),  # NIST style AC-2, SC-7(1)
    re.compile(r"\bA\.\d{1,2}(?:\.\d{1,2})+\b"),  # ISO 27001 Annex A
    re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),  # ATT&CK technique
    re.compile(
        r"\b(?:CIS|NIST|ISO|PCI|SOC|STIG|HIPAA)\b[\s#:-]*(?:Control|Benchmark|Requirement|Req)?"
        r"[\s#:-]*\d+(?:\.\d+)*",
        re.I,
    ),
]
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_PORT = [
    re.compile(r"\bports?\s+(\d{1,5})\b", re.I),
    re.compile(r"\b(?:tcp|udp)[/ ](\d{1,5})\b", re.I),
]
_TIER = re.compile(r"\bP[0-3]\b")
_CATALOG_IDS = re.compile(r"\bAC-[A-Z]+-\d+\b")  # our own catalog ids are not "controls" to ground


def _norm(s: str) -> str:
    return re.sub(r"[\s#:\-]+", "", s.upper())


def extract(text: str) -> dict[str, set[str]]:
    scrubbed = _CATALOG_IDS.sub(" ", text)
    controls: set[str] = set()
    for rx in _CONTROL:
        controls |= {_norm(m.group(0)) for m in rx.finditer(scrubbed)}
    ports: set[str] = set()
    for rx in _PORT:
        ports |= {m.group(1) for m in rx.finditer(text)}
    return {
        "cve": {re.sub(r"[^0-9A-Z]", "-", m.group(0).upper()) for m in _CVE.finditer(text)},
        "control": controls,
        "ip": set(_IP.findall(text)),
        "url": {m.group(0).rstrip(".,;:") for m in _URL.finditer(text)},
        "port": ports,
    }


def _corpus(subject: NarrativeSubject) -> str:
    parts: list[str] = [subject.title, *subject.context]
    for f in subject.facts:
        parts += [f.title, f.category, *f.control_ids, *f.evidence_refs]
    return "\n".join(parts)


def output_text(out: NarrativeOutput) -> str:
    return "\n".join([out.summary, *[c.text for c in out.claims], *out.open_questions])


def validate_narrative(out: NarrativeOutput, subject: NarrativeSubject) -> list[str]:
    defects: set[str] = set()
    text = output_text(out)

    if any(
        unicodedata.category(ch) == "Cf" or (unicodedata.category(ch) == "Cc" and ch != "\n")
        for ch in text
    ):
        defects.add("HIDDEN_OR_CONTROL_CHARACTERS")

    known_findings = {f.finding_id for f in subject.facts}
    known_assets = {a for f in subject.facts for a in f.asset_ids}
    for c in out.claims:
        for fid in c.finding_ids:
            if fid not in known_findings:
                defects.add(f"UNKNOWN_FINDING_REF:{fid}")
        for aid in c.asset_ids:
            if aid not in known_assets:
                defects.add(f"UNKNOWN_ASSET_REF:{aid}")

    allowed = extract(_corpus(subject))
    allowed["control"] |= {_norm(c) for f in subject.facts for c in f.control_ids}
    found = extract(text)
    for kind, values in found.items():
        for v in sorted(values - allowed[kind]):
            defects.add(f"UNGROUNDED_{kind.upper()}:{v}")

    for t in sorted(set(_TIER.findall(text))):
        if subject.tier is None:
            defects.add(f"FABRICATED_TIER:{t}")
        elif t != subject.tier:
            defects.add(f"TIER_MISMATCH:{t}")

    defects.update(prohibited_content(text))
    return sorted(defects)
