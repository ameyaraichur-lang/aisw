"""A stored report body as a flat list of blocks, which the PDF and DOCX writers render.

Built only from the stored body (plus the export stamp), so an export says exactly what the hashed
report says. Every string is treated as untrusted text; the writers escape it for their format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from aisw.reporting.gaps import GAP_LABEL, GAP_SHORT, architecture_delta

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass(frozen=True)
class Heading:
    level: int
    text: str


@dataclass(frozen=True)
class Para:
    text: str
    style: Literal["normal", "note", "alert", "small"] = "normal"


@dataclass(frozen=True)
class Bullets:
    items: list[str]


@dataclass(frozen=True)
class Table:
    headers: list[str]
    rows: list[list[str]]
    weights: list[int] = field(default_factory=list)  # relative column widths


Block = Heading | Para | Bullets | Table


def _risk(risk: dict[str, Any] | None) -> str:
    if not risk:
        return "-"
    if risk.get("tier"):
        return f"{risk['tier']} (rubric {risk['rubric_version']})"
    return f"Not rated (severity-only indication {risk['provisional_tier']})"


def _gap_blocks(body: dict[str, Any]) -> list[Block]:
    gaps = body.get("control_gaps")
    out: list[Block] = [Heading(2, "Control-gap matrix")]
    if not gaps:
        return [*out, Para("This report was generated before the control-gap matrix was recorded.",
                           "note")]  # fmt: skip
    out.append(Para(f"{gaps['notice']} Mapping catalog {gaps['catalog_version']}. PROPOSED marks "
                    "a mapping still awaiting policy-owner review.", "note"))  # fmt: skip
    for fw in gaps["frameworks"]:
        s = fw["summary"]
        out.append(Heading(3, f"{fw['name']} ({fw['version']})"))
        out.append(Para(", ".join(f"{GAP_SHORT[k]}: {n}" for k, n in s.items() if n), "small"))
        out.append(Table(
            ["Control", "Title", "State", "Pack checks", "Mapping"],
            [[r["control_id"], r["title"], GAP_LABEL[r["state"]],
              ", ".join(f"{p['control_id']} {p['outcome']}" for p in r["pack_controls"]),
              r["mapping"]] for r in fw["rows"]],
            [12, 30, 24, 22, 11],
        ))  # fmt: skip
    return out


def _delta_blocks(body: dict[str, Any]) -> list[Block]:
    rows = architecture_delta(body)
    if not rows:
        return []
    return [
        Heading(2, "Architecture delta (draft, for planning only)"),
        Para("Each row places the current state, as recorded in accepted findings, beside the "
             "approved target pattern. Effort is unknown until the owner estimates it.", "note"),
        Table(["Pattern", "Current state", "Target", "Assets", "Risk tier"],
              [[r["pattern"] or "-", "; ".join(r["current"]), r["target"] or "-",
                ", ".join(r["assets"]) or "-", r["tier"] or "not rated"] for r in rows],
              [16, 32, 28, 14, 10]),
    ]  # fmt: skip


def report_blocks(body: dict[str, Any], stamp: list[str]) -> list[Block]:
    out: list[Block] = [Heading(1, body["title"])]
    out += [Para(s, "alert" if s.startswith("DRAFT") else "note") for s in stamp]
    if body.get("notice"):
        out.append(Para(body["notice"], "note"))
    if body.get("banner"):
        out.append(Para(body["banner"], "alert"))
    if rev := body.get("revision"):
        out.append(Para(f"Revision {rev['number']}; supersedes report {rev['supersedes'] or '-'} "
                        "after a human review of AI validator dissent.", "note"))  # fmt: skip
    out.append(Para(body["disclaimer"]))
    out.append(Para(
        f"Run {body['run_id']} | scope hash {body['scope_manifest_hash']} | policy "
        f"{', '.join(body['policy_versions'])} | generated {body['generated_at']}", "small"))  # fmt: skip
    if ex := body.get("executive_summary"):
        out += [Heading(2, "Executive summary (AI-written)"), Para(ex["summary"]),
                Para(f"Written by model {ex.get('model_id') or 'unknown'}; every claim was checked "
                     "against the accepted findings. The findings table is authoritative.", "note")]  # fmt: skip
    fc = body["finding_counts"]
    counts = ", ".join(f"{k}: {fc[k]}" for k in ("total", *SEVERITY_ORDER) if k in fc)
    out.append(Heading(2, f"Findings ({counts})"))
    out.append(Table(
        ["Severity", "Risk tier", "Title", "Assets", "Evidence"],
        [[f["severity"], _risk(f.get("risk")), f["title"], ", ".join(f["affected_assets"]),
          ", ".join(f["evidence_refs"])] for f in body["findings"]],
        [9, 16, 35, 18, 22],
    ) if body["findings"] else Para("No accepted findings.", "note"))  # fmt: skip
    out.append(Heading(2, "Coverage"))
    out.append(Table(
        ["Segment", "Expected", "Reconciled", "Unknown", "Unsupported", "Reasons"],
        [[c["segment"], str(c["expected_count"]), str(c["reconciled_count"]),
          str(c["unknown_count"]), str(c["unsupported_count"]), ", ".join(c["reasons"]) or "-"]
         for c in body["coverage"]],
        [20, 10, 11, 10, 12, 37],
    ) if body["coverage"] else Para("No coverage information was produced.", "alert"))  # fmt: skip
    out += _gap_blocks(body)
    if body.get("exceptions"):
        out += [Heading(2, "Exceptions"), Table(
            ["Exception", "Effect", "Check", "Asset", "Expires", "Approved by", "Reason"],
            [[x["exception_id"], x["effect"], x["title"], x["asset_id"], x["expires_at"],
              x["approved_by"], x["reason"]] for x in body["exceptions"]],
            [12, 9, 20, 13, 14, 11, 21])]  # fmt: skip
    questions = [f for f in body["findings"] if f.get("verification_questions")]
    if questions:
        out.append(Heading(2, "Questions for asset owners (AI-written)"))
        for f in questions:
            out += [Heading(3, f["title"]), Bullets(list(f["verification_questions"]["questions"]))]
    for s in body.get("scenarios", []):
        if s is body["scenarios"][0]:
            out.append(Heading(2, "Correlated scenarios"))
        out += [Heading(3, s["title"]),
                Para(f"Asset {s['asset_id']} | risk tier {s.get('tier') or 'not rated'} | findings "
                     f"{', '.join(s['finding_ids'])}", "small"),
                Para(f"Assumptions: {'; '.join(s['assumptions']) or 'none'}"),
                Para(f"Validation steps: {'; '.join(s['validation_steps'])}")]  # fmt: skip
    out += _delta_blocks(body)
    for r in body.get("recommendations", []):
        if r is body["recommendations"][0]:
            out.append(Heading(2, "Recommendations (draft, for planning only)"))
        out += [Heading(3, r.get("title") or r["action"]),
                Para(f"Pattern {r.get('catalog_ref') or '-'} | risk tier {r.get('risk_tier') or 'not rated'} "
                     f"| findings {', '.join(r['finding_refs'])} | effort: unknown", "small"),
                Para(f"Target: {r.get('target_pattern') or '-'}"), Para(f"Action: {r['action']}"),
                Para(f"Rollback: {r.get('rollback') or '-'}"),
                Para(f"Acceptance test: {r.get('acceptance_test') or '-'}"),
                Bullets([f"Owner question: {q}" for q in r.get("owner_questions", [])] or
                        ["Owner questions: none"])]  # fmt: skip
    out += [Heading(2, "Limitations"), Bullets(list(body["limitations"]) or ["None recorded"])]
    out += [Heading(2, "Evidence manifest"), Table(
        ["Evidence", "SHA-256"], [[e["ref"], e["hash"]] for e in body["evidence_manifest"]],
        [45, 55])] if body["evidence_manifest"] else []  # fmt: skip
    return out
