"""Jira and ServiceNow payloads for a ticket draft. Pure functions: rendering never sends anything.

Every rendered ticket carries the draft's correlation key, so delivery can find a ticket it created
before (after a timeout, say) instead of creating a second one. A priority is set only from a rubric
tier; an untiered draft gets none rather than a guessed one.
"""

from __future__ import annotations

from typing import Any, Literal

Target = Literal["jira", "servicenow"]
TARGETS: tuple[Target, ...] = ("jira", "servicenow")
# ServiceNow urgency and impact (1 high .. 3 low) from the rubric tier. No tier, no priority.
SN_PRIORITY = {"P0": ("1", "1"), "P1": ("2", "1"), "P2": ("2", "2"), "P3": ("3", "3")}
JIRA_SUMMARY_MAX = 255
SN_SHORT_MAX = 160
FOOTER = (
    "Drafted by AISW from assurance-accepted findings. Planning only: nothing was changed by AISW. "
    "Effort is unknown until the owner estimates it."
)


def correlation_key(outbox_id: str) -> str:
    return f"aisw-{outbox_id}"


def _tier(payload: dict[str, Any]) -> str | None:
    return next((x for x in payload.get("labels", []) if x in SN_PRIORITY), None)


def _adf(text: str) -> dict[str, Any]:
    """Atlassian Document Format: one paragraph per line, plain text only (no markup injection)."""
    paras = [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
        for line in text.splitlines()
        if line.strip()
    ]
    return {"type": "doc", "version": 1, "content": paras}


def render_jira(
    payload: dict[str, Any], outbox_id: str, *, project_key: str, issue_type: str
) -> dict[str, Any]:
    key = correlation_key(outbox_id)
    tier = _tier(payload)
    labels = ["aisw", "aisw-draft", key, *([f"aisw-tier-{tier.lower()}"] if tier else [])]
    return {
        "fields": {
            "project": {"key": project_key},
            "issuetype": {"name": issue_type},
            "summary": str(payload["summary"])[:JIRA_SUMMARY_MAX],
            "description": _adf(f"{payload['description']}\n{FOOTER}\nCorrelation: {key}"),
            "labels": labels,
        }
    }


def render_servicenow(payload: dict[str, Any], outbox_id: str) -> dict[str, Any]:
    key = correlation_key(outbox_id)
    out: dict[str, Any] = {
        "short_description": str(payload["summary"])[:SN_SHORT_MAX],
        "description": f"{payload['description']}\n{FOOTER}",
        "correlation_id": key,
        "correlation_display": "AISW",
        "category": "security",
    }
    if (tier := _tier(payload)) is not None:
        out["urgency"], out["impact"] = SN_PRIORITY[tier]
    return out


def render(
    target: Target, payload: dict[str, Any], outbox_id: str, *, jira_project_key: str | None,
    jira_issue_type: str,
) -> dict[str, Any]:  # fmt: skip
    if target == "jira":
        return render_jira(
            payload, outbox_id, project_key=jira_project_key or "AISW", issue_type=jira_issue_type
        )
    return render_servicenow(payload, outbox_id)
