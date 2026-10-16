"""Agent registry (blueprint section 5): what each bounded agent does, and which adapters feed it.

Static, reviewable data. Every adapter in the runtime registry must map to exactly one agent
(asserted by a test), so a new adapter cannot silently appear outside the agent model.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentInfo:
    agent_id: int
    name: str
    purpose: str
    kind: str  # gate | adapter | deterministic
    adapter_ids: tuple[str, ...] = ()
    ai_capable: bool = False  # may ask the optional model for an explanation (never for a decision)
    outputs: tuple[str, ...] = ()
    ai_validated: bool = False  # outcomes reviewed by the agent validation pass (ADR-021)


AGENTS: tuple[AgentInfo, ...] = (
    AgentInfo(0, "Scope & Authorization Gate", "Validates, signs and enforces the scope manifest and execution permit before any tool call.", "gate", outputs=("decision", "permit"), ai_validated=True),
    AgentInfo(1, "Discovery & Reconciliation", "Reconciles inventory sources into one asset view; owner and criticality stay unknown unless supplied.", "adapter", ("cmdb_import", "netbox_import", "servicenow_import"), outputs=("assets", "coverage"), ai_validated=True),
    AgentInfo(2, "Host & OS Configuration", "Collects host configuration and host or container image vulnerability evidence from approved imports or read-only collectors.", "adapter", ("fixture", "greenbone_import", "openscap_import", "wazuh_import", "nessus_import", "tenable_import", "qualys_import", "trivy_import"), outputs=("evidence", "observations"), ai_validated=True),
    AgentInfo(3, "Cloud Posture", "Collects cloud, Kubernetes RBAC and identity posture from approved exports.", "adapter", ("prowler_import", "kubescape_import", "aws_iam_import", "directory_import"), outputs=("evidence", "observations"), ai_validated=True),
    AgentInfo(4, "Network, Perimeter & Web", "Collects exposure evidence: bounded port data, firewall rules, passive URL smoke checks, web baseline alerts.", "adapter", ("nmap_import", "url_smoke", "zap_import", "firewall_import"), ai_capable=True, outputs=("evidence", "observations"), ai_validated=True),
    AgentInfo(5, "Exposure, Vulnerability & Threat Correlation", "Scores each finding with the versioned risk rubric and builds evidence-backed scenarios. Never invents a tier or a link.", "deterministic", ai_capable=True, outputs=("risk_assessments", "scenarios"), ai_validated=True),
    AgentInfo(6, "Security Architecture & Modernization", "Maps findings to approved target patterns and drafts traceable recommendations. Never executes a change.", "deterministic", ai_capable=True, outputs=("recommendations",), ai_validated=True),
    AgentInfo(7, "Independent Assurance", "Re-validates every finding, risk, scenario, recommendation and narrative against evidence; only ACCEPT reaches the report.", "deterministic", outputs=("assurance_results",), ai_validated=True),
    AgentInfo(8, "Reporting & Ticket Drafts", "Assembles the report from accepted items only; drafts (never sends) tickets when explicitly enabled.", "deterministic", ai_capable=True, outputs=("report", "ticket_drafts"), ai_validated=True),
)  # fmt: skip


def agent_for_adapter(adapter_id: str) -> int | None:
    return next((a.agent_id for a in AGENTS if adapter_id in a.adapter_ids), None)
