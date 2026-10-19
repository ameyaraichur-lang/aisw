"""Ticket rendering, the delivery client against a loopback fake, and delivery settings."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from aisw.core import egress
from aisw.core.config import Settings
from aisw.itsm import render as itsm
from aisw.itsm.delivery import DeliveryError, ItsmClient
from tests.itsm_fake import FakeItsm

DRAFT: dict[str, Any] = {
    "summary": "Enforce MFA on admin consoles",
    "description": "Recommendation r-1 (AC-IAM-01), run run-1.\nAction: enforce MFA",
    "labels": ["aisw", "draft", "P1"],
    "delivery": "NOT_SENT",
}
OID = "6f1c1d2e-0000-4000-8000-000000000001"


@pytest.fixture
def fake() -> Iterator[FakeItsm]:
    f = FakeItsm().start()
    yield f
    f.stop()


def client(fake: FakeItsm, target: itsm.Target, **kw: Any) -> ItsmClient:
    return ItsmClient(target=target, base_url=fake.url, username=fake.username, token=fake.token,
                      timeout=1.0, **kw)  # fmt: skip


def test_jira_payload_carries_the_correlation_label_and_plain_text_adf() -> None:
    p = itsm.render_jira(DRAFT, OID, project_key="SEC", issue_type="Task")["fields"]
    assert p["project"] == {"key": "SEC"} and p["issuetype"] == {"name": "Task"}
    assert f"aisw-{OID}" in p["labels"] and "aisw-tier-p1" in p["labels"]
    texts = [n["content"][0]["text"] for n in p["description"]["content"]]
    assert texts[0].startswith("Recommendation r-1") and any("Planning only" in t for t in texts)
    assert all(n["content"][0]["type"] == "text" for n in p["description"]["content"])
    assert "priority" not in p  # Jira priority schemes differ per site: never guessed


def test_servicenow_priority_comes_only_from_a_rubric_tier() -> None:
    p = itsm.render_servicenow(DRAFT, OID)
    assert p["correlation_id"] == f"aisw-{OID}" and (p["urgency"], p["impact"]) == ("2", "1")
    untiered = itsm.render_servicenow({**DRAFT, "labels": ["aisw", "draft"]}, OID)
    assert "urgency" not in untiered and "impact" not in untiered
    long = itsm.render_servicenow({**DRAFT, "summary": "x" * 500}, OID)
    assert len(long["short_description"]) == itsm.SN_SHORT_MAX


@pytest.mark.parametrize("target", itsm.TARGETS)
def test_a_retry_after_a_late_reply_finds_the_ticket_instead_of_duplicating(
    fake: FakeItsm, target: itsm.Target
) -> None:
    c = client(fake, target)
    rendered = itsm.render(target, DRAFT, OID, jira_project_key="SEC", jira_issue_type="Task")
    fake.slow_creates = 1
    with pytest.raises(DeliveryError) as exc:
        c.deliver(OID, rendered)
    assert exc.value.code == "ITSM_UNREACHABLE" and exc.value.retryable
    again = c.deliver(OID, rendered)
    assert again.created is False and again.external_ref in {"SEC-1", "INC0000001"}
    assert len(fake.jira) + len(fake.servicenow) == 1


def test_errors_are_classified_without_leaking_bodies(fake: FakeItsm) -> None:
    c = client(fake, "jira")
    for status, code, retry in ((503, "ITSM_ERROR_503", True), (429, "ITSM_ERROR_429", True),
                                (400, "ITSM_REJECTED_400", False)):  # fmt: skip
        fake.fail_with = [status]
        with pytest.raises(DeliveryError) as exc:
            c.find(OID)
        assert (exc.value.code, exc.value.retryable) == (code, retry)
    bad = ItsmClient(target="jira", base_url=fake.url, username="x", token="wrong", timeout=1.0)  # noqa: S106
    with pytest.raises(DeliveryError) as exc:
        bad.find(OID)
    assert exc.value.code == "ITSM_REFUSED_401" and not exc.value.retryable
    assert "wrong" not in str(exc.value)


def test_nothing_listens_means_retryable_unreachable() -> None:
    c = ItsmClient(target="servicenow", base_url="http://127.0.0.1:9", username="u", token="t",  # noqa: S106
                   timeout=0.5)  # fmt: skip
    with pytest.raises(DeliveryError) as exc:
        c.find(OID)
    assert exc.value.code == "ITSM_UNREACHABLE"


BASE: dict[str, Any] = {"env": "test", "enable_itsm_ticket_creation": True,
                        "enable_itsm_ticket_delivery": True, "itsm_target": "jira",
                        "itsm_base_url": "https://acme.atlassian.net", "itsm_username": "bot",
                        "itsm_token": "t0ken"}  # fmt: skip


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"enable_itsm_ticket_creation": False}, "requires enable_itsm_ticket_creation"),
        ({"itsm_token": " "}, "itsm_token"),
        ({"itsm_target": None}, "itsm_target"),
        ({"itsm_base_url": "http://itsm.example.com"}, "itsm_base_url must use https"),
        ({"itsm_base_url": "https://bot:pw@acme.atlassian.net"}, "must not carry credentials"),
        ({"itsm_base_url": "https://acme.atlassian.net/jira"}, "must be an origin"),
        ({"env": "prod", "itsm_base_url": "http://127.0.0.1:8080"}, "must use https"),
    ],
)
def test_delivery_settings_fail_closed(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Settings(**{**BASE, **change})


def test_delivery_is_off_by_default_and_adds_one_api_egress_destination() -> None:
    assert Settings(env="test").enable_itsm_ticket_delivery is False
    assert not [d for d in egress.destinations(Settings(env="test")) if d.purpose == "itsm"]
    dests = [d for d in egress.destinations(Settings(**BASE)) if d.purpose == "itsm"]
    assert [(d.host, d.ports, d.roles) for d in dests] == [("acme.atlassian.net", (443,), ("api",))]
