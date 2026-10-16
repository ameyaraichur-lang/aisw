"""Deployment scan zones bind preflight and dispatch: a target resolving outside them is refused."""

from __future__ import annotations

import pytest

from aisw.authz.service import ScopeDenied
from aisw.gateway.gateway import GatewayDenied
from tests.support import Env

pytestmark = pytest.mark.security


def test_preflight_blocks_targets_outside_the_scan_zones(env: Env) -> None:
    env.dns["example.com"] = ["93.184.216.34"]
    env.gate.egress_zones = ("198.51.100.0/24",)
    with pytest.raises(ScopeDenied) as exc:
        env.approved()
    assert "BLOCKED_ADDRESS_OUTSIDE_EGRESS_ZONE" in exc.value.reason_codes


def test_dispatch_blocks_a_target_that_moved_outside_the_zones(env: Env) -> None:
    env.dns["example.com"] = ["93.184.216.34"]
    env.gate.egress_zones = env.gateway.egress_zones = ("93.184.216.0/24",)
    m = env.approved()
    auth = env.launch(m)
    env.dns["example.com"] = ["1.1.1.1"]  # mock DNS now answers outside the approved zone
    with pytest.raises(GatewayDenied) as exc:
        env.gateway.dispatch(env.request(auth, m))
    assert exc.value.reason_codes == ["BLOCKED_ADDRESS_OUTSIDE_EGRESS_ZONE"]
    assert env.total_dispatched == 0
    env.dns["example.com"] = ["93.184.216.34"]
    env.gateway.dispatch(env.request(auth, m))
    assert env.total_dispatched == 1
