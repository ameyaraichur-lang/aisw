"""Contract every adapter must satisfy, and the registry's registration-time refusals."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from pydantic import BaseModel

from aisw.adapters.cloud_import import ProwlerImportAdapter
from aisw.adapters.cmdb_import import CmdbImportAdapter
from aisw.adapters.fixture import FixtureAdapter
from aisw.adapters.scanner_imports import (
    GreenboneImportAdapter,
    NmapImportAdapter,
    OpenScapImportAdapter,
    WazuhImportAdapter,
)
from aisw.adapters.url_smoke import UrlSmokeAdapter
from aisw.adapters.web_import import ZapImportAdapter
from aisw.contracts.base import StrictModel
from aisw.contracts.enums import ProfileClass
from aisw.evidence.imports import IMPORT_KINDS
from aisw.gateway.registry import (
    ALLOWED_TARGET_KINDS,
    AdapterCapability,
    AdapterRegistry,
    RegistryError,
)
from aisw.policy.engine import PackRegistry


def all_adapters() -> list[Any]:
    return [FixtureAdapter(), UrlSmokeAdapter(), CmdbImportAdapter(), ProwlerImportAdapter(), GreenboneImportAdapter(),
            NmapImportAdapter(), OpenScapImportAdapter(), WazuhImportAdapter(), ZapImportAdapter()]  # fmt: skip


@pytest.mark.parametrize("adapter", all_adapters(), ids=lambda a: a.capability.adapter_id)
def test_every_adapter_satisfies_the_contract(adapter: Any) -> None:
    cap: AdapterCapability = adapter.capability
    assert not cap.mutates_infrastructure and cap.enabled and cap.permission_ok
    assert cap.target_kinds <= ALLOWED_TARGET_KINDS and cap.domains and cap.profiles
    assert cap.param_model is not None and cap.param_model.model_config.get("extra") == "forbid"
    assert isinstance(adapter.estimate_requests({}), int) and adapter.estimate_requests({}) >= 1
    assert callable(adapter.execute) and callable(adapter.normalize)
    if cap.kind == "import":
        assert (
            cap.import_kinds <= IMPORT_KINDS
            and cap.formats
            and "import_id" in cap.param_model.model_fields
        )
        assert (
            adapter.estimate_requests({}) == 1
        )  # reading a stored file never issues outbound requests
    else:
        assert not cap.import_kinds


def test_only_the_expected_profile_is_active_and_it_needs_approval() -> None:
    active = {
        (a.capability.adapter_id, p)
        for a in all_adapters()
        for p, c in a.capability.profiles.items()
        if c is ProfileClass.ACTIVE
    }
    assert active == {("zap_import", "ZAP_ACTIVE_IMPORT")}


def test_the_default_registry_registers_every_adapter_once() -> None:
    reg = AdapterRegistry()
    for a in all_adapters():
        reg.register(a)
    assert reg.ids() == [
        "cmdb_import",
        "fixture",
        "greenbone_import",
        "nmap_import",
        "openscap_import",
        "prowler_import",
        "url_smoke",
        "wazuh_import",
        "zap_import",
    ]  # noqa: E501
    assert all(h.status == "HEALTHY" for h in reg.health())
    with pytest.raises(RegistryError, match="already"):
        reg.register(FixtureAdapter())


def test_every_import_profile_has_a_policy_pack_that_can_judge_its_observations() -> None:
    pack = PackRegistry.builtin().get("import-baseline:1.0.0")
    assert pack is not None
    rules = {r.rule_id for r in pack.rules}
    adapter_rules = {"cmdb.owner_known", "vuln.max_cvss", "scan.feed_age_days", "net.open_ports", "scap.failed_rules",
                     "sca.failed_checks", "cloud.high_critical_failures", "web.high_alerts"}  # fmt: skip
    assert adapter_rules <= rules and len(pack.rules) == 13 and len(pack.control_ids()) == 13


class _Strict(StrictModel):
    import_id: str = "x"


class _Loose(BaseModel):  # default config ignores unknown fields: not acceptable
    import_id: str = "x"


class _NoImportId(StrictModel):
    x: int = 1


class Stub:
    def __init__(self, cap: AdapterCapability) -> None:
        self.capability = cap

    def execute(self, job: Any) -> Any:
        return None


BASE = AdapterCapability(adapter_id="stub", version="1.0.0", domains=frozenset({"d"}), profiles={"P": ProfileClass.READ_ONLY},
                         target_kinds=frozenset({"host"}), param_model=_Strict)  # fmt: skip
IMPORT = replace(BASE, kind="import", import_kinds=frozenset({"nmap_xml"}), formats=("nmap xml",))


@pytest.mark.parametrize(
    ("cap", "needle"),
    [
        (replace(BASE, mutates_infrastructure=True), "mutate"),
        (replace(BASE, adapter_id="bad id!"), "slug"),
        (replace(BASE, adapter_id="../x"), "slug"),
        (replace(BASE, version="latest"), "semver"),
        (replace(BASE, profiles={}), "profile"),
        (replace(BASE, profiles={"bad profile": ProfileClass.READ_ONLY}), "profile"),
        (replace(BASE, target_kinds=frozenset()), "target kinds"),
        (replace(BASE, target_kinds=frozenset({"shell"})), "target kinds"),
        (replace(BASE, domains=frozenset()), "domains"),
        (replace(BASE, param_model=_Loose), "forbid"),
        (replace(BASE, import_kinds=frozenset({"nmap_xml"})), "only import adapters"),
        (replace(IMPORT, import_kinds=frozenset()), "import kinds"),
        (replace(IMPORT, formats=()), "import kinds"),
        (replace(IMPORT, param_model=_NoImportId), "import_id"),
        (replace(IMPORT, param_model=None), "import_id"),
    ],
)
def test_registration_refuses_unsafe_or_ambiguous_capabilities(
    cap: AdapterCapability, needle: str
) -> None:
    with pytest.raises(RegistryError, match=needle):
        AdapterRegistry().register(Stub(cap))


def test_valid_stubs_register_and_health_reports_degradation() -> None:
    reg = AdapterRegistry()
    reg.register(Stub(BASE))
    reg.register(Stub(replace(IMPORT, adapter_id="imp")))
    assert [h.status for h in reg.health()] == ["HEALTHY", "HEALTHY"]
    reg2 = AdapterRegistry()
    reg2.register(Stub(replace(BASE, permission_ok=False)))
    reg2.register(Stub(replace(BASE, adapter_id="off", enabled=False)))
    h = {x.adapter_id: x for x in reg2.health()}
    assert h["stub"].status == "DEGRADED" and h["stub"].reasons == ("PERMISSION_CHECK_FAILED",)
    assert h["off"].status == "DISABLED" and h["off"].reasons == ("DISABLED",)
