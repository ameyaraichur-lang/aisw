"""The built images fail CI on fixable critical or high vulnerabilities, not on unfixed ones, and
an exception is honoured only while it is live and short."""

from __future__ import annotations

import importlib.util
import json
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
TODAY = date(2026, 10, 21)


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("image_scan", ROOT / "tools" / "image_scan.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


X = _load()


def vuln(vid: str, pkg: str, severity: str, fixed: str | None = None) -> dict[str, Any]:
    return {"VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": "1.0", "Severity": severity,
            "FixedVersion": fixed, "Status": "fixed" if fixed else "affected"}  # fmt: skip


def report(*vulns: dict[str, Any], name: str = "aisw-backend:ci", os_family: str | None = "alpine") -> dict[str, Any]:  # fmt: skip
    meta = {"OS": {"Family": os_family, "Name": "3.24.2"}} if os_family else {}
    return {"ArtifactName": name, "Metadata": meta,
            "Results": [{"Target": name, "Vulnerabilities": list(vulns) or None}]}  # fmt: skip


def exception(expires: str, **kw: str) -> dict[str, Any]:
    e = {"image": "aisw-backend", "vulnerability": "CVE-1", "package": "zlib",
         "owner": "Platform security lead", "reason": "Not reachable; upstream fix due", "expires": expires}  # fmt: skip
    return {"exceptions": [{**e, **kw}]}


def test_fixable_critical_or_high_fails_and_unfixed_is_reported_only() -> None:
    failures, text = X.check([report(vuln("CVE-1", "zlib", "HIGH", "1.1"), vuln("CVE-2", "ncurses", "CRITICAL"),
                                     vuln("CVE-3", "musl", "MEDIUM", "1.2"))], {}, TODAY)  # fmt: skip
    assert failures == ["aisw-backend: HIGH CVE-1 in zlib 1.0 is fixed in 1.1"]
    assert "- aisw-backend (alpine 3.24.2): 1 critical, 1 high, 1 medium, 0 low, 0 unknown" in text
    assert any(
        "unfixed critical or high, reported only (1): CVE-2 in ncurses 1.0" in t for t in text
    )
    assert X.check([report()], {}, TODAY) == ([], ["- aisw-backend (alpine 3.24.2): " + ", ".join(
        f"0 {s}" for s in ("critical", "high", "medium", "low", "unknown"))])  # fmt: skip


def test_an_image_whose_os_was_not_detected_fails() -> None:
    failures, _ = X.check([report(os_family=None)], {}, TODAY)
    assert failures == [
        "aisw-backend: Trivy did not detect the OS, so its packages were not scanned"
    ]
    assert X.check([], {}, TODAY)[0] == ["no Trivy reports given"]


def test_exceptions_apply_only_while_live_and_short() -> None:
    fixable = [report(vuln("CVE-1", "zlib", "HIGH", "1.1"))]
    failures, text = X.check(fixable, exception("2026-11-30"), TODAY)
    assert failures == [] and any(
        "excepted until 2026-11-30 (Platform security lead)" in t for t in text
    )
    assert X.check(fixable, exception("2026-10-20"), TODAY)[0] == [
        "aisw-backend: HIGH CVE-1 in zlib 1.0 is fixed in 1.1"
    ]
    too_long = X.check(fixable, exception("2027-03-01"), TODAY)[0]
    assert "more than 90 days ahead" in too_long[0] and len(too_long) == 2
    assert (
        X.check(fixable, exception("2026-11-30", owner=""), TODAY)[0][0]
        == "exception aisw-backend/CVE-1/zlib lacks owner"
    )
    other_image = X.check(fixable, exception("2026-11-30", image="aisw-web"), TODAY)
    assert len(other_image[0]) == 1 and any(
        "matched nothing and can be removed" in t for t in other_image[1]
    )


def test_cli_writes_the_summary_and_exits_non_zero_on_failure(tmp_path: Path) -> None:
    bad, ok, summary = tmp_path / "bad.json", tmp_path / "ok.json", tmp_path / "summary.md"
    bad.write_text(json.dumps(report(vuln("CVE-1", "zlib", "CRITICAL", "1.1"))))
    ok.write_text(json.dumps(report(name="aisw-web:ci")))
    none = tmp_path / "none.json"
    assert X.main([str(ok), "--exceptions", str(none), "--today", "2026-10-21"]) == 0
    assert X.main([str(bad), str(ok), "--exceptions", str(none), "--summary", str(summary)]) == 1
    assert "FAIL: aisw-backend: CRITICAL CVE-1" in summary.read_text()


def test_the_committed_exceptions_file_is_valid() -> None:
    data = json.loads((ROOT / "deploy" / "image-scan-exceptions.json").read_text())
    assert X.load_exceptions(data, date.today())[1] == []
