"""Score the Maple Trust fixture estate against the §7.2 targets and write the result (ADR-039).

Usage (from backend/):
  uv run python ../tools/eval_targets.py [--labelled ../docs/implementation/evaluation/<x>.json]

Runs the estate twice, end to end (approved scope, gateway, evidence, policy, coverage, report), on
a throwaway embedded PostgreSQL. Two runs, because reproducibility is one of the targets. Synthetic
data only; no network. The validator rows come from the newest labelled evaluation JSON (ADR-025).
Exit code: 0 when every target with a threshold is MET, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

import pgserver  # type: ignore[import-untyped]  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import URL, create_engine, text  # noqa: E402

from aisw.core.db import tenant_connection  # noqa: E402
from aisw.evaluation.answer_key import load  # noqa: E402
from aisw.evaluation.scorecard import run_scorecard  # noqa: E402

EVAL_DIR = ROOT / "docs/implementation/evaluation"


def newest_labelled() -> Path | None:
    found = sorted(EVAL_DIR.glob("labelled-*.json"), key=lambda p: p.stat().st_mtime)
    return found[-1] if found else None


def measure(labelled: dict[str, Any] | None) -> dict[str, Any]:
    from tests.slice import Slice

    work = Path(tempfile.mkdtemp(prefix="aisw-eval-"))
    server = pgserver.get_server(work / "pg", cleanup_mode="stop")
    host = parse_qs(urlparse(server.get_uri()).query)["host"][0]

    def url(user: str, pw: str | None, db: str) -> URL:
        return URL.create("postgresql+psycopg", username=user, password=pw, database=db,
                          query={"host": host})  # fmt: skip

    admin = create_engine(url("postgres", None, "postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text('CREATE DATABASE "aisw_eval"'))
    owner = create_engine(url("postgres", None, "aisw_eval"))
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "migrations"))
    with owner.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
    app_pw, worker_pw = secrets.token_hex(16), secrets.token_hex(16)
    with owner.begin() as c:
        c.execute(text(f"ALTER ROLE aisw_app LOGIN PASSWORD '{app_pw}'"))
        c.execute(text(f"ALTER ROLE aisw_worker LOGIN PASSWORD '{worker_pw}'"))
    app = create_engine(url("aisw_app", app_pw, "aisw_eval"), future=True)
    worker = create_engine(url("aisw_worker", worker_pw, "aisw_eval"), future=True)
    try:
        sl = Slice(app, worker, work / "evidence")
        key = load("maple-trust-1.0.0")
        runs = []
        for _ in range(2):
            _, _, run_id = sl.full_run(key.cmdb_expected_assets, fixture_set="maple-trust")
            sl.drain()
            runs.append(run_id)
            sl.clock.advance(minutes=1)
        with tenant_connection(app, "tenant-a") as conn:
            card = run_scorecard(conn, runs[-1], labelled=labelled)
        if card is None:
            raise SystemExit("the evaluation run produced no report")
        card["runs"] = runs
        return card
    finally:
        for eng in (app, worker, owner, admin):
            eng.dispose()
        server.cleanup()


def markdown(card: dict[str, Any], labelled: str | None) -> str:
    rows = "\n".join(f"| {m['label']} | {m['target']} | {m['display']} | **{m['status']}** |"
                     for m in card["metrics"])  # fmt: skip
    by = {m["metric"]: m for m in card["metrics"]}
    missed = "\n".join(f"- `{x['rule_id']}` on `{x['asset_id']}`: {x['reason']}"
                       for x in by["detection_recall"]["detail"].get("missed", [])) or "- None"  # fmt: skip
    fps = "\n".join(f"- `{x['rule_id']}` on `{x['asset_id']}` (`{x['finding_id']}`)"
                    for x in by["detection_precision"]["detail"].get("false_positive", []))  # fmt: skip
    s = card["summary"]
    return f"""# Evaluation targets on the Maple Trust estate ({card["generated_at"][:10]})

Synthetic fixture estate only (`maple-trust`, answer key `{card["answer_key"]["key_id"]}`). Numbers
are produced by `tools/eval_targets.py` from two end-to-end runs; they are not edited by hand.
Validator rows come from {f"`{labelled}`" if labelled else "no labelled evaluation (not measured)"}.

- Runs: `{card["runs"][0]}` then `{card["runs"][1]}` (scored: the second, compared with the first)
- Summary: {s["MET"]} met, {s["NOT_MET"]} not met, {s["MEASURED"]} measured without a threshold, {s["NOT_MEASURED"]} not measured

| Metric | Target | Result | Status |
|---|---|---|---|
{rows}

## Known issues the system did not detect

These are real in the estate's ground truth but could not be seen: the reason is the collection gap,
which the report also shows as UNKNOWN, NOT_ASSESSED or an unreachable asset, never as a pass.

{missed}

## False positives

{fps or "- None"}

## What this does not measure

- Any real estate, scanner or tool version: the estate and its answer key are synthetic.
- Owner-supplied targets (environment E2) and their answer keys: none have been provided.
- Validator quality on real evidence: the labelled set is synthetic (ADR-025).
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labelled", type=Path, default=newest_labelled())
    ap.add_argument("--json", type=Path, default=EVAL_DIR / "maple-trust-scorecard.json")
    ap.add_argument("--markdown", type=Path, default=ROOT / "docs/implementation/eval-targets.md")
    a = ap.parse_args()
    labelled = json.loads(a.labelled.read_text()) if a.labelled else None
    card = measure(labelled)
    card["generated_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(card, indent=2, sort_keys=True) + "\n")
    rel = str(a.labelled.resolve().relative_to(ROOT)) if a.labelled else None
    a.markdown.write_text(markdown(card, rel))
    print(f"{card['summary']} -> {a.json.relative_to(ROOT)}, {a.markdown.relative_to(ROOT)}")
    return 0 if card["summary"]["NOT_MET"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
