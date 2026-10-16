"""Evaluate the configured reviewer and narrator on the synthetic labelled set (ADR-025).

Usage (from backend/):
  uv run python ../tools/eval_labelled.py --env-file ../.env.astra \
      [--reviewer DEPLOYMENT] [--generator DEPLOYMENT] [--set labelled-1.0.0] \
      [--json ../docs/implementation/evaluation/<name>.json] [--markdown ../docs/implementation/evaluation.md]

Sends only the synthetic cases in aisw/llm/eval_data. Clients are built exactly as a run builds them
(failover, record/replay and the reviewer's separate deployment apply). Prints no secrets.
Exit code: 0 USABLE, 1 NOT_USABLE, 3 INCONCLUSIVE, 2 misconfigured.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aisw.core.config import Settings
from aisw.llm.client import DisabledModelClient
from aisw.llm.evaluation import DEFAULT_SET, evaluate, load_labelled_set, render_markdown
from aisw.llm.factory import build_model_client, build_validation_client


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-file", default=str(Path(__file__).resolve().parents[1] / ".env.astra"))
    ap.add_argument("--set", default=DEFAULT_SET)
    ap.add_argument("--reviewer", help="override AISW_ASTRA_VALIDATION_DEPLOYMENT")
    ap.add_argument("--generator", help="override AISW_MODEL_ID for narration")
    ap.add_argument("--no-narration", action="store_true")
    ap.add_argument(
        "--timeout", type=float, help="per-call timeout (default AISW_MODEL_TIMEOUT_SECONDS)"
    )
    ap.add_argument("--json", type=Path)
    ap.add_argument("--markdown", type=Path)
    args = ap.parse_args()
    over = {"model_id": args.generator} if args.generator else {}
    if args.reviewer:
        over["astra_validation_deployment"] = args.reviewer
    settings = Settings(_env_file=args.env_file, **over)  # type: ignore[call-arg]
    reviewer = build_validation_client(settings)
    if isinstance(reviewer, DisabledModelClient):
        print("AI or the validation pass is not enabled by this env file", file=sys.stderr)  # noqa: T201
        return 2
    generator = None if args.no_narration else build_model_client(settings)
    rep = evaluate(load_labelled_set(version=args.set), generator, reviewer,
                   timeout=args.timeout or float(settings.model_timeout_seconds))  # fmt: skip
    md = render_markdown(rep)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rep.model_dump_json(indent=2) + "\n")
    if args.markdown:
        args.markdown.write_text(md)
    print(md)  # noqa: T201
    return {"USABLE": 0, "NOT_USABLE": 1, "INCONCLUSIVE": 3}[rep.decision]


if __name__ == "__main__":
    raise SystemExit(main())
