# ADR-039: Maple Trust fixture estate, answer key, scorecard and Evaluation Lab

**Status:** Accepted. Implemented on synthetic data only.

## Context
The implementation plan (§7.2) sets targets for asset reconciliation, status coverage, known-issue recall and precision, finding traceability, unsupported compliance claims, scope enforcement, validator catch-rate and false dissent, reproducibility, and model cost and latency. The existing fixtures had only four hosts and no ground truth, so recall and precision could not be measured. Nothing produced the scorecard, and there was no Evaluation Lab page.

## Decision
- **Estate.** The fixture set `maple-trust` replays a synthetic 60-host hybrid estate:
  - web, application, database, Windows, jump, Kubernetes, mail, backup, DNS and log servers;
  - two PAN-OS firewalls and an AIX host that the baseline cannot collect from (UNSUPPORTED);
  - two unreachable legacy hosts;
  - two shadow hosts that are not in the CMDB, and two retired CMDB entries that are no longer present.

  The CMDB list has 60 entries. The fixture set is a closed enum value, as before.
- **Ground truth, not a mirror of the data.** The answer key `aisw/evaluation/answer_keys/maple-trust-1.0.0.json` states what is really true of the estate, including what the collector cannot see:
  - a root-login issue on an unreachable host;
  - an audit-logging issue where the tool returned no value;
  - an audit-logging issue where the check was not collected at all;
  - one Windows host where the tool misread a stale policy export (a false positive).

  Recall and precision therefore measure the whole system, collection gaps included. Each miss is listed with the run's own reason (`ASSET_UNREACHABLE`, `UNKNOWN`, `NOT_ASSESSED`), never hidden. Keys are packaged and loaded by a closed id. A key matches a run only when its fixture set and policy version both match.
- **Scorecard computed on read.** `aisw/evaluation/scorecard.py` collects one run's facts from the database and scores them with a pure function, so the result cannot drift from the evidence. No metric defaults to a pass: when a metric cannot be measured, it says NOT_MEASURED and why.
  - **Reconciliation:** matched assets plus absent or unexpected assets that the coverage ledger explicitly flags, over expected ∪ discovered. The answer-key agreement is shown beside it.
  - **Status coverage:** every in-scope asset has SCANNED, UNREACHABLE, UNSUPPORTED or a flagged ABSENT.
  - **Recall and precision:** finding ids are deterministic per pack, rule and asset, so key entries match exactly. A known issue under an applied exception counts as detected.
  - **Traceability:** every evidence ref of a finding is stored for the run and backs a recorded observation.
  - **Compliance claims:** the shared `COMPLIANCE` pattern is run over the report text, except the fixed, reviewed disclaimer (which says what the report does *not* prove). Every control-gap row saying NO_GAP_OBSERVED must also be backed by passing or not-applicable pack controls.
  - **Scope:** every executed task's adapter, profile (read-only), target and exclusions are checked against the run's approved manifest. Gateway refusals are counted as blocked.
  - **Reproducibility:** a digest of the deterministic layer (asset statuses, observations, control outcomes, finding ids and coverage counts) is compared with the most recent earlier run whose inputs are identical.
  - **Cost and latency:** taken from the model-call ledger.
- **Validator rows offline.** The catch-rate and false-dissent rate are not properties of a run. The API reports them as NOT_MEASURED. `tools/eval_targets.py` adds them from the newest labelled evaluation (ADR-025).
- **API and page.** The API, all requiring `finding:read` and tenant-scoped by RLS:
  - `GET /api/v1/evaluation/answer-keys` (metadata and the CMDB list);
  - `GET /api/v1/evaluation/runs/{id}/scorecard`;
  - `GET /api/v1/evaluation/runs` (trend of up to 20 reported runs).

  The Evaluation Lab page (`/evaluation`) shows the keys, explains how to score a run, offers the CMDB list to copy, and lists recent runs with their key metrics. The selected run's full scorecard shows its misses and false positives.
- **Recorded measurement.** `tools/eval_targets.py` runs the estate twice, end to end, on a throwaway embedded PostgreSQL. It writes `docs/implementation/eval-targets.md` and `docs/implementation/evaluation/maple-trust-scorecard.json`, and exits non-zero if any target with a threshold is not met.

## Consequences
- The numbers describe a synthetic estate built for this purpose. They show that the measurement works and that collection gaps are reported honestly. They say nothing about a real estate, a real tool version or the validator's quality on real evidence.
- Owner-supplied targets (environment E2) can be scored as soon as an answer key is supplied for them. A key is a packaged JSON file, reviewed like any other change.
- Scorecards are recomputed on every read. That is cheap for one run; the trend endpoint is capped at 20 runs.
