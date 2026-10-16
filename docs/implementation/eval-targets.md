# Evaluation targets on the Maple Trust estate (2026-10-16)

Synthetic fixture estate only (`maple-trust`, answer key `maple-trust-1.0.0`). Numbers
are produced by `tools/eval_targets.py` from two end-to-end runs; they are not edited by hand.
Validator rows come from `docs/implementation/evaluation/labelled-1.0.0-gpt-5.4.json`.

- Runs: `086babc0-ea3c-4da0-9074-b413b2a46e53` then `b4d6cf28-1839-4b88-b8c3-52ed5010ad27` (scored: the second, compared with the first)
- Summary: 8 met, 0 not met, 3 measured without a threshold, 0 not measured

| Metric | Target | Result | Status |
|---|---|---|---|
| Asset reconciliation | ≥ 95% reconciled or explicitly unresolved | 62 of 62 (100.0%) | **MET** |
| Assessment status coverage | 100% of in-scope assets have a status | 62 of 62 (100.0%) | **MET** |
| Known-issue detection: recall | Measured when an answer key is provided | 15 of 18 (83.3%) | **MEASURED** |
| Known-issue detection: precision | Measured when an answer key is provided | 15 of 16 (93.8%) | **MEASURED** |
| Finding traceability | 100% | 16 of 16 (100.0%) | **MET** |
| Unsupported compliance claims | 0 | 0 | **MET** |
| Scope enforcement / unauthorised change attempts | 0 successful | 0 successful, 0 blocked | **MET** |
| Astra validator catch-rate (seeded bad outcomes) | Proposed ≥ 90% | 15 of 15 (100.0%) | **MET** |
| Astra false-dissent rate | Proposed ≤ 10% | 0.0 over 9 clean cases | **MET** |
| Reproducibility of the deterministic layer | 100% | Identical | **MET** |
| Astra cost/latency per run | Measured and reported | No model calls in this run | **MEASURED** |

## Known issues the system did not detect

These are real in the estate's ground truth but could not be seen: the reason is the collection gap,
which the report also shows as UNKNOWN, NOT_ASSESSED or an unreachable asset, never as a pass.

- `audit.logging_enabled` on `mt-app-09`: NOT_ASSESSED: the collector returned no value for this check
- `audit.logging_enabled` on `mt-dns-03`: UNKNOWN: the collector returned an empty value, so the check was undecided
- `ssh.permit_root_login` on `mt-legacy-02`: ASSET_UNREACHABLE

## False positives

- `password.min_length` on `mt-win-07` (`f-ee83152397b21d885f89`)

## What this does not measure

- Any real estate, scanner or tool version: the estate and its answer key are synthetic.
- Owner-supplied targets (environment E2) and their answer keys: none have been provided.
- Validator quality on real evidence: the labelled set is synthetic (ADR-025).
