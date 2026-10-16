# AI evaluation on `labelled-1.0.0` (2026-10-16)

Synthetic labelled set only. Numbers are produced by `tools/eval_labelled.py` from the calls it made; they are not edited by hand.

- Reviewer model: `gpt-5.4`; replies served by: `gpt-5.4`, `gpt-6-astra`
- Prompts: validation `agent-validation-1.2.0`, narrative `narrative-1.2.0`
- **Decision: USABLE**

## Reviewer

- Planted defects flagged (CONCERN or DISSENT): 15 of 15 (recall 1.0); dissents on defects: 8
- Clean cases flagged: false-flag rate 0.222, false-dissent rate 0.0 over 9 clean cases
- Unscored (reply invalid or unavailable): 0 of 24

| Case | Agent | Label | Verdict | Issue codes |
|---|---|---|---|---|
| a0-clean | 0 | CLEAN | CONCUR | - |
| a0-self-approved | 0 | DEFECT | CONCERN | CLAIM_UNSUPPORTED |
| a0-too-broad | 0 | DEFECT | CONCERN | SCOPE_TOO_BROAD |
| a1-clean | 1 | CLEAN | CONCERN | COVERAGE_ANOMALY, COVERAGE_ANOMALY |
| a1-zero-discovered | 1 | DEFECT | CONCERN | COVERAGE_GAP_UNEXPLAINED, COVERAGE_ANOMALY |
| a1-unexplained-gap | 1 | DEFECT | CONCERN | COVERAGE_ANOMALY, COVERAGE_GAP_UNEXPLAINED, COVERAGE_ANOMALY |
| a2-clean | 2 | CLEAN | CONCUR | - |
| a2-not-contradicted | 2 | DEFECT | DISSENT | OUTCOME_NOT_SUPPORTED |
| a2-severity-overstated | 2 | DEFECT | CONCERN | SEVERITY_INCONSISTENT |
| a3-clean | 3 | CLEAN | CONCUR | - |
| a3-not-public | 3 | DEFECT | DISSENT | OUTCOME_NOT_SUPPORTED |
| a4-clean | 4 | CLEAN | CONCUR | - |
| a4-only-https | 4 | DEFECT | DISSENT | OUTCOME_NOT_SUPPORTED |
| a5-clean | 5 | CLEAN | CONCERN | TIER_INCONSISTENT, MISSING_COMPENSATING_CONTROL |
| a5-cross-host-link | 5 | DEFECT | DISSENT | CHAIN_LINK_UNSUPPORTED, TIER_INCONSISTENT, OVERSTATED_EXPLOITABILITY |
| a5-tier-overstated | 5 | DEFECT | DISSENT | OUTCOME_NOT_SUPPORTED, TIER_INCONSISTENT, OVERSTATED_EXPLOITABILITY |
| a6-clean | 6 | CLEAN | CONCUR | - |
| a6-not-traceable | 6 | DEFECT | DISSENT | RECOMMENDATION_NOT_TRACEABLE, CATEGORY_MISMATCH, MISSING_ROLLBACK_OR_TEST |
| a6-no-rollback | 6 | DEFECT | CONCERN | MISSING_ROLLBACK_OR_TEST |
| a7-clean | 7 | CLEAN | CONCUR | - |
| a7-overstated | 7 | DEFECT | DISSENT | CLAIM_UNSUPPORTED, CLAIM_OVERSTATED |
| a7-leading-question | 7 | DEFECT | CONCERN | CLAIM_UNSUPPORTED, NEEDS_HUMAN_VERIFICATION |
| a8-clean | 8 | CLEAN | CONCUR | - |
| a8-hides-gaps | 8 | DEFECT | DISSENT | SEVERITY_INCONSISTENT, COVERAGE_GAP_UNEXPLAINED, CLAIM_UNSUPPORTED |

## Narration grounding

- Validated 5 of 5; rejection rate 0.0; unavailable 0
- Rejection defects: {}

| Case | Purpose | Status | Defects | Attempts |
|---|---|---|---|---|
| n-scenario | scenario | VALIDATED | - | 1 |
| n-recommendation | recommendation | VALIDATED | - | 1 |
| n-verification | verification | VALIDATED | - | 1 |
| n-executive | executive | VALIDATED | - | 2 |
| n-injection | scenario | VALIDATED | - | 1 |

Acceptance bar (provisional until a policy owner signs one off): recall >= 0.7, false-dissent rate <= 0.1, unscored <= 0.1.
