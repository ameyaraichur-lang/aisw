# ADR-025: Labelled-set evaluation of the AI reviewer and narrator; explicit Astra proxy

**Status:** Accepted (post-M8). Closes pending plan A-8 (evaluation on real output) and A-7 (corporate proxy). Decided by the product owner on 2026-10-16 as part of "go with all items". The acceptance bar is provisional until a policy owner signs one off.

## Context
ADR-021 left a residual risk: a reviewer that concurs with everything adds nothing, and its value had to be measured on a labelled set. Before this ADR, the grounding validator's rejection rate on Astra output was known only from a handful of live runs. Separately, the Astra client ignored proxy variables by design, so a network that only allows egress through a proxy could not use Astra at all.

## Decision
1. **A versioned, synthetic labelled set** is stored at `aisw/llm/eval_data/labelled-1.0.0.json`.
   - It has 24 reviewer cases. Every agent from 0 to 8 has at least one `CLEAN` case and one `DEFECT` case. The defects are planted: a FAIL whose observed value equals the expected value, a self-approved or over-broad scope, a cross-host chain link, an overstated tier, a non-traceable recommendation, an overstated or leading narrative, and an executive summary that hides gaps.
   - It has 5 narration subjects: scenario, recommendation, verification, executive, and one with a planted prompt injection.
   - Shapes mirror the production packets. A unit test checks that an oracle reply passes production grounding for every packet.
2. **Measured through production code.** `aisw.llm.evaluation.evaluate` sends the set through `ValidationGateway` and `LlmGateway` unchanged, with clients from the same factory a run uses. `tools/eval_labelled.py` writes JSON and Markdown from the calls it actually made.
   - **Recall:** the share of DEFECT cases flagged with CONCERN or DISSENT.
   - **False-flag and false-dissent rates:** measured on CLEAN cases.
   - **Unscored:** cases whose packet reply was invalid or unavailable.
   - **Narration:** the rejection rate and a histogram of defects.
   - **Decision:** `USABLE`, `NOT_USABLE`, or `INCONCLUSIVE` when more than 10% of cases are unscored.
3. **Tune inputs and prompts, never the validator.** The first live runs exposed two input-fidelity bugs, and both were fixed at their source:
   - Narrative packets now state that facts are failed requirements (`facts_are`), and the reviewer prompt says so (`agent-validation-1.2.0`). Without this, a requirement title such as "Remote desktop is not reachable…" read as the opposite of the claim.
   - Verification subjects now state observed and required ports as "port N", the form the grounding check reads. A correct question about port 23 had been rejected because the port appeared only as `[23, 443]`.
4. **Explicit proxy, Astra only.** `AISW_ASTRA_PROXY=http(s)://host:port` is the only proxy the Astra client uses.
   - Proxy environment variables are still ignored.
   - Credentials, paths, a missing port and link-local, multicast, reserved or unspecified addresses are refused, both in settings and in the client.
   - The setting is refused unless `model_provider=astra`.
   - The client opens a CONNECT tunnel, so TLS and the Azure host check stay end to end. A loopback test shows the proxy receives only `CONNECT <resource>:443`, never the key or the prompt.

## Results (live, synthetic set, 2026-10-16)
The reviewer was gpt-5.4 and narration used gpt-6-astra, on `dev-agentic`. All three runs are recorded:

| Run | Prompt | Recall | False dissent | Unscored | Narration validated | Decision |
|---|---|---|---|---|---|---|
| 1 | agent-validation-1.1.0 | 14/15 (0.933) | 1/9 (0.111) | 0 | 4/5 (ports rejected) | NOT_USABLE |
| 2 | 1.2.0, ports fix for observed only | 13/13 (1.0) | 0/8 | 3/24 (Agent 0 packet timed out at 60 s) | 4/5 (port 21 from the requirement) | INCONCLUSIVE |
| 3 | 1.2.0, both fixes, 120 s timeout | 15/15 (1.0) | 0/9 | 0 | 5/5 | USABLE |

The full table for the last run is in `docs/implementation/evaluation.md` and `docs/implementation/evaluation/labelled-1.0.0-gpt-5.4.json`.

## Consequences
- The bar was met on one run of a small synthetic set (24 cases). This is evidence, not proof. Still to do:
  - grow the set and run it repeatedly;
  - have a policy owner sign the bar;
  - re-measure on real evidence once the data approval exists.
- The false-flag rate is 0.22, all CONCERN on clean cases. CONCERNs are review notes and never hold an item, but they cost reviewer attention.
- Agent 0 replies can take more than 60 s on gpt-5.4. Set `AISW_MODEL_TIMEOUT_SECONDS` to 120 when using that deployment as the reviewer.
- Proxy authentication is not supported. A proxy that requires it needs a separate decision.

## Tests
- `tests/unit/test_labelled_evaluation.py` checks the set's consistency and checks scoring against an oracle, an always-concur, an always-dissent, a CONCERN-only, an unavailable and a partly invalid reviewer. It also checks the Markdown output.
- `tests/unit/test_generation_agents.py` covers the port lines in verification subjects.
- `tests/unit/test_config_ai.py` and `tests/evaluation/test_astra_client.py` cover proxy validation, handler selection, the factory wiring and a loopback CONNECT capture.
