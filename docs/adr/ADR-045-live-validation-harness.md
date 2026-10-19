# ADR-045: Live validation harness with an authorisation gate

**Status:** Accepted (loopback only; no real target authorised)

## Context
M9 means checking the platform against real targets: a passive smoke of `example.com`, one bounded Nmap of `scanme.nmap.org`, and ZAP against a Juice Shop you own. Each needs your explicit authorisation, and nothing so far recorded or enforced that authorisation.

## Decision
1. **The plan is a file** (`docs/implementation/live-validation/plan.json`): each target has its selector, adapter, policy pack, allowed ports, the command an operator runs by hand for import targets, an `authorisation` block (who, reference, window), and `expect` (control id to outcome, the answer key).
2. **The gate** (`aisw.validation.live.authorise`): a non-loopback target may run only when
   - the `live-validation` sign-off is APPROVED and its decision's sha256 matches the plan file byte for byte (an edit after approval needs a new decision), and
   - the target's own authorisation names who and a reference, with a window that contains now.

   Loopback targets need neither. `python -m aisw.validation.live preflight` prints AUTHORISED or REFUSED with reasons per target and exits non-zero on any refusal.
3. **The harness never contacts a target.** Runs are launched and approved (two people) in the console as usual. `evaluate` reads a report exported from the console and compares each expected control outcome with the worst outcome across the run's assets. A target with no expectations can only be observed; it never counts as met.
4. **Proven on loopback**: a healthy and an expired-certificate HTTPS server on 127.0.0.1 run through the real API, worker and URL probe; both reports meet their expectations, a wrong expectation is reported as a mismatch, and no connection leaves loopback.

## Consequences
- Nothing in the committed plan is authorised, and the sign-off is PENDING, so `preflight` refuses all three targets. Approving means filling each authorisation block, re-checking the scanme.nmap.org terms, replacing the Juice Shop selector with your instance, recording expectations, and recording the decision with the plan's sha256.
- Nmap and ZAP have no live adapters; for those targets the operator runs the tool by hand within the window and imports the output (`nmap_import` with vantage `untrusted`, `zap_import`).
- The URL probe against a public CA (the remaining URL probe gap, ADR-016) is covered by the `example.com` target once authorised.
