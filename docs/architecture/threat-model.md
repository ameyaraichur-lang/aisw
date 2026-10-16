# Threat model (M8)

Method: trust boundaries and assets first, then STRIDE-style threats per boundary, each with the control that exists **in this repository today**, where it is tested, and what remains open. "Tested" means an automated test in this repo exercises it; it does not mean it was exercised against a real customer environment (none exists yet).

## Assets
Scope manifests and execution permits (authority to touch anything) · evidence (may contain sensitive configuration even after redaction) · findings/reports (decisions are made from them) · the audit trail · signing keys · tenant data separation · the optional model's output (a candidate, never an authority).

## Trust boundaries
1. Browser / API client -> API (authentication, authorisation, tenant context)
2. API/worker -> PostgreSQL (tenant isolation, role separation)
3. Worker -> Tool Gateway -> adapter -> target (the only egress path)
4. Uploaded files / adapter output -> parsers and evidence store (hostile input)
5. Platform -> model endpoint (optional): local loopback runtime, or the Astra / Azure OpenAI endpoint when explicitly enabled (ADR-020)
6. Operator -> filesystem evidence store and quarantine (retention)

## Threats and controls
| # | Boundary | Threat | Control (test) | Residual / open |
|---|---|---|---|---|
| T1 | 1 | Spoofed identity | Dev stub refused outside dev/test (`test_config_fail_closed`, `test_api_authz`) | **No production sign-in exists** (OIDC planned). Not deployable to production. |
| T2 | 1 | Privilege escalation by role | Server-side RBAC on every route, UI hiding is courtesy (`test_api_authz`, `e2e/permissions.spec.ts`) | Roles are coarse; no per-project roles |
| T3 | 1,2 | Cross-tenant read/write | Forced RLS on every tenant table incl. analysis and retention tables, fail-closed with no tenant set (`test_tenant_isolation_db`, `test_analysis_security`, `test_retention`) | Same database for all tenants; a DB superuser bypasses RLS by design |
| T4 | 1 | Approver approves own request / replay | Separation of duties, idempotency keys (`test_api_authz`, race test) | |
| T5 | 3 | Scan outside approved scope (wildcards, stale hash, expired/revoked permit, inventory drift) | Agent 0 gate, signed manifest, gateway re-check of permit/manifest/signature on every dispatch, **zero dispatch asserted** (`test_agent0_gate`, `test_tool_gateway`, `test_permit_renewal`) | Permit renewal re-runs the full launch policy; a lapsed or revoked permit is never renewed |
| T6 | 3 | SSRF / DNS rebinding / redirect to internal host | `net_guard`: canonicalisation, A/AAAA vetting at preflight and dispatch, pinned-address connect, per-hop redirect vetting (`test_net_guard`, `test_url_smoke_adapter`) | Tested against a local server only; real CA/IPv6/proxy behaviour unverified. **Egress firewall is not enforced** (runbook only) |
| T7 | 3 | Mutating adapter / remediation path | Registry refuses mutating adapters; no code path executes a recommendation (`test_adapter_contract`, `test_analysis_api`) | |
| T8 | 4 | Malicious import (XXE, entity bomb, oversized, wrong shape) | defusedxml, size/record caps, fail closed with no partial assets (`test_import_adapters`) | Built against synthetic fixtures; real tool versions unverified |
| T9 | 4 | Secrets in evidence, logs, reports, model input | Redaction before hashing/storage and before model input (`test_redaction`, `test_evidence`, evaluation suite) | Pattern-based; unknown secret formats can slip through. Raw uploads keep the operator's file (redacted for known patterns) until purged |
| T10 | 4 | Prompt injection via evidence text | Model sees a whitelisted projection, never raw evidence; output is schema- and grounding-checked; injection-looking input is flagged and sent to review (`tests/evaluation`, `test_evidence_text_never_reaches_the_model`) | Grounding is pattern-based (identifiers), not semantic |
| T11 | 5 | Model hallucination or tool use | No tool interface; hallucinated CVE/control/IP/URL/port/tier/asset rejected; only ACCEPT reaches the report; model outage leaves results identical (`tests/evaluation`, `test_analysis_pipeline`) | Real model quality/latency **unverified**; no model was run |
| T12 | 5 | Model endpoint turned into egress | Loopback-only endpoint for Ollama; Astra endpoint limited to an https origin on an Azure OpenAI host suffix, checked in config and client; no redirects, no proxies, size cap (`test_ollama_client`, `test_astra_client`, `test_config_ai`) | A loopback port-forward could still point elsewhere; any Azure OpenAI resource (not only yours) passes the host check; operator control |
| T22 | 5 | A model reviewer used to approve or suppress results | Validator verdicts have code-fixed, one-way effects: only DISSENT acts, and it can only hold an accepted item for review; schema forbids extra fields; grounding rejects unknown targets/refs/identifiers, commands and compliance claims; DB CHECK ties verdict to effect; table append-only under forced RLS (ADR-021; `test_ai_validation`, `test_ai_validation_pipeline`) | A reviewer can create false holds (review work, never false acceptance). A reviewer that always concurs adds no assurance; measure on a labelled set |
| T21 | 5 | Findings or the Astra key leaving the host | Astra is off unless fully configured with a recorded data-handling approval reference; only the redacted projection is sent, with `store: false`; key held as `SecretStr`, sent only in the `api-key` header, absent from settings output, errors and provenance (`test_config_ai`, `test_astra_client`) | Data does leave the host by design once enabled; Azure-side retention and logging are governed by the Azure agreement, not this code. Key custody depends on the secret provider |
| T13 | 2,4 | Tampered or missing evidence | Content-addressed write-once store, re-hash on read, independent assurance rejects (`test_pipeline_security`) | Local filesystem; no object-lock/WORM |
| T14 | 2 | Audit tampering | Hash-chained append-only audit with verifier, DB triggers (`test_audit_chain`) | Chain anchor is not externally witnessed |
| T15 | 1 | Unauthorised export / distribution of a draft | Download of an unapproved report needs the approve permission; every view/export audited incl. denials; HTML watermarked with who/when/hash/approval (`test_hardening`) | Watermark is visible text, not forensic; a recipient can strip it |
| T16 | 3 | Worker crash, retry storm, double execution | Leases, fencing tokens, bounded attempts with exponential backoff and jitter, replay-safe ingest (`test_pipeline_security`, `test_hardening`) | Single-process load only; no multi-node soak test |
| T17 | 6 | Premature or unreviewed deletion of evidence | Dry-run plan, execution pinned to the reviewed plan hash, legal holds, shared-blob protection, **soft purge** (quarantine, not delete), append-only action log (`test_retention`) | Quarantined files are removed only by a person (runbook); no automatic scheduler |
| T18 | all | Vulnerable or non-compliant dependency | pip-audit, npm audit, SBOM + licence gate with recorded acceptances (`test_sbom_gate`) | SBOM is lockfile-based, not Syft/ScanCode; native libs in wheels not inventoried; legal review of LGPL (psycopg) pending |
| T19 | 1 | Clickjacking / content injection in report preview | Escaped HTML, CSP `default-src 'none'`, sandboxed iframe, nosniff | |
| T20 | 2 | Signing key theft or loss | Ed25519 key in a local file, public keys in a key ring | **Local custody only**: no HSM/OpenBao, **no rotation procedure tested**; compromise would allow forged manifests |

## Findings from building the tests (fixed)
Late worker double-write after lease loss; scanner self-corroboration promoting a stray host to HIGH confidence; zero-rule OpenSCAP result read as clean; coverage ledger overwritten across adapters; export denials not recorded because the audit row was rolled back with the request transaction (M8). Each now has a regression test.

## Not covered
Denial-of-service sizing, physical/host compromise, insider with database superuser, supply-chain compromise of the build itself, anything about real customer systems.
