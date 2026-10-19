# ADR-028: Egress allow-list: app-level scan zones plus generated host-firewall rules

**Status:** Accepted. The app-level controls are implemented and tested. Host firewall rules are generated and tested as text, but have **not been loaded on a real host**, so in-host denial is unverified.

## Context
Egress was controlled only inside the application: `net_guard` for scan targets, and pinned endpoints for the model, the IdP and the KMS. A bug or a compromised process could still connect anywhere (pending-plan P0-3, threats T6 and T12).

## Decision
**Layer 1: application.**
- **Scan zones.** `AISW_EGRESS_SCAN_CIDRS` lists the networks the worker may scan. When it is set, every resolved address of a URL target must fall inside a zone, both at preflight (`ScopeGate`) and at dispatch (`ToolGateway`, including each redirect hop). Otherwise the target is refused with `BLOCKED_ADDRESS_OUTSIDE_EGRESS_ZONE`. This sits on top of the manifest scope and the existing private, metadata and rebinding blocks. A zone cannot be broader than /8 (IPv4) or /16 (IPv6), and cannot overlap cloud metadata ranges.
- **IdP endpoints.** The discovered `token_endpoint` and `jwks_uri` (the endpoints the server itself connects to) must be on the issuer's host, or listed in `AISW_EGRESS_ALLOWED_HOSTS`. Discovery cannot point the server at an arbitrary host.
- **Unchanged:** the Astra endpoint is pinned to an Azure OpenAI origin on port 443 (or the configured CONNECT proxy). Ollama is loopback-only. The KMS address must be an https origin. Every client ignores proxy environment variables and refuses redirects.

**Layer 2: host firewall, generated.**
- `aisw.core.egress.destinations(settings)` derives each role's allow-list from the same settings the processes run with:
  - DNS servers (`AISW_EGRESS_DNS_SERVERS`);
  - the database, for both API and worker;
  - the IdP and extra hosts, for the API;
  - the KMS, for both;
  - Astra or its proxy, for the worker;
  - the scan zones on `AISW_EGRESS_SCAN_PORTS`, for the worker.
- `tools/egress_check.py render` emits nftables, iptables or ip6tables rules that filter **only the AISW service user's** traffic (`meta skuid` / `-m owner`). They accept loopback, established traffic and the allow-list, and log and drop everything else. Hostnames are resolved only with `--resolve`; an unresolved host is left out and flagged, so the rules fail closed.
- `deploy/egress/*.example` are rendered from `deploy/egress/example.env`, which uses documentation addresses only. A test fails if the examples drift from the renderer.

**Verification from the host.** `tools/egress_check.py verify` TCP-connects to each control-plane destination for the role, which must succeed, and to each `--deny` canary, which must fail. A denied canary that connects is reported as a failure. Canaries must be destinations that are reachable when no firewall is present, otherwise a "refused" proves nothing.

## Consequences
- Scan targets need two independent approvals: the per-run manifest and the deployment's zones. A misconfigured zone shows up as a clear preflight error, not a silent miss.
- A firewall reload is needed when control-plane IPs change. Regenerate the rules with `--resolve`.
- **Not verified:** loading the rules into nftables or iptables on a real host, then running `verify` with a real deny canary. This machine has no Linux firewall or container runtime. The remaining step is owned by the platform admin and is recorded in P0-3.

## Tests
- `tests/unit/test_egress.py`:
  - derivation by role (database, unix socket, loopback, IdP extras, KMS, Astra or proxy, DNS, zones);
  - nftables, iptables and ip6tables rendering, including fail-closed handling of unresolved hosts and user-name validation;
  - loopback probes showing that a missing firewall is detected;
  - zone vetting and unsafe zones;
  - settings validation;
  - IdP endpoints on another host;
  - the CLI;
  - drift of the committed examples.
- `tests/security/test_egress_zones.py`: preflight refuses a target outside the zones; dispatch refuses a target whose DNS answer has moved outside them, and nothing is dispatched.
