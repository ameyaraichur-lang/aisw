# ADR-016: PASSIVE_HTTP_SMOKE adapter (M5)

**Status:** Accepted (M5)

## Decision
1. **The adapter never resolves names.** The gateway vets DNS (A/AAAA) at preflight and again at dispatch and passes the vetted, **pinned** addresses; the adapter connects only to those, with SNI and `Host` set to the registered hostname. A failed pinned address is never retried by name.
2. **Redirects are vetted by the gateway, per hop.** `AdapterJob.vet_redirect` is built from the signed manifest (scope, approved ports, internal-range authorisation, egress policy, DNS). The adapter must call it for every hop; with no hook, redirects are not followed. Cross-host redirects work only when the other host is itself an approved target.
3. **TLS is verified before anything is sent.** On verification failure no HTTP request is made; a second, data-less handshake with verification off only describes the rejected certificate. TLS 1.2 is the floor. The trust store is configured by the deployment (`ca_file` / platform default), never by the manifest or request.
4. **Bounded and passive.** GET or HEAD only; at most `1 + max_redirects` requests (budget enforced by the gateway before dispatch); no cookies, credentials, crawling, forms, fuzzing or port enumeration; response **bodies are never read or stored**; response headers are allow-listed, truncated and newline-stripped; `Set-Cookie` is recorded as presence only.
5. **Outcome semantics.** SUCCEEDED = chain completed; PARTIAL = definitive but incomplete (TLS untrusted, redirect blocked, too many redirects, read timeout, protocol error); FAILED = first hop unreachable or TLS handshake impossible. A failed TLS verification is an observation (HIGH finding), not a tool failure.
6. **Policy pack `url-smoke-baseline:1.0.0`** turns the observations into 7 controls; its `report_notice` ("Public URL smoke test — not a security certification") appears on the report body and HTML.
7. **Asset attributes are generic** (`assets.attrs`, migration 0003) so policy applicability can depend on e.g. `scheme`, not only `os_family`.
8. **Tests contact no public host.** A loopback-only socket guard fails any test that connects elsewhere; DNS is mocked; certificates are generated per test.

## Known limitations
- Never run against `example.com` or any real host: M9 only, with explicit authorisation. TLS behaviour against real CAs, IPv6-only hosts, HTTP/2-only servers and unusual redirect or chunking behaviour is unverified.
- Only the IP the gateway pinned is contacted, so multi-address failover across a resolver's full answer set is minimal (tries pinned addresses in order).
- No HEAD-fallback when a server rejects HEAD; no proxy support; no client certificates.
- A redirect hop re-resolves DNS through the gateway's resolver, so a hostile resolver could still return different addresses per hop; every answer is vetted, and deployment egress firewalling (M8 runbook) remains the second control.
