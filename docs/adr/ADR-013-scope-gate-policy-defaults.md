# ADR-013: Scope gate policy defaults and manifest profile contract

**Status:** Accepted (M2)

## Decision
1. **Every manifest needs an independent approval** before it is signed, not only active ones. Approver must differ from the requester and hold `manifest:approve`. Active profiles additionally need the approver to explicitly acknowledge each active adapter.
2. **Wildcards are denied by default** (`GatePolicy.allow_wildcards=False`): `*`/`?`, `any`/`all`, `/0` CIDRs, and CIDRs broader than /16 (IPv4) or /48 (IPv6). This is stricter than the blueprint ("unless explicitly approved") and can only be relaxed by policy code change.
3. **Manifest `profiles` is `adapter_id -> {profile_id, profile_class}`.** The class claim lives inside the signed body but is never trusted: the gate and the gateway both re-check it against the adapter's registered capability.
4. **Cloud-metadata addresses are never reachable**, even with an `internal_range_authorization` (stricter than J.6, which allows authorised internal ranges generally). Other internal ranges need an explicit CIDR in the signed manifest (conflict G9).
5. **Python's `ipaddress.is_global` is not trusted alone**: it reports multicast `ff02::1` and NAT64-wrapped loopback (`64:ff9b::7f00:1`) as global. `net_guard` unwraps IPv4-mapped, 6to4, NAT64 and Teredo addresses and blocks multicast explicitly.
6. **Preflight resolves targets and the resolved manifest is what gets hashed and signed.** If inventory drifts afterwards, approval and launch fail with `INVENTORY_DRIFT`.
7. **Launch re-runs the gate** (connector health, DNS, caps, inventory) at execution time, and the gateway re-runs authorisation on every adapter call, reading permit and manifest state fresh so revocation is immediate.

## Consequences
Stricter than the blueprint in points 2 and 4; relaxing either requires a new ADR. The M1 `ScopeManifestBody.profiles` type changed (no persisted data existed yet).
