# Egress control

ADR-028. There are two layers: the application refuses unapproved destinations, and the host firewall drops anything else the service user tries.

## Configure
- `AISW_EGRESS_SCAN_CIDRS`: the networks the worker may scan, comma-separated. Leave it unset only where the host firewall is the sole scan boundary. Zones broader than /8 (IPv4) or /16 (IPv6), and zones touching cloud metadata ranges, are refused at startup.
- `AISW_EGRESS_SCAN_PORTS`: the ports the firewall opens toward the zones (default `80,443`). The manifest's `allowed_ports` still limits each run.
- `AISW_EGRESS_DNS_SERVERS`: the resolver IPs the service user may query.
- `AISW_EGRESS_ALLOWED_HOSTS`: extra control-plane hosts, for example an IdP whose JWKS is on another host (`keys.idp.example` or `keys.idp.example:8443`).

## Install the firewall (unverified)
Follow `deploy/egress/README.md`: run `plan`, then `render --resolve`, load the rules, then run `verify` as the service user with a real deny canary. Keep the `verify` output with the change record.

## When a scan is refused
`BLOCKED_ADDRESS_OUTSIDE_EGRESS_ZONE` at preflight or dispatch means the target resolved outside every configured zone. Either the target is wrong, its DNS changed since preflight, or the deployment's zones need a reviewed change. Never widen a zone to make one run work.

## Logs
On the host, firewall drops appear as `aisw-egress-deny` in the kernel log. Any such line points to a bug or a compromise, and should be investigated under `security-incidents.md`.
