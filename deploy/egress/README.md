# Egress rules (ADR-028)

Generated host-firewall rules that let the AISW service user reach only its allow-list. Everything else that user tries is logged (`aisw-egress-deny`) and dropped. Other users on the host are not affected.

The `*.example` files are rendered from `example.env`, which uses documentation addresses only. They show the shape of the rules; do not load them. To produce real rules for a host, run this from `backend/`:

```
uv run python ../tools/egress_check.py plan   --env-file /etc/aisw/worker.env
uv run python ../tools/egress_check.py render --env-file /etc/aisw/worker.env --role worker \
    --format nftables --resolve --out /etc/nftables.d/aisw-egress.nft
sudo nft -f /etc/nftables.d/aisw-egress.nft
uv run python ../tools/egress_check.py verify --env-file /etc/aisw/worker.env --role worker \
    --deny <a host:port reachable without the firewall, e.g. a public HTTPS site you control>:443
```

Run `verify` as the service user (`sudo -u aisw ...`), because the rules filter only that user's traffic. Regenerate the rules whenever a control-plane address, scan zone or DNS server changes.

**Status:** these rules have not yet been loaded on a real host (unverified). See `docs/runbooks/egress.md`.
