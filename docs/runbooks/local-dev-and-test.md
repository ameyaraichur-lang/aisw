# Local development and tests

Needs `uv`, Node >= 24, npm and Google Chrome (system browser, nothing is downloaded). No Docker, no credentials.

```bash
cd backend && uv sync && uv run ruff format --check . && uv run ruff check . && uv run mypy && uv run pytest -q
cd web && npm install && npm run typecheck && npm run lint && npm test && npm run build && npm run e2e
python3 tools/secret_scan.py .
cd backend && uv run python ../tools/export_schemas.py --check && uv run python ../tools/sbom.py --check
```

Tests start an embedded PostgreSQL (pgserver). It leaks if a run is killed; macOS allows few shared-memory segments, so after a killed run:

```bash
tools/stop_stale_test_postgres.sh
```

It only matches this repository's own embedded servers. If `initdb` still fails, list leftovers with `ps aux | grep pgserver` before killing anything yourself.

Rules that keep tests honest: tests never contact a non-loopback host (a socket guard fails the test if code tries); no model weights exist (a scripted stub is used); fixture evidence is byte-identical between runs, so tests that reason about shared blobs use the isolated-database fixture.

## Running the product locally

`tools/dev_stack.py` starts the whole product on this machine: embedded PostgreSQL (migrated and bootstrapped), the OPA policy server, the API, one worker and the console. Sign-in is the development identity picker; there is no password and no SSO. Nothing here is a production configuration.

```bash
backend/.venv/bin/python tools/dev_stack.py up      # foreground; Ctrl-C stops everything
backend/.venv/bin/python tools/dev_stack.py down    # stop a stack started in another terminal
backend/.venv/bin/python tools/dev_stack.py reset   # after down: delete database, evidence and audit witness
```

Open http://127.0.0.1:5173/ and pick an identity. `sam` (operator and reviewer) can launch runs and read reports. `alice` launches but cannot read reports, and `bob` approves scopes; that split is the intended separation of duties.

- State lives in `data/dev-stack/` (gitignored): logs, evidence, the signing key, generated secrets (mode 0600), the audit witness and `scans/`. The database lives in `~/.aisw-dev/pg` (override with `AISW_DEV_PGDATA`), because PostgreSQL refuses paths that contain spaces.
- `--ai` turns on Astra using the `AISW_*` keys in `.env.astra`; the launcher never prints them. Pass `--ai-approval-ref <ref>` naming the product owner's approval to send these targets' redacted findings to the model.
- On a network that intercepts TLS (a corporate proxy re-signing public sites), pass `--tls-inspection-ca <pem>` with the proxy's root. URL probes then report the connection as inspected and leave the certificate controls unassessed (ADR-016, decision 9). Never add that root to the trust store instead. On macOS: `security find-certificate -c "<root name>" -p /Library/Keychains/System.keychain > data/dev-stack/tls-inspection-ca.pem`.
- The launcher restarts OPA if it exits. OPA's listener has been seen to exit on malformed connections, for example from an `nmap -sV` probe of port 8181.

### Live assessments

`tools/live_assess.py` drives authorised assessments through the running API the same way the console does. For each scenario it creates the project and the inventory with expected assets, then the scope; alice preflights it and bob approves it. It uploads any scanner output, launches the run, waits for it and prints coverage, controls, findings and the AI validation summary:

```bash
cd backend && .venv/bin/python ../tools/live_assess.py --ai                  # all scenarios
cd backend && .venv/bin/python ../tools/live_assess.py example-com --ai      # one
```

To watch a run while it happens, open **Mission Control** (`/mission`, signed in as sam). Each project is an orbit of its assets, coloured by the worst accepted finding. Probe and evidence pulses fire only for recorded run events. The event stream and the pipeline strip update while a run is in flight, and "Replay last run" plays back the newest run's recorded events. The 3D view is decorative (`aria-hidden`); the tracked-asset list and the event log carry the same facts. It is lazily loaded with three.js (MIT) and falls back to text without WebGL. Under reduced motion it draws one still frame.

Scenarios: `example-com` (passive URL probe, port 443), `local-portal` (this stack's console and API on loopback), `workstation` (an Nmap import of this machine) and `base-images` (a Trivy import of the product's container base images). Only add a target someone with authority over it has approved in writing.

Scanner output goes in `data/dev-stack/scans/`. Nmap must use the bounded profile the importer accepts; anything else is refused with `SCAN_PROFILE_VIOLATION`:

```bash
nmap -sT -Pn -T3 --top-ports 100 --max-retries 2 -oX data/dev-stack/scans/nmap-workstation.xml 127.0.0.1 <this machine's LAN address>
trivy image --image-src remote --format json --output data/dev-stack/scans/trivy-python.json python:3.12.15-alpine3.24
trivy image --image-src remote --format json --output data/dev-stack/scans/trivy-nginx.json nginxinc/nginx-unprivileged:1.30.6-alpine
```

Use the base images named in `deploy/docker/*.Dockerfile`; `--image-src remote` reads them from the registry, so Docker is not needed. Move older `trivy-*.json` files out of `scans/` first, because the scenario imports every file that matches. The scenario's inventory selector carries a hash of the expected images, so a new set of images gets its own inventory entry.
