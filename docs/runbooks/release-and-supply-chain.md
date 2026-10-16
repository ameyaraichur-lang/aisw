# Release, SBOM and licence gate

Before any release candidate:
```bash
cd backend && uv run pip-audit && uv run python ../tools/sbom.py --check
cd ../web && npm audit --omit=dev
python3 ../tools/secret_scan.py ..
```
`tools/sbom.py` writes a CycloneDX SBOM and licence report to `docs/implementation/sbom/`. It reads `uv.lock` and `package-lock.json` plus installed Python metadata. It is **not Syft or ScanCode** and does not see native libraries inside wheels (libpq, OpenSSL). Treat it as a floor.

The licence policy (`sbom/licence-policy.json`): allow-listed permissive licences pass; copyleft-style licences need a **recorded acceptance** with rationale; unknown or denied licences (AGPL, GPL, SSPL, BUSL) fail, and cannot be accepted if they ship at runtime. Adding a dependency that changes the SBOM requires regenerating and committing it (the test fails on drift).

Open obligations: `psycopg` and `psycopg-binary` are LGPL-3.0. Used unmodified as separate packages, but packaging must keep notices and the ability to replace the library. A named legal reviewer must confirm before any external distribution **(pending)**. Also pending: real Syft/ScanCode scan, container image build, signing of release artefacts.
