# Release, SBOM and licence gate

Before any release candidate:
```bash
cd backend && uv run pip-audit && uv run python ../tools/sbom.py --check
cd ../web && npm audit --omit=dev
python3 ../tools/secret_scan.py ..
```
`tools/sbom.py` writes a CycloneDX SBOM and licence report to `docs/implementation/sbom/`. It reads `uv.lock` and `package-lock.json` plus installed Python metadata. It does not see native libraries inside wheels (libpq, OpenSSL) or OS packages. Treat it as a floor.

**Independent checks (ADR-043).** CI scans the built images with Syft and runs `tools/sbom_crosscheck.py check`: every runtime component must appear at its locked version; anything only Syft sees is listed in the job summary and the `syft-sboms` artifact. The `licences` job stages runtime licence files (`sbom_crosscheck.py stage`) and scans them with ScanCode; a denied licence without an acceptance fails. gitleaks scans the full history; add a fingerprint to `.gitleaksignore` only for a confirmed test fixture, and rotate anything real. Locally, with `syft` on the PATH:
```bash
syft scan dir:backend -q -o cyclonedx-json=/tmp/backend.cdx.json
syft scan dir:web -q --exclude './node_modules/**' -o cyclonedx-json=/tmp/web.cdx.json
python3 tools/sbom_crosscheck.py check --syft /tmp/backend.cdx.json --syft /tmp/web.cdx.json
gitleaks git --redact=100 --no-banner .
```

The licence policy (`sbom/licence-policy.json`): allow-listed permissive licences pass; copyleft-style licences need a **recorded acceptance** with rationale; unknown or denied licences (AGPL, GPL, SSPL, BUSL) fail, and cannot be accepted if they ship at runtime. Adding a dependency that changes the SBOM requires regenerating and committing it (the test fails on drift).

Open obligations: `psycopg` and `psycopg-binary` are LGPL-3.0. Used unmodified as separate packages, but packaging must keep notices and the ability to replace the library. A named legal reviewer must confirm before any external distribution **(pending)**. Also pending: the first CI run of the image scan and ScanCode (neither can run on the development machine: no Docker, no libmagic), and signing of release artefacts.
