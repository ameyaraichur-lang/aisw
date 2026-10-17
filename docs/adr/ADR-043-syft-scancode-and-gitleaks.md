# ADR-043: Syft and ScanCode cross-checks and gitleaks in CI

**Status:** Accepted (Syft and gitleaks run locally; ScanCode runs in CI only; first CI run pending)

## Context
The SBOM (`tools/sbom.py`, ADR-019) is built from `uv.lock`, `package-lock.json` and installed Python metadata. It cannot see OS packages in the images or native code bundled in wheels, and its licences come from what packages declare about themselves. The secret scanner (`tools/secret_scan.py`) is a small pattern list over the working tree, not the git history.

## Decision
1. **Keep the lockfile SBOM as the committed record and check it against independent tools** rather than replace it: it is reproducible offline and drift-gated in every run, while Syft and ScanCode output depends on the platform and tool version.
2. **Syft (1.54.1, pinned by sha256)** scans the built backend and web images and the web lockfile in the `deploy` job. `tools/sbom_crosscheck.py check` fails when any runtime (`required`) component of the committed SBOM is missing from Syft's output or present only at another version, and fails if no ecosystem could be checked at all. Components only Syft sees (Debian packages, bundled binaries) are listed in the job summary and kept as an artifact for 30 days; the lockfile SBOM does not claim to cover them.
3. **ScanCode (scancode-toolkit-mini 32.5.0)** reads the licence files of every runtime component, staged by `sbom_crosscheck.py stage`, in a separate `licences` job. A licence on the policy's deny list fails unless the component has a recorded acceptance. `pluggy` is pinned to 1.5.0 because ScanCode 32.5.0's plugin loader fails with newer releases.
4. **gitleaks (8.30.1, pinned by sha256)** scans the full git history (`fetch-depth: 0`) with findings fully redacted. `.gitleaksignore` lists, by fingerprint, the four deliberate synthetic secrets in redaction and hostile-header tests. The stopgap scanner stays: it also covers uncommitted files and the repository's own patterns.

## Consequences
- Locally (macOS arm64): Syft confirmed all 26 Python and 9 npm runtime components at their locked versions; it also found the PostgreSQL 16.2 binary bundled by the test-only `pgserver` and pip's Windows launchers, which are not runtime. A directory scan on macOS does not detect libpq or OpenSSL inside wheels; the image scan is where OS-level and bundled libraries appear. gitleaks over the full history found only the four fixtures.
- ScanCode could not run here: it needs the system `libmagic`, which this machine lacks. Its first result comes from CI, as does the image scan (no Docker here).
- Release artefacts are still unsigned, and the LGPL review of psycopg is unchanged (`licence-review` sign-off).

## Tests
`tests/unit/test_sbom_crosscheck.py` (missing and version-drifted components, unchecked ecosystems, denied and accepted ScanCode licences, the CLI summary) and `tests/unit/test_ci_workflow.py` (the jobs exist, tools are checksum-pinned, history checkout for gitleaks).
