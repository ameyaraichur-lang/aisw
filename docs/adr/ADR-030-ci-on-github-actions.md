# ADR-030: GitHub Actions as the CI system of record

**Status:** Accepted. The workflow passes actionlint and zizmor locally, and every command in it passes locally. It has **never run on a GitHub runner** (pending-plan P0-5).

## Context
The original workflow ran most of the gates. It used floating action tags, unbounded jobs and `uv sync` without `--frozen`. It skipped the key-rotation drill and never built the deployment images. The rev 3 plan also drafted a `.gitlab-ci.yml`. The repository owner chose GitHub Actions (open question 4 in the pending plan).

## Decision
- **One workflow, `.github/workflows/ci.yml`, with five jobs:**
  - backend gates: ruff, format, strict mypy, pytest, pip-audit, schema drift, SBOM and licence gate, and the key-rotation drill against the emulator;
  - web gates: lint, generated-type drift, typecheck, unit tests, build, `npm audit --omit=dev`;
  - Playwright end-to-end, with results uploaded on failure;
  - deploy: build both images, check the uids and the migrations path inside the image, serve the web image and check its security headers, and validate the compose file;
  - hygiene: the secret scan, then actionlint and zizmor on the workflow itself.
- **Supply chain.** Every action is pinned to a full commit SHA, with the tag in a comment. uv and the linters are pinned by version. The uv and Node versions match the images (enforced by a test).
- **Least privilege.**
  - `permissions: contents: read` at workflow level, and no job widens it.
  - Checkout uses `persist-credentials: false`.
  - No repository secrets are used.
  - Triggers are `push` to main and `pull_request` only, never `pull_request_target`.
  - Every job has a timeout, and concurrency cancels superseded runs.
- **Nothing external.** Tests use embedded Postgres, the mock IdP, the KMS emulator and loopback servers. CI never needs a scan authorisation or a data approval.
- GitLab CI is not maintained. A port would mirror these jobs.

## Consequences
- Bumping an action means resolving its new SHA (`git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>`) and updating the comment.
- Possible first-run differences on ubuntu-24.04 runners: wheel licence metadata in the SBOM gate, the pgserver binaries, and the Chrome channel used by Playwright.

## Tests
- `tests/unit/test_ci_workflow.py`:
  - SHA pinning;
  - workflow-level read-only permissions, with no job overrides;
  - push and pull_request triggers only;
  - no secrets referenced;
  - bounded timeouts;
  - non-persisted checkout credentials;
  - every local gate present;
  - both Dockerfiles built;
  - toolchain versions match the images.
- Run locally: actionlint 1.7.12 (no findings); zizmor 1.31.1, auditor persona (no findings); the drill command (all steps PASS).
