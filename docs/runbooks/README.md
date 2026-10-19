# Runbooks

Written from what the code does today. Steps marked **(unverified)** were not exercised against a live deployment (none exists yet); treat them as a checklist to confirm, not as proven procedure. Nothing here instructs anyone to run an active scan or touch a customer system: those need a signed scope manifest and explicit approval.

- [Local development and tests](local-dev-and-test.md)
- [Sign-in (OIDC through the BFF)](sign-in.md) **(unverified against a real IdP)**
- [Egress control](egress.md) **(firewall unverified on a real host)**
- [Operating the worker and the task queue](worker-and-queue.md)
- [Permits, manifests and signing keys](permits-and-keys.md)
- [Evidence retention, legal holds and purge](evidence-retention.md)
- [Write-once evidence replica and audit anchors](evidence-integrity.md) **(emulators only; production backends pending sign-off)**
- [Enabling and disabling AI](ai-enablement.md)
- [Manual screen-reader pass](accessibility-screen-reader.md) **(checklist; not yet performed)**
- [Turning on ticket delivery (Jira or ServiceNow)](itsm-delivery.md) **(unverified against a real ITSM)**
- [Security incidents](security-incidents.md)
- [Release, SBOM and licence gate](release-and-supply-chain.md)
