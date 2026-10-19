# ADR-041: Reachability from recorded evidence, exposure scoring and internet-to-asset paths

**Status:** Accepted

## Context
Exposure came only from a finding's category (rubric `exposure_by_category`), so host vulnerabilities and hardening findings always scored exposure 0, and scenarios could only group weaknesses on one asset (ADR-010 left path questions open).

## Decision
1. **Edges come only from evidence in the run**, built by Agent 5 (`aisw/agents/reachability.py`) from each importer's own hash-checked raw output, whichever policy pack judged the run:
   - **CONFIGURED**: an iptables INPUT rule that accepts traffic from any address or from a range outside private address space gives an internet edge; a rule that admits a private range gives an edge from every run host inside it. An INPUT chain that accepts by default opens every port from everywhere.
   - **OBSERVED**: open ports from an Nmap import whose launcher declared the scan ran from an untrusted network (new import parameter `vantage`, chosen on the review step and stored with the task). Without that statement a scan adds no internet edge.
   - Firewall rules match exactly one run host by asset id, address or name; otherwise nothing is drawn and the gap is a caveat.
2. **Caveats name what is not modelled**: `UPSTREAM_FILTERING_NOT_EVALUATED`, `SCAN_VANTAGE_NOT_STATED`, `SECURITY_GROUP_ATTACHMENTS_UNKNOWN` (AWS rules are read but not tied to instances), unresolved or ambiguous hosts, and unreadable evidence.
3. **Exposure scoring.** A finding's exposure is the stronger of its category's level and its affected assets' internet reachability (OBSERVED gives VERIFIED, CONFIGURED gives CONFIGURED). The supporting edge ids are stored in `RiskFactors.exposure_basis`. Agent 7 rejects (`EXPOSURE_NOT_SUPPORTED`) any exposure above the category level that is not backed by stored internet edges of the right basis to an affected asset. The rubric is unchanged (1.0.0).
4. **Paths.** For every asset with findings, the shortest route from the internet (at most 4 hops, observed hops preferred) becomes a scenario that needs only one finding. Its hops are listed with ports and sources, its confidence is LOW when any hop is configuration-only, and it states that no traffic was sent. Agent 7 rejects a scenario whose hops differ from the stored edges (`PATH_EDGE_NOT_RECORDED`); the contract refuses a path that does not run hop by hop from the internet to the asset.
5. **Storage and display.** Migration 0022 adds append-only `reachability_edges` and `reachability_caveats` (forced RLS). `GET /assessments/{id}/reachability` returns edges, caveats and per-asset exposure. The Analysis tab shows a Reachability table; scenario cards and the report show the route.

## Known limitations
- Rules are read in isolation: a deny earlier in the chain that shadows an accept is not evaluated (the importer flags `ORDER_DEPENDENT_RULES`); NAT, routing and perimeter devices are not modelled.
- AWS security groups are not attached to instances, so cloud reachability is a caveat only.
- The vantage is the launcher's statement, not a measured fact; it is recorded with the run but not independently checked.
- The category-based exposure of rubric 1.0.0 still rates network-exposure findings VERIFIED whatever the vantage; changing that needs a new rubric version and sign-off.
- Validated only on fixtures (loopback); no real estate has been modelled.
