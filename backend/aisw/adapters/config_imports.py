"""Configuration exports that feed the Rego pack ``config-baseline`` (ADR-031, ADR-034).

Each record becomes one resource (``resource_type`` drives which rules apply) whose facts are the
input documents the domain rules read. An adapter emits an observation only for the rules its
export can judge: a fact it cannot see is left out, so the control is UNKNOWN, never PASS.

* firewall_import: AWS ``describe-security-groups`` JSON (ingress) and ``iptables-save`` (INPUT)
* kubescape_import: Kubernetes RBAC objects from a kubescape JSON report or a ``kubectl`` List
* directory_import: Active Directory user CSV (Get-ADUser | Export-Csv) and LDIF (ldifde, ldapsearch)
* aws_iam_import: the AWS IAM credential report CSV

Formats follow the documented structures but were written against synthetic fixtures; real-tool
compatibility per version is UNVERIFIED (see docs/implementation/status.md).
"""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import ipaddress
import re
import shlex
from datetime import UTC, datetime, timedelta
from typing import Any

from aisw.adapters.imports_base import (
    ImportAdapter,
    ImportParams,
    ImportParseError,
    Parsed,
    cap,
    clean,
    parse_json,
)
from aisw.adapters.normalized import NormalizedAsset, NormalizedBatch, NormalizedObservation
from aisw.contracts.enums import ProfileClass
from aisw.gateway.registry import AdapterJob, AdapterOutput

MAX_LIST = 200


def _id(prefix: str, *parts: str) -> str:
    return f"{prefix}-" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:14]


def _resource(aid: str, name: str, resource_type: str, native: dict[str, str]) -> NormalizedAsset:
    return NormalizedAsset(
        aid, name[:253], {"asset_class": resource_type, "resource_type": resource_type},
        "SCANNED", None, asset_type=resource_type, native_ids=native,
    )  # fmt: skip


def _emit(
    batch: NormalizedBatch, run_id: str, task_id: str, aid: str, rule: str, value: Any
) -> None:
    oid = hashlib.sha256(f"{run_id}|{task_id}|{aid}|{rule}".encode()).hexdigest()[:24]
    batch.observations.append(NormalizedObservation(f"o-{oid}", aid, rule, value))


def _csv(text: str, required: set[str]) -> list[dict[str, str]]:
    try:
        csv.field_size_limit(100_000)
        reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
        if not reader.fieldnames or not required <= set(reader.fieldnames):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        return cap([dict(r) for r in reader])
    except csv.Error as exc:
        raise ImportParseError("MALFORMED_CSV") from exc


def _when(value: Any) -> datetime | None:
    s = clean(value, 40)
    if not s or s.lower() in {"n/a", "no_information", "not_supported", "never"}:
        return None
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%Y%m%d%H%M%S.0Z"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=UTC)
        except ValueError:
            pass
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def _days(now: datetime, then: datetime | None) -> int | None:
    return None if then is None else max(0, (now - then).days)


# ================================================================ firewall rules
ANY = "0.0.0.0/0"


class FirewallImportAdapter(ImportAdapter):
    adapter_id = "firewall_import"
    tool = "aisw-firewall-import"
    domains = frozenset({"network"})
    profiles = {"FIREWALL_CONFIG_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"cloud_account", "host"})
    import_kinds = frozenset({"aws_security_groups_json", "iptables_save"})
    formats = (
        "AWS EC2 describe-security-groups JSON {SecurityGroups: [{GroupId, OwnerId, IpPermissions}]} (target: cloud_account)",
        "iptables-save / ip6tables-save text, filter table, INPUT chain (target: host)",
    )  # noqa: E501
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        if text.lstrip().startswith("{"):
            if job.target_kind != "cloud_account":
                raise ImportParseError("TARGET_KIND_MISMATCH")
            return self._security_groups(parse_json(text), job)
        if job.target_kind != "host":
            raise ImportParseError("TARGET_KIND_MISMATCH")
        return self._iptables(text, job)

    # -------------------------------------------------------------- AWS security groups
    def _security_groups(self, data: Any, job: AdapterJob) -> Parsed:
        groups = data.get("SecurityGroups") if isinstance(data, dict) else None
        if not isinstance(groups, list) or not all(isinstance(g, dict) for g in groups):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        rules: list[dict[str, Any]] = []
        dropped = 0
        for g in cap(groups):
            if clean(g.get("OwnerId"), 20) != job.target_selector:
                dropped += 1  # another account's group: never ingested
                continue
            gid = clean(g.get("GroupId"), 40)
            for n, p in enumerate(g.get("IpPermissions") or []):
                if not isinstance(p, dict):
                    continue
                sources = [clean(r.get("CidrIp"), 50) for r in p.get("IpRanges") or []]
                sources += [clean(r.get("CidrIpv6"), 50) for r in p.get("Ipv6Ranges") or []]
                sources += [
                    f"sg:{clean(r.get('GroupId'), 40)}" for r in p.get("UserIdGroupPairs") or []
                ]
                sources += [
                    f"pl:{clean(r.get('PrefixListId'), 40)}" for r in p.get("PrefixListIds") or []
                ]
                proto = clean(p.get("IpProtocol"), 10).lower()
                fact: dict[str, Any] = {"direction": "ingress", "action": "allow",
                                        "sources": sorted(set(sources))[:MAX_LIST], "protocol": proto}  # fmt: skip
                lo, hi = p.get("FromPort"), p.get("ToPort")
                if proto == "-1":
                    fact["all_ports"] = True
                elif proto in {"icmp", "icmpv6", "1", "58"}:
                    fact["port_ranges"] = []  # ICMP reaches no TCP/UDP port
                elif isinstance(lo, int) and isinstance(hi, int):
                    fact["all_ports"] = lo <= 0 and hi >= 65535
                    fact["port_ranges"] = [[lo, hi]]
                rules.append({"id": _id("sgr", job.target_selector, gid, str(n)), "group": gid,
                              "name": f"{clean(g.get('GroupName'), 120) or gid} ingress #{n + 1}",
                              "vpc": clean(g.get("VpcId"), 40), "fact": fact})  # fmt: skip
        warnings = [f"OUT_OF_SCOPE_RECORDS_DROPPED:{dropped}"] if dropped else []
        raw = {"format": "aws_security_groups", "account": job.target_selector,
               "dropped_out_of_scope": dropped, "rules": rules, "policies": []}  # fmt: skip
        return Parsed(raw, tool_version="aws-ec2-describe-security-groups", warnings=warnings)

    # -------------------------------------------------------------- iptables-save
    def _iptables(self, text: str, job: AdapterJob) -> Parsed:
        lines = [ln.strip() for ln in text.splitlines()]
        if not any(ln == "*filter" for ln in lines):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        table, policy = "", None
        rules: list[dict[str, Any]] = []
        unmodelled: list[str] = []
        seen_deny = order_dependent = 0
        catch_all_deny = False
        for n, ln in enumerate(cap(lines), 1):
            if ln.startswith("*"):
                table = ln[1:]
            elif table == "filter" and ln.startswith(":INPUT "):
                policy = {"ACCEPT": "allow", "DROP": "deny"}.get(ln.split()[1])
            elif table == "filter" and ln.startswith("-A INPUT "):
                try:
                    r = _iptables_rule(shlex.split(ln)[2:])
                except ValueError as exc:
                    unmodelled.append(f"line {n}: {exc}"[:80])
                    continue
                if r is None:
                    continue  # loopback, return traffic or a LOG target: not an exposure
                catch_all_deny = r["action"] == "deny" and r.get("catch_all", False)
                if r["action"] == "deny":
                    seen_deny += 1
                    continue
                order_dependent += 1 if seen_deny else 0
                r.pop("catch_all", None)
                rules.append({"id": _id("fwr", job.target_selector, "INPUT", str(n)),
                              "name": f"{job.target_selector} INPUT line {n}", "fact": r})  # fmt: skip
        warnings = [f"UNMODELLED_RULE:{u}" for u in unmodelled[:20]]
        if order_dependent:
            warnings.append(f"ORDER_DEPENDENT_RULES:{order_dependent}")
        policies = []
        if policy is not None:
            effective = "deny" if catch_all_deny else policy
            policies.append({"id": _id("fwp", job.target_selector, "INPUT"),
                             "name": f"{job.target_selector} INPUT policy",
                             "fact": {"default_action": effective, "chain_policy": policy,
                                      "final_rule_denies_all": catch_all_deny}})  # fmt: skip
        else:
            warnings.append("CHAIN_POLICY_MISSING:INPUT")
        raw = {"format": "iptables_save", "host": job.target_selector, "rules": rules,
               "policies": policies, "unmodelled_rules": len(unmodelled),
               "order_dependent_rules": order_dependent}  # fmt: skip
        return Parsed(raw, tool_version="iptables-save",
                      status="PARTIAL" if unmodelled else "SUCCEEDED", warnings=warnings)  # fmt: skip

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        rtype = (
            "security_group_rule"
            if output.raw.get("format") == "aws_security_groups"
            else "firewall_rule"
        )
        scope = (
            {"account": output.raw["account"]}
            if "account" in output.raw
            else {"host": output.raw.get("host", "")}
        )
        for r in output.raw.get("rules", []):
            b.assets.append(_resource(r["id"], r["name"], rtype, {**scope, "rule": r["name"]}))
            for rule in ("network.no_admin_ports_from_internet", "network.no_any_any_allow"):
                _emit(b, run_id, task_id, r["id"], rule, r["fact"])
        for p in output.raw.get("policies", []):
            b.assets.append(
                _resource(p["id"], p["name"], "firewall_policy", {**scope, "chain": "INPUT"})
            )
            _emit(b, run_id, task_id, p["id"], "network.default_deny", p["fact"])
        return b


def _ports(spec: str) -> list[list[int]]:
    out: list[list[int]] = []
    for part in spec.split(","):
        lo, _, hi = part.partition(":")
        if not lo.isdigit() or (hi and not hi.isdigit()):
            raise ValueError(f"port {part}")
        out.append([int(lo), int(hi or lo)])
    return out


def _iptables_rule(tokens: list[str]) -> dict[str, Any] | None:
    """One INPUT rule as a network fact, None when it exposes nothing; ValueError if unmodelled."""
    proto, sources, ranges, target = "all", [ANY], None, ""
    catch_all, it = True, iter(tokens)
    for t in it:
        if t == "!":
            raise ValueError("negated match")
        if t in {"-p", "--protocol"}:
            proto, catch_all = next(it, "all").lower(), False
        elif t in {"-s", "--source"}:
            sources, catch_all = [str(ipaddress.ip_network(next(it, ""), strict=False))], False
        elif t in {"-i", "--in-interface"}:
            if next(it, "") == "lo":
                return None
            catch_all = False
        elif t in {"--dport", "--destination-port", "--dports", "--destination-ports"}:
            ranges, catch_all = _ports(next(it, "")), False
        elif t in {"--state", "--ctstate"}:
            if "NEW" not in next(it, "").split(","):
                return None  # return traffic only
            catch_all = False
        elif t in {"-j", "--jump"}:
            target = next(it, "")
        elif t in {"-m", "--match", "--comment", "-d", "--destination"}:
            nxt = next(it, "")
            if t in {"-d", "--destination"}:
                catch_all = False
            elif t in {"-m", "--match"} and nxt not in {
                "tcp",
                "udp",
                "multiport",
                "state",
                "conntrack",
                "comment",
            }:
                raise ValueError(f"match {nxt}"[:40])
        else:
            raise ValueError(f"option {t}"[:40])
    if target == "LOG":
        return None
    if target in {"DROP", "REJECT"}:
        return {"action": "deny", "catch_all": catch_all}
    if target != "ACCEPT":
        raise ValueError(f"target {target or 'none'}"[:40])
    fact: dict[str, Any] = {"direction": "ingress", "action": "allow", "sources": sources,
                            "protocol": proto}  # fmt: skip
    if proto in {"icmp", "icmpv6", "ipv6-icmp"}:
        fact["port_ranges"] = []
    elif ranges is None:
        fact["all_ports"] = True
    else:
        fact["port_ranges"] = ranges
    return fact


# ================================================================ Kubernetes RBAC
BINDINGS = {"ClusterRoleBinding", "RoleBinding"}
ROLES = {"ClusterRole", "Role"}


class KubescapeImportAdapter(ImportAdapter):
    adapter_id = "kubescape_import"
    tool = "aisw-kubescape-import"
    domains = frozenset({"kubernetes"})
    profiles = {"KUBESCAPE_RESULTS_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"asset_group"})
    import_kinds = frozenset({"kubescape_json", "k8s_rbac_json"})
    formats = (
        "kubescape JSON report {clusterName, resources: [{resourceID, object}], results} (selector: cluster name)",
        "kubectl get clusterroles,clusterrolebindings,roles,rolebindings -A -o json (a v1 List)",
    )  # noqa: E501
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        data = parse_json(text)
        if not isinstance(data, dict):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        if isinstance(data.get("resources"), list) and (
            "results" in data or "summaryDetails" in data
        ):
            fmt, cluster = "kubescape", clean(data.get("clusterName"), 120)
            if cluster and cluster != job.target_selector:
                raise ImportParseError("CLUSTER_MISMATCH")
            objects = [r.get("object") for r in data["resources"] if isinstance(r, dict)]
            version = clean((data.get("metadata") or {}).get("kubescapeVersion")
                            or data.get("kubescapeVersion"), 20) or "unknown"  # fmt: skip
        elif data.get("kind") == "List" and isinstance(data.get("items"), list):
            fmt, objects, version = "kubectl_list", data["items"], "kubectl"
        else:
            raise ImportParseError("UNSUPPORTED_FORMAT")
        items: list[dict[str, Any]] = []
        defaults = 0
        for o in cap([o for o in objects if isinstance(o, dict)]):
            kind = clean(o.get("kind"), 40)
            if kind not in BINDINGS | ROLES:
                continue
            meta = o.get("metadata") or {}
            if (meta.get("labels") or {}).get("kubernetes.io/bootstrapping") == "rbac-defaults":
                defaults += 1  # platform defaults are not a configuration choice
                continue
            ns, name = clean(meta.get("namespace"), 63), clean(meta.get("name"), 253)
            ref = f"{kind}/{ns + '/' if ns else ''}{name}"
            if kind in BINDINGS:
                subjects = [{"kind": clean(s.get("kind"), 40), "name": clean(s.get("name"), 253),
                             **({"namespace": clean(s["namespace"], 63)} if s.get("namespace") else {})}
                            for s in (o.get("subjects") or []) if isinstance(s, dict)]  # fmt: skip
                fact = {"kind": kind, "role": clean((o.get("roleRef") or {}).get("name"), 253),
                        "subjects": subjects[:MAX_LIST]}  # fmt: skip
            else:
                fact = {"kind": kind, "rules": [
                    {"verbs": [clean(v, 40) for v in r.get("verbs") or []],
                     "resources": [clean(x, 80) for x in r.get("resources") or []]}
                    for r in (o.get("rules") or []) if isinstance(r, dict)][:MAX_LIST]}  # fmt: skip
            items.append({"id": _id("k8s", job.target_selector, ref), "ref": ref, "fact": fact})
        warnings = [f"PLATFORM_DEFAULTS_SKIPPED:{defaults}"] if defaults else []
        raw = {"format": fmt, "cluster": job.target_selector, "objects": items,
               "platform_defaults_skipped": defaults}  # fmt: skip
        return Parsed(raw, tool_version=f"{fmt}-{version}", warnings=warnings)

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        for o in output.raw.get("objects", []):
            binding = o["fact"]["kind"] in BINDINGS
            b.assets.append(_resource(o["id"], o["ref"], "k8s_binding" if binding else "k8s_role",
                                      {"cluster": output.raw["cluster"], "object": o["ref"]}))  # fmt: skip
            rules = (("k8s_rbac.no_cluster_admin_for_service_accounts", "k8s_rbac.no_anonymous_bindings")
                     if binding else ("k8s_rbac.no_wildcard_roles",))  # fmt: skip
            for rule in rules:
                _emit(b, run_id, task_id, o["id"], rule, o["fact"])
        return b


# ================================================================ directory (AD / LDAP)
PRIVILEGED_GROUPS = {"domain admins", "enterprise admins", "schema admins", "administrators",
                     "account operators", "backup operators", "server operators"}  # fmt: skip
UAC_DISABLED = 0x2
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _cn(dn: str) -> str:
    first = dn.split(",", 1)[0].strip()
    return first[3:].lower() if first.lower().startswith("cn=") else ""


def _dn_domain(dn: str) -> str:
    return ".".join(
        p.strip()[3:].lower() for p in dn.split(",") if p.strip().lower().startswith("dc=")
    )


def _filetime(value: str) -> datetime | None:
    if not value.isdigit() or int(value) == 0:
        return None
    return FILETIME_EPOCH + timedelta(microseconds=int(value) // 10)


def _ldif(text: str) -> list[dict[str, list[str]]]:
    """LDIF content records: folded lines joined, ``::`` values base64-decoded, comments skipped."""
    unfolded: list[str] = []
    for ln in text.lstrip("\ufeff").splitlines():
        if ln.startswith(" ") and unfolded:
            unfolded[-1] += ln[1:]
        elif not ln.startswith("#"):
            unfolded.append(ln)
    entries: list[dict[str, list[str]]] = []
    cur: dict[str, list[str]] = {}
    for ln in [*unfolded, ""]:
        if not ln.strip():
            if cur:
                entries.append(cur)
                cur = {}
            continue
        key, sep, value = ln.partition(":")
        if not sep:
            raise ImportParseError("MALFORMED_LDIF")
        if value.startswith(":"):
            try:
                value = base64.b64decode(value[1:].strip(), validate=True).decode(
                    "utf-8", "replace"
                )
            except (binascii.Error, ValueError) as exc:
                raise ImportParseError("MALFORMED_LDIF") from exc
        elif value.startswith("<"):
            raise ImportParseError("LDIF_URL_VALUE_REFUSED")  # never dereference a file or URL
        cur.setdefault(key.strip().lower(), []).append(value.strip())
        if len(entries) > 20_000:
            raise ImportParseError("TOO_MANY_RECORDS")
    return entries


class DirectoryImportAdapter(ImportAdapter):
    adapter_id = "directory_import"
    tool = "aisw-directory-import"
    domains = frozenset({"identity"})
    profiles = {"DIRECTORY_EXPORT_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"asset_group"})
    import_kinds = frozenset({"ad_users_csv", "ldif"})
    formats = (
        "Get-ADUser | Export-Csv with SamAccountName, Enabled, LastLogonDate, whenCreated, MemberOf (';'-joined DNs), adminCount, DistinguishedName",
        "LDIF of user entries (ldifde / ldapsearch): sAMAccountName or uid, userAccountControl, lastLogonTimestamp, whenCreated, memberOf, adminCount, pwdAccountLockedTime",
    )  # noqa: E501
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        now = self._clock()
        stripped = text.lstrip("\ufeff").lstrip()
        if re.search(r"(?im)^dn:", stripped):
            fmt, users = "ldif", [u for e in _ldif(stripped) if (u := _ldif_user(e))]
        else:
            if stripped.startswith("#TYPE"):  # Windows PowerShell 5 Export-Csv type header
                stripped = stripped.split("\n", 1)[-1]
            fmt, users = (
                "ad_csv",
                [_csv_user(r) for r in _csv(stripped, {"SamAccountName", "Enabled"})],
            )
        domain = job.target_selector.lower() if "." in job.target_selector else ""
        out: list[dict[str, Any]] = []
        dropped = 0
        for u in users:
            if domain and u["dn"] and _dn_domain(u["dn"]) not in {domain, ""}:
                dropped += 1
                continue
            last = u["last_logon"] or u["created"]
            fact: dict[str, Any] = {"admin": u["admin"], "enabled": u["enabled"]}
            if (days := _days(now, last)) is not None:
                fact["last_used_days"] = days
            out.append({"id": _id("id", job.target_selector, u["name"].lower()), "name": u["name"],
                        "fact": fact, "never_logged_on": u["last_logon"] is None})  # fmt: skip
        warnings = [f"OUT_OF_SCOPE_RECORDS_DROPPED:{dropped}"] if dropped else []
        if any(u["fact"]["admin"] for u in out):
            warnings.append("MFA_STATE_NOT_IN_DIRECTORY_EXPORT")
        raw = {"format": fmt, "directory": job.target_selector, "as_of": now.date().isoformat(),
               "dropped_out_of_scope": dropped, "identities": out}  # fmt: skip
        return Parsed(raw, tool_version=f"directory-{fmt}", warnings=warnings)

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        for u in output.raw.get("identities", []):
            b.assets.append(_resource(u["id"], u["name"], "identity",
                                      {"directory": output.raw["directory"], "account": u["name"]}))  # fmt: skip
            _emit(b, run_id, task_id, u["id"], "iam.admin_requires_mfa", u["fact"])
            _emit(b, run_id, task_id, u["id"], "iam.no_stale_accounts", u["fact"])
        return b


def _admin(groups: list[str], admin_count: str) -> bool:
    return admin_count.strip() == "1" or any(_cn(g) in PRIVILEGED_GROUPS for g in groups)


def _csv_user(r: dict[str, str]) -> dict[str, Any]:
    groups = [g for g in (r.get("MemberOf") or "").split(";") if g.strip()]
    return {"name": clean(r.get("SamAccountName"), 64), "dn": clean(r.get("DistinguishedName"), 500),
            "enabled": clean(r.get("Enabled"), 10).lower() == "true",
            "admin": _admin(groups, r.get("adminCount") or ""),
            "last_logon": _when(r.get("LastLogonDate")), "created": _when(r.get("whenCreated") or r.get("Created"))}  # fmt: skip


def _ldif_user(e: dict[str, list[str]]) -> dict[str, Any] | None:
    classes = {c.lower() for c in e.get("objectclass", [])}
    if "computer" in classes or not classes & {"user", "person", "inetorgperson", "posixaccount"}:
        return None
    name = clean((e.get("samaccountname") or e.get("uid") or [""])[0], 64)
    if not name:
        return None
    uac = (e.get("useraccountcontrol") or ["0"])[0]
    enabled = not (uac.isdigit() and int(uac) & UAC_DISABLED) and "pwdaccountlockedtime" not in e
    return {"name": name, "dn": clean((e.get("dn") or [""])[0], 500), "enabled": enabled,
            "admin": _admin(e.get("memberof", []), (e.get("admincount") or [""])[0]),
            "last_logon": _filetime((e.get("lastlogontimestamp") or [""])[0]),
            "created": _when((e.get("whencreated") or [""])[0])}  # fmt: skip


# ================================================================ AWS IAM credential report
REPORT_COLUMNS = {"user", "arn", "user_creation_time", "password_enabled", "password_last_used",
                  "mfa_active", "access_key_1_active", "access_key_1_last_rotated",
                  "access_key_2_active", "access_key_2_last_rotated"}  # fmt: skip
_ARN = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):")


class AwsIamImportAdapter(ImportAdapter):
    adapter_id = "aws_iam_import"
    tool = "aisw-aws-iam-import"
    domains = frozenset({"identity"})
    profiles = {"AWS_CREDENTIAL_REPORT_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"cloud_account"})
    import_kinds = frozenset({"aws_credential_report_csv"})
    formats = ("AWS IAM credential report CSV (aws iam get-credential-report, decoded)",)
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        now = self._clock()
        out: list[dict[str, Any]] = []
        dropped = 0
        for r in _csv(text, REPORT_COLUMNS):
            m = _ARN.match(clean(r.get("arn"), 300))
            if m is None or m.group(1) != job.target_selector:
                dropped += 1
                continue
            name, root = clean(r.get("user"), 64), clean(r.get("user"), 64) == "<root_account>"
            keys = [{"active": clean(r.get(f"access_key_{n}_active"), 10) == "true",
                     "age_days": _days(now, _when(r.get(f"access_key_{n}_last_rotated")))}
                    for n in (1, 2)]  # fmt: skip
            keys = [k for k in keys if k["age_days"] is not None]
            used = [d for d in (_when(r.get("password_last_used")), _when(r.get("access_key_1_last_used_date")),
                                _when(r.get("access_key_2_last_used_date"))) if d]  # fmt: skip
            enabled = (
                root
                or clean(r.get("password_enabled"), 10) == "true"
                or any(k["active"] for k in keys)
            )
            fact: dict[str, Any] = {"enabled": enabled, "mfa_enabled": clean(r.get("mfa_active"), 10) == "true",
                                    "access_keys": keys}  # fmt: skip
            if root:
                fact["admin"] = True
            if (
                days := _days(now, max(used) if used else _when(r.get("user_creation_time")))
            ) is not None:
                fact["last_used_days"] = days
            out.append(
                {
                    "id": _id("iam", job.target_selector, name),
                    "name": name,
                    "root": root,
                    "fact": fact,
                }
            )
        warnings = [f"OUT_OF_SCOPE_RECORDS_DROPPED:{dropped}"] if dropped else []
        if any(not u["root"] for u in out):
            warnings.append("ADMIN_MEMBERSHIP_NOT_IN_CREDENTIAL_REPORT")
        raw = {"account": job.target_selector, "as_of": now.date().isoformat(),
               "dropped_out_of_scope": dropped, "identities": out}  # fmt: skip
        return Parsed(raw, tool_version="aws-iam-credential-report", warnings=warnings)

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        for u in output.raw.get("identities", []):
            b.assets.append(_resource(u["id"], u["name"], "identity",
                                      {"account": output.raw["account"], "user": u["name"]}))  # fmt: skip
            if u["root"]:  # the report says nothing about other users' admin rights
                _emit(b, run_id, task_id, u["id"], "iam.admin_requires_mfa", u["fact"])
            _emit(b, run_id, task_id, u["id"], "iam.access_keys_rotated", u["fact"])
            _emit(b, run_id, task_id, u["id"], "iam.no_stale_accounts", u["fact"])
        return b
