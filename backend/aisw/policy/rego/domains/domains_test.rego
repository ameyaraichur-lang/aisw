package aisw.domains_test

import data.aisw.policy
import rego.v1

run(name, value) := run_with(name, {}, value)

run_with(name, params, value) := result if {
	r := {"rule_id": name, "applies_to": {}, "check": {"op": "rego", "value": {"rule": name, "params": params}}}
	d := policy.decision with input as {"rule": r, "value": value, "attrs": {}}
	result := d.outcome
}

ssh_world := {"direction": "ingress", "action": "allow", "sources": ["0.0.0.0/0"], "ports": [22]}

test_network_admin_ports if {
	run("network.no_admin_ports_from_internet", ssh_world) == "FAIL"
	run("network.no_admin_ports_from_internet", object.union(ssh_world, {"ports": [443]})) == "PASS"
	run("network.no_admin_ports_from_internet", object.union(ssh_world, {"sources": ["10.0.0.0/8"]})) == "PASS"
	run("network.no_admin_ports_from_internet", {"direction": "ingress", "action": "allow", "sources": ["any"], "port_ranges": [[3000, 4000]]}) == "FAIL"
	run("network.no_admin_ports_from_internet", object.union(ssh_world, {"action": "deny"})) == "NOT_APPLICABLE"
	run("network.no_admin_ports_from_internet", object.remove(ssh_world, ["ports"])) == "UNKNOWN"
	run("network.no_admin_ports_from_internet", object.remove(ssh_world, ["sources"])) == "UNKNOWN"
}

test_network_any_any_and_default if {
	run("network.no_any_any_allow", {"direction": "ingress", "action": "allow", "sources": ["*"], "all_ports": true}) == "FAIL"
	run("network.no_any_any_allow", ssh_world) == "PASS"
	run("network.no_admin_ports_from_internet", {"direction": "ingress", "action": "allow", "sources": ["::/0"], "all_ports": true}) == "FAIL"
	run("network.no_any_any_allow", object.union(ssh_world, {"action": "deny"})) == "NOT_APPLICABLE"
	run("network.default_deny", {"default_action": "deny"}) == "PASS"
	run("network.default_deny", {"default_action": "allow"}) == "FAIL"
	run("network.default_deny", {}) == "UNKNOWN"
}

test_storage if {
	run("storage.encrypted_at_rest", {"encryption_at_rest": true}) == "PASS"
	run("storage.encrypted_at_rest", {"encryption_at_rest": "yes"}) == "UNKNOWN" # not a boolean: not judged
	run("storage.versioning_enabled", {"versioning": false}) == "FAIL"
	run("storage.access_logging_enabled", {"access_logging": true}) == "PASS"
	run("storage.access_logging_enabled", {"access_logging": false}) == "FAIL"
	run("storage.not_public", {"public_access": false}) == "PASS"
	run("storage.encrypted_at_rest", {"encryption_at_rest": false}) == "FAIL"
	run("storage.versioning_enabled", {"versioning": true}) == "PASS"
}

test_logging if {
	run("logging.audit_enabled", {"audit_logging": false}) == "FAIL"
	run("logging.audit_enabled", {"audit_logging": true}) == "PASS"
	run("logging.retention_sufficient", {"retention_days": 400}) == "PASS"
	run("logging.retention_sufficient", {"retention_days": 90}) == "FAIL"
	run_with("logging.retention_sufficient", {"min_days": 90}, {"retention_days": 90}) == "PASS"
	run("logging.tls_minimum", {"tls_min_version": "1.0"}) == "FAIL"
	run("logging.tls_minimum", {"tls_min_version": "1.3"}) == "PASS"
	run_with("logging.tls_minimum", {"min_version": "1.3"}, {"tls_min_version": "1.2"}) == "FAIL"
	run("logging.tls_minimum", {"tls_min_version": "SSLv3"}) == "UNKNOWN"
}

test_iam if {
	run("iam.admin_requires_mfa", {"admin": true, "mfa_enabled": false}) == "FAIL"
	run("iam.admin_requires_mfa", {"admin": true, "mfa_enabled": true}) == "PASS"
	run("iam.admin_requires_mfa", {"admin": false}) == "NOT_APPLICABLE"
	run("iam.admin_requires_mfa", {"admin": true}) == "UNKNOWN"
	run("iam.access_keys_rotated", {"access_keys": [{"active": true, "age_days": 200}]}) == "FAIL"
	run("iam.access_keys_rotated", {"access_keys": [{"active": false, "age_days": 200}]}) == "PASS"
	run_with("iam.access_keys_rotated", {"max_age_days": 365}, {"access_keys": [{"active": true, "age_days": 200}]}) == "PASS"
	run("iam.access_keys_rotated", {"access_keys": [{"active": true}]}) == "UNKNOWN"
	run("iam.no_stale_accounts", {"enabled": true, "last_used_days": 400}) == "FAIL"
	run("iam.no_stale_accounts", {"enabled": false, "last_used_days": 400}) == "NOT_APPLICABLE"
	run("iam.no_stale_accounts", {"enabled": true, "last_used_days": 10}) == "PASS"
}

test_lifecycle_uses_the_evidence_date if {
	run("lifecycle.supported", {"eol_date": "2025-10-14", "as_of": "2026-10-16"}) == "FAIL"
	run("lifecycle.supported", {"eol_date": "2028-01-01", "as_of": "2026-10-16"}) == "PASS"
	run("lifecycle.supported", {"eol_date": null, "as_of": "2026-10-16"}) == "UNKNOWN"
	run("lifecycle.supported", {"eol_date": "2028-01-01"}) == "UNKNOWN"
}

test_hardening if {
	run("hardening.ssh_root_login_disabled", {"ssh_permit_root_login": "no"}) == "PASS"
	run("hardening.ssh_root_login_disabled", {"ssh_permit_root_login": "yes"}) == "FAIL"
	run("hardening.ssh_root_login_disabled", {"ssh_permit_root_login": "maybe"}) == "UNKNOWN"
	run("hardening.ssh_password_auth_disabled", {"ssh_password_authentication": true}) == "FAIL"
	run("hardening.host_firewall_enabled", {"firewall_enabled": true}) == "PASS"
	run("hardening.host_firewall_enabled", {"firewall_enabled": false}) == "FAIL"
	run("hardening.ssh_password_auth_disabled", {"ssh_password_authentication": false}) == "PASS"
}

admin_sa := {"kind": "ClusterRoleBinding", "role": "cluster-admin", "subjects": [{"kind": "ServiceAccount", "name": "default"}]}

test_k8s_rbac if {
	run("k8s_rbac.no_cluster_admin_for_service_accounts", admin_sa) == "FAIL"
	run("k8s_rbac.no_cluster_admin_for_service_accounts", object.union(admin_sa, {"subjects": [{"kind": "Group", "name": "ops"}]})) == "PASS"
	run("k8s_rbac.no_cluster_admin_for_service_accounts", object.union(admin_sa, {"role": "view"})) == "NOT_APPLICABLE"
	run("k8s_rbac.no_cluster_admin_for_service_accounts", object.remove(admin_sa, ["subjects"])) == "UNKNOWN"
	run("k8s_rbac.no_anonymous_bindings", object.union(admin_sa, {"subjects": [{"kind": "User", "name": "system:anonymous"}]})) == "FAIL"
	run("k8s_rbac.no_anonymous_bindings", admin_sa) == "PASS"
	run("k8s_rbac.no_wildcard_roles", {"kind": "ClusterRole", "rules": [{"verbs": ["*"], "resources": ["*"]}]}) == "FAIL"
	run("k8s_rbac.no_wildcard_roles", {"kind": "Role", "rules": [{"verbs": ["get"], "resources": ["pods"]}]}) == "PASS"
	run("k8s_rbac.no_wildcard_roles", admin_sa) == "NOT_APPLICABLE"
	run("k8s_rbac.no_cluster_admin_for_service_accounts", {"kind": "ClusterRole", "rules": []}) == "NOT_APPLICABLE"
	run("k8s_rbac.no_anonymous_bindings", {"kind": "Role", "rules": []}) == "NOT_APPLICABLE"
}
