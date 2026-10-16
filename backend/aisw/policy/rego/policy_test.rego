package aisw.policy_test

import data.aisw.policy
import rego.v1

rule(op, value) := {"rule_id": "r", "applies_to": {}, "check": {"op": op, "value": value}}

outcome(op, expected, value) := result if {
	d := policy.decision with input as {"rule": rule(op, expected), "value": value, "attrs": {}}
	result := d.outcome
}

test_equals if {
	outcome("equals", "no", "no") == "PASS"
	outcome("equals", "no", "yes") == "FAIL"
	outcome("equals", true, true) == "PASS"
	outcome("equals", true, 1) == "FAIL" # JSON equality: true is not 1
	outcome("equals", 12, 12.0) == "PASS"
}

test_in_and_disjoint if {
	outcome("in", ["a", "b"], "a") == "PASS"
	outcome("in", ["a", "b"], "c") == "FAIL"
	outcome("disjoint", ["telnet"], ["ssh"]) == "PASS"
	outcome("disjoint", ["telnet"], ["ssh", "telnet"]) == "FAIL"
	outcome("disjoint", ["telnet"], "telnet") == "ERROR"
}

test_numeric if {
	outcome("gte", 12, 12) == "PASS"
	outcome("gte", 12, 11) == "FAIL"
	outcome("gte", 12, 14.5) == "PASS"
	outcome("lte", 5, 6) == "FAIL"
	outcome("lte", 5, 4) == "PASS"
	outcome("gte", 12, "fourteen") == "ERROR"
	outcome("gte", 12, true) == "ERROR"
	outcome("lte", 5, [1]) == "ERROR"
}

test_missing_evidence_is_unknown if {
	outcome("equals", "no", null) == "UNKNOWN"
	outcome("gte", 12, null) == "UNKNOWN"
	outcome("rego", {"rule": "storage.not_public"}, null) == "UNKNOWN"
}

test_unknown_op_is_error if {
	outcome("regex", ".*", "x") == "ERROR"
}

test_applicability_needs_proof if {
	r := {"rule_id": "ssh", "applies_to": {"os_family": ["linux"]}, "check": {"op": "equals", "value": "no"}}
	policy.decision == {"applies": true, "outcome": "PASS"} with input as {"rule": r, "value": "no", "attrs": {"os_family": "linux"}}
	policy.decision == {"applies": false} with input as {"rule": r, "value": "no", "attrs": {"os_family": "windows"}}
	policy.decision == {"applies": false} with input as {"rule": r, "value": "no", "attrs": {}}
	policy.applicable == ["ssh"] with input as {"rules": [r], "attrs": {"os_family": "linux"}}
	policy.applicable == [] with input as {"rules": [r], "attrs": {"os_family": "None"}}
}

test_domain_rule_dispatch if {
	outcome("rego", {"rule": "storage.not_public"}, {"public_access": false}) == "PASS"
	outcome("rego", {"rule": "storage.not_public"}, {"public_access": true}) == "FAIL"
	outcome("rego", {"rule": "storage.not_public"}, {}) == "UNKNOWN" # facts missing
	outcome("rego", {"rule": "storage.no_such_rule"}, {"public_access": true}) == "UNKNOWN"
	outcome("rego", {"rule": "no_dots"}, {"public_access": true}) == "UNKNOWN"
}
