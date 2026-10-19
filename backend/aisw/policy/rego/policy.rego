# AISW policy decisions (ADR-003, ADR-031). Same semantics as aisw.policy.engine.PythonRuleEvaluator:
# missing evidence is UNKNOWN (never PASS or FAIL), a check that cannot run is ERROR, and a rule
# applies only when the asset proves every attribute it is conditioned on.
#
# input.attrs values are strings, stringified by the caller exactly as the Python evaluator does.
package aisw.policy

import rego.v1

# Applicability of one rule.
applies(rule, attrs) if {
	every key, allowed in object.get(rule, "applies_to", {}) {
		object.get(attrs, key, "None") in allowed
	}
}

# The ids of the rules in input.rules that apply to input.attrs, in input order.
applicable := [rule.rule_id | some rule in input.rules; applies(rule, input.attrs)]

# One observation: input.rule, input.value, input.attrs.
default decision := {"applies": false}

decision := {"applies": true, "outcome": outcome} if applies(input.rule, input.attrs)

outcome := "UNKNOWN" if is_null(input.value)

outcome := result if {
	not is_null(input.value)
	result := check(input.rule.check.op, input.rule.check.value, input.value)
}

outcome := "UNKNOWN" if {
	not is_null(input.value)
	input.rule.check.op == "rego"
	not defined
}

outcome := "ERROR" if {
	not is_null(input.value)
	input.rule.check.op != "rego"
	not defined
}

defined if check(input.rule.check.op, input.rule.check.value, input.value)

member(value, list) if {
	some item in list
	item == value
}

check("equals", expected, value) := "PASS" if value == expected

check("equals", expected, value) := "FAIL" if value != expected

check("in", expected, value) := "PASS" if member(value, expected)

check("in", expected, value) := "FAIL" if not member(value, expected)

check("disjoint", _, value) := "ERROR" if not is_array(value)

check("disjoint", expected, value) := "FAIL" if {
	is_array(value)
	some item in value
	member(item, expected)
}

check("disjoint", expected, value) := "PASS" if {
	is_array(value)
	every item in value {
		not member(item, expected)
	}
}

check("gte", _, value) := "ERROR" if not is_number(value)

check("gte", expected, value) := "PASS" if {
	is_number(value)
	value >= expected
}

check("gte", expected, value) := "FAIL" if {
	is_number(value)
	value < expected
}

check("lte", _, value) := "ERROR" if not is_number(value)

check("lte", expected, value) := "PASS" if {
	is_number(value)
	value <= expected
}

check("lte", expected, value) := "FAIL" if {
	is_number(value)
	value > expected
}

# A domain rule reads input.value and yields PASS, FAIL or NOT_APPLICABLE; anything it does not
# decide is UNKNOWN (above). Any other result is ERROR.
check("rego", spec, _) := result if {
	parts := split(spec.rule, ".")
	count(parts) == 2
	raw := data.aisw.domains[parts[0]][parts[1]]
	result := valid(raw)
}

valid(raw) := raw if raw in {"PASS", "FAIL", "NOT_APPLICABLE"}

valid(raw) := "ERROR" if not raw in {"PASS", "FAIL", "NOT_APPLICABLE"}
