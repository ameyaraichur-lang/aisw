# Identities. input.value: {"admin": bool, "mfa_enabled": bool, "enabled": bool,
#   "last_used_days": int, "access_keys": [{"active": bool, "age_days": int}]}
package aisw.domains.iam

import data.aisw.lib
import rego.v1

admin_requires_mfa := "NOT_APPLICABLE" if input.value.admin == false

admin_requires_mfa := "PASS" if {
	input.value.admin == true
	input.value.mfa_enabled == true
}

admin_requires_mfa := "FAIL" if {
	input.value.admin == true
	input.value.mfa_enabled == false
}

keys_known if {
	is_array(input.value.access_keys)
	every k in input.value.access_keys {
		is_boolean(k.active)
		is_number(k.age_days)
	}
}

stale_key if {
	some k in input.value.access_keys
	k.active == true
	k.age_days > lib.param("max_age_days", 90)
}

# params: max_age_days (default 90)
access_keys_rotated := "FAIL" if {
	keys_known
	stale_key
}

access_keys_rotated := "PASS" if {
	keys_known
	not stale_key
}

# params: max_idle_days (default 90). Disabled accounts are not in scope.
no_stale_accounts := "NOT_APPLICABLE" if input.value.enabled == false

no_stale_accounts := "PASS" if {
	input.value.enabled == true
	is_number(input.value.last_used_days)
	input.value.last_used_days <= lib.param("max_idle_days", 90)
}

no_stale_accounts := "FAIL" if {
	input.value.enabled == true
	is_number(input.value.last_used_days)
	input.value.last_used_days > lib.param("max_idle_days", 90)
}
