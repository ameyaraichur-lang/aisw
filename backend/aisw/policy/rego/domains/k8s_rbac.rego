# Kubernetes RBAC. input.value is one binding or role:
#   binding: {"kind": "ClusterRoleBinding"|"RoleBinding", "role": str,
#             "subjects": [{"kind": "User"|"Group"|"ServiceAccount", "name": str}]}
#   role:    {"kind": "ClusterRole"|"Role", "rules": [{"verbs": [str], "resources": [str]}]}
package aisw.domains.k8s_rbac

import rego.v1

binding if input.value.kind in {"ClusterRoleBinding", "RoleBinding"}

role if input.value.kind in {"ClusterRole", "Role"}

subjects_known if {
	is_array(input.value.subjects)
	every s in input.value.subjects {
		is_string(s.kind)
		is_string(s.name)
	}
}

sa_is_cluster_admin if {
	some s in input.value.subjects
	s.kind == "ServiceAccount"
}

no_cluster_admin_for_service_accounts := "NOT_APPLICABLE" if not binding

no_cluster_admin_for_service_accounts := "NOT_APPLICABLE" if {
	binding
	is_string(input.value.role)
	input.value.role != "cluster-admin"
}

no_cluster_admin_for_service_accounts := "FAIL" if {
	binding
	input.value.role == "cluster-admin"
	subjects_known
	sa_is_cluster_admin
}

no_cluster_admin_for_service_accounts := "PASS" if {
	binding
	input.value.role == "cluster-admin"
	subjects_known
	not sa_is_cluster_admin
}

anonymous := {"system:anonymous", "system:unauthenticated"}

binds_anonymous if {
	some s in input.value.subjects
	s.name in anonymous
}

no_anonymous_bindings := "NOT_APPLICABLE" if not binding

no_anonymous_bindings := "FAIL" if {
	binding
	subjects_known
	binds_anonymous
}

no_anonymous_bindings := "PASS" if {
	binding
	subjects_known
	not binds_anonymous
}

rules_known if {
	is_array(input.value.rules)
	every r in input.value.rules {
		is_array(r.verbs)
		is_array(r.resources)
	}
}

wildcard if {
	some r in input.value.rules
	"*" in r.verbs
	"*" in r.resources
}

no_wildcard_roles := "NOT_APPLICABLE" if not role

no_wildcard_roles := "FAIL" if {
	role
	rules_known
	wildcard
}

no_wildcard_roles := "PASS" if {
	role
	rules_known
	not wildcard
}
