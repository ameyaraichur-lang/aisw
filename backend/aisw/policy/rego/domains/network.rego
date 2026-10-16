# Network exposure. input.value is one firewall or security-group rule:
#   {"direction": "ingress"|"egress", "action": "allow"|"deny", "sources": [cidr],
#    "ports": [int], "port_ranges": [[from, to]], "all_ports": bool}
# or a policy: {"default_action": "allow"|"deny"}.
package aisw.domains.network

import data.aisw.lib
import rego.v1

admin_ports := {22, 23, 3389, 5985, 5986}

inbound_allow if {
	input.value.direction == "ingress"
	input.value.action == "allow"
}

from_anyone if {
	some s in input.value.sources
	s in lib.any_source
}

# Facts are complete enough to judge exposure.
judged if {
	is_array(input.value.sources)
	ports_known
}

ports_known if input.value.all_ports == true

ports_known if is_array(input.value.ports)

ports_known if is_array(input.value.port_ranges)

reaches(_) if input.value.all_ports == true

reaches(port) if port in input.value.ports

reaches(port) if {
	some r in input.value.port_ranges
	r[0] <= port
	port <= r[1]
}

exposes_admin if {
	some port in admin_ports
	reaches(port)
}

no_admin_ports_from_internet := "NOT_APPLICABLE" if {
	is_string(input.value.direction)
	is_string(input.value.action)
	not inbound_allow
}

no_admin_ports_from_internet := "FAIL" if {
	inbound_allow
	judged
	from_anyone
	exposes_admin
}

no_admin_ports_from_internet := "PASS" if {
	inbound_allow
	judged
	not admin_exposed_to_anyone
}

admin_exposed_to_anyone if {
	from_anyone
	exposes_admin
}

no_any_any_allow := "NOT_APPLICABLE" if {
	is_string(input.value.action)
	input.value.action != "allow"
}

no_any_any_allow := "FAIL" if {
	inbound_allow
	judged
	from_anyone
	input.value.all_ports == true
}

no_any_any_allow := "PASS" if {
	inbound_allow
	judged
	not any_any
}

any_any if {
	from_anyone
	input.value.all_ports == true
}

default_deny := "PASS" if input.value.default_action == "deny"

default_deny := "FAIL" if input.value.default_action == "allow"
