# Logging and encryption in transit. input.value: {"audit_logging": bool,
#   "retention_days": int, "tls_min_version": "1.0"|"1.1"|"1.2"|"1.3"}
package aisw.domains.logging

import data.aisw.lib
import rego.v1

audit_enabled := "PASS" if input.value.audit_logging == true

audit_enabled := "FAIL" if input.value.audit_logging == false

# params: min_days (default 365)
retention_sufficient := "PASS" if {
	is_number(input.value.retention_days)
	input.value.retention_days >= lib.param("min_days", 365)
}

retention_sufficient := "FAIL" if {
	is_number(input.value.retention_days)
	input.value.retention_days < lib.param("min_days", 365)
}

tls_rank := {"1.0": 10, "1.1": 11, "1.2": 12, "1.3": 13}

# params: min_version (default "1.2")
tls_minimum := "PASS" if {
	have := tls_rank[input.value.tls_min_version]
	have >= tls_rank[lib.param("min_version", "1.2")]
}

tls_minimum := "FAIL" if {
	have := tls_rank[input.value.tls_min_version]
	have < tls_rank[lib.param("min_version", "1.2")]
}
