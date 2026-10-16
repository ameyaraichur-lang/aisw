# Software lifecycle. input.value: {"eol_date": "YYYY-MM-DD" | null, "as_of": "YYYY-MM-DD"}.
# as_of is the evidence date, never the clock, so the decision is reproducible.
package aisw.domains.lifecycle

import data.aisw.lib
import rego.v1

dates_known if {
	lib.iso_date(input.value.eol_date)
	lib.iso_date(input.value.as_of)
}

supported := "PASS" if {
	dates_known
	input.value.eol_date > input.value.as_of
}

supported := "FAIL" if {
	dates_known
	input.value.eol_date <= input.value.as_of
}
