# Helpers shared by the domain rules.
package aisw.lib

import rego.v1

# A pack-supplied parameter of the current rule, or the default.
param(name, default_value) := object.get(object.get(input.rule.check.value, "params", {}), name, default_value)

# Addresses that mean "anyone".
any_source := {"0.0.0.0/0", "::/0", "*", "any", "internet"}

iso_date(s) if regex.match(`^\d{4}-\d{2}-\d{2}$`, s)
