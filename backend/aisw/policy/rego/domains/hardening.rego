# Host hardening. input.value: {"ssh_permit_root_login": str, "ssh_password_authentication": bool,
#   "firewall_enabled": bool}
package aisw.domains.hardening

import rego.v1

ssh_root_login_disabled := "PASS" if input.value.ssh_permit_root_login in {"no", "prohibit-password", "forced-commands-only"}

ssh_root_login_disabled := "FAIL" if input.value.ssh_permit_root_login in {"yes", "without-password"}

ssh_password_auth_disabled := "PASS" if input.value.ssh_password_authentication == false

ssh_password_auth_disabled := "FAIL" if input.value.ssh_password_authentication == true

host_firewall_enabled := "PASS" if input.value.firewall_enabled == true

host_firewall_enabled := "FAIL" if input.value.firewall_enabled == false
