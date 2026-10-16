# Object storage. input.value: {"public_access": bool, "encryption_at_rest": bool,
#   "versioning": bool, "access_logging": bool}
package aisw.domains.storage

import rego.v1

not_public := "PASS" if input.value.public_access == false

not_public := "FAIL" if input.value.public_access == true

encrypted_at_rest := "PASS" if input.value.encryption_at_rest == true

encrypted_at_rest := "FAIL" if input.value.encryption_at_rest == false

versioning_enabled := "PASS" if input.value.versioning == true

versioning_enabled := "FAIL" if input.value.versioning == false

access_logging_enabled := "PASS" if input.value.access_logging == true

access_logging_enabled := "FAIL" if input.value.access_logging == false
