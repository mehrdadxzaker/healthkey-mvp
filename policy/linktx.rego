package linktx

default allow = false

# Minimal policy:
# - Only allow READ/WRITE/DISCLOSE
# - Consent status must be 'dpv:Given'
# - If valid_until is provided, it must not be expired relative to created_at.

allow {
  input.action == "READ" or input.action == "WRITE" or input.action == "DISCLOSE"
  input.consent_snapshot.status == "dpv:Given"
  not expired
}

expired {
  input.consent_snapshot.valid_until != null
  time.parse_rfc3339_ns(input.created_at, t1)
  time.parse_rfc3339_ns(input.consent_snapshot.valid_until, t2)
  t2 < t1
}
