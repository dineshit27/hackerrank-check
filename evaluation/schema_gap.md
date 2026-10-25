# Unsupported Compliance-State Schema Gap

## Minimal reproducible example

`case_01` authorizes deletion and resolves explicitly to `user_01` through
`user_identities.csv`. At its `audit_at` (`2026-09-03T11:30:00Z`), no
participant-visible evidence observation matches that identity. No activity row
links `user_01` or the request email to an account resource. The public sample
expects `account_001`, but deriving that ID from the user/case number is not an
evidence link.

## Conflicting requirements

* AGENTS.md §6.5: `COMPLETE` requires every relevant copy to have its required
  treatment, which is not established in this example.
* AGENTS.md §6.5: an INCOMPLETE case must report supported policy violations or
  recreation risks.
* AGENTS.md §6.4 permits only four findings: a present record, exposed PII, an
  active flow, or an active restore risk. None means "required state is
  unproven".
* `NOT_APPLICABLE` is reserved for a request that does not authorize deletion.

Thus the status is conservatively `INCOMPLETE`, but no non-fabricated finding,
remediation, or verification array can be produced. This is a schema/data gap,
not a validation exception.
