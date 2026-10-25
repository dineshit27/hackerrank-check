# Public Sample Mismatch Analysis

## Scope and method

This report compares a fresh run of `code/main.py` on all 32 public requests
with `dataset/sample_output.csv`. The comparison parsed each `steps_json` array
and compared `step_no`, `phase`, `system_id`, `resource_id`, `operation`,
`state`, and `evidence_id` in array order. Only participant-facing files under
`dataset/` were inspected.

Baseline: **32/32 deletion statuses** and **16/32 exact step arrays**. The 16
non-exact arrays are listed below. `Same` means every field in that step is
identical; omitted steps are absent from the generated array.

## Applicable policy

| Category | Rule | Required treatment |
| --- | --- | --- |
| User profile | rule_01 | DELETE |
| Analytics profile | rule_07 | ANONYMIZE when attributable |
| Security audit log | rule_12 | RETAIN |
| Backup archive | rule_14 | RETAIN; block restore access |
| Account tombstone | rule_15 | REDACT direct identifiers while retaining stable reference |

## Case-by-case comparison

| Case | Reference vs generated field differences | Participant-visible support and cutoff | Root cause | Justified action |
| --- | --- | --- | --- | --- |
| case_03 | Count **3 vs 2**. Steps 1-2 are Same. Reference-only step 3: `VERIFICATION / analytics_platform / analytics_9406 / VERIFY_RECORD_ANONYMIZED / ANONYMIZED / evidence_94`. | `evidence_94` contains `analytics_9406` with every identifier null; it contains no link to `user_43`. `system_activity.csv` records an `ANONYMIZE_RECORD` for it, also without subject identity. Cutoff: 2026-09-26T11:00:00Z. | Anonymous-resource association not established. | No production change. |
| case_04 | Count **2 vs 1**. Step 1 Same. Reference-only step 2: `VERIFICATION / analytics_platform / analytics_901 / VERIFY_RECORD_ANONYMIZED / ANONYMIZED / evidence_56`. | `evidence_56` has `analytics_901` with null user, email, phone, and hash. The matching activity is also identity-free. Cutoff: 2026-09-07T10:20:00Z. Rule_07 applies only after attribution is established. | Anonymous-resource association not established. | No production change. |
| case_17 | Count **5 vs 8**. Generated adds finding/remediation/verification for `identity_service/tombstone_17` (`REPORT_EXPOSED_PII`, `REDACT_RECORD`, `VERIFY_RECORD_REDACTED`, `evidence_42`) and chooses `account_6523`; reference instead starts with the matching `backup_3245` restore-risk flow and verifies `account_4092`. All reference steps after the extra finding are shifted but otherwise match by type. | `evidence_42` is dated 2026-03-10, before the 2026-08-19 request, so it cannot prove state at the 2026-09-15 audit. `evidence_01` after the request directly links the subject to `account_4092`, `audit_record_1797`, and active `backup_3245`. | **Algorithm bug:** pre-request state is treated as current and a global account map overrides a later subject-linked observation. | Filter stale state observations that predate the deletion request and choose the most recent subject-linked account observation within the request-to-audit window. Add regression coverage. |
| case_18 | Count **14 vs 13**. Steps 1-8 and 10 Same. Step 9 account ID is `account_5521` vs `account_050`; reference step 11 security verification `audit_record_6645` is missing, shifting generated steps 11-13; reference step 14 integration verification is missing after the shift. | `evidence_94` directly links the subject to `search_4013`, `analytics_037`, `support_5569`, and `data_flow_4890`, which the generator emits. It contains no `account_5521` or `audit_record_6645`; the former appears only as an unlinked activity and the latter is absent from participant-facing evidence. | Account/security association not established. | No production change. |
| case_20 | Count **8 vs 7**. Steps 1-4 and 6 Same. Step 5 account ID is `account_5037` vs `account_048`; reference security verification `audit_record_5569` is missing, shifting the final flow verification. | `evidence_94` directly supports `search_4262` and `data_flow_1770`; it has no account or security record for `user_48`. `account_5037` is an identity-free activity only; `audit_record_5569` is not participant-visible. | Account/security association not established. | No production change. |
| case_21 | Count **3 vs 2**. Step 1 account ID is `account_6440` vs fallback `account_021`; step 2 Same; reference-only step 3 is anonymized `analytics_5335`. | `evidence_92` has `account_6440` with `profile: null` and `analytics_5335` with all identifiers null; both lack subject binding. `audit_record_3737` is explicitly linked to `user_21` and is correctly emitted. | Anonymous account/analytics association not established. | No production change. |
| case_22 | Count **8 vs 8**. Every field is Same except verification step 5 resource ID: `account_4990` vs fallback `account_051`. | `evidence_05` directly supports search, analytics, and security steps, but no account record for `user_51`. `account_4990` is only an identity-free activity. | Account association not established. | No production change. |
| case_23 | Count **8 vs 8**. Every field is Same except verification step 5 resource ID: `account_410` vs fallback `account_023`. | `evidence_92` directly supports export/search; `audit_record_4128` is linked by other visible evidence. `account_410` is a null-profile export/activity with no subject binding. | Account association not established. | No production change. |
| case_25 | Count **3 vs 2**. Step 1 account ID is `account_3136` vs fallback `account_025`; step 2 Same; reference-only step 3 is anonymized `analytics_1895`. | In `evidence_92`, `account_3136` has a null profile and `analytics_1895` has all identifiers null. `audit_record_451` is explicitly linked and emitted. | Anonymous account/analytics association not established. | No production change. |
| case_26 | Count **6 vs 5**. Steps 1-3 Same; reference-only analytics verification `analytics_4566` shifts generated flow and backup verification positions. | `evidence_92` directly links support, integration, backup, and security records to `user_26`; `analytics_4566` is all-null. `account_5684` is resolved from an explicit later snapshot. | Anonymous analytics association not established. | No production change. |
| case_27 | Count **6 vs 5**. Steps 1-3 Same; reference-only analytics verification `analytics_4574` shifts generated flow and backup verification positions. | `evidence_92` links integration, backup, support, security, and `account_3866` to `user_27`; `analytics_4574` is all-null. | Anonymous analytics association not established. | No production change. |
| case_28 | Count **6 vs 5**. Step 1 account ID is `account_5482` vs fallback `account_028`; steps 2-3 Same; reference-only analytics `analytics_6077` shifts the final two steps. | `evidence_92` links support/flow/backup/security to `user_28`; `account_5482` is null-profile and `analytics_6077` is all-null. | Anonymous account/analytics association not established. | No production change. |
| case_29 | Count **14 vs 14**. Steps 1-8 and 10-14 Same. Step 9 account ID is `account_7012` vs fallback `account_029`. | `evidence_92` directly links all finding resources and `audit_record_3954`, but contains no linked account. `account_7012` appears only in identity-free activity. | Account association not established. | No production change. |
| case_30 | Count **14 vs 14**. Steps 1-8 and 10-14 Same. Step 9 account ID is `account_4163` vs fallback `account_030`. | `evidence_92` directly links all finding resources and `audit_record_1707`, but contains no linked account. `account_4163` appears only in identity-free activity. | Account association not established. | No production change. |
| case_31 | Count **3 vs 3**. Steps 2-3 Same. Step 1 account ID is `account_4857` vs fallback `account_541`. | `evidence_51` links tombstone and security audit to `user_541`; it has no account record. `account_4857` appears only as identity-free activity. | Account association not established. | No production change. |
| case_32 | Count **5 vs 5**. Steps 1-2 and 4-5 Same. Step 3 account ID is `account_8858` vs fallback `account_542`. | `evidence_51` links identifiable tombstone and security audit to `user_542`; it has no account record. `account_8858` appears only as identity-free activity. | Account association not established. | No production change. |

## Root-cause groups and proposed changes

1. **Supported temporal/account-resolution bug (case_17 only).** The current
   engine allows an observation from before `requested_at` to establish current
   state and initializes the account verification from a global map rather than
   the qualified request observations. This conflicts with the time contract
   and directly explains the extra tombstone steps and wrong account ID. A
   narrow, general fix is justified.

2. **Anonymous resource associations (cases 03, 04, 21, 25--28).** The
   reference associates identifier-free analytics and/or null-profile account
   entries with a person, but no visible identifier, resource link, or
   subject-bound observation establishes that relationship. Adding these steps
   would fabricate evidence linkage.

3. **Unlinked activity IDs (cases 18, 20, 22, 23, 28--32).** The reference
   uses account IDs visible only in generic activity rows and, for cases 18/20,
   security IDs unavailable in the participant-facing evidence. The activity
   details do not identify a subject. Temporal proximity and similar names are
   insufficient under the evidence rules.

## Proposed next change (not yet applied)

Implement only group 1: constrain state observations used for a request to
the interval `[requested_at, audit_at]`, and derive `account_res_id` from the
latest qualified subject-linked account observation before using global/fallback
mapping. Add regression tests showing stale pre-request evidence is ignored and
the contemporaneous linked account is selected. This should improve case_17
without introducing unsupported links for the other 15 cases.
