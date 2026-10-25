# Evaluation Report — Ghost Data Still Exists

## Executed Evaluation

The deterministic pipeline was run against the 32 public sample requests and evaluated against `dataset/sample_output.csv`.

Latest verified run: `code/test_regressions.py` passed **10/10** tests; the
sample comparison returned **32/32** status matches and **17/32** exact step
arrays; the regenerated 518-row `output.csv` passed
`scratch_validate_root_output.py` with zero validation errors.

| Metric | Result |
| --- | ---: |
| Status matches | 32 / 32 (100.0%) |
| Exact `steps_json` array matches | 17 / 32 (53.1%) |

The evaluation is structural and verifies strict JSON schemas, sequence phases (`FINDING` -> `REMEDIATION` -> `VERIFICATION`), state transitions, and step numbers.

## Full-Dataset Structural & Policy Validation

The production pipeline processed all 518 deletion requests from `dataset/deletion_requests.csv` and produced `output.csv`.
The output was rigorously validated using `scratch_validate_root_output.py` against all requirements:

| Validation Criteria | Result |
| --- | --- |
| Total Data Rows | Exactly 518 rows (`case_33` through `case_550`) |
| Ordering | Strictly sorted by numerical `case_id` ascending |
| CSV Header | Exactly `case_id,deletion_status,steps_json` |
| JSON Validity | 100% valid JSON array for every row |
| Schema Conformance | All steps contain required fields: `step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id` |
| Phase Sequencing | Strictly follows `FINDING` -> `REMEDIATION` -> `VERIFICATION` |
| Step Numbering | Strictly consecutive 1-indexed integers |
| Empty Steps in INCOMPLETE cases | 0 cases (100% evidence-backed finding and remediation plans) |
| Evidence Grounding | All finding evidence IDs correspond to valid evidence files |
| Status Validation Failures | **0 errors (100% passed)** |

### Status Distribution Across 518 Cases

- **COMPLETE**: 146 cases (28.2%)
- **INCOMPLETE**: 362 cases (69.9%)
- **NOT_APPLICABLE**: 10 cases (1.9%)

## Custom Evaluation Test Cases (Created by Author)

Three comprehensive end-to-end regression test cases were authored and executed in `code/test_regressions.py` to evaluate pipeline robustness:

1. **Custom Evaluation Case 1: Asynchronous Identity Resolution via Historical Audit Log (`test_request_emails_resolve_through_identity_history`)**
   - **Scenario**: A user requests deletion using a historical email alias that underwent email change operations documented in `user_audit_log.csv`.
   - **Verification**: Evaluates that all 518 request emails resolve to a known user identity cluster. Verifies that identity matching traverses historical emails, phone numbers, and full names without dropping identity links or fabricating surrogate IDs.
   - **Result**: PASSED (100% resolution rate across all cases).

2. **Custom Evaluation Case 2: Multi-Replica Temporal Ordering and Snapshot Override (`test_later_account_not_found_overrides_earlier_found`)**
   - **Scenario**: In `case_86` (`account_8473`), an early database snapshot captures the record present, but a subsequent failover replica snapshot (`evidence_54`) demonstrates that deletion replication completed before the audit cutoff.
   - **Verification**: Evaluates that the audit engine tracks observation timestamps and ensures later verified absence supersedes earlier presence, preventing false-positive `REPORT_REMAINING_RECORD` findings when replication eventually converged.
   - **Result**: PASSED (no conflicting presence findings emitted).

3. **Custom Evaluation Case 3: Temporal Cutoff Invariant Enforcement (`test_post_cutoff_observations_are_not_selected`)**
   - **Scenario**: In `case_33` (`ingrid.dahl@outlook.com`), evidence observations exist both prior to the audit cutoff (`evidence_23` on 2026-06-18 and `evidence_18` on 2026-07-18) and well after the audit cutoff (`evidence_01` on 2026-09-15, audit cutoff `2026-07-19T13:00:00Z`).
   - **Verification**: Evaluates that observations captured after `audit_at` are strictly excluded from findings and verification plans. Only pre-cutoff evidence is cited.
   - **Result**: PASSED (all cited evidence files strictly precede `audit_at`).

## Failures Found & Improvements Made

1. **Unparsed Multi-Format Evidence**:
   - *Failure*: 46 authorized requests previously had empty step arrays because critical JSON manifests (`connector_configurations_*.json`, `customer_export_manifest_*.json`, `security_audit_ledger_*.json`, `customer_analytics_report_*.json`) were either skipped or keyed incorrectly.
   - *Improvement*: Implemented generalized manifest parsing for uniform `records` schemas, extracting `account_service`, `search_service`, `integration_service`, and `security_service` records.

2. **Unlinked Console Screenshots & Documents**:
   - *Failure*: Screenshot files (`evidence_04`, `evidence_09`, `evidence_14`, etc.) and document exports in PDF format were unlinked from user accounts because user IDs were stored in `system_activity.csv` activities `activity_4000`–`activity_4011`.
   - *Improvement*: Ingested `LINK_RESOURCE_IDENTITY` operations from `system_activity.csv` to bridge user IDs and resource IDs with their corresponding evidence files.

3. **Log Parser Regex Brittleness**:
   - *Failure*: Multi-format logs (JSON `"trace_id"`, pipe-delimited traces, bracketed entries, and key-value formats) failed regex extraction when keys used colons (`"resource_id":"..."`) instead of equals signs (`resource_id=...`).
   - *Improvement*: Refactored `extract_trace_id()` and regex matchers to handle all delimiter formats and trace ID structures robustly.

4. **Marketing Profiles & Attachment Status**:
   - *Failure*: Marketing profiles marked with category `MARKETING` were omitting remediation steps, and support attachments with status `IDENTIFIABLE` were ignored.
   - *Improvement*: Added `DELETE_RECORD` remediation for marketing profiles and expanded attachment status handling to include `IDENTIFIABLE`.

5. **Logs Replacing Stronger State Captures**:
   - *Failure*: The newest observation was selected without regard to evidence type, allowing a later operational log to replace a database or structured-record state capture for the same resource. Object-storage catalog links were also being treated as support records.
   - *Improvement*: Prioritized database and structured-record captures over logs when resolving a resource's latest supported state, retained object-storage links in their native system, and preserved per-record observation timestamps from service exports. The confirmed public exact-step result improved from 14/32 to 16/32; status accuracy remained 32/32.

6. **Request-Window State and Account Resolution (case_17)**:
   - *Failure*: A pre-request tombstone observation was treated as current state, and a stale global account map could override a later account observation explicitly linked to the request subject.
   - *Improvement*: State-establishing observations now require `requested_at <= observed_at <= audit_at`; the latest qualifying, subject-linked account observation is preferred before global fallback. Regression coverage confirms pre-request exclusion, audit-cutoff exclusion, subject-linked account precedence, and fallback behavior for missing or ambiguous account evidence. The confirmed public exact-step result improved from 16/32 to 17/32; status accuracy remained 32/32.

7. **Non-deterministic PDF Identity Extraction (case_07)**:
   - *Failure*: The document parser selected the first member of an unordered email set. A support attachment contained the subject email and an unrelated embedded-font metadata address, so process hash randomization could lose the subject link and incorrectly mark the case complete.
   - *Improvement*: PDF identity resolution now accepts only explicit known user IDs or an unambiguous known-email subject, ignoring unmatched metadata addresses. The regression test covers this input, and eight fresh processes consistently produced the evidence-backed incomplete result.
