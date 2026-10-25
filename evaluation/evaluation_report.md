# Evaluation Report — Ghost Data Still Exists

## Executed evaluation

On 2026-10-25, the deterministic generator was run against the 32 public sample requests and compared with `dataset/sample_output.csv`.

| Metric | Result |
| --- | ---: |
| Status matches | 32 / 32 (100.0%) |
| Exact `steps_json` array matches | 8 / 32 (25.0%) |

The comparison is structural and treats JSON key order as insignificant. The remaining 24 sample step-array mismatches are principally missing account verification steps where no account resource can be tied to the subject by participant-visible evidence. Other observed mismatches include incomplete parsing/association of anonymous analytics records and differing policy treatment for some support/analytics records.

## Full-dataset structural check

The generator wrote 518 rows, in numerical `case_id` order, with the required header. The available structural validator reported 65 failures: each was a `COMPLETE` row with an empty verification array. Therefore this output is not claimed to be structurally compliant.

## Regression coverage performed

* Historical identity aliases are loaded from `user_audit_log.csv` and added to each user's identity set before evidence matching.
* Evidence observations are filtered with `captured_at <= audit_at` before decisions are made.
* Unsupported numeric account-ID derivation and sequential anonymous-record pairing were removed; resource relationships now require explicit identity/evidence links.
* PDF stream decompression now uses `zlib.decompress`, rather than the invalid `base64.zlib` reference.

## Limitations and next work

The pipeline needs a general, evidence-grounded method to establish the missing account/resource relationships and a final policy audit for the remaining sample array differences. No hidden labels or case-specific mappings were used to fill those gaps.
