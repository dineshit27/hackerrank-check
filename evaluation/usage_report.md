# Usage Report — Ghost Data Still Exists

**Challenge:** HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Pipeline:** `code/main.py` — `DeletionAuditEngine` (rule-based, deterministic)  
**Run date:** 2026-10-25

---

## Summary

This solution uses a **fully deterministic, rule-based pipeline** — no LLM API calls are made at inference time.  
All evidence parsing, identity resolution, policy evaluation, and step generation are implemented in pure Python using only standard library modules (`csv`, `json`, `sqlite3`, `re`, `os`, `glob`, `datetime`, `base64`).

---

## Model Providers and Model Names

| Provider | Model | Role |
|---|---|---|
| Google DeepMind | Antigravity (Gemini 2.5 Pro) | Coding assistant used to design, implement, debug, and iterate on the pipeline |
| None (rule-based) | N/A | Inference/prediction at submission time |

> **No model API calls are made during the final pipeline run** (`python code/main.py`).  
> The AI assistant (Antigravity) was used interactively to write and refine the code, not to classify individual cases.

---

## Model Call Counts (Coding Phase)

These counts cover the full development session in this repository:

| Model | Approximate Calls | Purpose |
|---|---|---|
| Antigravity (Gemini 2.5 Pro) | ~60 | Code generation, debugging, analysis, report writing |

---

## Token Usage (Coding Assistant — Approximate)

| Phase | Input Tokens (est.) | Output Tokens (est.) |
|---|---|---|
| Repository exploration & dataset analysis | ~25,000 | ~8,000 |
| Pipeline design & main.py implementation | ~35,000 | ~18,000 |
| Evidence parser debugging & testing | ~20,000 | ~10,000 |
| Sample accuracy evaluation & fixes | ~15,000 | ~6,000 |
| Report writing & submission packaging | ~8,000 | ~5,000 |
| **Total (estimated)** | **~103,000** | **~47,000** |

---

## Final Full-Dataset Run Statistics

| Metric | Value |
|---|---|
| Requests processed | 518 |
| Runtime | ~3 seconds |
| Model API calls at inference | **0** |
| Input tokens at inference | **0** |
| Output tokens at inference | **0** |
| Cost at inference | **$0.00** |

---

## Per-Request Statistics (Inference)

Since inference is fully deterministic and requires no model calls:

| Metric | Value |
|---|---|
| Average inference time per request | ~6ms |
| API tokens per request | 0 |
| API cost per request | $0.00 |

---

## Notes

- The pipeline reads all evidence files once at startup, builds in-memory observation stores, then processes each case in O(n_observations) time.
- Evidence covers: 24 SQLite-format SQL snapshots, 26 log files, JSON export bundles, PDF documents (text extracted via zlib decompression), PNG screenshots (metadata indexed), and plain-text record files.
- Identity resolution uses `user_identities.csv` (current snapshot) and `user_audit_log.csv` (historical aliases) to match evidence across email changes.
- All decisions respect the `audit_at` cutoff: only evidence with `captured_at <= audit_at` is considered.
