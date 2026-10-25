# Usage Report — Ghost Data Still Exists

## Final generator run

Command executed on 2026-10-25:

```powershell
& 'C:\Users\dinesh\AppData\Local\Programs\Python\Python310\python.exe' code\main.py --output output.csv
```

| Metric | Value |
| --- | ---: |
| Requests processed | 518 |
| Inference model/API calls | 0 |
| Inference input tokens | 0 |
| Inference output tokens | 0 |
| Inference cost | $0.00 |

The submitted generator is a local, deterministic Python program using the standard library. It does not call a model provider at inference time.

## Development-assistant usage

No authoritative aggregate model-call, token, duration, or cost telemetry is available in this checkout. Those values are therefore unavailable rather than estimated. Earlier session entries identify an Antigravity IDE / `gemini-2.5-pro` coding session; this audit session used Codex / `GPT-5`. Neither was invoked by the final generator.
