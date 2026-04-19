# R3D Agent — Post-Audit Update Log
## Security Audit, Code Quality Pass, and Model Flexibility

**Date:** April 19, 2026
**Author:** HumdoesCyber
**Trigger:** Post-release security audit (Bandit, Pylint, Safety, Ruff) +
external reviewer feedback from 0xPa1e_H0rse
**Status:** All audit findings resolved. Dual-model verification run complete
(llama3:latest + qwen2.5-coder:14b on scanme.nmap.org).

---

## Summary

After shipping V1.0, a full security and code quality audit was run across the
entire codebase. Four tools were used: Bandit (security AST scanner), Pylint
(code quality), Safety (dependency CVEs), and Ruff (linter). The audit found
no security vulnerabilities but surfaced real code quality issues — including
a compliance data inconsistency that would have produced conflicting outputs
between the PDF report and XLSX compliance sheet.

All actionable findings were resolved. The codebase also received a new
`--model` CLI flag making the Ollama model switchable at runtime without
touching any code.

**Pylint score before:** 9.60/10 (with targeted warnings present)
**Pylint score after:** 9.60/10 (all targeted warnings eliminated —
score held at ceiling, remaining deductions are intentional architectural
patterns like broad exception catches in recon modules)

---

## What Changed

### 1. New File: `core/grc_constants.py`

**Why:** `NIST_MAPPING` and `NERC_CIP_MAPPING` — the dicts that map every
finding type to its compliance controls — existed as separate copies in both
`core/report_gen.py` and `modules/grc_mapper.py`. By the time the audit
caught it they had already diverged: `ai_surface` findings were mapping to
`CIP-010-4` (Configuration Change Management) in the PDF report but
`CIP-015-1` (Internal Network Security Monitoring) in the XLSX compliance
sheet. An auditor cross-referencing both documents would see conflicting
control citations for the same finding.

**Fix:** Created `core/grc_constants.py` as a single source of truth.
Both files now import from it. `CIP-015-1` is the authoritative NERC CIP
mapping for `ai_surface` — Internal Network Security Monitoring is the
correct control for AI surface exposure on OT networks.

**Impact:** PDF report and XLSX compliance sheet now cite identical controls.
One change propagates everywhere. No more drift.

---

### 2. New CLI Flag: `--model`

**Why:** The tool defaulted to `llama3` with no way to change the model
without editing source code. Anyone running `qwen2.5-coder:14b`,
`gemma3:4b`, or any other local model had no clean way to tell R3D to
use it for KB-guided attacks and executive summary generation.

**What changed:**
- `core/llm_client.py` — default model now reads from `OLLAMA_MODEL`
  environment variable, falling back to `llama3` if not set
- `main.py` — new `--model` argument sets `OLLAMA_MODEL` before
  the engagement starts. Applies to all LLM calls in the pipeline.

**Usage:**
```bash
python main.py --target example.com --model qwen2.5-coder:14b
python main.py --target example.com --model gemma3:4b
python main.py --target example.com --model llama3:latest
```

**Impact:** Model is now a runtime flag. No code changes needed to swap
models. Validated on both `llama3:latest` and `qwen2.5-coder:14b` against
scanme.nmap.org.

---

### 3. Duplicate Import Cleanup (W0404)

**Files:** `core/verifier.py`, `core/report_gen.py`, `modules/grc_mapper.py`

Five instances of modules being reimported inside `if __name__ == "__main__"`
test blocks when they were already imported at the top of the file.
`FindingsAggregator` promoted to top-level import in `report_gen.py` and
`grc_mapper.py` where it was only living in the test block.

---

### 4. f-Strings Without Interpolation Removed (W1309)

**Files:** `core/verifier.py`, `core/report_gen.py`,
`core/improvement_engine.py`, `modules/llm_attack.py`,
`modules/orchestrator.py`, `modules/osint_recon.py`,
`modules/traditional_recon.py`

15 string literals prefixed with `f` but containing no `{}` variables.
Every `f` prefix tells Python to scan the string for interpolation at
runtime — pointless overhead on static strings. Removed all 15 `f`
prefixes. They are now compile-time constants.

---

### 5. Unused Arguments Renamed (W0613)

**Files:** `core/llm_client.py`, `modules/llm_attack.py`,
`modules/osint_recon.py`

Five function parameters were accepted in signatures but never used inside
the function body:

| File | Function | Parameter | Reason Kept |
|------|----------|-----------|-------------|
| `llm_client.py` | `_repair_json` | `error` → `_error` | Accepted for API consistency |
| `llm_attack.py` | `_ollama_analysis` | `history` → `_history` | Callers pass it — analysis uses payload/response only |
| `llm_attack.py` | `_run_tep010` | `research_kb` → `_research_kb` | Reserved for KB-guided TEP-010 in v2 |
| `llm_attack.py` | `_analyze_cta_sequence` | `analyzer` → `_analyzer` | Reserved for semantic scoring in v2 |
| `osint_recon.py` | `RateLimiter.wait` | `label` → `_label` | Reserved for future rate limit logging |

Leading underscore is Python convention for intentionally unused —
keeps the API compatible, signals intent clearly to future maintainers.

---

### 6. Dead Variable Removed (W0612)

**File:** `core/improvement_engine.py`

In `_is_duplicate_suggestion()`, a SequenceMatcher result was computed
and stored in `ratio` on line 361, then immediately the loop below
computed a separate `r` variable doing the same comparison. The initial
`ratio` assignment was dead code — written, never read. Removed.

---

### 7. Explicit subprocess Intent (W1510)

**Files:** `core/banner.py`, `modules/osint_recon.py`, `main.py`

Seven `subprocess.run()` calls were missing the `check=` parameter.
Without it, non-zero return codes are silently ignored — ambiguous intent.
Every one of these calls checks `result.returncode` manually afterwards.

Added `check=False` with inline comments explaining why:

```python
# Non-zero exit is normal when no platforms found
result = subprocess.run([...], check=False)

# returncode checked manually below
r = subprocess.run(["nmap", "--version"], check=False)
```

The code behavior is unchanged — this makes the intent explicit and
removes the ambiguity for anyone reading the code later.

---

### 8. Unused Imports Removed (W0611)

| File | Import Removed | Confirmed Via |
|------|---------------|---------------|
| `core/banner.py` | `from datetime import datetime` | AST scan — `datetime.` never called |
| `core/verifier.py` | `import re` | AST scan — `re.` never called |
| `modules/grc_mapper.py` | `import json` | AST scan — `json.` never called |
| `main.py` | `import time` | AST scan — `time.` never called |

All four confirmed by Python AST analysis before removal.

---

## Security Audit Results

### Bandit
```
Files scanned: all Python files
Total lines:   10,134
Result:        0 medium/high severity issues
Low severity:  57 (all intentional — subprocess calls, assert statements,
               random module usage in a pen test tool context)
Existing #nosec annotations: 4
```

No changes made. All 57 low-severity flags are correct patterns for a
security research tool. The 4 existing `#nosec` annotations are appropriately
placed.

### Pylint
```
Score before: 9.60/10
Score after:  9.60/10
Warnings eliminated: W0404 (5), W1309 (15), W0613 (5),
                     W0612 (1), W1510 (7), W0611 (4)
Remaining deductions: W0718 broad-exception-caught (~30 instances)
                      — intentional, recon modules must not crash
                      W0621 redefined-outer-name — test block variables
                      W0212 protected-member access — test blocks
```

### Safety
```
Packages scanned: 98
CVEs found:       0
Result:           Clean
```

### Ruff
Flag error on `--ignore W503` (flake8-era flag, not valid in Ruff).
Not a code issue.

---

## Files Modified

| File | Changes |
|------|---------|
| `core/grc_constants.py` | **NEW** — shared NIST + NERC CIP mapping tables |
| `core/report_gen.py` | Import from grc_constants, remove duplicate dicts, fix 4 f-strings, clean reimport |
| `modules/grc_mapper.py` | Import from grc_constants, remove duplicate dicts, remove unused import, clean reimport |
| `core/verifier.py` | Fix 2 f-strings, remove unused `import re`, clean reimport |
| `core/improvement_engine.py` | Remove dead `ratio` variable, fix 2 f-strings |
| `core/llm_client.py` | `OLLAMA_MODEL` env var support, rename `_error`, add `import os` |
| `core/banner.py` | Remove unused `datetime` import, add `check=False` to 2 subprocess calls |
| `modules/llm_attack.py` | Rename 3 unused args, fix f-string in GUIDED block |
| `modules/orchestrator.py` | Fix 2 f-strings |
| `modules/osint_recon.py` | Rename `_label`, fix 2 f-strings, add `check=False` to subprocess |
| `modules/traditional_recon.py` | Fix 3 f-strings |
| `main.py` | Add `--model` flag + `os.environ` wiring, add `import os`, add `check=False` to 4 subprocess calls |

---

## Dual-Model Verification

Both runs on `scanme.nmap.org` in `FULL-AUTO` mode with `--fast-mode`:

| Run | Model | Target | Mode |
|-----|-------|--------|------|
| 1 | `llama3:latest` | scanme.nmap.org | FULL-AUTO |
| 2 | `qwen2.5-coder:14b` | scanme.nmap.org | FULL-AUTO |

Both confirmed the `--model` flag routes correctly through the pipeline.
Model override printed at engagement start. All LLM calls (KB-guided
payloads, executive summary, GRC narrative) used the specified model.

---

## What Is Still Pending (V2)

| Item | Notes |
|------|-------|
| `--resume` flag | Checkpoint logic broken — listed as known issue, will fix in v2 |
| TEP-010 KB wiring | `_research_kb` accepted but not yet used inside the sequence — v2 will wire full KB-guided RSE |
| `_analyzer` in CTA | Semantic analyzer scaffolded but not connected — v2 |
| Nuclei integration | 9,000+ templates — scoped for v2 |
| Shodan integration | Paid API — scoped for v2 when revenue exists |

---

*All changes reviewed and implemented by HumdoesCyber.
External review credit: 0xPa1e_H0rse (Ethan).*
