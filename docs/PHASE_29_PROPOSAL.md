# ARGUS - Phase 29: AI Scheduling Integrity

**Status:** Implemented.
**Scope:** `ai/recon_agent.py`, `ai/run_context.py`, `ai/loop.py`, and directly affected tests.
**Target:** Make recon-stage scheduling fail closed when a stage's adapter needs a URL seed.

## 1. Problem

`TASK_TYPE_FOR_STAGE` mapped `content_discover` and `js_analysis` to AI tasks, while
`web_crawl` was already absent. That mapping was unsafe: ReconAgent proposes the scope-root
hostname, but Katana, FFUF, and JS analysis require an evidence-backed URL seed. The same
mapping also let expansion-owned stages compete with deterministic discovery expansion.

## 2. Ownership Model

Every `STAGE_PRIORITY` stage belongs to exactly one category:

- **AI-schedulable:** `subdomain_enum`, `dns_resolve`, `port_scan`, `http_probe`,
  `tech_detect`, `historical_recon`.
- **Expansion-owned:** `web_crawl`, `content_discover`, `js_analysis`.
- **No-capability:** the remaining documented stages.

`STAGE_OWNERSHIP`, `AI_SCHEDULABLE_STAGES`, `EXPANSION_OWNED_STAGES`, and
`NO_CAPABILITY_STAGES` state this partition explicitly. `TASK_TYPE_FOR_STAGE` contains only
AI-schedulable stages; `TASK_TYPE_COVERS_STAGE` remains complete for coverage accounting.

## 3. Behavior

- `recon_context` exposes only AI-schedulable gaps to ReconAgent.
- ReconAgent also ignores expansion-owned gaps if given them directly.
- `AnalysisHook` refuses any task whose stage is not AI-schedulable.
- `coverage_gaps` and `uncovered_without_capability` keep their existing full-view behavior.
- `AnalysisResult.expansion_owned_gaps` reports uncovered expansion-owned stages so they are
  not silently lost. Disabled expansion gates remain visible in
  `uncovered_without_capability` as well.
- Discovery expansion remains the only scheduler for `web_crawl`, `content_discover`, and
  `js_analysis`.

## 4. Verification

Offline focused regression command:

```powershell
$env:ARGUS_TEST_DATABASE_URL = $null
$env:PYTHONDONTWRITEBYTECODE = '1'
.\.venv\Scripts\python.exe -m pytest tests/test_phase16.py tests/test_ai_agents.py tests/test_katana.py tests/test_ffuf.py tests/test_js_analyze.py tests/test_expansion.py -q -p no:cacheprovider
```

Result: `356 passed`.
