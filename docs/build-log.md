# R3D Build Log
## Engineering Journal v1.0
### Author: HumdoesCyber
### Built: March 2026

---

## Project Overview

R3D is an autonomous red team agent that bridges the gap
between technical security and GRC compliance. Built on
over 100 hours of research, planning, and engineering.

Fully local. No cloud APIs. No cost per run.
Zero data leaves the machine.

Stack: Python 3.12, Ollama llama3:8b, Nmap 7.95
Hardware: RTX 5070 Ti laptop

---

## Total Investment

```
Research period (14 months):
  NIST 800-53 study              ~20 hours
  NERC CIP study                 ~15 hours
  TEP risk register (4 versions) ~25 hours
  WISP audit execution           ~20 hours
  AI security research           ~40 hours
  TEP-005/TEP-010 development    ~15 hours
  Architecture planning          ~10 hours
  Total research:                ~145 hours

Build sprint (March 2026):
  Day 1: Setup + core files      ~8 hours
  Day 2: OSINT + LLM modules     ~10 hours
  Day 3: Traditional + GRC       ~10 hours
  Day 4: Orchestrator + finish   ~10 hours
  Total build:                   ~38 hours

Combined total: 180+ hours
```

---

## Timeline

### Late 2024 -- Early 2026: Research Period

Started studying NIST SP 800-53 and NERC CIP for real
client work at the Google Cybersecurity Clinic and
independent consulting engagements.

Key milestones:
- Built NIST SP 800-30 risk register through 4 versions
  for a real utility company engagement
- Executed WISP audit mapped to FTC Safeguards Rule
  with real $100K liability cap for a real client
- Authored 52-page governance framework adopted by
  University of Arizona college leadership
- 14 months of original AI security research
- Identified TEP-005 (Contextual Trust Accumulation)
  and TEP-010 (Relational State Exploitation) --
  novel multi-turn attack vectors outside OWASP LLM Top 10
- Competed at WRCCDC -- 9 hour live SOC simulation
- Google Cybersecurity Clinic -- real client engagements

### March 19, 2026: Architecture Planning

Planned the full R3D architecture before writing line one.
10 hours of planning across 2 days. Every module interface
defined. Every data contract written. Every handoff pattern
decided before any implementation began.

Key decisions locked before first commit:
- Fully local via Ollama -- zero API cost
- Three operating modes: GUIDED, SEMI-AUTO, FULL-AUTO
- Five module pipeline: OSINT -> LLM -> Trad -> GRC -> Report
- OSINTProfile dataclass as shared state across modules
- Finding dataclass with automatic MITRE + OWASP mapping
- Checkpointing via state.json after every module
- Org type selection for framework loading optimization
- Context filtering before LLM handoff
- Fail open on all external service dependencies

### March 21-24, 2026: Build Sprint

21 commits. ~38 hours of focused engineering.
Running at 3x the original 3-week projected timeline.
First successful end-to-end engagement completed March 24.

---

## Complete Commit History

```
129b283  feat: add banner with system checks and main.py CLI
bdac904  feat: add improvement engine with trend analysis
aef83cc  feat: add verifier with NVD CVE validation
a37875c  feat: add orchestrator with checkpointing
ac578d4  feat: add GRC mapper with org type selection
ff7fd42  fix: add org_type field to OSINTProfile
febf8c8  feat: add compliance KB files NIST/NERC/CIS/ISO/AI RMF
4cf14eb  feat: add traditional recon module with nmap and CVE
b6c14e0  feat: add LLM attack suite with 3-tier architecture
599b8d5  feat: add LLM attack KB files and static payload library
a7f076c  feat: add OSINT recon module with rate limiter and WAF
42de64d  feat: add sherlock-project dependency
7282cba  fix: remove __init__.py from gitignore
585c334  chore: add venv and cache dirs to gitignore
bf1f7c1  feat: add report generator with PDF XLSX and telemetry
3402ebb  feat: add findings aggregator with MITRE and OWASP
cfc6d02  feat: add CVE engine with tiered lookup and zero day
fa75de3  feat: add core LLM client with Ollama wrapper
b758131  feat: add requirements.txt with full dependency list
53e907e  docs: update README with full architecture
c70e262  feat: initial commit
```

---

## Architecture Decisions

### Why plan before coding
Every module worked first or second try because interfaces
were defined before implementation. The planning hours
paid back in zero major debugging sessions during build.

### Why Ollama and not OpenAI API
Zero cost per run. Zero data leaving the machine.
Fully air-gappable for sensitive engagements.
RTX 5070 Ti runs llama3:8b fast enough for production.

### Why three-tier LLM attack architecture
Tier 1 (static) catches poorly configured targets fast.
Tier 2 (adaptive KB-guided) catches targets that blocked Tier 1.
Tier 3 (original research) catches hardened targets using
novel multi-turn social engineering sequences that no
existing automated tool tests for.

### Why focused KB files not 400 page documents
llama3:8b has an 8,000 token context window.
Full frameworks overflow it and produce generic output.
Focused KB files produce specific actionable guidance.
Precision beats volume for local LLM inference.

### Why org type selection
Not every organization needs every framework.
Loading only relevant frameworks reduces runtime by
40-60% and produces focused reports operators can act on.

### Why checkpointing after every module
A full engagement takes 15-45 minutes. state.json saves
completed modules so --resume picks up exactly where
it stopped. No wasted work on interruptions.

### Why context filtering before LLM handoff
OSINT can find 500 subdomains and 50 emails.
Passing all that to the LLM fills the 8k context window
with noise. Filter passes only live AI surfaces and
AI-relevant subdomains. Everything else stripped.

### Why fail open on CVE validation
The verifier should never strip a CVE ID just because
it can't confirm it exists. If NVD is unavailable keep
the CVE. Only strip when NVD actively returns no results.

---

## On AI Consultation

AI tools were used as technical consultants during this
build -- not as code generators. Every architectural
decision, security design choice, and engineering tradeoff
was made by the developer based on 14+ months of prior
research and domain knowledge.

AI consultation was used for:
- Code review and error checking before execution
- Compatibility verification across module interfaces
- Identifying edge cases in error handling
- Second opinions on architectural decisions

What AI cannot do and did not do:
- Understand the TEP engagement context
- Know what problem was worth solving
- Have 14 months of security research to draw on
- Make judgment calls about what matters

The research, architecture, security vectors, compliance
mappings, and design philosophy are entirely original.
AI was a reviewer, not an author.

---

## Bugs Fixed During Build

### OSINT module
- DNS resolver: added nameservers 8.8.8.8 + 1.1.1.1
- datetime.utcnow() deprecated: timezone-aware replacement
- urllib3 warnings: suppressed at module level
- Sherlock module path: corrected to sherlock_project.sherlock

### Traditional recon
- datetime import conflict: removed inner import
- Unused imports: removed json/shlex/subprocess
- JS pattern matches: capped at [:3] per pattern
- Regex escape warning: fixed [^a-zA-Z0-9.-]

### GRC mapper
- ISO 27001:2022 colon in Excel sheet name:
  added _sanitize_sheet_name()
- OSINTProfile missing org_type: added field and to_dict()

### Orchestrator
- OSINTProfile.load() nonexistent: replaced with from_dict()
- FindingsAggregator.add_findings(): replaced with loop
- save_findings_json(): wrapped in own try/except

### Verifier
- cve_engine.lookup() no cve_override param:
  replaced with direct NVD API call
- model_copy() pydantic v2 only:
  added _copy_finding() helper for v1/v2 compatibility
- aggregated.findings[0].target fragile:
  replaced with aggregated.target directly

### Improvement engine
- Payload matching by text[:30] never matches:
  fixed to regex [P-XXX] bracket pattern
- Optional_str := None invalid syntax: fixed

---

## Security Decisions

All nmap inputs sanitized via regex. No shell=True.
urllib3 warnings suppressed at module level.
Rate limiter prevents DoS and IP bans.
GUIDED mode gates cannot be bypassed by orchestrator.
Sherlock hard-blocked in FULL-AUTO regardless of config.
TEP-005/TEP-010 research gitignored -- never public.
Authorization consent screen runs even in FULL-AUTO.
Context filtered before LLM handoff -- no PII to model.
Fail open on all external service dependencies.

---

## Performance Achieved

First live engagement: scanme.nmap.org
Duration: 28 minutes 50 seconds
Findings: 9 (1 MEDIUM, 8 LOW)
Output: PDF + XLSX risk register + compliance map + telemetry
Frameworks: NIST 800-53, NERC CIP, ISO 27001, CIS Controls, AI RMF

---

## Hardware

RTX 5070 Ti laptop
Ollama model portability:
$env:OLLAMA_MODELS = "E:\ollama\models"

---

## What Remains for v2

```
Metasploit integration    GUIDED/SEMI-AUTO gated
Self-improvement agent    Automated KB updates
Docker packaging          Enterprise on-prem deployment
Healthcare KB files       Specialized compliance
Finance KB files          SOC 2 + PCI-DSS
```
