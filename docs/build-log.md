# R3D Build Log
## Engineering Journal
### Author: Humza Sheikh (HumdoesCyber)

---

## Project Overview

R3D is a fully local autonomous purple team agent that bridges
the gap between technical security and GRC compliance.
Built on 14 months of original AI security research and
150 hours of engineering.

Fully local. No cloud APIs. No cost per run.
Zero data leaves the machine.

---

## The Real Timeline

This did not start in March 2026.

### December 2024 -- Research Begins

Started studying NIST SP 800-53 and NERC CIP for real client
work at the Google Cybersecurity Clinic and independent
consulting engagements. The gap between technical security
findings and GRC compliance language became impossible to ignore.

Key research milestones over 14 months:
- Built NIST SP 800-30 risk register through 4 versions
- Executed WISP audit mapped to FTC Safeguards Rule
  with $100K liability cap for real client
- Authored 52-page ISCC Governance Framework adopted
  by college leadership
- Competed at WRCCDC -- 9-hour live SOC simulation
- 14 months of original AI security research into
  multi-turn LLM attack vectors outside OWASP LLM Top 10

The architecture of R3D was shaped by this research period.
Every design decision traces back to something learned
during real client work or original research.

### March 19, 2026 -- Architecture Planning

Two days before the first commit, the full R3D architecture
was planned. Every module interface defined. Every data
contract locked. Every handoff pattern documented.

This is why the build was fast. The hard decisions were
already made before a single line existed.

Key decisions locked on day one:
- Fully local via Ollama -- zero API cost, air-gappable
- Three operating modes: GUIDED, SEMI-AUTO, FULL-AUTO
- Five module pipeline: OSINT → LLM → Trad → GRC → Report
- OSINTProfile dataclass as shared state across modules
- Finding dataclass with MITRE + OWASP auto-mapping
- Checkpointing via state.json after every module
- Org type selection for framework loading optimization
- Context filtering before LLM handoff
- Python always the final authority on CVEs

### March 21, 2026 -- Build Begins

First commit. Architecture already locked.
This is why velocity was high -- no design decisions
were made during implementation.

### March 22-23, 2026 -- Build Sprint

23 commits in less than 72 hours.
Full pipeline from zero to complete.

### March 24, 2026 -- V1.0 Complete

First live engagement: scanme.nmap.org
Time: 28 minutes 50 seconds
Findings: 9
Outputs: PDF, XLSX risk register, XLSX compliance map,
         JSON telemetry. All clean.

---

## Methodology

This project was built through AI-assisted systems engineering.
That is a precise description, not a marketing phrase.

Architecture before code. Every module interface was defined
before implementation began. OSINTProfile fields. Finding schema.
The data contract between every module. All locked before
a single line was written.

Security review before every paste. Every module was reviewed
for infinite loops, error handling gaps, input sanitization
failures, and cross-module compatibility before running on
hardware. This is why modules worked first or second try.

Comprehension over convenience. Every decision has a documented
reason. The context filter strips emails before LLM handoff
because they add noise without improving attack surface coverage.
The verifier only touches LLM findings because OSINT and
traditional recon outputs are Python-authoritative.

Claude and Gemini acted as technical consultants -- code review,
error checking, compatibility verification, syntax generation.
The domain knowledge, the architecture, the security decisions,
and the research are mine.

```
14 months   Domain research + real client work
150 hours   Coding, architecture, security review
4 days      Build sprint -- 23 commits
            Two weeks ahead of original 3-week estimate
```

---

## Commit History

```
3a2dcc3  chore: add CVE database to gitignore (130MB)
d4b8278  fix: use setup_cve_db function in cmd_setup_cve_db
a15b6fc  docs: complete README rewrite and final guides v1.0
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

### Why Ollama and Not OpenAI API
Zero cost per run. Zero data leaving the machine.
Fully air-gappable for sensitive engagements.
RTX 5070 Ti runs llama3:8b fast enough for production use.
For critical infrastructure work you cannot send data
to a cloud API. Local by design, not by configuration.

### Why Plan Before Coding
Every module worked first or second try because the interfaces
were defined before implementation. Most debugging time is spent
fixing design decisions made during implementation. I fixed
design first. The 4-day sprint was fast because of the
14 months before it.

### Why Focused KB Files and Not Full Documents
Ollama's context window is approximately 8,000 tokens.
A full NIST 800-53 document would overflow it and produce
generic output. Focused KB files with only relevant controls
give the model exactly what it needs for each finding type.
Precision beats volume for local LLM inference.

### Why Org Type Selection
Not every organization needs every framework. Loading only
relevant frameworks reduces runtime by 40-60%, improves
Ollama output quality, and produces focused reports operators
can actually act on. Nobody reads the 400-page report.

### Why Three-Tier LLM Attack Architecture
Tier 1 (static) catches poorly configured targets fast.
Tier 2 (adaptive) catches targets that blocked Tier 1.
Tier 3 (original research) catches hardened targets using
novel multi-turn sequences based on 14 months of independent
research into attack vectors outside the current published
literature. No existing tool uses this approach.

### Why Checkpointing After Every Module
A full engagement can take 15-45 minutes. If anything crashes
at minute 40, losing all data is unacceptable. state.json saves
completed modules so --resume picks up exactly where it stopped.

### Why Context Filtering Before LLM Handoff
OSINT can find 500 subdomains, 50 emails, 200 historical
endpoints. Passing all of that to the LLM attack module fills
the context window with noise. Filter passes only live AI
surfaces and relevant subdomains. Protects context window
quality and keeps Ollama output precise.

### Why Sanitize All Inputs Before Nmap
Command injection via target parameter is a real risk.
_sanitize_ip() and _sanitize_target() strip everything
except alphanumeric, dots, and hyphens before any nmap call.
No shell=True anywhere in the codebase.

### Why Python Is Always the Final Authority on CVEs
LLMs hallucinate. A hallucinated CVE ID in a security report
is a serious credibility and accuracy failure. CVE IDs only
come from cve_engine.py querying real NVD data. The LLM
never generates CVE identifiers under any circumstances.

---

## Module Engineering Notes

### core/llm_client.py
Ollama wrapper with JSON validation and LLMResponse schema.
All LLM calls go through this -- single point of control.
Synchronous by design -- no parallel LLM calls.
Prevents VRAM OOM on RTX 5070 Ti 12GB.

### core/cve_engine.py
Three-tier CVE lookup: local NVD database, NVD API, zero-day flag.
Python is the final authority -- LLM never generates CVE IDs.
This prevents hallucinated CVE numbers in reports.

### core/findings.py
Finding dataclass with automatic MITRE ATT&CK and OWASP mapping
on creation. MD5 deduplication prevents duplicate findings.
FindingsAggregator collects all findings with severity counts
and zero-day flags.

### core/report_gen.py
PDF via reportlab. XLSX via openpyxl. JSON telemetry for blue
team SIEM ingestion. All three outputs from single
AggregatedFindings object.

### modules/osint_recon.py
10 checks. RateLimiter class with per-domain sliding window.
WAF detection with 8 vendor signatures. Google to DuckDuckGo
automatic fallback. Sherlock blocked in FULL-AUTO regardless
of mode. fast_mode=True for testing only.

### modules/llm_attack.py
Three-tier architecture: static → KB-guided → original research.
ConversationManager handles multi-turn sessions per surface.
ResponseAnalyzer scores responses across three layers.
Tier 3 original research sequences are available to authorized
installations only and are never pushed to GitHub.

### modules/traditional_recon.py
Checks 1-3 combined in one nmap run for efficiency.
NMAP_TIMEOUT=300 hard caps execution.
SSL check uses timezone-aware datetime.
JS bundle analysis capped: 10 files, 3 matches per pattern.
WAF bypass only runs if OSINT detected a WAF.
Each check independent -- one failure never stops others.

### modules/grc_mapper.py
Org type selection -- asked once, saved to profile.
AI RMF auto-loads regardless of org type if AI surfaces found.
All framework lookup tables are pure Python dicts -- fast.
Excel sheet names sanitized -- no illegal characters.
Ollama generates executive summary grounded in KB context.
Falls back to template if Ollama unavailable.

### modules/orchestrator.py
Master sequencer for all four modules.
Engagement ID ties all output files together.
Authorization consent screen required before any module runs.
Context filtering before LLM handoff protects context window.
Heartbeat thread prints progress during long operations.
45 minute default timeout prevents infinite hangs.
Verifier hook fails gracefully if not built.

### core/verifier.py
Only touches LLM attack findings -- everything else passes through.
CVE validation via direct NVD API call. Fail open on timeout.
Semantic dedup with Ollama primary, difflib fallback.
Pydantic v1/v2 compatible via _copy_finding() helper.

### core/improvement_engine.py
Reads verification reports to find patterns in what fails.
Generates ranked suggestions -- CRITICAL/HIGH/MEDIUM.
Operator approves every suggestion. Nothing auto-modified.
Minimum 3 engagements before pattern analysis runs.

### data/compliance_kb/
Five focused KB files -- not full framework documents.
Each file contains only controls relevant to R3D finding types.
Ollama reads 1,500 chars from each -- enough to reason precisely.
Full frameworks overflow context window and degrade output.

---

## Bugs Found and Fixed

All bugs were caught during security review before pasting --
not discovered at runtime.

```
DNS resolver failing         added nameservers=['8.8.8.8','1.1.1.1']
datetime.utcnow() deprecated replaced with datetime.now(timezone.utc)
ISO 27001 colon in Excel     added _sanitize_sheet_name()
OSINTProfile missing field   added org_type + to_dict() entry
urllib3 warnings             suppressed at module level
Regex escape warning         [^a-zA-Z0-9.-] corrected
OSINTProfile.load()          replaced with from_dict()
add_findings() plural        replaced with add_finding() loop
Tuple unpack on OSINT        fixed to osint_findings = recon.run()
generate_all() missing       replaced with three individual calls
Orphan dir on resume         deferred dir creation until after check
Sleep on skipped modules     gated sleep on module completion
```

---

## Performance

Full engagement A to Z: 15-25 minutes standard

```
OSINT module        3-8 min
LLM attack          2-4 min (if AI surfaces found)
Traditional recon   3-5 min (top 1000 ports)
GRC mapper          1-2 min
Report generation   <1 min
```

First live result:
```
Target:   scanme.nmap.org
Time:     28 minutes 50 seconds
Findings: 9
Outputs:  PDF, XLSX x2, JSON telemetry -- all clean
```

---

## Security Decisions

```
All nmap inputs sanitized via regex before execution
No shell=True anywhere in codebase
urllib3 InsecureRequestWarning suppressed at module level
Rate limiter prevents accidental DoS and IP bans
GUIDED mode gates cannot be bypassed by orchestrator
Sherlock hard-blocked in FULL-AUTO regardless of config
Original research in .gitignore -- never public
Authorization consent screen runs even in FULL-AUTO
LLM never generates CVE IDs -- Python is final authority
```

---

## Hardware

Acer Predator Helios Neo 16 AI
NVIDIA RTX 5070 Ti 12GB VRAM
32GB DDR5 RAM
Windows 11

---

## What Remains for V2

```
Shodan API integration       Phase 1
Nuclei integration           Phase 1
Metasploit integration       Phase 1 (GUIDED/SEMI-AUTO only)
Healthcare + Finance KB      Phase 2
Docker packaging             Phase 2
SIEM push integration        Phase 2
Self-improvement agent       Phase 3
```

---

## Velocity

Original estimate: 3 weeks
Actual sprint:     4 days
Ahead of schedule: 2 weeks

Reason: Full architecture planned before line one.
All interfaces defined before implementation.
Security review before every paste.
Modules worked first or second try throughout.

Research started:  December 2024
Architecture:      March 19, 2026
First commit:      March 21, 2026
V1.0 complete:     March 24, 2026
Total coding:      150 hours