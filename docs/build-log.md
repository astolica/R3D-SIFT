# R3D Build Log
## Engineering Journal
### Author: Humza Sheikh (HumdoesCyber)

---

## Project Overview

R3D is a fully local autonomous purple team agent that bridges
the gap between technical security and GRC compliance.
Built on 14 months of original AI security research and
250 hours of engineering. Every module was built through
AI-assisted systems engineering with comprehensive security
review at each stage.

Fully local. No cloud APIs. No cost per run.
Zero data leaves the machine.

---

## The AI Accountability Problem This Solves

The industry is replacing human judgment with AI automation at speed.
In security this creates a specific and serious failure mode: AI makes
mistakes at the speed of light and there is no one in the machine to
hold accountable. A hallucinated CVE closes a real vulnerability on paper.
A miscalibrated severity leaves a CRITICAL finding untouched for 180 days.
An unverified NERC CIP finding means a utility files incorrect compliance
documentation at up to $1M per day per violation.

R3D was designed as a direct answer to this. The human operator is
kept in the loop at every stage through five architectural accountability
layers -- authorization gate, verifier, improvement engine, telemetry log,
and engagement ID. The AI executes. The human decides. The audit trail
proves it. That is not a philosophy statement -- it is a hard engineering
constraint baked into every module.

---

## The Real Timeline

### December 2024 -- Research Begins

Started studying NIST SP 800-53 and NERC CIP for real client
work at the Google Cybersecurity Clinic and independent
consulting engagements. The gap between technical security
findings and GRC compliance language became impossible to ignore.

Key research milestones:
- Built NIST SP 800-30 risk register through 4 versions
- Executed WISP audit mapped to FTC Safeguards Rule
  with $100K liability cap for real client
- Authored 52-page ISCC Governance Framework adopted
  by college leadership
- Competed at WRCCDC -- 9-hour live SOC simulation
- 14 months of original AI security research into
  multi-turn LLM attack vectors outside OWASP LLM Top 10

### March 19, 2026 -- Architecture Planning

Full R3D architecture planned before first commit.
Every module interface defined. Every data contract locked.
Every handoff pattern documented.

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
Velocity was high because design decisions were
made before implementation, not during it.

### March 22-23, 2026 -- Build Sprint

23 commits in less than 72 hours. Full pipeline built.

### March 24, 2026 -- V1.0 Complete

First live engagement: scanme.nmap.org
Outputs: PDF, XLSX risk register, XLSX compliance map,
JSON telemetry. All clean.

### March 26-29, 2026 -- Security Audit Sprint

Three full security audits completed:
pip-audit, bandit, pylint. All findings reviewed
and resolved. 17 targeted bug fixes applied.
5 additional quality improvements committed.

### April 01, 2026 -- V1.0 Released

Final patched and audited release. 50+ commits total.

---

## Methodology

This project was built through AI-assisted systems engineering.

Architecture before code. Every module interface was defined
before implementation began. When you know the shape of your
data going in and out, the implementation almost writes itself.

Security review before every paste. Every module was reviewed
for infinite loops, error handling gaps, input sanitization
failures, and cross-module compatibility before running on
hardware.

Comprehensive security audits before release:
- pip-audit: dependency vulnerability scan
- bandit: static security analysis
- pylint: code quality and error detection

Claude and Gemini acted as technical consultants -- code review,
error checking, compatibility verification, syntax generation.
The domain knowledge, the architecture, the security decisions,
and the research are mine.

```
14 months   Domain research + real client work
250 hours   Coding, architecture, security review
4 days      Build sprint -- 23 commits
1 week      Audit and patch sprint -- 30+ commits
50+         Total commits at release
```

---

## Top 10 Bugs Found and Fixed

All found through security review and live testing. Listed by impact.

### Bug 1 -- AI Surface False Positives (CRITICAL IMPACT)
**Module:** osint_recon.py
**Problem:** Any URL returning non-404 was flagged as an AI surface.
On a home router (10.0.0.1) this produced 30 false positive CRITICAL
findings because the router returned 200 to everything by redirecting
to its login page. The entire AI attack module would run against a
Xfinity login page.
**Fix:** Added POST confirmation before flagging. GET returning HTML
is a login redirect -- skip it. POST returning JSON, 401, 403, or 405
is a confirmed LLM API. Eliminated false positives entirely.

### Bug 2 -- PDF Rendering Crash on All Findings (CRITICAL IMPACT)
**Module:** core/report_gen.py
**Problem:** PDF generation failed with "Not enough horizontal space
to render a single character" on any engagement with findings.
Multi-cell rendering after inline label cells left zero width remaining.
No PDF output produced.
**Fix:** Full rewrite of finding_block() using a consistent field()
helper function. Every label on its own full-width line. Value indented
below. Cursor position explicitly reset after every field. All labels
now render: MITRE ATT&CK, OWASP, NIST SP 800-53, NERC CIP,
remediation -- all clean on every finding.

### Bug 3 -- CVE Path Mismatch -- Database Never Loaded (HIGH IMPACT)
**Module:** core/banner.py, main.py
**Problem:** banner.py and main.py were looking for
data/cve_db/nvdcve.db but the actual file was data/cve_database.json.
CVE database showed as missing on every startup despite being present.
CVE correlation silently degraded.
**Fix:** Corrected path in both files. CVE database now loads correctly
at startup and displays size confirmation (129MB).

### Bug 4 -- LLM Timeout Missing -- Pipeline Hangs (HIGH IMPACT)
**Module:** core/llm_client.py
**Problem:** No timeout on Ollama calls. If Ollama hung or was slow
the entire engagement pipeline hung indefinitely with no recovery.
No retry logic on empty responses.
**Fix:** Added OLLAMA_TIMEOUT=120 seconds, OLLAMA_MAX_RETRIES=2
with 3-second backoff, and flexible model resolution that handles
llama3, llama3:8b, and llama3.2 naming variants.

### Bug 5 -- OSINT Crash Leaves Null Profile (HIGH IMPACT)
**Module:** modules/orchestrator.py
**Problem:** If OSINT crashed mid-run, profile was left as None.
Downstream modules (traditional recon, GRC mapper) received
profile=None and crashed silently. Engagement appeared to complete
but produced no meaningful output.
**Fix:** On OSINT crash, orchestrator creates an empty
OSINTProfile(target=self.target) and continues. Pipeline
completes with reduced but valid output.

### Bug 6 -- Engagement Directory Created Before Authorization (MEDIUM IMPACT)
**Module:** modules/orchestrator.py
**Problem:** Engagement directory was created before the authorization
consent screen ran. If operator typed NO or Ctrl+C the directory
remained on disk -- creating phantom engagement records and
confusing the recent engagements table on next startup.
**Fix:** Directory creation moved to after YES confirmation.
No artifacts created until authorization is explicitly granted.

### Bug 7 -- DNS Resolver Using ISP DNS -- Constant Timeouts (MEDIUM IMPACT)
**Module:** modules/osint_recon.py
**Problem:** Default system DNS resolver (ISP DNS at 40.30.x.x)
timed out on every record type for external targets. 5 x 10 second
timeouts = 50 seconds of dead time per engagement before any
real OSINT work started. IP address never resolved, breaking
traditional recon handoff.
**Fix:** Explicit nameserver override to ["8.8.8.8", "1.1.1.1"].
DNS now resolves cleanly. ISP DNS bypassed entirely.

### Bug 8 -- Duplicate Apache Findings Every Engagement (LOW IMPACT)
**Module:** modules/osint_recon.py
**Problem:** Every engagement against an Apache server produced
two findings: "Server disclosed: Apache/2.4.7" from the server header
check AND "Tech fingerprinted: Apache" from the HTML fingerprint loop.
Same data source, two findings, different titles -- dedup MD5 missed it.
**Fix:** Added check before HTML fingerprinting: if the tech name
already appears in the server header string, skip creating a second
finding. Server disclosed finding is more specific (includes version)
and wins.

### Bug 9 -- DMARC Finding Type Wrong -- GRC Mapping Broken (LOW IMPACT)
**Module:** modules/osint_recon.py
**Problem:** DMARC missing was coded as finding_type="email_exposed"
which mapped to the email exposure NIST controls (AT-2, PL-4).
DMARC is a DNS configuration issue not an email exposure finding.
Wrong compliance controls were being reported.
**Fix:** Changed to finding_type="header_missing" which correctly
maps to SC-8, SI-16, CM-6 -- the configuration management controls
that actually apply to missing DNS security records.

### Bug 10 -- PDF Tab Character Glyph Warnings (LOW IMPACT)
**Module:** core/report_gen.py
**Problem:** Finding descriptions containing tab characters (\t)
caused fpdf2 to print "font missing glyph" warnings for every
tab character encountered. On findings from certain modules
this produced hundreds of terminal warnings during PDF generation.
**Fix:** Added _sanitize_for_pdf() function applied to all text
before passing to the PDF renderer. Replaces \t with four spaces,
strips null bytes and control characters, truncates to max_length.
Applied to every text field before it touches the renderer.

---

## Architecture Decisions

### Why Ollama and Not OpenAI API
Zero cost per run. Zero data leaving the machine.
Fully air-gappable for sensitive engagements.
For critical infrastructure work you cannot send data
to a cloud API. Local by design, not by configuration.

### Why Plan Before Coding
Every module worked first or second try because interfaces
were defined before implementation. The 4-day sprint was fast
because of the 14 months before it.

### Why Focused KB Files and Not Full Documents
Ollama's context window is approximately 8,000 tokens.
Full frameworks overflow it and produce generic output.
Focused KB files give the model exactly what it needs
for each finding type. Precision beats volume for local LLM.

### Why Org Type Selection
Loading only relevant frameworks reduces runtime by 40-60%,
improves Ollama output quality, and produces focused reports
operators can actually act on.

### Why Three-Tier LLM Attack Architecture
Tier 1 catches poorly configured targets fast.
Tier 2 catches targets that blocked Tier 1.
Tier 3 catches hardened targets using novel multi-turn sequences
from 14 months of original research outside published literature.

### Why Python Is Always the Final Authority on CVEs
LLMs hallucinate CVE IDs. A hallucinated CVE in a security report
is a credibility and accuracy failure. CVE IDs only come from
cve_engine.py querying real NVD data. Never from the LLM.

### Why Human in the Loop at Every Stage
AI automation without human oversight creates an accountability
vacuum. R3D enforces human decision-making at authorization,
at improvement suggestions, at SIEM push, and at every active
attack confirmation. The audit trail proves the human decided.

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
pip-audit: 1 known non-exploitable dependency CVE documented
bandit: 0 high/medium issues at release
pylint: 0 real errors at release
```

---

## Hardware

5070 Ti Laptop

---

## Performance

Typical engagement A to Z: 15-25 minutes

```
OSINT module        3-8 min
LLM attack          2-4 min (if AI surfaces found)
Traditional recon   3-5 min (top 1000 ports)
GRC mapper          1-2 min
Report generation   <1 min
```

Optimizations applied in patch sprint:
- DNS fallback eliminates 50s ISP timeout at start
- AI surface POST confirmation eliminates false positive
  LLM attack runs that added 8+ minutes on non-AI targets
- Private IP scope awareness skips irrelevant checks
- Duplicate suppression reduces finding noise

---
