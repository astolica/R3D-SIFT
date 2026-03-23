# R3D — Autonomous Red Team Agent

> Built by [Humza Sheikh](https://github.com/HumdoesCyber) | University of Arizona, Information Science  
> Status: **Active Development** | Week 1 of 3  
> Environment: University-approved lab environment  
> Donating to U of A Cyber Operations Program upon completion

---

## What is R3D?

R3D is a fully local, autonomous red team and GRC agent. You give it a target, it runs a full engagement across four modules, aggregates findings, maps them to compliance frameworks, and generates a professional report — all without a single cloud API call.

Built on an RTX 5070 Ti laptop. Powered by Ollama (llama3/mistral). Written in Python. Zero cost per run beyond hardware. Fully portable — runs from an external SSD on any machine with Ollama and Python installed.

This project was built from scratch as a learning exercise, portfolio piece, and research contribution. Every decision is documented. Every module is explained. The build log is public.

---

## Why This Exists

Most red team tools are either:
- Expensive SaaS platforms behind paywalls
- Raw scripts with no GRC context
- Cloud-dependent agents that cost money per run
- Heavy infrastructure requiring Docker, PostgreSQL, and full DevOps stacks

R3D is none of those. It runs locally, maps findings directly to NIST SP 800-53 and NERC CIP, and produces the kind of compliance-ready output that bridges the gap between technical operations and enterprise risk management.

The LLM attack module is built on 14+ months of original AI security research — specifically around social engineering vectors against LLM guardrails, a class of attack that sits outside the current OWASP LLM Top 10.

---

## Architecture

```
Target Input (domain / IP / org / LinkedIn URL)
                    │
                    ▼
        ┌─────────────────────────┐
        │     Master Orchestrator  │
        │  plans · routes · tracks │
        │  context summarization   │
        └──────┬──────────────────┘
               │
    ┌──────────┼──────────┬──────────┐
    ▼          ▼          ▼          ▼
 OSINT      LLM        Trad.       GRC
 Recon     Attack      Red Team    Module
 Module    Suite       Module
    │          │          │          │
    └──────────┴──────────┴──────────┘
                    │
                    ▼
        ┌─────────────────────────┐
        │   Ollama Local LLM       │
        │  llama3 · mistral        │
        │  runs on RTX 5070 Ti     │
        │  zero cost per call      │
        └─────────────────────────┘
                    │
                    ▼
        ┌─────────────────────────┐
        │   CVE Engine (Tiered)    │
        │  local DB → zero day     │
        │  flag → NVD API          │
        └─────────────────────────┘
                    │
                    ▼
        Findings Aggregator
        (dedup · severity · MITRE)
                    │
                    ▼
        Report Generator
        │                    │
        ▼                    ▼
   PDF Report          XLSX Risk Register
   + Telemetry Log     (NIST + NERC CIP)
```

---

## Modules

### 1. OSINT Recon
Passive reconnaissance only. Runs completely before any active module touches the target.

- WHOIS and registrar lookup
- DNS enumeration (A, MX, TXT, NS records)
- Certificate transparency logs via crt.sh
- Subdomain discovery
- Tech stack fingerprinting
- AI surface detection (finding exposed LLMs, chatbots, API endpoints)
- LinkedIn and social footprint mapping
- **Sherlock username enumeration** (GUIDED and SEMI-AUTO only — requires explicit consent)

### 2. LLM Attack Suite
Original research. Targets AI systems exposed on the target's surface.

- Prompt injection probing
- Jailbreak vector testing
- Social engineering against LLM guardrails
- Trust escalation sequences (Contextual Trust Accumulation)
- Context window manipulation
- Relational State Exploitation
- Data exfiltration vector mapping
- Multi-turn Crescendo attack simulation

### 3. Traditional Red Team
Standard offensive recon and surface analysis.

- Header security analysis
- SSL/TLS configuration audit
- CVE correlation against discovered tech stack
- Port and service mapping via nmap
- Endpoint discovery
- Exposed admin panel detection
- Subdomain enumeration

### 4. GRC Module
Translates every technical finding into compliance language automatically.

- NIST SP 800-53 control mapping
- NERC CIP mapping (relevant for critical infrastructure targets)
- Risk scoring (likelihood × impact)
- Control gap identification
- Remediation treatment recommendations
- Full risk register generation (XLSX)
- Exploitability-adjusted residual risk scoring

---

## CVE Engine — Tiered Lookup

R3D uses a three-tier CVE lookup system:

```
Agent finds a service/version on target
            │
            ▼
Tier 1 — Check local CVE database
            │
       Found? ──YES──► Return CVE, CVSS score, mapping. Done.
            │
            NO
            │
            ▼
Flag as: "Unmatched — Possible Zero Day"
Preserve ALL raw evidence for this scan
            │
            ▼
Pause — Ask operator: "Check NVD API? [Y/N]"
            │
           YES
            │
            ▼
Tier 2 — Query NVD API live
Cache result locally for future use
            │
       Found? ──YES──► Add to report
            │
            NO
            │
            ▼
Tier 3 — Flag as confirmed unknown
High priority finding in report
Raw evidence preserved in /output/evidence/
```

**Why this matters:** A local-first approach with zero day flagging means R3D doesn't guess when it hits something unfamiliar. Low confidence findings get flagged for human review — not hallucinated. This design is grounded in OpenAI's hallucination research (Kalai et al., 2025) showing models should abstain under uncertainty rather than guess.

---

## Evidence Preservation

Raw scan data is deleted immediately after parsing under normal operation.

**Exception — Zero Day Flag:** If the agent raises a zero day flag on any finding, all raw evidence is automatically preserved:

```
/output/evidence/
└── YYYY-MM-DD_target_zeroday_evidence.zip
    ├── raw_nmap_output.txt
    ├── raw_dns_records.txt
    ├── llm_reasoning_chain.json
    └── scan_metadata.json
```

This keeps storage minimal while ensuring unclassified findings are fully documented and defensible for responsible disclosure.

---

## Blue Team Telemetry

Every offensive action R3D takes generates a telemetry log entry:

```json
{
  "timestamp": "2026-03-22T19:52:00Z",
  "action": "prompt_injection_probe",
  "target": "target-domain.com/chatbot",
  "payload": "exact payload string sent",
  "response_summary": "model responded with...",
  "flag": "guardrail_bypassed",
  "mitre_technique": "T1566"
}
```

This allows defenders to correlate R3D's attack signatures against their own SIEM logs. The tool produces both offensive findings and defensive artifacts simultaneously.

---

## Operating Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `GUIDED` | Agent proposes every action, operator approves before execution | Default, demos, learning |
| `SEMI-AUTO` | Recon and analysis autonomous, pauses before active actions | Lab engagements |
| `FULL-AUTO` | Fully autonomous, flags only on critical findings or errors | Controlled lab only |

---

## Capability Matrix

| Capability | GUIDED | SEMI-AUTO | FULL-AUTO |
|-----------|--------|-----------|-----------|
| OSINT passive recon | ✅ | ✅ | ✅ |
| DNS / subdomain enum | ✅ | ✅ | ✅ |
| AI surface detection | ✅ | ✅ | ✅ |
| Sherlock username lookup | ✅ | ✅ | ❌ |
| Nmap port scanning | ✅ | ✅ | ✅ |
| LLM attack probing | ✅ | ✅ | ✅ |
| CVE correlation | ✅ | ✅ | ✅ |
| GRC mapping | ✅ | ✅ | ✅ |
| Report generation | ✅ | ✅ | ✅ |
| Metasploit integration | ✅ | ✅ | ❌ |

*Metasploit integration planned for v2.*

---

## Consent and Authorization

R3D requires explicit operator confirmation before running any powerful capability.

**Sherlock consent prompt:**
```
⚠ You are about to run Sherlock username enumeration.
Target: [discovered username/email]
Platforms: 300+ social media sites

You are responsible for ensuring you have authorization
to perform this reconnaissance. R3D and its creator
accept no liability for unauthorized use.

Proceed? [Y/N]
```

**Metasploit consent prompt (v2):**
```
⚠ You are about to execute an exploit module.
Module: [exact module path]
Target: [IP:PORT]
Payload: [payload type and parameters]

This action is irreversible and may cause system
instability. Ensure you have explicit written
authorization for this target.

Proceed? [Y/N]
```

Typing Y is required — pressing Enter alone does nothing. Deliberate friction by design.

---

## Tech Stack

```
CORE
├── ollama          # Local LLM client
├── pydantic        # Enforces clean data schemas between modules
└── rich            # Terminal UI — colored output, spinners, live logs

RECON
├── httpx           # Async HTTP — parallel subdomain/endpoint checks
├── dnspython       # DNS enumeration
├── beautifulsoup4  # Web scraping for AI surface detection
└── python-nmap     # Port and service scanning

SECURITY
└── shlex           # Shell injection prevention on LLM-generated inputs

REPORTING
├── pandas          # Data manipulation
├── openpyxl        # XLSX risk register generation
└── fpdf2           # PDF report generation
```

---

## Project Structure

```
r3d-agent/
├── README.md
├── requirements.txt
├── .gitignore
├── main.py                    # Entry point
├── modules/
│   ├── orchestrator.py        # Master agent loop + context summarization
│   ├── osint_recon.py         # OSINT module + Sherlock integration
│   ├── llm_attack.py          # LLM attack suite
│   ├── traditional_recon.py   # Traditional red team
│   └── grc_mapper.py          # GRC and risk register
├── core/
│   ├── llm_client.py          # Ollama wrapper
│   ├── cve_engine.py          # Tiered CVE lookup system
│   ├── findings.py            # Aggregator and deduplication
│   └── report_gen.py          # PDF + XLSX + telemetry log generation
├── output/                    # Generated reports — never pushed to GitHub
└── docs/
    ├── architecture.md
    ├── build-log.md
    ├── resources.md
    ├── lab-setup.md
    └── my-approach.md         # Written last. How I think.
```

---

## Performance Reference

Tested on: Acer Predator Helios Neo 16 AI | RTX 5070 Ti 12GB | 32GB DDR5

| Metric | Value |
|--------|-------|
| LLM inference speed | ~80-120 tokens/sec |
| Time per full engagement | ~10-15 minutes |
| Scans per 24 hours | ~96-144 |
| Storage after 1 month | ~35-40GB |
| Model size (llama3:8b) | 4.7GB |
| Local CVE database | ~15-20GB |

Also tested on: Lenovo IdeaPad Gaming 3i | GTX 1650 Ti | 16GB DDR4
CPU inference fallback — ~5-10 minutes per engagement. Slower but functional.

---

## Setup

### Prerequisites
- Python 3.12 (not 3.14 — library compatibility)
- [Ollama](https://ollama.com) installed locally
- llama3 pulled: `ollama pull llama3`

### Install

```bash
git clone git@github.com:HumdoesCyber/r3d-agent.git
cd r3d-agent
pip install -r requirements.txt
```

### Run

```bash
python main.py --target example.com --mode guided
```

### Portability

```powershell
$env:OLLAMA_MODELS = "E:\ollama\models"
ollama serve
```

Set `OLLAMA_MODELS` to your external drive letter. Prerequisites on any new machine: Ollama installed, Python 3.12 installed. That's it.

---

## Ethical Use

This tool was built for and is intended for use exclusively in:
- University-approved lab environments
- Systems you own or have explicit written permission to test
- Educational and research purposes

Running this against systems without authorization is illegal under the CFAA regardless of intent. The `GUIDED` mode default and consent popups exist to prevent accidental active scanning and create a clear record of operator authorization.

**Responsible disclosure:** Zero day findings flagged by R3D should be reported to the affected organization before any public disclosure. Raw evidence is preserved automatically to support this process.

This project is being donated to the University of Arizona Cyber Operations program upon completion.

---

## Planned Features — v2

- **Metasploit integration** via pymetasploit3 — GUIDED and SEMI-AUTO only, explicit consent required, LLM maps discovered CVE to specific module
- **NVD API key support** — live CVE lookup when local database misses
- **Claude Code integration** — optional API module for report enhancement

---

## Build Log

| Week | Status | Focus |
|------|--------|-------|
| Week 1 | 🔨 In Progress | Foundation, Git/GitHub, Ollama, OSINT module |
| Week 2 | ⏳ Pending | LLM attack suite, traditional recon, GRC module |
| Week 3 | ⏳ Pending | Integration, report generation, full demo run |

Full journal: [docs/build-log.md](docs/build-log.md)

---

## Research Foundation

The LLM attack module is grounded in original research on AI guardrail manipulation — specifically social engineering techniques to bypass LLM safety systems through gradual trust accumulation rather than direct injection. This attack class sits outside the current OWASP LLM Top 10.

CVE engine design is informed by Kalai et al. (2025) — proving mathematically that models should abstain under uncertainty rather than guess. R3D's tiered lookup implements this: unknown findings get flagged, not fabricated.

Structured output architecture follows the four-layer prompting pattern (schema + example + rules + validation). Every LLM call uses pydantic schema validation with targeted repair prompts on failure.

Full reading list: [docs/resources.md](docs/resources.md)

---

## How This Was Built

Every architectural decision was made before a single line of code was written. Ethical boundaries defined first, features built second. The full thinking behind this is in [docs/my-approach.md](docs/my-approach.md) — written last, after everything else.

---

*Built with Ollama · Python · original research · and a lot of late nights.*  
*Started: March 22, 2026*
