# R3D -- Autonomous Red Team Agent

> Bridges the gap between technical security and GRC compliance.
> One run. One report. Both sides of the aisle.

**Fully local. No cloud APIs. No cost per run. Everything stays on your machine.**

*Built with Ollama · Python · original research · and a lot of late nights.*
*Started: March 2026*

---

## What R3D Does

Most security tools live in one room. They find vulnerabilities
and hand over a PDF. The GRC team never sees it in their language.
The technical team never speaks compliance.

R3D lives in both rooms simultaneously.

It runs autonomous reconnaissance, attacks AI surfaces using
original research vectors, correlates CVEs against live services,
and automatically maps every finding to NIST 800-53, NERC CIP,
ISO 27001, CIS Controls, and NIST AI RMF.

One engagement. One report. Technical and compliance output combined.

---

## Architecture

```
python main.py --target example.com --mode guided
       │
       ▼
┌─────────────────────────────────────────────────┐
│  CORE LAYER                                     │
│  banner.py          Wizard terminal UI          │
│  findings.py        MITRE + OWASP mapping       │
│  llm_client.py      Ollama wrapper              │
│  cve_engine.py      NVD CVE correlation         │
│  report_gen.py      PDF + XLSX + telemetry      │
│  verifier.py        Hallucination detection     │
│  improvement_engine.py  Self-improvement loop   │
└─────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────┐
│  MODULE PIPELINE                                │
│                                                 │
│  1. osint_recon.py                              │
│     Passive recon -- 10 checks                  │
│     WHOIS, DNS, subdomains, Google/DDG dorking  │
│     Wayback Machine, tech stack, WAF detection  │
│     Email harvesting, Sherlock, breach checking │
│                                                 │
│  2. llm_attack.py                               │
│     3-tier attack architecture                  │
│     Tier 1: 30 static payloads (8 categories)  │
│     Tier 2: KB-guided adaptive via Ollama       │
│     Tier 3: Original research sequences         │
│             TEP-005: Contextual Trust Accum.    │
│             TEP-010: Relational State Exploit.  │
│                                                 │
│  3. traditional_recon.py                        │
│     Port scan + service detection + CVE         │
│     SSL/TLS audit, security headers             │
│     Endpoint discovery, JS bundle analysis      │
│     WAF bypass attempt                          │
│                                                 │
│  4. grc_mapper.py                               │
│     Org type selection (5 types)                │
│     Framework loading (relevant only)           │
│     Risk register XLSX                          │
│     Compliance map XLSX                         │
│     Executive summary via Ollama                │
└─────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────┐
│  OUTPUT                                         │
│  PDF executive report                           │
│  XLSX risk register (MITRE + OWASP + frameworks)│
│  XLSX compliance map (one sheet per framework)  │
│  JSON telemetry log (blue team artifact)        │
└─────────────────────────────────────────────────┘
```

---

## Capability Matrix

| Capability                    | Status  | Notes                              |
|-------------------------------|---------|------------------------------------|
| Passive OSINT recon           | ✅ Live  | 10 checks, rate limited            |
| WAF detection                 | ✅ Live  | 8 vendor signatures                |
| LLM surface discovery         | ✅ Live  | 20+ endpoint signatures            |
| Static payload attacks        | ✅ Live  | 30 payloads, 8 categories          |
| Adaptive KB-guided attacks    | ✅ Live  | Ollama RAG generation              |
| Original research sequences   | ✅ Live  | TEP-005, TEP-010 (auth installs)   |
| Port scan + CVE correlation   | ✅ Live  | Nmap + NVD API                     |
| SSL/TLS audit                 | ✅ Live  | Protocol + cert expiry             |
| Security header analysis      | ✅ Live  | CSP quality check included         |
| JS bundle secret scanning     | ✅ Live  | AWS, API keys, internal URLs       |
| NIST SP 800-53 mapping        | ✅ Live  | All finding types mapped           |
| NERC CIP mapping              | ✅ Live  | CIP-002 through CIP-015            |
| ISO 27001:2022 mapping        | ✅ Live  | All 4 themes covered               |
| CIS Controls v8 mapping       | ✅ Live  | IG1/IG2/IG3 levels                 |
| NIST AI RMF mapping           | ✅ Live  | Auto-loads on AI surfaces          |
| Hallucination verification    | ✅ Live  | NVD CVE validation + dedup         |
| Self-improvement engine       | ✅ Live  | Pattern analysis + suggestions     |
| Engagement checkpointing      | ✅ Live  | --resume support                   |
| Metasploit integration        | 🔲 v2   | GUIDED/SEMI-AUTO gated             |
| Docker packaging              | 🔲 v2   | Enterprise on-prem deployment      |

---

## Compliance Frameworks

R3D loads only what applies to your organization type.

| Org Type                 | Frameworks Loaded                          |
|--------------------------|--------------------------------------------|
| Personal / Researcher    | CIS Controls v8                            |
| Small Business           | CIS Controls v8 + NIST SP 800-53          |
| Enterprise               | NIST SP 800-53 + ISO 27001:2022           |
| Critical Infrastructure  | NERC CIP + NIST SP 800-53 + NIST AI RMF  |
| All                      | Everything above                           |

NIST AI RMF loads automatically whenever AI surfaces are
discovered -- regardless of organization type selected.

---

## Operating Modes

| Mode        | Behavior                                           |
|-------------|----------------------------------------------------|
| `guided`    | Approve every action -- Y/N for each check         |
| `semi-auto` | Passive recon auto, active attacks manual          |
| `full-auto` | Everything automatic -- controlled lab use only    |

Sherlock username enumeration is always blocked in FULL-AUTO.
Authorization consent screen runs before every engagement.

---

## Quick Start

```bash
# 1. Clone and install
git clone git@github.com:HumdoesCyber/r3d-agent.git
cd r3d-agent
python -m venv venv
venv\Scripts\activate       # Windows
pip install -r requirements.txt
ollama pull llama3:8b

# 2. Verify setup
python main.py --test-connection

# 3. Run your first engagement
python main.py --target scanme.nmap.org --mode guided
```

---

## All CLI Flags

```
Engagement:
  --target          Domain or IP (https:// stripped automatically)
  --mode            guided / semi-auto / full-auto
  --full-scan       All 65535 ports (default: top 1000)
  --auto-attack     LLM attacks without confirmation
  --org-type        personal / small_business / enterprise /
                    critical_infrastructure / all
  --resume          Resume interrupted engagement
  --skip-llm        Skip LLM attack module
  --skip-trad       Skip traditional recon
  --timeout         Seconds before timeout (default: 2700 = 45min)
  --fast-mode       Reduce delays for testing

Utilities:
  --test-connection Verify all 6 dependencies with fix hints
  --setup-cve-db    Download NVD CVE database locally
  --improve         Run improvement engine (needs 3+ engagements)
  --update          git pull + pip install
  --cleanup         Remove old engagement files
  --older-than      Days threshold for cleanup (default: 30)
```

---

## Sample Output

First live engagement against scanme.nmap.org:

```
====================================================
  R3D ENGAGEMENT COMPLETE
  ID     : R3D_20260324_015715_scanme_nmap_org
  Target : scanme.nmap.org
  Mode   : GUIDED
  Time   : 28m 50s
====================================================

Findings Summary
┏━━━━━━━━━━━┳━━━━━━━┓
┃ Severity  ┃ Count ┃
┡━━━━━━━━━━━╇━━━━━━━┩
│ MEDIUM    │     1 │
│ LOW       │     8 │
│ TOTAL     │     9 │
└───────────┴───────┘

  → DMARC missing -- email spoofing risk
  → HSTS missing
  → CSP missing
  → X-Frame-Options missing
  → X-Content-Type-Options missing

Output files:
  → PDF executive report
  → XLSX risk register (all 5 frameworks)
  → XLSX compliance map
  → JSON telemetry log
```

---

## Research Foundation

The LLM attack module is grounded in original research
on AI guardrail manipulation -- specifically social
engineering techniques that bypass LLM safety systems
through gradual trust accumulation rather than direct
injection. This attack class sits outside the current
OWASP LLM Top 10.

**TEP-005 -- Contextual Trust Accumulation**
Multi-turn protocol that builds conversational trust
across 8 turns before extracting sensitive information.
The attack emerges from the sequence as a whole --
no single turn looks malicious in isolation.

**TEP-010 -- Relational State Exploitation**
Extracts a commitment from the LLM in turn one,
then uses consistency pressure to bypass guardrails
in subsequent turns.

CVE engine design follows the principle that unknown
findings should be flagged, not fabricated. R3D's
tiered lookup implements this: unclassified services
get zero-day flags with preserved evidence, never
hallucinated CVE IDs.

Tier 3 is available to authorized installations only.
Tiers 1 and 2 are fully functional on all installations.

Full reading list: [docs/resources.md](docs/resources.md)

---

## How This Was Built

Every architectural decision was made before a single
line of code was written. Ethical boundaries defined
first, features built second.

180+ hours of total work:
- 14 months of original AI security research
- Real client engagements and compliance work
- 10 hours of architecture planning pre-build
- ~38 hours of focused build sprint

The full thinking behind this is in
[docs/my-approach.md](docs/my-approach.md) --
written last, after everything else.

---

## Planned Features -- v2

```
Metasploit integration    GUIDED/SEMI-AUTO gated, operator liability
Self-improvement agent    Automated KB and payload updates
Docker packaging          Enterprise on-prem appliance
Healthcare KB files       HIPAA + sector-specific compliance
Finance KB files          SOC 2 + PCI-DSS mapping
Update agent              Pulls new MITRE ATLAS techniques
```

---

## Repository Structure

```
r3d-agent/
├── main.py                    CLI entry point
├── requirements.txt
├── core/
│   ├── banner.py              Wizard terminal UI
│   ├── llm_client.py          Ollama wrapper
│   ├── cve_engine.py          CVE lookup engine
│   ├── findings.py            MITRE + OWASP aggregator
│   ├── report_gen.py          PDF + XLSX + telemetry
│   ├── verifier.py            Hallucination detection
│   └── improvement_engine.py  Self-improvement loop
├── modules/
│   ├── osint_recon.py         Passive recon (10 checks)
│   ├── llm_attack.py          3-tier LLM attack suite
│   ├── traditional_recon.py   Port scan + CVE + JS
│   ├── grc_mapper.py          Compliance framework mapper
│   └── orchestrator.py        Master engagement sequencer
├── data/
│   ├── compliance_kb/         NIST, NERC, CIS, ISO, AI RMF
│   ├── llm_attack_kb/         MITRE ATLAS, OWASP LLM, patterns
│   └── payloads/              Static injection library (30 payloads)
├── docs/
│   ├── user-guide.md          Complete operations manual
│   ├── build-log.md           Engineering journal
│   └── my-approach.md         Philosophy and design decisions
└── output/                    Generated per engagement
    ├── reports/
    ├── engagements/
    ├── profiles/
    └── attack_logs/
```

---

## Project Stats

```
Language:         Python 3.12
Commits:          21
Total work:       180+ hours (14 months research + 4 day sprint)
First engagement: scanme.nmap.org -- 28m 50s -- 9 findings
Hardware:         RTX 5070 Ti laptop
LLM:              llama3:8b via Ollama (fully local)
Frameworks:       NIST 800-53, NERC CIP, ISO 27001,
                  CIS Controls v8, NIST AI RMF
```

---

## Ethical Use

This tool must only be used against systems you own
or have explicit written authorization to test.

The authorization consent screen runs before every
engagement and creates a documented record of intent.
Unauthorized use violates the CFAA and equivalent
laws internationally.

---

## Author

**HumdoesCyber**
University of Arizona -- Information Science
Senior, graduating May 2026

14 months of original AI security research.
Real client engagements. Real compliance work.
Built to close the gap between technical security and GRC.

---

## License

Private repository. All rights reserved.
Contact via GitHub for collaboration or research inquiries.