# R3D — Autonomous Red Team Agent

> Built by [Humza Sheikh](https://github.com/HumdoesCyber) | University of Arizona, Information Science  
> Status: **Active Development** | Week 1 of 3  
> Environment: University-approved lab environment

---

## What is R3D?

R3D is a fully local, autonomous red team and GRC agent. You give it a target, it runs a full engagement across four modules, aggregates findings, maps them to compliance frameworks, and generates a professional report — all without a single cloud API call.

Built on an RTX 5070 laptop. Powered by Ollama (llama3/mistral). Zero cost per run beyond hardware.

This project was built from scratch as a learning exercise, portfolio piece, and research contribution. Every decision is documented. Every module is explained. The build log is public.

---

## Why This Exists

Most red team tools are either:
- Expensive SaaS platforms behind paywalls
- Raw scripts with no GRC context
- Cloud-dependent agents that cost money per run

R3D is none of those. It runs locally, maps findings directly to NIST SP 800-53 and NERC CIP, and produces the kind of compliance-ready output that bridges the gap between technical operations and enterprise risk management.

The LLM attack module is built on 14+ months of original AI security research — specifically around social engineering vectors against LLM guardrails, a class of attack that sits outside the current OWASP LLM Top 10.

---

## Architecture

```
Target Input (domain / IP / org / LinkedIn)
        │
        ▼
┌─────────────────────────────┐
│      Master Orchestrator     │
│  plans · routes · tracks     │
└──────┬──────────────────────┘
       │
  ┌────┴────┬──────────┬──────────┐
  ▼         ▼          ▼          ▼
OSINT    LLM Attack  Trad. RT    GRC
Recon    Suite       Module      Module
  │         │          │          │
  └────┬────┴──────────┴──────────┘
       ▼
┌─────────────────────────────┐
│     Ollama Local LLM         │
│  llama3 · mistral · local    │
└─────────────────────────────┘
       │
       ▼
Findings Aggregator
(dedup · severity · MITRE map)
       │
       ▼
Report Generator
       │
  ┌────┴────────────┐
  ▼                 ▼
PDF Report      XLSX Risk Register
                (NIST + NERC CIP)
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
- LinkedIn/social footprint mapping

### 2. LLM Attack Suite
Original research. Targets AI systems exposed on the target's surface.

- Prompt injection probing
- Jailbreak vector testing
- Social engineering against LLM guardrails
- Trust escalation sequences
- Context window manipulation
- Data exfiltration vector mapping

### 3. Traditional Red Team
Standard offensive recon and surface analysis.

- Header security analysis
- SSL/TLS configuration audit
- CVE correlation against discovered tech stack
- Port and service mapping (via nmap)
- Endpoint discovery
- Exposed admin panel detection

### 4. GRC Module
Translates technical findings into compliance language.

- NIST SP 800-53 control mapping
- NERC CIP mapping (relevant for critical infrastructure targets)
- Risk scoring (likelihood × impact)
- Control gap identification
- Remediation treatment recommendations
- Full risk register generation

---

## Operating Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `GUIDED` | Agent proposes every action, you approve before execution | Default, demos, learning |
| `SEMI-AUTO` | Recon and analysis run autonomously, pauses before active actions | Lab engagements |
| `FULL-AUTO` | Fully autonomous, flags only on critical findings or errors | Controlled lab only |

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
├── config.yaml
├── main.py                    # Entry point
├── modules/
│   ├── orchestrator.py        # Master agent loop
│   ├── osint_recon.py         # OSINT module
│   ├── llm_attack.py          # LLM attack suite
│   ├── traditional_recon.py   # Traditional red team
│   └── grc_mapper.py          # GRC and risk register
├── core/
│   ├── llm_client.py          # Ollama wrapper
│   ├── findings.py            # Aggregator and deduplication
│   └── report_gen.py          # PDF + XLSX generation
├── output/                    # Generated reports
└── docs/
    ├── architecture.md        # Deep dive on agent design
    ├── build-log.md           # Weekly engineering journal
    └── lab-setup.md           # How to set up the lab environment
```

---

## Setup

### Prerequisites
- Python 3.11+
- [Ollama](https://ollama.com) installed locally
- llama3 model pulled: `ollama pull llama3`

### Install

```bash
git clone https://github.com/HumdoesCyber/r3d-agent
cd r3d-agent
pip install -r requirements.txt
```

### Run

```bash
python main.py --target example.com --mode guided
```

---

## Ethical Use

This tool was built for and is intended for use exclusively in:
- University-approved lab environments
- Systems you own or have explicit written permission to test
- Educational and research purposes

Running this against systems without authorization is illegal. The `GUIDED` mode default exists precisely to prevent accidental active scanning.

This project is being donated to the University of Arizona Cyber Operations program upon completion.

---

## Build Log

Weekly updates documenting every decision, every problem, every fix.

| Week | Status | Focus |
|------|--------|-------|
| Week 1 | 🔨 In Progress | Foundation, Ollama setup, OSINT module |
| Week 2 | ⏳ Pending | LLM attack suite, traditional recon, GRC module |
| Week 3 | ⏳ Pending | Integration, report generation, full demo |

Full journal: [docs/build-log.md](docs/build-log.md)

---

## Research Background

The LLM attack module is grounded in original research conducted over 14 months on AI guardrail manipulation — specifically the use of social engineering techniques to bypass LLM safety systems through gradual trust accumulation rather than direct injection. This attack class predates its formal classification and sits outside the current OWASP LLM Top 10.

Related work: TEP LLM Vulnerability Assessment (2025) — a risk register mapping AI attack vectors to NERC CIP and NIST SP 800-53 controls for a critical infrastructure target.

---

*Built with Ollama · Python · and a lot of late nights on the bus.*
