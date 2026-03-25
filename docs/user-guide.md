# R3D User Guide
## Operations Manual v1.0
### Author: Humza Sheikh (HumdoesCyber)

---

## What is R3D?

R3D is a fully local autonomous purple team agent that bridges
the gap between technical security and GRC compliance.

It finds vulnerabilities AND maps them to compliance frameworks
automatically. It generates blue team telemetry for SIEM
ingestion alongside offensive findings. One run. One report.
Red team findings. Blue team artifacts. GRC compliance output.

Fully local. No cloud APIs. No cost per run.
Everything stays on your machine.

---

## System Requirements

### Hardware
- RAM: 8GB minimum, 16GB recommended
- GPU: NVIDIA recommended (RTX 5070 Ti tested)
- Storage: 20GB free minimum
- OS: Windows 10/11, Ubuntu, Kali Linux

### Software (install manually)
- Python 3.12 -- python.org/downloads
- Nmap 7.95+ -- nmap.org/download
- Ollama 0.18+ -- ollama.com
- Git 2.x -- git-scm.com

### Python packages (auto-installed)
All packages via: `pip install -r requirements.txt`

### AI Models (download once)
- llama3:8b -- `ollama pull llama3:8b` (4.7GB)

---

## Setup Guide A to Z

### Step 1 -- Install Python 3.12
Go to python.org/downloads.
During install CHECK "Add Python to PATH".
Verify:
```
python --version
# Python 3.12.x
```

### Step 2 -- Install Git
Go to git-scm.com. Accept all defaults.
Verify:
```
git --version
# git version 2.x.x
```

### Step 3 -- Install Ollama
Go to ollama.com. Download for your OS. Install.
Pull the model:
```
ollama pull llama3:8b
```
Takes 5-15 minutes (4.7GB download).
Verify:
```
ollama list
# shows llama3:8b
```

### Step 4 -- Install Nmap
Go to nmap.org/download.
Windows: download the .exe installer.
Check "Add to PATH" during install.
Verify:
```
nmap --version
# Nmap 7.95
```

### Step 5 -- Clone R3D
```
git clone git@github.com:HumdoesCyber/r3d-agent.git
cd r3d-agent
```

### Step 6 -- Virtual environment and dependencies
```
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac
pip install -r requirements.txt
```
Takes 2-3 minutes.

### Step 7 -- Download CVE database (optional but recommended)
```
python main.py --setup-cve-db
```
Downloads 295,406 CVEs from NVD locally.
Takes 30-60 minutes. Only needed once.
R3D works without it but CVE correlation is limited.

### Step 8 -- Verify everything
```
python main.py --test-connection
```
Checks Python, Ollama, Nmap, CVE database, internet.
All green = ready to run.

---

## Running R3D

### Basic usage
```
python main.py --target example.com --mode guided
```

---

## Complete Command Reference

Every command R3D accepts. A to Z.

---

### UTILITY COMMANDS
Run without --target. No engagement started.

```
# Verify all 6 dependencies before running anything
# Shows Python, Nmap, Ollama, llama3:8b, CVE DB, internet
# Run this first on any new machine
python main.py --test-connection

# Download NVD CVE database locally (295,406 CVEs)
# Takes 30-60 minutes. Only needed once.
# R3D works without it but CVE correlation is limited
python main.py --setup-cve-db

# Pull latest code from GitHub + update all dependencies
# Checks git status before pulling -- warns on local changes
python main.py --update

# Run improvement engine
# Reads verification reports, finds patterns in what fails
# Generates ranked KB and payload suggestions
# Requires 3+ prior engagements
# You approve every suggestion -- nothing auto-modified
python main.py --improve

# Remove engagement files older than 30 days (default)
# Shows what will be deleted before asking confirmation
python main.py --cleanup

# Remove engagement files older than N days
python main.py --cleanup --older-than 7
python main.py --cleanup --older-than 14
python main.py --cleanup --older-than 60
python main.py --cleanup --older-than 90
```

---

### CORE ENGAGEMENT FLAGS

```
# --target
# Required for all engagements
# Accepts domain or IP -- strips https:// automatically
python main.py --target example.com
python main.py --target subdomain.example.com
python main.py --target 192.168.1.1
python main.py --target 10.0.0.1

# --mode
# Sets operating mode for the entire engagement
# Default is semi-auto if not specified
python main.py --target example.com --mode guided
python main.py --target example.com --mode semi-auto
python main.py --target example.com --mode full-auto

# --org-type
# Sets compliance framework loading -- skips the menu prompt
# Default: menu shown at engagement start
python main.py --target example.com --org-type personal
python main.py --target example.com --org-type small_business
python main.py --target example.com --org-type enterprise
python main.py --target example.com --org-type critical_infrastructure
python main.py --target example.com --org-type all
```

---

### SCAN DEPTH FLAGS

```
# --full-scan
# Scans all 65535 ports instead of top 1000
# Adds 15-25 minutes to engagement time
# Use when standard scan returns nothing or target is hardened
python main.py --target example.com --full-scan

# --fast-mode
# Reduces delays between checks for testing
# Never use on real targets -- may trigger rate limiting or WAF
# Use for local lab testing and development only
python main.py --target example.com --fast-mode
```

---

### ATTACK CONTROL FLAGS

```
# --auto-attack
# LLM attacks run without per-surface confirmation
# Each AI surface attacked automatically
# Implied automatically when --mode full-auto is set
python main.py --target example.com --auto-attack

# --skip-llm
# Skip LLM attack module entirely
# Use when target has no AI surfaces or you only want recon
python main.py --target example.com --skip-llm

# --skip-trad
# Skip traditional recon module (nmap, CVE, SSL, headers)
# Use when you only want OSINT and compliance mapping
python main.py --target example.com --skip-trad
```

---

### ENGAGEMENT MANAGEMENT FLAGS

```
# --resume
# Resumes an interrupted engagement from last checkpoint
# Reads state.json, skips completed modules
# Works after crashes, timeouts, or manual interrupts
python main.py --target example.com --resume

# --timeout
# Sets engagement timeout in seconds
# Default: 2700 (45 minutes)
# Engagement stops cleanly after current module completes
python main.py --target example.com --timeout 1800   # 30 min
python main.py --target example.com --timeout 2700   # 45 min (default)
python main.py --target example.com --timeout 3600   # 60 min
python main.py --target example.com --timeout 5400   # 90 min
python main.py --target example.com --timeout 7200   # 2 hours
```

---

### COMMON COMBINATIONS

```
# First time use -- approve everything, learn the tool
python main.py --target example.com --mode guided

# Standard lab engagement -- semi-auto, enterprise compliance
python main.py --target example.com --mode semi-auto --org-type enterprise

# Full port scan engagement -- standard mode
python main.py --target example.com --mode semi-auto --full-scan

# Full port scan + enterprise + extended timeout
python main.py --target example.com --mode semi-auto --full-scan --org-type enterprise --timeout 5400

# Critical infrastructure engagement
python main.py --target example.com --mode guided --org-type critical_infrastructure

# OSINT only -- skip all active scanning
python main.py --target example.com --skip-trad --skip-llm

# OSINT + compliance only -- no attacks, no port scan
python main.py --target example.com --skip-trad --skip-llm --org-type small_business

# Full auto lab engagement -- everything runs
python main.py --target example.com --mode full-auto --auto-attack --org-type enterprise

# Full auto with full port scan -- deep lab engagement
python main.py --target example.com --mode full-auto --auto-attack --full-scan --org-type all

# Fast mode dev test -- skip active modules, no delays
python main.py --target example.com --skip-trad --skip-llm --fast-mode

# Fast mode full test -- everything but reduced delays
python main.py --target example.com --mode full-auto --auto-attack --fast-mode

# Resume after crash -- picks up where it stopped
python main.py --target example.com --resume

# Resume with extended timeout -- if prior run timed out
python main.py --target example.com --resume --timeout 7200

# Resume full-auto -- continue unattended after interrupt
python main.py --target example.com --mode full-auto --resume --auto-attack

# Pre-specified org type -- skip menu on resume
python main.py --target example.com --resume --org-type enterprise

# Quick scan no LLM -- port scan + compliance only
python main.py --target example.com --skip-llm --org-type small_business

# Deep engagement -- full scan, all frameworks, max timeout
python main.py --target example.com --mode semi-auto --full-scan --org-type all --timeout 7200

# Silent recon -- OSINT only, guided, personal researcher
python main.py --target example.com --mode guided --skip-trad --skip-llm --org-type personal

# Critical infra full engagement
python main.py --target example.com --mode guided --full-scan --org-type critical_infrastructure --timeout 5400
```

---

### FLAG REFERENCE TABLE

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | required | Domain or IP to assess |
| `--mode` | semi-auto | guided / semi-auto / full-auto |
| `--full-scan` | off | Scan all 65535 ports |
| `--auto-attack` | off | LLM attacks without confirmation |
| `--org-type` | menu | Compliance framework selection |
| `--resume` | off | Resume from last checkpoint |
| `--skip-llm` | off | Skip LLM attack module |
| `--skip-trad` | off | Skip traditional recon |
| `--timeout` | 2700 | Engagement timeout in seconds |
| `--fast-mode` | off | Reduce delays (testing only) |
| `--test-connection` | — | Verify all 6 dependencies |
| `--setup-cve-db` | — | Download NVD CVE database |
| `--update` | — | Pull latest code and deps |
| `--improve` | — | Run improvement engine |
| `--cleanup` | — | Remove old engagement files |
| `--older-than` | 30 | Days threshold for cleanup |

---

## Operating Modes

### GUIDED (recommended for first use)
Every action requires your approval before executing.
Use for: first time use, sensitive targets, learning the tool.
```
python main.py --target example.com --mode guided
```

### SEMI-AUTO (default)
Passive reconnaissance runs automatically.
Active attacks pause for your confirmation.
Use for: most engagements.
```
python main.py --target example.com --mode semi-auto
```

### FULL-AUTO (lab only)
Everything runs automatically without prompts.
Sherlock username enumeration is ALWAYS blocked in this mode.
Use ONLY in controlled lab environments you own.
```
python main.py --target example.com --mode full-auto --auto-attack
```

---

## Organization Type Selection

R3D asks once per engagement which type of organization
you are assessing. This loads only the relevant compliance
frameworks -- faster runtime, better output quality,
more focused reports.

```
[1] Personal / Researcher
    Frameworks: CIS Controls v8

[2] Small Business
    Frameworks: CIS Controls v8 + NIST SP 800-53

[3] Enterprise
    Frameworks: NIST SP 800-53 + ISO 27001:2022

[4] Critical Infrastructure
    Frameworks: NERC CIP + NIST SP 800-53 + NIST AI RMF

[5] All Frameworks
    Frameworks: Everything above
```

NIST AI RMF loads automatically on any org type
if AI surfaces are discovered during OSINT.

For critical infrastructure targets, R3D includes NERC CIP
financial penalty context (up to $1M/day per violation)
in the executive report.

---

## What R3D Does -- Module by Module

### OSINT Reconnaissance (3-8 minutes)
Passive information gathering. No active probing.
- DNS enumeration and subdomain discovery
- WHOIS and registrar information
- Certificate transparency log search
- Google and DuckDuckGo dorking (auto-fallback)
- Email harvesting from public sources
- Sherlock username enumeration (GUIDED/SEMI-AUTO only)
- HaveIBeenPwned breach check
- GitHub secret scanning
- WAF detection (8 vendor signatures)
- Tech stack fingerprinting
- AI surface discovery (20+ endpoint signatures)

### LLM Attack Suite (2-4 minutes)
Only runs if AI surfaces discovered by OSINT.

Three-tier architecture:
- Tier 1: 30 static payloads across 8 attack categories
           MITRE ATLAS tagged and scored
- Tier 2: KB-guided adaptive payloads via Ollama
           Adapts based on what Tier 1 found
- Tier 3: Original AI security research sequences
           Multi-turn attack vectors outside OWASP LLM Top 10
           Authorized installations only

### Traditional Reconnaissance (3-5 minutes)
Active scanning. Requires authorization.
- Port scanning (top 1000 default, all 65535 with --full-scan)
- Service version detection
- CVE correlation (295,406 CVEs local NVD database)
- SSL/TLS audit + certificate expiry check
- Security headers deep analysis (CSP quality scoring)
- 49-path endpoint discovery
- JavaScript bundle analysis for secrets
- WAF bypass attempt (only if WAF detected by OSINT)

### GRC Compliance Mapping (1-2 minutes)
Translates every technical finding into compliance language.
- Risk register XLSX with severity-based due dates
- Compliance map XLSX (one sheet per loaded framework)
- Executive summary in plain English via Ollama
- NERC CIP financial penalty context for critical infrastructure

### Report Generation (<1 minute)
- PDF executive report (board/CISO ready)
- XLSX risk register (MITRE + OWASP + all frameworks)
- XLSX compliance map
- JSON telemetry log (SIEM-ready blue team artifact)
- Verification report (hallucination audit trail)

---

## Understanding Your Outputs

Every engagement produces files tied to the same engagement ID:
```
R3D_YYYYMMDD_HHMMSS_TARGET_report.pdf
R3D_YYYYMMDD_HHMMSS_TARGET_risk_register.xlsx
R3D_YYYYMMDD_HHMMSS_TARGET_compliance_map.xlsx
R3D_YYYYMMDD_HHMMSS_TARGET_telemetry.json
```

### Risk Register (XLSX)
One row per finding. Columns include:
- Finding ID, Title, Severity, Score
- MITRE ATT&CK technique
- OWASP category
- Framework controls (loaded frameworks only)
- CVE ID and CVSS score (Python-verified, never hallucinated)
- Calculated due date based on severity
- Owner and Status fields for tracking

### Compliance Map (XLSX)
One sheet per loaded framework.
Shows which controls each finding violates
and gap status (Missing / Partial / Needs Review).

### Executive Summary (in PDF)
Written in plain English for CEO/board audience.
Generated by Ollama from your actual findings.
Falls back to template if Ollama unavailable.

### Telemetry Log (JSON)
Raw engagement data for blue team correlation.
Every finding with timestamps and evidence paths.
Feed into your SIEM for detection rule development.

### Verification Report (JSON)
Audit trail of hallucination detection.
Shows which LLM findings were validated, flagged, or removed.
CVE IDs confirmed against live NVD data.

---

## Severity and Due Dates

```
CRITICAL (9.0-10.0)  Fix within 1 day
HIGH     (7.0-8.9)   Fix within 30 days
MEDIUM   (5.0-6.9)   Fix within 90 days
LOW      (3.0-4.9)   Fix within 180 days
INFO     (0-2.9)     Track and review
```

Zero day findings (no CVE match) are always flagged
as CRITICAL with raw evidence preserved on disk.

---

## Resuming Interrupted Engagements

If an engagement is interrupted:
```
python main.py --target example.com --resume
```

R3D reads the saved state.json, identifies which modules
completed, and resumes from exactly where it stopped.
No need to start from scratch.

---

## The Improvement Engine

After 3 or more engagements run:
```
python main.py --improve
```

R3D reads verification reports, identifies patterns in what
consistently fails or gets flagged, and generates ranked
suggestions for KB file updates and payload retirement.

You approve every suggestion. Nothing is auto-modified.
The engine logs approved suggestions to improvement_log.json
for you to apply manually.

---

## Portability -- Running on Another Machine

```
git clone git@github.com:HumdoesCyber/r3d-agent.git
cd r3d-agent
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

For Ollama models on external SSD (Windows):
```
$env:OLLAMA_MODELS = "E:\ollama\models"
ollama serve
```

---

## Updating R3D

```
python main.py --update
```

Pulls latest code from GitHub and updates Python packages.
Checks git status before pulling -- warns on local changes.

---

## Troubleshooting

### DNS timeouts
R3D sets nameservers to 8.8.8.8 and 1.1.1.1 automatically.
If DNS still fails check your network or VPN configuration.

### SSL certificate errors on HTTPS requests
Usually means your network uses SSL inspection.
R3D logs the warning and continues with other checks.

### HIBP returns 401
HaveIBeenPwned requires a paid API key for bulk checks.
R3D skips this check gracefully without the key.

### Nmap returns 0 findings
Target may be behind a firewall blocking ICMP and TCP.
Try --full-scan. Verify Nmap is in your system PATH.

### Ollama executive summary fails
R3D falls back to template automatically.
Verify Ollama is running: `ollama list`
Verify model is downloaded: `ollama pull llama3:8b`

### CVE database warning at startup
Run: `python main.py --setup-cve-db`
R3D works without it but CVE matching is limited.

---

## Why No 400 Page Compliance Documents

R3D deliberately uses focused KB files instead of loading
full compliance frameworks.

Actionability beats comprehensiveness. A small business with
no security team cannot act on 1,000 NIST controls. They can
act on 18 CIS Controls. R3D gives operators what they can
actually fix.

Context window efficiency. Loading a 400-page document into
llama3:8b degrades output quality significantly. The model
reasons better with focused, relevant information. R3D feeds
Ollama exactly what it needs for each finding type -- nothing
more.

Org type matching. Not every organization needs every framework.
A personal researcher does not need NERC CIP. Loading only what
applies produces reports operators can actually use.

Speed. A full engagement in 15-25 minutes. Not 400-page PDFs.

---

## What's Coming in V2

V2 focuses on deeper offensive capability, broader compliance
coverage, and enterprise deployment.

Key additions planned:
- Shodan integration for IP intelligence and exposure mapping
- Nuclei for 9,000+ web vulnerability templates
- Metasploit integration (GUIDED/SEMI-AUTO only, operator gated)
- Healthcare and finance compliance KB files
- Docker packaging for enterprise on-prem deployment
- SIEM push integration (Splunk, Elastic, Wazuh)
- Self-improvement agent for autonomous KB updates

Full V2 roadmap in the README.

---

## Ethical Use and Legal Requirements

R3D must ONLY be used against:
- Systems you own
- Systems you have explicit written authorization to test
- Controlled lab environments

The authorization consent screen at engagement start is not
optional. It runs before every engagement -- even in FULL-AUTO.
It creates a documented record of operator intent.

Unauthorized use violates the Computer Fraud and Abuse Act
(CFAA) in the United States and equivalent laws internationally.
Operator assumes full legal liability for target selection.

---

## Contact and Attribution

Author: Humza Sheikh
GitHub: HumdoesCyber
Project: R3D Autonomous Purple Team Agent
University: University of Arizona, Information Science
Research: 14 months of original AI security research
Coding: 150 hours
Built: December 2024 -- March 2026
V1.0: March 24, 2026