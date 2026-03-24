# R3D User Guide
## Complete Operations Manual v1.0
### Author: HumdoesCyber
### Built: March 2026

---

## What is R3D?

R3D is a fully local autonomous red team agent that bridges
the gap between technical security and GRC compliance.
It finds vulnerabilities AND maps them to compliance
frameworks automatically. One run. One report. Both sides.

No cloud APIs. No cost per run. Everything stays on your machine.
Fully air-gappable for sensitive engagements.

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
```
pip install -r requirements.txt
```

### AI Model (download once, 4.7GB)
```
ollama pull llama3:8b
```

---

## Setup A to Z

### Step 1 -- Install Python 3.12
Download from python.org. During install CHECK "Add Python to PATH".
```
python --version
# Python 3.12.x
```

### Step 2 -- Install Git
Download from git-scm.com. Accept all defaults.
```
git --version
# git version 2.x.x
```

### Step 3 -- Install Ollama
Download from ollama.com. Install then pull the model:
```
ollama pull llama3:8b
ollama list
# shows llama3:8b
```

### Step 4 -- Install Nmap
Download from nmap.org. Check "Add to PATH" during install.
```
nmap --version
# Nmap 7.95
```

### Step 5 -- Clone R3D
```
git clone git@github.com:HumdoesCyber/r3d-agent.git
cd r3d-agent
```

### Step 6 -- Virtual environment
```
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac
pip install -r requirements.txt
```

### Step 7 -- Verify everything works
```
python main.py --test-connection
```

You should see 6 checks. 5 green and 1 yellow (CVE database)
is a perfect first run result.

### Step 8 -- Optional: Download CVE database
```
python main.py --setup-cve-db
```
Takes 30-60 minutes. Only needed once. R3D works without it
but CVE correlation is limited.

---

## Your First Scan

### Safe test target (authorized by Nmap)
```
python main.py --target scanme.nmap.org --mode guided
```

### What happens next
```
1. Banner shows with system checks
2. Engagement ID generated
3. Authorization consent screen -- type YES
4. GUIDED mode asks Y/N before every check
5. OSINT runs -- passive recon
6. LLM attack runs if AI surfaces found
7. Traditional recon runs
8. Organization type menu appears
9. GRC compliance mapping runs
10. Reports generated
11. Final summary shows output file paths
```

---

## All Commands Reference

### Run an engagement
```
python main.py --target example.com
python main.py --target example.com --mode guided
python main.py --target example.com --mode full-auto --auto-attack
python main.py --target 192.168.1.1 --mode semi-auto
```

### All flags
```
--target example.com
    Domain or IP to assess
    Protocol stripped automatically (https:// removed)
    Required for engagement commands

--mode guided|semi-auto|full-auto
    guided     -- approve every single action
    semi-auto  -- passive auto, active manual (default)
    full-auto  -- everything automatic, lab only

--full-scan
    Scan all 65535 ports instead of top 1000
    Takes 15-25 minutes vs 3-5 minutes
    Use when you need complete coverage

--auto-attack
    LLM attacks without per-surface confirmation
    Required for FULL-AUTO to actually attack
    Auto-enabled when --mode full-auto used

--org-type personal|small_business|enterprise|critical_infrastructure|all
    Skip the organization type menu
    Loads specific compliance frameworks
    personal:                CIS Controls
    small_business:          CIS Controls + NIST 800-53
    enterprise:              NIST 800-53 + ISO 27001
    critical_infrastructure: NERC CIP + NIST 800-53 + AI RMF
    all:                     Everything

--resume
    Resume an interrupted engagement
    Reads saved state.json and skips completed modules
    Use after crash, timeout, or Ctrl+C

--skip-llm
    Skip LLM attack module entirely
    Use when you only need infrastructure findings

--skip-trad
    Skip traditional recon module
    Use when you only need OSINT + GRC output

--timeout 2700
    Engagement timeout in seconds
    Default: 2700 (45 minutes)
    Use --timeout 5400 for complex targets

--fast-mode
    Reduce delays between requests
    Use for testing, not real engagements
```

### Utility commands
```
python main.py --test-connection
    Verify all 6 dependencies
    Run this first on any new machine

python main.py --setup-cve-db
    Download NVD CVE database locally
    Takes 30-60 minutes, only needed once
    Enables CVE correlation in traditional recon

python main.py --improve
    Run improvement engine
    Analyzes last 10 engagement reports
    Suggests payload and KB improvements
    Requires minimum 3 prior engagements

python main.py --update
    Pull latest code from GitHub
    Update Python dependencies
    Checks git status before pulling

python main.py --cleanup --older-than 30
    Remove engagement files older than 30 days
    Shows what will be deleted before confirming
    Default: 30 days
```

---

## Operating Modes Explained

### GUIDED -- Approve everything
Every single action requires your Y/N before executing.
Use for: first time use, sensitive authorized targets,
demonstrating the tool to others.

```
python main.py --target example.com --mode guided
```

### SEMI-AUTO -- Default safe mode
Passive recon runs automatically.
Active attacks pause for your confirmation.
Best balance of speed and control.

```
python main.py --target example.com --mode semi-auto
```

### FULL-AUTO -- Lab only
Everything runs without prompts.
Sherlock ALWAYS blocked in this mode.
Only use in controlled lab environments you own.

```
python main.py --target lab.example.com --mode full-auto --auto-attack
```

---

## Organization Type Selection

R3D asks once per engagement which type of organization
you are assessing. This determines which compliance
frameworks are loaded.

```
[1] Personal / Researcher
    CIS Controls v8

[2] Small Business
    CIS Controls v8 + NIST SP 800-53

[3] Enterprise
    NIST SP 800-53 + ISO 27001:2022

[4] Critical Infrastructure
    NERC CIP + NIST SP 800-53 + NIST AI RMF

[5] All Frameworks
    Everything above combined
```

Note: NIST AI RMF loads automatically on any org type
if AI surfaces are discovered -- regardless of selection.

---

## Understanding Your Output Files

Every engagement produces files with a shared engagement ID:
```
output/reports/
├── R3D_DATE_TARGET_report.pdf
├── R3D_DATE_TARGET_risk_register.xlsx
├── R3D_DATE_TARGET_compliance_map.xlsx
└── R3D_DATE_TARGET_telemetry.json
```

### PDF Report
Executive summary in plain English.
Generated by Ollama from your actual findings.
Written for CEO/board not security engineers.

### Risk Register (XLSX)
One row per finding. Columns include severity, MITRE
ATT&CK technique, OWASP category, NIST 800-53 controls,
NERC CIP standards, CIS Controls, ISO 27001 controls,
NIST AI RMF functions, CVE ID, CVSS score, due date.

### Compliance Map (XLSX)
One sheet per loaded framework.
Shows which specific controls each finding violates.
Gap status: Missing / Partial / Needs Review.

### Telemetry Log (JSON)
Raw engagement data for blue team use.
Feed into your SIEM for detection rule development.

---

## Severity and Due Dates

```
CRITICAL (9.0-10.0)  Fix within 1 day
HIGH     (7.0-8.9)   Fix within 30 days
MEDIUM   (5.0-6.9)   Fix within 90 days
LOW      (3.0-4.9)   Fix within 180 days
INFO     (0-2.9)     Track and review annually
```

---

## Getting More Out of R3D

### Run engagements regularly
The improvement engine needs at least 3 engagements
to identify patterns. Run R3D monthly against your
lab environment to build up improvement data.

### Use fast-mode for testing
```
python main.py --target lab.local --mode semi-auto --fast-mode
```

### Skip modules you don't need
```
python main.py --target example.com --skip-llm
python main.py --target example.com --skip-trad
```

### Resume interrupted engagements
```
python main.py --target example.com --resume
```

### Portable deployment (USB/external SSD)
For Ollama models on external drive (Windows):
```
$env:OLLAMA_MODELS = "E:\ollama\models"
ollama serve
```

---

## Troubleshooting

### DNS timeouts
R3D uses 8.8.8.8 and 1.1.1.1 automatically.

### SSL certificate errors
Network SSL inspection is common on university/corporate
networks. R3D logs and continues.

### Google dorking blocked
Expected. R3D falls back to DuckDuckGo automatically.

### Nmap returns 0 findings
Target may be behind a firewall. Try --full-scan.

### Ollama summary empty
R3D falls back to template. Run: ollama serve

### CVE database warning
Run: python main.py --setup-cve-db

---

## Ethical Use

R3D must ONLY be used against systems you own or have
explicit written authorization to test.
The authorization consent screen is not optional.
Unauthorized use violates the CFAA and equivalent laws.

---

## Why No 400 Page Compliance Documents?

1. Actionability beats comprehensiveness
2. Context window efficiency for local LLMs
3. Org type matching -- load only what applies
4. Speed -- targets 15-20 minute full engagements

---

## Contact

GitHub: HumdoesCyber
University: University of Arizona, Information Science
Version: 1.0 -- March 2026
