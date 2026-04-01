# R3D -- Autonomous Purple Team Agent
### Offensive security. Defensive telemetry. GRC compliance. One run.

Fully local. No cloud APIs. No cost per run. Zero data leaves your machine.

Built on Python · Ollama · Nmap · 14 months of AI security research.

**V1.0 complete. Most recent engagement: scanme.nmap.org -- 12 findings. Typical engagement time: 15-25 minutes.**

---

## What R3D Actually Is

I spent over a year sitting in two rooms that rarely talk to each other.

The red team finds vulnerabilities and hands over a 500-page automated PDF. The GRC team writes compliance documents in control IDs nobody on the technical side reads. Neither room speaks the other's language. The gap between them costs organizations time, money, and missed risk.

I built R3D to be the translator.

It runs autonomous offensive reconnaissance, attacks AI surfaces using original AI security research vectors, correlates CVEs against live services, generates blue team telemetry for SIEM ingestion, and automatically maps every finding to NIST 800-53, NERC CIP, ISO 27001, CIS Controls v8, and NIST AI RMF.

One engagement. One report. Red team findings. Blue team artifacts. GRC compliance output. All three.

That is why R3D is a purple team agent -- not just a scanner, not just a compliance tool. It was built to close a gap that the industry has accepted as normal. It doesn't have to be.

---

## The AI Accountability Problem

The industry is racing to replace human judgment with AI automation. When AI makes a mistake in a security context it is not abstract -- a hallucinated CVE means a real vulnerability stays open. A miscalibrated severity means a CRITICAL finding sits in a backlog for 180 days. An unverified finding in a NERC CIP compliance report means a utility files incorrect audit documentation at up to $1M per day per violation. R3D is my way of start to add accountability.

**The five accountability layers:**

- **Authorization gate** -- documented operator consent before any action runs. The human is legally accountable before the first packet leaves the machine.
- **Verifier** -- Python and NVD are always the final authority. The LLM never generates CVE IDs. Hallucinated findings are caught before they reach the report.
- **Improvement engine** -- the tool cannot modify its own KB or payload library without explicit operator approval. Y or N per suggestion. Nothing auto-modified ever.
- **Telemetry log** -- every offensive action timestamped with MITRE ATT&CK attribution. Full audit trail for SOC correlation and compliance documentation.
- **Engagement ID** -- ties every output file together. One run, one ID, complete traceability from authorization to final report.

The AI is the execution engine. The human is the architect. That is not a philosophy statement it is a hard engineering constraint enforced at every layer of this project.

---

## How This Was Built

R3D was built through AI-assisted systems engineering. Every module interface was defined before implementation began. Every module was security reviewed before it ran on hardware. Every decision has a documented reason behind it.

Claude and Gemini acted as technical consultants -- code review, error checking, compatibility verification, syntax generation. The domain knowledge, the architecture, the security decisions, and the research are mine.

Security audits completed before release: pip-audit, bandit, pylint. All findings reviewed and resolved or documented.

```
December 2024    Research begins
14 months        Original AI security research
                 Real client engagements
                 Google Cybersecurity Clinic
                 WISP audit with $100K liability cap
                 52-page governance framework
                 WRCCDC 9-hour SOC simulation

250 hours        Coding and engineering
                 Architecture planning
                 Security review before every module

March 19, 2026   Architecture locked
March 21, 2026   First commit
March 24, 2026   V1.0 complete
April 01, 2026   V1.0 patched, audited, and released
```

The full thinking behind this is in `docs/my-approach.md`.

---

## Architecture

```
       python main.py --target example.com --mode guided
          │
          ▼
      ┌─────────────────────────────────────────────────────┐
      │  CORE LAYER                                         │
      │  banner.py              Wizard terminal UI          │
      │  findings.py            MITRE ATT&CK + OWASP mapping│
      │  llm_client.py          Ollama wrapper              │
      │  cve_engine.py          NVD CVE correlation         │
      │  report_gen.py          PDF + XLSX + telemetry      │
      │  verifier.py            Hallucination detection     │
      │  improvement_engine.py  Self-improvement loop       │
      └─────────────────────────────────────────────────────┘
            │
            ▼
      ┌─────────────────────────────────────────────────────┐
      │  MODULE PIPELINE                                    │
      │                                                     │
      │  1. osint_recon.py      -- PASSIVE RECON            │
      │     WHOIS, DNS, subdomain enumeration               │
      │     Google/DuckDuckGo dorking (auto-fallback)       │
      │     Certificate transparency logs                   │
      │     Email harvesting + breach checking (HIBP)       │
      │     Sherlock username enumeration (GUIDED only)     │
      │     Tech stack fingerprinting                       │
      │     WAF detection (8 vendor signatures)             │
      │     AI surface discovery (30+ endpoint signatures)  │
      │     Rate limiter -- prevents accidental DoS         │
      │                                                     │
      │  2. llm_attack.py       -- LLM ATTACK SUITE         │
      │     Only runs when AI surfaces discovered           │
      │     Tier 1: 30 static payloads (8 categories)       │
      │             MITRE ATLAS tagged, scored              │
      │     Tier 2: KB-guided adaptive via Ollama RAG       │
      │             Adapts to what Tier 1 found             │
      │     Tier 3: Original research sequences             │
      │             TEP-005: Contextual Trust Accumulation  │
      │             TEP-010: Relational State Exploitation  │
      │             Outside OWASP LLM Top 10 (2025)         │
      │             Authorized installations only           │
      │                                                     │
      │  3. traditional_recon.py -- ACTIVE RECON            │
      │     Port scan (top 1000 default / all 65535)        │
      │     Service version detection                       │
      │     CVE correlation (295,406 CVEs local NVD)        │
      │     SSL/TLS audit + certificate expiry              │
      │     Security header deep analysis (CSP quality)     │
      │     49-path endpoint discovery                      │
      │     JavaScript bundle secret scanning               │
      │     WAF bypass attempt (only if WAF detected)       │
      │                                                     │
      │  4. grc_mapper.py       -- COMPLIANCE MAPPING       │
      │     Org type selection (5 types)                    │
      │     Loads only relevant frameworks -- fast          │
      │     Risk register XLSX with due dates               │
      │     Compliance map XLSX (one sheet per framework)   │
      │     Executive summary via Ollama                    │
      │     NERC CIP financial penalty context included     │
      └─────────────────────────────────────────────────────┘
            │
            ▼
      ┌─────────────────────────────────────────────────────┐
      │  OUTPUT LAYER                                       │
      │  PDF executive report    Board/CISO ready           │
      │  XLSX risk register      MITRE + OWASP + frameworks │
      │  XLSX compliance map     One sheet per framework    │
      │  JSON telemetry log      SIEM ingestion artifact    │
      │  Verification report     Hallucination audit trail  │
      │  Improvement log         Approved KB suggestions    │
      └─────────────────────────────────────────────────────┘
```

---

## Capability Matrix

| Capability                    | Status     | Notes                                    |
|-------------------------------|------------|------------------------------------------|
| Passive OSINT recon           | ✅ V1.0    | 10 checks, rate limited                  |
| WAF detection                 | ✅ V1.0    | 8 vendor signatures                      |
| AI/LLM surface discovery      | ✅ V1.0    | 30+ endpoint signatures, POST confirmed  |
| Static payload attacks        | ✅ V1.0    | 30 payloads, 8 categories, ATLAS tagged  |
| Adaptive KB-guided attacks    | ✅ V1.0    | Ollama RAG generation                    |
| Original research sequences   | ✅ V1.0    | TEP-005, TEP-010 (auth installs only)    |
| Port scan + CVE correlation   | ✅ V1.0    | Nmap + 295,406 CVEs local NVD            |
| SSL/TLS audit                 | ✅ V1.0    | Protocol + cert expiry                   |
| Security header analysis      | ✅ V1.0    | CSP quality scoring included             |
| JS bundle secret scanning     | ✅ V1.0    | AWS keys, API tokens, internal URLs      |
| NIST SP 800-53 mapping        | ✅ V1.0    | All finding types mapped                 |
| NERC CIP mapping              | ✅ V1.0    | CIP-002 through CIP-015-1                |
| ISO 27001:2022 mapping        | ✅ V1.0    | All 4 themes, 93 controls                |
| CIS Controls v8 mapping       | ✅ V1.0    | IG1/IG2/IG3 levels flagged               |
| NIST AI RMF mapping           | ✅ V1.0    | Auto-loads on AI surface discovery       |
| Blue team telemetry output    | ✅ V1.0    | JSON log for SIEM correlation            |
| Hallucination verification    | ✅ V1.0    | NVD CVE validation + semantic dedup      |
| Self-improvement engine       | ✅ V1.0    | Trend analysis + operator-approved KB    |
| Engagement checkpointing      | ✅ V1.0    | --resume from any module                 |
| Private IP scope awareness    | ✅ V1.0    | DNS/Wayback skipped on RFC1918           |
| Duplicate finding suppression | ✅ V1.0    | Cross-module semantic dedup              |
| Shodan integration            | 🔲 V2      | IP intel + exposure mapping              |
| Nuclei integration            | 🔲 V2      | 9,000+ web vulnerability templates       |
| Metasploit integration        | 🔲 V2      | GUIDED/SEMI-AUTO only, operator gated    |
| Healthcare KB                 | 🔲 V2      | HIPAA + HITRUST mapping                  |

---

## Compliance Frameworks

R3D loads only what applies to your organization. Unused frameworks are never loaded -- faster runtime, better Ollama output quality, more focused reports.

| Org Type                 | Frameworks Loaded                                    |
|--------------------------|------------------------------------------------------|
| Personal / Researcher    | CIS Controls v8                                      |
| Small Business           | CIS Controls v8 + NIST SP 800-53                    |
| Enterprise               | NIST SP 800-53 + ISO 27001:2022                     |
| Critical Infrastructure  | NERC CIP + NIST SP 800-53 + NIST AI RMF             |
| All                      | All frameworks                                       |

**NIST AI RMF loads automatically on any org type when AI surfaces are discovered.**

---

## Operating Modes

| Mode        | Behavior                                                         |
|-------------|------------------------------------------------------------------|
| `guided`    | Y/N approval before every single action. First use recommended. |
| `semi-auto` | Passive recon runs automatically. Active attacks require confirmation. Default. |
| `full-auto` | Everything runs automatically. Controlled lab environments only. |

**Sherlock username enumeration is always blocked in FULL-AUTO regardless of configuration.**
**Authorization consent screen runs before every engagement -- even in FULL-AUTO.**

---

## Quick Start

```powershell
# 1. Clone and install
git clone git@github.com:HumdoesCyber/r3d-agent.git
cd r3d-agent
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux/Mac
pip install -r requirements.txt
ollama pull llama3:8b

# 2. Verify setup
python main.py --test-connection

# 3. Optional -- download CVE database (30-60 min, once only)
python main.py --setup-cve-db

# 4. Run your first engagement
python main.py --target scanme.nmap.org --mode guided
```

---

## All CLI Flags

```
Engagement:
  --target          Domain or IP (https:// stripped automatically)
  --mode            guided / semi-auto / full-auto
  --full-scan       All 65535 ports (default: top 1000)
  --auto-attack     LLM attacks without per-surface confirmation
  --org-type        personal / small_business / enterprise /
                    critical_infrastructure / all
  --resume          Resume interrupted engagement from checkpoint
  --skip-llm        Skip LLM attack module
  --skip-trad       Skip traditional recon module
  --timeout         Seconds before timeout (default: 2700 = 45min)
  --fast-mode       Reduce delays for testing

Utilities:
  --test-connection Verify all 6 dependencies with fix hints
  --setup-cve-db    Download NVD CVE database locally (295,406 CVEs)
  --improve         Run improvement engine (requires 3+ engagements)
  --update          git pull + pip install -r requirements.txt
  --cleanup         Remove old engagement files
  --older-than      Days threshold for cleanup (default: 30)
```

---

## The Research Foundation

### Why the LLM Attack Module Is Different

Most LLM security research focuses on single-turn attacks -- what you say to a model in one message. The OWASP LLM Top 10, MITRE ATLAS, and most academic work operates in this space.

R3D's Tier 3 attack sequences are built on 14 months of original AI security research into a class of LLM vulnerability that operates on conversation trajectory rather than individual messages. These vectors sit outside the current OWASP LLM Top 10 (2025) and have no formal CVE classification. Not available publicly yet.

No single turn looks malicious in isolation. The attack emerges from the sequence as a whole. Single-turn content filters do not detect it.

This is the research gap Tier 3 addresses. It is available to authorized installations only.

### CVE Design Principle

Unknown findings are flagged, never fabricated. R3D's tiered CVE lookup implements this: unclassified services receive zero-day flags with preserved evidence on disk. The LLM never generates CVE IDs. Python and NVD data are always the final authority.

---

## Why Fully Local Matters

Every API call costs money. Every sensitive engagement is dozens of calls.

For critical infrastructure assessments testing systems adjacent to power grid operations  you cannot send data to a cloud API. The tool has to be local by design, not by configuration.

---

## Repository Structure

```
r3d-agent/
├── main.py                      CLI entry point (all flags)
├── requirements.txt
├── core/
│   ├── banner.py                Terminal UI + system checks
│   ├── llm_client.py            Ollama wrapper + JSON validation
│   ├── cve_engine.py            NVD CVE lookup (295,406 local)
│   ├── findings.py              Finding dataclass + MITRE + OWASP
│   ├── report_gen.py            PDF + XLSX + telemetry JSON
│   ├── verifier.py              Hallucination detection + NVD validation
│   └── improvement_engine.py    Self-improvement loop + trend analysis
├── modules/
│   ├── osint_recon.py           Passive recon (10 checks)
│   ├── llm_attack.py            3-tier LLM attack suite
│   ├── traditional_recon.py     Port scan + CVE + JS analysis
│   ├── grc_mapper.py            Compliance framework mapper
│   └── orchestrator.py          Master engagement sequencer
├── data/
│   ├── compliance_kb/           NIST 800-53, NERC CIP, CIS,
│   │                            ISO 27001, NIST AI RMF
│   ├── llm_attack_kb/           MITRE ATLAS, OWASP LLM Top 10,
│   │                            jailbreak patterns, injection taxonomy
│   │                            original_research.md (gitignored)
│   └── payloads/
│       └── static_injections.json   30 payloads, 8 categories
├── docs/
│   ├── user-guide.md            Complete operations manual
│   ├── build-log.md             Engineering journal
│   ├── my-approach.md           Philosophy and design decisions
│   └── how-it-works.md          Full technical breakdown A to Z
└── output/                      Generated per engagement
    ├── reports/
    ├── engagements/
    ├── profiles/
    ├── attack_logs/
    └── improvement_log.json
```

---

## Project Stats

```
Language:          Python 3.12
Commits:           50+
Research:          14 months (December 2024 -- April 2026)
Coding:            250 hours
Build sprint:      14 days
Audits:            pip-audit, bandit, pylint -- all resolved
Hardware:          NVIDIA RTX 5070 Ti, 32GB DDR5, Windows 11
LLM:               llama3:8b via Ollama (fully local)
CVE database:      295,406 CVEs (local NVD)
Payloads:          30 static (Tier 1) + adaptive (Tier 2)
                   + original research (Tier 3, auth installs)
Frameworks:        NIST 800-53 · NERC CIP · ISO 27001
                   CIS Controls v8 · NIST AI RMF
```

---

## Ethical Use

This tool must only be used against systems you own or have explicit written authorization to test.

The authorization consent screen runs before every engagement and creates a documented record of operator intent. This is legal protection -- not optional.

Unauthorized use violates the Computer Fraud and Abuse Act (CFAA) in the United States and equivalent laws internationally. Operator assumes full legal liability for target selection.

---

## Author

**HumdoesCyber**
University of Arizona -- Information Science

14 months of original AI security research. Real client engagements. Real compliance work.
Google Cybersecurity Clinic · WRCCDC · Independent consulting.

Built to close the gap between technical security and GRC.

---

## License

Private repository. All rights reserved. The owner does not take any liability on how the tool is used.
Contact via GitHub for collaboration or licensing inquiries.