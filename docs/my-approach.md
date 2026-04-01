# My Approach
## Philosophy Behind R3D
### Author: Humza Sheikh (HumdoesCyber)

---

*This document is written last -- after everything else exists.
It describes why R3D was built the way it was built,
not what it does or how to use it.*

---

## The Gap I Kept Running Into

I spent over a year sitting in two rooms that rarely talk to each other.

The technical room finds vulnerabilities. Open ports, weak TLS,
prompt injection, CVEs. They hand over a 500-page automated PDF
and call it a day.

The GRC room writes compliance documents. NIST 800-53 control gaps,
risk registers, audit evidence packages. They speak in control IDs
and residual risk scores.

Neither room speaks the other's language fluently.
The technical findings never become the compliance narrative.
The compliance narrative never reflects what the technical team
actually found.

I built R3D to be the translator.

---

## The AI Accountability Problem

The corporate rush to replace human workers with AI automation
is creating a vacuum of accountability. AI makes mistakes at the
speed of light -- and there is no one in the machine to hold responsible.
In security this is not abstract.

A hallucinated CVE in a report means a vulnerability that does not exist
gets closed on paper while a real one stays open. A miscalibrated severity
means a CRITICAL finding gets treated as LOW for 180 days. An unverified
finding in a NERC CIP compliance report means a utility is filing incorrect
audit documentation -- at up to $1M per day per violation.

R3D was built as the first step in trying solve this problem at the architecture level.
Not by removing AI from the equation but by keeping the human in the loop
at every single decision point. Five accountability layers enforce this:

- **Authorization gate** -- documented operator consent before anything runs.
  The human is legally on record before the first packet leaves the machine.
- **Verifier** -- Python and NVD are always the final authority on CVEs.
  The LLM never generates CVE identifiers. Hallucinated findings are caught
  before they reach the report.
- **Improvement engine** -- the tool cannot modify its own KB or payload
  library without explicit operator approval per suggestion. Nothing
  auto-modified under any circumstance.
- **Telemetry log** -- every offensive action timestamped with MITRE ATT&CK
  attribution. Full audit trail for SOC correlation and legal accountability.
- **Engagement ID** -- ties every output file together. One run, one ID,
  complete chain of custody from authorization to final report.

This is the first step toward actually solving the AI accountability problem
in security tooling. Not a marketing claim. An engineering constraint baked
into every module from the ground up.

---

## How This Was Built

R3D was built through AI-assisted systems engineering with comprehensive
security checks at every stage of design and implementation.

This is a precise description of the methodology, not a marketing phrase.

**Architecture before code.**
Every module interface was defined before a single line was written.
OSINTProfile dataclass. Finding schema. The handoff between every
module. The data contracts that connect them. All of that was
locked before implementation started. When you know the shape of
your data going in and out, the implementation almost writes itself.

**Security review before every paste.**
Every module was critically reviewed for infinite loops, error
handling gaps, input sanitization failures, and compatibility
with every other module -- before it ran on hardware. This is
why the modules worked first or second try throughout the build.

**Comprehensive audits before release.**
Three full security audits completed before V1.0 was released:
pip-audit for dependency vulnerabilities, bandit for static
security analysis, and pylint for code quality. All findings
were reviewed, resolved, or explicitly documented and accepted.

**AI as execution engine, not architect.**
Claude and Gemini acted as technical consultants -- code review,
error checking, compatibility verification, syntax generation.
Every architectural decision, security design, and engineering
tradeoff came from 14 months of domain research and real client work.
The domain knowledge is mine. The architecture is mine.
The research is mine.

---

## The Real Numbers

This project represents:

```
14 months   Original AI security research
            Real client engagements
            Google Cybersecurity Clinic
            WISP audit with $100K liability cap
            52-page governance framework adopted by U of A
            NIST SP 800-30 risk register through 4 versions
            WRCCDC 9-hour live SOC simulation

250 hours   Coding and engineering
            Architecture planning
            Security review before every module
            Debugging, testing, refinement

14 days     Build sprint -- 23 commits
            Full pipeline from zero to first live engagement

1 week      Audit and patch sprint
            pip-audit, bandit, pylint
            17 targeted bug fixes
            5 quality improvements

50+         Total commits at V1.0 release
```


---

## Why Plan Before You Code

Every module in R3D worked on the first or second try.
That is what happens when you define all interfaces before
writing any implementation.

The architecture was planned on March 19, 2026.
The first commit was March 21, 2026.
Two days of planning before a single line existed.

When you know exactly what every module receives,
what it does, and what it hands off -- the code
almost writes itself. The hard decisions are already made.

---

## Why Local and Not Cloud

Every API call is a dollar. Every engagement is dozens of calls.
A commercial red team tool built on OpenAI sends your data
to someone else's server on every run.

R3D runs entirely on your hardware.
Zero API cost. Zero data leaving the machine.
Fully air-gappable for sensitive engagements.

For a critical infrastructure assessment -- testing systems
adjacent to the power grid -- you cannot send operational data
to a cloud API. The tool must be local by design, not by
configuration. That decision was made on day one.

---

## Why Focused KB Files and Not Full Frameworks

NIST SP 800-53 has over 1,000 controls.
ISO 27001 Annex A has 93 controls.
NERC CIP has 13 standards with dozens of requirements.

A local LLM with an 8,000 token context window cannot reason
well over a 400-page document. It compresses everything and
produces generic output that nobody can act on.

R3D's KB files contain only the controls that map to findings
R3D can actually discover. Precision beats volume for local LLM inference.

---

## Why the Org Type Selection Matters

A personal researcher does not need NERC CIP.
A utility does not need basic CIS Controls advice.
A startup does not need ISO 27001 certification guidance.

Most tools force everyone through every framework.
The output is comprehensive but not actionable.
Nobody reads the 400-page report.

R3D asks one question before the engagement starts.
The answer determines which frameworks load, which KB files
are read, which XLSX sheets are generated, and what language
the executive summary uses.

One tool. Right output for each audience.

---

## What This Project Actually Is

R3D is not a school project.
It is not a capstone assignment.
It is not a portfolio piece to impress recruiters.

It is a research instrument built on 14 months of original work
that documents attack vectors outside the current published
literature -- a class of multi-turn social engineering attack
against LLMs that operates on conversation trajectory rather than
individual message content.

It is the proof of concept that the AI accountability gap in security
tooling can be closed with the right architecture and the right discipline.

The human operator is accountable. The AI is the engine.
That is how it should be. That is how R3D was built.

---

## The Build

Research started:  December 2024
Architecture:      March 19, 2026
First commit:      March 21, 2026
V1.0 complete:     March 24, 2026
V1.0 released:     April 01, 2026
Total coding:      250 hours

Humdoescyber