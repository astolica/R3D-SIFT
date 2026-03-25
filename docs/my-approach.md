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

## This Is Not Vibe Coding

I want to address this directly because it matters.

Vibe coding -- as defined by Andrej Karpathy -- is a workflow
where you fully surrender to the AI. You accept generated code
without understanding it. You paste error logs back into the
prompt until something runs. You do not plan. You do not review.
You do not know why the code does what it does.

That is not what happened here.

R3D was built through AI-assisted systems engineering.
The distinction is not semantic -- it changes everything about
the quality and reliability of what gets produced.

Here is what the methodology actually looked like:

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
Most debugging time is not spent fixing bugs. It is spent fixing
design decisions made during implementation that should have been
made before it. I fixed design first.

**Comprehension over convenience.**
Every architectural decision has a reason I can explain. Why the
context filter strips emails before LLM handoff. Why the CVE engine
never lets the LLM generate IDs. Why the verifier only touches
LLM attack findings and passes everything else through unchanged.
I can answer all of those. That is the difference between
engineering and vibe coding.

**AI as compiler, not architect.**
Claude and Gemini acted as technical consultants -- code review,
error checking, compatibility verification, high-speed syntax
generation. Every architectural decision, security design, and
engineering tradeoff came from 14 months of domain research and
real client work. The AI did not bring the domain knowledge.
I did.

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

150 hours   Coding and engineering
            Architecture planning
            Security review before every module
            Debugging, testing, refinement

4 days      Build sprint -- 23 commits
            Full pipeline from zero to first live engagement
            Two weeks ahead of original 3-week estimate
```

The 4-day sprint was fast because of the 14 months before it.
Velocity comes from preparation, not from letting the AI drive.

---

## Why Plan Before You Code

Every module in R3D worked on the first or second try.
That is not luck. That is what happens when you define
all interfaces before writing any implementation.

The architecture was planned on March 19, 2026.
The first commit was March 21, 2026.
Two days of planning before a single line existed.

When you know exactly what every module receives,
what it does, and what it hands off -- the code
almost writes itself. The hard decisions are already made.

This is not a lesson from a textbook.
It is what happened across four days of building R3D.

---

## Why Local and Not Cloud

Every API call is a dollar. Every engagement is dozens of calls.
A commercial red team tool built on OpenAI costs money every time
it runs and sends your data to someone else's server.

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
R3D can actually discover. When the model reads 1,500 characters
of focused context about which NIST controls apply to prompt
injection findings, it produces specific, accurate, actionable
compliance language.

Precision beats volume for local LLM inference.
This is not a limitation I worked around.
It is a design principle I built toward.

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

A small business gets a report written for them.
A utility gets a report written for their compliance team.
One tool. Right output for each audience.

---

## Why Two AIs Reviewing Each Other

Throughout the build, Claude acted as engineering partner
and Gemini acted as second opinion and critic.

This is not a gimmick. It is how the tool got better.
Two AIs reviewing architecture and code before anything runs
is the same principle as two engineers doing code review.
The cost is minutes. The benefit is modules that work the first time.

---

## What This Project Actually Is

R3D is not a school project.
It is not a capstone assignment.
It is not a portfolio piece to impress recruiters.

It is a research instrument built on 14 months of original work
that documents attack vectors outside the current published
literature -- specifically a class of multi-turn social
engineering attack against LLMs that operates on conversation
trajectory rather than individual message content.
It is the proof that the gap between technical security and GRC
can be closed with the right architecture and the right discipline.

---

## What Comes After V1

V1 is complete. First live engagement: scanme.nmap.org.
28 minutes 50 seconds. 9 findings. PDF, XLSX, telemetry. All clean.

V2 adds deeper offensive capability, specialized compliance
frameworks for healthcare and finance, enterprise deployment
packaging, and SIEM integration. The commercial path is not
a cloud SaaS. It is an on-premises appliance licensed to
enterprise SOC teams who run it inside their own networks
on their own hardware.

Both paths exist because R3D was built right the first time.

---

## The Build

Research started:  December 2024
Architecture:      March 19, 2026
First commit:      March 21, 2026
V1.0 complete:     March 24, 2026
Total coding:      150 hours
First engagement:  scanme.nmap.org -- 28m 50s -- 9 findings

Pure focus. Pure grit. Built right.

-- Humza Sheikh