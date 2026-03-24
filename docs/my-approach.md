# My Approach
## The Philosophy Behind R3D
### Author: HumdoesCyber
### Written: March 2026

---

This document is written last -- after everything else exists.
It explains why R3D was built the way it was built.
The user guide covers what it does. The build log covers
what was built. This one covers the thinking.

---

## The Gap I Kept Running Into

I spent over a year sitting in two rooms that rarely
talk to each other.

The technical room finds vulnerabilities. Open ports,
weak TLS, prompt injection, CVEs. They hand over automated
PDFs with hundreds of findings and call it done.

The GRC room writes compliance documents. NIST 800-53
control gaps, risk registers, audit evidence packages.
They speak in control IDs and residual risk scores.

Neither room speaks the other's language.
The technical findings never become the compliance
narrative. The compliance narrative never reflects
what was actually found on the network.
The business never gets a clear picture of real risk.

I built R3D to be the translator.
One tool. Both rooms. One report.

---

## 180 Hours of Work Behind 21 Commits

The commit history shows 21 commits over 4 days.
What it doesn't show is the 14 months and 145 hours
of research that made those 4 days possible.

Real client work at the Google Cybersecurity Clinic.
A WISP audit with a real $100K liability cap.
A governance framework that college leadership adopted.
Four versions of a risk register for a real utility company.
14 months of original AI security research leading to
two novel attack vectors that sit outside the current
published literature.

You don't build a tool like this in 4 days.
You build it in 180 hours across 14 months
and then execute the final sprint in 4 days
because every decision was already made.

---

## Why Plan Before You Code

Every module in R3D worked on the first or second try.

That is not luck. That is what happens when you spend
10 hours defining every interface before writing a
single line of implementation. Every module's inputs
and outputs were defined. Every data contract was
written as a dataclass. Every handoff pattern was
decided. Every safety gate was specified.

When you know the shape of your data going in and out,
the implementation almost writes itself. The thinking
is done. You're expressing decisions that already exist.

Most debugging time is not spent fixing bugs.
It is spent fixing design decisions made during
implementation that should have been made before it.

Plan first. Build second. This is the whole lesson.

---

## Why Local and Not Cloud

Every API call is a dollar. Every engagement is dozens
of calls. A tool built on cloud LLM APIs costs real
money every time it runs.

R3D runs entirely on your hardware. Zero API cost.
Zero data leaving the machine. Fully air-gappable.

For critical infrastructure assessments -- testing
systems adjacent to the power grid -- you cannot send
operational data to a cloud API. The tool must be
local by design, not by configuration.

The local constraint also forced better architecture.
When the model cannot be scaled infinitely you have
to be precise about what you feed it. That precision
is what makes the outputs useful instead of generic.

---

## Why Focused KB Files and Not Full Frameworks

A local LLM with an 8,000 token context window cannot
reason well over a 400 page document. It compresses
everything and produces output that sounds authoritative
but is not specific to what was actually found.

R3D's KB files contain only the controls that map to
findings R3D can actually discover. The model reads
focused context and produces specific, accurate,
actionable compliance language.

Precision beats volume for local LLM inference.
A focused question gets a useful answer.
A broad question gets a generic one.

---

## On Using AI Tools

I used AI tools as technical consultants during this
build. That is worth being precise about because the
distinction matters.

Every architectural decision came from 14 months of
domain research. The TEP engagement context, the
compliance framework knowledge, the novel attack
vectors, the security design philosophy -- none of
that came from an AI. It came from real client work,
real research, and real hours.

Where AI consultation helped:
- Code review before execution to catch edge cases
- Compatibility checks across module interfaces
- Second opinions on specific implementation choices
- Error detection in complex multi-module interactions

Where it had no role:
- Deciding what problem was worth solving
- Understanding the compliance landscape from experience
- Developing TEP-005 and TEP-010 from scratch
- Making judgment calls about security tradeoffs

Using AI as a consultant is no different from using
Stack Overflow, asking a senior engineer for a code
review, or running a linter. The work is still yours.
The thinking is still yours.

I did not vibe code this. I engineered it.
The difference is 180 hours of prior work.

---

## Why Security Review Before Every Paste

The discipline of checking code before executing it
is the same discipline that makes security engineering
different from regular engineering.

Security engineers think adversarially.
What happens if the input is malicious?
What happens if the external service fails?
What happens if the loop runs forever?

Every module was reviewed for:
- Infinite loop risk
- Error handling completeness
- Input sanitization
- Compatibility with every other module
- Finding field schema correctness

Before a single line ran on hardware.

This is not paranoia. This is what separates a tool
that works in a demo from a tool that works under
real conditions with real targets and real edge cases.

---

## What This Project Proves

R3D is not a school project.

It is an autonomous security research instrument built
on 180+ hours of work that documents attack vectors
outside the current published literature.

It proves that:
- The gap between technical security and GRC can be closed
- A local LLM can produce production-quality analysis
- Novel AI attack vectors can be automated and measured
- A senior student with the right foundation can build
  something that belongs at Black Hat Arsenal or DEF CON

It will be donated to the University of Arizona
Cyber Operations program when V1 is complete.

---

## The Real Timeline

```
Research + planning:  180+ hours across 14 months
Build sprint:         21 commits, ~38 hours, 4 days
First live engagement: 28 minutes 50 seconds
Findings on first run: 9 real findings, 5 frameworks
```

Original projected timeline: 3 weeks
Actual completion: 4 days

The velocity came from one thing.
Every design decision was made before the first line
of code was written. The build was fast because the
thinking was already done.

---

## To Whoever Reads This

If you are a hiring manager:
The commits are dated. The code is public.
The architecture is documented. This was built in
4 days on top of 180 hours of prior work.
That is not a portfolio piece. That is a track record.

If you are a researcher:
TEP-005 and TEP-010 are real attack vectors that work
against enterprise LLMs that block every single-shot
payload. The research is available for authorized
installations. Reach out.

If you are a student:
Plan before you code.
The planning is the work.
The coding is just the expression of decisions
you should have already made.

-- HumdoesCyber
   March 2026
