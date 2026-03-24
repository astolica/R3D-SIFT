# NIST AI Risk Management Framework
## R3D Compliance Knowledge Base
### Source: NIST AI RMF 1.0 + AI 600-1
### Reference: https://airc.nist.gov/Home

---

## Overview

The NIST AI Risk Management Framework (AI RMF) is the first
federal framework specifically designed to manage risks from
AI systems. Released January 2023 with AI 600-1 supplement
in July 2024 covering Generative AI specifically.

R3D loads this file for any org type where AI surfaces
are discovered -- regardless of organization type.
If R3D finds an exposed LLM or AI chatbot, AI RMF
controls apply regardless of whether the target is
a small business or a utility.

Why AI RMF matters now:
Most organizations deploying AI have no framework for
managing AI-specific risks. The OWASP LLM Top 10 covers
technical vulnerabilities. AI RMF covers the organizational
risk management process around AI deployment.

R3D is one of the first tools to map AI attack findings
to AI RMF controls -- this is a genuine differentiator
from every other scanning tool on the market.

---

## Four Core Functions

### GOVERN -- Organizational Accountability

GOVERN 1 -- Policies and Processes
  Establishes policies and processes for AI risk management.

  GOVERN 1.1: AI risk management policies are in place.
  R3D findings: ai_surface without documented policy

  GOVERN 1.2: Accountability for AI risk is assigned.
  R3D findings: ai_surface, trust_escalation
  Who owns the AI system R3D found?

  GOVERN 1.3: Organizational teams are committed to
  AI risk management.
  R3D findings: All LLM findings indicate governance gap.

  GOVERN 1.4: Organizational teams document the risks
  of AI systems across the life cycle.
  R3D findings: prompt_injection, jailbreak,
  trust_escalation -- undocumented attack vectors

  GOVERN 1.5: Organizational risk tolerance for AI is
  established and communicated.
  R3D findings: All LLM findings -- is this risk accepted?

  GOVERN 1.6: Policies require AI risks to be tracked.
  R3D findings: All LLM findings require tracking.

  GOVERN 1.7: Processes are in place for AI incident
  response.
  R3D findings: All critical LLM findings.

GOVERN 2 -- Accountability Structures
  GOVERN 2.1: Roles and responsibilities for AI risk
  management are defined.
  R3D findings: ai_surface -- who is responsible?

  GOVERN 2.2: Teams have the skills and training
  to manage AI risk.
  R3D findings: trust_escalation, crescendo_attack
  Social engineering attacks require trained responders.

GOVERN 4 -- Organizational Culture
  GOVERN 4.1: Organizational teams document AI risks.
  R3D findings: All LLM attack findings.

  GOVERN 4.2: Organizational teams are committed to
  ethical AI deployment.
  R3D findings: jailbreak, trust_escalation
  Ethical deployment requires red team testing.

GOVERN 6 -- Policies Include AI in Third Party Relationships
  GOVERN 6.1: Policies require AI risks from third
  party relationships to be managed.
  R3D findings: ai_surface (third party AI found),
  tech_stack (AI infrastructure identified)

  GOVERN 6.2: Contingency processes for third party
  AI failures are in place.
  R3D findings: ai_surface dependency identified.

---

### MAP -- Risk Identification and Classification

MAP 1 -- Context is Established
  MAP 1.1: Context of AI deployment is understood.
  R3D findings: ai_surface -- context not documented

  MAP 1.5: Organizational risk tolerance for the
  specific AI deployment is identified.
  R3D findings: All LLM findings -- risk not assessed

  MAP 1.6: Risks to third parties from AI deployment
  are identified.
  R3D findings: data_exfiltration via AI surface

MAP 2 -- Scientific and Technical Understanding
  MAP 2.1: Scientific understanding of AI technology
  is applied to risk identification.
  R3D findings: prompt_injection, jailbreak,
  trust_escalation -- technical attack vectors documented

  MAP 2.2: Scientific understanding is applied to
  identify AI-specific risks.
  R3D findings: crescendo_attack, context_manipulation
  Novel attack vectors documented by R3D research.

MAP 3 -- AI Risks Are Prioritized
  MAP 3.1: Risks are prioritized based on likelihood
  and impact.
  R3D findings: All LLM findings scored by confidence
  and severity.

  MAP 3.2: AI risks are compared to organizational
  risk tolerance.
  R3D findings: Trust escalation findings -- compare
  to acceptable risk threshold.

MAP 4 -- Risks Are Documented
  MAP 4.1: Approaches to risk treatment are
  documented and communicated.
  R3D findings: All findings -- treatment in report.

  MAP 4.2: Risk documentation is shared with
  appropriate stakeholders.
  R3D findings: R3D PDF report IS MAP 4.2 artifact.

MAP 5 -- Likelihood and Impact Are Prioritized
  MAP 5.1: Likelihood of the AI risk is estimated.
  R3D confidence scores serve as likelihood estimates.

  MAP 5.2: Practices for adversarial testing are
  established.
  R3D IS the MAP 5.2 adversarial testing mechanism.

---

### MEASURE -- Risk Analysis and Assessment

MEASURE 1 -- AI Risks Are Identified and Assessed
  MEASURE 1.1: Approaches to identify AI risks
  are defined.
  R3D three-tier attack architecture IS MEASURE 1.1.

  MEASURE 1.3: Internal experts test and evaluate
  AI systems for risks.
  R3D IS the MEASURE 1.3 mechanism.

MEASURE 2 -- AI Risk Metrics Are Established
  MEASURE 2.1: Test sets are developed to measure
  AI risk.
  R3D static payload library IS MEASURE 2.1 test set.

  MEASURE 2.2: Evaluations of AI systems are
  performed and documented.
  R3D engagement reports ARE MEASURE 2.2 documentation.

  MEASURE 2.3: AI system performance is assessed
  against benchmarks.
  R3D confidence scoring measures guardrail performance.

  MEASURE 2.5: AI system risks are periodically
  re-evaluated.
  Regular R3D runs implement periodic re-evaluation.

  MEASURE 2.6: Evaluations are documented.
  R3D PDF and XLSX outputs ARE evaluation documentation.

  MEASURE 2.7: AI risk measurement is shared with
  relevant stakeholders.
  R3D executive report IS stakeholder communication.

MEASURE 2.10 -- Privacy Risk of AI
  Privacy risks from AI systems are measured.
  R3D findings: data_exfiltration via AI surface,
  PII extraction via LLM attack.

MEASURE 2.11 -- Fairness and Bias
  Fairness and bias testing is applied.
  R3D findings: Indirect -- attack surface context.

MEASURE 2.13 -- Effectiveness of Risk Treatments
  Effectiveness of risk treatments is evaluated.
  R3D re-runs validate that remediations worked.

MEASURE 3 -- Risk Tracking
  MEASURE 3.1: Feedback processes for AI incidents
  are defined.
  R3D telemetry log IS MEASURE 3.1 feedback mechanism.

  MEASURE 3.2: Risk tracking approaches are used.
  R3D XLSX risk register IS MEASURE 3.2 tracking tool.

MEASURE 4 -- Feedback Informs AI Risk Management
  MEASURE 4.1: Post-deployment risks are monitored.
  Regular R3D runs implement post-deployment monitoring.

  MEASURE 4.2: Measurement results are taken into
  account in the overall AI risk management process.
  R3D improvement engine feeds back into KB updates.

---

### MANAGE -- Risk Response and Recovery

MANAGE 1 -- Risks Are Prioritized and Addressed
  MANAGE 1.1: A risk treatment plan is developed.
  R3D PDF report includes remediation for every finding.

  MANAGE 1.2: Residual risks are documented.
  R3D risk register documents residual risk scores.

  MANAGE 1.3: Responses to the AI risks are communicated.
  R3D executive report IS the communication artifact.

MANAGE 2 -- Risk Treatments Are Planned
  MANAGE 2.1: Resources required to manage AI risk
  are taken into account.
  R3D findings: Remediation effort estimated per finding.

  MANAGE 2.2: Mechanisms to sustain value of AI are
  managed.
  R3D findings: Balance security against functionality.

  MANAGE 2.4: Residual negative risks are documented.
  R3D risk register documents all residual risks.

MANAGE 3 -- Risk Response Is Communicated
  MANAGE 3.1: AI risk response plans include
  communication responsibilities.
  R3D telemetry log feeds SOC communication.

  MANAGE 3.2: Emergency response processes for AI
  risks are established.
  R3D findings: Critical LLM findings trigger
  emergency response consideration.

MANAGE 4 -- Risks Are Monitored and Reported
  MANAGE 4.1: Post-deployment AI risks are monitored.
  Periodic R3D runs implement MANAGE 4.1.

  MANAGE 4.2: Measurable performance improvements
  are identified.
  R3D improvement engine tracks finding trends.

---

## Generative AI Specific Controls (AI 600-1)

NIST AI 600-1 addresses risks specific to Generative AI
systems -- the exact systems R3D tests.

Key risk categories from AI 600-1:

CBRN Information Exposure:
  Risk that GenAI reveals dangerous information.
  R3D findings: data_exfiltration, jailbreak

Data Privacy:
  Risk that GenAI exposes personal data.
  R3D findings: data_exfiltration, prompt_injection

Human-AI Configuration:
  Risk from misconfigured human-AI interaction.
  R3D findings: trust_escalation, crescendo_attack

Information Integrity:
  Risk that GenAI produces false information.
  R3D findings: context_manipulation, jailbreak

Information Security:
  Risk that GenAI enables security breaches.
  R3D findings: All LLM attack findings.

Prompt Injection:
  Risk that malicious inputs manipulate GenAI.
  R3D findings: prompt_injection -- direct mapping.

Confabulation (Hallucination):
  Risk that GenAI produces false confident outputs.
  R3D verifier module addresses this for R3D itself.

Harmful Bias and Homogenization:
  Risk of systematic bias in GenAI outputs.
  R3D findings: Indirect context.

---

## R3D AI RMF Mapping Table

| Finding Type        | GOVERN    | MAP       | MEASURE      | MANAGE    |
|---------------------|-----------|-----------|--------------|-----------|
| prompt_injection    | GOV 1.4   | MAP 2.1   | MEA 2.1      | MAN 1.1   |
| jailbreak           | GOV 1.4   | MAP 2.1   | MEA 2.2      | MAN 1.1   |
| trust_escalation    | GOV 2.2   | MAP 2.2   | MEA 2.3      | MAN 1.1   |
| context_manipulation| GOV 1.4   | MAP 2.2   | MEA 2.2      | MAN 1.2   |
| data_exfiltration   | GOV 1.5   | MAP 3.1   | MEA 2.10     | MAN 3.2   |
| crescendo_attack    | GOV 2.2   | MAP 2.2   | MEA 2.3      | MAN 1.1   |
| ai_surface          | GOV 1.1   | MAP 1.1   | MEA 1.1      | MAN 4.1   |
| jailbreak           | GOV 4.2   | MAP 2.1   | MEA 2.1      | MAN 1.1   |

---

## Implementation Guidance by Finding Severity

CRITICAL findings (score 9.0+):
  Immediate AI system review and potential suspension
  GOVERN: Activate AI incident response process
  MAP: Re-assess AI risk tolerance immediately
  MEASURE: Document finding as measurement failure
  MANAGE: Execute emergency response plan
  Examples: zero_day on AI, data_exfiltration via LLM,
  trust_escalation confirmed

HIGH findings (score 7.0-8.9):
  Remediate within 30 days
  GOVERN: Document as policy gap
  MAP: Add to risk register with treatment plan
  MEASURE: Include in next AI evaluation cycle
  MANAGE: Assign owner and track to closure
  Examples: prompt_injection, jailbreak confirmed

MEDIUM findings (score 5.0-6.9):
  Remediate within 90 days
  Include in next AI governance review cycle
  Examples: context_manipulation, ai_surface exposure

LOW findings (score 3.0-4.9):
  Remediate within 180 days
  Track in AI risk register
  Examples: tech_stack adjacent to AI system

---

## Why AI RMF Matters for R3D Specifically

R3D is one of the only tools that tests AI systems AND
maps findings to AI RMF controls. This combination is
unique in the current market.

When R3D finds a prompt injection vulnerability and maps
it to GOVERN 1.4, MAP 2.1, MEASURE 2.1, and MANAGE 1.1
simultaneously -- it is doing work that currently requires
a team of GRC analysts and a separate red team to produce.

For critical infrastructure operators running AI systems:
The combination of NERC CIP + AI RMF mapping in a single
R3D report is genuinely novel. No other tool produces this.

---

## Usage in R3D GRC Mapper

Loaded when ai_surface findings exist regardless of org_type.
Also loaded when org_type is "critical_infrastructure" or "all".
Every LLM finding mapped across all four AI RMF functions.
AI 600-1 GenAI risk categories applied to LLM findings.
Executive summary includes AI governance recommendations.

