# CIS Controls Version 8
## R3D Compliance Knowledge Base
### Source: Center for Internet Security
### Reference: https://www.cisecurity.org/controls/v8

---

## Overview

CIS Controls v8 is the most practical, actionable security
framework available. Unlike NIST 800-53 which is exhaustive,
CIS Controls gives you a prioritized list of 18 controls
that address the most common attack vectors.

R3D loads this file for personal researchers and small
businesses -- organizations that need clear, actionable
security guidance without the complexity of federal frameworks.

Why CIS Controls and not just NIST 800-53:
NIST 800-53 has over 1,000 controls written for federal
agencies with dedicated compliance teams. CIS Controls has
18 controls written for organizations with limited security
resources. For a small business or individual researcher,
CIS Controls is more immediately actionable.

Implementation Groups:
  IG1 -- Essential (all organizations, minimum baseline)
  IG2 -- Foundational (organizations with security staff)
  IG3 -- Organizational (mature security programs)

R3D maps findings to IG level so small businesses know
exactly which controls apply to them.

---

## The 18 CIS Controls

### Control 1 -- Inventory and Control of Enterprise Assets
Actively manage all hardware assets on the network.
IG Level: IG1 (essential for all)

R3D findings:
- exposed_port -- unmanaged asset discovered
- subdomain -- untracked asset discovered
- ai_surface -- unmanaged AI asset discovered
- tech_stack -- asset fingerprinted

Remediation guidance:
Maintain a current inventory of all networked assets.
Any asset R3D discovers that is not in your inventory
is an immediate security gap.

---

### Control 2 -- Inventory and Control of Software Assets
Actively manage all software on the network.
IG Level: IG1

R3D findings:
- tech_stack -- unmanaged software identified
- cve_match -- vulnerable software in inventory
- zero_day -- unclassified software discovered
- outdated_ssl -- outdated software component

---

### Control 3 -- Data Protection
Develop processes to identify, classify, and protect data.
IG Level: IG1

R3D findings:
- data_exfiltration -- data protection failure
- email_exposed -- PII exposed
- username_exposed -- personal data exposed
- js_secret -- credentials in source code

---

### Control 4 -- Secure Configuration of Enterprise Assets
Establish and maintain secure configurations.
IG Level: IG1

R3D findings:
- header_missing -- insecure default configuration
- outdated_ssl -- insecure protocol configuration
- exposed_admin -- insecure service configuration
- exposed_port -- unnecessary service enabled

Remediation guidance:
Every header_missing and outdated_ssl finding from R3D
is a direct CIS Control 4 violation. These are the
easiest wins -- fix headers and TLS in an afternoon.

---

### Control 5 -- Account Management
Use processes and tools to assign and manage credentials.
IG Level: IG1

R3D findings:
- credential_stuffing -- weak account management
- username_exposed -- account enumeration possible
- exposed_admin -- privileged account exposed
- email_exposed -- account identifier exposed

---

### Control 6 -- Access Control Management
Use processes to create, assign, manage, and revoke
access credentials and privileges.
IG Level: IG1

R3D findings:
- exposed_admin -- excessive access exposure
- trust_escalation -- access control bypass
- privilege_escalation -- unauthorized privilege gain
- credential_stuffing -- access control failure

---

### Control 7 -- Continuous Vulnerability Management
Continuously assess and track vulnerabilities on all
assets to remediate and minimize the window of opportunity.
IG Level: IG1

R3D findings -- this control covers most R3D output:
- cve_match -- known vulnerability unpatched
- zero_day -- unknown vulnerability discovered
- tech_stack -- vulnerable component identified
- outdated_ssl -- outdated component in use

Note: R3D itself is a Control 7 mechanism.
Running R3D regularly IS your continuous vulnerability
management program for small businesses.

---

### Control 8 -- Audit Log Management
Collect, alert, review, and retain audit logs.
IG Level: IG1

R3D findings:
- exposed_admin -- privileged access not logged
- data_exfiltration -- exfiltration not detectable
- trust_escalation -- session not auditable

R3D contribution:
R3D's telemetry log is a direct audit artifact.
Every action taken during an engagement is logged
with timestamps for blue team correlation.

---

### Control 9 -- Email and Web Browser Protections
Improve protections for email and web browsers.
IG Level: IG1

R3D findings:
- email_exposed -- phishing surface identified
- username_exposed -- spear phishing target
- credential_stuffing -- email account at risk

---

### Control 10 -- Malware Defenses
Prevent malware installation and execution.
IG Level: IG1

R3D findings:
- cve_match -- exploitable vulnerability for malware
- exposed_port -- malware delivery vector
- zero_day -- undetectable malware risk

---

### Control 11 -- Data Recovery
Ensure data recovery practices are sufficient.
IG Level: IG1

R3D findings:
- zero_day -- recovery plan activation likely
- data_exfiltration -- recovery and notification needed
- cve_match (critical) -- recovery consideration

---

### Control 12 -- Network Infrastructure Management
Establish and maintain network infrastructure security.
IG Level: IG2

R3D findings:
- exposed_port -- network boundary violation
- subdomain -- network asset discovered
- waf_bypass -- network protection bypassed
- outdated_ssl -- network encryption failure

---

### Control 13 -- Network Monitoring and Defense
Operate processes and tooling to establish and maintain
comprehensive network monitoring and defense.
IG Level: IG2

R3D findings:
- ai_surface -- unmonitored AI endpoint
- exposed_port -- unmonitored service
- subdomain -- unmonitored asset

R3D contribution:
R3D's telemetry log feeds directly into Control 13
monitoring requirements by documenting attack signatures.

---

### Control 14 -- Security Awareness and Skills Training
Establish and maintain a security awareness program.
IG Level: IG1

R3D findings:
- email_exposed -- phishing awareness needed
- username_exposed -- social engineering risk
- credential_stuffing -- password hygiene training needed
- trust_escalation -- AI social engineering awareness

---

### Control 15 -- Service Provider Management
Develop a process to evaluate service providers.
IG Level: IG2

R3D findings:
- tech_stack -- third party component identified
- cve_match -- vulnerable third party component
- ai_surface -- third party AI service exposed

---

### Control 16 -- Application Software Security
Manage the security life cycle of in-house developed
and acquired software.
IG Level: IG2

R3D findings:
- prompt_injection -- application input not validated
- jailbreak -- application security bypass
- header_missing -- application security misconfiguration
- js_secret -- application credential exposure
- context_manipulation -- application logic manipulation

---

### Control 17 -- Incident Response Management
Establish a program to develop and maintain incident
response capability.
IG Level: IG2

R3D findings:
All critical and high findings require incident
response consideration.

R3D contribution:
Every R3D engagement produces a telemetry log that
serves as incident response documentation.

---

### Control 18 -- Penetration Testing
Test the effectiveness of your defenses by safely
attacking your own systems.
IG Level: IG2

R3D IS the Control 18 mechanism.
Running R3D against your own systems is penetration
testing. The output IS the Control 18 deliverable.

---

## R3D CIS Controls Mapping Table

| Finding Type        | Primary Control | IG Level | Secondary    |
|---------------------|-----------------|----------|--------------|
| prompt_injection    | Control 16      | IG2      | Control 7    |
| jailbreak           | Control 16      | IG2      | Control 18   |
| trust_escalation    | Control 6       | IG1      | Control 14   |
| context_manipulation| Control 16      | IG2      | Control 8    |
| data_exfiltration   | Control 3       | IG1      | Control 11   |
| crescendo_attack    | Control 14      | IG1      | Control 16   |
| zero_day            | Control 7       | IG1      | Control 11   |
| cve_match           | Control 7       | IG1      | Control 2    |
| exposed_admin       | Control 4       | IG1      | Control 6    |
| outdated_ssl        | Control 4       | IG1      | Control 7    |
| exposed_port        | Control 4       | IG1      | Control 12   |
| header_missing      | Control 4       | IG1      | Control 16   |
| subdomain           | Control 1       | IG1      | Control 12   |
| ai_surface          | Control 1       | IG1      | Control 13   |
| email_exposed       | Control 3       | IG1      | Control 9    |
| username_exposed    | Control 5       | IG1      | Control 14   |
| tech_stack          | Control 2       | IG1      | Control 15   |
| credential_stuffing | Control 5       | IG1      | Control 9    |

---

## Implementation Guidance by Finding Severity

CRITICAL findings (score 9.0+):
  Immediate action regardless of IG level
  IG1 organizations: call your IT provider today
  IG2+ organizations: activate incident response
  Examples: zero_day, data_exfiltration, trust_escalation

HIGH findings (score 7.0-8.9):
  Remediate within 30 days
  IG1: prioritize above all other IT work
  IG2+: assign owner and track to closure
  Examples: cve_match, exposed_admin, prompt_injection

MEDIUM findings (score 5.0-6.9):
  Remediate within 90 days
  IG1: schedule with IT provider
  IG2+: include in next security review
  Examples: outdated_ssl, header_missing, exposed_port

LOW findings (score 3.0-4.9):
  Remediate within 180 days
  Track in risk register
  Examples: tech_stack, subdomain, email_exposed

---

## Why CIS Controls and Not a 400 Page Document

R3D deliberately uses CIS Controls for personal and small
business users because:

1. Actionability beats comprehensiveness
   A small business owner with no security team cannot
   implement 1,000 NIST controls. They can implement 18.
   R3D gives them what they can actually act on.

2. Context window efficiency
   Loading a 400 page framework into Ollama's context
   window degrades output quality. Ollama reasons better
   with focused, relevant information than with everything
   at once. Precision over volume.

3. IG levels match organization size
   IG1 controls are the minimum baseline every organization
   needs. R3D flags which findings are IG1 so small
   businesses know their absolute minimum required fixes.

4. The goal is risk reduction not compliance theater
   A small business that fixes all their IG1 findings
   is genuinely more secure. A business that produces
   a 400 page compliance document but fixes nothing
   is not. R3D optimizes for actual security improvement.

---

## Usage in R3D GRC Mapper

Loaded when org_type is "personal", "small_business", or "all".
Findings mapped to control number and IG level.
IG1 findings flagged as minimum baseline requirements.
Remediation guidance tailored to organization size.
Executive summary uses plain English not compliance jargon.
