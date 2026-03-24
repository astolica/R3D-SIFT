# NERC CIP Standards
## R3D Compliance Knowledge Base
### Source: North American Electric Reliability Corporation
### Reference: https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx

---

## Overview

NERC CIP (Critical Infrastructure Protection) is the mandatory
cybersecurity framework for the North American bulk electric
system. Organizations classified as Bulk Electric System (BES)
owners, operators, and users must comply or face fines up to
$1 million per violation per day.

R3D loads this KB file when org_type is "critical_infrastructure"
to map findings to specific CIP standards and requirements.

This is the most consequential compliance framework in R3D --
non-compliance is not theoretical risk, it is regulatory
enforcement with documented financial penalties.

---

## Applicable Standards

### CIP-002-5.1a -- BES Cyber System Categorization
Requires identification and categorization of BES Cyber Systems
based on impact to the bulk electric system.

Relevance to R3D:
Any AI or LLM system with access to operational technology
data, grid management systems, or energy management systems
must be categorized and protected under CIP-002.

R3D findings that trigger CIP-002 review:
- ai_surface (LLM found on network)
- tech_stack (OT-adjacent technology identified)
- subdomain (new systems discovered)

---

### CIP-003-8 -- Security Management Controls
Requires documented cybersecurity policies for protecting
BES Cyber Systems.

Key requirements:
- Documented cybersecurity policy
- Leadership accountability for cybersecurity
- Delegation of authority

R3D findings: All findings indicate potential policy gaps.
Primary mapping for: exposed_admin, header_missing,
outdated_ssl, tech_stack

---

### CIP-004-7 -- Personnel and Training
Requires cyber security awareness, training, and personnel
risk assessment for individuals with access to BES Cyber Systems.

Key requirements:
- Security awareness program
- Cyber security training
- Personnel risk assessment (background checks)
- Access management

R3D findings:
- email_exposed -- personnel data exposed
- username_exposed -- staff enumeration possible
- credential_stuffing -- access control weakness
- trust_escalation -- social engineering risk

---

### CIP-005-7 -- Electronic Security Perimeters
Requires identification and protection of Electronic Security
Perimeters (ESPs) and interactive remote access.

Key requirements:
- Define and protect ESP boundaries
- Control inbound and outbound access
- Implement multi-factor authentication for remote access
- Protect dial-up connections

R3D findings:
- exposed_port -- ESP boundary violation
- exposed_admin -- unauthorized access point
- subdomain -- unprotected ESP entry point
- waf_bypass -- perimeter bypass confirmed
- outdated_ssl -- encrypted access failure

---

### CIP-006-6 -- Physical Security of BES Cyber Systems
Physical security controls for BES Cyber Systems.

R3D relevance:
Indirect -- R3D identifies network-accessible systems
that should be physically secured. Findings that suggest
internet-accessible OT systems are CIP-006 violations.

---

### CIP-007-6 -- Systems Security Management
Requires security management for BES Cyber Systems including
ports and services, security patches, malicious code prevention,
security event monitoring, and system access controls.

Key requirements:
- Disable unnecessary ports and services
- Implement security patch management
- Deploy malicious code prevention
- Monitor and log security events
- Enforce strong authentication

R3D findings -- this is the most commonly triggered standard:
- exposed_port -- ports and services violation
- cve_match -- patch management failure
- zero_day -- unpatched vulnerability
- outdated_ssl -- encryption failure
- header_missing -- security configuration gap
- prompt_injection -- malicious input not prevented
- jailbreak -- security bypass not prevented
- tech_stack -- unnecessary services exposed

---

### CIP-008-6 -- Incident Reporting and Response Planning
Requires incident response plan for cybersecurity incidents
affecting BES Cyber Systems.

Key requirements:
- Documented incident response plan
- Incident classification and reporting
- NERC reporting within 1 hour for major incidents
- Annual exercises

R3D relevance:
R3D's telemetry log is a direct input to incident response.
Every finding generates a timestamped action log that maps
to CIP-008 incident documentation requirements.

R3D findings: All critical and high findings trigger
CIP-008 incident response consideration.

---

### CIP-009-6 -- Recovery Plans for BES Cyber Systems
Requires recovery plans to ensure continuation of BES functions
after a cybersecurity incident.

R3D findings:
- zero_day -- recovery plan activation likely
- cve_match (CVSS 9+) -- recovery planning required
- data_exfiltration -- recovery and notification required

---

### CIP-010-4 -- Configuration Change Management
Requires configuration change management and vulnerability
assessments for BES Cyber Systems.

Key requirements:
- Baseline configurations documented
- Change management process
- Vulnerability assessments every 35 days (high impact)
  or 36 months (medium impact)
- Active vulnerability scanning

R3D findings:
- tech_stack -- configuration baseline deviation
- cve_match -- vulnerability assessment finding
- zero_day -- undocumented configuration
- prompt_injection -- AI system configuration gap
- jailbreak -- AI system configuration gap
- context_manipulation -- AI configuration gap

Note: R3D itself is a CIP-010 vulnerability assessment
mechanism when run against BES Cyber Systems.

---

### CIP-011-3 -- Information Protection
Requires protection of BES Cyber System Information (BCSI).

Key requirements:
- Identify and protect BCSI
- Secure storage and transit of BCSI
- Reuse and disposal controls

R3D findings:
- data_exfiltration -- BCSI exposure risk
- email_exposed -- BCSI recipient exposure
- tech_stack -- BCSI system identification
- ai_surface -- AI with BCSI access identified

---

### CIP-012-2 -- Communications between Control Centers
Protects real-time assessment and monitoring data transmitted
between control centers.

Effective: July 2026 -- directly affects Balancing Authorities.

R3D findings:
- outdated_ssl -- communication encryption failure
- exposed_port -- unprotected communication channel
- header_missing -- communication security gap

---

### CIP-013-2 -- Supply Chain Risk Management
Requires supply chain risk management plans for industrial
control system hardware, software, and services.

R3D findings:
- tech_stack -- third party component identified
- cve_match -- supply chain component vulnerable
- zero_day -- unclassified supply chain component

---

### CIP-014-3 -- Physical Security (Transmission)
Physical security for transmission stations and substations.
R3D relevance: indirect -- network findings may indicate
physical security gap in transmission infrastructure.

---

### CIP-015-1 -- Internal Network Security Monitoring (INSM)
NEW -- Effective September 2025, compliance October 2028.
Requires monitoring of network traffic inside ESPs for
anomalous activity.

R3D findings:
- ai_surface -- new monitored asset identified
- exposed_port -- traffic to monitor identified
- tech_stack -- monitoring baseline component

Note: R3D's telemetry log directly supports CIP-015
monitoring requirements by documenting attack signatures
for SIEM correlation.

---

## R3D CIP Mapping Table

| Finding Type        | Primary CIP     | Secondary CIP        |
|---------------------|-----------------|----------------------|
| prompt_injection    | CIP-007-6       | CIP-010-4, CIP-003-8 |
| jailbreak           | CIP-007-6       | CIP-010-4, CIP-003-8 |
| trust_escalation    | CIP-004-7       | CIP-007-6, CIP-003-8 |
| context_manipulation| CIP-007-6       | CIP-010-4, CIP-011-3 |
| data_exfiltration   | CIP-011-3       | CIP-007-6, CIP-008-6 |
| crescendo_attack    | CIP-004-7       | CIP-007-6, CIP-010-4 |
| zero_day            | CIP-007-6       | CIP-010-4, CIP-009-6 |
| cve_match           | CIP-007-6       | CIP-010-4, CIP-013-2 |
| exposed_admin       | CIP-005-7       | CIP-007-6, CIP-003-8 |
| outdated_ssl        | CIP-005-7       | CIP-007-6, CIP-012-2 |
| exposed_port        | CIP-005-7       | CIP-007-6, CIP-010-4 |
| header_missing      | CIP-007-6       | CIP-010-4, CIP-003-8 |
| subdomain           | CIP-005-7       | CIP-007-6, CIP-002-5 |
| ai_surface          | CIP-007-6       | CIP-010-4, CIP-015-1 |
| email_exposed       | CIP-004-7       | CIP-011-3, CIP-003-8 |
| username_exposed    | CIP-004-7       | CIP-011-3, CIP-007-6 |
| tech_stack          | CIP-010-4       | CIP-007-6, CIP-013-2 |
| credential_stuffing | CIP-004-7       | CIP-007-6, CIP-005-7 |

---

## Financial Penalty Reference

NERC CIP violations carry mandatory financial penalties:

| Violation Level | Penalty Range          |
|-----------------|------------------------|
| Lower VSL       | $1,000 - $50,000/day   |
| Moderate VSL    | $50,000 - $200,000/day |
| High VSL        | $200,000 - $500,000/day|
| Severe VSL      | Up to $1,000,000/day   |

VSL = Violation Severity Level

R3D includes penalty context in executive reports for
critical infrastructure targets to communicate financial
risk in business terms that boards and executives understand.

## Violation Severity Level Guidance

When R3D finds a critical infrastructure target vulnerable:

Severe VSL conditions (highest penalty):
  - BES Cyber System directly accessible from internet
  - Authentication bypassed on control system
  - Unencrypted transmission of operational data
  - Zero day on grid management system
  R3D findings: zero_day + exposed_port + outdated_ssl
  combined on critical infrastructure target

High VSL conditions:
  - Known CVE unpatched beyond required timeframe
  - ESP boundary violation confirmed
  - BCSI transmitted without encryption
  R3D findings: cve_match, waf_bypass, outdated_ssl

Moderate VSL conditions:
  - Configuration baseline deviation
  - Incomplete vulnerability assessment
  R3D findings: tech_stack, header_missing, subdomain
  
---

## Usage in R3D GRC Mapper

Loaded when org_type is "critical_infrastructure" or "all".
Every finding mapped to primary and secondary CIP standards.
Financial penalty context included in PDF executive report.
CIP compliance gap sheet generated as separate XLSX tab.
Findings sorted by CIP standard then by severity.
