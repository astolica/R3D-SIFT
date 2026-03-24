# ISO 27001 Annex A Controls
## R3D Compliance Knowledge Base
### Source: ISO/IEC 27001:2022
### Reference: https://www.iso.org/standard/82875.html

---

## Overview

ISO 27001 is the international standard for Information
Security Management Systems (ISMS). It is the most globally
recognized security certification and is required for
organizations doing business internationally, particularly
in Europe, the Middle East, and Asia Pacific.

The 2022 revision reorganized controls into 4 themes
and 93 controls (down from 114 in the 2013 version).

R3D loads this file when org_type is "enterprise" or "all"
to map findings to ISO 27001 controls for organizations
pursuing or maintaining ISO certification.

Why ISO 27001 matters for enterprises:
- Required for EU market access in many sectors
- Demonstrates security maturity to enterprise clients
- Reduces cyber insurance premiums
- Prerequisite for many government contracts outside US

---

## Four Control Themes (ISO 27001:2022)

### Theme A -- Organizational Controls (37 controls)

A.5.1 -- Policies for Information Security
  Defines and approves information security policies.
  R3D findings: All findings indicate potential policy gap.
  Primary: header_missing, outdated_ssl, exposed_admin

A.5.7 -- Threat Intelligence
  Collects and analyzes information about threats.
  R3D findings: All findings feed threat intelligence.
  R3D IS the A.5.7 mechanism for technical threats.

A.5.8 -- Information Security in Project Management
  Integrates security into project management.
  R3D findings: ai_surface, tech_stack
  New AI deployments require security assessment.

A.5.14 -- Information Transfer
  Rules for information transfer within and outside org.
  R3D findings: data_exfiltration, email_exposed,
  outdated_ssl

A.5.15 -- Access Control
  Rules to control physical and logical access.
  R3D findings: exposed_admin, trust_escalation,
  credential_stuffing, username_exposed

A.5.16 -- Identity Management
  Full life cycle management of identities.
  R3D findings: username_exposed, credential_stuffing,
  email_exposed

A.5.17 -- Authentication Information
  Management of authentication information.
  R3D findings: credential_stuffing, exposed_admin,
  default_credentials

A.5.18 -- Access Rights
  Provision, review, modify, and remove access rights.
  R3D findings: exposed_admin, trust_escalation,
  privilege_escalation

A.5.19 -- Information Security in Supplier Relationships
  Protecting assets accessible by suppliers.
  R3D findings: tech_stack, ai_surface, cve_match
  Third party components and AI services.

A.5.23 -- Information Security for Cloud Services
  Acquisition, use, management of cloud services.
  R3D findings: ai_surface, tech_stack, subdomain
  Cloud-hosted AI surfaces and infrastructure.

A.5.24 -- Information Security Incident Management
  Planning and preparation for incident management.
  R3D findings: All critical and high findings.
  R3D telemetry log feeds incident documentation.

A.5.25 -- Assessment of Information Security Events
  Assess events and decide if classified as incidents.
  R3D findings: zero_day, cve_match, data_exfiltration

A.5.29 -- Information Security During Disruption
  Security during disruption or crisis.
  R3D findings: zero_day, cve_match (critical)

A.5.30 -- ICT Readiness for Business Continuity
  ICT readiness to meet business continuity objectives.
  R3D findings: zero_day, data_exfiltration

A.5.36 -- Compliance with Policies
  Compliance with security policies and standards.
  R3D findings: All findings indicate compliance gap.

A.5.37 -- Documented Operating Procedures
  Documented operating procedures for security.
  R3D findings: header_missing, outdated_ssl,
  configuration gaps

---

### Theme B -- People Controls (8 controls)

B.6.1 -- Screening
  Background verification of personnel.
  R3D findings: username_exposed, email_exposed
  Personnel enumeration enables targeted attacks.

B.6.3 -- Information Security Awareness and Training
  Security education and training for personnel.
  R3D findings: email_exposed, credential_stuffing,
  trust_escalation, username_exposed

B.6.4 -- Disciplinary Process
  Disciplinary process for security violations.
  R3D findings: Indirect -- insider threat context.

B.6.8 -- Information Security Event Reporting
  Reporting of security events promptly.
  R3D findings: All findings require event reporting.

---

### Theme C -- Physical Controls (14 controls)

C.7.1 -- Physical Security Perimeters
  Defines security perimeters to protect sensitive areas.
  R3D findings: exposed_port, subdomain
  Network perimeter violations.

C.7.4 -- Physical Security Monitoring
  Continuous monitoring of premises.
  R3D findings: Indirect -- network findings suggest
  physical security gaps.

C.7.8 -- Equipment Siting and Protection
  Siting and protection of equipment.
  R3D findings: exposed_port, tech_stack
  Internet-accessible operational equipment.

C.7.14 -- Secure Disposal or Reuse of Equipment
  Secure disposal to prevent data leakage.
  R3D findings: tech_stack, data_exfiltration
  Legacy systems with exposed data.

---

### Theme D -- Technological Controls (34 controls)

D.8.1 -- User Endpoint Devices
  Protection of information on user endpoints.
  R3D findings: credential_stuffing, email_exposed

D.8.2 -- Privileged Access Rights
  Management of privileged access rights.
  R3D findings: exposed_admin, trust_escalation,
  privilege_escalation

D.8.3 -- Information Access Restriction
  Restrict access to information and assets.
  R3D findings: data_exfiltration, exposed_admin,
  ai_surface

D.8.4 -- Access to Source Code
  Restrict access to source code and development tools.
  R3D findings: js_secret, exposed_admin
  Source code exposure in JS bundles.

D.8.5 -- Secure Authentication
  Secure authentication technologies and procedures.
  R3D findings: credential_stuffing, outdated_ssl,
  exposed_admin

D.8.6 -- Capacity Management
  Monitor and optimize resource usage.
  R3D findings: exposed_port, unnecessary services

D.8.7 -- Protection Against Malware
  Protection against malware.
  R3D findings: cve_match, zero_day, exposed_port

D.8.8 -- Management of Technical Vulnerabilities
  Obtain information about vulnerabilities and remediate.
  R3D findings: cve_match, zero_day, tech_stack
  R3D IS the D.8.8 mechanism.

D.8.9 -- Configuration Management
  Manage configurations of hardware, software, services.
  R3D findings: header_missing, outdated_ssl,
  exposed_port, tech_stack

D.8.10 -- Information Deletion
  Delete information when no longer required.
  R3D findings: data_exfiltration, js_secret

D.8.11 -- Data Masking
  Mask data in accordance with access control policy.
  R3D findings: data_exfiltration, email_exposed,
  js_secret

D.8.12 -- Data Leakage Prevention
  Prevent unauthorized disclosure of information.
  R3D findings: data_exfiltration, js_secret,
  email_exposed, tech_stack

D.8.13 -- Information Backup
  Maintain and test backups.
  R3D findings: zero_day (recovery consideration),
  data_exfiltration

D.8.15 -- Logging
  Produce, store, protect, and analyze event logs.
  R3D findings: exposed_admin, data_exfiltration
  R3D telemetry log is a D.8.15 artifact.

D.8.16 -- Monitoring Activities
  Monitor networks, systems for anomalous behavior.
  R3D findings: All findings -- R3D IS D.8.16.

D.8.20 -- Networks Security
  Secure, manage, and control networks.
  R3D findings: exposed_port, subdomain, waf_bypass,
  outdated_ssl

D.8.21 -- Security of Network Services
  Security mechanisms for network services.
  R3D findings: exposed_port, outdated_ssl,
  header_missing

D.8.22 -- Segregation of Networks
  Segregate networks based on trust levels.
  R3D findings: exposed_port, subdomain, waf_bypass

D.8.23 -- Web Filtering
  Manage which websites users can access.
  R3D findings: ai_surface, tech_stack

D.8.24 -- Use of Cryptography
  Rules for use of cryptography to protect information.
  R3D findings: outdated_ssl, header_missing

D.8.25 -- Secure Development Life Cycle
  Rules for secure software development.
  R3D findings: prompt_injection, jailbreak,
  header_missing, js_secret

D.8.26 -- Application Security Requirements
  Security requirements for application development.
  R3D findings: prompt_injection, jailbreak,
  context_manipulation, header_missing

D.8.27 -- Secure System Architecture and Engineering
  Principles for secure system engineering.
  R3D findings: exposed_admin, exposed_port,
  header_missing, outdated_ssl

D.8.28 -- Secure Coding
  Secure coding principles in software development.
  R3D findings: js_secret, prompt_injection,
  header_missing, context_manipulation

D.8.29 -- Security Testing in Development and Acceptance
  Security testing processes in development life cycle.
  R3D findings: All findings -- R3D IS D.8.29.

D.8.30 -- Outsourced Development
  Security requirements for outsourced development.
  R3D findings: tech_stack, ai_surface, js_secret

D.8.31 -- Separation of Development, Test, Production
  Separate development, testing, production environments.
  R3D findings: subdomain (dev/test exposed),
  tech_stack (staging systems found)

D.8.32 -- Change Management
  Manage changes to information processing facilities.
  R3D findings: tech_stack, cve_match, zero_day

D.8.33 -- Test Information
  Protect test information appropriately.
  R3D findings: subdomain (test systems exposed),
  data_exfiltration

D.8.34 -- Protection of Information Systems During Audit
  Protect systems during audit and testing activities.
  R3D findings: Operational consideration during R3D run.

---

## R3D ISO 27001 Mapping Table

| Finding Type        | Primary Control | Theme | Secondary      |
|---------------------|-----------------|-------|----------------|
| prompt_injection    | D.8.26          | D     | D.8.25, D.8.28 |
| jailbreak           | D.8.26          | D     | D.8.29, A.5.7  |
| trust_escalation    | A.5.15          | A     | D.8.2, B.6.3   |
| context_manipulation| D.8.26          | D     | D.8.28, A.5.7  |
| data_exfiltration   | D.8.12          | D     | A.5.14, D.8.11 |
| crescendo_attack    | B.6.3           | B     | D.8.26, A.5.7  |
| zero_day            | D.8.8           | D     | A.5.25, D.8.7  |
| cve_match           | D.8.8           | D     | D.8.9, D.8.32  |
| exposed_admin       | A.5.15          | A     | D.8.2, C.7.1   |
| outdated_ssl        | D.8.24          | D     | D.8.9, D.8.20  |
| exposed_port        | D.8.20          | D     | D.8.22, C.7.1  |
| header_missing      | D.8.9           | D     | D.8.27, D.8.25 |
| subdomain           | D.8.20          | D     | A.5.1, D.8.31  |
| ai_surface          | A.5.23          | A     | D.8.3, A.5.8   |
| email_exposed       | D.8.12          | D     | B.6.1, B.6.3   |
| username_exposed    | A.5.16          | A     | B.6.1, D.8.12  |
| tech_stack          | D.8.9           | D     | A.5.19, D.8.8  |
| credential_stuffing | D.8.5           | D     | A.5.17, A.5.15 |

---

## Implementation Guidance by Finding Severity

CRITICAL findings (score 9.0+):
  Immediate ISMS incident activation
  ISO 27001 clause 10.1 nonconformity process triggered
  Must be documented and root cause analyzed
  Examples: zero_day, data_exfiltration, trust_escalation

HIGH findings (score 7.0-8.9):
  Remediate within 30 days
  Document as ISMS nonconformity
  Risk treatment plan required
  Examples: cve_match, exposed_admin, prompt_injection

MEDIUM findings (score 5.0-6.9):
  Remediate within 90 days
  Include in next management review
  Examples: outdated_ssl, header_missing, exposed_port

LOW findings (score 3.0-4.9):
  Remediate within 180 days
  Track in risk register
  Examples: tech_stack, subdomain, email_exposed

---

## Usage in R3D GRC Mapper

Loaded when org_type is "enterprise" or "all".
Findings mapped to control ID and theme.
Nonconformity language used for enterprise reports.
ISO clause references included in remediation guidance.
Management review summary generated for board reporting.

