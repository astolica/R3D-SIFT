# NIST SP 800-53 Rev 5 Controls
## R3D Compliance Knowledge Base
### Source: NIST Special Publication 800-53 Revision 5
### Reference: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

---

## Overview

NIST SP 800-53 is the federal standard for security and privacy
controls for information systems and organizations. It is the
most widely adopted security framework in the United States
and forms the basis for FedRAMP, FISMA compliance, and most
enterprise security programs.

R3D maps every technical finding to specific 800-53 controls
to translate attack surface findings into compliance language
that executives and auditors understand.

---

## Control Families Relevant to R3D Findings

### AC -- Access Control

AC-2: Account Management
  Manages system accounts including creation, activation,
  modification, review, disabling, and removal.
  R3D findings: exposed_admin, credential_stuffing,
  username_exposed

AC-3: Access Enforcement
  Enforces approved authorizations for logical access.
  R3D findings: exposed_admin, privilege_escalation,
  trust_escalation

AC-4: Information Flow Enforcement
  Controls flow of information within and between systems.
  R3D findings: data_exfiltration, exposed_port

AC-6: Least Privilege
  Employs least privilege principle for all users and processes.
  R3D findings: exposed_admin, trust_escalation,
  privilege_escalation

AC-7: Unsuccessful Login Attempts
  Enforces limit on consecutive invalid access attempts.
  R3D findings: credential_stuffing, exposed_admin

AC-17: Remote Access
  Establishes usage restrictions for remote access.
  R3D findings: exposed_port, exposed_admin, vpn_exposure

---

### AT -- Awareness and Training

AT-2: Literacy Training and Awareness
  Provides security awareness training to personnel.
  R3D findings: email_exposed, username_exposed,
  phishing_surface

AT-3: Role-Based Training
  Provides role-based security training before access.
  R3D findings: credential_stuffing, social_engineering

---

### AU -- Audit and Accountability

AU-9: Protection of Audit Information
  Protects audit information and tools from unauthorized access.
  R3D findings: data_exfiltration, exposed_admin

AU-10: Non-Repudiation
  Provides irrefutable evidence that actions occurred.
  R3D findings: context_manipulation, trust_escalation

---

### CA -- Assessment, Authorization, Monitoring

CA-8: Penetration Testing
  Conducts penetration testing on systems and networks.
  R3D findings: All findings -- R3D is the CA-8 mechanism

CA-9: Internal System Connections
  Authorizes internal connections between systems.
  R3D findings: exposed_port, subdomain

---

### CM -- Configuration Management

CM-6: Configuration Settings
  Establishes and documents configuration settings.
  R3D findings: header_missing, outdated_ssl,
  exposed_admin

CM-7: Least Functionality
  Configures system to provide only essential capabilities.
  R3D findings: exposed_port, exposed_admin,
  unnecessary_services

CM-8: System Component Inventory
  Develops and maintains inventory of system components.
  R3D findings: tech_stack, subdomain, ai_surface

---

### IA -- Identification and Authentication

IA-2: Identification and Authentication (Organizational Users)
  Uniquely identifies and authenticates organizational users.
  R3D findings: credential_stuffing, exposed_admin,
  username_exposed

IA-5: Authenticator Management
  Manages system authenticators including passwords.
  R3D findings: credential_stuffing, email_exposed,
  default_credentials

IA-8: Identification and Authentication (Non-Organizational)
  Identifies and authenticates non-organizational users.
  R3D findings: exposed_admin, outdated_ssl

---

### PL -- Planning

PL-4: Rules of Behavior
  Establishes rules describing responsibilities of users.
  R3D findings: email_exposed, username_exposed

---

### RA -- Risk Assessment

RA-5: Vulnerability Monitoring and Scanning
  Monitors and scans for vulnerabilities in systems.
  R3D findings: cve_match, zero_day, tech_stack,
  subdomain -- R3D is the RA-5 mechanism

---

### SA -- System and Services Acquisition

SA-10: Developer Configuration Management
  Requires developer to manage and control changes.
  R3D findings: zero_day, cve_match, tech_stack

SA-11: Developer Testing and Evaluation
  Requires developer to create security assessment plan.
  R3D findings: prompt_injection, jailbreak,
  llm_vulnerability

---

### SC -- System and Communications Protection

SC-7: Boundary Protection
  Monitors and controls communications at boundaries.
  R3D findings: exposed_port, subdomain, waf_bypass

SC-8: Transmission Confidentiality and Integrity
  Implements cryptographic mechanisms for transmission.
  R3D findings: outdated_ssl, header_missing

SC-23: Session Authenticity
  Protects authenticity of communication sessions.
  R3D findings: outdated_ssl, session_hijacking

---

### SI -- System and Information Integrity

SI-2: Flaw Remediation
  Identifies, reports, and corrects system flaws.
  R3D findings: cve_match, zero_day, outdated_ssl

SI-3: Malicious Code Protection
  Implements malicious code protection mechanisms.
  R3D findings: jailbreak, prompt_injection

SI-10: Information Input Validation
  Checks validity of information inputs.
  R3D findings: prompt_injection, jailbreak,
  context_manipulation, trust_escalation

SI-12: Information Management and Retention
  Manages and retains information within the system.
  R3D findings: data_exfiltration, context_manipulation

SI-16: Memory Protection
  Implements memory protection mechanisms.
  R3D findings: header_missing (CSP), xss_surface

---

## R3D Control Mapping Table

| Finding Type          | Primary Controls        | Secondary Controls   |
|-----------------------|-------------------------|----------------------|
| prompt_injection      | SI-10, SI-3, SA-11      | CA-8, RA-5           |
| jailbreak             | SI-10, SI-3, CA-8       | SA-11, RA-5          |
| trust_escalation      | AC-2, AC-6, IA-2        | SI-10, AU-10         |
| context_manipulation  | SI-10, SI-12, AU-10     | CA-8, SA-11          |
| data_exfiltration     | AC-4, SI-12, AU-9       | SC-7, AC-3           |
| crescendo_attack      | SI-10, AC-17, CA-8      | AU-10, SA-11         |
| zero_day              | RA-5, SI-2, SA-10       | CA-8, CM-8           |
| cve_match             | RA-5, SI-2, SA-10       | CM-7, CA-8           |
| exposed_admin         | AC-17, CM-7, SC-7       | AC-2, AC-6           |
| outdated_ssl          | SC-8, SC-23, IA-8       | SI-2, CM-6           |
| exposed_port          | CM-7, SC-7, CA-9        | AC-4, RA-5           |
| header_missing        | SC-8, SI-16, CM-6       | SC-7, SI-10          |
| subdomain             | CM-8, RA-5, SC-7        | CA-9, CM-7           |
| ai_surface            | RA-5, CA-8, SI-10       | CM-8, SA-11          |
| email_exposed         | AT-2, PL-4, RA-5        | IA-5, AT-3           |
| username_exposed      | AT-2, PL-4, RA-5        | IA-2, AC-2           |
| tech_stack            | CM-8, RA-5, SA-10       | CM-7, SI-2           |
| credential_stuffing   | IA-5, AC-7, SI-10       | IA-2, AC-2           |

---

## Severity Guidance by Control Family

CRITICAL controls -- immediate remediation required:
  AC (Access Control) violations
  IA (Identification/Authentication) failures
  SI-10 (Input Validation) failures for LLM surfaces

HIGH controls -- remediate within 30 days:
  SC (Communications Protection) gaps
  RA-5 (Vulnerability Scanning) findings
  CM-7 (Least Functionality) violations

MEDIUM controls -- remediate within 90 days:
  AU (Audit) gaps
  AT (Training) gaps
  PL (Planning) gaps

## Implementation Guidance by Finding Severity

CRITICAL findings (score 9.0+):
  Immediate escalation to CISO or equivalent
  Controls must be verified within 24 hours
  Incident response plan activation consideration
  Examples: zero_day, data_exfiltration, trust_escalation

HIGH findings (score 7.0-8.9):
  Remediation within 30 days
  Controls must be documented as gap findings
  Risk acceptance required if not remediated
  Examples: cve_match, exposed_admin, prompt_injection

MEDIUM findings (score 5.0-6.9):
  Remediation within 90 days
  Include in next security review cycle
  Examples: outdated_ssl, header_missing, exposed_port

LOW findings (score 3.0-4.9):
  Remediation within 180 days
  Track in risk register
  Examples: tech_stack, subdomain, email_exposed
  
---

## Usage in R3D GRC Mapper

When org_type is "small_business", "enterprise", or "all":
Load this file as context for compliance mapping.
Every finding gets mapped to primary and secondary controls.
Gap analysis produced per control family.
Remediation priority assigned based on severity guidance above.
