# MITRE ATLAS Techniques
## R3D LLM Attack Knowledge Base
### Source: MITRE ATLAS v2.1 -- https://atlas.mitre.org

---

## What is MITRE ATLAS

ATLAS (Adversarial Threat Landscape for Artificial-Intelligence
Systems) is MITRE's framework for documenting adversarial
techniques against AI and ML systems. It is the AI-specific
companion to MITRE ATT&CK.

Where ATT&CK covers traditional infrastructure attacks,
ATLAS covers attacks that target the AI/ML components
specifically -- the model, the training pipeline, the
inference endpoint, and the data.

R3D maps every LLM finding to both ATT&CK (for SOC correlation)
and ATLAS (for AI-specific documentation). This dual mapping
is a differentiator -- almost no other tools do it.

---

## Reconnaissance Techniques

### AML.T0000 -- Search for Victim's Publicly Available Research
Gather information about the target's AI/ML systems from
public sources -- papers, blog posts, job listings, GitHub.

R3D application:
OSINT module searches for AI surface indicators and technology
stack disclosures that reveal what model or platform is deployed.

---

### AML.T0001 -- Search Victim-Owned Websites
Search target websites for information about AI deployments,
API endpoints, model documentation.

R3D application:
Tech stack detection and AI surface detection checks look for
chatbot interfaces, API documentation, model version disclosures.

---

### AML.T0002 -- Search for Publicly Available Adversarial Vulnerability Research
Identify known vulnerabilities in the specific AI system deployed.

R3D application:
KB files contain documented attack patterns specific to common
enterprise LLM deployments and frameworks.

---

## Resource Development

### AML.T0017 -- Develop Adversarial ML Attack Capabilities
Develop attack tools and techniques specific to the target model.

R3D application:
Tier 2 KB-guided payload generation adapts attack techniques
to the specific model and deployment context discovered during
reconnaissance.

---

## Initial Access

### AML.T0051 -- LLM Prompt Injection
Craft input that causes the LLM to perform unintended actions
by overriding or manipulating its instructions.

Subtechniques:
- Direct injection via user input
- Indirect injection via processed content
- Stored injection via persistent data

R3D payload IDs: PI-001 through PI-020
Confidence scoring: Response deviation from baseline

---

### AML.T0054 -- LLM Jailbreak
Cause the LLM to ignore its safety training and alignment,
producing outputs it was designed to refuse.

Subtechniques:
- Persona replacement (DAN variants)
- Fictional framing
- Authority framing
- Logical manipulation
- Gradual escalation (Crescendo)

R3D payload IDs: PI-007 through PI-023
Multi-turn sequences: Trust Ladder, Classic Crescendo

---

## Execution

### AML.T0040 -- ML Supply Chain Compromise
Compromise the ML pipeline -- training data, model weights,
or deployment infrastructure.

R3D application:
Infrastructure probe payloads (PI-024, PI-025) map what
external services and tools the LLM can access, identifying
supply chain attack surface.

---

### AML.T0043 -- Craft Adversarial Data
Create inputs specifically designed to cause model failure
or unexpected behavior.

R3D application:
Token smuggling and encoding attack payloads (PI-010, PI-011)
craft adversarial inputs that bypass content filters.

---

## Collection

### AML.T0057 -- LLM Data Disclosure
Cause the LLM to reveal sensitive information from its
training data, system prompt, connected databases, or
configuration.

Subtechniques:
- System prompt extraction
- Training data extraction
- Connected data source enumeration
- Credential disclosure

R3D payload IDs: PI-001 through PI-003, PI-013 through PI-015
Severity: CRITICAL when credentials or PII are disclosed

---

### AML.T0037 -- Data from Information Repositories
Extract data from repositories the ML system has access to --
document stores, databases, APIs.

R3D application:
Data exfiltration payloads probe what the model can access
and whether it can be coerced into revealing that data.

---

## Exfiltration

### AML.T0024 -- Exfiltration via ML Inference API
Use the model's inference API as a data exfiltration channel.
The model becomes an unwitting data carrier.

R3D application:
Exfiltration payloads test whether sensitive internal data
can be extracted through the chat interface.

---

## Impact

### AML.T0048 -- Erode ML Model Integrity
Cause the model to produce incorrect, biased, or harmful
outputs that degrade trust in the system.

R3D application:
Context manipulation attacks test whether the model's
responses can be persistently corrupted within a session.

---

### AML.T0029 -- Denial of ML Service
Cause the ML system to become unavailable or unresponsive.

R3D application:
Context overflow attacks test whether flooding the context
window degrades model performance or causes errors.

---

## R3D ATLAS Mapping Table

| R3D Finding Type        | ATLAS Technique  | ATT&CK Technique |
|-------------------------|------------------|------------------|
| prompt_injection        | AML.T0051        | T1190            |
| jailbreak               | AML.T0054        | T1059            |
| trust_escalation        | AML.T0054        | T1078            |
| context_manipulation    | AML.T0051        | T1565            |
| data_exfiltration       | AML.T0057        | T1041            |
| crescendo_attack        | AML.T0054        | T1078            |
| ai_surface              | AML.T0001        | T1590            |
| infrastructure_probe    | AML.T0000        | T1592            |
| credential_disclosure   | AML.T0057        | T1552            |
| tool_disclosure         | AML.T0040        | T1592            |

---

## Why ATLAS Matters for Enterprise Targets

Most enterprise security teams are familiar with ATT&CK.
Very few have mapped their AI systems to ATLAS.

When R3D produces a finding mapped to AML.T0057 LLM Data
Disclosure, it is speaking a language that a mature security
program will immediately understand and act on.

For critical infrastructure targets like utilities, the
combination of NERC CIP compliance requirements and ATLAS
technique mapping creates a complete picture:

- What happened technically (ATLAS technique)
- What it means for compliance (NERC CIP control gap)
- What ATT&CK technique the SOC should detect (ATT&CK)
- What to do about it (NIST SP 800-53 control)

No other open source tool produces this complete a picture
for AI attack findings.