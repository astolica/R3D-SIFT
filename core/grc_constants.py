"""
R3D Agent — GRC Constants
Shared compliance mapping tables used by both report_gen and grc_mapper.

One source of truth. When NIST updates a control number or we refine a mapping,
change it here — both the PDF report and the XLSX compliance sheet stay in sync.
Duplicate dicts in two files = drift. This prevents that.
"""

# NIST SP 800-53 Rev 5 control mapping
# Maps each finding type to the most relevant controls.
# Err toward specificity — SI-10 (Information Input Validation)
# beats generic RA-5 (Risk Assessment) wherever possible.
NIST_MAPPING = {
    "prompt_injection":     ["SI-10", "SI-3", "SA-11"],
    "jailbreak":            ["SI-10", "SI-3", "CA-8"],
    "trust_escalation":     ["AC-2", "AC-6", "IA-2"],
    "context_manipulation": ["SI-10", "SI-12", "AU-10"],
    "data_exfiltration":    ["AC-4", "SI-12", "AU-9"],
    "crescendo_attack":     ["SI-10", "AC-17", "CA-8"],
    "zero_day":             ["RA-5", "SI-2", "SA-10"],
    "cve_match":            ["RA-5", "SI-2", "SA-10"],
    "exposed_admin":        ["AC-17", "CM-7", "SC-7"],
    "outdated_ssl":         ["SC-8", "SC-23", "IA-8"],
    "exposed_port":         ["CM-7", "SC-7", "CA-9"],
    "header_missing":       ["SC-8", "SI-16", "CM-6"],
    "subdomain":            ["CM-8", "RA-5", "SC-7"],
    "ai_surface":           ["RA-5", "CA-8", "SI-10"],
    "email_exposed":        ["AT-2", "PL-4", "RA-5"],
    "username_exposed":     ["AT-2", "PL-4", "RA-5"],
    "tech_stack":           ["CM-8", "RA-5", "SA-10"],
    "credential_stuffing":  ["IA-5", "AC-7", "SI-10"],
    "default":              ["RA-5", "CA-8", "SI-2"],
}

# NERC CIP mapping
# CIP-015-1 = Internal Network Security Monitoring — maps correctly
# for AI surfaces (monitoring internal OT network for AI interaction)
# versus CIP-010-4 (Configuration Change Management) which is
# less specific to the AI exposure vector.
NERC_CIP_MAPPING = {
    "prompt_injection":     ["CIP-007-6", "CIP-010-4"],
    "jailbreak":            ["CIP-007-6", "CIP-010-4"],
    "trust_escalation":     ["CIP-004-7", "CIP-007-6"],
    "context_manipulation": ["CIP-007-6", "CIP-010-4"],
    "data_exfiltration":    ["CIP-011-3", "CIP-007-6"],
    "crescendo_attack":     ["CIP-007-6", "CIP-004-7"],
    "zero_day":             ["CIP-007-6", "CIP-010-4"],
    "cve_match":            ["CIP-007-6", "CIP-010-4"],
    "exposed_admin":        ["CIP-005-7", "CIP-007-6"],
    "outdated_ssl":         ["CIP-005-7", "CIP-007-6"],
    "exposed_port":         ["CIP-005-7", "CIP-007-6"],
    "header_missing":       ["CIP-007-6", "CIP-010-4"],
    "subdomain":            ["CIP-005-7", "CIP-007-6"],
    "ai_surface":           ["CIP-007-6", "CIP-015-1"],
    "email_exposed":        ["CIP-004-7", "CIP-011-3"],
    "username_exposed":     ["CIP-004-7", "CIP-011-3"],
    "tech_stack":           ["CIP-010-4", "CIP-007-6"],
    "credential_stuffing":  ["CIP-004-7", "CIP-007-6"],
    "default":              ["CIP-007-6", "CIP-010-4"],
}
