"""
R3D Agent — Shared Utilities
Single source of truth for small helper functions used across multiple modules.
Import from here rather than duplicating.
"""

import re


def sanitize_filename(value: str, max_length: int = 30) -> str:
    """
    Sanitize a string for safe use in file and folder names.
    Strips anything that isn't alphanumeric, underscore, or hyphen.
    Prevents path traversal on Windows and Linux.
    Consistent across all modules — change here, applies everywhere.
    """
    sanitized = re.sub(r'[^a-zA-Z0-9_\-]', '_', value)
    return sanitized[:max_length]
