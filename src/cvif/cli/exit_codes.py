"""Authoritative exit codes for the CVIF Command-Line Interface (Phase 9).

Deterministic mapping enabling CI/CD pipelines, shell scripts, and automated
evaluators to distinguish clean execution from specific security findings,
tamper events, and operational/CLI syntax errors.
"""

# Operational & Success
EXIT_SUCCESS: int = 0
EXIT_CLI_ERROR: int = 1
EXIT_CONFIG_ERROR: int = 2
EXIT_VALIDATION_ERROR: int = 3

# Security & Assurance Findings
EXIT_ASSURANCE_REVIEW: int = 10
EXIT_ASSURANCE_QUARANTINE: int = 11
EXIT_DATA_INTEGRITY_FINDING: int = 12
EXIT_MODEL_INTEGRITY_FINDING: int = 13
EXIT_PROVENANCE_FAILED: int = 14
EXIT_SHIFT_DETECTED: int = 15

# Cryptographic & Storage Integrity
EXIT_TAMPER_DETECTED: int = 20
EXIT_NOT_FOUND: int = 21

# Internal & Unsupported
EXIT_UNSUPPORTED: int = 127
EXIT_INTERNAL_ERROR: int = 128
