# Phase 9/12 — Architecture Audit: Command-Line Interface (CLI)

**Document Reference**: `phase_9_architecture_audit.md`  
**Evaluation Role**: Independent Architecture & Forensic Security Auditor  
**Evaluation Date**: 2026-09-19  
**Target Subsystem**: Phase 9 CLI (`src/cvif/cli/`)  
**Underlying Subsystems**: Phases 1–8 Foundation, Ingestion, Model Integrity, Inference Provenance, Distribution Shift, Assurance Aggregation, and Evidence Store  
**Regression Baseline**: 247 / 247 tests passing (Phases 1–8 fully verified)  

---

## 1. Executive Summary

This architecture audit evaluates the readiness, security specification, determinism, and phase boundary compliance for **Phase 9: Command-Line Interface (CLI)** of the Computer Vision Integrity Assurance Framework (CVIF).

The audit establishes that:
1. **Core Architectural Readiness**: All underlying business logic, security detectors, cryptographic primitives, relational indexing, evidence storage, and assurance aggregation engines were fully implemented and independently verified in Phases 1 through 8.
2. **Strict Presentation/Control Boundary**: The Phase 9 CLI is designed exclusively as an operator interface and orchestration controller. It does NOT duplicate core security, detection, cryptographic, or verdict logic. It maps CLI arguments directly to the established Phase 2–8 services.
3. **Deterministic Automation Contract**: A standardized exit-code taxonomy (`0` for success, `10` for `REVIEW`, `11` for `QUARANTINE`, `12`–`15` for domain-specific security findings, `20` for cryptographic tampering, and `1`–`3` for CLI/config errors) enables reliable CI/CD and pipeline automation.
4. **Clean JSON/Stdout Separation**: A strict output contract guarantees that `--json` mode emits parseable, deterministic JSON on `stdout`, completely isolating all diagnostic, warning, and progress output to `stderr`.
5. **Air-Gap & Safety Preservation**: The CLI inherits all path traversal defenses (`safe_resolve_path`), mandatory model safety scans (`ModelSafetyScanner`), write-once evidence immutability (`EvidenceStore`), and air-gapped zero-network isolation.
6. **Dependency Assessment**: The project architecture specifies Typer. The audit documents that `typer` is not yet installed in `.venv` or declared in `pyproject.toml`. The audit details the exact implementation specification for Typer as well as a zero-dependency standard-library fallback (`argparse`), ready for Owner Review.

No architectural blockers were identified. Phase 9 is fully specified and ready for implementation upon owner review.

---

## 2. Phase 9 Scope

The Phase 9 CLI delivers a unified, local, scriptable command-line interface providing command groups that directly expose the capabilities delivered in Phases 1–8:

### In-Scope Functional Areas
1. **System & Health Diagnostics**:
   - Version, build metadata, and air-gap confinement verification (`cvif version`).
   - Local database, directory, and cryptographic key status inspection (`cvif status`).
   - Monotonic audit log hash-chain integrity verification (`cvif audit verify`).
2. **Dataset Ingestion & Integrity Analysis**:
   - Ingesting COCO and YOLO formatted datasets with perceptual hashing (`cvif dataset ingest`).
   - Executing dataset integrity analysis across threats DT-1 through DT-6 (`cvif data scan`).
3. **Model Safety & Integrity Analysis**:
   - Scanning raw model files for deserialization exploits, zip bombs, and header corruption (`cvif model scan-safety`).
   - Executing model integrity tests across threats MT-1 through MT-4 (`cvif model scan`).
4. **Inference Provenance Verification**:
   - Verifying cryptographic signatures, contributor keys, model bindings, and replay nonces (`cvif provenance verify`).
5. **Distribution Shift Analysis**:
   - Comparing reference baseline datasets against operational datasets across shift threats DS-1 through DS-4 (`cvif shift analyze`).
6. **Assurance Aggregation & Verdict Generation**:
   - Aggregating session findings into dimension risk scores, evaluating critical veto rules, and synthesizing an `AssuranceVerdict` (`cvif assess`).
7. **Evidence Store Inspection & Export**:
   - Querying and filtering indexed evidence records (`cvif evidence list`).
   - Fetching evidence records with cryptographic integrity verification (`cvif evidence get`).
   - Verifying store consistency across the physical filesystem and SQLite index (`cvif evidence verify`).
   - Packaging evidence and artifacts into offline transit bundles (`cvif evidence export`).

### Strictly Excluded (Belonging to Later Phases)
- **Phase 10**: REST API (FastAPI / OpenAPI endpoints, server daemon).
- **Phase 11**: Analyst UI Dashboard (Streamlit / web visualization).
- **Phase 12**: Production containerization, Docker packaging, and deployment hardening.

---

## 3. Command Matrix

The following matrix formally defines all Phase 9 CLI commands, arguments, defaults, and expected exit codes:

| Command | Subcommand | Required Arguments | Optional Arguments | Defaults | Input / Output Paths | Expected Exit Codes |
|---|---|---|---|---|---|---|
| `cvif` | `version` | *None* | `--json` | `--json=False` | Input: *None*<br>Output: `stdout` | `0` (Success) |
| `cvif` | `status` | *None* | `--config PATH`, `--json` | `--config=None`<br>`--json=False` | Input: Configured data dirs<br>Output: `stdout` | `0` (Healthy)<br>`20` (Audit Compromised)<br>`1` (Storage Inaccessible) |
| `cvif` | `audit verify` | *None* | `--log-file PATH`, `--config PATH`, `--json` | `--log-file=data/audit/audit.jsonl`<br>`--json=False` | Input: Audit log file<br>Output: `stdout` | `0` (Chain Intact)<br>`20` (Chain Tampered)<br>`1` (File Missing) |
| `cvif` | `dataset ingest` | `--data-dir PATH` | `--format [coco\|yolo\|auto]`, `--contributor-id STR`, `--batch-id STR`, `--config PATH`, `--json` | `--format=auto`<br>`--contributor-id=local`<br>`--json=False` | Input: Dataset directory<br>Output: DB registration row | `0` (Ingested)<br>`1` (Invalid Path/Format)<br>`3` (Validation Error) |
| `cvif` | `data scan` | `--data-dir PATH` *(or `--dataset-id UUID`)* | `--session-id UUID`, `--contributor-id STR`, `--config PATH`, `--json`, `--output PATH` | `--session-id=new_uuid`<br>`--json=False` | Input: Dataset files<br>Output: Findings + Evidence | `0` (Clean)<br>`12` (Data Integrity Findings)<br>`1` (Path Error) |
| `cvif` | `model scan-safety` | `--model-path PATH` | `--config PATH`, `--json` | `--json=False` | Input: Model file<br>Output: Safety report | `0` (Safe)<br>`13` (Unsafe Model / Exploit)<br>`1` (File Not Found) |
| `cvif` | `model scan` | `--model-path PATH` | `--reference-weights PATH`, `--dataset-path PATH`, `--session-id UUID`, `--config PATH`, `--json` | `--session-id=new_uuid`<br>`--json=False` | Input: Model + weights<br>Output: Findings + Evidence | `0` (Clean)<br>`13` (Model Integrity Findings)<br>`1` (Model Load Error) |
| `cvif` | `provenance verify` | `--record-file PATH` *(or `--record-json STR`)* | `--raw-image PATH`, `--model-digest STR`, `--config PATH`, `--json` | `--json=False` | Input: Inference record<br>Output: Verification result | `0` (Verified Valid)<br>`14` (Provenance Verification Failed)<br>`1` (File Error) |
| `cvif` | `shift analyze` | `--reference-data PATH`, `--evaluation-data PATH` | `--session-id UUID`, `--config PATH`, `--json` | `--session-id=new_uuid`<br>`--json=False` | Input: Reference & eval data<br>Output: Shift findings + Evidence | `0` (No Shift Detected)<br>`15` (Distribution Shift Detected)<br>`1` (Data Load Error) |
| `cvif` | `assess` | `--session-id UUID` | `--config PATH`, `--json`, `--output PATH` | `--json=False` | Input: Session findings in DB<br>Output: AssuranceVerdict | `0` (`ACCEPT`)<br>`10` (`REVIEW`)<br>`11` (`QUARANTINE`)<br>`21` (Session Not Found) |
| `cvif` | `evidence list` | *None* | `--session-id UUID`, `--finding-id UUID`, `--threat-id STR`, `--type STR`, `--config PATH`, `--json` | All filters `None`<br>`--json=False` | Input: SQLite metadata index<br>Output: Evidence record list | `0` (Success)<br>`1` (Query Error) |
| `cvif` | `evidence get` | `--id UUID` | `--no-verify`, `--config PATH`, `--json`, `--output PATH` | `--no-verify=False`<br>`--json=False` | Input: Evidence file + DB digest<br>Output: Canonical JSON | `0` (Verified & Returned)<br>`20` (Tamper Detected)<br>`21` (ID Not Found) |
| `cvif` | `evidence verify` | *None* | `--session-id UUID`, `--config PATH`, `--json` | `--session-id=None`<br>`--json=False` | Input: Filesystem + SQLite DB<br>Output: Consistency report | `0` (100% Consistent)<br>`20` (Tampered / Missing Items) |
| `cvif` | `evidence export` | `--session-id UUID`, `--output PATH` | `--config PATH`, `--json` | `--json=False` | Input: Session evidence & artifacts<br>Output: `.cvif` zip bundle | `0` (Exported)<br>`20` (Tampered Before Export)<br>`21` (Session Not Found) |

---

## 4. CLI Framework

### Evaluation of Options
1. **Typer (Primary Architecture Specification)**:
   - Built on top of Click with Python 3.10+ type-annotation parsing.
   - Seamless integration with Pydantic schemas (native type conversion for `UUID`, `Path`, `float`, and enums).
   - Generates clean, intuitive `--help` screens automatically.
   - Supports sub-applications via `typer.Typer()` to cleanly separate command groups (`evidence`, `model`, `dataset`, `audit`).
   - *Dependency Observation*: `typer` is not currently declared in `pyproject.toml` or installed in `.venv`.
2. **Argparse (Standard Library Fallback)**:
   - 100% built into Python 3.10+ standard library.
   - Zero additional third-party dependencies, zero wheel installation, zero network requirements, and zero supply-chain exposure.
   - Capable of implementing the identical sub-command matrix via `argparse.ArgumentParser.add_subparsers()`.
   - Requires manual type-casting and custom help formatting.

### Architectural Recommendation
- **Primary Design**: Standardize on **Typer** (`typer>=0.9.0,<1.0.0`) as specified in the frozen architecture.
- **Strict Stdout Isolation Rule**: When using Typer, terminal colorization and rich formatting must be explicitly suppressed when `--json` is active or when `stdout` is redirected to a pipe, ensuring machine-readable JSON is never corrupted by ANSI escape codes.
- **Owner Review Decision**: If the project authority permits updating `pyproject.toml` and installing `typer` from a local wheel or package repository, proceed with Typer. If a strict zero-new-dependencies policy is enforced, use `argparse` as a direct, drop-in replacement with the exact same CLI command signatures.

---

## 5. CLI/Core Boundary

The CLI is strictly an adapter and controller. It must adhere to the following architectural invariants:

```
[ Terminal / Analyst / CI Script ]
                │
                ▼
      [ cvif.cli (Phase 9) ]
   ├── Argument Parsing & Validation (Paths, UUIDs, Enums)
   ├── Config Resolution (load_config)
   └── Output Formatting (Human Tables / JSON stdout)
                │
                ▼
 [ Application & Orchestration Services ]
   ├── IngestionGateway (Phase 3)
   ├── DatasetIntegrityOrchestrator (Phase 3)
   ├── ModelSafetyScanner & ModelIntegrityOrchestrator (Phase 4)
   ├── InferenceProvenanceVerifier (Phase 5)
   ├── DistributionShiftOrchestrator (Phase 6)
   ├── AssuranceOrchestrator (Phase 7)
   ├── EvidenceStore (Phase 8)
   └── AuditLogger (Phase 2)
                │
                ▼
    [ Cryptographic & Storage Layer ]
      SQLite DB, SafeFileStore, Hash Chains, Ed25519, SHA-256
```

### Prohibited CLI Duplication
- **NO Cryptographic Calculations in CLI**: The CLI must never call `hashlib.sha256` or `hmac` directly; it must invoke `cvif.crypto` or `EvidenceStore`.
- **NO Risk Aggregation in CLI**: The CLI must never calculate risk scores, weighted averages, or threshold comparisons; it must invoke `AssuranceOrchestrator.evaluate_session()`.
- **NO Direct Model Loading in CLI**: The CLI must never call `torch.load` or `pickle.load` directly; it must pass paths to `ModelSafetyScanner` and the appropriate `ModelAdapter`.
- **NO Raw File Manipulation in CLI**: The CLI must never read or write raw evidence files directly; it must interface exclusively through `EvidenceStore`.

---

## 6. Security Boundary

The CLI receives untrusted user inputs (arguments, flags, filenames, environment variables) and must enforce the following security boundaries:

1. **Path Traversal Containment**:
   - All input paths (`--data-dir`, `--model-path`, `--record-file`, `--reference-data`, `--output`) must be validated against path traversal attacks (`..`, null bytes `\x00`, drive letters where disallowed).
   - Evidence retrieval and artifact operations inherit the rigorous containment checks implemented in `store.py` (`_validate_safe_relative_path` and `safe_resolve_path`).
2. **Model Deserialization Protection**:
   - Running `cvif model scan` on an arbitrary `.pth` or `.pkl` file could expose the system to arbitrary code execution.
   - The CLI architecture mandates that `validate_model_file_safety()` is invoked *before* any model adapter attempts to load weights.
3. **Write-Once Evidence Immutability**:
   - The CLI does NOT provide any `evidence delete` or `evidence update` commands.
   - Any attempt to overwrite an existing evidence record or artifact path via CLI analysis tools will fail closed with `EvidenceImmutableError`.
4. **Air-Gap Preservation**:
   - The CLI imports only local standard-library and verified project modules.
   - Zero outbound HTTP, DNS, cloud SDK, or telemetry connections.

---

## 7. Exit Code Contract

To support unambiguous, deterministic pipeline automation, exit codes are partitioned into three distinct semantic ranges:

```
[0]             SUCCESS / ACCEPT
[1 - 9]         OPERATIONAL & CLI ERRORS (Bad syntax, missing files, config errors)
[10 - 19]       SECURITY & ASSURANCE FINDINGS (Threats detected, review/quarantine)
[20 - 29]       CRYPTOGRAPHIC & INTEGRITY TAMPERING (Hash mismatch, broken chain)
[127 - 128]     INTERNAL & UNSUPPORTED ERRORS
```

### Authoritative Exit Code Mapping

| Code | Symbol | Meaning / Triggering Condition |
|---|---|---|
| `0` | `EXIT_SUCCESS` | Command completed successfully. For `cvif assess`, disposition is `ACCEPT`. |
| `1` | `EXIT_CLI_ERROR` | Bad syntax, unrecognized argument, missing required flag, or non-existent file path. |
| `2` | `EXIT_CONFIG_ERROR` | Configuration file missing, unparseable, or schema validation failed. |
| `3` | `EXIT_VALIDATION_ERROR` | Schema validation error on input payloads (e.g. malformed UUID, invalid enum). |
| `10` | `EXIT_ASSURANCE_REVIEW` | `cvif assess` synthesized verdict with disposition `REVIEW`. |
| `11` | `EXIT_ASSURANCE_QUARANTINE` | `cvif assess` synthesized verdict with disposition `QUARANTINE` or critical veto. |
| `12` | `EXIT_DATA_INTEGRITY_FINDING` | `cvif data scan` detected HIGH or CRITICAL data poisoning / trigger / label-flip threat. |
| `13` | `EXIT_MODEL_INTEGRITY_FINDING` | `cvif model scan` or `scan-safety` detected backdoor, modification, or exploit. |
| `14` | `EXIT_PROVENANCE_FAILED` | `cvif provenance verify` failed (invalid signature, untrusted key, or replay attack). |
| `15` | `EXIT_SHIFT_DETECTED` | `cvif shift analyze` detected significant covariate, semantic, or adversarial shift. |
| `20` | `EXIT_TAMPER_DETECTED` | Cryptographic hash mismatch in evidence record, artifact digest, or audit chain. |
| `21` | `EXIT_NOT_FOUND` | Requested evidence ID, session ID, or asset ID does not exist in database or store. |
| `127` | `EXIT_UNSUPPORTED` | Operation or model format is unsupported in the current air-gapped environment. |
| `128` | `EXIT_INTERNAL_ERROR` | Unhandled internal exception occurred. |

---

## 8. Assurance Verdict Semantics

The Phase 7 `AssuranceOrchestrator` produces an `AssuranceVerdict` with three potential dispositions: `ACCEPT`, `REVIEW`, and `QUARANTINE`. The CLI represents these dispositions with zero reinterpretation:

1. **Strict Presentation Fidelity**:
   - The CLI displays the exact `composite_risk_score` (rounded to 4 decimal places for display), `dimension_risks`, `critical_veto_applied` flag, and `unsupported_checks`.
   - The CLI cannot modify weights, recompute risks, or override dispositions.
2. **Deterministic Exit Codes**:
   - `ACCEPT` $\rightarrow$ Exit Code `0`
   - `REVIEW` $\rightarrow$ Exit Code `10`
   - `QUARANTINE` $\rightarrow$ Exit Code `11`
3. **No "Force-Accept" Bypass**:
   - The CLI does not provide a `--force-accept` or `--ignore-veto` flag. Overriding a quarantine verdict is architecturally prohibited at the CLI level.

---

## 9. Output Contract

The CLI supports two mutually exclusive output modes:

### 1. Human-Readable Mode (Default)
- Formatted summary cards, boxed headers, and tabular results.
- Colored status badges (Green = `ACCEPT` / `VALID`, Yellow = `REVIEW` / `WARNING`, Red = `QUARANTINE` / `TAMPER`).
- Honors `NO_COLOR=1` environment variable to disable ANSI colors in non-interactive terminals.

### 2. Machine-Readable Mode (`--json`)
- Deterministic JSON structure.
- Sorted keys (`sort_keys=True`) and standard 2-space indentation (or compact single-line if piped).
- Pydantic models serialized via `model_dump(mode="json")`.
- Guaranteed valid JSON on `stdout`.

---

## 10. stdout/stderr Contract

To ensure that automated scripts (e.g. `cvif assess --session-id ... --json | jq .disposition`) operate without parse failures:

1. **`stdout` Contract**:
   - In `--json` mode, `stdout` contains **ONLY** the raw JSON payload.
   - Zero banner messages, informational logs, progress bars, or debug messages may be written to `stdout`.
2. **`stderr` Contract**:
   - All logging events, diagnostic messages, progress spinners, warnings, and error descriptions are written strictly to `stderr`.
   - In case of command failure, human error descriptions are written to `stderr`, while `--json` mode additionally outputs an error JSON object `{ "error": true, "code": ..., "message": ... }` to `stderr` or `stdout` depending on CLI conventions.

---

## 11. Configuration Handling

Configuration resolution follows a strict, non-overriding precedence chain:

1. **CLI Flag (`--config PATH`)**: Explicit user-provided configuration file.
2. **Environment Variable (`CVIF_CONFIG_PATH`)**: Path set in operational shell.
3. **Project Default (`config/default_config.yaml`)**: Standard repo configuration.
4. **Built-in Fallback (`AppConfig()`)**: Safe internal defaults.

### Security Invariants
- CLI flags can customize runtime parameters (e.g. `--batch-size`, `--device`), but CANNOT disable core security locks (e.g. `air_gap_enforced: true`, `strict_hash_checks: true`).
- If an explicit `--config PATH` does not exist or is invalid YAML, the command must immediately abort with Exit Code `2` (`EXIT_CONFIG_ERROR`) rather than silently falling back to defaults.

---

## 12. Air-Gap & Offline Enforcement

1. **Zero External Communication**:
   - No CLI command may initialize HTTP clients, socket listeners, DNS queries, or telemetry loggers.
   - All dependency imports are validated against the standard library and local packages.
2. **Offline Runtime Verification**:
   - Tests will execute under the identical socket monkeypatch blocker established in Phase 2 (`test_offline.py` and `test_category_r_air_gap_offline_confinement`).
   - Attempting any socket creation during CLI execution raises a fatal runtime exception.

---

## 13. Error Handling & Exception Boundary

All CLI commands execute within an outer exception boundary that catches CVIF domain exceptions and maps them to clean user-facing output:

```python
try:
    # Execute core command logic
    ...
except PathTraversalError as e:
    log_error(f"Security Error: {e}")
    sys.exit(EXIT_CLI_ERROR)
except ConfigurationError as e:
    log_error(f"Configuration Error: {e}")
    sys.exit(EXIT_CONFIG_ERROR)
except SchemaValidationError as e:
    log_error(f"Validation Error: {e}")
    sys.exit(EXIT_VALIDATION_ERROR)
except TamperDetectedError as e:
    log_error(f"Integrity Violation: {e}")
    sys.exit(EXIT_TAMPER_DETECTED)
except EvidenceImmutableError as e:
    log_error(f"Immutability Violation: {e}")
    sys.exit(EXIT_TAMPER_DETECTED)
except CVIFError as e:
    log_error(f"Operational Error: {e}")
    sys.exit(EXIT_CLI_ERROR)
except Exception as e:
    if debug_mode:
        traceback.print_exc(file=sys.stderr)
    log_error(f"Internal Error: {e}")
    sys.exit(EXIT_INTERNAL_ERROR)
```

- Raw Python tracebacks are suppressed by default to prevent stack trace information leakage (Threat CT-12).
- Tracebacks are enabled only when `--debug` or `--verbose` is explicitly passed.

---

## 14. Logging Architecture

The CLI maintains strict separation across four distinct logging and output channels:

1. **Machine/Human Output (`stdout`)**: Command result artifacts, tables, or JSON summaries.
2. **Operational Diagnostics (`stderr`)**: User-facing status messages, warnings, and error descriptions.
3. **Application Log (`data/logs/cvif.log`)**: File-based technical logging governed by `LoggingConfig`.
4. **Tamper-Evident Audit Ledger (`data/audit/audit.jsonl`)**: Cryptographic SHA-256 chained audit events recorded via `AuditLogger`.

The CLI commands must NOT bypass `AuditLogger`. Actions that alter state (dataset ingestion, model scans, verdict synthesis, artifact storage) must continue to trigger their underlying `AuditEventType` records.

---

## 15. Evidence Store Integration

Commands interacting with evidence (`cvif evidence list`, `get`, `verify`, `export`) must use `EvidenceStore` and `DatabaseManager` exclusively:

1. **No Raw Filesystem Bypasses**: The CLI does not read `{evidence_id}.json` directly using `open()`; it calls `store.get_evidence(evidence_id, verify_integrity=True)`.
2. **Integrity Enforcement**:
   - `cvif evidence get` verifies record and artifact digests by default.
   - If a file or artifact was altered on disk, the command immediately raises `TamperDetectedError`, outputs the mismatch details to `stderr`, and exits with code `20`.
3. **Store Consistency Command**:
   - `cvif evidence verify` executes `store.verify_store_consistency()`, outputting a complete audit of missing files, tampered records, and corrupted artifacts.

---

## 16. Session / Run Model

All CLI analysis runs operate within the established `AnalysisSession` lifecycle:

1. **Session Identification**:
   - Commands accept an optional `--session-id UUID`.
   - If omitted, a fresh UUIDv4 is automatically generated: `session_id = uuid4()`.
2. **Asset Binding**:
   - The asset under analysis (`dataset_id` or `model_path` / `asset_id`) is linked to the session in SQLite `sessions` table.
3. **Finding & Evidence Association**:
   - All emitted findings and evidence records reference the active `session_id`.
   - `cvif assess --session-id <UUID>` uses this relational linkage to query all findings recorded for that session.

---

## 17. Input Validation

The CLI enforces fail-fast validation before initiating expensive or security-sensitive core operations:

- **Path Existence**: Verifies that input files and directories exist before passing them to adapters.
- **UUID Format**: Validates that all `--session-id`, `--finding-id`, `--dataset-id`, and `--id` parameters conform strictly to RFC 4122 UUID syntax.
- **Enum Bounds**: Ensures that `--format` is strictly in `[coco, yolo, auto]` and `--type` matches `EvidenceType` values.
- **Mutual Exclusion**: Verifies that conflicting options (e.g. `--data-dir` and `--dataset-id`) are not supplied simultaneously.

---

## 18. Determinism

For identical input files, configuration, and environment, the CLI must produce deterministic output:

1. **JSON Key Sorting**: Guaranteed via `sort_keys=True` in serialization.
2. **List Ordering**: Evidence and finding lists are sorted chronologically by `created_at` or alphabetically by ID.
3. **Timestamp Handling**: Serialized in ISO 8601 UTC format (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`).

---

## 19. Interactive vs. Non-Interactive Execution

- **Non-Interactive by Default**: All CLI commands execute without requiring user keyboard input (no `input()` or interactive prompts). This is mandatory for automated test runners and CI pipelines.
- **Confirmation Flags**: If any potentially destructive or high-impact maintenance command is added in future phases, a `--yes` / `-y` flag must be supported to bypass confirmation prompts in headless environments.

---

## 20. Performance Expectations

- **CLI Startup Overhead**: Argument parsing and dispatcher startup must complete in **< 50 milliseconds**.
- **Index Queries**: Commands such as `cvif evidence list` and `cvif evidence get` query the indexed SQLite tables, completing in **< 20 milliseconds**.
- **Heavy Analysis Operations**: Ingestion, model safety scanning, and distribution shift analysis depend on dataset and model sizes, with feature extraction and probe battery execution remaining bounded by configured batch sizes (`ResourceConfig.batch_size`).

---

## 21. Help & Documentation Contract

1. **Top-Level Help**: `cvif --help` displays all available command groups (`dataset`, `model`, `provenance`, `shift`, `assess`, `evidence`, `audit`, `status`, `version`).
2. **Subcommand Help**: Every subcommand provides `--help` detailing required parameters, optional flags, environment variable overrides, and usage examples.
3. **Accurate Security Descriptions**: Help text must not claim capabilities not implemented in the framework (e.g. it must clearly note that safety scanning inspects model file containers and formats, while integrity scanning runs behavioral reference batteries).

---

## 22. Versioning

- `cvif version` and `cvif --version` must read dynamically from `cvif.version.__version__` or package distribution metadata (`importlib.metadata.version("cvif")`).
- The version must NOT be hard-coded separately inside CLI source files.

---

## 23. Test Architecture (Categories A–T)

The Phase 9 test suite will be structured in `tests/unit/test_cli.py` covering 20 comprehensive test categories:

- **Category A**: CLI invocation and entry point startup.
- **Category B**: `--help` output across top-level and all subcommands.
- **Category C**: Handling of invalid/unrecognized commands.
- **Category D**: Handling of missing required arguments and malformed flags.
- **Category E**: Handling of non-existent input files and paths.
- **Category F**: Path traversal defense on CLI arguments (`../`, absolute paths, null bytes).
- **Category G**: Machine-readable JSON output validity (`--json` parseable by `json.loads`).
- **Category H**: Human-readable table and badge formatting.
- **Category I**: Strict `stdout` vs `stderr` separation in `--json` mode.
- **Category J**: Exit code verification across all mapped exit conditions.
- **Category K**: Configuration file loading, `--config` flag, and environment variable overrides.
- **Category L**: EvidenceStore integration (`cvif evidence list` and `get`).
- **Category M**: Tampered evidence detection via `cvif evidence get` and `verify`.
- **Category N**: Assurance `ACCEPT` verdict exit code (`0`).
- **Category O**: Assurance `REVIEW` verdict exit code (`10`).
- **Category P**: Assurance `QUARANTINE` verdict exit code (`11`).
- **Category Q**: Air-gap offline confinement (execution under socket blocker).
- **Category R**: Deterministic JSON output reproducibility across repeated runs.
- **Category S**: Headless, non-interactive script execution.
- **Category T**: Full repository regression (all 247 Phase 1–8 baseline tests remain passing).

---

## 24. Anti-Stub Requirements

The Phase 9 implementation must strictly avoid all stub and fake patterns:
1. **No Fake Results**: Commands must invoke the live underlying Phase 2–8 engines; commands that simply print canned strings or exit 0 without executing core logic are strictly prohibited.
2. **No Hard-Coded Verdicts**: `cvif assess` must invoke `AssuranceOrchestrator.evaluate_session()` on live database findings.
3. **Keyword Audit**: Production CLI code must contain zero `TODO`, `FIXME`, `mock`, `stub`, `placeholder`, `random`, or `randint` statements.

---

## 25. Security Threat Model (CLI Threats CT-1 to CT-12)

The CLI architecture addresses the following twelve specific threats:

| Threat ID | Threat Name | Attack Scenario | Mitigation in Phase 9 Architecture |
|---|---|---|---|
| **CT-1** | Path Traversal Injection | Attacker supplies `../../etc/shadow` as dataset or config path | All CLI paths resolved via `safe_resolve_path()` against designated roots |
| **CT-2** | Argument Injection | Special characters or shell metacharacters in CLI parameters | Parameterized parsing via CLI framework; no `shell=True` subprocess calls |
| **CT-3** | Config Tampering | Attacker supplies malicious config disabling air-gap or hash checks | Config validation rejects weakening of immutable security parameters |
| **CT-4** | Evidence Integrity Bypass | Attempting to suppress tamper detection or force-read tampered record | `verify_integrity=True` enforced by default; fail-closed exception on mismatch |
| **CT-5** | Model Exploit Bypass | Supplying malicious pickle file to `cvif model scan` | CLI enforces `ModelSafetyScanner` execution before any model adapter is loaded |
| **CT-6** | Verdict Manipulation | Supplying flags to force `ACCEPT` on quarantined assets | CLI has zero verdict override flags; displays authoritative verdict only |
| **CT-7** | Terminal Injection | ANSI escape sequence injection via finding narrative or asset names | Terminal output sanitized; raw binary bytes stripped from console strings |
| **CT-8** | JSON Stream Contamination | Log messages or warnings mixed into `stdout` corrupting `jq` pipes | Strict `stdout`/`stderr` separation: JSON only on `stdout`, logs on `stderr` |
| **CT-9** | Exit Code Confusion | Security findings returning exit code 0 causing automated CI to pass | Deterministic non-zero exit codes for `REVIEW` (10), `QUARANTINE` (11), findings |
| **CT-10** | Unauthorized Filesystem Access | Exporting evidence to system folders | Output directory paths validated and restricted to user-accessible paths |
| **CT-11** | Network Telemetry Leakage | CLI library attempting to check for updates or send telemetry | Air-gapped dependency audit; zero telemetry libraries allowed |
| **CT-12** | Information Leakage | Stack traces exposing internal paths or keys in error output | Global exception boundary suppresses tracebacks unless `--debug` is active |

---

## 26. Dependency Audit

1. **Current Dependencies in `pyproject.toml`**:
   - `pydantic>=2.6.0` (present: 2.13.5)
   - `cryptography>=42.0.0` (present: 50.0.1)
   - `pyyaml>=6.0` (present: 6.0.3)
2. **CLI Framework Dependency Status**:
   - The architecture specifies **Typer**.
   - `typer` is **NOT currently declared** in `pyproject.toml` and **NOT installed** in `.venv`.
   - `argparse` is available immediately as part of Python 3.10+ standard library.
3. **Compatibility**:
   - Typer is fully compatible with Python 3.10+ and Pydantic v2.
   - If Typer is installed, `typer>=0.9.0` will be declared under `dependencies` in `pyproject.toml`.

---

## 27. Phase Boundary Confinement

The Phase 9 implementation must be strictly confined to:
- Package: `src/cvif/cli/`
- Entrypoint script / module: `src/cvif/cli/main.py`
- Setup script entry point: `cvif = "cvif.cli.main:app"` (or `run_cli`)
- Tests: `tests/unit/test_cli.py`

Zero code from Phase 10 (REST API / FastAPI routes), Phase 11 (UI / Streamlit dashboards), or Phase 12 (Docker / deployment) may be introduced.

---

## 28. Blocker Analysis

| Potential Concern | Severity | Concrete Evidence | Impact | Status / Resolution |
|---|---|---|---|---|
| Core Orchestrator Readiness | None | All Phase 2–8 components passing 247 tests | Core services ready for CLI invocation | **RESOLVED** |
| CLI Framework Dependency | Medium (Non-blocking) | `typer` not yet installed in `.venv` | If Typer is chosen, requires updating `pyproject.toml` | **OWNER DECISION** (Typer vs stdlib `argparse`) |
| stdout Contamination | Low (Non-blocking) | Rich text / logs could corrupt `--json` | Piped automation could fail if logs leak to stdout | **SPECIFIED**: Strict stderr routing |
| Security Invariant Preservation | None | Verified in `store.py`, `safety.py`, `verifier.py` | Full fail-closed protection inherited | **RESOLVED** |

**Conclusion**: There are **ZERO BLOCKERS**. All core prerequisites are satisfied.

---

## 29. Non-Blocking Improvements

1. **Shell Autocompletion**:
   - Support `cvif --install-completion` for Bash, Zsh, and PowerShell when Typer is utilized.
2. **Terminal Auto-Detection**:
   - Automatically suppress ANSI colors when output is redirected to a non-TTY pipe, even if `--json` was not explicitly passed.
3. **Quiet Mode Flag (`-q` / `--quiet`)**:
   - Support a global `--quiet` flag to suppress non-essential diagnostic output on `stderr`.

---

## 30. Final Recommendation

The Phase 9 CLI architecture is thoroughly specified, cryptographically sound, air-gap compliant, and strictly separated from core business logic. All underlying Phase 1–8 services are verified and operational.

The implementation plan should proceed upon owner review of the dependency selection (Typer vs stdlib `argparse`).

---

PHASE 9 READY FOR IMPLEMENTATION — AWAITING OWNER REVIEW
