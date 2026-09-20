# Phase 2/12 — Foundation Verification Gate Report

**Project**: Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines  
**Stakeholder**: Ministry of Defence (MoD) / Indian Army (DGIS)  
**Theme**: Blockchain & Cybersecurity  
**Architecture Specification**: Version 0.2-REVISED  
**Review Type**: Independent Technical Quality Gate Audit  
**Date**: September 18, 2026  

---

## A. Executive Verdict

An exhaustive, independent verification of the Phase 2 Foundation implementation has been conducted against the approved architecture specification v0.2-REVISED (`implementation_plan.md`), the repository source files, and the test suite.

The foundation layer successfully establishes:
1. A reproducible Python 3.10 virtual environment with strictly pinned dependencies.
2. Canonical Pydantic v2 data contracts with deterministic canonical JSON and byte serialization.
3. Cryptographic primitives including streaming SHA-256, constant-time HMAC-SHA256, Ed25519 digital signatures, and an air-gapped local Trust Store (`KeyStore`).
4. A SQLite storage foundation (`DatabaseManager`) with WAL mode, foreign-key constraints, and transaction management, accompanied by a path-traversal-hardened filesystem store (`SafeFileStore`).
5. A tamper-evident append-only JSONL audit logger (`AuditLogger`) enforcing monotonic SHA-256 hash chains with chain verification and corruption detection.
6. A write-once immutable evidence repository (`EvidenceStore`).
7. Abstract adapter contracts (`ModelAdapter`, `DatasetAdapter`, `FeatureExtractor`) with strict access-level enforcement (blocking white-box inspection methods on black-box models).
8. A pure standard-library fallback feature extractor (`StatisticalFeatureExtractor`) for air-gapped bootstrapping.
9. A 38-test deterministic test suite that runs 100% offline with verified zero socket/network activity.
10. Strict adherence to phase boundaries: no Phase 3–8 detection/analysis algorithms were prematurely implemented.

All 38 foundation unit tests pass in 0.40 seconds. A few minor non-blocking discrepancies and recommendations for downstream phases were identified (such as adding an explicit `sequence_number` field to `AuditEvent` and strengthening `EvidenceRecord` content validation).

**Status**: **FOUNDATION VERIFIED WITH NON-BLOCKING IMPROVEMENTS**

---

## B. Architecture Conformance

The actual implementation was compared line-by-line against `implementation_plan.md` v0.2-REVISED:

| Architecture Component | Target Specification | Actual Implementation | Status | Evidence |
|:---|:---|:---|:---|:---|
| **Project Structure** | Section AD.1 (`core`, `crypto`, `storage`, `audit`, `evidence`, `model`, `ingestion`, `features`, `utils`, `tests`) | Exact match in `src/cvif/` and `tests/` | **CORRECT** | Directory structure inspection of `src/cvif/` |
| **Python Environment** | Section AA / AD-10 (Python >= 3.10, pinned dependencies) | Python 3.10.11 in `.venv`, exact pins in `requirements.lock` | **CORRECT** | `pyproject.toml`, `requirements.lock` |
| **Packaging** | Standard editable setuptools build | `pyproject.toml` with `setuptools.build_meta`, editable install verified | **CORRECT** | `pyproject.toml` lines 1–34 |
| **Core Schemas** | Section I (I.1 to I.11) | Pydantic v2 models with `schema_version = "1.0"` and canonical byte dumps | **PARTIAL** | `src/cvif/core/schemas.py` (see Section C) |
| **Configuration** | Section W / System Config | `AppConfig` / `CVIFConfig` with path resolution and YAML parsing | **CORRECT** | `src/cvif/core/config.py`, `config/default_config.yaml` |
| **Storage Foundation** | Section W.1 & W.2 | SQLite `DatabaseManager` (WAL, FKs, index tables) and `SafeFileStore` | **CORRECT** | `src/cvif/storage/database.py`, `filestore.py` |
| **Filesystem Safety** | Section AC.2 (Path traversal defense) | `safe_resolve_path` using `os.path.commonpath` boundary verification | **CORRECT** | `src/cvif/storage/filestore.py` lines 12–32 |
| **Cryptographic Primitives** | Section O.1 & O.2 | SHA-256 (streaming), HMAC-SHA256, Ed25519, hash chain | **CORRECT** | `src/cvif/crypto/hashing.py`, `hmac.py`, `signing.py`, `chain.py` |
| **Audit Trail** | Section S.1 & S.2 | Tamper-evident JSONL audit logger with monotonic hash chain | **CORRECT** | `src/cvif/audit/logger.py` |
| **Evidence Store** | Section R.1 & R.2 | Write-once `EvidenceStore` with session artifact management | **CORRECT** | `src/cvif/evidence/store.py` |
| **ModelAdapter** | Section K.2 | `ModelAdapter` ABC enforcing `ModelTask` and `ModelAccessLevel` | **CORRECT** | `src/cvif/model/adapter.py` |
| **DatasetAdapter** | Section J.3 | `DatasetAdapter` ABC with `validate()`, `iter_samples()` | **CORRECT** | `src/cvif/ingestion/adapters/base.py` |
| **FeatureExtractor** | Section K.5 | `FeatureExtractor` ABC and `StatisticalFeatureExtractor` fallback | **CORRECT** | `src/cvif/features/base.py`, `statistical.py` |
| **Logging** | Section 10 / Structured Logging | `setup_logger` with `SecurityRedactionFilter` | **CORRECT** | `src/cvif/utils/logging.py` |
| **Error Handling** | Section Z.1 | `CVIFError` hierarchy with specialized exception classes | **CORRECT** | `src/cvif/core/exceptions.py` |
| **Testing Infrastructure** | Section X.1 | Pytest suite, isolated temp directories, mock adapters | **CORRECT** | `tests/conftest.py`, `tests/unit/` |
| **Offline Operation** | Section V.1 (Air-Gapped Operation) | Fully offline runtime, verified via socket-blocking test | **CORRECT** | `tests/unit/test_offline.py` |

---

## C. Schema Audit

Inspection of `src/cvif/core/schemas.py`:

1. **Schema Completeness**:
   All mandatory architectural schemas exist:
   - `AssetRegistration` & `HashManifest` (I.1)
   - `Finding` (I.2)
   - `EvidenceRecord` & `ArtifactReference` (I.3)
   - `AssuranceVerdict` (I.4)
   - `InferenceRecord` (I.5)
   - `AuditEvent` (I.6)
   - `ShiftReport` & `ShiftAssessment` (I.7)
   - `PredictionResult`, `ClassificationOutput`, `DetectionOutput`, `SegmentationOutput` (I.8)
   - `AnalysisSession` (I.10)
   - `ValidationResult` (I.11)
   - `KeyRecord` (Trust Store)

2. **Schema Versioning**:
   Every persistent schema (`AssetRegistration`, `Finding`, `EvidenceRecord`, `AssuranceVerdict`, `InferenceRecord`, `AuditEvent`, `ShiftReport`, `AnalysisSession`) defines `schema_version: str = Field(default="1.0")`.

3. **Canonical Serialization & Determinism**:
   `CVIFBaseModel` provides:
   - `to_canonical_json()`: Dumps model dict in `json` mode, formats with `sort_keys=True` and separators `(',', ':')`.
   - `to_canonical_bytes()`: Canonical UTF-8 bytes for hashing, HMAC, and Ed25519 signing.
   - Tested in `test_schemas.py::test_evidence_record_deterministic_canonical_bytes` (round-trip equality verified).

4. **PredictionResult Polymorphism**:
   - Appropriately discriminates based on `task_type: ModelTask`.
   - `DetectionOutput` strictly enforces normalized bounding box geometry (`x_min <= x_max`, `y_min <= y_max`) and normalized coordinate ranges (`[0.0, 1.05]`). Rejection of inverted or out-of-bound bounding boxes is tested and verified.

5. **Identified Schema Discrepancies (Non-Blocking)**:
   - **`AuditEvent.sequence_number`**: `implementation_plan.md` Section I.6 specified `sequence_number: int # Monotonically increasing, gapless`. `src/cvif/core/schemas.py` omitted `sequence_number`, relying on list position and hash-chain linkage instead.
   - **`EvidenceRecord` Content Validator**: `implementation_plan.md` states "at least one of metrics, artifacts, baseline_comparison, raw_data_ref must be present". In `schemas.py`, `@field_validator` contains a comment indicating content validation occurs at the full record level, returning `v` without raising if all 4 are `None`.
   - **`ShiftReport.dimensions` Structure**: `implementation_plan.md` specified `dimensions: list[ShiftDimension]`. `schemas.py` implemented `dimensions: Dict[str, ShiftDimensionResult]`. The dictionary implementation is practically superior for key-based lookups, but is an architectural deviation from the YAML list format.

---

## D. Cryptographic Audit

Inspection of `src/cvif/crypto/`:

1. **Hashing (`hashing.py`)**:
   - `sha256_bytes` and `sha256_string` use Python's native `hashlib.sha256`.
   - `sha256_file` streams files in 64 KB chunks (`chunk_size=65536`), preventing memory exhaustion when hashing large model weights or dataset archives.
   - `sha256_canonical_json` ensures deterministic dictionary hashing with sorted keys.
   - Standard test vector verified in `test_crypto.py`: empty string produces NIST standard digest `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

2. **HMAC (`hmac.py`)**:
   - `compute_hmac_sha256` correctly implements RFC 2104 HMAC-SHA256.
   - `verify_hmac_sha256` uses `hmac.compare_digest` for constant-time comparison, mitigating timing attacks.

3. **Digital Signatures (`signing.py`)**:
   - Uses `cryptography.hazmat.primitives.asymmetric.ed25519`.
   - Ed25519 does not require nonce generation (deterministic EdDSA RFC 8032), avoiding RNG failure vulnerabilities.
   - Raw key material is strictly 32 bytes (64 hex characters). Length checks prevent truncated key injections.
   - `verify_ed25519` safely catches `InvalidSignature` and `ValueError`, returning a clean boolean without crashing.

4. **Trust Store (`keystore.py`)**:
   - Thread-safe local key repository backed by `threading.RLock`.
   - Supports key lifecycle: `ACTIVE`, `SUSPENDED`, `REVOKED`, `EXPIRED`.
   - `check_key_validity` enforces expiration against timezone-aware UTC now.
   - Atomic persistence via temporary file replace.
   - **Observation**: HMAC secrets in `truststore.json` are stored in plaintext hex. In production, this file must be protected with strict OS filesystem permissions (e.g., Windows ACLs restricting read access to the CVIF service account).

5. **InferenceRecord Canonical Payload Binding**:
   - `InferenceRecord.compute_canonical_payload()` binds:
     `input_image_hash`, `model_id`, `model_weight_digest`, `preprocessing_config_hash`, `inference_config`, and `output`.
   - **Observation**: `sequence_number`, `nonce`, and `timestamp` are checked at the record verification layer (`seen_nonces` table, sequence tracking) rather than being inside the HMAC payload itself. This strictly adheres to the architecture in Section N.3/N.4, but binding `nonce` and `sequence_number` into the HMAC payload would provide an even stronger defense against transport tampering.

---

## E. Storage and Filesystem Security Audit

Inspection of `src/cvif/storage/`:

1. **Database Manager (`database.py`)**:
   - Thread-isolated connections using `threading.local()`.
   - WAL mode enabled (`PRAGMA journal_mode = WAL;`) for concurrent reads and writes.
   - Foreign keys enforced (`PRAGMA foreign_keys = ON;`).
   - Busy timeout set to 5000 ms to prevent lock contention crashes.
   - Atomic transactions managed via `@contextmanager transaction()`.
   - Replay defense table `seen_nonces` uses an atomic `SELECT ... INSERT` transaction.

2. **Filesystem Security (`filestore.py`)**:
   - `safe_resolve_path` uses `os.path.commonpath([str(base), str(target)]) == str(base)`.
   - Prevents directory traversal (`../`, `..\\`, absolute path overrides, and cross-drive jumps on Windows).
   - Rejection of path traversal verified in `test_storage.py::test_filestore_path_traversal_protection`.
   - Atomic file writes implemented using `tempfile.mkstemp` in the target directory followed by `os.replace`.

3. **Evidence Store Immutability (`store.py`)**:
   - Enforces write-once persistence.
   - Once an `evidence_id` is registered, subsequent write attempts raise `EvidenceImmutableError`.
   - Verified in `test_evidence.py::test_evidence_store_write_once_immutability`.

---

## F. Audit Trail Security

Inspection of `src/cvif/audit/logger.py` and `src/cvif/crypto/chain.py`:

1. **Hash Chain Mechanism**:
   - Genesis link: `previous_event_hash = "0" * 64`.
   - Subsequent link: $H_n = \text{SHA-256}(E_n \parallel H_{n-1})$.
   - Canonical representation computed over:
     `event_id`, `timestamp` (ISO8601), `event_type`, `actor`, `asset_id`, `session_id`, `details`, `previous_event_hash`, `schema_version`.
   - Optional Ed25519 signature over `event_hash`.

2. **Tamper Detection Capabilities**:
   The test suite proves the following properties in `test_audit.py`:
   - Valid chain verifies successfully.
   - Modifying an event's payload in the JSONL file breaks hash verification (`Corrupted event content`).
   - Deleting an event breaks chain continuity (`Broken chain link`).
   - Reordering events breaks chain continuity (`Broken chain link`).
   - Appending an unauthorized event with an incorrect previous hash is detected (`Broken chain link`).

3. **Security Boundary & Real Guarantees**:
   - **Guaranteed Property**: The audit log provides *tamper-evidence against arbitrary local mutation, record removal, record insertion, or reordering* assuming the verifier has a trusted anchor (either the genesis block or a trusted chain tip).
   - **Realistic Limitation**: If an adversary gains unrestricted root-level write access to the host disk, they could theoretically regenerate an entirely new valid hash chain from genesis *unless* events are digitally signed with an off-host / hardware-protected private key. The framework supports this via `AuditEvent.signature`, and external root checkpointing should be enforced in operational deployments.

---

## G. Model Safety Audit

Inspection of `src/cvif/model/safety.py`:

1. **Preflight Checks Implemented**:
   - Validates file existence and non-zero size.
   - Enforces allowlisted extensions: `.onnx`, `.pt`, `.pth`, `.torchscript`, `.bin`.
   - Scans the first 1 MB for dangerous pickle opcodes:
     `b"cos\nsystem"`, `b"cposix\nsystem"`, `b"cbuiltins\neval"`, `b"cbuiltins\nexec"`, `b"c__builtin__\neval"`, `b"c__builtin__\nexec"`, `b"subprocess"`, `b"shutil"`.
   - Verified in `test_adapters.py::test_model_file_safety`.

2. **Crucial Security Scope Clarification**:
   - **The current implementation is a static preflight scanner, NOT an execution sandbox.**
   - Hostile pickle payloads can easily bypass static bytecode substring matching via dynamic attribute resolution or opcode obfuscation.
   - **Architectural Conformance**: Architecture Table K.4 specifically defines a *layered defense*:
     1. Pre-validation of file structure against opcodes (implemented in Phase 2).
     2. `weights_only=True` loading (scheduled for Phase 3 PyTorch adapter).
     3. Disposable subprocess isolation with memory/time sandboxing (scheduled for Phase 3/5 model execution engine).
   - The Phase 2 scanner fulfills the foundation preflight mandate, but must NOT be represented to operators as a standalone security guarantee against arbitrary code execution.

---

## H. Adapter Contracts

Inspection of adapter interfaces:

1. **`ModelAdapter` (`src/cvif/model/adapter.py`)**:
   - Concrete base properties: `task: ModelTask`, `access_level: ModelAccessLevel`, `class_names: List[str]`, `input_shape: Tuple[int, ...]`.
   - Abstract method: `predict(image_data: Any) -> PredictionResult`.
   - White-box protection: `get_weights()`, `get_layer_activations()`, and `get_gradients()` explicitly check `access_level == ModelAccessLevel.WHITE_BOX` and raise `AccessDeniedError` if invoked on `BLACK_BOX` or `GREY_BOX` models.
   - Downstream analysers can safely rely on this interface contract.

2. **`DatasetAdapter` (`src/cvif/ingestion/adapters/base.py`)**:
   - Contract exposes: `format_name`, `sample_count`, `class_names`, `validate() -> ValidationResult`, `get_sample(index) -> Dict[str, Any]`, and `iter_samples()`.
   - Clean, iterable contract ready for COCO and YOLO adapters in Phase 3.

3. **`FeatureExtractor` (`src/cvif/features/base.py`)**:
   - Contract exposes: `name`, `embedding_dim`, `device`, `extract(image) -> List[float]`, `extract_batch(images) -> List[List[float]]`.
   - Downstream data-integrity and distribution-shift checks can depend directly on this contract.

---

## I. Feature Extractor Audit

Inspection of `src/cvif/features/statistical.py`:

1. **Implementation Analysis**:
   - Pure Python standard library implementation (`math`, `pathlib`, `typing`).
   - Computes:
     - 64-bin normalized byte histogram across the input stream.
     - 4 distribution moments: mean, standard deviation, skewness, kurtosis.
     - 2 gradient deltas: mean delta, max delta.
   - Outputs a fixed 128-dimensional vector, normalized to unit length ($L_2$ norm = 1.0).
   - Determinism verified in `test_adapters.py::test_statistical_feature_extractor_offline`.

2. **Role & Limitations**:
   - Designed strictly as the air-gapped bootstrapping fallback (AD-06) for testing and low-resource operations when deep neural backbones (`resnet18_features.pt`) are unverified or absent.
   - **Does NOT provide semantic representation equivalence to deep neural networks.** The foundation documentation accurately presents it as an engineering fallback, not a replacement for deep representations.

---

## J. Configuration and Logging Audit

Inspection of `src/cvif/core/config.py` and `src/cvif/utils/logging.py`:

1. **Configuration**:
   - Default configuration sets `system.offline_mode = True` and `system.air_gapped = True`.
   - Relative paths are cleanly resolved against a designated base directory via `AppConfig.resolve_paths()`.
   - No hardcoded machine-specific absolute paths.
   - Correctly distinguishes path fields (`_path`, `_dir`, `_file`) from string configuration values (`primary_backbone`, `log_level`).

2. **Logging**:
   - Standardized UTC timestamps: `%(asctime)s [%(levelname)s] [%(name)s] %(message)s`.
   - `SecurityRedactionFilter` regex masks strings matching cryptographic keys, HMAC secrets, tokens, or hex strings $\ge 16$ chars.
   - Logs to stdout by default, with optional file output.

---

## K. Test Quality Audit

The test suite consists of 38 unit tests across 8 modules:

### 1. Strong Tests (High Confidence)
- `test_filestore_path_traversal_protection`: Actively attempts traversal outside root (`../`, `../../etc/passwd`) and proves `PathTraversalError` is raised.
- `test_modifying_event_breaks_verification`: Writes valid audit events to disk, modifies a string inside the file directly, and verifies chain verification detects corruption at the exact index.
- `test_reordering_events_detected` & `test_deleting_event_detected`: Proves hash chain detects sequence alterations.
- `test_evidence_store_write_once_immutability`: Proves second write of same `evidence_id` raises `EvidenceImmutableError`.
- `test_model_file_safety`: Tests malicious pickle opcode detection (`cos\nsystem`) and invalid format rejection.
- `test_model_adapter_black_box_restrictions`: Proves black-box models raise `AccessDeniedError` when white-box inspection is requested.
- `test_core_foundation_strictly_offline`: Replaces `socket.socket` with an exception raiser and proves all foundation operations complete without network activity.

### 2. Tests with Room for Improvement (Non-Blocking)
- `test_evidence_record_valid`: Does not test the failure case where all 4 content fields are `None`, because the schema validator currently allows it.
- `test_database_manager_session_findings_verdict`: Tests single-threaded SQLite operations; does not test concurrent multi-threaded writes under WAL mode.
- `test_audit_event_hash_calculation`: Tests hash computation, but does not verify Ed25519 digital signature against `KeyStore` during chain verification.

---

## L. Offline / Air-Gap Verification

1. **Socket Inspection**:
   - Search across all `src/cvif/` source files confirms zero imports of `urllib`, `requests`, `httpx`, `aiohttp`, `boto3`, or `socket`.
2. **Runtime Verification**:
   - `tests/unit/test_offline.py` actively patches `socket.socket` to raise `RuntimeError("AIR_GAP_VIOLATION")` and executes:
     - Package import and configuration loading
     - Key generation and KeyStore persistence
     - Database asset cataloging and transaction commit
     - Content-addressed file storage
     - Audit logging and hash-chain verification
     - Evidence record saving and retrieval
     - Statistical feature extraction
     - Mock model inference
     - Mock dataset iteration
   - **All operations succeed with zero socket attempts.**

---

## M. Windows Compatibility Audit

The development and deployment environment is Windows:
1. **Path Handling**: `pathlib.Path` is used throughout. `safe_resolve_path` explicitly strips both forward slashes and backslashes (`.lstrip("/\\")`) before joining, avoiding absolute path overrides.
2. **Drive Boundaries**: Handles Windows cross-drive access attempts (`C:` to `D:`), catching `ValueError` from `os.path.commonpath` and converting to `PathTraversalError`.
3. **Atomic Writes**: `tempfile.mkstemp` is placed in `target.parent` (same filesystem/drive), ensuring `os.replace` succeeds atomically on Windows NTFS without cross-volume errors.
4. **File Locking**: Database transactions close properly. WAL mode on SQLite functions correctly on Windows.
5. **Character Encoding**: All text I/O explicitly specifies `encoding="utf-8"`.

---

## N. Phase Boundary Verification

A rigorous code search confirms that **no Phase 3–8 analysis logic was prematurely implemented**:
- No trigger injection detection algorithms (Phase 4).
- No label flipping / mislabelling algorithms (Phase 4).
- No near-duplicate clustering algorithms (Phase 4).
- No OOD detection algorithms (Phase 4).
- No model parameter distribution analysis or activation clustering (Phase 5).
- No trigger search / neural cleanse algorithms (Phase 5).
- No distribution shift MMD / Wasserstein distance algorithms (Phase 7).
- No composite risk aggregation / thresholding engine (Phase 8).
- No CLI or web dashboard code (Phase 9+).

All future component requirements are represented solely as clean abstract contracts (`ModelAdapter`, `DatasetAdapter`, `FeatureExtractor`) or clearly demarcated testing stubs (`MockModelAdapter`, `MockDatasetAdapter`, `MockFeatureExtractor`).

---

## O. Dependency Audit

Dependencies declared in `pyproject.toml` and locked in `requirements.lock`:

| Package | Version | Justification | Air-Gap Safe? |
|:---|:---|:---|:---|
| `pydantic` | `2.13.5` | Core data validation and schema serialization | Yes (Pure Python + C extension) |
| `pydantic-core` | `2.41.5` | High-performance Pydantic core engine | Yes |
| `cryptography` | `50.0.1` | Native Ed25519 asymmetric signatures and primitives | Yes |
| `cffi` | `2.0.0` | C foreign function interface for cryptography | Yes |
| `pyyaml` | `6.0.3` | YAML configuration loading | Yes |
| `pytest` | `9.1.1` | Unit test execution | Yes |
| `annotated-types` | `0.7.0` | Pydantic dependency | Yes |
| `typing_extensions`| `4.15.0` | Typing support for Python 3.10 | Yes |

No unnecessary, heavy, or cloud-dependent packages are present.

---

## P. Reproducibility

A clean setup was verified:
1. Python 3.10 virtual environment creation.
2. Direct installation from `requirements.lock` via `pip`.
3. Editable installation of `cvif` via `pip install -e . --no-deps`.
4. Pytest execution of 38 tests passing deterministically in 0.40s.
5. Setup instructions documented clearly in `README.md`.

---

## Q. Security Overclaims Audit

The codebase was reviewed for overstated security claims:
1. **"Tamper-Evident" vs "Tamper-Proof"**:
   - The documentation and code correctly use "tamper-evident" for the audit log. The hash chain makes unauthorized tampering *evident* upon verification; it does not physically prevent a disk write from occurring.
2. **"Immutable" Evidence Store**:
   - Immutability is enforced at the application layer (`EvidenceImmutableError`). It does not represent hardware-level WORM (Write Once Read Many) storage. Documentation should clarify this boundary.
3. **Model Safety Scanner**:
   - `validate_model_file_safety` is a preflight heuristic scanner, not a secure runtime sandbox. This distinction has been explicitly stated in Section G.

---

## R. Required Fixes (Prior to Phase 3)

None of the identified items represent blocking architecture flaws that prevent Phase 3 ingestion adapters from being developed. However, the following two minor schema fixes should be incorporated at the start of Phase 3:
1. **Add `sequence_number: int` to `AuditEvent`**:
   Ensure `AuditEvent` matches Section I.6 of `implementation_plan.md` by tracking an explicit monotonic integer sequence number alongside the hash chain.
2. **Enforce At Least One Content Field in `EvidenceRecord`**:
   Add a `@model_validator(mode="after")` to `EvidenceRecord` confirming that at least one of `metrics`, `artifacts`, `baseline_comparison`, or `raw_data_ref` is populated.

---

## S. Recommended Improvements (For Downstream Phases)

1. **HMAC Binding of Inference Record Transport Metadata**:
   In Phase 6 (Inference Provenance), consider including `sequence_number` and `nonce` directly within `InferenceRecord.compute_canonical_payload()` so the HMAC cryptographically binds transport replay tokens to the inference payload.
2. **KeyStore OS Permission Hardening**:
   In Phase 6, ensure that file permissions on `data/keys/truststore.json` are restricted at the OS level (Windows ACLs / Linux 0600) to protect plaintext HMAC secrets.
3. **Layered Model Loading Sandboxing**:
   In Phase 3/5, implement the subprocess worker model specified in Architecture Table K.4 so untrusted PyTorch models are loaded in an isolated process with memory and time caps, rather than relying solely on the Phase 2 preflight opcode scanner.
4. **Audit Chain Signature Verification**:
   In Phase 9 (Governance/Audit), enhance `verify_audit_chain()` to accept an optional `KeyStore` parameter and verify Ed25519 signatures on audit events where present.

---

## T. Final Status

**FOUNDATION VERIFIED WITH NON-BLOCKING IMPROVEMENTS**

The Phase 2 Foundation is technically sound, clean, thoroughly tested, strictly air-gapped, and faithful to architecture v0.2-REVISED. It is safe to proceed to Phase 3 (Ingestion Adapters) once authorized.
