# Phase 2/12 — Foundation Report

**Project**: Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines  
**Stakeholder**: Ministry of Defence (MoD) / Indian Army (DGIS)  
**Theme**: Blockchain & Cybersecurity  
**Architecture Specification**: Version 0.2-REVISED  
**Date**: September 18, 2026  

---

## A. What Was Implemented

Phase 2 established the complete, reproducible, and air-gapped technical foundation required by the CVIF architecture without implementing any later-phase detection algorithms:

1. **Python Environment & Packaging**: Established Python 3.10 virtual environment with pinned dependencies (`requirements.lock`) and editable package configuration (`pyproject.toml`).
2. **Core Domain & Schemas**: Implemented all canonical Pydantic v2 data contracts with strict schema versioning (`1.0`), canonical deterministic JSON/byte serialization (`to_canonical_json`, `to_canonical_bytes`), and domain enumerations.
3. **Cryptographic Foundation**: Built SHA-256 primitives (streaming file hashing, canonical dict hashing), HMAC-SHA256 generation with constant-time verification, Ed25519 asymmetric signing and key verification, monotonic hash-chain logic, and the local air-gapped Trust Store (`KeyStore`).
4. **Storage Foundation**: Built SQLite persistence manager (`DatabaseManager`) with WAL mode, foreign key enforcement, and atomic transactions. Built filesystem storage (`SafeFileStore`) featuring strict path traversal defenses (`os.path.commonpath`) and atomic file replacement (`os.replace`).
5. **Tamper-Evident Audit Logging**: Implemented `AuditLogger` writing monotonic, hash-chained JSONL logs ($H_n = \text{SHA-256}(E_n \parallel H_{n-1})$) with automated chain verification, recovery, and corruption detection.
6. **Evidence Store Foundation**: Implemented `EvidenceStore` with write-once immutability enforcement (`EvidenceImmutableError`), session-scoped directory partitioning, and binary artifact management.
7. **Model, Data & Feature Adapter Contracts**: Established abstract contracts for `ModelAdapter` (with `ModelTask` and `ModelAccessLevel` checks), `DatasetAdapter` (sample iteration and validation), and `FeatureExtractor` (with an offline `StatisticalFeatureExtractor` fallback). Built `validate_model_file_safety` to inspect model weight headers and guard against dangerous unpickling opcodes.
8. **Structured Logging & Error Handling**: Configured sanitized logging (`setup_logger` with `SecurityRedactionFilter` to prevent secrets leakage) and a unified exception hierarchy (`CVIFError` and specialized subclasses).
9. **Configuration System**: Created `AppConfig` / `CVIFConfig` supporting YAML loading, environment overrides, and path resolution.
10. **Testing Infrastructure**: Built 38 comprehensive unit tests verifying schemas, crypto, audit chain integrity, storage, evidence, adapters, configuration, and strict air-gap compliance.

---

## B. Files / Directories Created or Modified

### Workspace Configuration & Metadata
- `pyproject.toml`: Package build specification and pytest configuration.
- `requirements.lock`: Exact pinned dependency lockfile.
- `.gitignore`: Ignore rules for `.venv`, cache, data, keys, logs, and database files.
- `README.md`: Project overview, foundation scope, and developer instructions.
- `config/default_config.yaml`: Default system and component configuration.
- `phase_2_foundation_report.md`: This comprehensive foundation report.

### Source Code (`src/cvif/`)
- `src/cvif/__init__.py`: Package export file for core symbols and version metadata.
- `src/cvif/version.py`: Version declarations (`__version__ = "0.1.0"`, `__schema_version__ = "1.0"`).
- `src/cvif/core/`:
  - `enums.py`: Domain enums (`AssetType`, `AssetStatus`, `SeverityLevel`, `Disposition`, `EvidenceType`, `ModelAccessLevel`, `ModelTask`, `RecordOrigin`, `KeyType`, `KeyStatus`, `AuditEventType`, `SessionStatus`, `ProvenanceOutcome`).
  - `exceptions.py`: CVIF exception hierarchy (`CVIFError`, `SchemaValidationError`, `CryptographicError`, `StorageError`, `PathTraversalError`, `TamperDetectedError`, `EvidenceImmutableError`, `InvalidModelError`, `AccessDeniedError`, etc.).
  - `schemas.py`: Canonical Pydantic schemas (`EvidenceRecord`, `Finding`, `AssetRegistration`, `AssuranceVerdict`, `InferenceRecord`, `AuditEvent`, `ShiftReport`, `PredictionResult`, `ClassificationOutput`, `DetectionOutput`, `SegmentationOutput`, `AnalysisSession`, `ValidationResult`, `KeyRecord`).
  - `config.py`: Pydantic-based configuration management (`AppConfig`, `StorageConfig`, `AuditConfig`, `KeyStoreConfig`, `EvidenceConfig`, `LoggingConfig`, `SecurityConfig`, `load_config`).
  - `__init__.py`: Core package initialization and re-exports.
- `src/cvif/crypto/`:
  - `hashing.py`: SHA-256 byte, string, streaming file, and canonical JSON hashing.
  - `hmac.py`: HMAC-SHA256 generation and constant-time verification.
  - `signing.py`: Ed25519 key generation, sign, verify, and hex serialization.
  - `chain.py`: Cryptographic hash chain verification and event link validation.
  - `keystore.py`: Local Trust Store for Ed25519 public keys and HMAC secrets with lifecycle management.
  - `__init__.py`: Crypto package export.
- `src/cvif/storage/`:
  - `filestore.py`: `SafeFileStore` and `safe_resolve_path` with path traversal defense and atomic writes.
  - `database.py`: `DatabaseManager` with SQLite connection pooling, WAL mode, foreign keys, and asset/session/finding/verdict/nonce tables.
  - `__init__.py`: Storage package export.
- `src/cvif/audit/`:
  - `logger.py`: `AuditLogger` with append-only JSONL writing, hash linkage, and chain recovery.
  - `__init__.py`: Audit package export.
- `src/cvif/evidence/`:
  - `store.py`: `EvidenceStore` enforcing write-once immutability and session artifact storage.
  - `__init__.py`: Evidence package export.
- `src/cvif/model/`:
  - `adapter.py`: `ModelAdapter` abstract base class and `MockModelAdapter`.
  - `safety.py`: `validate_model_file_safety` format inspector and malicious opcode scanner.
  - `__init__.py`: Model package export.
- `src/cvif/ingestion/`:
  - `adapters/base.py`: `DatasetAdapter` abstract base class and `MockDatasetAdapter`.
  - `adapters/__init__.py`: Adapters export.
  - `__init__.py`: Ingestion package export.
- `src/cvif/features/`:
  - `base.py`: `FeatureExtractor` abstract base class and `MockFeatureExtractor`.
  - `statistical.py`: `StatisticalFeatureExtractor` deterministic air-gapped statistical fallback.
  - `__init__.py`: Features package export.
- `src/cvif/utils/`:
  - `logging.py`: Structured logger setup with `SecurityRedactionFilter`.
  - `__init__.py`: Utilities export.

### Tests (`tests/`)
- `tests/conftest.py`: Fixtures for isolated temp directories, database managers, file stores, keystores, and socket guards.
- `tests/unit/test_schemas.py`: Validation, serialization, bounds checking, and canonical byte determinism.
- `tests/unit/test_crypto.py`: SHA-256, HMAC, Ed25519, and KeyStore lifecycle.
- `tests/unit/test_audit.py`: Valid chain verification, payload modification detection, reorder detection, deletion detection, and unauthorized append detection.
- `tests/unit/test_storage.py`: SafeFileStore path traversal rejection, atomic writes, content-addressed storage, DatabaseManager CRUD, and nonce replay defense.
- `tests/unit/test_evidence.py`: Write-once immutability enforcement, artifact storage, and session listing.
- `tests/unit/test_adapters.py`: Access level enforcement (white-box vs black-box), mock predictions, dataset iteration, statistical feature extraction, and model safety verification.
- `tests/unit/test_config.py`: Default loading, path resolution, and YAML parsing.
- `tests/unit/test_offline.py`: Socket-level air-gap isolation test.

---

## C. Dependencies Added

The following packages are installed and pinned in `requirements.lock`:
- `pydantic==2.13.5`: High-performance data validation and contract enforcement.
- `pydantic-core==2.41.5`: Core parsing engine.
- `cryptography==50.0.1`: Asymmetric Ed25519 signatures and low-level cryptographic primitives.
- `pyyaml==6.0.3`: YAML configuration parser.
- `pytest==9.1.1`: Test framework.

---

## D. Core Interfaces Established

1. **`ModelAdapter` (`src/cvif/model/adapter.py`)**:
   - Contract for all computer vision models (ONNX, PyTorch, YOLO).
   - Enforces `ModelAccessLevel` boundaries: calling `get_weights()`, `get_layer_activations()`, or `get_gradients()` on a `BLACK_BOX` or `GREY_BOX` model raises `AccessDeniedError`.
   - Returns normalized `PredictionResult` polymorphic across `ClassificationOutput`, `DetectionOutput` (with normalized bounding boxes), and `SegmentationOutput`.
2. **`DatasetAdapter` (`src/cvif/ingestion/adapters/base.py`)**:
   - Contract for dataset ingestion formats (COCO, YOLO).
   - Exposes `validate() -> ValidationResult`, `sample_count`, `class_names`, and `get_sample(index)`.
3. **`FeatureExtractor` (`src/cvif/features/base.py`)**:
   - Contract for producing fixed-dimension normalized feature embeddings.
   - Includes `StatisticalFeatureExtractor` fallback operating completely without external deep learning model files.
4. **`KeyStore` (`src/cvif/crypto/keystore.py`)**:
   - Air-gapped local trust store managing public keys and HMAC secrets with lifecycle states (`ACTIVE`, `SUSPENDED`, `REVOKED`, `EXPIRED`).
5. **`AuditLogger` (`src/cvif/audit/logger.py`)**:
   - Hash-chained monotonic event logger with `log_event()` and `verify_chain()`.
6. **`EvidenceStore` (`src/cvif/evidence/store.py`)**:
   - Immutable write-once persistence for canonical `EvidenceRecord` objects and visual/data artifacts.

---

## E. Tests Created

A total of 8 test modules containing 38 test functions were implemented:
1. `test_schemas.py`: 7 tests covering `EvidenceRecord`, `Finding`, `AssetRegistration`, `AssuranceVerdict`, `InferenceRecord`, `AuditEvent`, `PredictionResult`, `DetectionOutput`, and `ShiftReport`.
2. `test_crypto.py`: 5 tests covering SHA-256 (byte, string, streaming, JSON), HMAC-SHA256, Ed25519 key management and signatures, and KeyStore lifecycle.
3. `test_audit.py`: 5 tests proving valid chain verification, modified event detection, reordered event detection, deleted event detection, and unauthorized append detection.
4. `test_storage.py`: 5 tests covering path traversal defense, content-addressed storage, asset CRUD, session/finding/verdict relations, and nonce replay defense.
5. `test_evidence.py`: 2 tests covering write-once immutability enforcement (`EvidenceImmutableError`) and session artifact storage.
6. `test_adapters.py`: 6 tests covering model access level enforcement, detection bounding box outputs, dataset iteration, feature extractor contracts, statistical fallback, and model file safety checks.
7. `test_config.py`: 4 tests covering default loading, path resolution, custom YAML, and malformed YAML handling.
8. `test_offline.py`: Complete air-gap isolation test with active network socket blocking.

---

## F. Test Results

The test suite was executed via `pytest`:

```
============================= test session starts =============================
platform win32 -- Python 3.10.11, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Namith Singh\OneDrive\Documents\SIH 2ND ATTEMPT
configfile: pyproject.toml
testpaths: tests
collected 38 items

tests\unit\test_adapters.py ......                                       [ 15%]
tests\unit\test_audit.py .....                                           [ 28%]
tests\unit\test_config.py ....                                           [ 39%]
tests\unit\test_crypto.py .....                                          [ 52%]
tests\unit\test_evidence.py ..                                           [ 57%]
tests\unit\test_offline.py .                                             [ 60%]
tests\unit\test_schemas.py ..........                                    [ 86%]
tests\unit\test_storage.py .....                                         [100%]

============================= 38 passed in 0.43s ==============================
```

**Result**: 38 passed, 0 failed, 0 skipped. Execution duration: 0.43 seconds.

---

## G. Offline Verification

Offline independence was verified through `tests/unit/test_offline.py`:
- `socket.socket` was intercepted and patched to raise an explicit `RuntimeError("AIR_GAP_VIOLATION: Attempted socket connection!")`.
- The complete foundational workflow (importing, configuration loading, key registration, asset cataloging, content-addressed storage, audit event chaining, evidence saving, statistical feature extraction, mock model inference, and dataset validation) executed successfully with zero socket calls.
- No network requests, remote telemetry, cloud APIs, or background asset downloads exist in the foundation.

---

## H. Security Checks Performed

1. **Path Traversal Defense**:
   - Verified that attempts to write or resolve paths containing `../`, `..\\`, absolute paths, or cross-drive references outside `base_dir` immediately raise `PathTraversalError`.
2. **Model File Safety**:
   - Verified that `validate_model_file_safety` blocks disallowed file types, zero-byte files, and scans headers for dangerous pickle opcodes (`cos\nsystem`, `cbuiltins\neval`, etc.) before loading.
3. **Audit Chain Tamper Detection**:
   - Verified that changing a single character in an audit event payload causes chain verification to fail with `Corrupted event content`.
   - Verified that deleting or swapping events causes verification to fail with `Broken chain link`.
4. **Evidence Immutability**:
   - Verified that attempting to write an `EvidenceRecord` with an existing `evidence_id` raises `EvidenceImmutableError`.
5. **Nonce Replay Protection**:
   - Verified that `record_nonce_if_new` records new nonces and rejects repeated nonces to prevent replay attacks.
6. **Log Redaction**:
   - Verified that `SecurityRedactionFilter` redacts keys, tokens, and secrets from application logs.

---

## I. Intentionally Left Unimplemented (Belonging to Later Phases)

In strict accordance with the Phase 2 Foundation mandate, the following components were intentionally NOT implemented:
- **Phase 3**: Real format parsers for COCO annotations, YOLO label directories, ONNX graph loaders, and PyTorch model weight extractors.
- **Phase 4**: Training data integrity analysis algorithms (Trigger injection detection, label flipping detection, systematic mislabelling detection, near-duplicate flooding detection, OOD detection, contributor/source-level aggregation).
- **Phase 5**: Model integrity analysis algorithms (Model substitution verification, behavioral fingerprinting, trigger search/reconstruction, parameter distribution analysis, activation clustering).
- **Phase 6**: Inference record verification pipeline and full provenance analysis engine.
- **Phase 7**: Distribution shift analysis engines (MMD, KS, Wasserstein distances, drift vs. manipulation likelihood classifier).
- **Phase 8**: Composite risk scoring, decision thresholds, and automated verdict synthesis logic.
- **Phase 9+**: CLI commands, dashboard UI, and operational workflows.

Where later components needed an interface, only minimal safe abstract contracts and clearly demarcated mock stubs were created.

---

## J. Problems Encountered and How They Were Resolved

1. **Package Import in Isolated Environment**:
   - *Problem*: `import cvif` initially failed with `ModuleNotFoundError` because `src` was not installed in editable mode in the virtual environment.
   - *Solution*: Added minimal `README.md` and installed the package in editable mode using `pip install -e . --no-deps`.
2. **Path Resolution in Config**:
   - *Problem*: `AppConfig.resolve_paths()` converted all string attributes (including `primary_backbone="resnet18"` and `log_level="INFO"`) into `Path` objects, causing Pydantic type validation errors.
   - *Solution*: Refined `resolve_paths()` to selectively resolve only fields ending with `_path`, `_dir`, or `_file`.

---

## K. Architecture Contradictions Discovered

No architectural contradictions were discovered during Phase 2. The architecture v0.2-REVISED was found to be consistent, clear, and fully realizable.

---

## L. Phase 2 Completion Status

**FOUNDATION COMPLETE**
