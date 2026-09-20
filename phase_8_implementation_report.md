# Phase 8/12 — Evidence Store: Implementation Report

**Project**: Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines  
**Customer / Authority**: Ministry of Defence (MoD) / Indian Army (DGIS)  
**Theme**: Blockchain & Cybersecurity  
**Phase**: Phase 8/12 — Evidence Store  
**Stage**: Production Implementation & Test Verification  
**Date**: September 19, 2026  
**Status**: PHASE 8 IMPLEMENTATION COMPLETE — AWAITING INDEPENDENT VERIFICATION  

---

## 1. Scope

Phase 8 establishes the authoritative, tamper-evident repository for all security evidence generated across the CVIF operational lifecycle (Phases 3–7):
- **Lifecycle Engine**: Implemented `CREATE → VALIDATE → HASH → STORE → INDEX → RETRIEVE → VERIFY → CONSUME → AUDIT`.
- **Dual-Layer Architecture**: Transitioned the preliminary prototype to a production engine combining an indexed relational metadata layer (SQLite `metadata.db`) and an atomic, write-once filesystem content layer.
- **Cryptographic Binding**: Streaming SHA-256 digests bound to physical artifacts and canonical JSON records.
- **Strict Immutability**: Complete collision detection preventing overwrite or silent substitution of evidence records and artifacts.
- **Phase Boundary Confinement**: Confined strictly to Phase 8 internal storage mechanisms without implementing Phase 9 (CLI), Phase 10 (REST API), Phase 11 (UI Dashboard), or Phase 12 (Containerization).

---

## 2. Files Changed

| File Path | Action | Description |
|:---|:---|:---|
| [`src/cvif/core/enums.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/enums.py) | **MODIFY** | Added Phase 8 evidence lifecycle audit events (`EVIDENCE_STORED`, `ARTIFACT_STORED`, `EVIDENCE_VERIFIED`, `EVIDENCE_TAMPERED`). |
| [`src/cvif/storage/database.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/storage/database.py) | **MODIFY** | Added DDL and indexes for `evidence_records` and `evidence_artifacts` tables; added relational CRUD, verdict/threat lookups, and binding methods. |
| [`src/cvif/evidence/store.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/evidence/store.py) | **MODIFY** | Complete production dual-layer implementation: write-once immutability, streaming SHA-256 hashing, path traversal defenses, audit logging, and consistency audit. |
| [`tests/unit/test_evidence_store_v2.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/tests/unit/test_evidence_store_v2.py) | **NEW** | Comprehensive unit test suite covering Categories A through T, anti-stub sensitivity proofs, and 1,000-record scale benchmarks. |

---

## 3. Evidence Store Architecture Implemented

The production `EvidenceStore` operates as a **Dual-Layer Storage Engine**:

```
                              PHASE 8 DUAL-LAYER ENGINE
                              
   [ Client / Pipeline ]
             │
             ├── save_evidence(record) / save_artifact(session_id, path, data)
             ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                    EvidenceStore Engine                         │
   │  - Pre-persistence content validation (reject empty records)    │
   │  - Reentrant lock (threading.RLock) thread safety               │
   │  - Path traversal containment (_validate_safe_relative_path)    │
   │  - Canonical deterministic serialization (CVIFBaseModel)        │
   │  - Streaming SHA-256 digest computation (sha256_file)           │
   └────────────────┬───────────────────────────────┬────────────────┘
                    │                               │
       File-first   │                               │ Atomic index
       atomic write │                               │ commit
                    ▼                               ▼
   ┌─────────────────────────────────┐  ┌────────────────────────────┐
   │     Immutable Content Layer     │  │  Relational Metadata Layer │
   │       (Filesystem Store)        │  │     (SQLite metadata.db)   │
   │ - Session-confined directory    │  │ - evidence_records index   │
   │ - Canonical JSON records        │  │ - evidence_artifacts index │
   │ - Raw binary diagnostic files   │  │ - Content & artifact hashes│
   │ - Atomic os.replace semantics   │  │ - Foreign keys & multi-key │
   │ - Fail-safe rollback unlinking  │  │   relational lookups       │
   └─────────────────────────────────┘  └────────────────────────────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │ Audit event emission
                                    ▼
                        ┌───────────────────────┐
                        │      AuditLogger      │
                        │    (audit.jsonl)      │
                        │ Tamper-evident chain  │
                        └───────────────────────┘
```

---

## 4. Database Schema & Indexes

Implemented in `DatabaseManager._init_db()` ([`src/cvif/storage/database.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/storage/database.py)):

### 4.1 `evidence_records` Table
```sql
CREATE TABLE IF NOT EXISTS evidence_records (
    evidence_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    file_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence_records(session_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence_records(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence_records(content_hash);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence_records(evidence_type);
```

### 4.2 `evidence_artifacts` Table
```sql
CREATE TABLE IF NOT EXISTS evidence_artifacts (
    artifact_id TEXT PRIMARY KEY,
    evidence_id TEXT,
    session_id TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    media_type TEXT NOT NULL,
    description TEXT,
    artifact_digest TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence_records(evidence_id)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_session ON evidence_artifacts(session_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_evidence ON evidence_artifacts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_digest ON evidence_artifacts(artifact_digest);
CREATE UNIQUE INDEX IF NOT EXISTS idx_artifacts_session_relpath ON evidence_artifacts(session_id, rel_path);
```

---

## 5. Immutability Guarantees

1. **Write-Once Enforcement**:
   - `save_evidence()` checks both in-memory cache and SQLite `evidence_records` primary key. If `evidence_id` exists, raises `EvidenceImmutableError`.
   - Before filesystem write, verifies `target_file.exists()`. If exists, raises `EvidenceImmutableError`.
2. **Artifact Write-Once Protection**:
   - `save_artifact()` checks `target_path.exists()` and the SQLite `(session_id, rel_path)` unique index.
   - Any attempt to overwrite an existing artifact raises `EvidenceImmutableError`.
3. **Atomic Replacement Protection**:
   - Temporary file writes (`.tmp_...`) followed by `os.replace` ensure no partial or corrupt writes.
   - Immediate re-check prior to atomic replace prevents concurrent race-condition overwrite.

---

## 6. Artifact Integrity

1. **Streaming SHA-256**: Raw binary artifact data is hashed using `sha256_file(path, chunk_size=65536)` preventing high memory usage on large diagnostic dumps.
2. **Cryptographic Indexing**: The streaming digest is recorded in `evidence_artifacts.artifact_digest`.
3. **Fail-Closed Verification on Read**:
   - `read_artifact(..., verify_integrity=True)` recomputes `sha256_file(target_path)` and matches against registered `artifact_digest`.
   - If corrupted, truncated, or replaced: raises `TamperDetectedError` and emits `EVIDENCE_TAMPERED`.
   - Stored evidence records referencing artifacts also verify all referenced artifacts on `get_evidence(..., verify_integrity=True)`.

---

## 7. Content Hashing & Cryptographic Identity

1. **Deterministic Serialization**: `record.to_canonical_json()` serializes with sorted keys and tight separators (`','`, `':'`).
2. **Canonical Hash**: `content_hash = sha256_bytes(record.to_canonical_bytes())`.
3. **Tamper Detection**: On `get_evidence(..., verify_integrity=True)`, computed SHA-256 must match `db_row["content_hash"]`.
4. **Dual Validation**: Compares canonical model bytes and raw stored file bytes, supporting forward-compatible schema versioning without compromising tamper detection.

---

## 8. Provenance Model

Bidirectional forensic traceability across the full assurance graph:
- $\text{AssuranceVerdict} \xrightarrow{\text{contributing\_finding\_ids}} \text{Finding} \xrightarrow{\text{evidence\_ids}} \text{EvidenceRecord} \xrightarrow{\text{artifacts}} \text{Physical Artifact}$
- Implemented relational queries:
  - `store.get_evidence_by_finding(finding_id)`
  - `store.get_evidence_for_verdict(verdict_id)`
  - `store.get_evidence_by_threat_id(threat_id)`
  - `store.get_evidence_by_category(category)`

---

## 9. Retrieval Security

Implemented `_validate_safe_relative_path(path)` enforcing:
- **Null Byte Rejection**: Rejects `\x00` with `PathTraversalError`.
- **Absolute Path Rejection**: Rejects leading `/` or `\\` with `PathTraversalError`.
- **Windows Drive Letter Rejection**: Rejects `C:`, `D:` with `PathTraversalError`.
- **Parent Traversal Rejection**: Rejects `..` path segments with `PathTraversalError`.
- **Confinement**: Session directories and artifact subdirectories strictly confined under `base_dir / "sessions" / str(session_id)`.

---

## 10. Failure Semantics

All storage operations follow fail-closed behavior:
- `SchemaValidationError`: Empty evidence records with zero content payloads.
- `EvidenceImmutableError`: Duplicate record ID or artifact collision.
- `TamperDetectedError`: Hash mismatch on record JSON or physical artifact.
- `CorruptedArtifactError`: Missing file on disk or unparseable JSON.
- `PathTraversalError`: Path escaping session boundaries.
- `StorageError`: Transactional database failure with automatic file rollback unlink.

---

## 11. Concurrency

- **Thread Safety**: Protected by `threading.RLock()` across in-memory indexing, filesystem atomic writes, and database operations.
- **Process Safety**: SQLite WAL mode (`PRAGMA journal_mode = WAL;`) with 5000ms busy timeout.
- **Verified Under Load**: Multi-threaded stress test (`test_category_o_concurrent_thread_writes`) executed 8 concurrent worker threads without a single collision or dead-lock.

---

## 12. Audit Logging

Integrated with `AuditLogger`:
- `EVIDENCE_STORED`: Emitted with `evidence_id`, `finding_id`, `evidence_type`, `content_hash`, `file_path`.
- `ARTIFACT_STORED`: Emitted with `artifact_id`, `rel_path`, `media_type`, `artifact_digest`, `size_bytes`.
- `EVIDENCE_VERIFIED`: Emitted when evidence and artifacts pass cryptographic validation.
- `EVIDENCE_TAMPERED`: Emitted when content or artifact digest mismatch is detected.
- Verified monotonic hash chain from genesis to tip via `audit_logger.verify_chain().is_valid == True`.

---

## 13. Air-Gap Verification

- **Zero Socket Activity**: Verified under socket-blocking fixture (`test_category_q_air_gap_execution`) intercepting `socket.socket`.
- **Zero Cloud / External Calls**: Operates strictly on local filesystem and local SQLite database.

---

## 14. Performance Benchmarks

Measured and verified on Windows environment:

| Benchmark Scale | Save Time | Retrieval / Query Time | Architecture Target | Status |
|:---|:---|:---|:---|:---|
| **1 Record** | 7.98 ms | 16.70 ms (full integrity check) | Fast responsive | **PASSED** |
| **100 Records** | 763.22 ms | 0.81 ms (session indexed list) | < 50 ms | **PASSED** |
| **1,000 Records** | 8,176.77 ms | 6.90 ms (session indexed list) | < 50 ms | **PASSED** |
| **Single Indexed Get (at $N=1,000$)** | — | 16.07 ms (read + verify) | < 50 ms | **PASSED** |

---

## 15. Test Matrix Results

All 20 required audit test categories passed with 100% success rate in `tests/unit/test_evidence_store_v2.py`:

| Category | Test Name | Result |
|:---|:---|:---|
| **A. Create & Persist** | `test_category_a_create_and_persist` | **PASSED** |
| **B. Retrieve by ID** | `test_category_b_retrieve_by_id` | **PASSED** |
| **C. Content Hash Verification** | `test_category_c_content_hash_verification` | **PASSED** |
| **D. Metadata Tampering** | `test_category_d_metadata_tampering_detection` | **PASSED** |
| **E. Content Tampering** | `test_category_e_disk_content_tampering_detection` | **PASSED** |
| **F. Duplicate Insertion** | `test_category_f_duplicate_insertion_rejected` | **PASSED** |
| **G. Write-Once Immutability** | `test_category_g_write_once_enforcement` | **PASSED** |
| **H. Path Traversal** | `test_category_h_path_traversal_rejected` | **PASSED** |
| **I. Missing Artifact** | `test_category_i_missing_artifact_detection` | **PASSED** |
| **J. Orphan Artifact** | `test_category_j_orphan_and_consistency_detection` | **PASSED** |
| **K. Orphan DB Row** | `test_category_k_orphan_database_row` | **PASSED** |
| **L. Schema Mismatch** | `test_category_l_schema_mismatch_corrupted_json` | **PASSED** |
| **M. Forward Compatibility** | `test_category_m_forward_compatible_extra_fields` | **PASSED** |
| **N. Content Validation** | `test_category_n_content_validation_enforcement` | **PASSED** |
| **O. Concurrent Writes** | `test_category_o_concurrent_thread_writes` | **PASSED** |
| **P. Restart Persistence** | `test_category_p_restart_persistence` | **PASSED** |
| **Q. 100% Air-Gap** | `test_category_q_air_gap_execution` | **PASSED** |
| **R. Audit Hash Chain** | `test_category_r_audit_chain_linkage` | **PASSED** |
| **S. Provenance Linkage** | `test_category_s_provenance_linkage` | **PASSED** |
| **T. Canonical Serialization** | `test_category_t_deterministic_serialization` | **PASSED** |
| **Anti-Stub Proof** | `test_anti_stub_sensitivity_proof` | **PASSED** |
| **Scale Benchmarks** | `test_scale_performance_benchmarks` | **PASSED** |

---

## 16. Anti-Stub Verification

Production code in `src/cvif/evidence/store.py` and newly added methods in `src/cvif/storage/database.py` were audited for anti-stub violations:
- Scanned for banned patterns: `random`, `randint`, `mock`, `Mock`, `stub`, `placeholder`, `TODO`, `FIXME`.
- Result: **0 matches found**.
- Sensitivity tests proven: Altering metric float values or single artifact bytes demonstrably produces different SHA-256 digests and triggers integrity errors.

---

## 17. Full System Regression Results

Full pytest regression suite executed across all project phases:
- **Pre-Phase-8 Baseline**: 225 tests passing.
- **Phase 8 Implementation Suite**: +22 tests added in `tests/unit/test_evidence_store_v2.py`.
- **Post-Phase-8 Total**: **247 passed in 18.32s**.
- **Regressions**: **ZERO (0)**.
- **Existing Test Modification**: **ZERO (0) existing tests modified**.

---

## 18. Phase Boundary Verification

- **Phase 9 (CLI)**: Not implemented (strictly deferred).
- **Phase 10 (REST API)**: Not implemented (strictly deferred).
- **Phase 11 (UI Dashboard)**: Not implemented (strictly deferred).
- **Phase 12 (Containerization)**: Not implemented (strictly deferred).
- Only internal `EvidenceStore` APIs and database indexing methods were implemented.

---

## 19. Non-Blocking Improvements

### IMPLEMENTED
- **Backwards Compatibility**: Constructor `EvidenceStore(base_dir)` retained with optional `db_manager` and `audit_logger`. Safe default initializes internal `DatabaseManager(base_dir / "metadata.db")`.
- **Forensic Consistency Audit**: Implemented `verify_store_consistency(session_id=None)` utility detecting orphaned files, missing database rows, and modified content across the entire repository.

### DEFERRED NON-BLOCKING IMPROVEMENTS
- **Forensic Export Archive (`.cvif` zip packaging)**: Standalone packaging utility exporting session bundles with SHA-256 manifests for offline transit. Identified as non-blocking in Phase 8 architecture audit and deferred to Phase 9/10 integration.

---

## 20. Known Limitations

- Multi-process write concurrency relies on SQLite file locks; tactical deployments operating hundreds of concurrent worker processes should consider WAL tuning for extreme concurrent write bursts.
- Storage disk space monitoring is governed at the OS/filesystem level.

---

## 21. Final Status

PHASE 8 IMPLEMENTATION COMPLETE — AWAITING INDEPENDENT VERIFICATION
