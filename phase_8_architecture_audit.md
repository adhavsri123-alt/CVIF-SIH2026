# Phase 8/12 — Evidence Store: Architecture & Requirements Audit

**Project**: Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines  
**Customer / Authority**: Ministry of Defence (MoD) / Indian Army (DGIS)  
**Theme**: Blockchain & Cybersecurity  
**Phase**: Phase 8/12 — Evidence Store  
**Audit Type**: ARCHITECTURE & REQUIREMENTS AUDIT ONLY (Strict Read-Only)  
**Date**: September 19, 2026  
**Auditor**: Lead System Architect & Forensic Assurance Gate  

---

## 1. Executive Summary

This document establishes the authoritative architectural audit, security threat model, cryptographic identity rules, lifecycle specifications, and implementation requirements for **Phase 8: Evidence Store** of the Computer Vision Integrity Assurance Framework (CVIF).

### 1.1 Context & Operational Milestone
Phases 1 through 7 of the CVIF architecture have completed independent forensic verification:
- **Phase 2 (Foundation)**: Cryptographic primitives (SHA-256, HMAC-SHA256, Ed25519), SQLite storage engine, safe filesystem storage (`SafeFileStore`), append-only audit logger (`AuditLogger`), local trust store (`KeyStore`), and preliminary write-once evidence store.
- **Phase 3 (Data Integrity)**: `DT-1` through `DT-6` detection engines emitting `EvidenceRecord` items linked to data poisoning and dataset anomalies.
- **Phase 4 (Model Integrity)**: `MT-1` through `MT-4` detection engines emitting `EvidenceRecord` items containing layer weight digests, Neural Cleanse trigger patterns, and activation anomalies.
- **Phase 5 (Inference Provenance)**: `IT-1` through `IT-5` verifiers emitting `EvidenceRecord` items binding cryptographic signature verification and replay defense results.
- **Phase 6 (Distribution Shift)**: `DS-1` through `DS-4` detection engines emitting `EvidenceRecord` items and persisting comprehensive `shift_report.json` artifacts.
- **Phase 7 (Assurance Aggregation)**: Composite risk engine synthesizing multi-phase findings into authoritative [`AssuranceVerdict`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L176-L191) records with cryptographic audit chaining.

### 1.2 Audit Mandate & Findings
This audit was conducted under strict read-only rules:
- **Zero Production Code Modified**: No production files have been created or edited.
- **Zero Tests Modified**: The existing 225-test regression baseline is preserved.
- **Zero Schemas Modified**: Existing schemas in `schemas.py` remain frozen.
- **Zero Dependencies Installed**: The Python runtime remains strictly pinned to `requirements.lock`.
- **Zero Implementation of Phase 9+**: CLI, REST API, UI, and containerization remain strictly excluded.

**Key Architectural Findings**:
1. **Preliminary Implementation Limitations**: The existing [`src/cvif/evidence/store.py`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/evidence/store.py) implemented in Phase 2 provided a minimal write-once proof-of-concept. However, it lacks relational metadata indexing, content hashing, artifact immutability (calling `save_artifact` can silently overwrite existing files), and integrity verification on retrieval.
2. **Dual-Layer Architecture Mandate**: Phase 8 must transition the Evidence Store to a robust **Dual-Layer Storage Engine**:
   - *Relational Metadata Layer* (`metadata.db` SQLite): Indexed queryability by `evidence_id`, `finding_id`, `session_id`, `asset_id`, `threat_id`, and `evidence_type`.
   - *Immutable Content Layer* (Conconfined FileStore): Atomic, write-once storage of canonical `EvidenceRecord` JSON payloads and raw binary artifacts (heatmaps, tensors, JSON diagnostic dumps).
3. **Cryptographic Binding of Artifacts**: The preliminary [`ArtifactReference`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L56-L62) schema lacks a `digest` field. Phase 8 must ensure every physical artifact is indexed with its streaming SHA-256 digest, preventing silent artifact substitution attacks.
4. **Audit Readiness**: Phase 8 is **READY FOR IMPLEMENTATION** with zero blocking defects once the dual-layer model, write-once artifact guarantees, and integrity verification methods are formally codified.

---

## 2. Phase 8 Scope

Phase 8 establishes the authoritative, tamper-evident repository for all security evidence generated across the CVIF operational lifecycle.

```
                               PHASE 8 EVIDENCE STORE SCOPE
                               
   [ Upstream Generators ]
   ├── Phase 3: Data Integrity (DT-1..6)
   ├── Phase 4: Model Integrity (MT-1..4)
   ├── Phase 5: Inference Provenance (IT-1..5)
   ├── Phase 6: Distribution Shift (DS-1..4)
   └── Phase 7: Assurance Aggregation (Verdicts)
              │
              ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                 Phase 8: EVIDENCE STORE                     │
   ├──────────────────────────────┬──────────────────────────────┤
   │    Relational Metadata Layer │   Immutable Content Layer    │
   │    (SQLite metadata.db)      │   (Filesystem Store)         │
   │  - Evidence index & registry │ - Canonical JSON records     │
   │  - Artifact SHA-256 digests  │ - Binary artifacts (PNG/JSON)│
   │  - Provenance & session FKs  │ - Path traversal containment │
   │  - Fast multi-key lookups    │ - Atomic temp-file replace   │
   ├──────────────────────────────┴──────────────────────────────┤
   │              Integrity & Lifecycle Engine                   │
   │  - Write-once immutability enforcement                      │
   │  - Content-integrity verification on read                   │
   │  - Hash mismatch & tampering detection                      │
   │  - Tamper-evident audit logging (EVIDENCE_STORED/VERIFIED)  │
   │  - Forensic export bundle packaging (.cvif zip archive)     │
   └─────────────────────────────────────────────────────────────┘
              │
              ▼
   [ Downstream Consumers ]
   ├── Phase 9: CLI (evidence query, verify, export commands)
   ├── Phase 10: REST API (evidence inspection endpoints)
   └── Phase 11: UI Dashboard (heatmap & evidence viewer)
```

### Core Responsibilities
- **Constituency of `EvidenceRecord`**: Structured metadata linking an atomic finding to quantitative metrics, narrative methodology, reproducibility seeds, and physical artifact references.
- **Constituency of Evidence Artifact**: Binary or structured diagnostic files (Grad-CAM heatmaps, saliency maps, JSON diagnostic reports, layer weight snapshots).
- **Addressing & Indexing**: Dual addressing via UUIDv4 (`evidence_id`) and content hash (SHA-256 hex digest).
- **Integrity Verification**: Verifying that stored JSON payloads and binary artifacts have not been modified, truncated, or substituted post-insertion.
- **Audit Integration**: Emitting hash-chained audit events for evidence lifecycle milestones.

---

## 3. Existing Evidence Schema Analysis

### 3.1 Field-by-Field Audit of `EvidenceRecord`

From [`src/cvif/core/schemas.py:64-99`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/schemas.py#L64-L99):

| Field Name | Type | Required / Default | Validation & Security Significance | Mutability |
|:---|:---|:---|:---|:---|
| `evidence_id` | `UUID` | Default: `uuid4()` | Primary identifier. Uniquely addresses evidence in database and filesystem. | **IMMUTABLE** |
| `finding_id` | `UUID` | Required | Foreign key to parent `Finding`. Anchors evidence to threat detection. | **IMMUTABLE** |
| `session_id` | `UUID` | Required | Foreign key to `AnalysisSession`. Confines storage directory. | **IMMUTABLE** |
| `evidence_type` | `EvidenceType` | Required | Enum: `STATISTICAL`, `VISUAL`, `CRYPTOGRAPHIC`, `BEHAVIORAL`, `COMPARATIVE`. | **IMMUTABLE** |
| `metrics` | `Optional[Dict[str, float]]` | Default: `None` | Quantitative test metrics (anomaly scores, p-values, distance metrics). | **IMMUTABLE** |
| `artifacts` | `Optional[List[ArtifactReference]]` | Default: `None` | Pointers to stored visual/data files. | **IMMUTABLE** |
| `baseline_comparison` | `Optional[Dict[str, Any]]` | Default: `None` | Expected baseline vs observed actual values. | **IMMUTABLE** |
| `raw_data_ref` | `Optional[str]` | Default: `None` | Relative path to diagnostic dump. | **IMMUTABLE** |
| `narrative` | `str` | Required | Human-readable forensic explanation of what evidence indicates. | **IMMUTABLE** |
| `methodology` | `str` | Required | Formal algorithm or procedure used to produce evidence. | **IMMUTABLE** |
| `reproducibility_info` | `Dict[str, Any]` | Default: `{}` | Random seeds, parameters, and environment context. | **IMMUTABLE** |
| `timestamp` | `datetime` | Default: `utc_now()` | Timezone-aware UTC timestamp of evidence generation. | **IMMUTABLE** |
| `schema_version` | `str` | Default: `"1.0"` | Schema version for forward/backward compatibility. | **IMMUTABLE** |

### 3.2 Audit of Content Validation Defect (from Phase 2 Gate Review)
In `schemas.py:94-98`:
```python
@field_validator("metrics", "artifacts", "baseline_comparison", "raw_data_ref")
@classmethod
def check_at_least_one_content(cls, v: Any, info: Any) -> Any:
    # Content verification handled at full record level
    return v
```
- **Audit Finding**: In Phase 2, this validator was stubbed with a comment stating content verification would occur at the full record level. Because it returns `v` directly, an `EvidenceRecord` with `metrics=None, artifacts=None, baseline_comparison=None, raw_data_ref=None` is syntactically accepted.
- **Architectural Resolution for Phase 8**: While existing schemas must not be modified during audit, Phase 8's `EvidenceStore.save_evidence()` MUST enforce a strict pre-persistence check:
  ```python
  if not any([record.metrics, record.artifacts, record.baseline_comparison, record.raw_data_ref]):
      raise SchemaValidationError(f"EvidenceRecord {record.evidence_id} must contain at least one content payload.")
  ```
  This cleanly resolves the Phase 2 defect at the storage boundary without requiring a schema breaking change.

---

## 4. Immutability Model

### 4.1 Strict Write-Once Semantics
Once written, evidence is permanent and unchangeable. The immutability model distinguishes:
- **Content Immutability (Absolute)**: The bytes representing the `EvidenceRecord` JSON payload and the raw bytes of any referenced artifact file MUST NEVER be modified, updated, or truncated. Any attempt to write to an existing `evidence_id` or existing artifact path raises `EvidenceImmutableError`.
- **Metadata Mutability (Restricted)**: In Phase 8, external index records (e.g. verification status, verification timestamp, quarantine flag) may be updated in the relational SQLite layer. However, the original creation timestamp, content hash, and parent linkages remain strictly immutable.

### 4.2 Overwrite & Replacement Defense
1. **In-Memory & Database Collision Detection**: Before writing to disk, `save_evidence()` checks both the in-memory cache and the SQLite registry for `evidence_id`.
2. **Filesystem Collision Detection**: Even if the cache is bypassed, `target_file.exists()` is verified before file write.
3. **Atomic Replacement**: Temporary files are written to `.tmp_{evidence_id}.json` and renamed via `os.replace`.

---

## 5. Content Hashing & Cryptographic Identity

### 5.1 Evidence Record Hash
- **Algorithm**: Standard SHA-256 (`cvif.crypto.hashing.sha256_bytes`).
- **Target Payload**: Deterministic canonical UTF-8 byte stream produced by `record.to_canonical_bytes()`.
- **Canonicalization Rules**: `json.dumps(data, sort_keys=True, separators=(',', ':'))`. Sorted keys prevent false hash discrepancies due to dictionary insertion order.

### 5.2 Artifact Content Hashing
- **Algorithm**: Streaming SHA-256 (`cvif.crypto.hashing.sha256_file`).
- **Target Payload**: Raw binary bytes of the physical artifact file (e.g. PNG image, JSON report).
- **Storage**: Stored in the SQLite `evidence_artifacts` table under `artifact_digest TEXT NOT NULL`.

### 5.3 Adversarial Substitution & Tampering Tests
1. **Case 1: Attacker modifies metrics in `{evidence_id}.json` on disk.**
   - *Detection*: Upon retrieval with `verify_integrity=True`, the computed SHA-256 of the file differs from `content_hash` in the database registry. Result: `CorruptedArtifactError` / `TamperDetectedError`.
2. **Case 2: Attacker replaces `heatmaps/trigger.png` on disk with benign image.**
   - *Detection*: Computed SHA-256 of `trigger.png` differs from the indexed `artifact_digest`. Result: `TamperDetectedError`.
3. **Case 3: Attacker alters SQLite metadata row.**
   - *Detection*: When the session is verified against the hash-chained `AuditLogger` (`audit.jsonl`), the event hash mismatch exposes unauthorized database alteration.

---

## 6. Evidence Addressing & Filesystem Confinement

### 6.1 Authoritative Addressing
- **Primary Canonical Key**: `evidence_id: UUID` (RFC 4122 UUIDv4).
- **Secondary Content Address**: `content_hash: str` (64-character SHA-256 hex digest).
- **Artifact Address**: Composite `(session_id, rel_path)` relative to `data/evidence_store/sessions/{session_id}/artifacts/`.

### 6.2 Path Traversal Defenses
All file resolutions MUST pass through [`safe_resolve_path`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/storage/filestore.py#L12-L33):
- Rejects `../`, `..\\`, absolute paths, null bytes (`\x00`), and Windows drive letter hopping (`C:`, `D:`).
- Enforces `os.path.commonpath([base_dir, target_path]) == base_dir`.
- Prevents escaping the session boundary.

---

## 7. Evidence Lifecycle

The complete evidence lifecycle is defined across nine discrete stages:

```
                          EVIDENCE LIFECYCLE STAGES
                          
[ CREATE ]    Detector generates EvidenceRecord & binary artifacts
    │
    ▼
[ VALIDATE ]  Preflight verification: UUID, non-empty content, path bounds
    │
    ▼
[ HASH ]      Compute SHA-256 over canonical record and artifact bytes
    │
    ▼
[ STORE ]     Atomic write to session evidence directory (write-once)
    │
    ▼
[ INDEX ]     Commit metadata, hashes, and foreign keys to metadata.db
    │
    ▼
[ RETRIEVE ]  Fetch record and artifacts by evidence_id or session_id
    │
    ▼
[ VERIFY ]    Recompute digests on read; compare with indexed SHA-256
    │
    ▼
[ CONSUME ]   Ingested by Phase 7 AssuranceAggregator for risk scoring
    │
    ▼
[ AUDIT ]     Lifecycle events logged to tamper-evident audit trail
```

---

## 8. Write-Once & Immutability Guarantees

### 8.1 The Current `save_artifact` Defect
In [`src/cvif/evidence/store.py:103-129`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/evidence/store.py#L103-L129):
```python
def save_artifact(self, session_id, rel_path, data, media_type, description):
    sess_dir = self._get_session_dir(session_id)
    artifacts_dir = sess_dir / "artifacts"
    target_path = safe_resolve_path(artifacts_dir, rel_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        target_path.write_bytes(data)
```
- **Vulnerability**: `target_path.exists()` is NOT checked. Calling `save_artifact` with an existing `rel_path` silently overwrites the file.
- **Architectural Mandate for Phase 8**:
  ```python
  if target_path.exists():
      raise EvidenceImmutableError(f"Artifact at '{target_path}' already exists and is immutable.")
  ```
  Artifact writes must use temporary files (`.tmp_...`) followed by `os.replace` to ensure atomicity.

---

## 9. Database + FileStore Consistency Model

### 9.1 Potential Consistency Failures
| Failure Scenario | State | Risk | Required Phase 8 Resolution |
|:---|:---|:---|:---|
| **A. DB succeeds, file fails** | DB row exists; disk file missing | Dangling pointer; verification fails | **File-First Order**: Always write file to disk before committing DB row. |
| **B. File succeeds, DB fails** | File on disk; DB row missing | Orphan file on disk | **Rollback Unlink**: If DB transaction raises error, unlink created file. |
| **C. File replaced post-DB** | Content modified on disk | Undetected tampering | **Digest Recomputation**: Compare SHA-256 on retrieval; raise error. |
| **D. DB row altered post-file** | DB metadata manipulated | Tampered record | **Audit Linkage**: Audit hash chain exposes altered event records. |

---

## 10. Cryptographic Boundary

Phase 8 adheres strictly to the cryptographic boundaries established in Phase 2 and Phase 5:
1. **Hashing Only**: Local evidence records and artifacts are bound via **SHA-256** digests. No symmetric encryption or secret key is required for local storage at rest.
2. **Provenance Authentication**: If evidence was generated from an external contributor (Phase 5 Mode 2), the underlying `InferenceRecord` retains its **Ed25519 signature** or **HMAC-SHA256**. Phase 8 preserves these signatures without modification.
3. **Audit Chaining**: Every evidence ingestion milestone is chained into `audit.jsonl` using monotonic SHA-256 hash linkage.

---

## 11. Provenance Model

Phase 8 ensures complete forensic backward-traceability:
$$\text{AssuranceVerdict} \xrightarrow{\text{contributing\_finding\_ids}} \text{Finding} \xrightarrow{\text{evidence\_ids}} \text{EvidenceRecord} \xrightarrow{\text{artifacts}} \text{Physical Artifact}$$

Every `EvidenceRecord` retains:
- `session_id`: Unique execution run.
- `finding_id`: Specific threat finding.
- `methodology`: Exact algorithm and parameters.
- `reproducibility_info`: Seeds and environment details.

---

## 12. Evidence → Finding → Verdict Relationship Graph

```
                               RELATIONAL GRAPH
                               
                           AssetRegistration
                                  │ 1
                                  │
                                  ▼ N
                            AnalysisSession
                           ┌──────┴──────┐
                         N │             │ N
                           ▼             ▼
                        Finding     EvidenceRecord
                           │             │
                         N │             │ N (artifacts)
                           ▼             ▼
                    AssuranceVerdict  Physical Files (PNG, JSON)
```

- **Cardinality**: One `AnalysisSession` contains $N$ `EvidenceRecord` items and $M$ `Finding` items. A `Finding` references $1..K$ `EvidenceRecord` UUIDs.
- **Cascade Deletion Defense**: In the database, foreign key constraints MUST NOT allow cascade deletion of evidence records when a finding or session is deleted in production, preserving forensic audit trails.

---

## 13. Retrieval Security

When retrieving evidence via `get_evidence()` or `read_artifact()`:
1. **Boundary Containment**: Path string is cleaned and checked via `safe_resolve_path`.
2. **Integrity Pre-check**: If `verify_integrity=True`, the file digest is recomputed and compared to the database registry.
3. **Fail-Closed Retrieval**: If the artifact is corrupted, missing, or altered, the method raises `CorruptedArtifactError` rather than returning compromised bytes.

---

## 14. Corruption & Tampering Detection

Phase 8 codifies the following failure signals:
- **`CorruptedArtifactError`**: File exists on disk but is truncated, empty, or unparseable JSON.
- **`TamperDetectedError`**: File exists but computed SHA-256 differs from the registered digest.
- **`EvidenceImmutableError`**: An attempt is made to overwrite an existing evidence record or artifact path.
- **`PathTraversalError`**: An attempt is made to access files outside the session directory.

---

## 15. Schema Versioning

- All evidence schemas define `schema_version: str = Field(default="1.0")`.
- `CVIFBaseModel` uses `model_config = ConfigDict(extra="ignore")` ensuring forward compatibility if minor fields are added in future iterations.
- Historical evidence files remain immutable; schema upgrades do not rewrite historical JSON files on disk.

---

## 16. Retention & Deletion Policy

- **Operational Mandate**: In MoD / DGIS military intelligence pipelines, **security evidence is non-deletable in normal operation**.
- **No Silent Deletion**: The `EvidenceStore` MUST NOT provide a public `delete_evidence()` method.
- **Forensic Tombstoning (Future/Admin Only)**: If a statutory purge is legally mandated, it must be performed via an administrative utility that logs a `PURGE_EVENT` into the audit trail and writes an immutable tombstone record.

---

## 17. Concurrency Model

1. **Thread Safety**: `EvidenceStore` uses a reentrant lock (`threading.RLock`) protecting index lookups and filesystem writes.
2. **Process Safety**: SQLite WAL mode (`PRAGMA journal_mode = WAL;`) supports multiple concurrent readers and sequential atomic writes.
3. **Filesystem Safety**: Atomic file creation via unique temporary files (`mkstemp`) eliminates write collisions on disk.

---

## 18. Air-Gap Requirement

- **Zero Socket Access**: All storage and indexing operations are strictly local filesystem and SQLite.
- **Zero Cloud SDKs**: No S3, GCS, Azure Blob, or remote database drivers.
- **Verified via Test Fixture**: Verified under `test_offline.py` socket-blocking fixture.

---

## 19. Performance & Scalability

### 19.1 Workload Profile & Benchmarks
- **Volume**: Tactical deployments generate 10 to 500 evidence records and 5 to 50 binary artifacts per analysis session.
- **Scale Target**: Support up to **100,000 evidence records** without performance degradation.

### 19.2 Database Indexing Strategy
To eliminate the $O(N)$ filesystem glob on startup (`self.sessions_dir.glob("*/evidence/*.json")`), Phase 8 will introduce the relational table:
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
```
- **Lookup Complexity**: $O(1)$ indexed lookup by `evidence_id`, $O(\log N)$ by `session_id`.
- **Startup Time**: $O(1)$ database initialization (eliminates directory globbing).

---

## 20. Failure Semantics

All storage operations follow fail-closed behavior:
- If an evidence record fails Pydantic validation: raises `SchemaValidationError` (no disk/DB write).
- If an evidence ID already exists: raises `EvidenceImmutableError` (no overwrite).
- If an artifact path already exists: raises `EvidenceImmutableError` (no overwrite).
- If disk write fails: unlinks temp file and raises `StorageError`.
- If database insert fails: unlinks written file and raises `StorageError`.
- If retrieved file hash mismatches: raises `TamperDetectedError` (untrusted content never returned).

---

## 21. Audit Logging

Phase 8 introduces the following audit events into [`AuditEventType`](file:///c:/Users/Namith%20Singh/OneDrive/Documents/SIH%202ND%20ATTEMPT/src/cvif/core/enums.py#L78-L90):
- `EVIDENCE_STORED`: Emitted when an `EvidenceRecord` is committed to disk and database.
- `ARTIFACT_STORED`: Emitted when a physical artifact is persisted.
- `EVIDENCE_VERIFIED`: Emitted when evidence integrity is successfully validated.
- `EVIDENCE_TAMPERED`: Emitted when content hash verification fails.

---

## 22. Security Threat Model

| Threat ID | Threat Description | Attack Vector | Phase 8 Countermeasure & Defense |
|:---|:---|:---|:---|
| **ET-1** | Evidence Substitution | Attacker replaces evidence JSON on disk | Content hash verification on retrieval catches mismatch. |
| **ET-2** | Evidence Modification | Attacker modifies metrics in-place | Write-once file permissions + canonical SHA-256 check. |
| **ET-3** | Evidence Deletion | Attacker deletes file to hide failure | Database registry flags missing artifact on check. |
| **ET-4** | Evidence Replay | Attacker copies evidence from older run | `session_id` and `finding_id` foreign keys bind context. |
| **ET-5** | Metadata Tampering | Attacker edits SQLite row | Audit log hash chain detects altered records. |
| **ET-6** | Path Traversal | Malicious `rel_path` (`../../etc/passwd`) | `safe_resolve_path` strictly confines to session dir. |
| **ET-7** | DB/Disk Desync | Crash between disk write and DB write | File-first atomic rename + DB failure rollback unlink. |
| **ET-8** | Duplicate ID Collision | Attacker generates colliding UUID | Primary key collision in DB and index raises `EvidenceImmutableError`. |
| **ET-9** | Schema Downgrade | Attacker writes malformed schema | Pydantic validation enforces schema version "1.0". |
| **ET-10**| Concurrent Write Race | Two threads write same artifact name | Reentrant lock (`RLock`) + atomic `mkstemp` replace. |
| **ET-11**| Truncated / Corrupt Write | Sudden power cut during write | Atomic temporary file rename (`os.replace`) prevents partial files. |
| **ET-12**| Unauthorized Retrieval | Path escape during read | `safe_resolve_path` prevents reading out-of-boundary files. |

---

## 23. Required Test Architecture

The Phase 8 test suite (`tests/unit/test_evidence_store_v2.py`) will implement 20 test categories:

```
TEST CATEGORIES (PHASE 8)
├── A. Create & Persist EvidenceRecord (Normal write, file exists, DB row exists)
├── B. Retrieve EvidenceRecord by ID (Exact content match)
├── C. List Evidence by Session ID (All session records returned)
├── D. Query Evidence by Finding ID (Relational lookup)
├── E. Content Hash Calculation & Verification (Matches canonical SHA-256)
├── F. Metadata Tampering Detection (Altered DB row detected)
├── G. Disk Content Tampering Detection (Altered JSON file raises TamperDetectedError)
├── H. Write-Once Immutability (Second save of same evidence_id raises EvidenceImmutableError)
├── I. Artifact Write-Once Immutability (Second save of same rel_path raises EvidenceImmutableError)
├── J. Artifact Path Traversal Rejection (../../ rejected with PathTraversalError)
├── K. Atomic Write Resilience (Interrupted temp writes cleaned up)
├── L. Missing File on Retrieval (Raises StorageError / CorruptedArtifactError)
├── M. Orphan File Detection (File on disk without DB row flagged)
├── N. Content Validation Enforcement (Record with zero content payloads rejected)
├── O. Concurrent Thread Writes (Zero race conditions or corrupted indexes)
├── P. 100% Air-Gap Execution (Verified under socket blocker)
├── Q. Audit Event Emission (EVIDENCE_STORED, ARTIFACT_STORED in audit chain)
├── R. Audit Chain Verification (Valid hash linkage maintained)
├── S. Performance at Scale (1,000 records indexed in < 50ms)
└── T. Full System Regression (All 225 existing tests pass)
```

---

## 24. Phase Boundary

```
PHASE BOUNDARY DEFINITION
├── PHASE 8 SCOPE (TO BE IMPLEMENTED)
│   ├── Dual-layer EvidenceStore (SQLite metadata.db + FileStore)
│   ├── Write-once artifact immutability enforcement
│   ├── SHA-256 content hashing & integrity verification
│   ├── Relational query methods (by finding_id, session_id, threat_id)
│   ├── Audit logging integration (EVIDENCE_STORED, ARTIFACT_STORED)
│   └── Offline test suite (tests/unit/test_evidence_store_v2.py)
└── STRICTLY EXCLUDED (BELONGS TO PHASE 9+)
    ├── Phase 9: CLI commands (cvif evidence list, cvif evidence export)
    ├── Phase 10: REST API routes (/api/v1/evidence/{id})
    ├── Phase 11: UI visualizer / dashboard heatmaps
    └── Phase 12: Production containerization / packaging
```

---

## 25. Blocker Analysis

An exhaustive search for architectural blockers was conducted:

| Potential Issue | Severity | Analysis & Evidence | Resolution / Status |
|:---|:---|:---|:---|
| **Artifact Overwrite Vulnerability** | **RESOLVED IN ARCHITECTURE** | Existing `save_artifact` did not check `target_path.exists()`. Phase 8 formally mandates `if target_path.exists(): raise EvidenceImmutableError`. | **NO BLOCKER** |
| **Unindexed Glob Startup Scan** | **RESOLVED IN ARCHITECTURE** | `EvidenceStore` globbed all session directories on startup. Phase 8 mandates relational SQLite index `evidence_records`, achieving $O(1)$ startup. | **NO BLOCKER** |
| **Missing Content Validation** | **RESOLVED IN ARCHITECTURE** | Phase 2 validator was non-enforcing. Phase 8 mandates storage-level pre-persistence check `if not any([metrics, artifacts, baseline_comparison, raw_data_ref]): raise`. | **NO BLOCKER** |
| **Artifact Digest Missing from Schema** | **RESOLVED IN ARCHITECTURE** | Schema `ArtifactReference` lacks digest. Phase 8 stores `artifact_digest` in SQLite `evidence_artifacts` table, binding the file cryptographically without schema breakage. | **NO BLOCKER** |

**Conclusion**: There are **ZERO BLOCKING ARCHITECTURAL FLAWS**. The requirements and security constraints for Phase 8 are fully defined and actionable.

---

## 26. Non-Blocking Improvements

1. **Backwards Compatibility**: The existing `EvidenceStore(base_dir)` constructor signature will be preserved, adding optional `db_manager` and `audit_logger` parameters with safe defaults.
2. **Export Archive Packaging**: Consider providing a helper method `export_session_bundle(session_id, target_zip_path)` that packages all session evidence, artifacts, and a SHA-256 manifest into a single `.cvif` zip package for air-gapped forensic transit.

---

## 27. Final Recommendation & Verdict

The architecture for Phase 8 (Evidence Store) has been audited, security-hardened, and fully specified against all upstream dependencies (Phases 2–7). The framework is ready to proceed to Phase 8 implementation.

PHASE 8 READY FOR IMPLEMENTATION — AWAITING OWNER REVIEW
