# Phase 5/12 — Inference Provenance: Pre-Implementation Architecture & Requirements Audit

**Project**: Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipeline  
**Phase**: Phase 5/12 — Inference Provenance  
**Stage**: Pre-Implementation Architecture & Requirements Forensic Audit  
**Auditor**: Independent Forensic Verification Agent  
**Date**: 2026-09-19  
**Status**: DESIGN / REQUIREMENTS AUDIT ONLY (No Production Code Modified)

---

## 1. Source of Truth & Baseline Inspection

This audit evaluated all foundational documentation, architectural specifications, Phase 2–4 review reports, and the actual implementation in `src/cvif/` and `tests/`.

### 1.1 Documents Reviewed
1. `architecture_final_review.md`: Architectural source of truth (v0.2-REVISED), specifically Section B.3 (Requirements R-I1 to R-I5), Section N (Inference Provenance Architecture N.1–N.5), Section I.5 (`InferenceRecord` schema), Section I.8 (`PredictionResult`), and Section C Blocker #1 (Inference generation vs verification separation).
2. `architecture_review.md`: Initial forensic review establishing Mode 1 (Generation) vs Mode 2 (External Assurance Gateway), key exchange constraints, and air-gapped Trust Store requirements.
3. `implementation_plan.md`: Master architectural implementation plan and module roadmap.
4. `task.md`: Original requirements tracking specification (Section 2.7).
5. `phase_2_foundation_report.md` & `phase_2_foundation_review.md`: Foundational cryptographic contracts, base schemas, SQLite DB storage, and append-only audit logger.
6. `phase_3_dataset_integrity_report.md` & `phase_3_dataset_integrity_review.md`: Ingestion gateways, format adapters, and DT-1 to DT-6 analysis implementations.
7. `phase_4_model_integrity_report.md` & `phase_4_adapter_independent_verification.md`: Model safety scanners, ONNX/PyTorch/TorchScript adapters, reference battery execution, and MT-1 to MT-4 checkers.
8. `walkthrough.md`: Historical change tracking across revisions.

### 1.2 Actual Source Code & Test Suite Baseline Traced
- **Cryptographic primitives**: `src/cvif/crypto/hashing.py`, `src/cvif/crypto/hmac.py`, `src/cvif/crypto/signing.py`, `src/cvif/crypto/chain.py`, `src/cvif/crypto/keystore.py`.
- **Core schemas**: `src/cvif/core/schemas.py` (`InferenceRecord`, `PredictionResult`, `ClassificationOutput`, `DetectionOutput`, `KeyRecord`, `AuditEvent`, `EvidenceRecord`, `Finding`).
- **Core enumerations & exceptions**: `src/cvif/core/enums.py` (`ProvenanceOutcome`, `RecordOrigin`, `KeyType`, `KeyStatus`, `SeverityLevel`, `Disposition`), `src/cvif/core/exceptions.py`.
- **Storage & audit**: `src/cvif/storage/database.py` (`DatabaseManager` with `seen_nonces`), `src/cvif/storage/filestore.py`, `src/cvif/audit/logger.py`, `src/cvif/evidence/store.py`.
- **Existing tests**: All 134 unit tests pass with `PYTHONPATH=src` (`test_crypto.py`, `test_schemas.py`, `test_audit.py`, `test_storage.py`, `test_offline.py`, `test_model_adapters.py`, `test_model_adapter_capabilities.py`, `test_mt3_neural_cleanse.py`).

---

## 2. Define Exact Phase 5 Scope (R-I1 to R-I5 Mapping)

In this project, **"Inference Provenance"** means:
> Providing tamper-evident, cryptographically verifiable proof of origin, integrity, and chronological ordering for computer vision model inference outputs originating from internal pipeline stages or external, untrusted multi-contributor field devices (tactical UAVs, border observation towers, edge sensors) operating in completely air-gapped environments.

The scope is strictly defined by requirements **R-I1 through R-I5**.

### 2.1 Requirements Mapping Table

| Requirement | Architectural Intent | Existing Implementation | Missing Implementation | Proposed Phase 5 Component |
|---|---|---|---|---|
| **R-I1: Cryptographic binding of inference records** | Deterministically bind input digest, model identity, preprocessing config, and prediction outputs using HMAC-SHA256 or Ed25519. | `InferenceRecord` schema in `schemas.py`; `compute_hmac_sha256()` in `hmac.py`; `sign_ed25519()` in `signing.py`. | Canonical serialization method in `InferenceRecord` excludes critical anti-replay/ordering fields; missing verification pipeline module; missing orchestrator integration. | `cvif.provenance.record.InferenceProvenanceRecord`, `cvif.provenance.verifier.ProvenanceVerifier` |
| **R-I2: Hashes, signatures, timestamps** | Cryptographic content-addressing of raw input image (SHA-256), model weight artifact (SHA-256), preprocessing parameters (SHA-256), UTC ISO-8601 timestamp, and digital signature. | `sha256_file()`, `sha256_canonical_json()`, `sign_ed25519()`, `verify_ed25519()`, `KeyStore` with `KeyRecord`. | Automated extractor for raw input image hashes from batches; preprocessing configuration hasher; timestamp freshness validator. | `cvif.provenance.generator.ProvenanceGenerator`, `cvif.provenance.verifier.ProvenanceVerifier` |
| **R-I3: Sequence & nonce controls** | Monotonically increasing sequence counters per session/contributor and unique random nonces to prevent replay, duplicate injection, or packet omission. | `seen_nonces` table and `record_nonce_if_new()` method in `DatabaseManager`. | SQLite session sequence tracking table (`session_sequences`); sequence regression detection; sequence gap detection. | `cvif.storage.database.DatabaseManager` (sequence extension), `cvif.provenance.verifier.ReplayChecker` |
| **R-I4: Post-hoc alteration detection** | Recompute cryptographic binding over canonical payload; flag any payload modification (confidence score, class ID, bounding box, metadata) as `TAMPERED_OUTPUT`. | Primitive functions `verify_hmac_sha256` and `verify_ed25519` exist; constant-time comparison enforced. | End-to-end payload extraction, normalization, signature verification against `KeyStore`, and emission of `IT-1` findings. | `cvif.analysis.provenance.alteration_check.AlterationCheck` |
| **R-I5: Substitution & replay detection** | Cross-reference model weight digest against Asset Catalogue (`SUBSTITUTED_MODEL`); flag duplicate nonces or sequence regressions as `REPLAYED_RECORD`. | `seen_nonces` check in DB; registered assets in `DatabaseManager.get_asset()`. | Model weight digest cross-referencing logic; duplicate nonce finding generation (`IT-3`); model substitution finding generation (`IT-2`). | `cvif.analysis.provenance.substitution_check.SubstitutionCheck`, `cvif.analysis.provenance.replay_check.ReplayCheck` |

### 2.2 Explicit Exclusions from Phase 5
Phase 5 must NOT implement:
- Distribution Shift Analysis (environmental, covariate, semantic shift) → Phase 6
- Overall Assurance Aggregation & Risk Scoring → Phase 7
- Evidence Store Schema / UI expansions → Phase 8
- Command-Line Interface (CLI) commands → Phase 9
- REST API endpoints → Phase 10
- Dashboard / Web UI → Phase 11
- Production hardening / packaging → Phase 12

---

## 3. Existing Cryptography Audit

The existing cryptographic foundation resides in `src/cvif/crypto/`. It was audited against air-gapped, defence-grade constraints.

| Primitive | Module & Implementation | Input | Output | Serialization / Canonicalization | Key Source | Verification Method | Failure Behavior |
|---|---|---|---|---|---|---|---|
| **SHA-256 (Bytes/String)** | `hashing.py`<br>`sha256_bytes()`, `sha256_string()` | `bytes`, `str` | 64-char hex string | UTF-8 encoding | N/A (unkeyed) | Direct hex string equality | Raises `CVIFCryptographicError` if input invalid |
| **SHA-256 (Streaming File)** | `hashing.py`<br>`sha256_file()` | File path (`Path`, `str`), chunk size (64 KB) | 64-char hex string | Streaming binary chunks | N/A (unkeyed) | Direct hex string equality | Raises `CVIFStorageError` if file unreadable/missing |
| **SHA-256 (Canonical JSON)** | `hashing.py`<br>`sha256_canonical_json()` | `Dict[str, Any]` | 64-char hex string | `json.dumps(sort_keys=True, separators=(',', ':'))` | N/A (unkeyed) | Direct hex string equality | Raises `CVIFCryptographicError` if non-serializable |
| **HMAC-SHA256** | `hmac.py`<br>`compute_hmac_sha256()`, `verify_hmac_sha256()` | Key: `bytes` / `str`<br>Payload: `bytes` | 64-char hex string | Key encoded as UTF-8 if str; payload raw bytes | `KeyStore.get_hmac_secret(key_id)` | `hmac.compare_digest()` (constant-time) | Raises `CVIFCryptographicError` on invalid types; returns `False` on mismatch |
| **Ed25519 (Digital Signature)** | `signing.py`<br>`sign_ed25519()`, `verify_ed25519()` | Private key: `Ed25519PrivateKey`<br>Payload: `bytes`<br>Public key: `Ed25519PublicKey` or 64-char hex | Signature: 128-char hex (64 bytes) | Payload raw bytes; keys raw 32 bytes exported via `serialization` | `KeyStore.get_public_key(key_id)` (verification); local private key (signing) | `public_key.verify(sig_bytes, payload)` | Returns `False` on `InvalidSignature` or malformed hex; raises `CVIFCryptographicError` on signing error |
| **Cryptographic Hash Chaining** | `chain.py`<br>`verify_audit_chain()` | Ordered `List[AuditEvent]` | `ChainVerificationResult` | Canonical dict serialization: `event.compute_hash()` | `GENESIS_PREVIOUS_HASH` (`"0"*64`) | $H_n = \text{SHA-256}(E_n \parallel H_{n-1})$ and $S_n > S_{n-1}$ and $T_n \ge T_{n-1}$ | Returns `ChainVerificationResult(is_valid=False, ...)` or raises `CVIFAuditChainError` |
| **Trust Store (`KeyStore`)** | `keystore.py`<br>`KeyStore` class | Key metadata, raw bytes, hex strings | `KeyRecord`, keys, status | Local thread-safe SQLite/JSON file | Air-gapped administrator import via physical media | `check_key_validity(key_id)` verifies `ACTIVE` status and validity window $[T_{from}, T_{until}]$ | Returns `(False, "reason")` if inactive, expired, suspended, or revoked |

> [!IMPORTANT]
> **No New Crypto Primitives Needed**: The existing cryptographic library is complete, well-tested (100% offline), uses constant-time comparisons, and directly meets all mathematical requirements for Phase 5. Phase 5 must reuse `cvif.crypto.*` directly.

---

## 4. Inference Record Schema Audit

### 4.1 Existing Schema: `InferenceRecord` (`src/cvif/core/schemas.py:197-231`)

```python
class InferenceRecord(CVIFBaseModel):
    record_id: UUID = Field(default_factory=uuid4)
    origin: RecordOrigin = Field(default=RecordOrigin.EXTERNAL)
    input_image_hash: str
    model_id: str
    model_weight_digest: str
    preprocessing_config_hash: str
    inference_config: Dict[str, Any] = Field(default_factory=dict)
    output: Dict[str, Any]
    binding_hmac: str
    signing_key_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=utc_now)
    sequence_number: int = Field(..., ge=0)
    nonce: str
    signature: Optional[str] = None
    schema_version: str = Field(default="1.0")
```

### 4.2 Field-by-Field Semantic Audit & Critical Gaps

| Field | Current Purpose | Threat Mitigated | Requirement | Architectural Gap / Flaw Identified |
|---|---|---|---|---|
| `record_id` | Unique UUID of the record | Entity ambiguity | Foundation | Not bound in canonical payload. |
| `origin` | `INTERNAL` vs `EXTERNAL` | Provenance domain separation | Section N.1 | Semantic tag; not cryptographically verified by remote party. |
| `input_image_hash` | SHA-256 of raw input image bytes | Input substitution (IT-4) | R-I2, R-I5 | Bound in canonical payload. Valid. |
| `model_id` | Model identifier string | Model confusion | R-I1 | Bound in canonical payload. Valid. |
| `model_weight_digest` | SHA-256 of model weights | Model substitution (IT-2) | R-I2, R-I5 | Bound in canonical payload. Valid. |
| `preprocessing_config_hash`| SHA-256 of preprocessing params | Preprocessing tampering | R-I2 | Bound in canonical payload. Valid. |
| `inference_config` | Execution config (thresholds, NMS) | Config manipulation | R-I1 | Bound in canonical payload. Valid. |
| `output` | Prediction results dictionary | Output alteration (IT-1) | R-I1, R-I4 | Bound in canonical payload. Valid, but floating-point values lack canonical quantization. |
| `binding_hmac` | HMAC-SHA256 hex string | Post-hoc alteration (IT-1) | R-I1, R-I4 | Valid for symmetric trust. |
| `signing_key_id` | Key ID in `KeyStore` | Key attribution | Section N.2 | Optional in schema, but MUST be mandatory for external verification. |
| `timestamp` | UTC timestamp of inference | Stale record / timing replay | R-I2, R-I3 | **CRITICAL FLAW**: Excluded from `compute_canonical_payload()`. An attacker can alter `timestamp` without breaking signature! |
| `sequence_number` | Monotonic counter | Sequence regression / drop | R-I3, R-I5 | **CRITICAL FLAW**: Excluded from `compute_canonical_payload()`. An attacker can alter `sequence_number` without breaking signature! |
| `nonce` | Unique random string | Replay attack (IT-3) | R-I3, R-I5 | **CRITICAL FLAW**: Excluded from `compute_canonical_payload()`. An attacker can swap `nonce` without breaking signature! |
| `signature` | Ed25519 digital signature | Tampering, repudiation | R-I1, R-I2 | Valid for asymmetric multi-contributor trust. |
| `schema_version` | Schema version (`"1.0"`) | Schema incompatibility | Architecture C.8 | Excluded from canonical payload. |

### 4.3 Missing Architectural Fields
1. `session_id: UUID` (or `str`): **MISSING**. Section N.4 step 6 and Section N.5 explicitly require tracking sequence monotonicity per `(session_id, signing_key_id)`. Without `session_id`, a sequence counter from one operational sortie or camera stream will collide with another, causing false-positive `REPLAYED_RECORD` errors.
2. `producer_id: Optional[str]`: **MISSING**. Captures the tactical unit, drone ID, or organization (e.g. `"UAV-SQDN-04"`), cross-referenced with `KeyRecord.owner_entity`.

---

## 5. Canonicalization — Critical Analysis

### 5.1 The Determinism Problem
Cryptographic signatures verify exact byte sequences. If two independently generated records contain semantically identical data, will they produce exactly the same cryptographic digest?

Under the current `InferenceRecord.compute_canonical_payload()`, the answer is **NO** in three critical edge cases:

1. **Floating-Point Representation in `output`**:
   Object detection outputs contain bounding box coordinates and confidence floats:
   `{"confidence": 0.8500000000000001, "bbox": [0.123456789, 0.23456789, 0.45678901, 0.67890123]}`.
   Different platforms, Python micro-versions, or serialization libraries format IEEE 754 floats with differing trailing digits (e.g., `0.85` vs `0.8500000000000001`).
   - *Requirement*: Numerical coordinates and confidences in canonical payloads must be quantized to fixed precision (e.g., 6 decimal places for normalized coordinates, 4 decimal places for confidences) prior to canonical JSON encoding, identical to `UnifiedDataset.compute_dataset_hash()`:
     `[round(coord, 6) for coord in bbox]`.

2. **Dictionary Key Ordering**:
   `json.dumps(..., sort_keys=True)` handles shallow and recursive dictionary key sorting in standard Python dictionaries. However, if arbitrary objects or unvalidated nested structures are embedded in `output` or `inference_config`, serialization can fail or introduce platform-dependent representations.
   - *Requirement*: `output` must be validated against `PredictionResult` schema before canonical serialization.

3. **Timestamp Representation**:
   `self.timestamp.isoformat()` can produce `2026-09-19T02:00:00+00:00` or `2026-09-19T02:00:00Z` or vary microsecond precision (`.123000` vs `.123`).
   - *Requirement*: When `timestamp` is added to the canonical payload, it must be normalized to UTC and formatted as a strict ISO-8601 string: `dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")` or equivalent standard.

4. **Unicode & Separators**:
   Python's `json.dumps(..., separators=(",", ":"), ensure_ascii=True)` ensures deterministic ASCII-escaped formatting across all OS encodings (avoiding Windows `cp1252` vs Linux `UTF-8` divergences).

---

## 6. What Exactly Is Being Bound?

To prevent conflating "hash exists" with "tamper protection", the cryptographic boundary is formally decomposed below.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      PROVENANCE CRYPTOGRAPHIC BINDING BOUNDARY                   │
│                                                                                  │
│   ┌───────────────────────────┐         ┌─────────────────────────────────────┐  │
│   │ Hash Identities (Pointers)│         │ In-Line Payload Components          │  │
│   │ • input_image_hash        │         │ • model_id                          │  │
│   │ • model_weight_digest     │         │ • inference_config                  │  │
│   │ • preprocess_config_hash  │         │ • output (PredictionResult dict)    │  │
│   └─────────────┬─────────────┘         │ • timestamp (UTC ISO-8601)          │  │
│                 │                       │ • session_id                        │  │
│                 │                       │ • sequence_number                   │  │
│                 │                       │ • nonce                             │  │
│                 └───────────────┬───────┴─────────────────────────────────────┘  │
│                                 ▼                                                │
│               Canonical Payload Byte Stream (UTF-8)                              │
│                                 │                                                │
│                 ┌───────────────┴───────────────┐                                │
│                 ▼                               ▼                                │
│         HMAC-SHA256                        Ed25519                               │
│       (binding_hmac)                     (signature)                             │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 6.1 Cryptographic Boundary Table

| Component | Bound By | Mechanism | Classification | Security Guarantee Provided |
|---|---|---|---|---|
| **A. Input Image Bytes** | `input_image_hash` | SHA-256 digest included in canonical payload | Hash Identity & Integrity | Input image cannot be swapped or modified without failing payload check (when image is present). |
| **B. Decoded Pixels** | Excluded | Not directly hashed | N/A | Excluded by design; raw file hashing avoids platform-specific decoder discrepancies (libjpeg vs OpenCV). |
| **C. Normalized Tensor** | Excluded | Not directly hashed | N/A | Excluded by design; floating-point tensor serialization across GPU/CPU would introduce non-determinism. |
| **D. Model File** | `model_weight_digest` | SHA-256 digest included in canonical payload | Hash Identity & Registry Linkage | Deployed model file cannot be altered or substituted without failing catalog cross-reference. |
| **E. Model Weights** | `model_weight_digest` | SHA-256 of file/tensors in canonical payload | Hash Identity & Authenticity | Binds the exact mathematical parameter state used for inference. |
| **F. Preprocessing Config** | `preprocessing_config_hash` | SHA-256 digest of config included in payload | Hash Identity & Pipeline Linkage | Input transforms (resizing, normalization, mean/std) cannot be covertly changed. |
| **G. PredictionResult** | `output` | Quantized dict included in canonical payload | Full Cryptographic Authenticity | Bounding boxes, class labels, and confidences cannot be modified by any adversary. |
| **H. Chronology & Stream** | `timestamp`, `sequence_number`, `nonce`, `session_id` | Included directly in canonical payload | Anti-Replay & Stream Linkage | Records cannot be delayed, duplicated, replayed, or moved between operational sessions. |
| **I. Previous Record** | Optional hash chain | $H_{prev}$ link in stream session | Session Hash Chain Linkage | Guarantees complete stream ordering without record deletions. |

---

## 7. Model Hash Semantics

Phase 4 introduced model integrity checks and defined `ModelFingerprint` containing:
- `artifact_hash`: SHA-256 of the physical file on disk.
- `weight_digest`: SHA-256 over serialized weight tensors.
- `architecture_hash`: SHA-256 of layer topology.

### 7.1 Questions & Architectural Resolutions

1. **Is model file SHA-256 sufficient for Phase 5?**
   - **Resolution**: **YES, for Mode 2 (External Assurance)**. In field deployments (UAVs, forward sensors), edge devices possess compiled models (.onnx, .pt) and compute file-level SHA-256. Demanding tensor extraction at the tactical edge is computationally infeasible.
   - For registered models in CVIF, `AssetRegistration.hash_manifest` records file digests. Comparing `InferenceRecord.model_weight_digest` against the registered model asset's file digest provides robust, air-gapped verification.

2. **Does the project distinguish container/file hash from weight-content hash?**
   - **Resolution**: Yes, Phase 4 distinguished them in `ModelFingerprint`. In Phase 5:
     - `InferenceRecord.model_weight_digest` represents the primary cryptographic digest of the deployed model file registered in the catalog.
     - If the model is an internal asset, the catalog links this file digest to its full `ModelFingerprint`.

3. **Can two files with identical semantic weights but different container metadata be considered the same model?**
   - **Resolution**: In high-assurance defence verification, **NO**. If a model file is modified—even if only metadata or headers change—the file digest changes. In Phase 5, any digest mismatch against the registered model catalog must be reported as `SUBSTITUTED_MODEL` (disposition QUARANTINE).

---

## 8. Preprocessing Provenance

### 8.1 Preprocessing Transformation Inventory
Computer vision pipelines apply pre-inference transformations:
- Geometry: resize (width, height), letterbox / padding, center crop
- Color: BGR to RGB conversion, grayscale conversion
- Normalization: pixel value scaling ($[0, 255] \to [0.0, 1.0]$), z-score standardization ($(\text{pixel} - \mu) / \sigma$)
- Layout: channel transposition ($HWC \to CHW$, NCHW)
- Quantization / dtype: `uint8` to `float32` or `float16`

### 8.2 Architectural Resolution: Configuration Hash vs Implementation Hash
- **Preprocessing Configuration Hash**: Required. The pipeline defines a standard `PreprocessingConfig`:
  ```json
  {
    "target_size": [640, 640],
    "interpolation": "bilinear",
    "color_space": "RGB",
    "channel_order": "NCHW",
    "normalize": true,
    "mean": [0.485, 0.456, 0.406],
    "std": [0.229, 0.224, 0.225],
    "range": [0.0, 1.0]
  }
  ```
  `preprocessing_config_hash = SHA-256(canonical_json(PreprocessingConfig))`.
- **Implementation Code Hash**: Out of scope for field edge records. Embedding python bytecode or library hashes into edge inference records is brittle across OS releases.
- **Decision**: Preprocessing provenance is governed by `preprocessing_config_hash`.

---

## 9. Timestamp, Sequence Number, and Nonce Model

### 9.1 Parameter Specifications
- **Timestamp**: UTC wall-clock time, serialized as ISO-8601 (`YYYY-MM-DDTHH:MM:SS.ffffffZ`).
  - *Tolerance Window*: $\pm 300\text{ seconds}$ relative to the CVIF host clock to accommodate edge clock drift without network NTP in air-gapped zones.
- **Sequence Number**: Integer $\ge 0$, strictly monotonic ($S_n > S_{n-1}$) per `(session_id, signing_key_id)`.
- **Nonce**: 128-bit cryptographically secure random string (32 hex characters or UUID4). Must be unique across the entire system lifetime.

### 9.2 Replay Scenarios & Detection Matrix

| Scenario # | Attack Description | Detection Mechanism | Primary Finding Emitted |
|---|---|---|---|
| **1** | Exact duplicate record submitted twice | SQLite `seen_nonces` table collision | `IT-3: REPLAYED_RECORD` (CRITICAL) |
| **2** | Old valid record re-injected hours/days later | Timestamp exceeds $\pm 300\text{s}$ window; sequence number $\le$ session tip | `IT-3: REPLAYED_RECORD` / `IT-TIME-SKEW` |
| **3** | Valid record copied into a different session | Session ID mismatch; signature over canonical payload fails if session is bound | `IT-1: TAMPERED_OUTPUT` / `IT-SESSION-MISMATCH` |
| **4** | Sequence number rollback ($S_n \le S_{n-1}$) | Verifier compares $S$ against `session_sequences` table | `IT-3: SEQUENCE_REGRESSION` (HIGH) |
| **5** | Timestamp rollback ($T_n < T_{n-1}$) | Verifier checks non-decreasing timestamp in sequence stream | `IT-3: TIMING_ANOMALY` (HIGH) |
| **6** | Reused nonce with altered payload | Nonce exists in `seen_nonces`; signature also fails if nonce is in payload | `IT-3: REPLAYED_RECORD` (CRITICAL) |
| **7** | Altered prediction with unchanged input/model | Cryptographic binding verification (HMAC or Ed25519) fails | `IT-1: TAMPERED_OUTPUT` (CRITICAL) |

---

## 10. Replay Detection Architecture

Replay detection requires combining **stateful persistence** with **stateless structural validation**.

```
Inbound InferenceRecord
         │
         ├─── 1. Stateless Timing Check: |T_record - T_verifier| <= 300s?
         │         └── FAIL ──▶ Emits IT-3 (Timing Skew / Replay)
         │
         ├─── 2. Stateful Nonce Lookup: Does nonce exist in SQLite seen_nonces?
         │         ├── YES ───▶ Emits IT-3 (Duplicate Nonce Replay)
         │         └── NO ────▶ Atomically insert (nonce, record_id, timestamp)
         │
         └─── 3. Stateful Sequence Tracker: S_record > S_last for (session_id, key_id)?
                   ├── NO ────▶ Emits IT-3 (Sequence Regression)
                   ├── GAP ───▶ Emits IT-5 (Dropped Record Warning)
                   └── OK ────▶ Update session_sequences table (last_seq = S_record)
```

- `seen_nonces` is already implemented in `DatabaseManager:160-167`.
- A companion table `session_sequences` must be added to track `(session_id, key_id, last_sequence_number, last_timestamp)`.

---

## 11. Substitution Detection Architecture

Trace of substitution attacks against cryptographic bindings:

```
Baseline:
Raw Image A ──(SHA-256)──▶ InputHash A
Model File A ──(SHA-256)──▶ ModelHash A   ──▶ CanonicalPayload A ──▶ Sig A (Key A)
Preprocess A ──(SHA-256)──▶ PreprocHash A
Output A     ─────────────▶ Output A
```

1. **Input Substitution**: Attacker presents Image B with Record A.
   - Verifier computes $\text{SHA-256}(\text{Image B}) \ne \text{InputHash A}$.
   - **Binding Broken**: Hash mismatch triggers `IT-4` (`TAMPERED_INPUT`).
2. **Model Substitution**: Attacker runs inference on unauthorized Model B, claims Model A.
   - If attacker puts Model B hash in record: Signature verification fails (Sig A does not match).
   - If attacker leaves Model A hash in record: Model registry cross-reference fails when verifying against physical artifact. Triggers `IT-2` (`SUBSTITUTED_MODEL`).
3. **Preprocessing Substitution**: Attacker alters normalization to cause misclassification.
   - Preprocessing hash mismatch detected against authorized pipeline config. Triggers `IT-2` / `SUBSTITUTED_CONFIG`.
4. **Output Substitution**: Attacker alters bounding box coordinates or classification label.
   - Output dictionary differs from signed canonical payload.
   - **Binding Broken**: Ed25519 / HMAC verification fails deterministically. Triggers `IT-1` (`TAMPERED_OUTPUT`).
5. **Provenance Record Substitution**: Attacker replaces Record A with Record C from another camera.
   - Nonce collision or sequence regression detected; session ID mismatch detected. Triggers `IT-3`.

---

## 12. Tampering Detection (Post-Hoc Alteration)

| Alteration | What Verification Fails? | Deterministic? | Verifier External State Needed? |
|---|---|---|---|
| **Modify input hash** | HMAC / Ed25519 verification over canonical payload | Yes (100%) | No (Self-contained cryptographic check) |
| **Modify model hash** | HMAC / Ed25519 verification over canonical payload | Yes (100%) | No |
| **Modify prediction output** | HMAC / Ed25519 verification over canonical payload | Yes (100%) | No |
| **Modify timestamp** | HMAC / Ed25519 (when timestamp included in payload) | Yes (100%) | No |
| **Modify sequence number** | HMAC / Ed25519 (when sequence included in payload) | Yes (100%) | No (Also caught by sequence tracker) |
| **Modify nonce** | HMAC / Ed25519 (when nonce included in payload) | Yes (100%) | No (Also caught by nonce registry) |
| **Modify previous record hash** | Hash chain verification link broken | Yes (100%) | Stream context |
| **Modify signature / MAC** | Cryptographic signature verification (`InvalidSignature`) | Yes (100%) | No |

---

## 13. HMAC-SHA256 vs Ed25519 Cryptographic Trust Model

| Criterion | HMAC-SHA256 | Ed25519 Digital Signature |
|---|---|---|
| **Cryptographic Scheme** | Symmetric shared-secret | Asymmetric public/private keypair |
| **Key Distribution** | Pre-shared key (PSK) shared between producer and verifier | Private key kept on device; Public key distributed to verifiers |
| **Repudiation Resistance** | Low (Verifier can forge valid records since it holds the secret) | High (Only producer possessing private key can sign; verifier cannot forge) |
| **Air-Gap Operational Fit** | Best for closed, high-throughput internal pipelines (Mode 1) | Mandatory for untrusted, multi-contributor field devices (Mode 2) |
| **Computation Latency** | $\sim 0.005\text{ ms}$ per record | $\sim 0.05\text{ ms}$ to sign, $\sim 0.10\text{ ms}$ to verify |
| **Signature Size** | 32 bytes (64 hex characters) | 64 bytes (128 hex characters) |
| **Phase 5 Role** | Supported for Mode 1 (Internal Generation) & high-speed telemetry | Primary requirement for Mode 2 (Multi-Contributor Field Assurance) |

**Conclusion**: Both primitives must be supported. External assurance gateways prioritize Ed25519; HMAC is used when symmetric shared keys are provisioned.

---

## 14. Key Management & Air-Gapped Trust Store

The existing `KeyStore` (`src/cvif/crypto/keystore.py`) fully satisfies air-gapped constraints:
- **Key Identifiers**: Alphanumeric IDs (`IN-ARMY-UAV-04-PUB`, `BORDER-CAM-SECTOR-2-PUB`).
- **Key Material**: Raw 32-byte Ed25519 public keys or HMAC secrets.
- **Key Status Lifecycle**: `ACTIVE` $\to$ `SUSPENDED` $\to$ `REVOKED` $\to$ `EXPIRED`.
- **Offline Provisioning**: Keys imported via encrypted physical storage (USB/SD) by system administrators. No external network, CA, or OCSP required.
- **Key Rotation**: New key registered with new `key_id`; old key marked `SUSPENDED` (valid for historical verification, rejected for new timestamps).
- **Missing / Unknown Key**: Returns `UNVERIFIED_KEY` (Disposition: `REVIEW`).

---

## 15. Failure, Disposition & Verification Semantics

| Inbound Record Condition | Verification Outcome | Severity | Recommended Disposition | Finding Code | Architectural Category |
|---|---|---|---|---|---|
| Fully valid record | `VERIFIED` | NONE | `ACCEPT` | None | PASS |
| Signature / HMAC mismatch | `TAMPERED_OUTPUT` | `CRITICAL` | `QUARANTINE` | `IT-1` | FAIL |
| Prediction output altered | `TAMPERED_OUTPUT` | `CRITICAL` | `QUARANTINE` | `IT-1` | FAIL |
| Input image hash mismatch | `TAMPERED_OUTPUT` | `CRITICAL` | `QUARANTINE` | `IT-4` | FAIL |
| Model weight digest mismatch | `SUBSTITUTED_MODEL`| `HIGH` | `QUARANTINE` | `IT-2` | FAIL |
| Preprocessing config mismatch | `SUBSTITUTED_MODEL`| `MEDIUM` | `REVIEW` | `IT-2` | FAIL |
| Reused nonce | `REPLAYED_RECORD` | `CRITICAL` | `QUARANTINE` | `IT-3` | FAIL |
| Sequence regression ($S_n \le S_{n-1}$)| `REPLAYED_RECORD` | `HIGH` | `QUARANTINE` | `IT-3` | FAIL |
| Sequence gap ($S_n > S_{n-1} + 1$) | `VERIFIED_WARN` | `MEDIUM` | `REVIEW` | `IT-5` | PASS (Warning) |
| Unknown `signing_key_id` | `UNVERIFIED_KEY` | `MEDIUM` | `REVIEW` | `IT-KEY-UNKNOWN`| UNVERIFIABLE |
| Revoked / expired key | `EXPIRED_KEY` | `HIGH` | `QUARANTINE` | `IT-KEY-EXPIRED`| FAIL |
| Timestamp skew $> 300\text{s}$ | `REPLAYED_RECORD` | `HIGH` | `REVIEW` | `IT-3` | FAIL |
| Unsupported schema version | `UNSUPPORTED` | `MEDIUM` | `REVIEW` | `IT-SCHEMA-ERR` | UNSUPPORTED |

---

## 16. Threat Model Mapping

```
Threat Taxonomy (IT Series: Inference & Provenance Threats)
├── IT-1: Post-Hoc Output Alteration (Prediction Tampering)
├── IT-2: Model & Preprocessing Substitution
├── IT-3: Replay, Injection & Sequence Reordering
├── IT-4: Input Image Tampering / Substitution
├── IT-5: Dropped Records / Sequence Gaps
└── IT-KEY: Key Lifecycle & Authentication Failures
```

### Threat Mitigation Table

| Threat ID | Threat / Attack Vector | Provenance Control | Evidence Produced | Verification Method |
|---|---|---|---|---|
| **IT-1** | Adversary alters detection bbox or class confidence in transit | Ed25519 / HMAC-SHA256 signature over quantized canonical payload | `EvidenceRecord` with expected vs actual digest delta | `ProvenanceVerifier.verify_binding()` |
| **IT-2** | Adversary substitutes unapproved or compromised model weights | Cross-reference `model_weight_digest` against Asset Catalogue | `EvidenceRecord` showing registered vs observed model digest | `ProvenanceVerifier.verify_model_registration()` |
| **IT-3** | Adversary replays recorded legitimate reconnaissance output | Unique nonce check against SQLite `seen_nonces` index; sequence monotonicity check | `EvidenceRecord` with duplicate nonce or regression sequence numbers | `ReplayChecker.check_nonce()`, `ReplayChecker.check_sequence()` |
| **IT-4** | Adversary swaps raw input image while retaining valid output | Compute `SHA-256(raw_image)` and compare with `input_image_hash` | `EvidenceRecord` with image byte hash mismatch | `ProvenanceVerifier.verify_input_image()` |
| **IT-5** | Adversary drops frames to suppress detection events | Sequence gap detection ($S_n - S_{prev} > 1$) | `EvidenceRecord` listing missing sequence IDs | `ReplayChecker.check_sequence_gaps()` |
| **IT-KEY** | Adversary submits record signed with revoked or unknown key | KeyStore status check (`ACTIVE`, not `REVOKED` or `EXPIRED`) | `EvidenceRecord` detailing key status and expiry timestamp | `KeyStore.check_key_validity()` |

---

## 17. Strict Phase Boundaries

To prevent scope creep, Phase 5 boundaries are strictly demarcated:

- **IN SCOPE for Phase 5**:
  - `InferenceRecord` schema update (canonical payload fix, `session_id`, `producer_id`).
  - Mode 1: Provenance Generator (`InferenceProvenanceGenerator`) to sign/bind outputs from local `ModelAdapter`.
  - Mode 2: Provenance Assurance Verifier (`InferenceProvenanceVerifier`) for external record verification.
  - Replay & sequence protection engine (`ReplayChecker`, `session_sequences` table).
  - Standalone provenance analysis checks (`IT-1` to `IT-5`) conforming to `BaseAnalysisCheck`.
  - Comprehensive unit test battery (A through R).

- **EXCLUDED from Phase 5**:
  - Image distribution shift, sensor drift, environmental shifts $\to$ **Phase 6**.
  - Risk score aggregation formulas, composite verdicts $\to$ **Phase 7**.
  - CLI commands (`cvif verify-provenance`) $\to$ **Phase 9**.
  - REST API routes (`/api/v1/provenance/verify`) $\to$ **Phase 10**.
  - UI Dashboards & visual charts $\to$ **Phase 11**.

---

## 18. Test Strategy

Minimum required test battery before Phase 5 sign-off:

| Test ID | Test Name | Target Security Property Proven |
|---|---|---|
| **A** | `test_deterministic_canonical_payload` | Identical inputs produce identical byte-level canonical payloads across float variations. |
| **B** | `test_ed25519_valid_signature_verification` | Legitimate Ed25519 signature verifies with status `VERIFIED` and disposition `ACCEPT`. |
| **C** | `test_hmac_valid_binding_verification` | Legitimate HMAC-SHA256 verifies with status `VERIFIED` and disposition `ACCEPT`. |
| **D** | `test_output_tampering_detection_it1` | Single-bit alteration of detection bounding box or class confidence triggers `TAMPERED_OUTPUT` (CRITICAL). |
| **E** | `test_input_image_mismatch_detection_it4` | Swapping attached image file while keeping record intact triggers `TAMPERED_OUTPUT` (CRITICAL). |
| **F** | `test_model_weight_substitution_it2` | Mismatched model weight digest against Asset Catalogue triggers `SUBSTITUTED_MODEL` (HIGH). |
| **G** | `test_preprocessing_config_tampering` | Altered preprocessing config hash triggers `SUBSTITUTED_MODEL` / `REVIEW`. |
| **H** | `test_exact_duplicate_replay_it3` | Submitting the same valid record twice triggers `REPLAYED_RECORD` (CRITICAL) on duplicate nonce. |
| **I** | `test_sequence_number_regression_it3` | Submitting record with $S_n \le S_{n-1}$ for the same session triggers `REPLAYED_RECORD` (HIGH). |
| **J** | `test_sequence_gap_detection_it5` | Missing sequence numbers ($S=1$, then $S=4$) triggers warning finding `IT-5` (MEDIUM). |
| **K** | `test_nonce_uniqueness_across_sessions` | Reusing a nonce in a different session is caught by global SQLite `seen_nonces` index. |
| **L** | `test_timestamp_skew_rejection` | Timestamp > 300s in past or future triggers `REPLAYED_RECORD` / `IT-TIME-SKEW`. |
| **M** | `test_unknown_signing_key` | Valid signature from unregistered key ID triggers `UNVERIFIED_KEY` (MEDIUM) with disposition `REVIEW`. |
| **N** | `test_revoked_and_expired_key` | Signature with revoked or expired key ID triggers `EXPIRED_KEY` (HIGH) with disposition `QUARANTINE`. |
| **O** | `test_schema_version_compatibility` | Record with unsupported `schema_version` fails gracefully with `UNSUPPORTED`. |
| **P** | `test_air_gapped_provenance_verification` | Verification completes 100% offline with zero network sockets opened. |
| **Q** | `test_multi_contributor_key_isolation` | Stream from Contributor A cannot corrupt or reset sequence state of Contributor B. |
| **R** | `test_mode1_generation_to_mode2_verification` | Record generated by Mode 1 passes Mode 2 verification end-to-end. |

---

## 19. Performance, Latency & Scale Analysis

Expected provenance overhead per inference record:

| Operation | Typical Overhead | Mitigation / Caching Strategy |
|---|---|---|
| **Input Image Hashing** | $1.0 - 4.0\text{ ms}$ (2–5 MB image) | Compute streaming SHA-256 during ingestion; cache hash by image content. |
| **Model Artifact Hashing** | $100 - 1500\text{ ms}$ (50–500 MB model) | **MUST BE CACHED**. Do not hash model on every inference. Look up cached digest from Asset Catalogue by `model_id`. |
| **Preprocessing Config Hashing** | $< 0.05\text{ ms}$ (< 1 KB JSON) | Fast in-memory canonical JSON hashing. |
| **Canonical Serialization** | $< 0.10\text{ ms}$ | Pre-compiled JSON serializer with sorted keys. |
| **Ed25519 Signature Verification** | $\sim 0.10\text{ ms}$ | Standard CPU asymmetric verification. |
| **HMAC-SHA256 Verification** | $\sim 0.005\text{ ms}$ | Hardware-accelerated SHA-256. |
| **SQLite Nonce & Sequence Check** | $< 0.30\text{ ms}$ | Indexed SQLite queries with WAL mode enabled. |
| **Total Verification Latency** | **$< 2.0\text{ ms}$** (with cached model digest and in-memory image hash) | Suitable for near-real-time tactical edge stream verification. |

---

## 20. Final Architecture Decisions Table

| # | Decision | Current Architecture | Ambiguity | Recommended Resolution | Requirement Affected |
|---|---|---|---|---|---|
| **1** | **Canonical Payload Contents** | `InferenceRecord.compute_canonical_payload()` binds only image, model, config, and output. | `timestamp`, `sequence_number`, `nonce`, and `session_id` are excluded from the signed payload, allowing undetected metadata tampering. | **Add `timestamp`, `sequence_number`, `nonce`, and `session_id` to the canonical payload**. | R-I1, R-I2, R-I3, R-I4 |
| **2** | **Session Binding** | `InferenceRecord` has no `session_id` field. | Sequence monotonicity cannot be checked across independent streams without session context. | **Add `session_id: UUID` to `InferenceRecord` schema**. | R-I3, R-I5 |
| **3** | **Sequence Tracking State** | `DatabaseManager` only tracks `seen_nonces`. | Sequence numbers cannot be validated without persistent sequence state. | **Add `session_sequences` table to `DatabaseManager`**: `(session_id, key_id, last_seq, last_time)`. | R-I3, R-I5 |
| **4** | **Float Canonicalization** | Bounding box coordinates and confidences have unquantized floats. | Minor float formatting differences across platforms break signature verification. | **Quantize bboxes to 6 decimal places and confidences to 4 decimal places** in canonical payload. | R-I1, R-I4 |
| **5** | **Signing Key Identification** | `signing_key_id` is optional in `InferenceRecord`. | Verifier cannot resolve public key from `KeyStore` if key ID is omitted. | **Mandate `signing_key_id: str` for any signed record**. | Section N.2, R-I1 |
| **6** | **Model Hash Semantics** | `model_weight_digest` name implies tensor weights, but file hash is used for verification. | Ambiguity between container file hash and internal weight tensor hash. | **Clarify that `model_weight_digest` in `InferenceRecord` stores the registered model container file SHA-256** matching `AssetRegistration.hash_manifest`. | R-I2, R-I5 |
| **7** | **HMAC vs Ed25519 Precedence** | Schema supports both `binding_hmac` and `signature`. | Verifier doesn't know which to check if both or either are present. | **If `signature` is present, verify Ed25519 using `KeyStore` public key. If `binding_hmac` is present, verify HMAC using `KeyStore` secret. At least one must be present**. | R-I1 |
| **8** | **Air-Gap Clock Skew Window** | Undefined allowable skew. | False rejections due to unsynchronized edge RTC clocks. | **Set default tolerance window to $\pm 300\text{ seconds}$** with configuration override. | R-I3 |
| **9** | **Producer Attribution** | Only `RecordOrigin` (INTERNAL/EXTERNAL) is tracked. | Cannot attribute external records to specific tactical unit or vehicle. | **Add `producer_id: Optional[str]` to `InferenceRecord`** and cross-reference with `KeyRecord.owner_entity`. | Section N.2 |
| **10**| **Verifier Interface Structure** | No analysis checker exists under `cvif/analysis/` for inference. | How does orchestrator execute inference provenance checks? | **Create `InferenceProvenanceOrchestrator` and checks `AlterationCheck`, `SubstitutionCheck`, `ReplayCheck`**. | R-I1 to R-I5 |

---

## 21. Final Verdict & Phase 5 Readiness

All architectural requirements R-I1 through R-I5 are fully understood, traceable to the existing foundation, and the 10 critical design resolutions above are completely concrete and actionable without requiring changes to Phase 2, Phase 3, or Phase 4 code.

### 21.1 Exact Phase 5 Implementation Scope
1. **Schema Refinements** (`src/cvif/core/schemas.py`):
   - Enhance `InferenceRecord` with `session_id`, `producer_id`, and mandatory `signing_key_id`.
   - Update `InferenceRecord.compute_canonical_payload()` to deterministically bind `session_id`, `timestamp`, `sequence_number`, `nonce`, and quantized `output`.
2. **Storage Enhancements** (`src/cvif/storage/database.py`):
   - Add `session_sequences` table schema.
   - Add `record_sequence_if_monotonic()` method to validate and update session sequence numbers atomically.
3. **Provenance Engine** (`src/cvif/provenance/`):
   - `generator.py`: Mode 1 internal record generator binding outputs from `ModelAdapter`.
   - `verifier.py`: Mode 2 assurance verifier performing 8-step verification pipeline against `KeyStore` and `DatabaseManager`.
   - `replay.py`: Stateful nonce and sequence monotonicity engine.
4. **Analysis Checks** (`src/cvif/analysis/inference_provenance/`):
   - `orchestrator.py`: `InferenceProvenanceOrchestrator` coordinating analysis.
   - `alteration.py`: `PostHocAlterationCheck` (emits `IT-1`).
   - `substitution.py`: `SubstitutionCheck` (emits `IT-2`, `IT-4`).
   - `replay.py`: `ReplayCheck` (emits `IT-3`, `IT-5`).
5. **Unit Test Suite** (`tests/unit/test_inference_provenance.py`):
   - 18 comprehensive tests covering Scenarios A through R.

### 21.2 Explicit Exclusions
- Do NOT implement distribution shift algorithms (Phase 6).
- Do NOT modify existing dataset integrity checks (Phase 3).
- Do NOT modify model integrity algorithms (Phase 4).
- Do NOT build CLI or web UI endpoints (Phases 9 & 11).

PHASE 5 READY FOR IMPLEMENTATION
