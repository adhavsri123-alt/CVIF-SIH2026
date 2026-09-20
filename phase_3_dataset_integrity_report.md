# Phase 3: Dataset Ingestion & Data Integrity Analysis Report
**Project:** Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines  
**Department:** Ministry of Defence (MoD) / Indian Army (DGIS)  
**System Version:** CVIF Architecture v0.2-REVISED  
**Phase Status:** COMPLETE  
**Execution Environment:** Windows-10-10.0.26200-SP0 | Python 3.10.11 | Air-Gapped (Zero Network Sockets)

---

## 1. Executive Summary

Phase 3/12 implements the model-agnostic **Dataset Ingestion** and **Data Integrity Analysis** layer of the Computer Vision Integrity Framework (CVIF). The layer ingests computer vision datasets (COCO and YOLO formats across all standard structural variants), performs strict non-destructive structural validation, establishes immutable cryptographic dataset and sample identities, preserves multi-contributor provenance without heuristic inference, and executes a battery of data integrity checks covering Threat Taxonomy items **DT-1 through DT-6**.

All operations are 100% offline, require zero external network dependencies, generate canonical `EvidenceRecord` artifacts in the append-only `EvidenceStore`, and record tamper-evident hash-chained audit events into the `AuditLogger`.

---

## 2. Components Implemented

### 2.1 Domain Data Schemas (`src/cvif/core/schemas.py`)
- **`ImageRecord`**: Canonical per-sample metadata including relative path, content SHA-256 digest, width, height, file size, and acquisition source metadata.
- **`AnnotationRecord`**: Normalized bounding box representation `[x_min, y_min, x_max, y_max]` in range `[0.0, 1.05]`, category mappings, polygon segmentation envelope, confidence score, and origin tags.
- **`ClassInfo`**: Class identifier, normalized display name, and instance count tracking.
- **`UnifiedDataset`**: Canonical, model-agnostic dataset container unifying COCO and YOLO representations. Features deterministic `compute_dataset_hash()` based on canonical JSON sorting over images, annotations, classes, and provenance.

### 2.2 Pure-Python Image Header Inspection & Hashing (`src/cvif/ingestion/image_utils.py`)
- **`inspect_image_file` / `get_image_metadata`**: Pure-Python byte-level header parsers extracting image dimensions and format from PNG (IHDR chunk), JPEG (SOF0/SOF2 markers), BMP (BITMAPINFOHEADER), GIF (Screen Descriptor), and WebP (VP8/VP8L/VP8X chunks) without third-party C-extensions (PIL/OpenCV), ensuring 100% air-gap reliability on Windows.
- **`compute_dhash`**: 64-bit perceptual difference hash measuring horizontal luminance gradients across an 8x8 block grid, enabling invariant detection of compression, minor scaling, and near-duplicate flooding.
- **`hamming_distance`**: Bitwise XOR population count measuring perceptual similarity between 64-bit dHash hex strings.

### 2.3 Dataset Ingestion Adapters (`src/cvif/ingestion/adapters/`)
- **`COCOAdapter` (`coco.py`)**:
  - Auto-locates primary COCO JSON (`annotations/instances_train.json`, `instances_*.json`, `annotations/*.json`, or root JSON).
  - Validates mandatory keys (`images`, `annotations`, `categories`).
  - Converts COCO bounding boxes `[x, y, width, height]` to normalized coordinates `[x_min, y_min, x_max, y_max]`.
  - Non-destructive validation detecting missing images, orphan annotations, unknown category IDs, malformed coordinates, and negative dimensions.
  - Sanitizes file paths against directory traversal attacks (`../`, `..\\`).
  - Preserves contributor metadata from `info.contributor` when explicitly supplied.
- **`YOLOAdapter` (`yolo.py`)**:
  - Supports **Standard Split** layout (`images/{train,val}`, `labels/{train,val}`).
  - Supports **Flat** layout (`images/`, `labels/`).
  - Supports **Paired** layout (co-located image and `.txt` files).
  - Parses `data.yaml` / `dataset.yaml` for class name lists or dictionary maps and contributor provenance.
  - Generates synthetic class names (`class_0`, `class_1`, ...) when `data.yaml` is absent.
  - Converts standard YOLO box format `[center_x, center_y, width, height]` to normalized `[x_min, y_min, x_max, y_max]`.
  - Calculates minimum enclosing bounding box envelopes for YOLOv8 polygon segmentation annotations (`len(tokens) > 5`).
  - Detects malformed annotation tokens, negative class IDs, and orphan label files.

### 2.4 Ingestion Gateway (`src/cvif/ingestion/gateway.py`)
- **`FormatDetector`**: Inspects directory layout and file signatures to classify dataset formats (`coco` or `yolo`) and variants (`split`, `flat`, `paired`).
- **`IngestionGateway`**: Coordinates format detection, adapter execution, structural validation, hash manifest generation, asset cataloging in SQLite `DatabaseManager`, and audit trail logging (`AuditEventType.ASSET_INGESTED`).

### 2.5 Data Integrity Analysis Engine (`src/cvif/analysis/`)
- **`DataIntegrityCheck` (`base.py`)**: Abstract base contract for all integrity checks. Pairs each finding with a canonical `EvidenceRecord` and persists it directly into `EvidenceStore`.
- **`NearDuplicateCheck` (`DT-4`)**:
  - Detects exact duplicate image files via content SHA-256 collisions.
  - Detects perceptual near-duplicates via 64-bit dHash Hamming distance clustering using connected-component graph traversal.
- **`TriggerInjectionCheck` (`DT-1`)**:
  - Evaluates spatial-frequency boundary residuals and high-contrast corner artifacts to detect digital backdoor patches or checkerboard watermark injection.
- **`LabelFlippingCheck` (`DT-2`)**:
  - Computes k-NN neighborhood consensus in feature embedding space to detect individual samples whose assigned label severely contradicts their visual peers.
- **`SystematicMislabellingCheck` (`DT-3`)**:
  - Analyzes directional class confusion asymmetry between class centroids to identify targeted, asymmetric mislabelling patterns.
- **`OODInsertionCheck` (`DT-5`)**:
  - Measures sample-level feature dispersion distances ($> 3.0\sigma$) across active variance dimensions within each class conditional distribution to flag out-of-distribution insertions.
- **`ContributorRiskCheck` (`DT-6`)**:
  - Aggregates integrity findings by explicit `contributor_id` and computes normalized risk scores. Strictly skips execution when provenance is absent (never infers or invents contributor identity).
- **`DatasetIntegrityOrchestrator` (`orchestrator.py`)**:
  - Executes applicable integrity checks on `UnifiedDataset`, creates an `AnalysisSession`, records audit events (`ANALYSIS_STARTED`, `FINDING_RECORDED`, `ANALYSIS_COMPLETED`), and stores session data in SQLite database.

---

## 3. Cryptographic Identity & Hashing Rules

### 3.1 Dataset Identity (`dataset_hash`)
The dataset identity is an immutable SHA-256 digest computed over a canonical JSON payload comprising:
1. **Format Origin**: `coco` or `yolo`.
2. **Images**: List of images sorted lexicographically by normalized POSIX relative path (`file_path.replace("\\", "/")`), with `file_hash`, `width`, and `height`.
3. **Annotations**: List of annotations sorted lexicographically by `(image_id, class_id, bbox_str)`, with coordinates rounded to 6 decimal places.
4. **Classes**: List of classes sorted numerically by `class_id`.
5. **Provenance**: Explicit `contributor_id` and `batch_id`.
6. **Schema Version**: Schema version string (`1.0`).

### 3.2 Invariance and Sensitivity Guarantees
- **Invariance**: Filesystem directory traversal order and in-memory list shuffling do not alter `dataset_hash` due to strict deterministic sorting.
- **Sensitivity**: Modifying a single byte of an image, altering an annotation coordinate, changing a class label, or updating contributor provenance produces a completely distinct `dataset_hash`.

---

## 4. Analysis Check Thresholds & Configuration

| Check ID | Threat Name | Methodology | Default Threshold | Recommended Disposition |
| :--- | :--- | :--- | :--- | :--- |
| **DT-1** | Trigger Injection | Boundary gradient residual divergence | `trigger_anomaly_threshold = 0.55` | `QUARANTINE` |
| **DT-2** | Label Flipping | k-NN feature neighborhood consensus | `k_neighbors = 5`, `disagreement_threshold = 0.80` | `REVIEW` |
| **DT-3** | Systematic Mislabelling | Directional centroid confusion asymmetry | `asymmetry_threshold = 0.35`, `min_class_samples = 3` | `REVIEW` |
| **DT-4** | Near-Duplicate Flooding | SHA-256 collision + 64-bit dHash | `max_hamming_dist = 4` | `QUARANTINE` (exact) / `REVIEW` (near) |
| **DT-5** | OOD Sample Insertion | Active dimension feature dispersion ($Z$-score) | `sigma_threshold = 3.0`, `min_class_samples = 4` | `REVIEW` |
| **DT-6** | Contributor Attribution | Finding density & severity-weighted risk | `risk_threshold = 0.60` | `REVIEW` / `QUARANTINE` |

---

## 5. False-Positive & Threat Attribution Nuance

1. **Validation Failures vs. Malicious Indicators**:
   - A missing image file or malformed annotation line is classified as an **ingestion/structural defect**, not evidence of an adversary.
2. **Statistical Outliers vs. Poisoning**:
   - An image with feature dispersion $> 3.0\sigma$ is reported as a **Potential Out-of-Distribution (OOD) Candidate** rather than confirmed poisoning, acknowledging legitimate rare operational environments (e.g. night-vision or camouflage).
3. **Provenance Integrity**:
   - Contributor provenance is strictly attributed only when explicitly stated in dataset metadata (`info.contributor` or `data.yaml`). The framework never infers or invents contributor identity.

---

## 6. Known Limitations & Unsupported Variants

1. **Unsupported Formats**:
   - Pascal VOC XML, TFRecord, and LabelMe formats are detected as unsupported and cleanly rejected by `FormatDetector` and `IngestionGateway`.
2. **Extreme Geometric Transforms in dHash**:
   - 64-bit difference hashing detects scaling, minor compression, and identical frames, but does not detect heavy 90-degree rotations or extreme non-linear warping without deep embeddings.
3. **Sub-Pixel Backdoor Triggers**:
   - Static spatial-frequency boundary analysis detects high-contrast digital watermark patches and corner patterns, but imperceptible sub-pixel clean-label perturbation attacks require model-level analysis (deferred to Phase 5).

---

## 7. Test Suite Execution & Verification

The test suite was executed in full without skipping tests or disabling air-gap controls.

### Test Results Breakdown
- **`tests/unit/test_adapters.py`**: 6 passed (Phase 2 foundation contracts)
- **`tests/unit/test_audit.py`**: 5 passed (Audit logger, monotonic sequence, hash chain verification)
- **`tests/unit/test_config.py`**: 4 passed (Config resolution, schema defaults)
- **`tests/unit/test_crypto.py`**: 5 passed (Ed25519 signing, HMAC-SHA256, keystore)
- **`tests/unit/test_evidence.py`**: 2 passed (EvidenceStore write-once and tamper-resistance)
- **`tests/unit/test_image_utils.py`**: 4 passed (Pure-Python PNG/JPEG header parsing, dHash, Hamming distance)
- **`tests/unit/test_ingestion_coco.py`**: 6 passed (Valid COCO, missing images, orphan annotations, bad bboxes, path traversal)
- **`tests/unit/test_ingestion_yolo.py`**: 6 passed (Split layout, flat layout, paired layout, polygon segmentation, malformed lines, orphan labels)
- **`tests/unit/test_dataset_identity.py`**: 5 passed (Determinism, image sensitivity, annotation sensitivity, contributor sensitivity, ordering invariance)
- **`tests/unit/test_data_integrity_checks.py`**: 6 passed (Unit verification of DT-1 through DT-6 checkers)
- **`tests/unit/test_ingestion_gateway_and_orchestrator.py`**: 2 passed (Full ingestion to analysis pipeline, database persistence, audit chain verification)
- **`tests/unit/test_adversarial_datasets.py`**: 6 passed (Path traversal, disguised duplicates, same metadata spoofing, extreme aspect ratios, extreme class imbalance, partially corrupt files)
- **`tests/unit/test_offline.py`**: 2 passed (Strict air-gap execution with monkeypatched socket prohibition)
- **`tests/unit/test_schemas.py`**: 10 passed (Pydantic schema validation, sequence numbers, hash manifest)
- **`tests/unit/test_storage.py`**: 5 passed (SQLite storage, filestore, path traversal safety)

### Summary Statistics
- **Total Tests:** 74
- **Passed:** 74
- **Failed:** 0
- **Skipped:** 0
- **Runtime:** 1.07 seconds
- **Python Version:** 3.10.11 (64-bit)
- **Platform:** Windows-10-10.0.26200-SP0

---

## 8. Phase Scope Boundary Confirmation

In accordance with Phase 3 instructions:
- **No Phase 4+ functionality was implemented:**
  - Zero model behavioral fingerprinting
  - Zero trigger reconstruction / Neural Cleanse
  - Zero parameter / activation analysis
  - Zero inference provenance tracking on live streams
  - Zero dashboard UI components
- All changes strictly adhere to `implementation_plan.md` v0.2-REVISED.

---

## 9. Final Phase Status

**PHASE 3 COMPLETE**
