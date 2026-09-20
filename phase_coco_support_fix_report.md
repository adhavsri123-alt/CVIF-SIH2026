# CVIF COCO Split-First Ingestion & Multi-Manifest Hardening Report

## Executive Summary

- **Task**: CVIF COCO Split-First Support — Implementation + Hardening
- **Target Dataset**: `COCO Subset.v4-80-15-5-ratio-with-5-classes.coco` (Roboflow / Ultralytics split-first COCO layout)
- **Status**: **COCO SUPPORT FIX VERIFIED** (All 13 acceptance criteria satisfied)

---

## 1. Root Cause Analysis

Prior to this fix, the CVIF COCO ingestion pipeline contained architectural assumptions that prevented it from recognizing and loading multi-split COCO datasets:

1. **Restricted Detection**: `FormatDetector.detect()` only searched the dataset root and `annotations/` directory for COCO JSON files. It never inspected split directories (`train/`, `valid/`, `val/`, `test/`). Consequently, standard split-first COCO datasets were marked as `unsupported`.
2. **Single-Manifest Assumption**: `COCOAdapter` assumed a single annotation file (`self.annotation_file`). It lacked mechanisms to discover, validate, or aggregate multiple split manifests simultaneously.
3. **Missing Split Image Candidates**: `_find_image_file()` did not include `"valid"` in its candidate directory lookups and lacked split-scoped resolution (`preferred_dir / file_name`), incurring unnecessary fallback searches.
4. **ID Collisions Across Splits**: Split-first COCO manifests frequently reset image IDs and annotation IDs starting at 0 in every split file. Ingesting multiple manifests without namespacing resulted in image and annotation ID collisions and corrupt dataset hashing.
5. **Missing Unified Splits Mapping**: `UnifiedDataset.splits` was not populated for COCO datasets, discarding split provenance.

---

## 2. Files Changed

| File Path | Nature of Modification |
|---|---|
| `src/cvif/ingestion/format_detector.py` | Added inspection of split subdirectories (`train/`, `valid/`, `val/`, `test/`) for candidate COCO manifests (`_annotations.coco.json`, `annotations.json`, `instances.json`, `instances_{split}.json`, and arbitrary `*.json` with genuine COCO signatures). Refined `_is_coco_json` to inspect up to 8KB peek and full JSON fallback. |
| `src/cvif/ingestion/adapters/coco.py` | Replaced single-manifest model with `self.split_manifests: List[Tuple[Optional[str], Path]]`. Added split-aware image resolution (`preferred_dir` first O(1) resolution), `"valid"` and `"images/valid"` candidate directories, deterministic ID namespacing (`f"{split}_{raw_id}"`), `UnifiedDataset.splits` population, zero-match validation failure, and multi-manifest validation/loading. |
| `tests/unit/test_ingestion_coco.py` | Added 10 new regression test cases covering all 20 required scenarios (split-first directories, all 4 split names, multiple manifests, ID collision handling, zero-match failure, missing/orphan split reporting, and real dataset verification). |

---

## 3. Discovery Behavior Before vs. After

| Stage | Before Fix | After Fix |
|---|---|---|
| **Format Detection** | Searched only root and `annotations/`. Reported `unsupported` on split-first datasets. | Searches root, `annotations/`, and split folders (`train/`, `valid/`, `val/`, `test/`). Reports `("coco", "coco_split_first")` when split manifests are detected. |
| **Manifest Discovery** | Assumed single manifest: `instances_*.json`, `annotations/*.json`, or root `*.json`. | Discovers all split manifests across split directories, `annotations/`, and root. Stores as `[(split_name, manifest_path), ...]`. |
| **Image Resolution** | Searched root, `images/`, `train/`, `val/`, `test/`. Missing `valid/` and lacked split-local priority. | Prioritizes `preferred_dir / file_name` (O(1) resolution within the split folder), then checks candidate subdirectories including `valid/`, `images/valid/`, `images/test/`, then safe fallback. |

---

## 4. Supported COCO Layouts After Fix

The CVIF ingestion layer now automatically recognizes, validates, and loads all the following COCO layout variants:

1. **Split-First Multi-Folder Layout** (Roboflow / Ultralytics export standard):
   ```
   dataset_root/
   ├── train/
   │   ├── _annotations.coco.json (or instances.json / annotations.json)
   │   └── *.jpg / *.png
   ├── valid/ (or val/)
   │   ├── _annotations.coco.json
   │   └── *.jpg / *.png
   └── test/
       ├── _annotations.coco.json
       └── *.jpg / *.png
   ```
2. **Standard Multi-Split Annotations Directory**:
   ```
   dataset_root/
   ├── annotations/
   │   ├── instances_train.json
   │   ├── instances_val.json
   │   └── instances_test.json
   └── images/
   ```
3. **Flat Root-Level Single or Multi-Manifest Layouts**:
   ```
   dataset_root/
   ├── instances_train.json
   ├── instances_val.json
   └── *.png
   ```
4. **Explicit Single-File Ingestion**:
   Direct instantiation `COCOAdapter(path, annotation_file=...)` continues to function with 100% backward compatibility.

---

## 5. ID Namespacing Strategy

In multi-split datasets, raw numeric image IDs and annotation IDs frequently restart from `0` in each split JSON manifest.

### Implementation Details:
- When multiple manifests are aggregated (or manifests originate from split directories):
  - **Image ID**: `img_id = f"{split_name}_{raw_img_id}"` (e.g., `train_0`, `valid_0`, `test_0`)
  - **Annotation ID**: `ann_id = f"{split_name}_{raw_ann_id}"` (e.g., `train_0`, `valid_0`, `test_0`)
  - **Annotation Image Reference**: `ann.image_id = f"{split_name}_{raw_img_id}"`
  - **Source Metadata**: `{"original_id": raw_img_id, "split": split_name}` preserved in `ImageRecord.source_metadata`
- For single-manifest flat datasets without split folders, raw IDs remain un-prefixed (`"101"`), maintaining complete backward compatibility with existing tests and datasets.
- **Cryptographic Hashing**: `compute_dataset_hash()` hashes sorted records keyed by `(image_id, class_id, bbox)`. Because `image_id` is deterministically namespaced across splits, no collision occurs and the hash remains cryptographically distinct and deterministic.

---

## 6. Split Handling

`UnifiedDataset.splits` is populated using the canonical CVIF schema:
```python
splits: Dict[str, List[str]] = {
    "train": ["train_0", "train_1", ...],
    "valid": ["valid_0", "valid_1", ...],
    "test": ["test_0", "test_1", ...]
}
```
Passed as `splits=splits or None` to `UnifiedDataset`, aligning identically with `yolo.py`.

---

## 7. Validation Behavior

`COCOAdapter.validate()` validates all discovered manifests and reports aggregated statistics and errors:
- **Mandatory Keys**: Requires `"images"`, `"annotations"`, `"categories"`.
- **Duplicate ID Detection**: Validates namespaced IDs across all splits.
- **Image File Verification**: Each referenced image is verified to exist on disk. Missing images are reported with filename and namespaced ID.
- **Orphan Annotations**: Validates that annotation `image_id` references a valid image in the manifest.
- **Category References**: Validates that annotation `category_id` references a declared category.
- **Bounding Boxes**: Validates 4-number length, `width > 0`, `height > 0`, and warns on negative coordinates.
- **Segmentation Structures**: Validates list or dict polygon/RLE structures.
- **Zero-Match Safety**: If manifests exist but contain zero valid images or annotations, validation fails with an explicit error rather than silently succeeding.

---

## 8. Real Dataset Verification

### Benchmark Dataset:
`C:\Users\Namith Singh\OneDrive\Documents\datasets for sih\coco\COCO Subset.v4-80-15-5-ratio-with-5-classes.coco`

### Results:
| Parameter | Expected | Actual Result | Status |
|---|---|---|---|
| **Format Detected** | `coco` (`coco_split_first`) | `coco` (`coco_split_first`) | **PASS** |
| **Discovered Manifests** | 3 (`train`, `valid`, `test`) | 3 (`train`, `valid`, `test`) | **PASS** |
| **Total Images Loaded** | 100 | 100 | **PASS** |
| **Total Annotations Loaded** | 392 | 392 | **PASS** |
| **Total Categories** | 6 | 6 | **PASS** |
| **Split Breakdown** | train: 80, valid: 15, test: 5 | train: 80, valid: 15, test: 5 | **PASS** |
| **Missing Images** | 0 | 0 | **PASS** |
| **Orphan Annotations** | 0 | 0 | **PASS** |
| **Namespacing** | `train_*`, `valid_*`, `test_*` | Verified for all images & annotations | **PASS** |
| **Dataset Hash** | 64 hex SHA-256 | `24c5f84c0e16a327f805db40a095d1e599bdc2775c3a9f37995e7bc5180c2610` | **PASS** |
| **DT-1 to DT-6 Threat Scan** | `status == COMPLETED` | `status == COMPLETED` (0 exceptions) | **PASS** |
| **Dataset File Mutation** | 0 bytes changed | Verified bit-for-bit unchanged | **PASS** |

---

## 9. Test Counts & Coverage

| Test Suite | Total Tests | Passed | Failed | Skipped |
|---|---|---|---|---|
| `tests/unit/test_ingestion_coco.py` | 16 | 16 | 0 | 0 |
| `tests/unit/test_ingestion_yolo.py` | 12 | 12 | 0 | 0 |
| `tests/unit/test_adversarial_datasets.py` | 6 | 6 | 0 | 0 |
| `tests/unit/test_data_integrity_checks.py` | 6 | 6 | 0 | 0 |
| `tests/unit/test_dataset_identity.py` | 5 | 5 | 0 | 0 |
| `tests/unit/test_ingestion_gateway_and_orchestrator.py` | 2 | 2 | 0 | 0 |
| **Complete Unit Test Battery** | **291** | **291** | **0** | **0** |

---

## 10. YOLO Regression Results

All 12 YOLO ingestion and validation unit tests executed and passed:
- `test_yolo_yaml_standard_ingestion`: PASSED
- `test_yolo_flat_paired_ingestion`: PASSED
- `test_yolo_split_structure`: PASSED
- `test_yolo_missing_label_file_allowed`: PASSED
- `test_yolo_invalid_coordinates`: PASSED
- `test_yolo_unknown_class_id`: PASSED
- `test_yolo_path_traversal_sanitization`: PASSED
- `test_yolo_malformed_text_rows`: PASSED
- `test_yolo_split_first_layout`: PASSED
- `test_yolo_split_first_with_valid_dir`: PASSED
- `test_yolo_real_split_first_dataset`: PASSED
- `test_yolo_real_dataset_threat_scan`: PASSED

**Result**: Zero regression in YOLO ingestion.

---

## 11. Security & Air-Gap Confirmation

- **Air-Gap Compliance**: No network access, HTTP calls, or external APIs introduced.
- **Path Traversal Protection**: All split and image file resolutions pass through `safe_resolve_path(self.root_path, ...)`; attempts to break out of the dataset boundary raise `PathTraversalError` and are rejected as missing images without exposing host files.
- **Dependencies**: No new external dependencies added. Standard library `json`, `pathlib`, `typing`, `uuid` used throughout.

---

## 12. Limitations

- COCO split-first detection looks for standard split names (`train`, `valid`, `val`, `test`). Non-standard split names (e.g., `holdout_fold_1/`) without an `annotations/` directory will not automatically infer split names unless passed explicitly via `annotation_file`.
- Highly malformed JSON files that lack standard top-level COCO keys (`images`, `categories`, `annotations`) are correctly rejected as unsupported.

---

## 13. Exact Final Status

```
COCO SUPPORT FIX VERIFIED
```
