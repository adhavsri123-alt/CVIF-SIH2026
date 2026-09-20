# Phase 11/12 — Architecture Audit Report: UI Dashboard

**Document Reference**: `phase_11_architecture_audit.md`  
**Evaluation Role**: Lead Security Architect & System Auditor  
**Evaluation Date**: 2026-09-19  
**Target Subsystem**: Phase 11 UI Dashboard (`frontend/`, `src/cvif/api/`, `cvif serve`)  
**Current Test Suite Baseline**: 323 / 323 passing regression tests (100% pass rate)  
**Phase 10 Forensic Verification**: 35 / 35 forensic security tests passing  
**Status**: ARCHITECTURE AUDIT ONLY — READ-ONLY INSPECTION  

---

## 1. Executive Summary

This document presents the rigorous architectural audit and formal design specification for **Phase 11: UI Dashboard** of the Computer Vision Integrity Assurance Framework (CVIF). The audit was executed strictly in read-only inspection mode with zero production code modifications, zero additions of UI dependencies, and zero alterations to existing test suites.

CVIF is an air-gapped, tamper-evident framework designed for defense and critical surveillance pipelines (MoD / DGIS). Phases 1 through 10 have established verified, mathematically rigorous capabilities across dataset integrity (DT-1..6), model safety and backdoor detection (MT-1..4), inference provenance with Ed25519 signatures, distribution shift testing (DS-1..4), holistic Weakest-Link and Noisy-OR assurance aggregation, immutable SQLite/content-addressed evidence storage, a standardized CLI, and an air-gapped FastAPI REST microservice.

Phase 11 introduces a **local, air-gapped, high-fidelity UI Dashboard** to serve as the unified presentation and operational command center for human analysts, auditors, and leadership juries during Smart India Hackathon (SIH) demonstrations.

### Crucial Architectural Principles for Phase 11:
1. **Strict Presentation Boundary**: The UI Dashboard is purely a client consumer of the Phase 10 REST API. It **must not** duplicate or reimplement core cryptographic verification, threat detection algorithms, distribution shift statistics, or assurance risk aggregation mathematics.
2. **Absolute Air-Gap Integrity**: Zero external content delivery networks (CDNs), remote web fonts, analytics beacons, external CSS/JS scripts, or telemetry trackers. All assets, fonts, icons, and libraries are 100% bundled locally.
3. **Zero Direct Storage Access**: The frontend operates exclusively over HTTP/JSON via the `/api/v1/` endpoints. It has zero direct access to the SQLite catalog database or the filesystem evidence store.
4. **Verbatim Assurance Fidelity**: Dispositions (`ACCEPT`, `REVIEW`, `QUARANTINE`), composite risk scores, dimension risks, and critical vetoes are presented verbatim as emitted by `POST /api/v1/assess`. The UI never applies subjective re-scoring or client-side threshold overrides.
5. **Unified Single-Process Local Deployment**: In production/demo mode, the dashboard is served directly by the existing FastAPI daemon via `cvif serve`, binding to `127.0.0.1:8000` without requiring an active Node.js runtime on the demonstration machine.

---

## 2. Current System Baseline & Repository Verification

A comprehensive repository inspection confirms that all underlying subsystems from Phases 1 through 10 are complete, passing, and structurally sound:

| Subsystem / Phase | Primary Modules | Verified State | Test Coverage |
|---|---|---|---|
| **Phase 1: Schemas & Foundation** | `src/cvif/core/`, `src/cvif/version.py` | Complete & Frozen | 24 tests |
| **Phase 2: Ingestion & Storage** | `src/cvif/ingestion/`, `src/cvif/storage/` | Complete & Frozen | 25 tests |
| **Phase 3: Dataset Integrity** | `src/cvif/analysis/` (DT-1..6) | Complete & Frozen | 23 tests |
| **Phase 4: Model Integrity** | `src/cvif/model/` (MT-1..4) | Complete & Frozen | 37 tests |
| **Phase 5: Inference Provenance**| `src/cvif/provenance/`, `src/cvif/crypto/` | Complete & Frozen | 39 tests |
| **Phase 6: Distribution Shift** | `src/cvif/distribution/` (DS-1..4) | Complete & Frozen | 23 tests |
| **Phase 7: Assurance Aggregation**| `src/cvif/analysis/assurance/` | Complete & Frozen | 33 tests |
| **Phase 8: Evidence & Audit** | `src/cvif/evidence/`, `src/cvif/audit/` | Complete & Frozen | 44 tests |
| **Phase 9: Command-Line Interface**| `src/cvif/cli/` (10 command groups) | Complete & Frozen | 28 tests |
| **Phase 10: REST API** | `src/cvif/api/` (14 endpoints) | Complete & Frozen | 48 tests (+35 forensic) |
| **Total Regression Baseline** | Full test suite across `tests/unit/` | **323 / 323 Passed** | **100% Pass Rate** |

### Verified Subsystem Invariants:
- **Core Exceptions**: All domain exceptions reside in `src/cvif/core/exceptions.py`.
- **Configuration**: Pydantic v2 configuration hierarchy in `src/cvif/core/config.py` includes `APIConfig`, which already supports `host`, `port`, `cors_origins`, `api_key_enabled`, `api_keys`, and `enable_docs`.
- **API Main**: `src/cvif/api/main.py` utilizes the application factory pattern (`create_app`), integrates `RequestIDMiddleware`, centralized error handling, and routes under `/api/v1/`.
- **CLI Serve**: `src/cvif/cli/commands/serve_cmd.py` implements `cvif serve`, binding safely to `127.0.0.1:8000` by default.

---

## 3. Existing API Inventory

The UI Dashboard will interact with the 14 verified Phase 10 endpoints:

| Endpoint | HTTP Method | Auth Required | Purpose in UI Dashboard |
|---|---|---|---|
| `/api/v1/health` | `GET` | No | System health indicator, DB/Ledger connectivity, degraded status banner |
| `/api/v1/version` | `GET` | No | Header badge, schema version, runtime platform, air-gap confirmation |
| `/api/v1/audit/verify` | `POST` | Yes | Audit ledger cryptographic hash-chain verification view |
| `/api/v1/datasets/ingest` | `POST` | Yes | Dataset ingestion workflow (triggering folder ingestion & validation) |
| `/api/v1/datasets/scan` | `POST` | Yes | Dataset integrity threat scan (DT-1..6 execution) |
| `/api/v1/models/scan-safety`| `POST` | Yes | Model safety pre-flight inspection modal |
| `/api/v1/models/scan` | `POST` | Yes | Full model integrity battery (MT-1..4 execution) |
| `/api/v1/provenance/verify` | `POST` | Yes | Multi-contributor inference record & Ed25519 signature verification |
| `/api/v1/shift/analyze` | `POST` | Yes | Distribution shift analysis (DS-1..4 matrix & characterization) |
| `/api/v1/assess` | `POST` | Yes | Holistic session synthesis, Weakest-Link vetoes, composite risk |
| `/api/v1/evidence` | `GET` | Yes | Evidence explorer tabular view with multi-parameter filtering |
| `/api/v1/evidence/{id}` | `GET` | Yes | Detailed evidence record drawer with SHA-256 hash verification |
| `/api/v1/evidence/verify` | `POST` | Yes | Global/session store consistency audit (detects tampered records) |
| `/api/v1/evidence/export` | `POST` | Yes | Trigger creation of tamper-evident `.cvif` ZIP bundle |

---

## 4. UI Technology Decision

### 4.1 Candidate Evaluation

Three primary architectural candidates were evaluated for the local frontend:

| Criteria | Candidate 1: Server-Rendered HTML (Jinja2 + HTMX) | Candidate 2: Python Dashboard (Streamlit / Dash) | Candidate 3: React 18 + Vite SPA (Compiled to Static) |
|---|---|---|---|
| **Air-Gap Compatibility** | High (static HTML templates) | Moderate (often attempts wheel downloads/telemetry) | **Maximum** (compiles to self-contained static JS/CSS/HTML) |
| **SIH Demonstration Impact** | Basic / Monolithic feel; full-page refreshes or partial DOM swaps | Python widget feel; non-standard UX, high latency on state update | **Exceptional**; modern glassmorphism, instant tab transitions, command-center aesthetic |
| **FastAPI Decoupling** | Mixed (tightly couples Jinja2 rendering into API handlers) | Poor (runs as separate heavy Python process on separate port) | **Clean separation** (API remains pure REST JSON; frontend consumes API via standard HTTP) |
| **Client-Side Responsiveness** | Moderate | Poor (WebSocket overhead per widget click) | **High** (instant client-side filtering, sorting, tab switching) |
| **Production Runtime Footprint** | Low (Python only) | High (requires separate Python runtime, Tornado server, high RAM) | **Zero runtime overhead** (FastAPI serves compiled static files via Starlette StaticFiles) |
| **Type Safety & Maintainability** | Low (untyped HTML/JS templates) | Moderate | **High** (TypeScript interfaces matching Pydantic schemas) |
| **Deterministic Testing** | Moderate | Hard to isolate | **High** (Component unit tests + headless integration tests) |

### 4.2 Architecture Selection: Candidate 3 (React + TypeScript + Vite SPA)

**Formal Decision**: The Phase 11 UI Dashboard will be built as a modern **React 18 Single Page Application (SPA)** with **TypeScript** and **Vite**, compiled into a static distribution directory (`frontend/dist/`).

### Rationale:
1. **Zero Production Runtime Overhead**: During deployment and jury demonstrations, Node.js is **not required**. The compiled static assets (`index.html`, `.js`, `.css`) are mounted directly into FastAPI via Starlette's `StaticFiles`. The single command `cvif serve` delivers both the REST API and the complete UI Dashboard on `http://127.0.0.1:8000`.
2. **Strict Clean Separation**: The API remains 100% pure JSON REST. No server-side HTML rendering dependencies are introduced into the core API routers.
3. **Type-Safe Contract Synchronization**: TypeScript definitions will mirror Phase 1/10 Pydantic schemas, eliminating presentation bugs and ensuring strict schema adherence.
4. **Superior Demonstration Experience**: High-fidelity cybersecurity UI (deep slate, dark mode, responsive telemetry cards, animated threat severity badges, clear evidence drawers) provides a winning impression for SIH evaluators.

---

## 5. Air-Gap Architecture & Network Isolation

The CVIF system operates under strict air-gapped defense constraints. The UI must function with zero network access.

```
+-------------------------------------------------------------------------+
|                       AIR-GAPPED BROWSER CLIENT                         |
|                                                                         |
|  +---------------------+  +--------------------+  +------------------+  |
|  |   Local Web Fonts   |  |   SVG Icons        |  |  React Bundle    |  |
|  |   (Inter / System)  |  |   (Lucide-React)   |  |  (Single JS/CSS) |  |
|  +---------------------+  +--------------------+  +------------------+  |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 Content Security Policy (CSP)                     |  |
|  |  default-src 'self'; script-src 'self'; style-src 'self' ...      |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
                                    |
                                    | HTTP (localhost / 127.0.0.1 only)
                                    v
+-------------------------------------------------------------------------+
|                       LOCAL FASTAPI / UVICORN                           |
|                                                                         |
|  Static Asset Mount:                 REST API Endpoints:                |
|  /            -> frontend/dist/      /api/v1/health                     |
|  /assets/*    -> static JS/CSS       /api/v1/assess                     |
|                                      /api/v1/evidence                   |
+-------------------------------------------------------------------------+
```

### 5.1 Defense Invariants
1. **Zero CDN Dependencies**: No `<script src="https://cdn...">` or `<link href="https://fonts...">` tags anywhere in `index.html` or CSS.
2. **Local Typography**: Uses modern system font stacks (`system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`) with fallback to local bundled WOFF2 font files if required.
3. **Bundled Icons**: Icons are bundled directly into the JavaScript chunk at build time via `lucide-react` (pure inline SVGs, zero icon font downloads).
4. **No External Maps or Telemetry**: No Google Maps, Mapbox, Sentry, Google Analytics, or external beacons.
5. **Content Security Policy (CSP)**:
   FastAPI will attach the following strict CSP header to all static frontend responses:
   ```http
   Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' http://127.0.0.1:* http://localhost:*; object-src 'none'; frame-ancestors 'none';
   ```
6. **Runtime Network Verification**: Automated audit tests verify that the frontend build output contains zero external `http://` or `https://` URLs in its compiled HTML/JS/CSS assets.

---

## 6. Information Architecture & Navigation

The dashboard is structured around an intuitive, cybersecurity-first navigation hierarchy designed to guide an auditor through the five integrity pillars of CVIF:

```
+-----------------------------------------------------------------------------------+
| [CVIF Logo]  CVIF Integrity Command Center      [AIR-GAP ACTIVE] [HEALTHY] [v0.1.0] |
+-----------------------------------------------------------------------------------+
| NAVIGATION   | ACTIVE WORKSPACE: Session #f47ac10b...                             |
|              +--------------------------------------------------------------------+
| [=] Overview |                                                                    |
| [D] Datasets |  +--------------------------------------------------------------+  |
| [M] Models   |  |                  ASSURANCE VERDICT BANNER                    |  |
| [P] Provenance| |                  DISPOSITION: QUARANTINE                     |  |
| [S] Shift    |  |  Composite Risk: 0.85 | Critical Vetoes: 1 | Findings: 4     |  |
| [A] Assess   |  +--------------------------------------------------------------+  |
| [E] Evidence |                                                                    |
| [*] Audit    |  +---------------------+  +-----------------+  +----------------+  |
|              |  | Dataset Integrity   |  | Model Integrity |  | Shift Matrix   |  |
|              |  | DT-1: Passed        |  | MT-3: VIOLATION |  | DS-1: Detected |  |
|              |  +---------------------+  +-----------------+  +----------------+  |
+-----------------------------------------------------------------------------------+
```

### Navigation Map:
- **1. Overview / Command Center**: High-level posture, active sessions, latest verdict banner, risk breakdown, quick status.
- **2. Dataset Integrity**: Ingestion gateway trigger, dataset statistics, DT-1..6 threat scanning view, sample issue viewer.
- **3. Model Integrity**: Model safety pre-flight check, MT-1..4 battery runner, neural cleanse backdoor visualization.
- **4. Inference Provenance**: Multi-contributor inference record inspector, Ed25519 signature verification, hash-chain integrity.
- **5. Distribution Shift**: DS-1..4 shift matrix (Covariate, Semantic, Environmental, Adversarial), p-values, distance metrics, drift vs manipulation assessment.
- **6. Assurance Assessment**: Session synthesizer, Weakest-Link Critical Vetoes, Noisy-OR composite risk calculation, contributing findings roll-up.
- **7. Evidence Explorer**: Indexed evidence table, multi-field filtering, detail drawer with cryptographic SHA-256 validation, ZIP export.
- **8. Audit Ledger & System**: SHA-256 monotonic hash-chain verification, database/store connectivity, API key management.

---

## 7. Screen-by-Screen Architectural Design

### Screen A: Overview / Command Center
- **Purpose**: Executive dashboard displaying real-time integrity posture at a glance.
- **Data Source**: `GET /api/v1/health`, `GET /api/v1/version`, `GET /api/v1/evidence` (recent), `POST /api/v1/assess` (cached latest verdict).
- **Key Elements**:
  - Global Header: System status pill (`HEALTHY` / `DEGRADED`), Air-Gap shield badge (`OFFLINE`), Version badge (`v0.1.0`), Session selector.
  - Assurance Hero Banner: Massive prominent verdict card showing disposition (`ACCEPT` / `REVIEW` / `QUARANTINE`) with composite risk gauge.
  - Four Pillar Cards: Summary cards for Data, Model, Provenance, and Shift with check counts and violation badges.
  - Threat Activity Feed: Recent findings emitted across active sessions.
- **User Actions**: Switch active session, trigger one-click re-assessment, jump to detailed pillar screens.

### Screen B: Dataset Integrity (DT-1..6)
- **Purpose**: Manage untrusted data ingestion and visualize data integrity threats.
- **Data Source**: `POST /api/v1/datasets/ingest`, `POST /api/v1/datasets/scan`, `GET /api/v1/evidence?threat_id=DT-*`.
- **Key Elements**:
  - Ingestion Panel: Input server path (`data_dir`), format selector (`auto`, `coco`, `yolo`), contributor organization ID.
  - Ingest Result Card: Image count, annotation count, total bytes, format detected, validation warnings.
  - DT-1..6 Scanner Panel: Trigger scan on ingested dataset.
  - Findings Grid: Interactive cards for DT-1 (Label Inconsistency), DT-2 (Class Imbalance), DT-3 (Distribution Outliers), DT-4 (Near-Duplicates), DT-5 (Annotation Corruption), DT-6 (Steganography/Watermarks).
- **User Actions**: Ingest new dataset, run DT battery, drill down into sample IDs affected.

### Screen C: Model Integrity (MT-1..4)
- **Purpose**: Ensure models are safe before deserialization and detect backdoor triggers or evasion vulnerability.
- **Data Source**: `POST /api/v1/models/scan-safety`, `POST /api/v1/models/scan`.
- **Key Elements**:
  - Pre-Flight Safety Banner: Standalone card displaying `validate_model_file_safety` results (format, file hash, safety status, pickle opcode safety).
  - MT Battery Runner: Inputs for candidate `model_path` and optional `reference_weights`.
  - MT-1..4 Cards:
    - MT-1: Architecture & Structural Safety.
    - MT-2: Model Weight Integrity & Fingerprint verification against golden reference.
    - MT-3: Trojan & Backdoor Detection (Neural Cleanse anomaly index, trigger norm ratio, affected class).
    - MT-4: Adversarial Evasion Robustness (FGSM/PGD evasion vulnerability score).
- **User Actions**: Run pre-flight scan, execute MT battery, inspect anomaly index chart.

### Screen D: Inference Provenance
- **Purpose**: Verify integrity and non-repudiation of distributed inference outputs.
- **Data Source**: `POST /api/v1/provenance/verify`.
- **Key Elements**:
  - Provenance Verifier Card: Form to submit or paste `InferenceRecord` JSON, raw image path, and expected weight digest.
  - Cryptographic Verification Matrix:
    - Ed25519 Signature: `VALID` (green) / `INVALID` (red).
    - Input Image Digest Match: `MATCH` (SHA-256 match confirmed).
    - Model Weight Digest Match: `MATCH` (Confirmed against registered model).
    - Preprocessing Config Digest: `MATCH`.
    - Sequence & Nonce Validation: Replay attack defense verification.
    - Previous Record Hash Link: Hash-chain sequence linkage check.
- **User Actions**: Verify record, toggle raw JSON inspector, export verified record.

### Screen E: Distribution Shift (DS-1..4)
- **Purpose**: Detect operational distribution drift and distinguish benign shift from adversarial manipulation.
- **Data Source**: `POST /api/v1/shift/analyze`.
- **Key Elements**:
  - Analysis Setup: Reference dataset path (`reference_data`) vs. Evaluation dataset path (`evaluation_data`).
  - Shift Dimension Matrix:
    - DS-1: Covariate Shift (Wasserstein distance, p-value, threshold).
    - DS-2: Semantic/Concept Shift (Maximum Mean Discrepancy MMD, p-value).
    - DS-3: Environmental & Sensor Drift (Contrast, brightness, blur shift).
    - DS-4: Adversarial Distribution Manipulation (High-frequency dispersion).
  - Attribution Assessment Card: Comparative likelihood bar: `natural_drift_likelihood` vs. `suspicious_manipulation_likelihood`.
  - Evidence Sufficient Badge: Indicates if sample size was statistically sufficient.
- **User Actions**: Execute shift analysis, filter dimensions by detected status.

### Screen F: Assurance Assessment & Synthesis
- **Purpose**: Authoritative synthesis of session findings into holistic verdict.
- **Data Source**: `POST /api/v1/assess`.
- **Key Elements**:
  - Session Assessment Trigger: Executes `AssuranceOrchestrator.evaluate_session()`.
  - Disposition Hero:
    - `ACCEPT` (Green / Shield Check) — Low composite risk, zero critical vetoes.
    - `REVIEW` (Amber / Alert Triangle) — Moderate risk or warning vetoes requiring human review.
    - `QUARANTINE` (Crimson / Octagon Alert) — Critical veto triggered or composite risk > threshold.
  - Composite Risk Gauge: Numerical score [0.0, 1.0] displayed with risk scale.
  - Critical Veto Alert Box: Prominent warning list if any CRITICAL finding exercised veto power.
  - Unsupported Checks List: Explicitly shows checks that could not be run due to format constraints.
  - Contributing Findings Table: Direct links to all findings that influenced the verdict.
- **User Actions**: Synthesize verdict, export audit summary, inspect contributing evidence.

### Screen G: Evidence Explorer
- **Purpose**: Audit immutable evidence store records with tamper verification.
- **Data Source**: `GET /api/v1/evidence`, `GET /api/v1/evidence/{id}`, `POST /api/v1/evidence/verify`, `POST /api/v1/evidence/export`.
- **Key Elements**:
  - Filter Bar: Session UUID, Finding UUID, Threat ID (`DT-1`, `MT-3`, etc.), Evidence Type (`STATISTICAL`, `ARTIFACT`, etc.).
  - Evidence Table: Record UUID, Type, Content SHA-256 Hash (shortened hex with copy button), Creation Timestamp, Integrity Badge.
  - Detail Drawer: Slides out on row click, displaying full record metadata, linked artifact file paths, and live SHA-256 verification status.
  - Store Consistency Action: "Verify Store Integrity" button. If tampered, displays immediate red alert with corrupt records.
  - Export Session Action: "Export Evidence Package (.cvif)" button.
- **User Actions**: Filter, view detail, trigger store consistency audit, export ZIP package.
- **Strict Constraint**: Zero DELETE, UPDATE, or OVERWRITE buttons exist.

### Screen H: System & Audit Status
- **Purpose**: System diagnostics and audit ledger verification.
- **Data Source**: `GET /api/v1/health`, `GET /api/v1/version`, `POST /api/v1/audit/verify`.
- **Key Elements**:
  - Subsystem Connectivity Cards: Catalog Database (SQLite), Evidence Store directory, Trust Store (KeyStore directory).
  - Audit Ledger Chain Card: Monotonic SHA-256 hash-chain verification status, total events count, verified events count, broken block index (if any).
  - Version & Environment: CVIF version, schema version, architecture revision, Python runtime, OS platform, Air-Gap enforcement confirmation.
  - API Key Settings: Input field for `X-API-Key` (held in memory/sessionStorage).
- **User Actions**: Verify audit ledger, test subsystem connectivity, update session API key.

---

## 8. Assurance Verdict & Findings Presentation

### 8.1 Verbatim Verdict Rendering Contract
The UI Dashboard must never recalculate, scale, or subjectively modify assurance metrics:

```typescript
// Strict UI Representation of Authoritative AssuranceVerdict
interface UIAssuranceVerdict {
  verdict_id: string;
  asset_id: string;
  session_id: string;
  composite_risk_score: number;      // Rendered verbatim as percentage (e.g. 0.85 -> 85%)
  disposition: 'ACCEPT' | 'REVIEW' | 'QUARANTINE'; // Verbatim enum mapping
  contributing_finding_ids: string[];
  summary: string;                   // Verbatim backend narrative
  unsupported_checks: string[];      // Displayed as warning pills
  timestamp: string;
}
```

### 8.2 Visual Representation Rules
- **ACCEPT**: Emerald green (`#10b981`), checkmark shield icon, text label "ACCEPT (Integrity Verified)".
- **REVIEW**: Amber yellow (`#f59e0b`), alert triangle icon, text label "REVIEW (Manual Inspection Required)".
- **QUARANTINE**: Crimson red (`#ef4444`), blocked octagon icon, text label "QUARANTINE (Critical Integrity Failure)".
- **Critical Veto**: If `disposition === 'QUARANTINE'` and any contributing finding has `severity === 'CRITICAL'`, render an explicit red alert banner:  
  `"CRITICAL VETO TRIGGERED: Pipeline halted by Weakest-Link decision logic."`

### 8.3 Findings Taxonomy
Every finding is rendered using standardized domain terms:
- **Severity**: `CRITICAL` (Red), `HIGH` (Orange), `MEDIUM` (Amber), `LOW` (Blue), `INFORMATIONAL` (Slate).
- **Confidence**: Progress bar [0.0–1.0].
- **Threat Tag**: Monospace badge (e.g. `[DT-1]`, `[MT-3]`, `[IT-2]`, `[DS-4]`).
- **Evidence Link**: Clickable link opening the corresponding Evidence Record in Screen G.

---

## 9. Distribution Shift Visualization Architecture

The UI consumes the `DistributionShiftResponse` and renders safe, deterministic metrics without inventing fake charts:

### Visualized Metrics:
1. **Dimension Shift Matrix**:
   - Covariate Shift (DS-1): Distance statistic, p-value, threshold, detection badge.
   - Semantic Shift (DS-2): MMD statistic, p-value, threshold, detection badge.
   - Environmental Drift (DS-3): Metric value, p-value, threshold, detection badge.
   - Adversarial Shift (DS-4): Dispersion metric, p-value, threshold, detection badge.
2. **Attribution Ratio Bar**:
   - Horizontal comparative bar:
     - Left (Blue): `natural_drift_likelihood` (e.g. 35%)
     - Right (Red): `suspicious_manipulation_likelihood` (e.g. 65%)
3. **Statistically Sufficient Flag**:
   - Badge: `EVIDENCE SUFFICIENT` (Green) or `INSUFFICIENT SAMPLE SIZE` (Amber).

All visualizations will be rendered using **pure SVG and Canvas**, eliminating the need for heavy external charting packages that introduce supply-chain or CDN risks.

---

## 10. Evidence Immutability & Cryptographic Explorer

### Write-Once Compliance:
The Evidence Explorer strictly adheres to the Phase 8 write-once architecture:
- **No Mutation**: No edit, delete, rename, or update controls.
- **Verification on Retrieval**: When inspecting an evidence record, the UI passes `verify=true` to `GET /api/v1/evidence/{id}`.
- **Tamper Alerting**: If the backend returns `409 Conflict` (`EvidenceTamperedError`), the UI displays a persistent crimson alert box:
  ```
  [!] INTEGRITY VIOLATION DETECTED
  Evidence Record #a1b2c3d4 has been tampered with or modified on disk!
  Expected SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  Calculated SHA-256: 4f8b9... [MISMATCH]
  ```

---

## 11. Security Model & Authentication

### 11.1 Threat Model for UI Layer

| Threat ID | Threat Description | Architectural Mitigation | Residual Risk |
|---|---|---|---|
| **UI-T1** | Cross-Site Scripting (XSS) via finding descriptions or metadata | React JSX auto-escapes all strings; zero `dangerouslySetInnerHTML`; strict CSP header blocks inline scripts. | Negligible |
| **UI-T2** | API Key Theft from browser persistence | API keys are held strictly in memory (or optionally `sessionStorage` during user session); never written to `localStorage` or cookies. | Minimal (local memory only) |
| **UI-T3** | UI/API State Desynchronization | UI displays exact timestamp of data fetch; manual refresh button on all screens; cache invalidated on mutations. | Low |
| **UI-T4** | Misleading Verdict Rendering | Centralized, pure verdict-rendering component; automated screenshot and DOM unit tests assert strict parity with API response. | Negligible |
| **UI-T5** | Unauthorized Network Egress (Air-Gap Leak) | Zero external URLs in build; strict CSP `connect-src 'self' http://127.0.0.1:*`; offline test gate blocks any outbound socket. | Zero |
| **UI-T6** | Path Traversal / Arbitrary Path Submission | All paths entered in UI are passed to Phase 10 API, which validates via `safe_resolve_path()`. UI never accesses server filesystem. | Zero (handled by backend) |
| **UI-T7** | Supply-Chain Vulnerabilities in Frontend Packages | Pinned dependencies in `package-lock.json`; strictly audited package footprint; zero post-install script dependencies. | Low |

### 11.2 Authentication Mechanics
- If Phase 10 API has `api_key_enabled = false` (default for local air-gapped use), the UI automatically detects this via `/api/v1/health` and omits `X-API-Key`.
- If `api_key_enabled = true`, the UI displays an API Key banner prompting the operator for the key. The key is attached to all subsequent request headers as `X-API-Key: <key>`.
- If an endpoint returns `401 Unauthorized`, the UI clears the invalid key from memory and prompts the user with an explicit authentication failure banner.

---

## 12. Error & Diagnostic UX

Error handling strictly follows the Phase 10 contract, shielding users from raw Python internals while surfacing actionable diagnostics:

| HTTP Status | Triggering Scenario | UI Representation |
|---|---|---|
| **400** | Path traversal, null byte, model safety violation | Warning Modal: Displays sanitized `detail` and `error_type` (e.g., `model_safety_violation`). |
| **401** | Missing or invalid API key | Authentication Drawer: "API Key required or invalid. Please check your credentials." |
| **404** | Session or Evidence record not found | Informational Toast: "Requested record does not exist in catalog." |
| **409** | Evidence or Audit Ledger tampering detected | Critical Alert Banner: "Cryptographic Tampering Detected! Hash chain broken." |
| **422** | Invalid UUID, malformed payload | Form Field Highlights: Displays validation error under affected input. |
| **500** | Unexpected internal server error | Error Card: "An internal server error occurred. Correlate with Request-ID: `<uuid>` in server logs." |
| **Offline** | API daemon not running (`cvif serve` stopped) | Persistent Top Banner: "Unable to connect to CVIF API at `127.0.0.1:8000`. Ensure `cvif serve` is running." |

**Information Leakage Prevention**: The UI will **never** display raw Python stack traces, file line numbers, or internal exception classes. If an error contains a `request_id`, it is displayed prominently to allow the operator to cross-reference server-side logs.

---

## 13. Deployment Architecture

Two distinct operational modes are defined:

```
+---------------------------------------------------------------------------------+
|                       MODE 1: PRODUCTION / SIH DEMO MODE                        |
|                                                                                 |
|   Command: `cvif serve`                                                         |
|                                                                                 |
|   +-------------------------------------------------------------------------+   |
|   |                         FASTAPI (Port 8000)                             |   |
|   |                                                                         |   |
|   |  Routes:                                                                |   |
|   |  /api/v1/*        -> JSON REST API Endpoints                            |   |
|   |  /                -> Serves frontend/dist/index.html (SPA Fallback)     |   |
|   |  /assets/*        -> Serves frontend/dist/assets/* (Static JS/CSS)      |   |
|   +-------------------------------------------------------------------------+   |
|                                        ^                                        |
|                                        | Browser accesses http://127.0.0.1:8000  |
|                                        v                                        |
|                          [ Local Web Browser ]                                  |
+---------------------------------------------------------------------------------+

+---------------------------------------------------------------------------------+
|                       MODE 2: FRONTEND DEVELOPMENT MODE                         |
|                                                                                 |
|   Backend Terminal: `cvif serve --reload` (Port 8000)                           |
|   Frontend Terminal: `npm run dev` (Vite Dev Server on Port 5173)              |
|                                                                                 |
|   Vite config proxies `/api` requests to `http://127.0.0.1:8000`               |
|   CORS enabled via `api.cors_origins = ["http://127.0.0.1:5173"]`              |
+---------------------------------------------------------------------------------+
```

### Static Mounting in FastAPI:
In production mode, FastAPI mounts the compiled frontend directory:
```python
# In src/cvif/api/main.py (Phase 11 update):
dist_dir = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist"
if dist_dir.is_dir():
    app.mount("/", StaticFiles(directory=dist_dir, html=True), name="frontend")
```
If a route is refreshed (e.g. `/datasets`), Starlette's `html=True` automatically resolves to `index.html`, allowing client-side React Router to resume state smoothly.

---

## 14. Frontend Project Structure

The frontend application will reside in a dedicated `frontend/` directory at the project root:

```
frontend/
├── index.html                   # HTML entrypoint (zero external CDN tags)
├── package.json                 # Pinned dependencies & scripts
├── package-lock.json            # Deterministic lockfile
├── tsconfig.json                # Strict TypeScript configuration
├── tsconfig.node.json
├── vite.config.ts               # Vite build configuration with proxy
└── src/
    ├── main.tsx                 # Application entrypoint
    ├── App.tsx                  # Master layout, navigation, and router
    ├── index.css                # Global styles, Tailwind/CSS variables, dark theme
    ├── api/                     # Type-safe API client layer
    │   ├── client.ts            # Fetch wrapper with Request-ID & API-key injection
    │   ├── endpoints.ts         # All 14 API endpoint calls
    │   └── types.ts             # TypeScript definitions matching Pydantic schemas
    ├── components/              # Reusable UI components
    │   ├── layout/              # Header, Sidebar, StatusPill, Navigation
    │   ├── common/              # Button, Card, Modal, Drawer, Table, Badge, Spinner
    │   ├── assurance/           # VerdictBanner, RiskGauge, VetoAlert
    │   ├── findings/            # FindingCard, SeverityBadge, ThreatTag
    │   ├── shift/               # ShiftMatrix, LikelihoodBar, DimensionChart
    │   └── evidence/            # EvidenceTable, HashViewer, TamperAlert
    ├── context/                 # Lightweight state management
    │   ├── SessionContext.tsx   # Active session state & selector
    │   └── AuthContext.tsx      # API key state
    └── pages/                   # Dedicated screen views
        ├── OverviewPage.tsx     # Screen A
        ├── DatasetsPage.tsx     # Screen B
        ├── ModelsPage.tsx       # Screen C
        ├── ProvenancePage.tsx   # Screen D
        ├── ShiftPage.tsx        # Screen E
        ├── AssessPage.tsx       # Screen F
        ├── EvidencePage.tsx     # Screen G
        └── AuditPage.tsx        # Screen H
```

---

## 15. Proposed Dependency Boundary

### 15.1 Python Runtime Dependencies
**Zero new Python production dependencies required!**  
Phase 10 already introduced and locked:
- `fastapi==0.115.8`
- `starlette==0.45.3` (provides `StaticFiles`)
- `uvicorn==0.34.0`

`pyproject.toml` and `requirements.lock` require no new external packages for Phase 11 production execution.

### 15.2 Frontend Build Dependencies (`frontend/package.json`)
All frontend dependencies will be pinned in a dedicated `frontend/package.json`:

```json
{
  "name": "cvif-dashboard",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "test": "vitest run"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "lucide-react": "^0.468.0"
  },
  "devDependencies": {
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.4",
    "typescript": "^5.6.3",
    "vite": "^6.0.1",
    "vitest": "^2.1.8"
  }
}
```
*Note: External charting libraries are intentionally excluded. Native SVG/Canvas components will be used for lightweight, 100% deterministic, offline-safe charts.*

---

## 16. Comprehensive Testing Strategy

Phase 11 verification requires a dual-boundary test architecture:

```
+---------------------------------------------------------------------------------+
|                            PHASE 11 TEST SUITE                                  |
+---------------------------------------------------------------------------------+
|                                                                                 |
|  1. Python Backend Integration Tests (`tests/unit/test_ui_serving.py`):         |
|     - TestStaticMount: Asserts / mounts and returns 200 with index.html         |
|     - TestSPAFallback: Asserts /datasets, /models resolve to index.html         |
|     - TestCSPHeaders: Asserts Content-Security-Policy header presence           |
|     - TestAirGapCompliance: Regex audit on dist/ ensuring ZERO external CDNs    |
|     - TestNoDirectStorageAccess: Confirms UI routes cannot access SQLite directly|
|     - TestAPIBoundary: Confirms /api/v1/* routes continue to work unaltered     |
|                                                                                 |
|  2. Frontend Component & Fidelity Tests (`frontend/src/**/*.test.tsx`):        |
|     - TestVerdictParity: Verifies displayed text/color matches API response     |
|     - TestCriticalVetoDisplay: Asserts prominent red alert on veto condition     |
|     - TestEvidenceImmutability: Asserts absence of delete/update DOM elements   |
|     - TestTamperRendering: Asserts crimson tamper warning on 409 status         |
|     - TestXSSSanitization: Asserts finding descriptions render safely           |
|     - TestAPIKeyInjection: Asserts X-API-Key header sent on authenticated calls  |
+---------------------------------------------------------------------------------+
```

### Anti-Stub / Anti-Mock Test Specification:
To guarantee that the UI never displays fake, simulated, or hardcoded security data:
1. `test_ui_displays_verbatim_api_verdict`: Mock API returns `{ "disposition": "REVIEW", "composite_risk_score": 0.42 }` -> Assert DOM contains `"REVIEW"` and `"42%"`, and does NOT contain `"ACCEPT"` or `"QUARANTINE"`.
2. `test_ui_displays_live_findings_count`: Mock API returns 3 findings -> Assert finding table displays exactly 3 rows.
3. `test_no_random_chart_data`: Assert chart rendering functions take pure props derived from `ShiftReport` or `AssuranceVerdict` with zero `Math.random()` invocations.

---

## 17. Phase Boundary & Non-Goals

### Included in Phase 11:
- Development of the React/TypeScript frontend inside `frontend/`.
- Pre-compiling static assets into `frontend/dist/`.
- Mounting `StaticFiles` in `src/cvif/api/main.py` to serve the SPA.
- Adding CSP headers to static responses.
- Implementation of frontend unit tests and Python UI-serving tests.
- UI operator and demonstration documentation.

### Explicitly Excluded from Phase 11:
- **NO modifications** to Phase 1–8 core algorithms, threat detection logic, or risk scoring math.
- **NO modifications** to Phase 10 REST API endpoint contracts.
- **NO Docker or containerization** (strictly deferred to Phase 12).
- **NO remote deployments** or public cloud integrations.
- **NO new mandatory Python dependencies**.

---

## 18. Phase 12 Handoff & Known Non-Blocking Items

The following known non-blocking items are cataloged for Phase 12 (Hardening & Containerization):
1. **Starlette HTTP 422 Deprecation**: Update `HTTP_422_UNPROCESSABLE_ENTITY` to `HTTP_422_UNPROCESSABLE_CONTENT` under Python 3.13.
2. **Phase 6 Statistical Polish**: MMD zero-variance heuristic, environmental metric aggregation, pooled Wasserstein variance ranking.
3. **Phase 8 Storage Polish**: Bidirectional orphan scanning and optional content-addressable deduplication.
4. **Phase 9 CLI Polish**: Explicit `PYTHONPATH` propagation in isolated subprocess model safety checks; optional shell auto-completion documentation.
5. **Phase 10 API Polish**: Request body size limit ASGI middleware; in-memory token bucket rate limiting.
6. **Phase 12 Multi-Stage Containerization**: Multi-stage Dockerfile compiling React with Node.js in stage 1, copying `frontend/dist` to minimal Python 3.13 distroless container in stage 2.

---

## 19. Open Architectural Questions for Owner Review

1. **Static Files Directory Location**:  
   - *Option A (Recommended)*: Keep `frontend/` as a sibling directory at the workspace root, compiling into `frontend/dist/`, which FastAPI mounts.  
   - *Option B*: Store compiled assets directly inside Python package `src/cvif/api/static/`.  
   *Auditor Recommendation*: **Option A** preserves clean separation between Python source code and frontend source code, while `pyproject.toml` can package `frontend/dist` as package data if needed.
2. **Local Font Bundling vs. System Fonts**:  
   - *Option A (Recommended)*: Use modern CSS system font stack (`system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`).  
   - *Option B*: Bundle local WOFF2 files for "Inter" font inside `frontend/src/assets/fonts/`.  
   *Auditor Recommendation*: **Option A** requires zero font binary files, renders instantaneously, matches native OS aesthetics, and guarantees 100% offline air-gap compliance.
3. **Default Route Behavior**:  
   - When the user visits `http://127.0.0.1:8000/`, should it directly open the UI Dashboard?  
   *Auditor Recommendation*: **Yes**. Mounting the SPA at `/` ensures that opening `http://127.0.0.1:8000` immediately opens the command center during demonstrations, while all API endpoints remain clean under `/api/v1/`.

---

## 20. Final Architecture Decision

The architecture for Phase 11 (UI Dashboard) is complete, comprehensive, air-gap safe, deterministic, and rigorously bounded. It fulfills all technical, security, and presentation requirements without compromising the underlying framework.

**FINAL DECISION**:  
### PHASE 11 READY FOR IMPLEMENTATION — AWAITING OWNER REVIEW
