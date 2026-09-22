# Computer Vision Integrity Assurance Framework (CVIF)

**Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines**

- **Customer / Authority**: Ministry of Defence (MoD) / Indian Army (DGIS)
- **Theme**: Blockchain & Cybersecurity
- **Architecture Version**: 1.0.0-PRODUCTION
- **Milestone**: Phase 12/12 — FINAL HARDENING & POLISH (Production Ready)

---

## 1. Executive Summary & Architecture

The **Computer Vision Integrity Assurance Framework (CVIF)** is a defense-grade, air-gapped, model-agnostic assurance system designed to secure computer vision pipelines against adversarial compromise, data poisoning, backdoor injection, inference spoofing, and operational distribution shifts.

CVIF monitors, cryptographically binds, and evaluates assets across four core pillars:

```
[Raw Dataset] ──(1)──> [Dataset Ingestion & Integrity Scan]
                             │
                             ▼ (DT-1 to DT-6 Findings)
[Model Binary] ──(2)──> [Model Safety Scan (Pre-flight)]
                             │
                             ▼ (Pickle/Zip Safe)
                        [Model Integrity Scan (Weights/Backdoor)]
                             │
                             ▼ (MT-1 to MT-4 Findings)
[Inference] ──(3)──> [Inference Provenance Verification (Ed25519)]
                             │
                             ▼ (IT-1 to IT-5 Findings)
[Data Streams] ──(4)──> [Distribution Shift Analysis (MMD, KS, W1)]
                             │
                             ▼ (DS-1 to DS-4 Findings)
[All Findings] ──(5)──> [Assurance Engine (Veto + Noisy-OR + Anti-Dilution)]
                             │
                             ▼ (AssuranceVerdict: ACCEPT / REVIEW / QUARANTINE)
                        [Evidence Store (Immutable Content-Addressed Storage)]
                             │
         ┌───────────────────┴───────────────────┐
         ▼                                       ▼
    [Typer CLI]                             [FastAPI REST API]
         │                                       │
         ▼                                       ▼
  (Exit Codes 0/10/11)                     [React UI Dashboard]
```

### The Four Core Assurance Pillars

1. **Dataset Integrity (DT-1 to DT-6):**
   - Ingestion adapters for standard vision formats (COCO, YOLO).
   - Spatial and frequency-domain trigger detection (DT-1).
   - KNN feature-space label flipping and systematic mislabelling detection (DT-2/DT-3).
   - Out-of-Distribution (OOD) sample insertion detection (DT-4).
   - Perceptual hash (dHash) near-duplicate flooding detection (DT-5).
   - Multi-contributor risk aggregation and anomalous contributor isolation (DT-6).

2. **Model Integrity (MT-1 to MT-4):**
   - Pre-flight static security scanning (ZIP bomb, compression ratio, forbidden pickle opcodes).
   - Disposable isolated subprocess execution with curated system environment allowlist.
   - SHA-256 weight fingerprinting and structural tensor hashing.
   - Neural Cleanse / trigger inversion for backdoor detection (MT-1).
   - Model adapters for PyTorch, ONNX, and TorchScript runtime evaluation.

3. **Inference Provenance & Replay Defense (IT-1 to IT-5):**
   - Asymmetric Ed25519 cryptographic signatures and canonical JSON payload hashing.
   - Anti-replay validation via unique cryptographic nonces and monotonic sequence numbers.
   - Producer identity attestation via local air-gapped `KeyStore`.
   - Continuous stream hash chaining ($H_n = \text{SHA-256}(P_n \mathbin{\Vert} H_{n-1})$).

4. **Distribution Shift Analysis (DS-1 to DS-4):**
   - Unbiased Maximum Mean Discrepancy (MMD) with RBF kernel and median heuristic bandwidth.
   - Wasserstein Distance ($W_1$) 1D step-integral representations.
   - Two-Sample Kolmogorov-Smirnov (KS) test with exact supremum and asymptotic p-values.
   - Total Variation (TV) distance across discrete class priors.
   - Minimum sample gating ($N \ge 15$) preventing false positives on sparse data.

### Foundation & Assurance Engine

- **Weakest-Link Critical Veto:** Any critical-severity finding immediately forces a `QUARANTINE` verdict regardless of other dimension scores.
- **Noisy-OR Dimensional Aggregation:** Independent probability combination across finding vectors.
- **Anti-Dilution Composite Risk:** Composite score cannot be masked by low risk in uncompromised dimensions: $R_{\text{composite}} = \max(\max(r_i), \sum W_d R_d)$.
- **Write-Once Evidence Store:** Content-addressable storage with atomic writes, SHA-256 verification, and bidirectional (DB $\leftrightarrow$ Disk) orphan detection.
- **Tamper-Evident Audit Ledger:** Append-only cryptographic hash chain logging all security events with monotonic sequence numbers.

---

## 2. Directory Structure

```
├── pyproject.toml                     # Project packaging and metadata
├── requirements.lock                  # Pinned, reproducible runtime dependencies
├── README.md                          # Framework documentation
├── config/
│   └── default_config.yaml            # Safe default configuration (air-gapped, localhost)
├── frontend/                          # Air-gapped React 18 UI Dashboard
│   ├── src/                           # TypeScript application components & views
│   ├── dist/                          # Production compiled static assets
│   ├── package.json                   # Zero external runtime dependencies (React, Lucide)
│   └── vite.config.ts                 # Production bundle configuration
├── src/cvif/                          # Core Python package
│   ├── analysis/                      # Integrity analysis algorithms (data, model, shift)
│   ├── api/                           # FastAPI REST API, middleware, and route handlers
│   │   ├── routes/                    # 14 REST endpoints (audit, assess, datasets, etc.)
│   │   ├── error_handler.py           # Exception envelope shielding and correlation
│   │   ├── frontend.py                # Static serving, SPA routing, and CSP headers
│   │   └── main.py                    # Application factory and PayloadSizeLimitMiddleware
│   ├── audit/                         # Tamper-evident hash-chained AuditLogger
│   ├── cli/                           # Typer-based CLI interface and command definitions
│   ├── core/                          # Enums, exceptions, configuration, and Pydantic schemas
│   ├── crypto/                        # Ed25519, SHA-256, HMAC, hash chain, and KeyStore
│   ├── evidence/                      # Content-addressable EvidenceStore & packaging
│   ├── features/                      # Statistical and vision feature extraction
│   ├── ingestion/                     # COCO and YOLO dataset format adapters
│   ├── model/                         # Safety scanner, isolated execution, and adapters
│   ├── provenance/                    # Inference record canonical binding and verification
│   └── storage/                       # SQLite DatabaseManager and SafeFileStore
└── tests/                             # Comprehensive 346-test automated regression suite
    └── unit/                          # Unit and integration test modules
```

---

## 3. Installation & Environment Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.10 to 3.13)
- Node.js 18+ (only required if recompiling the frontend; pre-compiled `frontend/dist/` is bundled)
- 100% air-gapped capable; zero external internet connectivity required at runtime

### Setup Instructions

```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\activate

# 2. Install pinned dependencies
pip install -r requirements.lock

# 3. Install cvif in editable mode
pip install -e . --no-deps
```

---

## 4.Command-Line Interface (CLI)

The `cvif` command provides full programmatic control over all framework capabilities:

```powershell
cvif --help
```

### Primary Commands

| Command | Description |
|---|---|
| `cvif serve` | Start the REST API server and serve the built React UI dashboard simultaneously. |
| `cvif dataset` | Register, validate, and catalog datasets in COCO or YOLO format. |
| `cvif data` | Execute dataset integrity analysis checks (DT-1 to DT-6). |
| `cvif model` | Execute pre-flight model safety scanning and weight analysis (MT-1 to MT-4). |
| `cvif provenance` | Cryptographically verify inference record streams and replay defenses (IT-1 to IT-5). |
| `cvif shift` | Analyze distribution shifts using MMD, Wasserstein, and KS tests (DS-1 to DS-4). |
| `cvif assess` | Synthesize holistic assurance verdicts with Critical Veto and Anti-Dilution scoring. |
| `cvif evidence` | Inspect, verify consistency, and export evidence packages (`.cvif`). |
| `cvif audit` | Verify cryptographic hash chain integrity of the audit ledger. |
| `cvif status` | Print system health, database connectivity, and diagnostic metrics. |
| `cvif version` | Display framework version, schema version, and build info. |

### Shell Completion

Enable tab-completion in your preferred shell:

```powershell
# PowerShell
cvif --install-completion powershell

# Bash / Zsh
cvif --install-completion bash
cvif --install-completion zsh
```

---

## 5. Web Application & UI Dashboard

CVIF includes an air-gapped, zero-CDN React 18 single-page application (SPA) pre-compiled into `frontend/dist/`.

### Starting the Combined Server

Run a single command to launch both the REST API and the UI dashboard:

```powershell
cvif serve --host 127.0.0.1 --port 8000
```

Open your browser and navigate to:
```
http://127.0.0.1:8000
```

### UI Features
- **Holistic Verdict Hero:** Live visual risk dial and disposition badge (`ACCEPT`, `REVIEW`, `QUARANTINE`).
- **Four Pillar Dashboards:** Dedicated interactive views for Dataset, Model, Provenance, and Distribution Shift findings.
- **Evidence Explorer:** Inspect content-addressed evidence records, metrics, and linked visual artifacts.
- **Audit Ledger Viewer:** Real-time tamper-evident event log with monotonic sequence numbers and hash chain verification.
- **Security & Air-Gap Guarantees:** Strict Content Security Policy (CSP), zero external fonts or CDN requests, and tab-isolated session storage.

---

## 6. Verification & Test Suite

CVIF maintains an exhaustive test suite covering unit, integration, and security verification.

### Running Regression Tests

```powershell
python -m pytest tests/ -q
```
**Result:** `346 passed, 0 warnings` (100% pass rate).

### Running Independent Forensic Security Audit

```powershell
python scratch/phase_11_final_forensic_audit.py
```
**Result:** `20 / 20 PASS` (Tests A through T covering SPA routes, CSP headers, path traversal, anti-stub verification, and air-gap confinement).

### Building Frontend (Optional)

```powershell
cd frontend
npm run build
```
**Result:** Clean compilation with TypeScript strict type checking and zero warnings.

---

## 7. Security Hardening Specifications

1. **Strict Air-Gap Confinement:** Zero outbound HTTP/HTTPS calls or DNS queries. Validated via runtime socket interception.
2. **Payload Size Limits:** ASGI middleware enforces configurable request limits (`max_payload_size_mb`, default: 10 MB). Oversized requests are rejected with HTTP 413 and correlated `X-Request-ID`.
3. **Subprocess Isolation:** Model safety scans execute in disposable subprocesses with explicit `PYTHONPATH` resolution and a strict allowlist of system environment variables.
4. **Path Traversal Defense:** Centralized `safe_resolve_path()` prevents directory escape via null bytes, `%2e%2e`, and backslash manipulation.
5. **Bidirectional Store Consistency:** `EvidenceStore.verify_store_consistency()` cross-checks SQLite metadata against physical files in both directions (DB $\to$ Disk and Disk $\to$ DB) to detect untracked or orphaned files.
6. **Error Envelope Shielding:** Production API returns uniform error envelopes (`status="ERROR"`, `error_code`, `request_id`) and suppresses internal Python tracebacks.

---

## 8. Classification & License

- **Classification**: Sensitive / Defence Computer Vision Pipeline Integrity Assurance
- **Target Deployment**: Air-Gapped High-Assurance Enclaves / Tactical Operations Centers
- **Copyright**: Government of India — Ministry of Defence / Indian Army (DGIS)
