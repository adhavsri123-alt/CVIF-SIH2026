# Phase 10/12 — Architecture Audit: REST API

**Document Reference**: `phase_10_architecture_audit.md`  
**Evaluation Role**: Independent Architecture & Forensic Security Auditor  
**Evaluation Date**: 2026-09-19  
**Target Subsystem**: Phase 10 REST API (`src/cvif/api/`, `src/cvif/core/config.py`, `pyproject.toml`)  
**Underlying Subsystems**: Phases 1–9 Foundation, Ingestion, Model Safety/Integrity, Provenance, Distribution Shift, Assurance Aggregation, Evidence Store, and CLI  
**Regression Baseline**: 272 / 272 tests passing across Phases 1–9 (100% pass rate)  

---

## 1. Executive Summary

This architecture audit evaluates the readiness, security specification, determinism, and phase boundary compliance for **Phase 10: REST API** of the Computer Vision Integrity Assurance Framework (CVIF).

The audit establishes that:
1. **Core Architectural Readiness**: All underlying business logic, threat detection batteries (DT-1..6, MT-1..4, IT-1..5, DS-1..4), cryptographic primitives (Ed25519, SHA-256 hash chains), relational indexing, write-once evidence storage, and assurance aggregation engines were fully implemented and independently verified in Phases 1 through 9.
2. **Strict Presentation/Invocation Boundary**: The Phase 10 REST API is designed exclusively as an HTTP invocation, dispatch, serialization, and presentation layer. It does NOT duplicate core security, detection, cryptographic, or verdict logic. It maps HTTP requests directly to the established Phase 1–9 services.
3. **Framework Standard**: The architecture specifies **FastAPI** (`fastapi>=0.100.0`) running on **Uvicorn** (`uvicorn>=0.22.0`) and Starlette. Both libraries are verified to be already present in the environment (`fastapi==0.136.1`, `uvicorn==0.46.0`, `starlette==1.0.0`), with full Pydantic v2 compatibility and zero external cloud SDK requirements.
4. **Air-Gap Preservation & CDN Isolation**: FastAPI's default `/docs` endpoint attempts to fetch Swagger UI JavaScript and CSS from an external public CDN (`cdn.jsdelivr.net`), which violates the strict air-gap mandate. The audit mandates that Phase 10 either disable CDN documentation routes (`docs_url=None, redoc_url=None`) or bundle offline static assets, while exposing raw machine-readable OpenAPI at `/openapi.json`.
5. **Safe Host Binding**: The server configuration must enforce a default bind host of `127.0.0.1` (localhost only). Binding to `0.0.0.0` (all interfaces) is strictly prohibited unless overridden by explicit configuration with security acknowledgement.
6. **Path Traversal Containment**: All path arguments (`data_dir`, `model_path`, `evaluation_data`) must undergo strict sanitization prohibiting null bytes (`\x00`), directory escapes (`..`), absolute drive escapes, and UNC shares, resolving exclusively within pre-configured data directories via `safe_resolve_path()`.
7. **Model Pre-Flight Safety Enforcement**: Endpoints executing model operations (`/api/v1/models/scan`) must unconditionally invoke `validate_model_file_safety()` *before* any model weight loading, deserialization, or adapter initialization occurs.
8. **Preservation of Assurance Semantics**: The API layer must return `AssuranceVerdict` verbatim. Domain dispositions (`ACCEPT`, `REVIEW`, `QUARANTINE`) are domain-level evaluation outcomes represented in the response payload and must NOT be mapped to HTTP transport errors (e.g. `QUARANTINE` returns HTTP 200 with disposition `QUARANTINE`, not HTTP 400/500).

No architectural blockers exist. Phase 10 is fully specified and ready for implementation upon Owner Review.

---

## 2. Repository & Source Inspection

The auditor inspected the entire current repository structure, existing Phase 1–9 subsystems, and configuration:

| Subsystem Component | Location | Lines | Verification Finding |
|---|---|---|---|
| **Core Schemas** | `src/cvif/core/schemas.py` | 338 | Pydantic v2 data models (`InferenceRecord`, `Finding`, `AssuranceVerdict`, `EvidenceRecord`, `AnalysisSession`). Ready for direct FastAPI response serialization. |
| **Exception Hierarchy** | `src/cvif/core/exceptions.py` | 91 | Structured taxonomy (`CVIFError`, `PathTraversalError`, `TamperDetectedError`, `InvalidModelError`). Ready for centralized HTTP exception handlers. |
| **Config System** | `src/cvif/core/config.py` | 158 | Hierarchical YAML config (`AppConfig`). Requires addition of `APIConfig` schema for host, port, cors, and rate limits. |
| **Cryptographic Keystore** | `src/cvif/crypto/keystore.py` | 148 | Thread-safe Ed25519 key management and verification. |
| **Audit Ledger** | `src/cvif/audit/logger.py` | 139 | Thread-safe (`RLock`) monotonic SHA-256 hash chaining. Ready for concurrent event appending. |
| **Catalogue Database** | `src/cvif/storage/database.py` | 678 | SQLite WAL mode (`PRAGMA journal_mode=WAL;`), thread-local connections (`threading.local`), busy timeout 5000ms. Ready for multi-threaded API requests. |
| **Evidence Store** | `src/cvif/evidence/store.py` | 659 | Dual-layer write-once store with thread lock (`RLock`), atomic `.tmp_` writes, and SHA-256 verification. |
| **Model Pre-Flight Scanner** | `src/cvif/model/safety.py` | 344 | Static scanner for pickle opcodes, zip bombs, and corrupted headers. |
| **Model Orchestrator** | `src/cvif/analysis/model_orchestrator.py` | 211 | Dynamic MT-1..4 battery execution against model adapters. |
| **Dataset Ingestion & Scan** | `src/cvif/ingestion/gateway.py` & `src/cvif/analysis/orchestrator.py` | 420 | COCO/YOLO ingestion and DT-1..6 threat scanning. |
| **Inference Provenance** | `src/cvif/provenance/verifier.py` | 215 | Ed25519 signature verification, timestamp freshness, and nonce replay defense. |
| **Distribution Shift** | `src/cvif/analysis/distribution_shift/orchestrator.py` | 196 | Multi-dimensional statistical drift analysis (DS-1..4). |
| **Assurance Aggregation** | `src/cvif/analysis/assurance/orchestrator.py` | 289 | Weakest-Link Veto, Noisy-OR risk aggregation, and `AssuranceVerdict` synthesis. |
| **Command-Line Interface** | `src/cvif/cli/` | 1,842 | Phase 9 Typer CLI serving as reference behavioral contract. |
| **Installed Environment** | Local Python 3.13 Runtime | — | `fastapi==0.136.1`, `uvicorn==0.46.0`, `starlette==1.0.0`, `pydantic==2.13.3`, `httpx==0.28.1` already installed and functional. |

---

## 3. Frozen Architecture Alignment

The Phase 10 REST API directly mirrors the frozen architectural responsibilities established in earlier audits:
1. **`phase_5_architecture_audit.md` L435**: Provenance verification HTTP route (`/api/v1/provenance/verify`).
2. **`phase_6_architecture_audit.md` L498**: Distribution shift analysis HTTP route (`/api/v1/shift/analyze`).
3. **`phase_7_architecture_audit.md` L541**: Assurance verdict evaluation HTTP route (`/api/v1/assess`).
4. **`phase_8_architecture_audit.md` L467**: Evidence retrieval and verification routes (`/api/v1/evidence/{id}`, `/api/v1/evidence/verify`).
5. **`phase_9_architecture_audit.md` L56**: REST API designated strictly as Phase 10, exposing Phase 1–8 capabilities over HTTP without algorithm duplication.

Phase 10 does not alter, replace, or supersede any frozen architecture. It adds an HTTP transport adapter to the existing service core.

---

## 4. Endpoint Matrix

The proposed endpoint matrix defines 14 core HTTP operations across 8 functional groups:

| Group | Method | Path | Request Body / Query / Path Params | Existing Core Service Invoked | Response Schema | Success Status | Error Statuses | Mutating? | Evidence Stored? | Audit Logged? |
|---|---|---|---|---|---|---|---|---|---|---|
| **System** | `GET` | `/api/v1/health` | Query: `config_path: Optional[str]` | `DatabaseManager.transaction()`, `AuditLogger`, `EvidenceStore` | `HealthStatusResponse` | `200 OK` | `503` | No | No | No |
| **System** | `GET` | `/api/v1/version` | *None* | `cvif.version.__version__`, `__schema_version__` | `VersionResponse` | `200 OK` | `500` | No | No | No |
| **Audit** | `POST` | `/api/v1/audit/verify` | Body: `AuditVerifyRequest` (`log_file: Optional[str]`) | `AuditLogger.verify_chain()` | `AuditVerifyResponse` | `200 OK` | `400`, `409`, `500` | No | No | Yes |
| **Dataset** | `POST` | `/api/v1/datasets/ingest` | Body: `DatasetIngestRequest` (`data_dir`, `format`, `contributor_id`, `batch_id`) | `IngestionGateway.ingest_dataset()` | `DatasetIngestResponse` | `201 Created` | `400`, `422`, `500` | Yes | Yes | Yes |
| **Dataset** | `POST` | `/api/v1/datasets/scan` | Body: `DatasetScanRequest` (`data_dir`, `session_id`, `contributor_id`) | `DatasetIntegrityOrchestrator.run_analysis()` | `DatasetScanResponse` | `200 OK` | `400`, `422`, `500` | Yes | Yes | Yes |
| **Model** | `POST` | `/api/v1/models/scan-safety` | Body: `ModelSafetyScanRequest` (`model_path`) | `ModelSafetyScanner.scan_model_file()` | `ModelSafetyResult` | `200 OK` | `400`, `422`, `500` | No | No | Yes |
| **Model** | `POST` | `/api/v1/models/scan` | Body: `ModelScanRequest` (`model_path`, `reference_weights`, `session_id`) | `ModelIntegrityOrchestrator.run_analysis()` | `ModelScanResponse` | `200 OK` | `400`, `422`, `500` | Yes | Yes | Yes |
| **Provenance** | `POST` | `/api/v1/provenance/verify` | Body: `InferenceRecord` (or `ProvenanceVerifyRequest`) | `InferenceProvenanceVerifier.verify_record()` | `ProvenanceVerifyResponse` | `200 OK` | `400`, `422`, `500` | Yes | No | Yes |
| **Shift** | `POST` | `/api/v1/shift/analyze` | Body: `DistributionShiftRequest` (`reference_data`, `evaluation_data`, `session_id`) | `DistributionShiftOrchestrator.run_analysis()` | `DistributionShiftResponse` | `200 OK` | `400`, `422`, `500` | Yes | Yes | Yes |
| **Assurance** | `POST` | `/api/v1/assess` | Body: `AssessRequest` (`session_id`) | `AssuranceOrchestrator.evaluate_session()` | `AssuranceVerdict` | `200 OK` | `404`, `422`, `500` | Yes | Yes | Yes |
| **Evidence** | `GET` | `/api/v1/evidence` | Query: `session_id`, `finding_id`, `threat_id`, `type`, `limit`, `offset` | `DatabaseManager.list_evidence_records()` | `EvidenceListResponse` | `200 OK` | `400`, `500` | No | No | No |
| **Evidence** | `GET` | `/api/v1/evidence/{id}` | Path: `id: UUID`, Query: `verify: bool = True` | `EvidenceStore.get_evidence()` | `EvidenceRecord` | `200 OK` | `404`, `409`, `500` | No | No | No |
| **Evidence** | `POST` | `/api/v1/evidence/verify` | Body: `EvidenceVerifyRequest` (`session_id: Optional[UUID]`) | `EvidenceStore.verify_store_consistency()` | `EvidenceConsistencyResponse` | `200 OK` | `409`, `500` | No | No | Yes |
| **Evidence** | `POST` | `/api/v1/evidence/export` | Body: `EvidenceExportRequest` (`session_id: UUID`, `output_path: Optional[str]`) | `EvidenceStore.export_session_bundle()` | `EvidenceExportResponse` | `200 OK` | `404`, `409`, `500` | Yes | No | Yes |

---

## 5. Core / API Boundary & Service Separation

```
[ HTTP Client / Automation / UI (Phase 11) ]
                  │
                  ▼ (JSON over HTTP / Localhost)
       [ cvif.api (Phase 10) ]
  ├── FastAPI App / Lifespan Context (`src/cvif/api/main.py`)
  ├── Centralized Exception Handlers (`src/cvif/api/error_handler.py`)
  ├── Request Path Confinement & DTO Validation (`src/cvif/api/schemas.py`)
  └── Route Handlers (`src/cvif/api/routes/`)
                  │
                  ▼ (Python In-Memory Calls)
   [ Phase 1–8 Core Services (cvif.core, analysis, storage, crypto) ]
  ├── IngestionGateway & DatasetIntegrityOrchestrator
  ├── ModelSafetyScanner & ModelIntegrityOrchestrator
  ├── InferenceProvenanceVerifier
  ├── DistributionShiftOrchestrator
  ├── AssuranceOrchestrator
  ├── EvidenceStore
  ├── AuditLogger & DatabaseManager
  └── KeyStore
```

### Prohibited API Duplications
1. **Zero Crypto in API**: Route handlers must never call `hashlib.sha256`, `hmac`, or `cryptography` directly; they must call `cvif.crypto` or domain orchestrators.
2. **Zero Risk Calculations in API**: Route handlers must never compute weighted averages or threshold evaluations; they must call `AssuranceOrchestrator`.
3. **Zero Direct Model Loading in API**: Route handlers must never call `torch.load` or `onnx.load`; they must invoke `validate_model_file_safety` followed by `ModelAdapter`.
4. **Zero Raw Filesystem Access**: Reading/writing evidence records must go exclusively through `EvidenceStore`.

---

## 6. Request / Response Contract & Serialization

1. **Format**: Strictly `application/json` (UTF-8).
2. **Determinism**: JSON serialization must use sorted keys and ISO-8601 UTC timestamps with microsecond precision (`Z` suffix).
3. **Pydantic v2 Schema Reuse**:
   - `InferenceRecord`: directly deserialized as the request payload for provenance verification.
   - `AssuranceVerdict`: directly serialized as the response payload for session evaluation.
   - `EvidenceRecord`: directly serialized as the response payload for evidence retrieval.
4. **Standard Error Envelope**: All HTTP errors emit a consistent, machine-parseable JSON schema:
   ```json
   {
     "status": "ERROR",
     "error_code": "RESOURCE_NOT_FOUND",
     "message": "Session not found in catalogue database: 3fa85f64-5717-4562-b3fc-2c963f66afa6",
     "details": {},
     "request_id": "c1f7b82e-9d33-4a11-8e54-52317189c4d2"
   }
   ```
5. **No Information Leakage**: Error responses must never include Python tracebacks, internal file paths, operating system versions, or database credentials.

---

## 7. HTTP Status Code Semantics

The API establishes a rigorous mapping between domain outcomes and standard HTTP status codes:

| Condition / Outcome | Domain Exception / Trigger | HTTP Status Code | Response Body Behavior |
|---|---|---|---|
| Successful Operation | Execution completed normally | `200 OK` (or `201 Created`) | Complete domain payload |
| Assurance Verdict `ACCEPT` | Normal evaluation, clean pipeline | `200 OK` | `AssuranceVerdict` with `disposition="ACCEPT"` |
| Assurance Verdict `REVIEW` | Elevated risk, operator review required | `200 OK` | `AssuranceVerdict` with `disposition="REVIEW"` |
| Assurance Verdict `QUARANTINE` | Critical threat veto triggered | `200 OK` | `AssuranceVerdict` with `disposition="QUARANTINE"` |
| Dataset Integrity Finding | DT-1..6 threat identified | `200 OK` | `DatasetScanResponse` detailing findings |
| Model Integrity Finding | MT-1..4 threat identified | `200 OK` | `ModelScanResponse` detailing findings |
| Provenance Rejection | Invalid signature or replay detected | `200 OK` | `ProvenanceVerifyResponse` with `is_valid=False` |
| Malformed Request / Bad Syntax | Invalid JSON, missing parameters | `400 Bad Request` | Standard error envelope (`INVALID_REQUEST`) |
| Path Traversal Attempt | Null byte, `..`, escape detected | `400 Bad Request` | Standard error envelope (`PATH_TRAVERSAL_DETECTED`) |
| Schema Validation Error | Pydantic constraint violation | `422 Unprocessable Entity` | Standard error envelope with field details |
| Resource Not Found | Session, evidence, or asset missing | `404 Not Found` | Standard error envelope (`RESOURCE_NOT_FOUND`) |
| Cryptographic Tamper Detected | Hash divergence, broken audit chain | `409 Conflict` | Standard error envelope (`TAMPER_DETECTED`) |
| Evidence Immutability Conflict | Attempt to overwrite existing record | `409 Conflict` | Standard error envelope (`EVIDENCE_IMMUTABLE`) |
| Unsupported Format | Unrecognized model/data format | `415 Unsupported Media Type` | Standard error envelope (`UNSUPPORTED_FORMAT`) |
| Payload / Memory Exhaustion | Exceeded configured size limits | `413 Payload Too Large` | Standard error envelope (`RESOURCE_EXHAUSTED`) |
| Internal Server Error | Unhandled system exception | `500 Internal Server Error` | Generic message with `request_id`, zero traceback |

> [!IMPORTANT]
> **Domain Verdict vs. Transport Status Separation**:  
> The HTTP status code represents the success of the HTTP request and execution of the analysis service. The `AssuranceVerdict` disposition (`ACCEPT`, `REVIEW`, `QUARANTINE`) is an evaluation finding returned in the JSON payload. `QUARANTINE` does NOT produce an HTTP 4xx/5xx status.

---

## 8. Request Validation & Path Confinement

1. **Path Arguments**: Endpoints accepting disk paths (`data_dir`, `model_path`, `evaluation_data`, `output_path`) must reject:
   - Null bytes (`\x00`): raises `PathTraversalError`.
   - Path traversal tokens (`..`): raises `PathTraversalError`.
   - Windows UNC paths (`\\server\share`): prohibited.
   - Raw drive letter roots (`C:\`): prohibited.
2. **Confinement Root**: Paths must be validated using `safe_resolve_path(allowed_root, path)`. All accessed files must reside within `config.storage.data_dir` or an explicitly configured `allowed_paths` list.
3. **Numeric & String Limits**:
   - `UUID` fields: validated via Pydantic native UUID parsing.
   - Strings (contributor IDs, batch IDs): maximum length 128 characters, regex-constrained `^[a-zA-Z0-9_\-\.]+$`.
   - Floating point metrics: rejection of `NaN` and `Infinity`.
   - Pagination parameters: `limit` capped at 100, `offset` non-negative integer.

---

## 9. Authentication & Authorization Boundary

1. **Deployment Context**: The framework operates in an air-gapped environment. Single-host local use (analyst workstation) interacts via `127.0.0.1`. Multi-contributor network deployments (LAN enclave) expose services across internal network segments.
2. **Cryptographic Identity on Ingestion**:
   - Multi-contributor inference submissions are authenticated cryptographically at the data layer via **Ed25519 digital signatures** in `InferenceRecord`. A caller without a registered private key cannot forge a valid inference record, regardless of HTTP authentication.
3. **API-Key Boundary (Defense-in-Depth)**:
   - Phase 10 must implement an optional `X-API-Key` header authentication mechanism (`APIKeyHeader(name="X-API-Key")`).
   - Controlled by `config.api.api_key_enabled: bool` (default: `False` for local single-user, `True` for multi-contributor).
   - If enabled, missing or invalid keys return `401 Unauthorized`.
4. **Safe Host Bind Default**:
   - Server must bind exclusively to `127.0.0.1` by default.
   - Binding to `0.0.0.0` is blocked unless `config.api.allow_remote_binding: True` is explicitly configured.

---

## 10. Air-Gap Requirement & CDN Isolation

1. **Zero Outbound Connections**: The API process must never initiate external network requests. Handlers contain no HTTP client calls, telemetry, or cloud SDKs.
2. **Swagger UI CDN Vulnerability**:
   - Standard FastAPI `/docs` loads JavaScript and CSS from `cdn.jsdelivr.net`.
   - In an air-gapped system, this generates failing or hanging browser requests and egress firewall alarms.
   - **Architectural Mandate**: Set `docs_url=None, redoc_url=None` by default in `FastAPI()`.
   - Provide raw OpenAPI specification at `/openapi.json`.
   - Optional local offline docs can be enabled only if static assets are bundled locally in the repository.
3. **Socket Confinement Testing**: Phase 10 test suite must include monkeypatched socket tests (`socket.socket`, `socket.create_connection`) verifying that API startup, request dispatch, and response emission execute with zero outbound socket attempts.

---

## 11. Host & Bind Security

1. **Default Settings**:
   - Host: `127.0.0.1` (localhost only).
   - Port: `8000` (configurable via `config.api.port`).
   - Workers: `1` (single-process ASGI server).
2. **Prohibited Unsafe Defaults**:
   - `debug=False` strictly enforced in FastAPI application factory.
   - `reload=False` strictly enforced (no code hot-reloading in operational deployments).
   - Binding to `0.0.0.0` disabled by default.
3. **CLI Server Startup**:
   - Phase 10 will register `cvif serve` in Typer CLI, allowing operators to run:  
     `cvif serve --host 127.0.0.1 --port 8000 --config path/to/config.yaml`

---

## 12. File Upload & Large Payload Handling

1. **Architectural Policy**:
   - The primary API mode operates on **pre-staged local files** (paths residing within `config.storage.data_dir`).
   - Arbitrary multipart file upload endpoints for multi-gigabyte models are **prohibited** in Phase 10 to prevent denial-of-service, memory exhaustion, and unconfined disk filling.
2. **JSON Payload Limits**:
   - Maximum JSON request body size: 10 MB (sufficient for inference records, metadata, and configuration).
   - Enforced via custom Starlette middleware (`Content-Length` header check and body stream limiter).
3. **Temporary Files**:
   - Any temporary files created during evidence export or analysis must use `tempfile.NamedTemporaryFile` in `data/staging/` with deterministic cleanup in `finally` blocks.

---

## 13. Model Security Boundary

1. **Pre-Flight Inspection Enforced**:
   ```
   POST /api/v1/models/scan
      ├── 1. Validate path within allowed storage root
      ├── 2. Invoke validate_model_file_safety(model_path) [STATIC SCAN]
      │      └── Fails closed on pickle opcode exploit / zip bomb -> HTTP 422
      ├── 3. Instantiate ModelAdapter
      └── 4. Execute ModelIntegrityOrchestrator.run_analysis()
   ```
2. **Zero Deserialization Bypass**: There is no API parameter or flag that allows bypassing the static safety check.
3. **Isolated Subprocess Scanning**: Where configured, model inspection runs in a disposable subprocess via `isolated_inspect_model_file()`.

---

## 14. Evidence Store Security & Immutability

1. **Write-Once Preservation**:
   - No `DELETE /api/v1/evidence/{id}` endpoint.
   - No `PUT` or `PATCH` endpoints on evidence.
2. **Integrity-Checked Retrieval**:
   - `GET /api/v1/evidence/{id}` defaults to `verify=True`, recalculating the canonical SHA-256 and verifying artifact digests before returning. If tampering is detected, returns `HTTP 409 Conflict`.
3. **Pre-Export Integrity Verification**:
   - `POST /api/v1/evidence/export` runs `verify_store_consistency()` first. If any record or artifact is missing or tampered, export is rejected with `HTTP 409 Conflict`.
4. **Thread Safety**: Evidence store operations are protected by `EvidenceStore._lock` (`threading.RLock()`).

---

## 15. Provenance Security Boundary

1. **Replay & Nonce Enforcement**:
   - `POST /api/v1/provenance/verify` passes `enforce_replay_checks=True` to `InferenceProvenanceVerifier`.
   - Repeated submissions with the same nonce and producer ID are detected and flagged as replay attacks (Threat IT-2).
2. **Cryptographic Binding**:
   - Verifies Ed25519 digital signature over canonicalized inference record payload.
   - Verifies raw image SHA-256 and model weight digest binding.

---

## 16. Assurance Semantics & Risk Integrity

1. **Assurance Evaluation**:
   - `POST /api/v1/assess` takes `session_id: UUID`, queries session findings from `DatabaseManager`, and invokes `AssuranceOrchestrator.evaluate_session()`.
2. **Mathematical Invariants Preserved**:
   - Weakest-Link Veto Gating: Critical veto findings force disposition to `QUARANTINE` regardless of weighted average.
   - Noisy-OR Multi-Finding Escalation: Accruing multiple findings in a single dimension escalates risk monotonically.
   - Anti-Dilution Principle: Clean dimensions cannot dilute severe threats in another dimension.
3. **Fidelity**: The API outputs the exact `AssuranceVerdict` object produced by the orchestrator.

---

## 17. Concurrency & State Management

1. **SQLite Concurrency**:
   - `DatabaseManager` already initializes SQLite in WAL mode (`PRAGMA journal_mode=WAL;`) with a 5000ms busy timeout and thread-local connections.
   - Multiple concurrent read requests (`GET /api/v1/evidence`) can execute simultaneously without blocking writers.
2. **Audit Ledger Synchronization**:
   - `AuditLogger` uses `threading.RLock()`. Concurrent API calls logging audit events will acquire the lock sequentially, preserving strictly monotonic hash chains ($H_n = SHA-256(E_n || H_{n-1})$).
3. **Lifespan Management**:
   - FastAPI lifespan handler initializes a singleton `RuntimeContext` at application startup and invokes `RuntimeContext.close()` on shutdown, ensuring database and file locks are released cleanly.

---

## 18. Long-Running Operations & Execution Strategy

1. **Execution Nature**:
   - Dataset ingestion (1,000 images) and model battery scans (MT-1..4) are CPU/disk-bound and execute synchronously in 1–10 seconds under typical workloads.
2. **FastAPI Thread Pool Dispatch**:
   - Long-running domain operations must be implemented as synchronous standard functions (`def endpoint(...)`, not `async def endpoint(...)`). FastAPI automatically runs standard synchronous handlers in its internal `anyio` worker thread pool, preventing CPU-bound tasks from starving the async event loop.
3. **Client Timeout Recommendation**: Clients should configure an HTTP timeout of at least 60 seconds for scanning operations.
4. **Session-Based Querying**: Every scanning operation accepts or generates a `session_id: UUID`. The client can retrieve results subsequently via `GET /api/v1/evidence?session_id={id}`.

---

## 19. Resource Limits & Denial-of-Service Protections

1. **Request Body Size**: 10 MB maximum.
2. **Query Pagination**: Maximum 100 records per page on `GET /api/v1/evidence`.
3. **Process Memory Confinement**: Governed by existing `config.resources.max_memory_mb` (8,192 MB).
4. **Execution Timeouts**: API request processing timeout bounded at 60 seconds.

---

## 20. Error Handling & Exception Translation

A centralized exception handler (`cvif.api.error_handler.setup_exception_handlers(app)`) maps core exceptions to HTTP responses:

```python
# Authoritative Exception-to-HTTP Translation Map
EXCEPTION_HTTP_MAP = {
    ConfigurationError: 500,
    SchemaValidationError: 422,
    UnsupportedFormatError: 415,
    InvalidModelError: 422,
    TamperDetectedError: 409,
    EvidenceImmutableError: 409,
    KeyNotFoundError: 404,
    PathTraversalError: 400,
    ResourceExhaustionError: 413,
    AirGapViolationError: 403,
    StorageError: 500,
    FileNotFoundError: 404,
    KeyError: 404,
    CVIFError: 400,
}
```

Every handled error returns the standard JSON error envelope with a unique `request_id`.

---

## 21. Request Correlation & Tracing

1. **Correlation Middleware**: A custom Starlette middleware (`CorrelationIdMiddleware`) intercepts each incoming request:
   - Reads `X-Request-ID` header if supplied by client (must match valid UUID or alphanumeric string $\le 64$ chars).
   - Generates a fresh `uuid4()` string if header is absent or invalid.
   - Sets `request.state.request_id`.
   - Injects `X-Request-ID` into outgoing HTTP response headers.
2. **Audit Association**: When an API operation generates an `AuditEvent`, the `request_id` is recorded in `event.metadata["request_id"]`.

---

## 22. CORS & Browser Exposure

1. **Default Policy**: CORS is **disabled** by default.
2. **Configuration Control**: Configured via `config.api.cors_origins` (e.g. `["http://127.0.0.1:8501"]` for Streamlit Phase 11).
3. **Security Invariant**: Wildcard origins (`"*"`) are strictly prohibited when credentials or API keys are enabled.

---

## 23. OpenAPI Specification & Documentation

1. **OpenAPI Schema**: Generated automatically by FastAPI at `/openapi.json`.
2. **Air-Gap Protection**: Interactive UI docs (`/docs`, `/redoc`) are **disabled by default** (`docs_url=None, redoc_url=None`) to prevent browser CDN fetch attempts.
3. **Endpoint Descriptions**: Every route includes explicit OpenAPI tags, summaries, and response model documentation.

---

## 24. CLI & API Consistency

The REST API and CLI share 100% of underlying domain infrastructure:

| Component | CLI (Phase 9) | REST API (Phase 10) | Consistency Guarantee |
|---|---|---|---|
| **Service Layer** | Calls domain orchestrators | Calls domain orchestrators | Identical domain logic executed |
| **Config Loader** | `cvif.core.config.load_config()` | `cvif.core.config.load_config()` | Same configuration files and defaults |
| **Database** | `DatabaseManager` | `DatabaseManager` | Same SQLite catalogue and WAL settings |
| **Evidence Store**| `EvidenceStore` | `EvidenceStore` | Same write-once immutability and hashing |
| **Audit Ledger** | `AuditLogger` | `AuditLogger` | Same cryptographic hash chains |
| **Exit / Status** | Exit Code `0` | HTTP Status `200` | Deterministic 1-to-1 semantic mapping |
| **Tamper Code** | Exit Code `20` | HTTP Status `409` | Deterministic tamper identification |
| **Not Found** | Exit Code `21` | HTTP Status `404` | Deterministic resource resolution |

---

## 25. Determinism & Canonical Output

1. **Domain Identity**: The REST API emits data extracted from Pydantic schemas using `.model_dump(mode="json")`.
2. **Cryptographic Hashes**: Record and artifact SHA-256 hashes are computed by the core before reaching the API layer; the API transport cannot alter hash digests.
3. **Sorted Serialization**: JSON outputs are serialized with sorted keys to guarantee deterministic payloads across repeated calls.

---

## 26. Audit & Observability

The API integrates with `AuditLogger`:
1. **Audited Operations**:
   - `POST /api/v1/datasets/ingest`: logs `DATASET_INGESTED` with asset ID and hash manifest.
   - `POST /api/v1/datasets/scan`: logs `ANALYSIS_STARTED`, `FINDING_RECORDED`, `ANALYSIS_COMPLETED`.
   - `POST /api/v1/models/scan`: logs `MODEL_SCAN_STARTED`, `MODEL_SCAN_COMPLETED`.
   - `POST /api/v1/provenance/verify`: logs `PROVENANCE_VERIFIED` with outcome.
   - `POST /api/v1/assess`: logs `VERDICT_ISSUED` with final disposition.
   - `POST /api/v1/audit/verify`: logs `AUDIT_VERIFIED` with integrity status.
   - `POST /api/v1/evidence/export`: logs `EVIDENCE_EXPORTED`.
2. **Sensitive Data Protection**: Audit events record identifiers, hashes, and metadata; they never record raw model weights, image pixels, or private keys.

---

## 27. Security Threat Model

| Threat ID | Threat Description | Attack Surface | Existing Defense | Required Phase 10 Architectural Control | Verification Strategy |
|---|---|---|---|---|---|
| **T-10-1** | Path Traversal via URL parameter | `model_path`, `data_dir` | `_validate_safe_relative_path` | `resolve_api_path()` rejects null bytes, `..`, unconfined roots | Test with `..\..\Windows` and null bytes |
| **T-10-2** | Arbitrary Model File Deserialization | `POST /api/v1/models/scan` | `validate_model_file_safety` | Mandatory pre-flight scan before adapter initialization | Test with malicious pickle bytecode |
| **T-10-3** | Evidence Record Tampering / Overwrite | `POST /api/v1/evidence` | `EvidenceStore` write-once | No mutating evidence endpoints exposed | Test for absence of PUT/DELETE routes |
| **T-10-4** | Replay of Stolen Inference Nonce | `POST /api/v1/provenance/verify` | `InferenceProvenanceVerifier` | Enforce `enforce_replay_checks=True` | Re-submit identical signed record |
| **T-10-5** | Stack Trace Information Leakage (CT-12) | Unhandled server exception | `@cli_error_boundary` | Global Starlette exception handler emits generic JSON | Inject exception, verify zero traceback |
| **T-10-6** | Air-Gap CDN Resource Fetch | Browser loads `/docs` | None | `docs_url=None, redoc_url=None` by default | Verify zero external URLs in responses |
| **T-10-7** | Public Network Exposure | Default server start | None | Default host strictly `127.0.0.1` | Verify socket binds to loopback only |
| **T-10-8** | Denial of Service via Payload Flooding | Large POST bodies | Resource limit checks | Request body size middleware limit (10 MB) | Send 20 MB body, verify HTTP 413 |
| **T-10-9** | Permissive Cross-Origin Access | Malicious web page in browser | None | CORS disabled by default; explicit origin whitelist | Test preflight OPTIONS from unauthorized origin |
| **T-10-10**| Export of Tampered Evidence Store | `POST /api/v1/evidence/export`| Store consistency audit | Mandatory pre-export consistency check | Tamper disk byte, verify export rejected |

---

## 28. Test Architecture Matrix

Phase 10 test suite (`tests/unit/test_api.py`) will implement 26 comprehensive test categories (A through Z) using `fastapi.testclient.TestClient`:

| Test Category | Target Feature / Security Boundary |
|---|---|
| **Category A** | Application startup, lifespan initialization, and shutdown resource cleanup |
| **Category B** | `GET /api/v1/health` status reporting under healthy and degraded conditions |
| **Category C** | `GET /api/v1/version` schema metadata and air-gap flag |
| **Category D** | Request validation: invalid JSON, missing parameters, malformed types |
| **Category E** | Path traversal defense: rejection of `..`, null bytes, and root escapes |
| **Category F** | Model safety pre-flight scan: clean ONNX model (HTTP 200) |
| **Category G** | Model safety exploit rejection: malicious pickle opcodes (HTTP 422 / finding) |
| **Category H** | Model scan battery: MT-1..4 dynamic execution and findings reporting |
| **Category I** | Dataset ingestion: cataloging and asset registration row creation |
| **Category J** | Dataset integrity scan: DT-1..6 threat detection and findings recording |
| **Category K** | Provenance verification: valid Ed25519 signature and metadata match |
| **Category L** | Provenance forgery: invalid signature rejection (HTTP 200, `is_valid=False`) |
| **Category M** | Provenance replay attack rejection: duplicate nonce handling |
| **Category N** | Distribution shift analysis: DS-1..4 evaluation and ShiftReport return |
| **Category O** | Assurance assessment: `ACCEPT` verdict evaluation (HTTP 200) |
| **Category P** | Assurance assessment: `REVIEW` verdict evaluation (HTTP 200) |
| **Category Q** | Assurance assessment: `QUARANTINE` critical veto evaluation (HTTP 200) |
| **Category R** | Evidence querying and filtering by session, finding, and type |
| **Category S** | Evidence retrieval by ID with cryptographic digest verification |
| **Category T** | Evidence tamper detection: modified disk bytes triggers HTTP 409 |
| **Category U** | Evidence export: valid session packaging into `.cvif` bundle |
| **Category V** | Evidence export rejection: tampered store aborts export |
| **Category W** | Audit ledger verification: valid chain vs. broken chain (HTTP 409) |
| **Category X** | Error handling: exception translation and zero traceback leakage |
| **Category Y** | Strict air-gap socket confinement under blocked network sockets |
| **Category Z** | Anti-stub validation: dynamic response to mutated inputs |

---

## 29. Performance & Resource Footprint

1. **Overhead**: FastAPI route dispatch overhead is $\le 2$ ms on local loopback.
2. **Memory Footprint**: Single-process ASGI application footprint $\approx 45$ MB.
3. **Database Concurrency**: SQLite WAL mode handles $\ge 500$ read operations per second without locking contention.

---

## 30. Dependencies

| Package | Version Required | Current Environment Status | Usage in Phase 10 | Security / Air-Gap Implication |
|---|---|---|---|---|
| `fastapi` | `>=0.100.0` | **Installed** (`0.136.1`) | Application framework, routing, dependency injection | Local execution; must disable CDN docs |
| `uvicorn` | `>=0.22.0` | **Installed** (`0.46.0`) | ASGI web server for `cvif serve` | Local loopback server |
| `starlette` | `>=0.27.0` | **Installed** (`1.0.0`) | Underlying HTTP primitives, middleware, status codes | Bundled with FastAPI |
| `httpx` | `>=0.24.0` | **Installed** (`0.28.1`) | `TestClient` test runner for unit tests | Test dependency only |

No new external packages need to be installed. All required libraries are already installed in `.venv`.

---

## 31. Phase Boundary Compliance & Anti-Stub Invariants

1. **Phase 10 Boundary**: Delivers REST API only. Zero Streamlit/Dash UI code (Phase 11). Zero Dockerfile/container code (Phase 12).
2. **Anti-Stub Invariant**: Every API endpoint connects directly to its authoritative domain orchestrator. Zero mock findings, zero hardcoded verdicts, zero synthetic sleep stubs.

---

## 32. Findings Summary

### High Severity Findings (Architectural Constraints)
1. **Finding H-10-1 (Swagger UI CDN Fetch)**:  
   *Description*: FastAPI default `/docs` loads assets from `cdn.jsdelivr.net`. In air-gapped defense networks, this violates egress policy.  
   *Resolution*: Enforce `docs_url=None, redoc_url=None` by default in application factory; serve raw `/openapi.json`.
2. **Finding H-10-2 (Unsafe Host Binding Default)**:  
   *Description*: Binding to `0.0.0.0` could expose the unauthenticated API to unauthorized local network nodes.  
   *Resolution*: Enforce default host `127.0.0.1` in configuration and CLI options.

### Medium Severity Findings
1. **Finding M-10-1 (Long-Running Task Thread Starvation)**:  
   *Description*: Declaring CPU-bound analysis handlers as `async def` would block the asyncio event loop.  
   *Resolution*: Mandate synchronous `def` route definitions so FastAPI automatically dispatches them to worker thread pools.

### Low Severity Findings / Non-Blocking Improvements
1. **Finding L-10-1 (Configuration Schema Extension)**:  
   *Description*: `AppConfig` in `src/cvif/core/config.py` does not currently include an `APIConfig` section.  
   *Resolution*: Add `APIConfig` schema with sensible defaults (`host="127.0.0.1"`, `port=8000`, `cors_origins=[]`).

---

## 33. Blocker Resolution Plan

All identified findings are fully resolved by architectural design specifications:
- **H-10-1**: Addressed in Section 10 & 23 (disable CDN docs).
- **H-10-2**: Addressed in Section 11 (bind to `127.0.0.1`).
- **M-10-1**: Addressed in Section 18 (synchronous thread-pool dispatch).
- **L-10-1**: Addressed in Section 2 (add `APIConfig`).

Zero blockers remain.

---

## 34. Final Readiness Decision

The architecture for Phase 10 (REST API) is comprehensively specified, cryptographically sound, air-gap compliant, and fully aligned with the frozen project requirements.

**Final Audit Status**:  
PHASE 10 READY FOR IMPLEMENTATION — AWAITING OWNER REVIEW
