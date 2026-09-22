"""SQLite storage manager for CVIF asset catalogue, session results, and metadata."""

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, Generator, List, Optional, Tuple, Union
from uuid import UUID, uuid4

from cvif.core.enums import AssetStatus, AssetType, Disposition, SeverityLevel, SessionStatus
from cvif.core.exceptions import StorageError
from cvif.core.schemas import (
    AssetRegistration,
    AnalysisSession,
    Finding,
    AssuranceVerdict,
)


class DatabaseManager:
    """Thread-safe SQLite database manager configured with WAL mode and foreign key constraints."""

    SCHEMA_VERSION = 1

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=10.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            # Enable WAL mode for concurrent reads/writes and enforce foreign keys
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager for atomic database transactions."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise StorageError(f"Database transaction failed: {e}") from e

    def _init_db(self) -> None:
        """Initialize database schema tables and indexes."""
        with self.transaction() as cur:
            # Metadata schema version
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)
            cur.execute(
                "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', ?);",
                (str(self.SCHEMA_VERSION),),
            )

            # Assets catalog
            cur.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id TEXT PRIMARY KEY,
                    asset_type TEXT NOT NULL,
                    format TEXT NOT NULL,
                    total_size_bytes INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    contributor_id TEXT,
                    batch_id TEXT,
                    ingestion_timestamp TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);")

            # Analysis sessions
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    asset_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration_ms REAL,
                    operator_id TEXT,
                    schema_version TEXT NOT NULL,
                    session_json TEXT NOT NULL,
                    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_asset ON sessions(asset_id);")

            # Findings
            cur.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    threat_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    title TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
                    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);")

            # Assurance Verdicts
            cur.execute("""
                CREATE TABLE IF NOT EXISTS verdicts (
                    verdict_id TEXT PRIMARY KEY,
                    asset_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    composite_risk_score REAL NOT NULL,
                    disposition TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    verdict_json TEXT NOT NULL,
                    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                );
            """)

            # Audit Event Index
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_index (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    asset_id TEXT,
                    session_id TEXT,
                    event_hash TEXT NOT NULL,
                    previous_event_hash TEXT NOT NULL,
                    log_offset INTEGER NOT NULL
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_index(timestamp);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_index(event_type);")

            # Replay protection: seen nonces
            cur.execute("""
                CREATE TABLE IF NOT EXISTS seen_nonces (
                    nonce TEXT PRIMARY KEY,
                    record_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );
            """)

            # Replay protection: session sequence tracking
            cur.execute("""
                CREATE TABLE IF NOT EXISTS session_sequences (
                    session_id TEXT NOT NULL,
                    signing_key_id TEXT NOT NULL,
                    last_sequence_number INTEGER NOT NULL,
                    last_timestamp TEXT NOT NULL,
                    PRIMARY KEY (session_id, signing_key_id)
                );
            """)

            # Phase 8: Evidence Records
            cur.execute("""
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
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence_records(session_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence_records(finding_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence_records(content_hash);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence_records(evidence_type);")

            # Phase 8: Evidence Artifacts
            cur.execute("""
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
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_session ON evidence_artifacts(session_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_evidence ON evidence_artifacts(evidence_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_digest ON evidence_artifacts(artifact_digest);")
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_artifacts_session_relpath ON evidence_artifacts(session_id, rel_path);")

            # Phase 12 / Lineage: Provenance Verification Records
            cur.execute("""
                CREATE TABLE IF NOT EXISTS provenance_records (
                    record_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    model_weight_digest TEXT NOT NULL,
                    input_image_hash TEXT NOT NULL,
                    signing_key_id TEXT,
                    producer_id TEXT,
                    is_valid INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    details_json TEXT,
                    created_at TEXT NOT NULL
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_provenance_session ON provenance_records(session_id);")


    # -------------------------------------------------------------
    # Asset Registration CRUD
    # -------------------------------------------------------------
    def save_asset(self, asset: AssetRegistration) -> None:
        """Insert or replace an asset registration in the catalog."""
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO assets (
                    asset_id, asset_type, format, total_size_bytes, status,
                    contributor_id, batch_id, ingestion_timestamp, schema_version,
                    manifest_json, record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(asset.asset_id),
                    asset.asset_type.value,
                    asset.format,
                    asset.total_size_bytes,
                    asset.status.value,
                    asset.contributor_id,
                    asset.batch_id,
                    asset.ingestion_timestamp.isoformat(),
                    asset.schema_version,
                    asset.hash_manifest.to_canonical_json(),
                    asset.to_canonical_json(),
                ),
            )

    def get_asset(self, asset_id: Union[str, UUID]) -> Optional[AssetRegistration]:
        """Fetch asset registration by ID."""
        with self.transaction() as cur:
            cur.execute("SELECT record_json FROM assets WHERE asset_id = ?;", (str(asset_id),))
            row = cur.fetchone()
            if not row:
                return None
            return AssetRegistration.model_validate_json(row["record_json"])

    def list_assets(
        self,
        asset_type: Optional[AssetType] = None,
        status: Optional[AssetStatus] = None,
    ) -> List[AssetRegistration]:
        """List assets matching criteria."""
        query = "SELECT record_json FROM assets WHERE 1=1"
        params: List[Any] = []
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type.value)
        if status:
            query += " AND status = ?"
            params.append(status.value)
        query += " ORDER BY ingestion_timestamp DESC;"

        with self.transaction() as cur:
            cur.execute(query, tuple(params))
            rows = cur.fetchall()
            return [AssetRegistration.model_validate_json(r["record_json"]) for r in rows]

    # -------------------------------------------------------------
    # Analysis Sessions CRUD
    # -------------------------------------------------------------
    def save_session(self, session: AnalysisSession) -> None:
        """Insert or replace analysis session state."""
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO sessions (
                    session_id, asset_id, status, start_time, end_time,
                    duration_ms, operator_id, schema_version, session_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(session.session_id),
                    str(session.asset_id),
                    session.status.value,
                    session.start_time.isoformat(),
                    session.end_time.isoformat() if session.end_time else None,
                    session.duration_ms,
                    session.operator_id,
                    session.schema_version,
                    session.to_canonical_json(),
                ),
            )

    def get_session(self, session_id: Union[str, UUID]) -> Optional[AnalysisSession]:
        """Retrieve an analysis session by ID."""
        with self.transaction() as cur:
            cur.execute("SELECT session_json FROM sessions WHERE session_id = ?;", (str(session_id),))
            row = cur.fetchone()
            if not row:
                return None
            return AnalysisSession.model_validate_json(row["session_json"])

    def list_sessions(self, limit: int = 50) -> List[AnalysisSession]:
        """List recently created analysis sessions."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT session_json FROM sessions ORDER BY start_time DESC LIMIT ?;",
                (limit,),
            )
            rows = cur.fetchall()
            return [AnalysisSession.model_validate_json(r["session_json"]) for r in rows]

    def update_session_section(
        self,
        session_id: Union[str, UUID],
        section: str,
        asset_id: Optional[Union[str, UUID]] = None,
        executed_analyses: Optional[List[str]] = None,
        skipped_analyses: Optional[List[Dict[str, str]]] = None,
        findings: Optional[List[Finding]] = None,
        environment_updates: Optional[Dict[str, Any]] = None,
        verdict: Optional[AssuranceVerdict] = None,
        operator_id: Optional[str] = None,
        status: Optional[SessionStatus] = None,
        duration_ms: Optional[float] = None,
    ) -> AnalysisSession:
        """Atomically merge/patch a specific pipeline module's section into a persistent analysis session.

        Preserves all other pipeline sections (e.g. running Model preserves Dataset, Inference, etc.).
        """
        sess_str = str(session_id)
        sess_uuid = UUID(sess_str) if isinstance(session_id, str) else session_id
        sec = section.strip().lower()

        def _is_section_finding(f: Finding) -> bool:
            t_upper = (f.threat_id or "").upper()
            c_upper = (f.category or "").upper()
            if sec == "dataset":
                return t_upper.startswith("DT-") or c_upper in ("DATA_INTEGRITY", "DATASET")
            elif sec == "model":
                return t_upper.startswith("MT-") or c_upper in ("MODEL_INTEGRITY", "MODEL")
            elif sec == "inference":
                return t_upper.startswith("IT-") or c_upper in ("INFERENCE_PROVENANCE", "INFERENCE")
            elif sec == "distribution":
                return t_upper.startswith("DS-") or c_upper in ("DISTRIBUTION_SHIFT", "DISTRIBUTION")
            return False

        def _is_section_analysis_id(aid: str) -> bool:
            a_upper = (aid or "").upper()
            if sec == "dataset":
                return a_upper.startswith("DT-") or a_upper in ("DATASET", "DATA_INTEGRITY")
            elif sec == "model":
                return a_upper.startswith("MT-") or a_upper in ("MODEL", "MODEL_INTEGRITY")
            elif sec == "inference":
                return a_upper.startswith("IT-") or a_upper in ("INFERENCE", "INFERENCE_PROVENANCE")
            elif sec == "distribution":
                return a_upper.startswith("DS-") or a_upper in ("DISTRIBUTION", "DISTRIBUTION_SHIFT")
            return False

        existing = self.get_session(sess_str)
        now = datetime.now(timezone.utc)

        if existing is None:
            # First module running for this session
            primary_asset_id = UUID(str(asset_id)) if asset_id else uuid4()
            # Ensure asset exists for foreign key constraint
            if self.get_asset(primary_asset_id) is None:
                try:
                    from cvif.core.schemas import HashManifest
                    fallback_reg = AssetRegistration(
                        asset_id=primary_asset_id,
                        asset_type=AssetType.MODEL if sec == "model" else AssetType.DATASET,
                        format=environment_updates.get("format", "generic") if environment_updates else "generic",
                        hash_manifest=HashManifest(),
                        total_size_bytes=0,
                    )
                    self.save_asset(fallback_reg)
                except Exception:
                    pass

            merged_executed = list(executed_analyses or [])
            merged_skipped = list(skipped_analyses or [])
            merged_findings = list(findings or [])
            merged_env: Dict[str, Any] = dict(environment_updates or {})
            merged_env["sections"] = {
                sec: {
                    "updated_at": now.isoformat(),
                    "executed_analyses": list(executed_analyses or []),
                    "findings_count": len(findings or []),
                    "details": dict(environment_updates or {}),
                }
            }

            merged_session = AnalysisSession(
                session_id=sess_uuid,
                asset_id=primary_asset_id,
                status=status or SessionStatus.COMPLETED,
                requested_analyses=merged_executed or ["AUTO"],
                executed_analyses=merged_executed,
                skipped_analyses=merged_skipped,
                start_time=now,
                end_time=now,
                duration_ms=duration_ms or 0.0,
                findings=merged_findings,
                verdict=verdict,
                operator_id=operator_id or "cvif_api",
                execution_environment=merged_env,
            )
        else:
            # Updating existing session: preserve other sections
            if asset_id and (existing.status == SessionStatus.INITIALIZING or sec == "dataset"):
                primary_asset_id = UUID(str(asset_id))
            else:
                primary_asset_id = existing.asset_id

            # Ensure asset exists for foreign key constraint
            if self.get_asset(primary_asset_id) is None:
                try:
                    from cvif.core.schemas import HashManifest
                    fallback_reg = AssetRegistration(
                        asset_id=primary_asset_id,
                        asset_type=AssetType.MODEL if sec == "model" else AssetType.DATASET,
                        format=environment_updates.get("format", "generic") if environment_updates else "generic",
                        hash_manifest=HashManifest(),
                        total_size_bytes=0,
                    )
                    self.save_asset(fallback_reg)
                except Exception:
                    pass

            # If a new asset_id is provided, record it in environment
            if asset_id:
                if environment_updates is None:
                    environment_updates = {}
                environment_updates[f"{sec}_asset_id"] = str(asset_id)

            # Merge findings: replace only findings belonging to this section
            retained_findings = [f for f in (existing.findings or []) if not _is_section_finding(f)]
            merged_findings = retained_findings + list(findings or [])

            # Merge executed analyses: replace only analyses belonging to this section
            retained_analyses = [a for a in (existing.executed_analyses or []) if not _is_section_analysis_id(a)]
            new_analyses = list(executed_analyses or [])
            merged_analyses = []
            seen_analyses = set()
            for a in (retained_analyses + new_analyses):
                if a not in seen_analyses:
                    seen_analyses.add(a)
                    merged_analyses.append(a)

            # Merge skipped analyses: replace only skipped items belonging to this section
            retained_skipped = [s for s in (existing.skipped_analyses or []) if not _is_section_analysis_id(s.get("analysis_id", ""))]
            merged_skipped = retained_skipped + list(skipped_analyses or [])

            # Merge environment: preserve existing keys and other sections
            merged_env = dict(existing.execution_environment or {})
            if "sections" not in merged_env or not isinstance(merged_env["sections"], dict):
                merged_env["sections"] = {}

            if environment_updates:
                for k, v in environment_updates.items():
                    if v is not None:
                        merged_env[k] = v

            merged_env["sections"][sec] = {
                "updated_at": now.isoformat(),
                "executed_analyses": list(executed_analyses or []),
                "findings_count": len(findings or []),
                "details": dict(environment_updates or {}),
            }

            merged_session = AnalysisSession(
                session_id=existing.session_id,
                asset_id=primary_asset_id,
                status=status or (existing.status if existing.status != SessionStatus.INITIALIZING else SessionStatus.COMPLETED) or SessionStatus.COMPLETED,
                requested_analyses=merged_analyses or existing.requested_analyses,
                executed_analyses=merged_analyses,
                skipped_analyses=merged_skipped,
                start_time=existing.start_time,
                end_time=now,
                duration_ms=(existing.duration_ms or 0.0) + (duration_ms or 0.0),
                findings=merged_findings,
                verdict=verdict or existing.verdict,
                operator_id=operator_id or existing.operator_id or "cvif_api",
                execution_environment=merged_env,
            )

        self.save_session(merged_session)

        # Also persist newly added findings to findings table
        if findings:
            for f in findings:
                self.save_finding(f)

        return merged_session

    # -------------------------------------------------------------
    # Findings CRUD
    # -------------------------------------------------------------
    def save_finding(self, finding: Finding) -> None:
        """Save a finding record."""
        with self.transaction() as cur:
            # Ensure asset exists for foreign key
            if self.get_asset(finding.asset_id) is None:
                try:
                    from cvif.core.schemas import HashManifest
                    fallback_reg = AssetRegistration(
                        asset_id=finding.asset_id,
                        asset_type=AssetType.DATASET,
                        format="generic",
                        hash_manifest=HashManifest(),
                        total_size_bytes=0,
                    )
                    self.save_asset(fallback_reg)
                except Exception:
                    pass
            # Ensure session exists for foreign key
            if self.get_session(finding.session_id) is None:
                try:
                    fallback_session = AnalysisSession(
                        session_id=finding.session_id,
                        asset_id=finding.asset_id,
                        status=SessionStatus.INITIALIZING,
                    )
                    self.save_session(fallback_session)
                except Exception:
                    pass
            cur.execute(
                """
                INSERT OR REPLACE INTO findings (
                    finding_id, session_id, asset_id, threat_id, category,
                    severity, confidence, title, finding_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(finding.finding_id),
                    str(finding.session_id),
                    str(finding.asset_id),
                    finding.threat_id,
                    finding.category,
                    finding.severity.value,
                    finding.confidence,
                    finding.title,
                    finding.to_canonical_json(),
                ),
            )

    def get_findings_for_session(self, session_id: Union[str, UUID]) -> List[Finding]:
        """Retrieve all findings for a given session."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT finding_json FROM findings WHERE session_id = ? ORDER BY confidence DESC;",
                (str(session_id),),
            )
            rows = cur.fetchall()
            return [Finding.model_validate_json(r["finding_json"]) for r in rows]

    # -------------------------------------------------------------
    # Assurance Verdicts CRUD
    # -------------------------------------------------------------
    def save_verdict(self, verdict: AssuranceVerdict) -> None:
        """Save an assurance verdict."""
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO verdicts (
                    verdict_id, asset_id, session_id, composite_risk_score,
                    disposition, summary, verdict_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(verdict.verdict_id),
                    str(verdict.asset_id),
                    str(verdict.session_id),
                    verdict.composite_risk_score,
                    verdict.disposition.value,
                    verdict.summary,
                    verdict.to_canonical_json(),
                ),
            )

    def get_verdict_for_session(self, session_id: Union[str, UUID]) -> Optional[AssuranceVerdict]:
        """Retrieve verdict for a given session."""
        with self.transaction() as cur:
            cur.execute("SELECT verdict_json FROM verdicts WHERE session_id = ?;", (str(session_id),))
            row = cur.fetchone()
            if not row:
                return None
            return AssuranceVerdict.model_validate_json(row["verdict_json"])

    # -------------------------------------------------------------
    # Replay Protection (Nonce & Sequence Registry)
    # -------------------------------------------------------------
    def record_nonce_if_new(self, nonce: str, record_id: str, timestamp_iso: str) -> bool:
        """Atomically record nonce. Returns True if new (recorded), False if already seen (replay)."""
        with self.transaction() as cur:
            cur.execute("SELECT 1 FROM seen_nonces WHERE nonce = ?;", (nonce,))
            if cur.fetchone() is not None:
                return False  # Nonce already seen!
            cur.execute(
                "INSERT INTO seen_nonces (nonce, record_id, timestamp) VALUES (?, ?, ?);",
                (nonce, record_id, timestamp_iso),
            )
            return True

    def record_sequence_if_monotonic(
        self, session_id: str, signing_key_id: str, sequence_number: int, timestamp_iso: str
    ) -> Tuple[bool, Optional[int]]:
        """Validate and atomically advance sequence number for (session_id, signing_key_id).
        
        Returns (is_valid, previous_sequence).
        If sequence_number <= previous_sequence: returns (False, previous_sequence).
        Otherwise: records new sequence and returns (True, previous_sequence).
        """
        with self.transaction() as cur:
            cur.execute(
                "SELECT last_sequence_number FROM session_sequences WHERE session_id = ? AND signing_key_id = ?;",
                (str(session_id), str(signing_key_id)),
            )
            row = cur.fetchone()
            if row is not None:
                last_seq = row["last_sequence_number"]
                if sequence_number <= last_seq:
                    return False, last_seq
                cur.execute(
                    """
                    UPDATE session_sequences
                    SET last_sequence_number = ?, last_timestamp = ?
                    WHERE session_id = ? AND signing_key_id = ?;
                    """,
                    (sequence_number, timestamp_iso, str(session_id), str(signing_key_id)),
                )
                return True, last_seq
            else:
                cur.execute(
                    """
                    INSERT INTO session_sequences (session_id, signing_key_id, last_sequence_number, last_timestamp)
                    VALUES (?, ?, ?, ?);
                    """,
                    (str(session_id), str(signing_key_id), sequence_number, timestamp_iso),
                )
                return True, None

    def get_last_sequence(self, session_id: str, signing_key_id: str) -> Optional[int]:
        """Fetch last observed sequence number for (session_id, signing_key_id)."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT last_sequence_number FROM session_sequences WHERE session_id = ? AND signing_key_id = ?;",
                (str(session_id), str(signing_key_id)),
            )
            row = cur.fetchone()
            return row["last_sequence_number"] if row else None

    # -------------------------------------------------------------
    # Phase 8: Evidence Records & Artifacts CRUD & Relational Lookups
    # -------------------------------------------------------------
    def save_evidence_record(
        self,
        evidence_id: Union[str, UUID],
        session_id: Union[str, UUID],
        finding_id: Union[str, UUID],
        evidence_type: str,
        content_hash: str,
        file_path: str,
        schema_version: str,
        record_json: str,
        created_at: Optional[str] = None,
    ) -> None:
        """Insert an evidence record index row."""
        if created_at is None:
            from datetime import datetime, timezone
            created_at = datetime.now(timezone.utc).isoformat()
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT INTO evidence_records (
                    evidence_id, session_id, finding_id, evidence_type,
                    content_hash, file_path, created_at, schema_version, record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(evidence_id),
                    str(session_id),
                    str(finding_id),
                    str(evidence_type),
                    str(content_hash),
                    str(file_path),
                    str(created_at),
                    str(schema_version),
                    str(record_json),
                ),
            )

    def get_evidence_record(self, evidence_id: Union[str, UUID]) -> Optional[Dict[str, Any]]:
        """Fetch evidence record index by ID."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT * FROM evidence_records WHERE evidence_id = ?;",
                (str(evidence_id),),
            )
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def list_evidence_records(
        self,
        session_id: Optional[Union[str, UUID]] = None,
        finding_id: Optional[Union[str, UUID]] = None,
        evidence_type: Optional[str] = None,
        content_hash: Optional[str] = None,
        threat_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query evidence records matching filters."""
        query = (
            "SELECT DISTINCT er.*, "
            "COALESCE(f.threat_id, json_extract(er.record_json, '$.reproducibility_info.threat_id')) AS threat_id "
            "FROM evidence_records er "
            "LEFT JOIN findings f ON er.finding_id = f.finding_id "
            "WHERE 1=1"
        )
        params: List[Any] = []
        if session_id:
            s_clean = str(session_id).strip()
            query += " AND (er.session_id = ? OR er.session_id LIKE ?)"
            params.extend([s_clean, f"{s_clean}%"])
        if finding_id:
            f_clean = str(finding_id).strip()
            query += " AND (er.finding_id = ? OR er.finding_id LIKE ?)"
            params.extend([f_clean, f"{f_clean}%"])
        if evidence_type:
            e_clean = str(evidence_type).strip()
            query += " AND (UPPER(er.evidence_type) = UPPER(?) OR UPPER(er.evidence_type) LIKE UPPER(?))"
            params.extend([e_clean, f"{e_clean}%"])
        if content_hash:
            c_clean = str(content_hash).strip()
            query += " AND (er.content_hash = ? OR er.content_hash LIKE ?)"
            params.extend([c_clean, f"{c_clean}%"])
        if threat_id:
            t_clean = str(threat_id).strip()
            query += (
                " AND (UPPER(COALESCE(f.threat_id, json_extract(er.record_json, '$.reproducibility_info.threat_id'))) = UPPER(?)"
                "  OR UPPER(COALESCE(f.threat_id, json_extract(er.record_json, '$.reproducibility_info.threat_id'))) LIKE UPPER(?))"
            )
            params.extend([t_clean, f"{t_clean}%"])
        query += " ORDER BY er.created_at ASC;"

        with self.transaction() as cur:
            cur.execute(query, tuple(params))
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def save_evidence_artifact(
        self,
        artifact_id: str,
        session_id: Union[str, UUID],
        rel_path: str,
        media_type: str,
        artifact_digest: str,
        size_bytes: int,
        description: Optional[str] = None,
        evidence_id: Optional[Union[str, UUID]] = None,
        created_at: Optional[str] = None,
    ) -> None:
        """Insert or index an evidence artifact."""
        if created_at is None:
            from datetime import datetime, timezone
            created_at = datetime.now(timezone.utc).isoformat()
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT INTO evidence_artifacts (
                    artifact_id, evidence_id, session_id, rel_path,
                    media_type, description, artifact_digest, size_bytes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(artifact_id),
                    str(evidence_id) if evidence_id else None,
                    str(session_id),
                    str(rel_path),
                    str(media_type),
                    description,
                    str(artifact_digest),
                    int(size_bytes),
                    str(created_at),
                ),
            )

    def get_evidence_artifact(
        self, session_id: Union[str, UUID], rel_path: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch evidence artifact metadata by (session_id, rel_path)."""
        clean_rel = str(rel_path).replace("\\", "/")
        with self.transaction() as cur:
            cur.execute(
                "SELECT * FROM evidence_artifacts WHERE session_id = ? AND rel_path = ?;",
                (str(session_id), clean_rel),
            )
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def list_evidence_artifacts(
        self,
        session_id: Optional[Union[str, UUID]] = None,
        evidence_id: Optional[Union[str, UUID]] = None,
        artifact_digest: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List evidence artifacts matching criteria."""
        query = "SELECT * FROM evidence_artifacts WHERE 1=1"
        params: List[Any] = []
        if session_id:
            query += " AND session_id = ?"
            params.append(str(session_id))
        if evidence_id:
            query += " AND evidence_id = ?"
            params.append(str(evidence_id))
        if artifact_digest:
            query += " AND artifact_digest = ?"
            params.append(str(artifact_digest))
        query += " ORDER BY created_at ASC;"

        with self.transaction() as cur:
            cur.execute(query, tuple(params))
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def bind_artifact_to_evidence(
        self,
        session_id: Union[str, UUID],
        rel_path: str,
        evidence_id: Union[str, UUID],
    ) -> None:
        """Bind an existing artifact to an EvidenceRecord UUID."""
        clean_rel = str(rel_path).replace("\\", "/")
        with self.transaction() as cur:
            cur.execute(
                """
                UPDATE evidence_artifacts
                SET evidence_id = ?
                WHERE session_id = ? AND rel_path = ?;
                """,
                (str(evidence_id), str(session_id), clean_rel),
            )

    def get_evidence_for_verdict(self, verdict_id: Union[str, UUID]) -> List[Dict[str, Any]]:
        """Fetch all evidence records contributing to an AssuranceVerdict."""
        import json
        with self.transaction() as cur:
            cur.execute("SELECT verdict_json FROM verdicts WHERE verdict_id = ?;", (str(verdict_id),))
            row = cur.fetchone()
            if not row:
                return []
            verdict_data = json.loads(row["verdict_json"])
            finding_ids = verdict_data.get("contributing_finding_ids", [])
            if not finding_ids:
                return []
            placeholders = ",".join("?" for _ in finding_ids)
            cur.execute(
                f"SELECT * FROM evidence_records WHERE finding_id IN ({placeholders}) ORDER BY created_at ASC;",
                tuple(str(fid) for fid in finding_ids),
            )
            return [dict(r) for r in cur.fetchall()]

    def get_evidence_by_threat_id(self, threat_id: str) -> List[Dict[str, Any]]:
        """Fetch all evidence records associated with findings of a specific threat ID."""
        clean_threat = str(threat_id).strip()
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT DISTINCT er.*,
                       COALESCE(f.threat_id, json_extract(er.record_json, '$.reproducibility_info.threat_id')) AS threat_id
                FROM evidence_records er
                LEFT JOIN findings f ON er.finding_id = f.finding_id
                WHERE UPPER(f.threat_id) = UPPER(?)
                   OR UPPER(f.threat_id) LIKE UPPER(?)
                   OR UPPER(json_extract(er.record_json, '$.reproducibility_info.threat_id')) = UPPER(?)
                   OR UPPER(json_extract(er.record_json, '$.reproducibility_info.threat_id')) LIKE UPPER(?)
                ORDER BY er.created_at ASC;
                """,
                (clean_threat, f"{clean_threat}%", clean_threat, f"{clean_threat}%"),
            )
            return [dict(r) for r in cur.fetchall()]

    def get_evidence_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Fetch all evidence records associated with findings of a specific category."""
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT er.* FROM evidence_records er
                JOIN findings f ON er.finding_id = f.finding_id
                WHERE f.category = ?
                ORDER BY er.created_at ASC;
                """,
                (str(category),),
            )
            return [dict(r) for r in cur.fetchall()]

    # -------------------------------------------------------------
    # Provenance Records CRUD
    # -------------------------------------------------------------
    def save_provenance_record(
        self,
        record_id: Union[str, UUID],
        session_id: Union[str, UUID],
        model_id: str,
        model_weight_digest: str,
        input_image_hash: str,
        signing_key_id: Optional[str],
        producer_id: Optional[str],
        is_valid: bool,
        status: str,
        details_json: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> None:
        """Insert or update a verified inference record in provenance registry."""
        if created_at is None:
            created_at = datetime.now(timezone.utc).isoformat()
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO provenance_records (
                    record_id, session_id, model_id, model_weight_digest,
                    input_image_hash, signing_key_id, producer_id, is_valid,
                    status, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(record_id),
                    str(session_id),
                    model_id,
                    model_weight_digest,
                    input_image_hash,
                    signing_key_id,
                    producer_id,
                    1 if is_valid else 0,
                    status,
                    details_json or "{}",
                    created_at,
                ),
            )

    def get_provenance_for_session(
        self, session_id: Union[str, UUID]
    ) -> Optional[Dict[str, Any]]:
        """Retrieve most recent verified provenance record for a given session."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT * FROM provenance_records WHERE session_id = ? ORDER BY created_at DESC LIMIT 1;",
                (str(session_id),),
            )
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def list_provenance_for_session(
        self, session_id: Union[str, UUID]
    ) -> List[Dict[str, Any]]:
        """Retrieve all verified provenance records for a given session."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT * FROM provenance_records WHERE session_id = ? ORDER BY created_at DESC;",
                (str(session_id),),
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]


    def close(self) -> None:
        """Close open connection for current thread."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None
