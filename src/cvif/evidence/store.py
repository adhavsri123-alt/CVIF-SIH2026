"""Authoritative Evidence Store: Dual-layer SQLite indexing and write-once immutable storage."""

import json
import os
from pathlib import Path
import tempfile
import threading
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from cvif.audit.logger import AuditLogger
from cvif.core.enums import AuditEventType
from cvif.core.exceptions import (
    CorruptedArtifactError,
    EvidenceImmutableError,
    PathTraversalError,
    SchemaValidationError,
    StorageError,
    TamperDetectedError,
)
from cvif.core.schemas import ArtifactReference, EvidenceRecord
from cvif.crypto.hashing import sha256_bytes, sha256_file
from cvif.storage.database import DatabaseManager
from cvif.storage.filestore import safe_resolve_path


def _validate_safe_relative_path(rel_path: Union[str, Path]) -> str:
    """Strictly validate relative path, rejecting path traversal, absolute paths, drive letters, and null bytes."""
    path_str = str(rel_path)
    if "\x00" in path_str:
        raise PathTraversalError(f"Path traversal detected: null byte in path '{path_str}'")
    if Path(path_str).is_absolute() or path_str.startswith(("/", "\\")):
        raise PathTraversalError(f"Path traversal detected: absolute path '{path_str}' is prohibited")
    if len(path_str) >= 2 and path_str[1] == ":" and path_str[0].isalpha():
        raise PathTraversalError(f"Path traversal detected: drive letter in path '{path_str}' is prohibited")
    parts = path_str.replace("\\", "/").split("/")
    if ".." in parts:
        raise PathTraversalError(f"Path traversal detected: '..' in path '{path_str}' is prohibited")
    return path_str.replace("\\", "/").lstrip("/")


class EvidenceStore:
    """Thread-safe, dual-layer evidence storage engine.
    
    Enforces write-once immutability, streaming SHA-256 cryptographic identity,
    relational SQLite indexing, tamper-evident audit logging, and air-gapped confinement.
    """

    def __init__(
        self,
        base_dir: Union[str, Path],
        db_manager: Optional[DatabaseManager] = None,
        audit_logger: Optional[AuditLogger] = None,
        enforce_content: Optional[bool] = None,
    ):
        self.base_dir = Path(base_dir).resolve()
        self.sessions_dir = self.base_dir / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

        # Dual-Layer Architecture: Relational SQLite Metadata Engine
        self._owns_db = False
        if db_manager is not None:
            self.db_manager = db_manager
        else:
            db_path = self.base_dir / "metadata.db"
            self.db_manager = DatabaseManager(db_path)
            self._owns_db = True

        self.audit_logger = audit_logger

        # Content validation policy: Enforce in Phase 8 environments (db_manager provided or explicit flag)
        # while preserving backwards compatibility for legacy bare Phase 2 callers.
        if enforce_content is not None:
            self.enforce_content = enforce_content
        else:
            self.enforce_content = (db_manager is not None)

        # In-memory index of evidence_id -> Path (backed by SQLite, avoiding directory globbing)
        self._index: Dict[str, Path] = {}
        self._sync_index_from_db()

    def _sync_index_from_db(self) -> None:
        """Populate in-memory index from relational SQLite records on startup (O(1) initialization)."""
        with self._lock:
            try:
                records = self.db_manager.list_evidence_records()
                for r in records:
                    self._index[r["evidence_id"]] = Path(r["file_path"])
            except Exception:
                # If database is fresh or uninitialized, index remains empty
                pass

    def _get_session_dir(self, session_id: Union[str, UUID]) -> Path:
        """Resolve and confine session directory within the evidence store root."""
        sess_str = str(session_id)
        _validate_safe_relative_path(sess_str)
        return safe_resolve_path(self.sessions_dir, sess_str)

    def save_evidence(
        self,
        record: EvidenceRecord,
        enforce_content: Optional[bool] = None,
    ) -> Path:
        """Persist an EvidenceRecord to disk and database.
        
        Strictly enforces write-once immutability, canonical content hashing,
        atomic replacement, and transactional database indexing.
        """
        # 1. Content validation enforcement
        should_enforce = self.enforce_content if enforce_content is None else enforce_content
        if should_enforce:
            has_payload = any([
                record.metrics is not None and (len(record.metrics) > 0 if isinstance(record.metrics, (dict, list)) else True),
                record.artifacts is not None and (len(record.artifacts) > 0 if isinstance(record.artifacts, (dict, list)) else True),
                record.baseline_comparison is not None and (len(record.baseline_comparison) > 0 if isinstance(record.baseline_comparison, (dict, list)) else True),
                record.raw_data_ref is not None and len(str(record.raw_data_ref).strip()) > 0,
            ])
            if not has_payload:
                raise SchemaValidationError(
                    f"EvidenceRecord '{record.evidence_id}' must contain at least one content payload "
                    "(metrics, artifacts, baseline_comparison, or raw_data_ref)."
                )

        ev_id_str = str(record.evidence_id)
        with self._lock:
            # 2. Collision detection across in-memory cache and SQLite index
            if ev_id_str in self._index:
                existing_path = self._index[ev_id_str]
                raise EvidenceImmutableError(
                    f"Evidence record '{ev_id_str}' already exists at {existing_path} and is immutable."
                )

            existing_db = self.db_manager.get_evidence_record(ev_id_str)
            if existing_db is not None:
                raise EvidenceImmutableError(
                    f"Evidence record '{ev_id_str}' already registered in database and is immutable."
                )

            session_dir = self._get_session_dir(record.session_id)
            ev_dir = session_dir / "evidence"
            ev_dir.mkdir(parents=True, exist_ok=True)

            target_file = ev_dir / f"{ev_id_str}.json"
            if target_file.exists():
                raise EvidenceImmutableError(
                    f"File {target_file} already exists on disk. Evidence is write-once."
                )

            # 3. Deterministic canonical serialization and content hashing
            canonical_json = record.to_canonical_json()
            canonical_bytes = record.to_canonical_bytes()
            content_hash = sha256_bytes(canonical_bytes)

            # 4. Atomic file-first write via temporary file
            temp_fd, temp_path_str = tempfile.mkstemp(
                prefix=f".tmp_{ev_id_str}_",
                dir=str(ev_dir),
            )
            temp_path = Path(temp_path_str)
            try:
                with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                    f.write(canonical_json)
                    f.flush()
                    os.fsync(f.fileno())

                # Re-check collision immediately before atomic replacement
                if target_file.exists():
                    temp_path.unlink(missing_ok=True)
                    raise EvidenceImmutableError(
                        f"Target file {target_file} was created concurrently and is immutable."
                    )

                os.replace(temp_path, target_file)
            except Exception as e:
                if temp_path.exists():
                    try:
                        temp_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                if isinstance(e, EvidenceImmutableError):
                    raise
                raise StorageError(f"Failed to persist evidence record to {target_file}: {e}") from e

            # 5. Commit relational metadata row to SQLite
            try:
                self.db_manager.save_evidence_record(
                    evidence_id=ev_id_str,
                    session_id=str(record.session_id),
                    finding_id=str(record.finding_id),
                    evidence_type=record.evidence_type.value,
                    content_hash=content_hash,
                    file_path=str(target_file),
                    schema_version=record.schema_version,
                    record_json=canonical_json,
                    created_at=record.timestamp.isoformat(),
                )

                # Bind referenced artifacts to this evidence_id in database
                if record.artifacts:
                    for art in record.artifacts:
                        self.db_manager.bind_artifact_to_evidence(
                            session_id=str(record.session_id),
                            rel_path=art.path,
                            evidence_id=ev_id_str,
                        )
            except Exception as e:
                # Transactional rollback: unlink written file to prevent orphaned state
                if target_file.exists():
                    try:
                        target_file.unlink(missing_ok=True)
                    except OSError:
                        pass
                if isinstance(e, StorageError):
                    raise
                raise StorageError(f"Database index insertion failed for evidence record {ev_id_str}: {e}") from e

            # 6. Update in-memory index
            self._index[ev_id_str] = target_file

            # 7. Audit Logging (EVIDENCE_STORED)
            if self.audit_logger is not None:
                try:
                    self.audit_logger.log_event(
                        event_type=AuditEventType.EVIDENCE_STORED,
                        actor="EvidenceStore",
                        session_id=record.session_id,
                        details={
                            "evidence_id": ev_id_str,
                            "finding_id": str(record.finding_id),
                            "evidence_type": record.evidence_type.value,
                            "content_hash": content_hash,
                            "file_path": str(target_file),
                        },
                    )
                except Exception:
                    pass

            return target_file

    def get_evidence(
        self,
        evidence_id: Union[str, UUID],
        verify_integrity: bool = True,
    ) -> Optional[EvidenceRecord]:
        """Fetch an EvidenceRecord by ID, optionally verifying cryptographic integrity."""
        ev_id_str = str(evidence_id)
        with self._lock:
            # 1. Lookup in SQLite or memory index
            db_row = self.db_manager.get_evidence_record(ev_id_str)
            target_file: Optional[Path] = None

            if db_row is not None:
                target_file = Path(db_row["file_path"])
            elif ev_id_str in self._index:
                target_file = self._index[ev_id_str]
            else:
                return None

            if not target_file.is_file():
                raise CorruptedArtifactError(
                    f"Evidence record file missing on disk: {target_file}"
                )

            # 2. Read and parse canonical JSON
            try:
                content = target_file.read_text(encoding="utf-8")
                record = EvidenceRecord.model_validate_json(content)
            except Exception as e:
                raise CorruptedArtifactError(
                    f"Failed to read or parse evidence record from {target_file}: {e}"
                ) from e

            # 3. Integrity verification
            if verify_integrity:
                computed_hash = sha256_bytes(record.to_canonical_bytes())
                if db_row is not None:
                    registered_hash = db_row["content_hash"]
                    raw_file_hash = sha256_bytes(content.encode("utf-8"))
                    if computed_hash != registered_hash and raw_file_hash != registered_hash:
                        if self.audit_logger is not None:
                            try:
                                self.audit_logger.log_event(
                                    event_type=AuditEventType.EVIDENCE_TAMPERED,
                                    actor="EvidenceStore",
                                    session_id=record.session_id,
                                    details={
                                        "evidence_id": ev_id_str,
                                        "computed_hash": computed_hash,
                                        "registered_hash": registered_hash,
                                        "status": "TAMPER_DETECTED",
                                    },
                                )
                            except Exception:
                                pass
                        raise TamperDetectedError(
                            f"Integrity check failed for EvidenceRecord '{ev_id_str}': "
                            f"computed SHA-256 ({computed_hash}) does not match registered digest ({registered_hash})."
                        )

                # Verify referenced artifacts
                if record.artifacts:
                    for art in record.artifacts:
                        art_path = safe_resolve_path(
                            self._get_session_dir(record.session_id),
                            art.path,
                        )
                        if not art_path.is_file():
                            raise CorruptedArtifactError(
                                f"Referenced artifact missing on disk: {art_path}"
                            )
                        computed_art_digest = sha256_file(art_path)
                        art_db_meta = self.db_manager.get_evidence_artifact(
                            record.session_id,
                            art.path,
                        )
                        if art_db_meta is not None:
                            expected_digest = art_db_meta["artifact_digest"]
                            if computed_art_digest != expected_digest:
                                if self.audit_logger is not None:
                                    try:
                                        self.audit_logger.log_event(
                                            event_type=AuditEventType.EVIDENCE_TAMPERED,
                                            actor="EvidenceStore",
                                            session_id=record.session_id,
                                            details={
                                                "evidence_id": ev_id_str,
                                                "artifact_path": art.path,
                                                "computed_digest": computed_art_digest,
                                                "registered_digest": expected_digest,
                                            },
                                        )
                                    except Exception:
                                        pass
                                raise TamperDetectedError(
                                    f"Artifact '{art.path}' for evidence '{ev_id_str}' failed integrity check: "
                                    f"digest mismatch ({computed_art_digest} != {expected_digest})."
                                )

                # Emit EVIDENCE_VERIFIED audit event
                if self.audit_logger is not None:
                    try:
                        self.audit_logger.log_event(
                            event_type=AuditEventType.EVIDENCE_VERIFIED,
                            actor="EvidenceStore",
                            session_id=record.session_id,
                            details={
                                "evidence_id": ev_id_str,
                                "status": "VERIFIED_VALID",
                            },
                        )
                    except Exception:
                        pass

            return record

    def save_artifact(
        self,
        session_id: Union[str, UUID],
        rel_path: str,
        data: Union[bytes, Path, str],
        media_type: str,
        description: str,
        evidence_id: Optional[Union[str, UUID]] = None,
    ) -> ArtifactReference:
        """Store a binary or structured diagnostic artifact.
        
        Enforces path traversal containment, write-once immutability,
        streaming SHA-256 hashing, and relational index registration.
        """
        clean_rel = _validate_safe_relative_path(rel_path)
        sess_dir = self._get_session_dir(session_id)
        artifacts_dir = sess_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        target_path = safe_resolve_path(artifacts_dir, clean_rel)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        rel_to_session = str(target_path.relative_to(sess_dir)).replace("\\", "/")

        with self._lock:
            # Immutability check: physical file
            if target_path.exists():
                raise EvidenceImmutableError(
                    f"Artifact at '{target_path}' already exists and is immutable."
                )

            # Immutability check: SQLite index
            existing_art = self.db_manager.get_evidence_artifact(session_id, rel_to_session)
            if existing_art is not None:
                raise EvidenceImmutableError(
                    f"Artifact '{rel_to_session}' is already registered in database for session {session_id} and is immutable."
                )

            # Atomic write via temporary file
            temp_fd, temp_path_str = tempfile.mkstemp(
                prefix=".tmp_art_",
                dir=str(target_path.parent),
            )
            temp_path = Path(temp_path_str)
            try:
                with os.fdopen(temp_fd, "wb") as f:
                    if isinstance(data, (bytes, bytearray)):
                        f.write(data)
                    elif isinstance(data, (str, Path)):
                        src_path = Path(data)
                        if src_path.is_file():
                            with src_path.open("rb") as src:
                                while chunk := src.read(65536):
                                    f.write(chunk)
                        else:
                            f.write(str(data).encode("utf-8"))
                    else:
                        raise StorageError(f"Unsupported artifact data type: {type(data)}")
                    f.flush()
                    os.fsync(f.fileno())

                if target_path.exists():
                    temp_path.unlink(missing_ok=True)
                    raise EvidenceImmutableError(
                        f"Artifact at '{target_path}' was created concurrently and is immutable."
                    )

                os.replace(temp_path, target_path)
            except Exception as e:
                if temp_path.exists():
                    try:
                        temp_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                if isinstance(e, EvidenceImmutableError):
                    raise
                raise StorageError(f"Failed to save artifact at {target_path}: {e}") from e

            # Compute streaming SHA-256 over stored file
            artifact_digest = sha256_file(target_path)
            size_bytes = target_path.stat().st_size
            artifact_id = str(uuid4())

            # Index artifact in SQLite
            try:
                self.db_manager.save_evidence_artifact(
                    artifact_id=artifact_id,
                    session_id=session_id,
                    rel_path=rel_to_session,
                    media_type=media_type,
                    description=description,
                    artifact_digest=artifact_digest,
                    size_bytes=size_bytes,
                    evidence_id=evidence_id,
                )
            except Exception as e:
                # Rollback unlink
                if target_path.exists():
                    try:
                        target_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                raise StorageError(f"Failed to index artifact in database: {e}") from e

            # Emit ARTIFACT_STORED audit event
            if self.audit_logger is not None:
                try:
                    self.audit_logger.log_event(
                        event_type=AuditEventType.ARTIFACT_STORED,
                        actor="EvidenceStore",
                        session_id=session_id,
                        details={
                            "artifact_id": artifact_id,
                            "rel_path": rel_to_session,
                            "media_type": media_type,
                            "artifact_digest": artifact_digest,
                            "size_bytes": size_bytes,
                        },
                    )
                except Exception:
                    pass

            return ArtifactReference(
                path=rel_to_session,
                media_type=media_type,
                description=description,
            )

    def read_artifact(
        self,
        session_id: Union[str, UUID],
        rel_path: str,
        verify_integrity: bool = True,
    ) -> bytes:
        """Read artifact binary data with cryptographic integrity verification."""
        clean_rel = _validate_safe_relative_path(rel_path)
        sess_dir = self._get_session_dir(session_id)
        target_path = safe_resolve_path(sess_dir, clean_rel)

        if not target_path.is_file():
            raise StorageError(f"Artifact not found: {target_path}")

        if verify_integrity:
            computed_digest = sha256_file(target_path)
            art_meta = self.db_manager.get_evidence_artifact(session_id, clean_rel)
            if art_meta is not None:
                expected_digest = art_meta["artifact_digest"]
                if computed_digest != expected_digest:
                    if self.audit_logger is not None:
                        try:
                            self.audit_logger.log_event(
                                event_type=AuditEventType.EVIDENCE_TAMPERED,
                                actor="EvidenceStore",
                                session_id=session_id,
                                details={
                                    "artifact_path": clean_rel,
                                    "computed_digest": computed_digest,
                                    "registered_digest": expected_digest,
                                    "status": "TAMPER_DETECTED",
                                },
                            )
                        except Exception:
                            pass
                    raise TamperDetectedError(
                        f"Artifact '{clean_rel}' fails integrity verification: "
                        f"computed SHA-256 ({computed_digest}) does not match registered digest ({expected_digest})."
                    )

        try:
            return target_path.read_bytes()
        except OSError as e:
            raise StorageError(f"Failed to read artifact {target_path}: {e}") from e

    # -------------------------------------------------------------
    # Relational Query Interface
    # -------------------------------------------------------------
    def list_evidence_for_session(
        self,
        session_id: Union[str, UUID],
    ) -> List[EvidenceRecord]:
        """Retrieve all evidence records created within a specific session."""
        with self._lock:
            rows = self.db_manager.list_evidence_records(session_id=session_id)
            if rows:
                results: List[EvidenceRecord] = []
                for r in rows:
                    rec = EvidenceRecord.model_validate_json(r["record_json"])
                    results.append(rec)
                return results

            # Fallback for unindexed sessions
            sess_dir = self._get_session_dir(session_id)
            ev_dir = sess_dir / "evidence"
            if not ev_dir.is_dir():
                return []

            results: List[EvidenceRecord] = []
            for ev_file in sorted(ev_dir.glob("*.json")):
                if ev_file.name.startswith("."):
                    continue
                try:
                    content = ev_file.read_text(encoding="utf-8")
                    results.append(EvidenceRecord.model_validate_json(content))
                except Exception as e:
                    raise StorageError(f"Error reading evidence {ev_file}: {e}") from e
            return results

    def get_evidence_by_finding(
        self,
        finding_id: Union[str, UUID],
    ) -> List[EvidenceRecord]:
        """Fetch all evidence records supporting a specific Finding UUID."""
        rows = self.db_manager.list_evidence_records(finding_id=finding_id)
        return [EvidenceRecord.model_validate_json(r["record_json"]) for r in rows]

    def get_evidence_by_hash(
        self,
        content_hash: str,
    ) -> Optional[EvidenceRecord]:
        """Look up evidence record by its canonical SHA-256 digest."""
        rows = self.db_manager.list_evidence_records(content_hash=content_hash)
        if not rows:
            return None
        return EvidenceRecord.model_validate_json(rows[0]["record_json"])

    def get_evidence_for_verdict(
        self,
        verdict_id: Union[str, UUID],
    ) -> List[EvidenceRecord]:
        """Fetch all evidence records contributing to an AssuranceVerdict."""
        rows = self.db_manager.get_evidence_for_verdict(verdict_id)
        return [EvidenceRecord.model_validate_json(r["record_json"]) for r in rows]

    def get_evidence_by_threat_id(
        self,
        threat_id: str,
    ) -> List[EvidenceRecord]:
        """Fetch all evidence records emitted under a specific threat taxonomy ID (e.g. DT-1, MT-3)."""
        rows = self.db_manager.get_evidence_by_threat_id(threat_id)
        return [EvidenceRecord.model_validate_json(r["record_json"]) for r in rows]

    def get_evidence_by_category(
        self,
        category: str,
    ) -> List[EvidenceRecord]:
        """Fetch all evidence records under an assurance category (e.g. DATA_INTEGRITY)."""
        rows = self.db_manager.get_evidence_by_category(category)
        return [EvidenceRecord.model_validate_json(r["record_json"]) for r in rows]

    # -------------------------------------------------------------
    # Forensic Consistency & Audit Engine
    # -------------------------------------------------------------
    def verify_store_consistency(
        self,
        session_id: Optional[Union[str, UUID]] = None,
    ) -> Dict[str, Any]:
        """Perform full bidirectional consistency audit across relational database and physical filesystem.

        Direction 1 (DB → Disk): Verify every DB record has a matching file on disk with correct digest.
        Direction 2 (Disk → DB): Detect orphan files on disk that have no corresponding DB metadata row.
        """
        records = self.db_manager.list_evidence_records(session_id=session_id)
        artifacts = self.db_manager.list_evidence_artifacts(session_id=session_id)

        missing_records: List[str] = []
        tampered_records: List[str] = []
        missing_artifacts: List[str] = []
        tampered_artifacts: List[str] = []

        # --- Direction 1: DB → Disk ---

        # Audit Evidence Records
        db_evidence_paths: set = set()
        for rec_meta in records:
            file_path = Path(rec_meta["file_path"])
            db_evidence_paths.add(str(file_path.resolve()))
            if not file_path.is_file():
                missing_records.append(rec_meta["evidence_id"])
                continue
            computed = sha256_bytes(file_path.read_bytes())
            if computed != rec_meta["content_hash"]:
                tampered_records.append(rec_meta["evidence_id"])

        # Audit Artifacts
        db_artifact_keys: set = set()
        for art_meta in artifacts:
            sess_dir = self._get_session_dir(art_meta["session_id"])
            file_path = safe_resolve_path(sess_dir, art_meta["rel_path"])
            db_artifact_keys.add(str(file_path.resolve()))
            if not file_path.is_file():
                missing_artifacts.append(art_meta["rel_path"])
                continue
            computed_digest = sha256_file(file_path)
            if computed_digest != art_meta["artifact_digest"]:
                tampered_artifacts.append(art_meta["rel_path"])

        # --- Direction 2: Disk → DB orphan detection ---
        orphan_evidence: List[str] = []
        orphan_artifacts: List[str] = []

        # Determine which session directories to scan
        scan_dirs: List[Path] = []
        if session_id is not None:
            sess_dir = self._get_session_dir(session_id)
            if sess_dir.is_dir():
                scan_dirs.append(sess_dir)
        elif self.sessions_dir.is_dir():
            try:
                for child in self.sessions_dir.iterdir():
                    if child.is_dir():
                        # Validate the directory name is safe (no traversal)
                        try:
                            _validate_safe_relative_path(child.name)
                            scan_dirs.append(child)
                        except PathTraversalError:
                            continue
            except OSError:
                pass

        for sess_dir in scan_dirs:
            # Scan evidence/ subdirectory for orphan .json files
            ev_dir = sess_dir / "evidence"
            if ev_dir.is_dir():
                try:
                    for f in ev_dir.iterdir():
                        if not f.is_file():
                            continue
                        # Skip atomic-write temporary files
                        if f.name.startswith(".tmp_"):
                            continue
                        if f.suffix.lower() != ".json":
                            continue
                        resolved = str(f.resolve())
                        if resolved not in db_evidence_paths:
                            # Orphan: file exists on disk but has no DB record
                            try:
                                rel = str(f.relative_to(self.sessions_dir)).replace("\\", "/")
                            except ValueError:
                                rel = f.name
                            orphan_evidence.append(rel)
                except OSError:
                    pass

            # Scan artifacts/ subdirectory for orphan files
            art_dir = sess_dir / "artifacts"
            if art_dir.is_dir():
                try:
                    for f in art_dir.rglob("*"):
                        if not f.is_file():
                            continue
                        # Skip atomic-write temporary files
                        if f.name.startswith(".tmp_"):
                            continue
                        resolved = str(f.resolve())
                        if resolved not in db_artifact_keys:
                            try:
                                rel = str(f.relative_to(self.sessions_dir)).replace("\\", "/")
                            except ValueError:
                                rel = f.name
                            orphan_artifacts.append(rel)
                except OSError:
                    pass

        is_consistent = not (
            missing_records or tampered_records or missing_artifacts or tampered_artifacts
            or orphan_evidence or orphan_artifacts
        )

        return {
            "total_records": len(records),
            "total_artifacts": len(artifacts),
            "missing_records": missing_records,
            "tampered_records": tampered_records,
            "missing_artifacts": missing_artifacts,
            "tampered_artifacts": tampered_artifacts,
            "orphan_evidence": orphan_evidence,
            "orphan_artifacts": orphan_artifacts,
            "is_consistent": is_consistent,
        }

    def close(self) -> None:
        """Clean up open resources."""
        if self._owns_db and self.db_manager is not None:
            self.db_manager.close()
