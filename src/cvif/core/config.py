"""Configuration management for the CVIF architecture."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field
import yaml

from cvif.core.exceptions import ConfigurationError


class StorageConfig(BaseModel):
    data_dir: Path = Field(default=Path("data"))
    catalog_db_path: Path = Field(default=Path("data/db/catalogue.db"))
    filestore_dir: Path = Field(default=Path("data/assets"))


class AuditConfig(BaseModel):
    audit_dir: Path = Field(default=Path("data/audit"))
    audit_log_path: Path = Field(default=Path("data/audit/audit.jsonl"))
    index_db_path: Path = Field(default=Path("data/db/audit_index.db"))
    auto_verify_on_startup: bool = Field(default=True)


class KeyStoreConfig(BaseModel):
    keystore_dir: Path = Field(default=Path("data/keys"))
    keystore_db_path: Path = Field(default=Path("data/db/keystore.db"))


class EvidenceConfig(BaseModel):
    evidence_dir: Path = Field(default=Path("data/evidence_store"))
    metadata_db_path: Path = Field(default=Path("data/evidence_store/metadata.db"))
    sessions_dir: Path = Field(default=Path("data/evidence_store/sessions"))


class FeatureExtractorConfig(BaseModel):
    primary_backbone: str = Field(default="resnet18")
    weights_path: Path = Field(default=Path("assets/models/resnet18_features.pt"))
    expected_weights_sha256: str = Field(default="")
    allow_statistical_fallback: bool = Field(default=True)
    embedding_dimension: int = Field(default=512)
    fallback_dimension: int = Field(default=128)


class ResourceConfig(BaseModel):
    max_memory_mb: int = Field(default=8192)
    batch_size: int = Field(default=32)
    device: str = Field(default="cpu")
    trigger_search_iterations: int = Field(default=200)


class SystemConfig(BaseModel):
    offline_mode: bool = Field(default=True)
    air_gapped: bool = Field(default=True)
    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")


class LoggingConfig(BaseModel):
    log_level: str = Field(default="INFO")
    log_dir: Path = Field(default=Path("data/logs"))
    log_file: Path = Field(default=Path("data/logs/cvif.log"))
    json_format: bool = Field(default=False)


class SecurityConfig(BaseModel):
    air_gap_enforced: bool = Field(default=True)
    allow_unverified_keys: bool = Field(default=False)
    strict_hash_checks: bool = Field(default=True)


class DistributionShiftConfig(BaseModel):
    mmd_threshold: float = Field(default=0.15)
    wasserstein_threshold: float = Field(default=0.20)
    ks_alpha: float = Field(default=0.05)
    class_tv_threshold: float = Field(default=0.25)
    min_sample_size: int = Field(default=15)
    batch_size: int = Field(default=250)
    subpopulation_clustering: bool = Field(default=True)
    max_variance_dimensions: int = Field(default=16)


class AssuranceConfig(BaseModel):
    quarantine_threshold: float = Field(default=0.70, ge=0.0, le=1.0)
    review_threshold: float = Field(default=0.30, ge=0.0, le=1.0)
    critical_veto_enabled: bool = Field(default=True)
    min_confidence_for_veto: float = Field(default=0.50, ge=0.0, le=1.0)
    dimension_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "data_integrity": 0.25,
            "model_integrity": 0.35,
            "inference_provenance": 0.25,
            "distribution_shift": 0.15,
        }
    )
    severity_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "CRITICAL": 1.00,
            "HIGH": 0.80,
            "MEDIUM": 0.50,
            "LOW": 0.20,
            "INFORMATIONAL": 0.00,
        }
    )
    require_all_mandatory_checks: bool = Field(default=False)


class APIConfig(BaseModel):
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000)
    cors_origins: List[str] = Field(default_factory=list)
    api_key_enabled: bool = Field(default=False)
    api_keys: List[str] = Field(default_factory=list)
    enable_docs: bool = Field(default=False)
    allow_remote_binding: bool = Field(default=False)
    max_payload_size_mb: int = Field(default=10)
    timeout_seconds: int = Field(default=60)


class AppConfig(BaseModel):
    system: SystemConfig = Field(default_factory=SystemConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    keystore: KeyStoreConfig = Field(default_factory=KeyStoreConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    feature_extractor: FeatureExtractorConfig = Field(default_factory=FeatureExtractorConfig)
    resources: ResourceConfig = Field(default_factory=ResourceConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    distribution_shift: DistributionShiftConfig = Field(default_factory=DistributionShiftConfig)
    assurance: AssuranceConfig = Field(default_factory=AssuranceConfig)
    api: APIConfig = Field(default_factory=APIConfig)

    def resolve_paths(self, base_dir: Union[str, Path]) -> "AppConfig":
        """Resolve all relative paths against a designated base directory."""
        base = Path(base_dir).resolve()
        data = self.model_dump()
        for section in ["storage", "audit", "keystore", "evidence", "feature_extractor", "logging"]:
            if section in data:
                for k, v in data[section].items():
                    if (k.endswith("_path") or k.endswith("_dir") or k.endswith("_file")) and v:
                        p = Path(v)
                        if not p.is_absolute():
                            data[section][k] = base / p
        return AppConfig.model_validate(data)


# Alias
CVIFConfig = AppConfig


def load_config(config_path: Optional[Union[str, Path]] = None) -> AppConfig:
    """Load configuration from a YAML file, environment variables, or defaults."""
    env_path = os.environ.get("CVIF_CONFIG_PATH")
    target_path = Path(config_path or env_path or "config/default_config.yaml")

    if target_path.exists():
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f) or {}
            return AppConfig.model_validate(raw_data)
        except Exception as e:
            raise ConfigurationError(
                f"Failed to parse configuration from {target_path}: {e}",
                details={"path": str(target_path), "error": str(e)},
            ) from e

    # Fall back to default configuration
    return AppConfig()
