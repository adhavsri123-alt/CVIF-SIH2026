"""Unit tests for configuration loading, validation, and path resolution."""

from pathlib import Path
import pytest
import yaml

from cvif.core.config import AppConfig, load_config
from cvif.core.exceptions import ConfigurationError


def test_default_config_loading():
    cfg = AppConfig()
    assert cfg.system.offline_mode is True
    assert cfg.system.air_gapped is True
    assert cfg.storage.data_dir == Path("data")


def test_config_path_resolution(temp_dir: Path):
    cfg = AppConfig()
    resolved = cfg.resolve_paths(temp_dir)

    assert resolved.storage.data_dir.is_absolute()
    assert str(resolved.storage.data_dir).startswith(str(temp_dir.resolve()))
    assert resolved.audit.audit_log_path.is_absolute()
    assert str(resolved.audit.audit_log_path).startswith(str(temp_dir.resolve()))


def test_config_from_yaml_file(temp_dir: Path):
    yaml_file = temp_dir / "custom_config.yaml"
    custom_data = {
        "system": {
            "environment": "production",
            "offline_mode": True,
            "air_gapped": True,
            "log_level": "DEBUG",
        },
        "resources": {
            "batch_size": 64,
            "device": "cpu",
        },
    }
    with yaml_file.open("w", encoding="utf-8") as f:
        yaml.dump(custom_data, f)

    loaded = load_config(yaml_file)
    assert loaded.system.environment == "production"
    assert loaded.system.log_level == "DEBUG"
    assert loaded.resources.batch_size == 64


def test_config_malformed_yaml(temp_dir: Path):
    bad_file = temp_dir / "bad.yaml"
    bad_file.write_text("system: [unbalanced brackets", encoding="utf-8")

    with pytest.raises(ConfigurationError):
        load_config(bad_file)
