"""Tests for sysmon.config."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from sysmon.config import DEFAULT_CONFIG, _deep_merge, dump_default_config, load_config


class TestLoadConfigDefaults:
    def test_defaults_returned_when_no_file(self, tmp_path: Path) -> None:
        # Point to a nonexistent path so the default location isn't used
        cfg = load_config(None)
        assert cfg["alert_cooldown"] == 300
        assert cfg["docker_idle_minutes"] == 60
        assert "cpu_percent" in cfg["thresholds"]
        assert "zoom" in cfg["watchlist"]

    def test_all_default_keys_present(self) -> None:
        cfg = load_config(None)
        assert set(cfg.keys()) == set(DEFAULT_CONFIG.keys())


class TestTomlOverlay:
    def test_overrides_threshold(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "config.toml"
        toml_file.write_text(
            "[thresholds.cpu_percent]\nwarning = 70.0\ncritical = 90.0\n"
        )
        cfg = load_config(toml_file)
        assert cfg["thresholds"]["cpu_percent"]["warning"] == 70.0
        assert cfg["thresholds"]["cpu_percent"]["critical"] == 90.0
        # Other thresholds remain at defaults
        assert cfg["thresholds"]["ram_percent"]["warning"] == 85.0

    def test_adds_watchlist_entry(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "config.toml"
        toml_file.write_text(
            '[watchlist.spotify]\nlabel = "Spotify"\nidle_minutes = 45\n'
        )
        cfg = load_config(toml_file)
        assert cfg["watchlist"]["spotify"]["label"] == "Spotify"
        # Defaults preserved
        assert "zoom" in cfg["watchlist"]
        assert "chrome" in cfg["watchlist"]

    def test_omitted_entries_preserved(self, tmp_path: Path) -> None:
        """Omitting watchlist entries in user config keeps them from defaults."""
        toml_file = tmp_path / "config.toml"
        toml_file.write_text("alert_cooldown = 600\n")
        cfg = load_config(toml_file)
        assert cfg["alert_cooldown"] == 600
        # All default watchlist entries still present
        assert len(cfg["watchlist"]) == len(DEFAULT_CONFIG["watchlist"])

    def test_overrides_scalar(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "config.toml"
        toml_file.write_text("docker_idle_minutes = 120\n")
        cfg = load_config(toml_file)
        assert cfg["docker_idle_minutes"] == 120


class TestExplicitPath:
    def test_explicit_path_used(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "custom.toml"
        cfg_file.write_text("alert_cooldown = 999\n")
        cfg = load_config(cfg_file)
        assert cfg["alert_cooldown"] == 999

    def test_missing_explicit_path_errors(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.toml"
        with pytest.raises(SystemExit):
            load_config(missing)

    def test_invalid_toml_errors(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.toml"
        bad_file.write_text("this is [not valid toml\n")
        with pytest.raises(SystemExit):
            load_config(bad_file)


class TestDumpDefaultConfig:
    def test_is_valid_toml(self) -> None:
        output = dump_default_config()
        parsed = tomllib.loads(output)
        assert "alert_cooldown" in parsed
        assert "thresholds" in parsed
        assert "watchlist" in parsed

    def test_roundtrips_defaults(self) -> None:
        output = dump_default_config()
        parsed = tomllib.loads(output)
        assert parsed["alert_cooldown"] == DEFAULT_CONFIG["alert_cooldown"]
        assert parsed["thresholds"]["cpu_percent"]["warning"] == 80.0
        assert parsed["watchlist"]["zoom"]["label"] == "Zoom"


class TestDeepMerge:
    def test_scalar_overwrite(self) -> None:
        result = _deep_merge({"a": 1, "b": 2}, {"a": 10})
        assert result == {"a": 10, "b": 2}

    def test_nested_dict_merge(self) -> None:
        base = {"x": {"a": 1, "b": 2}}
        overlay = {"x": {"b": 3, "c": 4}}
        result = _deep_merge(base, overlay)
        assert result["x"] == {"a": 1, "b": 3, "c": 4}

    def test_new_key_added(self) -> None:
        result = _deep_merge({"a": 1}, {"b": 2})
        assert result == {"a": 1, "b": 2}
