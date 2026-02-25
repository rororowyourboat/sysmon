"""Configuration loading for sysmon.

Loads settings from TOML config files with sensible defaults.
Search order: explicit --config path → ~/.config/sysmon/config.toml → defaults only.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "alert_cooldown": 300,
    "docker_idle_minutes": 60,
    "thresholds": {
        "cpu_percent": {"warning": 80.0, "critical": 95.0},
        "iowait": {"warning": 15.0, "critical": 30.0},
        "ram_percent": {"warning": 85.0, "critical": 95.0},
        "swap_percent": {"warning": 50.0, "critical": 80.0},
        "disk_percent": {"warning": 85.0, "critical": 95.0},
        "cpu_temp": {"warning": 80.0, "critical": 90.0},
        "load_per_cpu": {"warning": 1.0, "critical": 2.0},
    },
    "sustained": {
        "cpu_percent": {"warning": 30, "critical": 15},
        "cpu_temp": {"warning": 60, "critical": 30},
    },
    "watchlist": {
        "zoom": {"label": "Zoom", "idle_minutes": 30, "active_cpu": 5.0},
        "postman": {"label": "Postman", "idle_minutes": 60},
        "slack": {"label": "Slack", "idle_minutes": 120},
        "teams": {"label": "Teams", "idle_minutes": 60, "active_cpu": 5.0},
        "obs": {"label": "OBS Studio", "idle_minutes": 30, "active_cpu": 3.0},
        "discord": {"label": "Discord", "idle_minutes": 120, "active_cpu": 3.0},
        "dbeaver": {"label": "DBeaver", "idle_minutes": 60},
        "code": {"label": "VS Code", "idle_minutes": 0},
        "firefox": {"label": "Firefox", "idle_minutes": 0},
        "chrome": {"label": "Chrome", "idle_minutes": 0},
    },
}

_DEFAULT_PATH = Path.home() / ".config" / "sysmon" / "config.toml"


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge overlay into base. Nested dicts are merged at the first level only."""
    merged = dict(base)
    for key, value in overlay.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            # Merge one level: overlay sub-keys into base sub-keys
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load configuration, merging user TOML over defaults.

    Args:
        path: Explicit config file path (from --config). If None, tries the
              default location ~/.config/sysmon/config.toml.

    Returns:
        Merged configuration dict.

    Raises:
        SystemExit: If an explicit path doesn't exist or can't be parsed.
    """
    if path is not None:
        if not path.is_file():
            print(f"sysmon: config file not found: {path}", file=sys.stderr)
            raise SystemExit(1)
        try:
            user_config = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as e:
            print(f"sysmon: invalid TOML in {path}: {e}", file=sys.stderr)
            raise SystemExit(1) from e
        return _deep_merge(DEFAULT_CONFIG, user_config)

    # Try default location silently
    if _DEFAULT_PATH.is_file():
        try:
            user_config = tomllib.loads(_DEFAULT_PATH.read_text(encoding="utf-8"))
            return _deep_merge(DEFAULT_CONFIG, user_config)
        except tomllib.TOMLDecodeError:
            print(
                f"sysmon: warning: ignoring invalid TOML in {_DEFAULT_PATH}",
                file=sys.stderr,
            )

    return dict(DEFAULT_CONFIG)


def dump_default_config() -> str:
    """Return the default configuration as a TOML string."""
    lines = [
        "# sysmon configuration",
        "# Place this file at ~/.config/sysmon/config.toml",
        "",
        f"alert_cooldown = {DEFAULT_CONFIG['alert_cooldown']}",
        f"docker_idle_minutes = {DEFAULT_CONFIG['docker_idle_minutes']}",
        "",
    ]

    # Thresholds
    for metric, levels in DEFAULT_CONFIG["thresholds"].items():
        lines.append(f"[thresholds.{metric}]")
        lines.append(f"warning = {levels['warning']}")
        lines.append(f"critical = {levels['critical']}")
        lines.append("")

    # Sustained
    for metric, levels in DEFAULT_CONFIG["sustained"].items():
        lines.append(f"[sustained.{metric}]")
        lines.append(f"warning = {levels['warning']}")
        lines.append(f"critical = {levels['critical']}")
        lines.append("")

    # Watchlist
    for key, cfg in DEFAULT_CONFIG["watchlist"].items():
        lines.append(f"[watchlist.{key}]")
        lines.append(f'label = "{cfg["label"]}"')
        lines.append(f"idle_minutes = {cfg['idle_minutes']}")
        lines.append("")

    return "\n".join(lines) + "\n"
