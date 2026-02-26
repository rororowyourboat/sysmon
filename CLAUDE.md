# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

sysmon is a lightweight system health monitor for Linux desktops. It watches OS metrics (CPU, RAM, disk, temperature, etc.) and idle services (Docker containers, watchlisted processes), sends desktop notifications via `notify-send`, and spawns interactive terminal inspectors with kill/stop options.

## Commands

```bash
# Run the monitor (via entry point)
uv run sysmon
uv run sysmon --verbose --interval 5 --btop-on-critical
uv run sysmon --config path/to/config.toml
uv run sysmon --dump-config  # print default config as TOML

# Run the inspector standalone (normally spawned by the monitor)
uv run sysmon-inspect --process zoom
uv run sysmon-inspect --docker financial_db

# Tests and type checking
uv run pytest -q
uv run pytest tests/test_monitor.py -q          # single file
uv run pytest tests/test_monitor.py::test_name -q  # single test
uv run mypy sysmon/
uv run pyright sysmon/

# Linting
uv run ruff check sysmon/ tests/
uv run ruff check --fix sysmon/ tests/  # auto-fix

# Add dependencies
uv add <package>
```

## Architecture

**Three-file design** — `sysmon/monitor.py`, `sysmon/config.py`, and `sysmon/inspect_service.py`.

### config.py — Configuration Loading

- `DEFAULT_CONFIG` dict holds all default thresholds, sustained settings, watchlist, cooldowns
- `load_config(path)` loads TOML and deep-merges over defaults; search order: explicit `--config` → `~/.config/sysmon/config.toml` → defaults only
- `dump_default_config()` returns defaults as a valid TOML string
- Uses `tomllib` (stdlib since 3.11), no write dependency needed

### monitor.py — Main Loop

Module-level config variables (`thresholds`, `sustained`, `alert_cooldown`, `watchlist`, `docker_idle_minutes`, `docker_whitelist`) are initialized from `DEFAULT_CONFIG` and overwritten by `_apply_config()` at startup.

`main()` runs a loop every N seconds:
1. `collect_metrics()` — gathers 7 system metrics via psutil + os
2. `check_thresholds()` — compares against `thresholds` dict, returns `list[Alert]`. Uses `SustainedTracker` for metrics that must stay elevated before alerting (e.g. CPU >80% for 30s)
3. `send_alert()` — desktop notification + writes to rotating alert log (`~/.local/state/sysmon/alerts.log`); optionally opens btop on critical
4. `check_idle_services()` — scans Docker containers (`docker ps`) and watchlisted processes (`psutil.process_iter`), returns `list[ServiceAlert]`
5. `send_service_alert()` — notification + spawns `inspect_service.py` in a new terminal

### inspect_service.py — Interactive Kill UI

Launched by the monitor as a subprocess in a new terminal (`start_new_session=True`). No shared state with the monitor — receives service name via CLI args. Two modes:
- `--process <name>`: finds matching PIDs via psutil, shows resource table, offers SIGTERM/SIGKILL/dismiss
- `--docker <name>`: runs `docker stats/inspect/top`, offers `docker stop`/`docker kill`/dismiss

### Terminal detection

`_detect_terminal()` tries ghostty → gnome-terminal → xterm → x-terminal-emulator, using `shutil.which()`.

## Key Design Decisions

- **Config externalization** — all hardcoded values moved to `config.py` with TOML overlay support; `--dump-config` bootstraps a config file
- **Alert cooldown** (300s) prevents notification spam for the same metric+severity
- **Sustained checks** prevent flaky single-sample spikes from triggering false alarms
- **Graceful degradation** — missing sensors, Docker not running, or no terminal emulator won't crash the monitor
- **Watchlist `idle_minutes: 0`** means "track in verbose output but never nag" (used for Chrome, VS Code, Firefox)
- **`docker_whitelist`** — container names (e.g. `["ollama"]`) that skip idle checks entirely, for persistent services that should always run
- **Alert log** — `~/.local/state/sysmon/alerts.log`, rotating at ~500KB with 1 backup; provides short-term history for debugging recurring alerts
