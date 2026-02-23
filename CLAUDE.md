# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

sysmon is a lightweight system health monitor for Linux desktops. It watches OS metrics (CPU, RAM, disk, temperature, etc.) and idle services (Docker containers, watchlisted processes), sends desktop notifications via `notify-send`, and spawns interactive terminal inspectors with kill/stop options.

## Commands

```bash
# Run the monitor
uv run python sysmon/monitor.py
uv run python sysmon/monitor.py --verbose --interval 5 --btop-on-critical

# Run the inspector standalone (normally spawned by the monitor)
uv run python sysmon/inspect_service.py --process zoom
uv run python sysmon/inspect_service.py --docker financial_db

# Add dependencies
uv add <package>
```

There are no tests, linter, or build step.

## Architecture

**Two-file design** — all logic lives in `sysmon/monitor.py` and `sysmon/inspect_service.py`.

### monitor.py — Main Loop

`main()` runs a loop every N seconds:
1. `collect_metrics()` — gathers 7 system metrics via psutil + os
2. `check_thresholds()` — compares against `THRESHOLDS` dict, returns `list[Alert]`. Uses `SustainedTracker` for metrics that must stay elevated before alerting (e.g. CPU >80% for 30s)
3. `send_alert()` — desktop notification; optionally opens btop on critical
4. `check_idle_services()` — scans Docker containers (`docker ps`) and watchlisted processes (`psutil.process_iter`), returns `list[ServiceAlert]`
5. `send_service_alert()` — notification + spawns `inspect_service.py` in a new terminal

All configuration is in module-level dicts at the top: `THRESHOLDS`, `SUSTAINED`, `WATCHLIST`, `DOCKER_IDLE_MINUTES`, `ALERT_COOLDOWN`.

### inspect_service.py — Interactive Kill UI

Launched by the monitor as a subprocess in a new terminal (`start_new_session=True`). No shared state with the monitor — receives service name via CLI args. Two modes:
- `--process <name>`: finds matching PIDs via psutil, shows resource table, offers SIGTERM/SIGKILL/dismiss
- `--docker <name>`: runs `docker stats/inspect/top`, offers `docker stop`/`docker kill`/dismiss

### Terminal detection

`_detect_terminal()` tries ghostty → gnome-terminal → xterm → x-terminal-emulator, using `shutil.which()`.

## Key Design Decisions

- **Alert cooldown** (300s) prevents notification spam for the same metric+severity
- **Sustained checks** prevent flaky single-sample spikes from triggering false alarms
- **Graceful degradation** — missing sensors, Docker not running, or no terminal emulator won't crash the monitor
- **Watchlist `idle_minutes: 0`** means "track in verbose output but never nag" (used for Chrome, VS Code, Firefox)
