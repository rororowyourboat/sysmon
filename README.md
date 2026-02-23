# sysmon

[![CI](https://github.com/rororowyourboat/sysmon/actions/workflows/ci.yml/badge.svg)](https://github.com/rororowyourboat/sysmon/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Strict typing: mypy + pyright](https://img.shields.io/badge/typing-strict-blue.svg)](https://mypy-lang.org/)
[![Built with AI](https://img.shields.io/badge/built%20with-AI%20%2B%20human%20review-blueviolet.svg)](#built-with-ai)

Lightweight Linux system health monitor with desktop notifications.

sysmon watches CPU, RAM, disk, temperature, swap, load average, and I/O wait. When metrics cross configurable thresholds it fires desktop notifications via `notify-send`. It also tracks idle Docker containers and watchlisted processes (Zoom, Postman, Slack, etc.) and spawns interactive terminal inspectors to kill or stop them.

## Features

- **7 system metrics** — CPU, RAM, swap, disk, temperature, load average, I/O wait
- **Smart alerting** — sustained-duration checks prevent false alarms from brief spikes
- **Desktop notifications** — warning and critical alerts via `notify-send`
- **Docker monitoring** — reminds you about forgotten containers
- **Process watchlist** — nags about idle apps (Zoom, Postman, Slack, etc.)
- **Interactive inspectors** — terminal UI to kill/stop offending services
- **TOML configuration** — externalize all thresholds, watchlist, and settings
- **Strictly typed** — passes mypy and pyright in strict mode

## Requirements

- Python 3.11+
- Linux with `notify-send` (libnotify) for desktop notifications
- Docker (optional, for container monitoring)

## Installation

```bash
# Clone and install
git clone https://github.com/rororowyourboat/sysmon.git
cd sysmon
uv tool install .

# Or install in development mode
uv pip install -e .
```

After installation, two commands are available:

- `sysmon` — the main monitor
- `sysmon-inspect` — the interactive service inspector (normally launched automatically)

## Quick start

```bash
# Start monitoring with terminal output
sysmon --verbose

# Customize the check interval (seconds)
sysmon --verbose --interval 5

# Auto-open btop on critical alerts
sysmon --btop-on-critical

# Use a custom config file
sysmon --config ~/my-sysmon.toml

# Print the default configuration as TOML
sysmon --dump-config
```

## Configuration

sysmon loads configuration from TOML files in this order:

1. Explicit `--config <path>` (error if file missing)
2. `~/.config/sysmon/config.toml` (silently ignored if missing)
3. Built-in defaults

Bootstrap a config file:

```bash
mkdir -p ~/.config/sysmon
sysmon --dump-config > ~/.config/sysmon/config.toml
```

### Sample configuration

```toml
alert_cooldown = 300        # seconds between repeated alerts
docker_idle_minutes = 60    # remind after container running this long

[thresholds.cpu_percent]
warning = 80.0
critical = 95.0

[thresholds.ram_percent]
warning = 85.0
critical = 95.0

[thresholds.disk_percent]
warning = 85.0
critical = 95.0

[thresholds.cpu_temp]
warning = 80.0
critical = 90.0

[sustained.cpu_percent]
warning = 30    # seconds above threshold before alerting
critical = 15

[watchlist.zoom]
label = "Zoom"
idle_minutes = 30   # nag after 30 min

[watchlist.code]
label = "VS Code"
idle_minutes = 0    # 0 = track but never nag
```

User config is merged over defaults — you only need to include the values you want to change.

## How it works

Every N seconds, sysmon:

1. **Collects metrics** via [psutil](https://github.com/giampaolo/psutil) — CPU usage, I/O wait, RAM, swap, disk, temperature, and load average
2. **Checks thresholds** — compares metrics against warning/critical limits. CPU has sustained-duration checks to avoid alerting on brief spikes
3. **Sends desktop notifications** via `notify-send` when thresholds are crossed, with a cooldown to prevent spam
4. **Scans for idle services** — Docker containers running longer than configured and watchlisted processes open past their idle timeout
5. **Spawns inspectors** — opens an interactive terminal UI (`sysmon-inspect`) to view resource usage and kill/stop the offending service

## Development

```bash
# Install dev dependencies
uv sync

# Run tests
uv run pytest -q

# Type checking (strict mode)
uv run mypy sysmon/
uv run pyright sysmon/
```

## Built with AI

This project was built using AI coding CLI tools ([Claude Code](https://claude.ai/claude-code)) with human-driven test-driven development and code review. Every feature was specified, reviewed, and validated by a human — the AI accelerated the writing, the human ensured the quality.

## License

[MIT](LICENSE)
