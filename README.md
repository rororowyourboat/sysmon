# sysmon

Lightweight Linux system health monitor with desktop notifications.

sysmon watches CPU, RAM, disk, temperature, swap, load average, and I/O wait. When metrics cross configurable thresholds it fires desktop notifications via `notify-send`. It also tracks idle Docker containers and watchlisted processes (Zoom, Postman, Slack, etc.) and spawns interactive terminal inspectors to kill or stop them.

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

- `sysmon` - the main monitor
- `sysmon-inspect` - the interactive service inspector (normally launched automatically)

## Usage

```bash
# Start monitoring (default: every 10 seconds)
sysmon

# Verbose mode with custom interval
sysmon --verbose --interval 5

# Auto-open btop on critical alerts
sysmon --btop-on-critical

# Use a custom config file
sysmon --config ~/my-sysmon.toml

# Print the default configuration
sysmon --dump-config
```

## Configuration

sysmon loads configuration from TOML files in this order:

1. Explicit `--config <path>` (error if missing)
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

User config is merged over defaults - you only need to include the values you want to change.

## How it works

Every N seconds, sysmon:

1. **Collects metrics** via [psutil](https://github.com/giampaolo/psutil) - CPU usage, I/O wait, RAM, swap, disk, temperature, and load average
2. **Checks thresholds** - compares metrics against warning/critical limits. CPU has sustained-duration checks to avoid alerting on brief spikes
3. **Sends desktop notifications** via `notify-send` when thresholds are crossed, with a cooldown to prevent spam
4. **Scans for idle services** - Docker containers running longer than configured and watchlisted processes open past their idle timeout
5. **Spawns inspectors** - opens an interactive terminal UI (`sysmon-inspect`) to view resource usage and kill/stop the offending service

## Development

```bash
# Run tests
uv run pytest -q

# Type checking (strict mode)
uv run mypy sysmon/
uv run pyright sysmon/
```

## License

MIT
