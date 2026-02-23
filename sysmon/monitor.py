"""Lightweight system health monitor with desktop notifications."""

import argparse
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field

import psutil


# ── Thresholds ──────────────────────────────────────────────────────────────

THRESHOLDS: dict[str, dict[str, float]] = {
    "cpu_percent":    {"warning": 80.0, "critical": 95.0},
    "iowait":         {"warning": 15.0, "critical": 30.0},
    "ram_percent":     {"warning": 85.0, "critical": 95.0},
    "swap_percent":    {"warning": 50.0, "critical": 80.0},
    "disk_percent":    {"warning": 85.0, "critical": 95.0},
    "cpu_temp":        {"warning": 80.0, "critical": 90.0},
    "load_per_cpu":    {"warning": 1.0,  "critical": 2.0},  # multiplier of nproc
}

# Sustained thresholds: metric must stay above threshold for this many seconds
SUSTAINED: dict[str, dict[str, int]] = {
    "cpu_percent": {"warning": 30, "critical": 15},
}

ALERT_COOLDOWN = 300  # seconds between repeated alerts for the same metric+severity

# ── Idle service detection ──────────────────────────────────────────────────

# Processes to nag about if they're running — add/remove as needed.
# Keys are matched case-insensitively against process names.
# "idle_minutes" = how long before the first reminder fires.
WATCHLIST: dict[str, dict] = {
    "zoom":         {"label": "Zoom",           "idle_minutes": 30},
    "postman":      {"label": "Postman",        "idle_minutes": 60},
    "slack":        {"label": "Slack",          "idle_minutes": 120},
    "teams":        {"label": "Teams",          "idle_minutes": 60},
    "obs":          {"label": "OBS Studio",     "idle_minutes": 30},
    "discord":      {"label": "Discord",        "idle_minutes": 120},
    "dbeaver":      {"label": "DBeaver",        "idle_minutes": 60},
    "code":         {"label": "VS Code",        "idle_minutes": 0},  # 0 = never nag
    "firefox":      {"label": "Firefox",        "idle_minutes": 0},
    "chrome":       {"label": "Chrome",         "idle_minutes": 0},
}

# Docker: remind after this many minutes of a container running
DOCKER_IDLE_MINUTES = 60

METRIC_LABELS: dict[str, str] = {
    "cpu_percent":  "CPU Usage",
    "iowait":       "I/O Wait",
    "ram_percent":   "RAM Usage",
    "swap_percent":  "Swap Usage",
    "disk_percent":  "Disk Usage (/)",
    "cpu_temp":      "CPU Temperature",
    "load_per_cpu":  "Load Average",
}


# ── Data types ──────────────────────────────────────────────────────────────

@dataclass
class Alert:
    metric: str
    severity: str  # "warning" or "critical"
    value: float
    threshold: float
    unit: str


@dataclass
class SustainedTracker:
    """Tracks when a metric first exceeded a threshold."""
    exceeded_since: dict[str, float] = field(default_factory=dict)  # key -> timestamp

    def check(self, key: str, is_exceeded: bool, required_seconds: int) -> bool:
        now = time.monotonic()
        if is_exceeded:
            self.exceeded_since.setdefault(key, now)
            return (now - self.exceeded_since[key]) >= required_seconds
        else:
            self.exceeded_since.pop(key, None)
            return False


# ── Metric collection ───────────────────────────────────────────────────────

def collect_metrics() -> dict[str, float | None]:
    """Gather all system metrics. Returns None for unavailable sensors."""
    cpu = psutil.cpu_percent(interval=1)
    cpu_times = psutil.cpu_times_percent(interval=0)
    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    load1, _, _ = os.getloadavg()
    nproc = os.cpu_count() or 1

    # CPU temperature — may not be available on all systems
    temp = None
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            # Try common sensor names
            for name in ("coretemp", "k10temp", "acpitz", "cpu_thermal"):
                if name in temps and temps[name]:
                    temp = max(t.current for t in temps[name])
                    break
            # Fallback: take first available sensor
            if temp is None:
                first = next(iter(temps.values()))
                if first:
                    temp = max(t.current for t in first)
    except (AttributeError, OSError):
        pass

    return {
        "cpu_percent":  cpu,
        "iowait":       getattr(cpu_times, "iowait", 0.0),
        "ram_percent":   ram.percent,
        "swap_percent":  swap.percent,
        "disk_percent":  disk.percent,
        "cpu_temp":      temp,
        "load_per_cpu":  load1 / nproc,
    }


# ── Threshold checking ──────────────────────────────────────────────────────

def check_thresholds(
    metrics: dict[str, float | None],
    sustained: SustainedTracker,
) -> list[Alert]:
    """Compare metrics against thresholds and return any triggered alerts."""
    alerts: list[Alert] = []

    units = {
        "cpu_percent": "%", "iowait": "%", "ram_percent": "%",
        "swap_percent": "%", "disk_percent": "%", "cpu_temp": "°C",
        "load_per_cpu": "x",
    }

    for metric, value in metrics.items():
        if value is None:
            continue
        thresh = THRESHOLDS.get(metric)
        if not thresh:
            continue

        # Check critical first, then warning
        for severity in ("critical", "warning"):
            limit = thresh[severity]
            exceeded = value >= limit

            # For sustained metrics, check duration
            if metric in SUSTAINED:
                key = f"{metric}:{severity}"
                required = SUSTAINED[metric][severity]
                if not sustained.check(key, exceeded, required):
                    continue
            elif not exceeded:
                continue

            alerts.append(Alert(
                metric=metric,
                severity=severity,
                value=value,
                threshold=limit,
                unit=units.get(metric, ""),
            ))
            break  # Only report highest severity per metric

    return alerts


# ── Desktop notifications ───────────────────────────────────────────────────

def send_alert(alert: Alert) -> None:
    """Send a desktop notification via notify-send."""
    label = METRIC_LABELS.get(alert.metric, alert.metric)
    icon = "dialog-warning" if alert.severity == "warning" else "dialog-error"
    urgency = "normal" if alert.severity == "warning" else "critical"

    title = f"[{alert.severity.upper()}] {label}"
    body = f"{alert.value:.1f}{alert.unit} (threshold: {alert.threshold:.0f}{alert.unit})"

    try:
        subprocess.run(
            ["notify-send", f"--urgency={urgency}", f"--icon={icon}",
             "--app-name=sysmon", title, body],
            check=False,
            timeout=5,
        )
    except FileNotFoundError:
        print(f"  !! notify-send not found — {title}: {body}")
    except subprocess.TimeoutExpired:
        pass


# ── btop integration ────────────────────────────────────────────────────────

def _detect_terminal() -> list[str]:
    """Return the command prefix to open a new terminal window."""
    for cmd, args in [
        ("ghostty", ["ghostty", "-e"]),
        ("gnome-terminal", ["gnome-terminal", "--"]),
        ("xterm", ["xterm", "-e"]),
        ("x-terminal-emulator", ["x-terminal-emulator", "-e"]),
    ]:
        if shutil.which(cmd):
            return args
    return []


_btop_opened_at: float = 0.0  # prevent spamming btop windows

def open_btop() -> None:
    """Launch btop in a new terminal window (rate-limited to once per 60s)."""
    global _btop_opened_at
    now = time.time()
    if now - _btop_opened_at < 60:
        return  # already opened recently

    terminal = _detect_terminal()
    if not terminal:
        print("  !! No supported terminal found for btop launch")
        return

    try:
        subprocess.Popen(
            [*terminal, "btop"],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _btop_opened_at = now
        print("  >> Opened btop for investigation")
    except FileNotFoundError:
        print("  !! btop not found — install with: sudo apt install btop")


# ── Idle service / Docker detection ─────────────────────────────────────────

def _get_running_docker_containers() -> list[dict[str, str]]:
    """Return list of running Docker containers with name, image, and uptime."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.RunningFor}}"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    containers = []
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            containers.append({
                "name": parts[0],
                "image": parts[1],
                "status": parts[2],
                "running_for": parts[3] if len(parts) > 3 else "",
            })
    return containers


def _parse_docker_uptime_minutes(running_for: str) -> int:
    """Rough parse of Docker's 'running for' string into minutes."""
    s = running_for.lower()
    # e.g. "About an hour", "2 hours", "3 days", "45 minutes", "30 seconds"
    minutes = 0
    if "day" in s:
        try:
            minutes += int("".join(c for c in s.split("day")[0] if c.isdigit()) or 1) * 1440
        except ValueError:
            minutes += 1440
    if "hour" in s:
        try:
            minutes += int("".join(c for c in s.split("hour")[0].split()[-1] if c.isdigit()) or 1) * 60
        except ValueError:
            minutes += 60
    if "minute" in s:
        try:
            minutes += int("".join(c for c in s.split("minute")[0].split()[-1] if c.isdigit()) or 1)
        except ValueError:
            minutes += 1
    return minutes


@dataclass
class ServiceAlert:
    """An idle service or Docker container that triggered a reminder."""
    kind: str           # "docker" or "process"
    name: str           # container name or watchlist key
    label: str          # human-readable label
    detail: str         # "Running for 4 days (postgres:16-alpine)"
    age_str: str        # "4h 12m"


def check_idle_services(
    last_alerted: dict[str, float],
) -> list[ServiceAlert]:
    """Check for forgotten services. Returns list of ServiceAlerts."""
    results: list[ServiceAlert] = []
    now = time.time()

    # ── Docker containers ───────────────────────────────────────────────
    if DOCKER_IDLE_MINUTES > 0:
        containers = _get_running_docker_containers()
        for c in containers:
            uptime = _parse_docker_uptime_minutes(c["running_for"])
            if uptime >= DOCKER_IDLE_MINUTES:
                key = f"docker:{c['name']}"
                if now - last_alerted.get(key, 0) >= ALERT_COOLDOWN:
                    results.append(ServiceAlert(
                        kind="docker",
                        name=c["name"],
                        label=f"Docker: {c['name']}",
                        detail=f"Running for {c['running_for']} ({c['image']})",
                        age_str=c["running_for"],
                    ))
                    last_alerted[key] = now

    # ── Watchlisted processes ───────────────────────────────────────────
    seen: set[str] = set()
    for proc in psutil.process_iter(["name", "create_time"]):
        try:
            pname = (proc.info["name"] or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        for watch_key, cfg in WATCHLIST.items():
            if cfg["idle_minutes"] <= 0:
                continue
            if watch_key in seen:
                continue
            if watch_key not in pname:
                continue

            age_minutes = (now - proc.info["create_time"]) / 60
            if age_minutes >= cfg["idle_minutes"]:
                alert_key = f"proc:{watch_key}"
                if now - last_alerted.get(alert_key, 0) >= ALERT_COOLDOWN:
                    hrs = int(age_minutes // 60)
                    mins = int(age_minutes % 60)
                    age_str = f"{hrs}h {mins}m" if hrs else f"{mins}m"
                    results.append(ServiceAlert(
                        kind="process",
                        name=watch_key,
                        label=f"Still running: {cfg['label']}",
                        detail=f"Open for {age_str}",
                        age_str=age_str,
                    ))
                    last_alerted[alert_key] = now
            seen.add(watch_key)

    return results


def _get_inspector_cmd(alert: ServiceAlert) -> list[str]:
    """Build the command to launch the inspect_service script."""
    python = sys.executable
    module_dir = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(module_dir, "inspect_service.py")

    if alert.kind == "docker":
        return [python, script, "--docker", alert.name]
    else:
        return [python, script, "--process", alert.name]


def send_service_alert(alert: ServiceAlert) -> None:
    """Send desktop notification AND open an inspector terminal for the service."""
    # Desktop notification
    title = alert.label
    body = f"{alert.detail}\nOpening inspector..."
    try:
        subprocess.run(
            ["notify-send", "--urgency=normal", "--icon=dialog-information",
             "--app-name=sysmon", title, body],
            check=False, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Open inspector in a new terminal
    terminal = _detect_terminal()
    if not terminal:
        print(f"  !! No terminal found — run manually: {' '.join(_get_inspector_cmd(alert))}")
        return

    try:
        subprocess.Popen(
            [*terminal, *_get_inspector_cmd(alert)],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pass


# ── Verbose output ──────────────────────────────────────────────────────────

def print_metrics(metrics: dict[str, float | None]) -> None:
    """Print current metrics to terminal."""
    ts = time.strftime("%H:%M:%S")
    nproc = os.cpu_count() or 1
    lines = [f"\n── sysmon [{ts}] ──"]

    fmt = {
        "cpu_percent":  ("CPU",       "{:.1f}%"),
        "iowait":       ("I/O Wait",  "{:.1f}%"),
        "ram_percent":   ("RAM",       "{:.1f}%"),
        "swap_percent":  ("Swap",      "{:.1f}%"),
        "disk_percent":  ("Disk /",    "{:.1f}%"),
        "cpu_temp":      ("CPU Temp",  "{:.1f}°C"),
        "load_per_cpu":  ("Load/CPU",  "{:.2f}x"),
    }

    for key, value in metrics.items():
        label, pattern = fmt.get(key, (key, "{:.1f}"))
        if value is None:
            lines.append(f"  {label:12s}  n/a")
        else:
            lines.append(f"  {label:12s}  {pattern.format(value)}")

    # Also show raw load average for context
    load1, load5, load15 = os.getloadavg()
    lines.append(f"  {'Load avg':12s}  {load1:.2f} / {load5:.2f} / {load15:.2f}  ({nproc} cores)")

    # Docker containers
    containers = _get_running_docker_containers()
    if containers:
        lines.append(f"  {'Docker':12s}  {len(containers)} container(s)")
        for c in containers:
            lines.append(f"    - {c['name']:20s}  {c['image']:30s}  up {c['running_for']}")

    # Watchlisted processes currently running
    now = time.time()
    running_watched = []
    seen: set[str] = set()
    for proc in psutil.process_iter(["name", "create_time"]):
        try:
            pname = (proc.info["name"] or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        for watch_key, cfg in WATCHLIST.items():
            if watch_key in seen or watch_key not in pname:
                continue
            age = (now - proc.info["create_time"]) / 60
            hrs, mins = int(age // 60), int(age % 60)
            age_str = f"{hrs}h {mins}m" if hrs else f"{mins}m"
            running_watched.append(f"{cfg['label']} ({age_str})")
            seen.add(watch_key)
    if running_watched:
        lines.append(f"  {'Services':12s}  {', '.join(running_watched)}")

    print("\n".join(lines))


# ── Main loop ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor system health and send desktop alerts.",
    )
    parser.add_argument(
        "--interval", type=int, default=10,
        help="Seconds between checks (default: 10)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print metrics to terminal each tick",
    )
    parser.add_argument(
        "--btop-on-critical", action="store_true",
        help="Auto-open btop in a new terminal on critical alerts",
    )
    args = parser.parse_args()

    sustained = SustainedTracker()
    last_alerted: dict[str, float] = {}  # "metric:severity" -> timestamp

    print(f"sysmon: monitoring every {args.interval}s (Ctrl+C to stop)")

    try:
        while True:
            metrics = collect_metrics()

            if args.verbose:
                print_metrics(metrics)

            alerts = check_thresholds(metrics, sustained)

            has_critical = False
            for alert in alerts:
                key = f"{alert.metric}:{alert.severity}"
                now = time.time()

                if now - last_alerted.get(key, 0) >= ALERT_COOLDOWN:
                    send_alert(alert)
                    last_alerted[key] = now
                    label = METRIC_LABELS.get(alert.metric, alert.metric)
                    print(
                        f"  >> {alert.severity.upper()}: {label} "
                        f"at {alert.value:.1f}{alert.unit}"
                    )
                    if alert.severity == "critical":
                        has_critical = True

            if has_critical and args.btop_on_critical:
                open_btop()

            # Check for forgotten services/containers
            service_alerts = check_idle_services(last_alerted)
            for sa in service_alerts:
                send_service_alert(sa)
                print(f"  >> REMINDER: {sa.label} — {sa.detail}")

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nsysmon: stopped.")


if __name__ == "__main__":
    main()
