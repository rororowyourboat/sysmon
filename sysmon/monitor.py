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
WATCHLIST: dict[str, dict[str, str | int]] = {
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
    exceeded_since: dict[str, float] = field(default_factory=lambda: {})

    def check(self, key: str, is_exceeded: bool, required_seconds: int) -> bool:
        now = time.monotonic()
        if is_exceeded:
            self.exceeded_since.setdefault(key, now)
            return (now - self.exceeded_since[key]) >= required_seconds
        else:
            self.exceeded_since.pop(key, None)
            return False


# ── Metric collection (reads /proc directly, no sleeps) ────────────────────

_NPROC: int = os.cpu_count() or 1
_prev_cpu_times: list[int] | None = None
_hwmon_temp_path: str | None = None
_hwmon_searched: bool = False


def _read_cpu_times() -> list[int]:
    """Read aggregate CPU jiffies from /proc/stat: [user,nice,system,idle,iowait,...]."""
    with open("/proc/stat") as f:
        parts = f.readline().split()
    return [int(x) for x in parts[1:]]  # skip "cpu" label


def _calc_cpu_percent(prev: list[int], curr: list[int]) -> tuple[float, float]:
    """Compute overall CPU% and iowait% from two /proc/stat samples."""
    deltas = [c - p for c, p in zip(curr, prev)]
    total = sum(deltas)
    if total == 0:
        return 0.0, 0.0
    idle = deltas[3]        # idle field
    iowait = deltas[4] if len(deltas) > 4 else 0  # iowait field
    cpu_pct = 100.0 * (1.0 - idle / total)
    iowait_pct = 100.0 * (iowait / total)
    return cpu_pct, iowait_pct


def _find_hwmon_temp() -> str | None:
    """Find the best hwmon temp file once, cache the path."""
    hwmon_base = "/sys/class/hwmon"
    try:
        entries = os.listdir(hwmon_base)
    except OSError:
        return None

    for hwmon in sorted(entries):
        name_path = os.path.join(hwmon_base, hwmon, "name")
        try:
            with open(name_path) as f:
                name = f.read().strip()
        except OSError:
            continue
        if name in ("coretemp", "k10temp", "cpu_thermal", "acpitz"):
            # Find highest numbered temp input
            hwmon_dir = os.path.join(hwmon_base, hwmon)
            temps = sorted(
                p for p in os.listdir(hwmon_dir) if p.startswith("temp") and p.endswith("_input")
            )
            if temps:
                return os.path.join(hwmon_dir, temps[0])
    return None


def _read_temp() -> float | None:
    """Read CPU temperature from cached hwmon path."""
    global _hwmon_temp_path, _hwmon_searched
    if not _hwmon_searched:
        _hwmon_temp_path = _find_hwmon_temp()
        _hwmon_searched = True
    if _hwmon_temp_path is None:
        return None
    try:
        with open(_hwmon_temp_path) as f:
            return int(f.read().strip()) / 1000.0
    except (OSError, ValueError):
        return None


def collect_metrics() -> dict[str, float | None]:
    """Gather all system metrics by reading /proc and /sys directly.

    CPU percentage is computed as a delta between ticks (no blocking sleep).
    First call returns 0% CPU — that's expected.
    """
    global _prev_cpu_times

    # CPU — delta between previous and current /proc/stat
    curr_times = _read_cpu_times()
    if _prev_cpu_times is not None:
        cpu_pct, iowait_pct = _calc_cpu_percent(_prev_cpu_times, curr_times)
    else:
        cpu_pct, iowait_pct = 0.0, 0.0
    _prev_cpu_times = curr_times

    # Memory — still use psutil, it's fast (single /proc/meminfo read)
    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    load1, _, _ = os.getloadavg()

    return {
        "cpu_percent":  cpu_pct,
        "iowait":       iowait_pct,
        "ram_percent":   ram.percent,
        "swap_percent":  swap.percent,
        "disk_percent":  disk.percent,
        "cpu_temp":      _read_temp(),
        "load_per_cpu":  load1 / _NPROC,
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

    containers: list[dict[str, str]] = []
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


@dataclass
class WatchedProcess:
    """A watchlisted process found running on the system."""
    key: str        # watchlist key
    label: str      # human-readable
    age_str: str    # "2h 10m"
    age_minutes: float


def scan_watched_processes() -> list[WatchedProcess]:
    """Single pass over process table to find all watchlisted processes."""
    now = time.time()
    found: list[WatchedProcess] = []
    seen: set[str] = set()

    for proc in psutil.process_iter(["name", "create_time"]):
        try:
            pname = (proc.info["name"] or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        for watch_key, cfg in WATCHLIST.items():
            if watch_key in seen or watch_key not in pname:
                continue
            age_minutes = (now - proc.info["create_time"]) / 60
            hrs, mins = int(age_minutes // 60), int(age_minutes % 60)
            age_str = f"{hrs}h {mins}m" if hrs else f"{mins}m"
            found.append(WatchedProcess(
                key=watch_key,
                label=str(cfg["label"]),
                age_str=age_str,
                age_minutes=age_minutes,
            ))
            seen.add(watch_key)

    return found


def check_idle_services(
    last_alerted: dict[str, float],
    watched: list[WatchedProcess],
    containers: list[dict[str, str]],
) -> list[ServiceAlert]:
    """Check for forgotten services. Returns list of ServiceAlerts."""
    results: list[ServiceAlert] = []
    now = time.time()

    # ── Docker containers ───────────────────────────────────────────────
    if DOCKER_IDLE_MINUTES > 0:
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
    for wp in watched:
        cfg: dict[str, str | int] = WATCHLIST.get(wp.key, {})
        idle_min: int = int(cfg.get("idle_minutes", 0))
        if idle_min <= 0:
            continue
        if wp.age_minutes >= idle_min:
            alert_key = f"proc:{wp.key}"
            if now - last_alerted.get(alert_key, 0) >= ALERT_COOLDOWN:
                results.append(ServiceAlert(
                    kind="process",
                    name=wp.key,
                    label=f"Still running: {wp.label}",
                    detail=f"Open for {wp.age_str}",
                    age_str=wp.age_str,
                ))
                last_alerted[alert_key] = now

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

def print_metrics(
    metrics: dict[str, float | None],
    containers: list[dict[str, str]],
    watched: list[WatchedProcess],
) -> None:
    """Print current metrics to terminal."""
    ts = time.strftime("%H:%M:%S")
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

    load1, load5, load15 = os.getloadavg()
    lines.append(f"  {'Load avg':12s}  {load1:.2f} / {load5:.2f} / {load15:.2f}  ({_NPROC} cores)")

    if containers:
        lines.append(f"  {'Docker':12s}  {len(containers)} container(s)")
        for c in containers:
            lines.append(f"    - {c['name']:20s}  {c['image']:30s}  up {c['running_for']}")

    if watched:
        labels = [f"{w.label} ({w.age_str})" for w in watched]
        lines.append(f"  {'Services':12s}  {', '.join(labels)}")

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

            # Single scan of processes + docker for this tick
            watched = scan_watched_processes()
            containers = _get_running_docker_containers()

            if args.verbose:
                print_metrics(metrics, containers, watched)

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

            # Check for forgotten services/containers (reuses scanned data)
            service_alerts = check_idle_services(last_alerted, watched, containers)
            for sa in service_alerts:
                send_service_alert(sa)
                print(f"  >> REMINDER: {sa.label} — {sa.detail}")

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nsysmon: stopped.")


if __name__ == "__main__":
    main()
