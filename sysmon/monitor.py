"""Lightweight system health monitor with desktop notifications."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from sysmon.config import DEFAULT_CONFIG, dump_default_config, load_config

# ── Configuration (populated by _apply_config / main) ─────────────────────

thresholds: dict[str, dict[str, float]] = DEFAULT_CONFIG["thresholds"]
sustained: dict[str, dict[str, int]] = DEFAULT_CONFIG["sustained"]
alert_cooldown: int = DEFAULT_CONFIG["alert_cooldown"]
watchlist: dict[str, dict[str, str | int]] = DEFAULT_CONFIG["watchlist"]
docker_idle_minutes: int = DEFAULT_CONFIG["docker_idle_minutes"]


def _apply_config(cfg: dict[str, Any]) -> None:
    """Update module globals from a merged config dict."""
    global thresholds, sustained, alert_cooldown, watchlist, docker_idle_minutes
    thresholds = cfg["thresholds"]
    sustained = cfg["sustained"]
    alert_cooldown = cfg["alert_cooldown"]
    watchlist = cfg["watchlist"]
    docker_idle_minutes = cfg["docker_idle_minutes"]


METRIC_LABELS: dict[str, str] = {
    "cpu_percent": "CPU Usage",
    "iowait": "I/O Wait",
    "ram_percent": "RAM Usage",
    "swap_percent": "Swap Usage",
    "disk_percent": "Disk Usage (/)",
    "cpu_temp": "CPU Temperature",
    "load_per_cpu": "Load Average",
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


# ── Metric collection (via psutil) ─────────────────────────────────────────

_NPROC: int = os.cpu_count() or 1


def _read_temp() -> float | None:
    """Read CPU temperature via psutil.sensors_temperatures()."""
    try:
        temps = psutil.sensors_temperatures()
    except AttributeError:
        # sensors_temperatures() not available on this platform
        return None
    if not temps:
        return None

    # Try common chip names in order of preference
    for chip in ("coretemp", "k10temp", "cpu_thermal", "acpitz"):
        if chip in temps and temps[chip]:
            return float(temps[chip][0].current)

    # Fallback: use the first available sensor
    for entries in temps.values():
        if entries:
            return float(entries[0].current)

    return None


def collect_metrics() -> dict[str, float | None]:
    """Gather all system metrics via psutil.

    Uses psutil.cpu_times_percent() for non-blocking CPU stats (computes
    delta since last call internally). First call may return 0% — that's
    expected.
    """
    # CPU — psutil tracks the delta internally, no blocking sleep needed
    cpu_times = psutil.cpu_times_percent(interval=None)
    cpu_pct = 100.0 - cpu_times.idle
    iowait_pct = cpu_times.iowait if hasattr(cpu_times, "iowait") else 0.0

    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    load1, _, _ = os.getloadavg()

    return {
        "cpu_percent": cpu_pct,
        "iowait": iowait_pct,
        "ram_percent": ram.percent,
        "swap_percent": swap.percent,
        "disk_percent": disk.percent,
        "cpu_temp": _read_temp(),
        "load_per_cpu": load1 / _NPROC,
    }


# ── Threshold checking ──────────────────────────────────────────────────────


def check_thresholds(
    metrics: dict[str, float | None],
    tracker: SustainedTracker,
) -> list[Alert]:
    """Compare metrics against thresholds and return any triggered alerts."""
    alerts: list[Alert] = []

    units = {
        "cpu_percent": "%",
        "iowait": "%",
        "ram_percent": "%",
        "swap_percent": "%",
        "disk_percent": "%",
        "cpu_temp": "°C",
        "load_per_cpu": "x",
    }

    for metric, value in metrics.items():
        if value is None:
            continue
        thresh = thresholds.get(metric)
        if not thresh:
            continue

        # Check critical first, then warning
        for severity in ("critical", "warning"):
            limit = thresh[severity]
            exceeded = value >= limit

            # For sustained metrics, check duration
            if metric in sustained:
                key = f"{metric}:{severity}"
                required = sustained[metric][severity]
                if not tracker.check(key, exceeded, required):
                    continue
            elif not exceeded:
                continue

            alerts.append(
                Alert(
                    metric=metric,
                    severity=severity,
                    value=value,
                    threshold=limit,
                    unit=units.get(metric, ""),
                )
            )
            break  # Only report highest severity per metric

    return alerts


# ── Desktop notifications ───────────────────────────────────────────────────


def send_alert(alert: Alert) -> None:
    """Send a desktop notification via notify-send."""
    label = METRIC_LABELS.get(alert.metric, alert.metric)
    icon = "dialog-warning" if alert.severity == "warning" else "dialog-error"
    urgency = "normal" if alert.severity == "warning" else "critical"

    title = f"[{alert.severity.upper()}] {label}"
    body = (
        f"{alert.value:.1f}{alert.unit} (threshold: {alert.threshold:.0f}{alert.unit})"
    )

    try:
        subprocess.run(
            [
                "notify-send",
                f"--urgency={urgency}",
                f"--icon={icon}",
                "--app-name=sysmon",
                title,
                body,
            ],
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
    """Return running containers with name, image, status, and created-at."""
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--format",
                "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.CreatedAt}}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    containers: list[dict[str, str]] = []
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            containers.append(
                {
                    "name": parts[0],
                    "image": parts[1],
                    "status": parts[2],
                    "created_at": parts[3] if len(parts) > 3 else "",
                }
            )
    return containers


def _parse_docker_created_at(created_at: str) -> int:
    """Parse Docker's CreatedAt timestamp and return uptime in minutes.

    Docker outputs timestamps like "2025-01-15 10:30:00 +0000 UTC".
    We parse the first 25 characters (date + timezone offset) and compute
    the delta from now.
    """
    if not created_at:
        return 0
    try:
        # Docker format: "2025-01-15 10:30:00 +0000 UTC"
        # Parse "2025-01-15 10:30:00 +0000" (the "UTC" suffix is redundant)
        ts_str = created_at[:25].strip()
        created = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S %z")
        delta = datetime.now(UTC) - created
        return max(0, int(delta.total_seconds() / 60))
    except (ValueError, IndexError):
        return 0


def _format_minutes(minutes: int) -> str:
    """Format a duration in minutes as a human-readable string."""
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h {minutes % 60}m"
    days = hours // 24
    remaining_hours = hours % 24
    return f"{days}d {remaining_hours}h"


@dataclass
class ServiceAlert:
    """An idle service or Docker container that triggered a reminder."""

    kind: str  # "docker" or "process"
    name: str  # container name or watchlist key
    label: str  # human-readable label
    detail: str  # "Running for 4 days (postgres:16-alpine)"
    age_str: str  # "4h 12m"


@dataclass
class WatchedProcess:
    """A watchlisted process found running on the system."""

    key: str  # watchlist key
    label: str  # human-readable
    age_str: str  # "2h 10m"
    age_minutes: float
    cpu_percent: float = 0.0  # aggregate CPU% across all matching PIDs


def scan_watched_processes() -> list[WatchedProcess]:
    """Single pass over process table to find all watchlisted processes.

    Collects aggregate CPU% for each watchlist entry (summed across all
    matching PIDs) so that check_idle_services can distinguish active
    processes (e.g. Zoom in a call) from truly idle ones.
    """
    now = time.time()
    # Accumulate per watch_key: oldest create_time and total CPU%
    accum: dict[str, dict[str, Any]] = {}

    for proc in psutil.process_iter(["name", "create_time", "cpu_percent"]):
        try:
            pname = (proc.info["name"] or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        for watch_key, cfg in watchlist.items():
            if watch_key not in pname:
                continue
            if watch_key not in accum:
                accum[watch_key] = {
                    "cfg": cfg,
                    "create_time": proc.info["create_time"],
                    "cpu_total": 0.0,
                }
            # Track the oldest matching process for age calculation
            accum[watch_key]["create_time"] = min(
                accum[watch_key]["create_time"], proc.info["create_time"]
            )
            accum[watch_key]["cpu_total"] += proc.info.get("cpu_percent", 0.0) or 0.0
            break  # this proc matched; move to next proc

    found: list[WatchedProcess] = []
    for watch_key, data in accum.items():
        age_minutes = (now - data["create_time"]) / 60
        hrs, mins = int(age_minutes // 60), int(age_minutes % 60)
        age_str = f"{hrs}h {mins}m" if hrs else f"{mins}m"
        found.append(
            WatchedProcess(
                key=watch_key,
                label=str(data["cfg"]["label"]),
                age_str=age_str,
                age_minutes=age_minutes,
                cpu_percent=data["cpu_total"],
            )
        )

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
    if docker_idle_minutes > 0:
        for c in containers:
            uptime = _parse_docker_created_at(c["created_at"])
            if uptime >= docker_idle_minutes:
                key = f"docker:{c['name']}"
                if now - last_alerted.get(key, 0) >= alert_cooldown:
                    age = _format_minutes(uptime)
                    results.append(
                        ServiceAlert(
                            kind="docker",
                            name=c["name"],
                            label=f"Docker: {c['name']}",
                            detail=f"Running for {age} ({c['image']})",
                            age_str=age,
                        )
                    )
                    last_alerted[key] = now

    # ── Watchlisted processes ───────────────────────────────────────────
    for wp in watched:
        cfg: dict[str, str | int] = watchlist.get(wp.key, {})
        idle_min: int = int(cfg.get("idle_minutes", 0))
        if idle_min <= 0:
            continue
        if wp.age_minutes >= idle_min:
            # Skip if process is actively using CPU (e.g. Zoom in a call)
            active_cpu: float = float(cfg.get("active_cpu", 0))
            if active_cpu > 0 and wp.cpu_percent >= active_cpu:
                continue

            alert_key = f"proc:{wp.key}"
            if now - last_alerted.get(alert_key, 0) >= alert_cooldown:
                results.append(
                    ServiceAlert(
                        kind="process",
                        name=wp.key,
                        label=f"Still running: {wp.label}",
                        detail=f"Open for {wp.age_str}",
                        age_str=wp.age_str,
                    )
                )
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
            [
                "notify-send",
                "--urgency=normal",
                "--icon=dialog-information",
                "--app-name=sysmon",
                title,
                body,
            ],
            check=False,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Open inspector in a new terminal
    terminal = _detect_terminal()
    if not terminal:
        cmd = " ".join(_get_inspector_cmd(alert))
        print(f"  !! No terminal found — run manually: {cmd}")
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
        "cpu_percent": ("CPU", "{:.1f}%"),
        "iowait": ("I/O Wait", "{:.1f}%"),
        "ram_percent": ("RAM", "{:.1f}%"),
        "swap_percent": ("Swap", "{:.1f}%"),
        "disk_percent": ("Disk /", "{:.1f}%"),
        "cpu_temp": ("CPU Temp", "{:.1f}°C"),
        "load_per_cpu": ("Load/CPU", "{:.2f}x"),
    }

    for key, value in metrics.items():
        label, pattern = fmt.get(key, (key, "{:.1f}"))
        if value is None:
            lines.append(f"  {label:12s}  n/a")
        else:
            lines.append(f"  {label:12s}  {pattern.format(value)}")

    load1, load5, load15 = os.getloadavg()
    loads = f"{load1:.2f} / {load5:.2f} / {load15:.2f}"
    lines.append(f"  {'Load avg':12s}  {loads}  ({_NPROC} cores)")

    if containers:
        lines.append(f"  {'Docker':12s}  {len(containers)} container(s)")
        for c in containers:
            age = _format_minutes(_parse_docker_created_at(c["created_at"]))
            lines.append(f"    - {c['name']:20s}  {c['image']:30s}  up {age}")

    if watched:
        parts = []
        for w in watched:
            active_cpu = float(watchlist.get(w.key, {}).get("active_cpu", 0))
            if active_cpu > 0 and w.cpu_percent >= active_cpu:
                parts.append(f"{w.label} ({w.age_str}, active ~{w.cpu_percent:.0f}%)")
            else:
                parts.append(f"{w.label} ({w.age_str})")
        lines.append(f"  {'Services':12s}  {', '.join(parts)}")

    print("\n".join(lines))


# ── Main loop ───────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor system health and send desktop alerts.",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Seconds between checks (default: 10)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print metrics to terminal each tick",
    )
    parser.add_argument(
        "--btop-on-critical",
        action="store_true",
        help="Auto-open btop in a new terminal on critical alerts",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to TOML config file (default: ~/.config/sysmon/config.toml)",
    )
    parser.add_argument(
        "--dump-config",
        action="store_true",
        help="Print default configuration as TOML and exit",
    )
    args = parser.parse_args()

    if args.dump_config:
        print(dump_default_config(), end="")
        return

    _apply_config(load_config(args.config))

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

                if now - last_alerted.get(key, 0) >= alert_cooldown:
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
