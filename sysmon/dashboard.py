"""Interactive terminal dashboard — sysmon's btop-inspired system monitor.

Displays live CPU (per-core), GPU, memory, disk, temperature, I/O, network
and top-process panels using curses. Colour thresholds come from the sysmon
config so the dashboard matches the alerting rules.

Usage:
    uv run sysmon-dashboard
    uv run sysmon-dashboard --interval 2 --config path/to/config.toml
"""

from __future__ import annotations

import argparse
import curses
import os
import subprocess
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil

from sysmon.config import DEFAULT_CONFIG, load_config

# ── Constants ──────────────────────────────────────────────────────────────

SPARK = " ▁▂▃▄▅▆▇█"
BAR_FILL = "█"
BAR_EMPTY = "░"
_NPROC: int = os.cpu_count() or 1

# Curses colour-pair IDs
C_NORMAL = 1
C_WARNING = 2
C_CRITICAL = 3
C_TITLE = 4
C_DIM = 5
C_BLUE = 6

# ── GPU availability cache ─────────────────────────────────────────────────

_gpu_available: bool | None = None  # None = not probed yet

# ── Previous I/O counters (for rate computation) ───────────────────────────

_prev_disk_read: int = 0
_prev_disk_write: int = 0
_prev_net_recv: int = 0
_prev_net_sent: int = 0
_prev_time: float = 0.0
_has_prev: bool = False


# ── Colour helpers ─────────────────────────────────────────────────────────


def _init_colors() -> None:
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_NORMAL, curses.COLOR_GREEN, -1)
    curses.init_pair(C_WARNING, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_CRITICAL, curses.COLOR_RED, -1)
    curses.init_pair(C_TITLE, curses.COLOR_CYAN, -1)
    curses.init_pair(C_DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(C_BLUE, curses.COLOR_BLUE, -1)


def _severity_color(value: float, warn: float, crit: float) -> int:
    if value >= crit:
        return C_CRITICAL
    if value >= warn:
        return C_WARNING
    return C_NORMAL


# ── Data types ─────────────────────────────────────────────────────────────


@dataclass
class DashboardData:
    """Snapshot of all metrics for one dashboard tick."""

    cpu_total: float = 0.0
    cpu_per_core: list[float] = field(default_factory=lambda: list[float]())
    ram_percent: float = 0.0
    ram_used: int = 0
    ram_total: int = 0
    swap_percent: float = 0.0
    swap_used: int = 0
    swap_total: int = 0
    disk_percent: float = 0.0
    disk_used: int = 0
    disk_total: int = 0
    iowait: float = 0.0
    cpu_temp: float | None = None
    load_avg: tuple[float, float, float] = (0.0, 0.0, 0.0)
    disk_read_rate: float = 0.0
    disk_write_rate: float = 0.0
    net_rx_rate: float = 0.0
    net_tx_rate: float = 0.0
    gpu_util: float | None = None
    gpu_mem_used: float | None = None
    gpu_mem_total: float | None = None
    gpu_temp: float | None = None
    gpu_power: float | None = None
    gpu_power_limit: float | None = None
    gpu_name: str = ""
    top_procs: list[dict[str, Any]] = field(
        default_factory=lambda: list[dict[str, Any]]()
    )


# ── Data collection ────────────────────────────────────────────────────────


def _read_gpu() -> dict[str, Any] | None:
    """Read GPU metrics via nvidia-smi.  Returns *None* if unavailable."""
    global _gpu_available
    if _gpu_available is False:
        return None
    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=utilization.gpu,memory.used,memory.total,"
                "temperature.gpu,power.draw,power.limit,name",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode != 0:
            _gpu_available = False
            return None
        parts = [p.strip() for p in result.stdout.strip().split(",")]
        if len(parts) < 7:
            _gpu_available = False
            return None
        _gpu_available = True
        return {
            "util": float(parts[0]),
            "mem_used": float(parts[1]),
            "mem_total": float(parts[2]),
            "temp": float(parts[3]),
            "power": float(parts[4]),
            "power_limit": float(parts[5]),
            "name": parts[6],
        }
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, IndexError):
        _gpu_available = False
        return None


def _read_temp() -> float | None:
    try:
        temps = psutil.sensors_temperatures()
    except AttributeError:
        return None
    if not temps:
        return None
    for chip in ("coretemp", "k10temp", "cpu_thermal", "acpitz"):
        if chip in temps and temps[chip]:
            return float(temps[chip][0].current)
    for entries in temps.values():
        if entries:
            return float(entries[0].current)
    return None


def _get_top_processes(n: int = 12) -> list[dict[str, Any]]:
    procs: list[dict[str, Any]] = []
    for proc in psutil.process_iter(
        ["pid", "name", "cpu_percent", "memory_percent", "memory_info"],
    ):
        try:
            info: dict[str, Any] = proc.info
            cpu: float = info.get("cpu_percent") or 0.0
            if cpu > 0:
                mem_info = info.get("memory_info")
                procs.append(
                    {
                        "pid": info.get("pid", 0),
                        "name": info.get("name") or "?",
                        "cpu_percent": cpu,
                        "memory_percent": info.get("memory_percent") or 0.0,
                        "rss": mem_info.rss if mem_info else 0,
                    }
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue
    procs.sort(key=lambda p: p["cpu_percent"], reverse=True)
    return procs[:n]


def collect_dashboard_data() -> DashboardData:
    """Gather every metric the dashboard needs in one pass."""
    global _prev_disk_read, _prev_disk_write
    global _prev_net_recv, _prev_net_sent
    global _prev_time, _has_prev

    data = DashboardData()
    now = time.monotonic()

    # CPU
    cpu_times = psutil.cpu_times_percent(interval=None)
    data.cpu_total = 100.0 - cpu_times.idle
    data.iowait = cpu_times.iowait if hasattr(cpu_times, "iowait") else 0.0
    data.cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)

    # Memory
    ram = psutil.virtual_memory()
    data.ram_percent = ram.percent
    data.ram_used = ram.used
    data.ram_total = ram.total
    swap = psutil.swap_memory()
    data.swap_percent = swap.percent
    data.swap_used = swap.used
    data.swap_total = swap.total

    # Disk
    disk = psutil.disk_usage("/")
    data.disk_percent = disk.percent
    data.disk_used = disk.used
    data.disk_total = disk.total

    # Temperature
    data.cpu_temp = _read_temp()

    # Load average
    la = os.getloadavg()
    data.load_avg = (la[0], la[1], la[2])

    # Disk I/O rates
    disk_io = psutil.disk_io_counters()
    if disk_io is not None:
        if _has_prev and now > _prev_time:
            dt = now - _prev_time
            data.disk_read_rate = max(0.0, (disk_io.read_bytes - _prev_disk_read) / dt)
            data.disk_write_rate = max(
                0.0, (disk_io.write_bytes - _prev_disk_write) / dt
            )
        _prev_disk_read = disk_io.read_bytes
        _prev_disk_write = disk_io.write_bytes

    # Network I/O rates (net_io_counters can return None in rare cases)
    net_io = psutil.net_io_counters()
    if net_io is not None:  # pyright: ignore[reportUnnecessaryComparison]
        if _has_prev and now > _prev_time:
            dt = now - _prev_time
            data.net_rx_rate = max(0.0, (net_io.bytes_recv - _prev_net_recv) / dt)
            data.net_tx_rate = max(0.0, (net_io.bytes_sent - _prev_net_sent) / dt)
        _prev_net_recv = net_io.bytes_recv
        _prev_net_sent = net_io.bytes_sent

    _prev_time = now
    _has_prev = True

    # GPU (cached: stops trying after first failure)
    gpu = _read_gpu()
    if gpu is not None:
        data.gpu_util = gpu["util"]
        data.gpu_mem_used = gpu["mem_used"]
        data.gpu_mem_total = gpu["mem_total"]
        data.gpu_temp = gpu["temp"]
        data.gpu_power = gpu["power"]
        data.gpu_power_limit = gpu["power_limit"]
        data.gpu_name = str(gpu["name"])

    # Top processes
    data.top_procs = _get_top_processes()
    return data


# ── Formatting helpers ─────────────────────────────────────────────────────


def fmt_bytes(n: int | float) -> str:
    """Human-readable byte count (binary prefixes)."""
    v = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(v) < 1024:
            return f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TiB"


def fmt_rate(bps: float) -> str:
    """Human-readable transfer rate."""
    if bps < 1024:
        return f"{bps:.0f} B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    if bps < 1024**3:
        return f"{bps / 1024 ** 2:.1f} MB/s"
    return f"{bps / 1024 ** 3:.1f} GB/s"


# ── Curses drawing primitives ──────────────────────────────────────────────


def _safe(win: curses.window, *args: Any) -> None:
    """addstr wrapper that swallows out-of-bounds errors."""
    try:
        win.addstr(*args)
    except curses.error:
        pass


def _draw_box(
    win: curses.window,
    y: int,
    x: int,
    h: int,
    w: int,
    title: str = "",
) -> curses.window | None:
    """Draw a bordered box and return the inner sub-window."""
    max_y, max_x = win.getmaxyx()
    h = min(h, max_y - y)
    w = min(w, max_x - x)
    if h < 3 or w < 4:
        return None
    try:
        sub = win.subwin(h, w, y, x)
        sub.box()
        if title and len(title) + 4 < w:
            sub.addstr(
                0, 2, f" {title} ", curses.color_pair(C_TITLE) | curses.A_BOLD
            )
        return sub
    except curses.error:
        return None


def _draw_bar(
    win: curses.window,
    y: int,
    x: int,
    width: int,
    pct: float,
    label: str = "",
    color: int = C_NORMAL,
    suffix: str | None = None,
) -> None:
    """Render ``label ████░░░░ suffix`` on one line."""
    max_y, max_x = win.getmaxyx()
    if y >= max_y - 1 or x >= max_x - 1:
        return

    cx = x
    if label:
        _safe(win, y, cx, f"{label:>6s} ", curses.color_pair(C_DIM))
        cx += 7

    if suffix is None:
        suffix = f" {pct:5.1f}%"

    bar_w = min(width - (cx - x) - len(suffix), max_x - cx - len(suffix) - 1)
    if bar_w < 3:
        return

    filled = int(bar_w * min(pct, 100.0) / 100.0)
    empty = bar_w - filled

    _safe(win, y, cx, BAR_FILL * filled, curses.color_pair(color) | curses.A_BOLD)
    _safe(win, BAR_EMPTY * empty, curses.color_pair(C_DIM))
    _safe(win, suffix, curses.color_pair(color) | curses.A_BOLD)


def _draw_sparkline(
    win: curses.window,
    y: int,
    x: int,
    width: int,
    history: deque[float],
    max_val: float = 100.0,
    color: int = C_BLUE,
) -> None:
    """Render a sparkline from the most recent *width* history values."""
    max_y, max_x = win.getmaxyx()
    if y >= max_y - 1 or x >= max_x - 1:
        return
    w = min(width, max_x - x - 1, len(history))
    if w < 1:
        return
    values = list(history)[-w:]
    chars: list[str] = []
    for v in values:
        idx = int(min(v / max_val, 1.0) * (len(SPARK) - 1))
        chars.append(SPARK[max(0, min(idx, len(SPARK) - 1))])
    _safe(win, y, x, "".join(chars), curses.color_pair(color))


# ── Panel renderers ────────────────────────────────────────────────────────


def draw_cpu_panel(
    win: curses.window,
    y: int,
    x: int,
    w: int,
    h: int,
    data: DashboardData,
    history: deque[float],
    thresh: dict[str, Any],
) -> None:
    box = _draw_box(win, y, x, h, w, "CPU")
    if not box:
        return
    warn = float(thresh.get("cpu_percent", {}).get("warning", 80))
    crit = float(thresh.get("cpu_percent", {}).get("critical", 95))
    row = 1

    # Total
    color = _severity_color(data.cpu_total, warn, crit)
    _draw_bar(box, row, 1, w - 3, data.cpu_total, "Total", color)
    row += 1

    # Per-core bars (capped to available space)
    max_cores = max(0, min(len(data.cpu_per_core), h - 6))
    for i in range(max_cores):
        pct = data.cpu_per_core[i]
        _draw_bar(box, row, 1, w - 3, pct, f"#{i}", _severity_color(pct, warn, crit))
        row += 1
    if len(data.cpu_per_core) > max_cores:
        _safe(
            box,
            row,
            2,
            f"... +{len(data.cpu_per_core) - max_cores} cores",
            curses.color_pair(C_DIM),
        )
        row += 1

    # Load average
    row = max(row + 1, h - 3)
    load_str = (
        f" Load {data.load_avg[0]:.2f}  {data.load_avg[1]:.2f}  "
        f"{data.load_avg[2]:.2f}  ({_NPROC} cores)"
    )
    _safe(box, row, 1, load_str[: w - 3], curses.color_pair(C_DIM))

    # Sparkline
    if row + 1 < h - 1 and len(history) > 1:
        _draw_sparkline(box, row + 1, 2, w - 4, history, 100.0, C_BLUE)


def draw_mem_panel(
    win: curses.window,
    y: int,
    x: int,
    w: int,
    h: int,
    data: DashboardData,
    thresh: dict[str, Any],
) -> None:
    box = _draw_box(win, y, x, h, w, "Memory & Disk")
    if not box:
        return
    row = 1

    # RAM
    warn = float(thresh.get("ram_percent", {}).get("warning", 85))
    crit = float(thresh.get("ram_percent", {}).get("critical", 95))
    color = _severity_color(data.ram_percent, warn, crit)
    _draw_bar(box, row, 1, w - 3, data.ram_percent, "RAM", color)
    row += 1
    detail = f"       {fmt_bytes(data.ram_used)} / {fmt_bytes(data.ram_total)}"
    _safe(box, row, 1, detail[: w - 3], curses.color_pair(C_DIM))
    row += 2

    # Swap
    warn = float(thresh.get("swap_percent", {}).get("warning", 50))
    crit = float(thresh.get("swap_percent", {}).get("critical", 80))
    color = _severity_color(data.swap_percent, warn, crit)
    _draw_bar(box, row, 1, w - 3, data.swap_percent, "Swap", color)
    row += 1
    detail = f"       {fmt_bytes(data.swap_used)} / {fmt_bytes(data.swap_total)}"
    _safe(box, row, 1, detail[: w - 3], curses.color_pair(C_DIM))
    row += 2

    # Disk
    warn = float(thresh.get("disk_percent", {}).get("warning", 85))
    crit = float(thresh.get("disk_percent", {}).get("critical", 95))
    color = _severity_color(data.disk_percent, warn, crit)
    _draw_bar(box, row, 1, w - 3, data.disk_percent, "Disk", color)
    row += 1
    detail = f"       {fmt_bytes(data.disk_used)} / {fmt_bytes(data.disk_total)}"
    _safe(box, row, 1, detail[: w - 3], curses.color_pair(C_DIM))


def draw_temp_panel(
    win: curses.window,
    y: int,
    x: int,
    w: int,
    h: int,
    data: DashboardData,
    thresh: dict[str, Any],
) -> None:
    box = _draw_box(win, y, x, h, w, "Temperature")
    if not box:
        return
    warn = float(thresh.get("cpu_temp", {}).get("warning", 80))
    crit = float(thresh.get("cpu_temp", {}).get("critical", 90))
    row = 1

    if data.cpu_temp is not None:
        color = _severity_color(data.cpu_temp, warn, crit)
        bar_pct = min(data.cpu_temp / 110.0 * 100.0, 100.0)
        _draw_bar(
            box, row, 1, w - 3, bar_pct, "CPU", color, f" {data.cpu_temp:.0f} C"
        )
        row += 1
        _safe(
            box,
            row,
            2,
            f"      warn {warn:.0f} C   crit {crit:.0f} C",
            curses.color_pair(C_DIM),
        )
        row += 2
    else:
        _safe(box, row, 2, "CPU temp: n/a", curses.color_pair(C_DIM))
        row += 2

    if data.gpu_temp is not None:
        color = _severity_color(data.gpu_temp, 75.0, 90.0)
        bar_pct = min(data.gpu_temp / 110.0 * 100.0, 100.0)
        _draw_bar(
            box, row, 1, w - 3, bar_pct, "GPU", color, f" {data.gpu_temp:.0f} C"
        )


def draw_io_panel(
    win: curses.window,
    y: int,
    x: int,
    w: int,
    h: int,
    data: DashboardData,
    io_history: deque[float],
    thresh: dict[str, Any],
) -> None:
    box = _draw_box(win, y, x, h, w, "I/O & Network")
    if not box:
        return
    row = 1

    # Disk I/O rates
    _safe(box, row, 2, "Disk Read  ", curses.color_pair(C_DIM))
    _safe(box, fmt_rate(data.disk_read_rate), curses.color_pair(C_BLUE) | curses.A_BOLD)
    row += 1
    _safe(box, row, 2, "Disk Write ", curses.color_pair(C_DIM))
    _safe(
        box, fmt_rate(data.disk_write_rate), curses.color_pair(C_BLUE) | curses.A_BOLD
    )
    row += 2

    # I/O Wait bar
    warn = float(thresh.get("iowait", {}).get("warning", 15))
    crit = float(thresh.get("iowait", {}).get("critical", 30))
    color = _severity_color(data.iowait, warn, crit)
    _draw_bar(box, row, 1, w - 3, data.iowait, "IOWait", color)
    row += 2

    # Network rates
    _safe(box, row, 2, "Net RX     ", curses.color_pair(C_DIM))
    _safe(
        box, fmt_rate(data.net_rx_rate), curses.color_pair(C_NORMAL) | curses.A_BOLD
    )
    row += 1
    _safe(box, row, 2, "Net TX     ", curses.color_pair(C_DIM))
    _safe(
        box, fmt_rate(data.net_tx_rate), curses.color_pair(C_NORMAL) | curses.A_BOLD
    )
    row += 2

    # I/O sparkline
    if row < h - 1 and len(io_history) > 1:
        _safe(box, row, 2, "iowait ", curses.color_pair(C_DIM))
        _draw_sparkline(box, row, 9, w - 11, io_history, 50.0, C_BLUE)


def draw_gpu_panel(
    win: curses.window,
    y: int,
    x: int,
    w: int,
    h: int,
    data: DashboardData,
) -> None:
    title = f"GPU - {data.gpu_name}" if data.gpu_name else "GPU"
    if len(title) > w - 6:
        title = title[: w - 9] + "..."
    box = _draw_box(win, y, x, h, w, title)
    if not box:
        return
    row = 1

    if data.gpu_util is not None:
        color = _severity_color(data.gpu_util, 80.0, 95.0)
        _draw_bar(box, row, 1, w - 3, data.gpu_util, "Load", color)
        row += 1

    if (
        data.gpu_mem_used is not None
        and data.gpu_mem_total is not None
        and data.gpu_mem_total > 0
    ):
        pct = data.gpu_mem_used / data.gpu_mem_total * 100
        color = _severity_color(pct, 80.0, 95.0)
        _draw_bar(box, row, 1, w - 3, pct, "VRAM", color)
        row += 1
        detail = f"       {data.gpu_mem_used:.0f} MiB / {data.gpu_mem_total:.0f} MiB"
        _safe(box, row, 1, detail[: w - 3], curses.color_pair(C_DIM))
        row += 2

    if data.gpu_power is not None and data.gpu_power_limit is not None:
        pwr = f" Power {data.gpu_power:.0f}W / {data.gpu_power_limit:.0f}W"
        _safe(box, row, 1, pwr[: w - 3], curses.color_pair(C_DIM))


def draw_proc_panel(
    win: curses.window,
    y: int,
    x: int,
    w: int,
    h: int,
    data: DashboardData,
) -> None:
    box = _draw_box(win, y, x, h, w, "Processes")
    if not box:
        return
    row = 1

    hdr = f" {'PID':>7s}  {'CPU%':>6s}  {'MEM%':>6s}  {'MEM':>10s}  NAME"
    _safe(box, row, 1, hdr[: w - 3], curses.color_pair(C_TITLE) | curses.A_BOLD)
    row += 1
    _safe(box, row, 1, "\u2500" * min(w - 3, 60), curses.color_pair(C_DIM))
    row += 1

    max_rows = min(len(data.top_procs), h - 4)
    for i in range(max_rows):
        p = data.top_procs[i]
        cpu: float = p.get("cpu_percent", 0)
        mem_pct: float = p.get("memory_percent", 0)
        line = (
            f" {p['pid']:>7d}  {cpu:>5.1f}%  {mem_pct:>5.1f}%"
            f"  {fmt_bytes(p.get('rss', 0)):>10s}  {p['name']}"
        )
        color = C_NORMAL
        if cpu >= 50:
            color = C_CRITICAL
        elif cpu >= 20:
            color = C_WARNING
        _safe(box, row, 1, line[: w - 3], curses.color_pair(color))
        row += 1


# ── Header ─────────────────────────────────────────────────────────────────


def _draw_header(win: curses.window, w: int) -> None:
    ts = time.strftime("%H:%M:%S")
    attr = curses.color_pair(C_TITLE) | curses.A_REVERSE
    _safe(win, 0, 0, " " * (w - 1), attr)
    _safe(win, 0, 1, "sysmon dashboard", attr | curses.A_BOLD)
    hint = "q: quit"
    _safe(win, 0, max(0, w - len(hint) - 2), hint, attr)
    _safe(win, 0, (w - len(ts)) // 2, ts, attr)


# ── Main loop ──────────────────────────────────────────────────────────────


def _dashboard_loop(
    stdscr: curses.window, config: dict[str, Any], interval: float
) -> None:
    _init_colors()
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(int(interval * 1000))

    thresh: dict[str, Any] = config.get("thresholds", DEFAULT_CONFIG["thresholds"])
    cpu_hist: deque[float] = deque(maxlen=120)
    io_hist: deque[float] = deque(maxlen=120)

    # Warm-up psutil internal deltas
    psutil.cpu_percent(interval=None, percpu=True)
    psutil.cpu_times_percent(interval=None)

    while True:
        data = collect_dashboard_data()
        cpu_hist.append(data.cpu_total)
        io_hist.append(data.iowait)

        max_y, max_x = stdscr.getmaxyx()

        if max_y < 10 or max_x < 40:
            stdscr.erase()
            _safe(stdscr, 0, 0, "Terminal too small (need 40x10+)")
            stdscr.refresh()
            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                return
            continue

        stdscr.erase()
        _draw_header(stdscr, max_x)

        has_gpu = data.gpu_util is not None
        two_col = max_x >= 82

        if two_col:
            col_w = max_x // 2

            # Reserve bottom rows for process panel
            proc_h = min(len(data.top_procs) + 4, max(6, max_y // 4))
            body_h = max_y - 1 - proc_h

            # ── Left column: CPU + Temperature (+ GPU) ────────────────
            temp_h = 7 if data.gpu_temp is not None else 5
            gpu_h = 7 if has_gpu else 0
            cpu_h = max(6, body_h - temp_h - gpu_h)

            draw_cpu_panel(stdscr, 1, 0, col_w, cpu_h, data, cpu_hist, thresh)
            left_y = 1 + cpu_h
            if left_y + temp_h <= max_y:
                draw_temp_panel(stdscr, left_y, 0, col_w, temp_h, data, thresh)
                left_y += temp_h
            if has_gpu and left_y + gpu_h <= max_y:
                draw_gpu_panel(stdscr, left_y, 0, col_w, gpu_h, data)

            # ── Right column: Memory + I/O & Network ──────────────────
            mem_h = 10
            io_h = max(8, body_h - mem_h)

            draw_mem_panel(stdscr, 1, col_w, col_w, mem_h, data, thresh)
            right_y = 1 + mem_h
            if right_y + io_h <= max_y:
                draw_io_panel(
                    stdscr, right_y, col_w, col_w, io_h, data, io_hist, thresh
                )

            # ── Bottom: Processes (full width) ────────────────────────
            proc_y = max_y - proc_h
            if proc_y > 1:
                draw_proc_panel(stdscr, proc_y, 0, max_x, proc_h, data)

        else:
            # ── Single-column stacked layout ──────────────────────────
            cur_y = 1
            panel_w = max_x
            chunk = max(6, (max_y - 1) // 4)

            draw_cpu_panel(stdscr, cur_y, 0, panel_w, chunk, data, cpu_hist, thresh)
            cur_y += chunk
            if cur_y + 10 <= max_y:
                draw_mem_panel(stdscr, cur_y, 0, panel_w, 10, data, thresh)
                cur_y += 10
            if cur_y + 5 <= max_y:
                draw_temp_panel(stdscr, cur_y, 0, panel_w, 5, data, thresh)
                cur_y += 5
            remaining = max_y - cur_y
            if remaining >= 6:
                draw_proc_panel(stdscr, cur_y, 0, panel_w, remaining, data)

        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            return
        if key == curses.KEY_RESIZE:
            stdscr.clear()


# ── CLI entry point ────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Interactive system dashboard — sysmon's btop-inspired TUI.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.5,
        help="Seconds between refreshes (default: 1.5)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to TOML config file",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    try:
        curses.wrapper(_dashboard_loop, config, args.interval)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
