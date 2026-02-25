"""Tests for the dashboard module helpers and data collection."""

from __future__ import annotations

from collections import deque
from unittest.mock import MagicMock, patch

import pytest

from sysmon.dashboard import (
    DashboardData,
    _severity_color,
    collect_dashboard_data,
    fmt_bytes,
    fmt_rate,
)

# ── fmt_bytes ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0.0 B"),
        (512, "512.0 B"),
        (1024, "1.0 KiB"),
        (1024 * 1024, "1.0 MiB"),
        (1024**3, "1.0 GiB"),
        (1024**4, "1.0 TiB"),
        (1536, "1.5 KiB"),
        (2.5 * 1024**2, "2.5 MiB"),
    ],
)
def test_fmt_bytes(value: int | float, expected: str) -> None:
    assert fmt_bytes(value) == expected


# ── fmt_rate ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("bps", "expected"),
    [
        (0, "0 B/s"),
        (500, "500 B/s"),
        (1024, "1.0 KB/s"),
        (1024 * 1024, "1.0 MB/s"),
        (1024**3, "1.0 GB/s"),
    ],
)
def test_fmt_rate(bps: float, expected: str) -> None:
    assert fmt_rate(bps) == expected


# ── _severity_color ────────────────────────────────────────────────────────

from sysmon.dashboard import C_CRITICAL, C_NORMAL, C_WARNING


def test_severity_normal() -> None:
    assert _severity_color(50.0, 80.0, 95.0) == C_NORMAL


def test_severity_warning() -> None:
    assert _severity_color(85.0, 80.0, 95.0) == C_WARNING


def test_severity_critical() -> None:
    assert _severity_color(96.0, 80.0, 95.0) == C_CRITICAL


def test_severity_at_boundary() -> None:
    assert _severity_color(80.0, 80.0, 95.0) == C_WARNING
    assert _severity_color(95.0, 80.0, 95.0) == C_CRITICAL


# ── DashboardData defaults ─────────────────────────────────────────────────


def test_dashboard_data_defaults() -> None:
    d = DashboardData()
    assert d.cpu_total == 0.0
    assert d.cpu_per_core == []
    assert d.gpu_util is None
    assert d.top_procs == []


# ── collect_dashboard_data (mocked) ────────────────────────────────────────


def _mock_cpu_times() -> MagicMock:
    m = MagicMock()
    m.idle = 30.0
    m.iowait = 5.0
    return m


@patch("sysmon.dashboard.psutil")
@patch("sysmon.dashboard._read_gpu", return_value=None)
@patch("sysmon.dashboard._read_temp", return_value=55.0)
@patch("sysmon.dashboard.os")
def test_collect_dashboard_data(
    mock_os: MagicMock,
    mock_temp: MagicMock,
    mock_gpu: MagicMock,
    mock_psutil: MagicMock,
) -> None:
    # Reset module-level state so rate computation works cleanly
    import sysmon.dashboard as mod

    mod._has_prev = False

    mock_psutil.cpu_times_percent.return_value = _mock_cpu_times()
    mock_psutil.cpu_percent.return_value = [70.0, 30.0]

    vm = MagicMock()
    vm.percent = 65.0
    vm.used = 8 * 1024**3
    vm.total = 16 * 1024**3
    mock_psutil.virtual_memory.return_value = vm

    sw = MagicMock()
    sw.percent = 10.0
    sw.used = 1024**3
    sw.total = 8 * 1024**3
    mock_psutil.swap_memory.return_value = sw

    dk = MagicMock()
    dk.percent = 72.0
    dk.used = 150 * 1024**3
    dk.total = 500 * 1024**3
    mock_psutil.disk_usage.return_value = dk

    mock_psutil.disk_io_counters.return_value = None
    mock_psutil.net_io_counters.return_value = None
    mock_psutil.process_iter.return_value = []

    mock_os.getloadavg.return_value = (1.5, 1.2, 0.8)
    mock_os.cpu_count.return_value = 4

    data = collect_dashboard_data()

    assert data.cpu_total == pytest.approx(70.0)
    assert data.iowait == pytest.approx(5.0)
    assert data.cpu_per_core == [70.0, 30.0]
    assert data.ram_percent == pytest.approx(65.0)
    assert data.cpu_temp == pytest.approx(55.0)
    assert data.gpu_util is None
    assert data.disk_read_rate == 0.0
    assert data.net_rx_rate == 0.0


# ── Sparkline history buffer ──────────────────────────────────────────────


def test_history_deque_maxlen() -> None:
    h: deque[float] = deque(maxlen=120)
    for i in range(200):
        h.append(float(i))
    assert len(h) == 120
    assert h[0] == 80.0
