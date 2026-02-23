"""Tests for sysmon.monitor."""

import subprocess
import time
from unittest.mock import MagicMock, patch

import psutil
import pytest

from sysmon.monitor import (
    alert_cooldown,
    Alert,
    ServiceAlert,
    SustainedTracker,
    WatchedProcess,
    _calc_cpu_percent,
    _detect_terminal,
    _get_running_docker_containers,
    _parse_docker_uptime_minutes,
    check_idle_services,
    check_thresholds,
    collect_metrics,
    scan_watched_processes,
    send_alert,
)


# ── _calc_cpu_percent ──────────────────────────────────────────────────────


class TestCalcCpuPercent:
    def test_full_load(self) -> None:
        # All time went to user (index 0), none to idle (index 3)
        prev = [0, 0, 0, 1000, 0, 0, 0, 0, 0, 0]
        curr = [1000, 0, 0, 1000, 0, 0, 0, 0, 0, 0]
        cpu, iowait = _calc_cpu_percent(prev, curr)
        assert cpu == 100.0
        assert iowait == 0.0

    def test_all_idle(self) -> None:
        prev = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        curr = [0, 0, 0, 1000, 0, 0, 0, 0, 0, 0]
        cpu, iowait = _calc_cpu_percent(prev, curr)
        assert cpu == 0.0
        assert iowait == 0.0

    def test_50_percent(self) -> None:
        prev = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        curr = [500, 0, 0, 500, 0, 0, 0, 0, 0, 0]
        cpu, iowait = _calc_cpu_percent(prev, curr)
        assert cpu == pytest.approx(50.0)
        assert iowait == 0.0

    def test_iowait(self) -> None:
        prev = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        curr = [0, 0, 0, 500, 500, 0, 0, 0, 0, 0]
        cpu, iowait = _calc_cpu_percent(prev, curr)
        assert cpu == pytest.approx(50.0)
        assert iowait == pytest.approx(50.0)

    def test_zero_delta(self) -> None:
        prev = [100, 0, 0, 100, 0, 0, 0, 0, 0, 0]
        curr = [100, 0, 0, 100, 0, 0, 0, 0, 0, 0]
        cpu, iowait = _calc_cpu_percent(prev, curr)
        assert cpu == 0.0
        assert iowait == 0.0

    def test_short_fields_no_iowait(self) -> None:
        prev = [0, 0, 0, 0]
        curr = [500, 0, 0, 500]
        cpu, iowait = _calc_cpu_percent(prev, curr)
        assert cpu == pytest.approx(50.0)
        assert iowait == 0.0


# ── SustainedTracker ───────────────────────────────────────────────────────


class TestSustainedTracker:
    def test_not_exceeded_returns_false(self) -> None:
        tracker = SustainedTracker()
        assert tracker.check("cpu:warning", False, 30) is False
        assert "cpu:warning" not in tracker.exceeded_since

    def test_just_exceeded_returns_false(self) -> None:
        tracker = SustainedTracker()
        assert tracker.check("cpu:warning", True, 30) is False

    def test_exceeded_long_enough(self) -> None:
        tracker = SustainedTracker()
        # Manually set the start time to 60 seconds ago
        tracker.exceeded_since["cpu:warning"] = time.monotonic() - 60
        assert tracker.check("cpu:warning", True, 30) is True

    def test_clears_on_recovery(self) -> None:
        tracker = SustainedTracker()
        tracker.exceeded_since["cpu:warning"] = time.monotonic() - 60
        tracker.check("cpu:warning", False, 30)
        assert "cpu:warning" not in tracker.exceeded_since

    def test_zero_seconds_threshold(self) -> None:
        tracker = SustainedTracker()
        assert tracker.check("cpu:critical", True, 0) is True


# ── check_thresholds ──────────────────────────────────────────────────────


class TestCheckThresholds:
    def test_below_all_thresholds(self) -> None:
        metrics: dict[str, float | None] = {
            "cpu_percent": 10.0,
            "ram_percent": 20.0,
            "swap_percent": 5.0,
            "disk_percent": 30.0,
            "cpu_temp": 45.0,
            "load_per_cpu": 0.5,
            "iowait": 1.0,
        }
        # For sustained metrics like cpu_percent, it won't fire immediately
        tracker = SustainedTracker()
        alerts = check_thresholds(metrics, tracker)
        assert alerts == []

    def test_warning_non_sustained(self) -> None:
        metrics: dict[str, float | None] = {"ram_percent": 90.0}
        tracker = SustainedTracker()
        alerts = check_thresholds(metrics, tracker)
        assert len(alerts) == 1
        assert alerts[0].severity == "warning"
        assert alerts[0].metric == "ram_percent"

    def test_critical_over_warning(self) -> None:
        metrics: dict[str, float | None] = {"ram_percent": 96.0}
        tracker = SustainedTracker()
        alerts = check_thresholds(metrics, tracker)
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"

    def test_none_metric_skipped(self) -> None:
        metrics: dict[str, float | None] = {"cpu_temp": None}
        tracker = SustainedTracker()
        alerts = check_thresholds(metrics, tracker)
        assert alerts == []

    def test_sustained_cpu_not_immediate(self) -> None:
        metrics: dict[str, float | None] = {"cpu_percent": 85.0}
        tracker = SustainedTracker()
        # First check: won't alert because sustained duration not met
        alerts = check_thresholds(metrics, tracker)
        assert alerts == []

    def test_sustained_cpu_after_duration(self) -> None:
        metrics: dict[str, float | None] = {"cpu_percent": 85.0}
        tracker = SustainedTracker()
        # Fake that it's been elevated for 60 seconds
        tracker.exceeded_since["cpu_percent:warning"] = time.monotonic() - 60
        alerts = check_thresholds(metrics, tracker)
        assert len(alerts) == 1
        assert alerts[0].severity == "warning"


# ── _parse_docker_uptime_minutes ──────────────────────────────────────────


class TestParseDockerUptimeMinutes:
    def test_days(self) -> None:
        assert _parse_docker_uptime_minutes("3 days") == 3 * 1440

    def test_about_an_hour(self) -> None:
        assert _parse_docker_uptime_minutes("About an hour") == 60

    def test_hours(self) -> None:
        assert _parse_docker_uptime_minutes("2 hours") == 120

    def test_minutes(self) -> None:
        assert _parse_docker_uptime_minutes("45 minutes") == 45

    def test_seconds(self) -> None:
        # No minute/hour/day component → 0
        assert _parse_docker_uptime_minutes("30 seconds") == 0

    def test_compound(self) -> None:
        # Docker sometimes says "3 days, 2 hours"
        result = _parse_docker_uptime_minutes("3 days, 2 hours")
        assert result == 3 * 1440 + 120


# ── check_idle_services ──────────────────────────────────────────────────


class TestCheckIdleServices:
    def test_docker_container_over_idle(self) -> None:
        last_alerted: dict[str, float] = {}
        containers = [
            {"name": "mydb", "image": "postgres:16", "status": "Up 2 hours", "running_for": "2 hours"},
        ]
        alerts = check_idle_services(last_alerted, [], containers)
        assert len(alerts) == 1
        assert alerts[0].kind == "docker"
        assert alerts[0].name == "mydb"

    def test_docker_container_under_idle(self) -> None:
        last_alerted: dict[str, float] = {}
        containers = [
            {"name": "mydb", "image": "postgres:16", "status": "Up 5 minutes", "running_for": "5 minutes"},
        ]
        alerts = check_idle_services(last_alerted, [], containers)
        assert alerts == []

    def test_process_over_idle(self) -> None:
        last_alerted: dict[str, float] = {}
        wp = WatchedProcess(key="zoom", label="Zoom", age_str="1h 0m", age_minutes=60.0)
        alerts = check_idle_services(last_alerted, [wp], [])
        assert len(alerts) == 1
        assert alerts[0].kind == "process"
        assert alerts[0].name == "zoom"

    def test_process_never_nag(self) -> None:
        # idle_minutes=0 means never nag
        last_alerted: dict[str, float] = {}
        wp = WatchedProcess(key="code", label="VS Code", age_str="5h 0m", age_minutes=300.0)
        alerts = check_idle_services(last_alerted, [wp], [])
        assert alerts == []

    def test_cooldown_suppresses_repeat(self) -> None:
        last_alerted: dict[str, float] = {"docker:mydb": time.time()}
        containers = [
            {"name": "mydb", "image": "postgres:16", "status": "Up 2 hours", "running_for": "2 hours"},
        ]
        alerts = check_idle_services(last_alerted, [], containers)
        assert alerts == []

    def test_cooldown_expired_allows_alert(self) -> None:
        last_alerted: dict[str, float] = {"docker:mydb": time.time() - alert_cooldown - 1}
        containers = [
            {"name": "mydb", "image": "postgres:16", "status": "Up 2 hours", "running_for": "2 hours"},
        ]
        alerts = check_idle_services(last_alerted, [], containers)
        assert len(alerts) == 1


# ── collect_metrics (mocked) ─────────────────────────────────────────────


class TestCollectMetrics:
    @patch("sysmon.monitor._read_temp", return_value=55.0)
    @patch("sysmon.monitor.os.getloadavg", return_value=(1.5, 1.0, 0.8))
    @patch("sysmon.monitor.psutil.disk_usage")
    @patch("sysmon.monitor.psutil.swap_memory")
    @patch("sysmon.monitor.psutil.virtual_memory")
    @patch("sysmon.monitor._read_cpu_times")
    def test_returns_all_keys(
        self,
        mock_cpu: MagicMock,
        mock_ram: MagicMock,
        mock_swap: MagicMock,
        mock_disk: MagicMock,
        mock_load: MagicMock,
        mock_temp: MagicMock,
    ) -> None:
        import sysmon.monitor as mod

        # prev: 500 user, 500 idle => curr adds 500 more user, 500 more idle
        mod._prev_cpu_times = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        mock_cpu.return_value = [500, 0, 0, 500, 0, 0, 0, 0, 0, 0]

        mock_ram.return_value = MagicMock(percent=45.0)
        mock_swap.return_value = MagicMock(percent=10.0)
        mock_disk.return_value = MagicMock(percent=60.0)

        result = collect_metrics()

        expected_keys = {
            "cpu_percent", "iowait", "ram_percent",
            "swap_percent", "disk_percent", "cpu_temp", "load_per_cpu",
        }
        assert set(result.keys()) == expected_keys
        assert result["cpu_percent"] == pytest.approx(50.0)
        assert result["ram_percent"] == 45.0
        assert result["cpu_temp"] == 55.0


# ── scan_watched_processes (mocked) ──────────────────────────────────────


class TestScanWatchedProcesses:
    @patch("sysmon.monitor.psutil.process_iter")
    def test_finds_watchlisted(self, mock_iter: MagicMock) -> None:
        now = time.time()
        proc = MagicMock()
        proc.info = {"name": "zoom", "create_time": now - 3600}
        mock_iter.return_value = [proc]

        result = scan_watched_processes()
        assert len(result) == 1
        assert result[0].key == "zoom"
        assert result[0].label == "Zoom"
        assert result[0].age_minutes == pytest.approx(60.0, abs=1.0)

    @patch("sysmon.monitor.psutil.process_iter")
    def test_ignores_non_watchlisted(self, mock_iter: MagicMock) -> None:
        proc = MagicMock()
        proc.info = {"name": "randomprocess", "create_time": time.time() - 7200}
        mock_iter.return_value = [proc]

        result = scan_watched_processes()
        assert result == []

    @patch("sysmon.monitor.psutil.process_iter")
    def test_deduplicates(self, mock_iter: MagicMock) -> None:
        now = time.time()
        p1 = MagicMock()
        p1.info = {"name": "zoom", "create_time": now - 3600}
        p2 = MagicMock()
        p2.info = {"name": "zoom-helper", "create_time": now - 3600}
        mock_iter.return_value = [p1, p2]

        result = scan_watched_processes()
        # "zoom" appears in both names, but should only be counted once
        zoom_results = [r for r in result if r.key == "zoom"]
        assert len(zoom_results) == 1


# ── _get_running_docker_containers (mocked) ──────────────────────────────


class TestGetRunningDockerContainers:
    @patch("sysmon.monitor.subprocess.run")
    def test_parses_output(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="mydb\tpostgres:16\tUp 2 hours\t2 hours\nredis\tredis:7\tUp 30 minutes\t30 minutes\n",
        )
        result = _get_running_docker_containers()
        assert len(result) == 2
        assert result[0]["name"] == "mydb"
        assert result[0]["image"] == "postgres:16"

    @patch("sysmon.monitor.subprocess.run")
    def test_docker_not_installed(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError
        result = _get_running_docker_containers()
        assert result == []

    @patch("sysmon.monitor.subprocess.run")
    def test_docker_error(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        result = _get_running_docker_containers()
        assert result == []


# ── send_alert (mocked) ──────────────────────────────────────────────────


class TestSendAlert:
    @patch("sysmon.monitor.subprocess.run")
    def test_warning_sends_notify(self, mock_run: MagicMock) -> None:
        alert = Alert(
            metric="ram_percent",
            severity="warning",
            value=90.0,
            threshold=85.0,
            unit="%",
        )
        send_alert(alert)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "notify-send"
        assert "--urgency=normal" in args
        assert "[WARNING]" in args[-2]

    @patch("sysmon.monitor.subprocess.run")
    def test_critical_sends_notify(self, mock_run: MagicMock) -> None:
        alert = Alert(
            metric="cpu_percent",
            severity="critical",
            value=98.0,
            threshold=95.0,
            unit="%",
        )
        send_alert(alert)
        args = mock_run.call_args[0][0]
        assert "--urgency=critical" in args
        assert "[CRITICAL]" in args[-2]

    @patch("sysmon.monitor.subprocess.run", side_effect=FileNotFoundError)
    def test_missing_notify_send(self, mock_run: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        alert = Alert(metric="ram_percent", severity="warning", value=90.0, threshold=85.0, unit="%")
        send_alert(alert)
        captured = capsys.readouterr()
        assert "notify-send not found" in captured.out


# ── _detect_terminal (mocked) ────────────────────────────────────────────


class TestDetectTerminal:
    @patch("sysmon.monitor.shutil.which")
    def test_ghostty_found(self, mock_which: MagicMock) -> None:
        mock_which.side_effect = lambda cmd: "/usr/bin/ghostty" if cmd == "ghostty" else None
        assert _detect_terminal() == ["ghostty", "-e"]

    @patch("sysmon.monitor.shutil.which")
    def test_gnome_terminal_fallback(self, mock_which: MagicMock) -> None:
        def which(cmd: str) -> str | None:
            return "/usr/bin/gnome-terminal" if cmd == "gnome-terminal" else None
        mock_which.side_effect = which
        assert _detect_terminal() == ["gnome-terminal", "--"]

    @patch("sysmon.monitor.shutil.which", return_value=None)
    def test_no_terminal(self, mock_which: MagicMock) -> None:
        assert _detect_terminal() == []
