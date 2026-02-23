"""Tests for sysmon.inspect_service."""

from unittest.mock import MagicMock, patch

import psutil

from sysmon.inspect_service import _find_processes, _fmt_bytes


# ── _fmt_bytes ────────────────────────────────────────────────────────────


class TestFmtBytes:
    def test_bytes(self) -> None:
        assert _fmt_bytes(500) == "500.0 B"

    def test_kilobytes(self) -> None:
        assert _fmt_bytes(2048) == "2.0 KB"

    def test_megabytes(self) -> None:
        assert _fmt_bytes(5 * 1024 * 1024) == "5.0 MB"

    def test_gigabytes(self) -> None:
        assert _fmt_bytes(3 * 1024 * 1024 * 1024) == "3.0 GB"

    def test_terabytes(self) -> None:
        assert _fmt_bytes(2 * 1024 * 1024 * 1024 * 1024) == "2.0 TB"

    def test_zero(self) -> None:
        assert _fmt_bytes(0) == "0.0 B"

    def test_fractional_kb(self) -> None:
        assert _fmt_bytes(1536) == "1.5 KB"


# ── _find_processes (mocked) ─────────────────────────────────────────────


class TestFindProcesses:
    @patch("sysmon.inspect_service.psutil.process_iter")
    def test_finds_matching(self, mock_iter: MagicMock) -> None:
        proc = MagicMock(spec=psutil.Process)
        proc.info = {"pid": 1234, "name": "zoom", "cmdline": ["zoom"]}
        mock_iter.return_value = [proc]

        result = _find_processes("zoom")
        assert len(result) == 1
        assert result[0] is proc

    @patch("sysmon.inspect_service.psutil.process_iter")
    def test_case_insensitive(self, mock_iter: MagicMock) -> None:
        proc = MagicMock(spec=psutil.Process)
        proc.info = {"pid": 1234, "name": "Zoom", "cmdline": ["Zoom"]}
        mock_iter.return_value = [proc]

        result = _find_processes("zoom")
        assert len(result) == 1

    @patch("sysmon.inspect_service.psutil.process_iter")
    def test_no_match(self, mock_iter: MagicMock) -> None:
        proc = MagicMock(spec=psutil.Process)
        proc.info = {"pid": 1234, "name": "firefox", "cmdline": ["firefox"]}
        mock_iter.return_value = [proc]

        result = _find_processes("zoom")
        assert result == []

    @patch("sysmon.inspect_service.psutil.process_iter")
    def test_handles_access_denied(self, mock_iter: MagicMock) -> None:
        proc = MagicMock()
        proc.info = {"pid": 1, "name": None, "cmdline": []}
        mock_iter.return_value = [proc]

        # name is None, so (proc.info["name"] or "").lower() = "" which won't match "zoom"
        result = _find_processes("zoom")
        assert result == []

    @patch("sysmon.inspect_service.psutil.process_iter")
    def test_substring_match(self, mock_iter: MagicMock) -> None:
        proc = MagicMock(spec=psutil.Process)
        proc.info = {"pid": 1234, "name": "zoom-helper", "cmdline": ["zoom-helper"]}
        mock_iter.return_value = [proc]

        result = _find_processes("zoom")
        assert len(result) == 1
