"""Interactive terminal UI for inspecting and killing a flagged service.

Launched by the monitor in a new terminal window. Shows resource usage
for the offending process/container and offers kill options.

Usage:
    python -m sysmon.inspect_service --process <name>
    python -m sysmon.inspect_service --docker <container_name>
"""

import argparse
import os
import subprocess
import time

import psutil

# ── ANSI helpers ────────────────────────────────────────────────────────────

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"


def _hr() -> str:
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 60
    return "─" * cols


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} TB"


# ── Process inspection ──────────────────────────────────────────────────────

def _find_processes(name: str) -> list[psutil.Process]:
    """Find all processes matching a name (case-insensitive substring)."""
    name_lower = name.lower()
    matched = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            pname = (proc.info["name"] or "").lower()
            if name_lower in pname:
                matched.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return matched


def _show_process_table(procs: list[psutil.Process]) -> None:
    """Print a resource table for a set of processes."""
    header = f"  {'PID':>7s}  {'CPU%':>6s}  {'MEM':>10s}  {'MEM%':>5s}  {'UPTIME':>10s}  {'COMMAND'}"
    print(header)
    print(f"  {'─'*7}  {'─'*6}  {'─'*10}  {'─'*5}  {'─'*10}  {'─'*30}")

    total_mem = 0
    total_cpu = 0.0
    for proc in procs:
        try:
            with proc.oneshot():
                pid = proc.pid
                cpu = proc.cpu_percent(interval=0)
                mem_info = proc.memory_info()
                mem_pct = proc.memory_percent()
                create = proc.create_time()
                cmdline = proc.cmdline()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        age_s = time.time() - create
        hrs, rem = divmod(int(age_s), 3600)
        mins, _ = divmod(rem, 60)
        age_str = f"{hrs}h {mins}m"

        cmd_str = " ".join(cmdline[:3]) if cmdline else "(unknown)"
        if len(cmd_str) > 45:
            cmd_str = cmd_str[:42] + "..."

        total_mem += mem_info.rss
        total_cpu += cpu

        print(f"  {pid:>7d}  {cpu:>5.1f}%  {_fmt_bytes(mem_info.rss):>10s}  {mem_pct:>4.1f}%  {age_str:>10s}  {cmd_str}")

    print()
    print(f"  {BOLD}Total: {len(procs)} process(es), CPU {total_cpu:.1f}%, MEM {_fmt_bytes(total_mem)}{RESET}")


def inspect_process(name: str) -> None:
    """Inspect and optionally kill a process group."""
    # Warm up cpu_percent (first call returns 0)
    for proc in psutil.process_iter(["pid"]):
        try:
            proc.cpu_percent(interval=0)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(0.5)

    procs = _find_processes(name)
    if not procs:
        print(f"\n  {YELLOW}No processes found matching '{name}'{RESET}")
        _wait_dismiss()
        return

    print(f"\n{_hr()}")
    print(f"  {BOLD}{CYAN}sysmon — Process Inspector{RESET}")
    print(f"  Matching: {BOLD}{name}{RESET} ({len(procs)} process(es))")
    print(f"{_hr()}\n")

    _show_process_table(procs)

    print(f"\n{_hr()}")
    print(f"  {BOLD}Options:{RESET}")
    print(f"    {GREEN}[g]{RESET} Graceful stop (SIGTERM) — let it clean up")
    print(f"    {RED}[k]{RESET} Force kill (SIGKILL) — immediate")
    print(f"    {DIM}[d]{RESET} Dismiss — do nothing")
    print(f"{_hr()}")

    choice = input(f"\n  Choice [g/k/d]: ").strip().lower()

    if choice == "g":
        print(f"\n  Sending SIGTERM to {len(procs)} process(es)...")
        for proc in procs:
            try:
                proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"    {YELLOW}PID {proc.pid}: {e}{RESET}")
        # Wait briefly and check
        gone, alive = psutil.wait_procs(procs, timeout=5)
        if alive:
            print(f"  {YELLOW}{len(alive)} process(es) still running after 5s{RESET}")
            force = input(f"  Force kill remaining? [y/N]: ").strip().lower()
            if force == "y":
                for proc in alive:
                    try:
                        proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                print(f"  {RED}Force killed.{RESET}")
        else:
            print(f"  {GREEN}All processes stopped.{RESET}")

    elif choice == "k":
        print(f"\n  {RED}Sending SIGKILL to {len(procs)} process(es)...{RESET}")
        for proc in procs:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"    {YELLOW}PID {proc.pid}: {e}{RESET}")
        print(f"  {GREEN}Done.{RESET}")

    else:
        print(f"\n  Dismissed.")

    _wait_dismiss()


# ── Docker inspection ───────────────────────────────────────────────────────

def inspect_docker(container_name: str) -> None:
    """Inspect and optionally stop a Docker container."""
    # Get container stats
    try:
        stats = subprocess.run(
            ["docker", "stats", container_name, "--no-stream",
             "--format", "{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}"],
            capture_output=True, text=True, timeout=10,
        )
        info = subprocess.run(
            ["docker", "inspect", container_name,
             "--format", "{{.Config.Image}}\t{{.State.StartedAt}}\t{{.State.Status}}"],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print(f"  {RED}Docker not available{RESET}")
        _wait_dismiss()
        return

    if stats.returncode != 0 or info.returncode != 0:
        print(f"\n  {YELLOW}Container '{container_name}' not found or not running{RESET}")
        _wait_dismiss()
        return

    print(f"\n{_hr()}")
    print(f"  {BOLD}{CYAN}sysmon — Docker Inspector{RESET}")
    print(f"  Container: {BOLD}{container_name}{RESET}")
    print(f"{_hr()}\n")

    # Parse info
    info_parts = info.stdout.strip().split("\t")
    image = info_parts[0] if len(info_parts) > 0 else "?"
    started = info_parts[1][:19].replace("T", " ") if len(info_parts) > 1 else "?"
    status = info_parts[2] if len(info_parts) > 2 else "?"

    print(f"  {'Image':12s}  {image}")
    print(f"  {'Status':12s}  {status}")
    print(f"  {'Started':12s}  {started}")
    print()

    # Parse stats
    stat_parts = stats.stdout.strip().split("\t")
    if len(stat_parts) >= 6:
        labels = ["CPU %", "Memory", "MEM %", "Net I/O", "Block I/O", "PIDs"]
        for label, val in zip(labels, stat_parts):
            print(f"  {label:12s}  {val}")
    else:
        print(f"  {DIM}(stats unavailable){RESET}")

    # List processes inside the container
    print()
    top = subprocess.run(
        ["docker", "top", container_name, "-o", "pid,pcpu,pmem,comm"],
        capture_output=True, text=True, timeout=5,
    )
    if top.returncode == 0 and top.stdout.strip():
        print(f"  {BOLD}Container processes:{RESET}")
        for line in top.stdout.strip().splitlines():
            print(f"    {line}")

    print(f"\n{_hr()}")
    print(f"  {BOLD}Options:{RESET}")
    print(f"    {GREEN}[s]{RESET} docker stop  — graceful shutdown (10s timeout)")
    print(f"    {RED}[k]{RESET} docker kill  — immediate SIGKILL")
    print(f"    {DIM}[d]{RESET} Dismiss — do nothing")
    print(f"{_hr()}")

    choice = input(f"\n  Choice [s/k/d]: ").strip().lower()

    if choice == "s":
        print(f"\n  Stopping {container_name}...")
        result = subprocess.run(
            ["docker", "stop", container_name],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            print(f"  {GREEN}Stopped.{RESET}")
        else:
            print(f"  {RED}Failed: {result.stderr.strip()}{RESET}")

    elif choice == "k":
        print(f"\n  {RED}Killing {container_name}...{RESET}")
        result = subprocess.run(
            ["docker", "kill", container_name],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            print(f"  {GREEN}Killed.{RESET}")
        else:
            print(f"  {RED}Failed: {result.stderr.strip()}{RESET}")

    else:
        print(f"\n  Dismissed.")

    _wait_dismiss()


# ── Helpers ─────────────────────────────────────────────────────────────────

def _wait_dismiss() -> None:
    """Wait for user to press Enter before closing the terminal."""
    print(f"\n  {DIM}Press Enter to close...{RESET}")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect a service flagged by sysmon.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--process", "-p", help="Process name to inspect")
    group.add_argument("--docker", "-d", help="Docker container name to inspect")
    args = parser.parse_args()

    if args.process:
        inspect_process(args.process)
    elif args.docker:
        inspect_docker(args.docker)


if __name__ == "__main__":
    main()
