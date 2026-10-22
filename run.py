"""
Cerberus Unified Terminal Launcher (`run.py`)
=============================================
Starts the FastAPI Backend (`api.py`), the React + Vite Frontend (`frontend/`),
and optionally the Sentinel HIDS Daemon (`sentinel_engine.py`) concurrently in a
single terminal window with color-coded log prefixes and graceful Ctrl+C shutdown.

Usage:
    python run.py                # Starts Backend (port 8000) + Frontend (port 3000)
    python run.py --with-engine  # Also starts sentinel_engine.py log watcher
    python run.py --open         # Automatically opens http://localhost:3000 in browser
    python run.py --prod         # Serves pre-built frontend/dist via serve_frontend.py
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
import webbrowser

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

# ANSI color codes for multiplexed terminal output
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"


def _enable_windows_ansi() -> None:
    """Enables ANSI escape sequence rendering on Windows consoles."""
    if os.name == "nt":
        os.system("")  # nosec B605 B607


def _stream_output(proc: subprocess.Popen, prefix: str, color: str) -> None:
    """Reads lines from a subprocess stdout/stderr pipe and prints with a colored prefix."""
    if proc.stdout is None:
        return
    try:
        for raw_line in iter(proc.stdout.readline, ""):
            if not raw_line:
                break
            line = raw_line.rstrip("\r\n")
            print(f"{color}{BOLD}[{prefix}]{RESET} {line}", flush=True)
    except Exception:
        pass


def _resolve_npm_cmd() -> str | None:
    """Finds the npm executable across Windows (.cmd) and POSIX platforms."""
    if os.name == "nt":
        return shutil.which("npm.cmd") or shutil.which("npm")
    return shutil.which("npm")


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    """Gracefully terminates a child process (and its tree on Windows)."""
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    except Exception:
        pass


def main() -> int:
    _enable_windows_ansi()

    parser = argparse.ArgumentParser(
        description="Cerberus SOC — Unified Single-Terminal Launcher (Backend + Frontend)"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Backend bind host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=8000,
        help="FastAPI backend port (default: 8000)",
    )
    parser.add_argument(
        "--ui-port",
        type=int,
        default=3000,
        help="Frontend web console port (default: 3000)",
    )
    parser.add_argument(
        "--with-engine",
        action="store_true",
        help="Also launch the Sentinel HIDS log monitoring daemon (sentinel_engine.py)",
    )
    parser.add_argument(
        "--prod",
        action="store_true",
        help="Serve the static production build (frontend/dist) instead of Vite dev server",
    )
    parser.add_argument(
        "--no-reload",
        action="store_true",
        help="Disable uvicorn auto-reload on backend file changes",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Automatically open the SOC Console in your default web browser",
    )
    args = parser.parse_args()

    # Ensure required admin credentials have sensible local development defaults if not set
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    if not env.get("ADMIN_USERNAME"):
        env["ADMIN_USERNAME"] = "admin"
    if not env.get("ADMIN_PASSWORD"):
        env["ADMIN_PASSWORD"] = "Cerberus@Dev2026!"
        print(
            f"{YELLOW}[NOTICE]{RESET} ADMIN_PASSWORD not set in environment; "
            f"using local dev default: {BOLD}admin / Cerberus@Dev2026!{RESET}"
        )

    print(f"\n{CYAN}{BOLD}============================================================{RESET}")
    print(f"{CYAN}{BOLD}  🛡️  CERBERUS SOC — UNIFIED CONSOLE LAUNCHER v1.0.0{RESET}")
    print(f"{CYAN}{BOLD}============================================================{RESET}")
    print(f"  {GREEN}► Backend API:{RESET}      http://{args.host}:{args.api_port}")
    print(f"  {MAGENTA}► SOC Web Console:{RESET}  http://localhost:{args.ui_port}")
    print(f"  {CYAN}► Health & Docs:{RESET}    http://{args.host}:{args.api_port}/docs")
    if args.with_engine:
        print(f"  {YELLOW}► Sentinel Daemon:{RESET}  Active (sentinel_engine.py)")
    print(f"  {YELLOW}► Stop All:{RESET}         Press Ctrl+C to shut down cleanly")
    print(f"{CYAN}{BOLD}============================================================{RESET}\n")

    processes: list[tuple[str, subprocess.Popen]] = []
    threads: list[threading.Thread] = []

    def start_service(name: str, cmd: list[str], cwd: str, color: str) -> subprocess.Popen:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace",
        )
        t = threading.Thread(target=_stream_output, args=(proc, name, color), daemon=True)
        t.start()
        processes.append((name, proc))
        threads.append(t)
        return proc

    try:
        # 1. Start FastAPI Backend
        uvicorn_cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "api:app",
            "--host",
            args.host,
            "--port",
            str(args.api_port),
        ]
        if not args.no_reload:
            uvicorn_cmd.append("--reload")

        start_service("BACKEND ", uvicorn_cmd, ROOT_DIR, CYAN)

        # 2. Start Frontend (Vite dev server or static server)
        npm_bin = _resolve_npm_cmd()
        node_modules_exists = os.path.isdir(os.path.join(FRONTEND_DIR, "node_modules"))

        if not args.prod and npm_bin:
            if not node_modules_exists:
                print(
                    f"{MAGENTA}{BOLD}[FRONTEND]{RESET} Installing frontend npm dependencies first..."
                )
                subprocess.run([npm_bin, "install"], cwd=FRONTEND_DIR, check=True)

            frontend_cmd = [
                npm_bin,
                "run",
                "dev",
                "--",
                "--port",
                str(args.ui_port),
            ]
            start_service("FRONTEND", frontend_cmd, FRONTEND_DIR, MAGENTA)
        else:
            frontend_cmd = [sys.executable, "serve_frontend.py"]
            start_service("FRONTEND", frontend_cmd, ROOT_DIR, MAGENTA)

        # 3. Optionally start Sentinel HIDS Engine
        if args.with_engine:
            engine_cmd = [sys.executable, "sentinel_engine.py"]
            start_service("SENTINEL", engine_cmd, ROOT_DIR, YELLOW)

        if args.open:
            time.sleep(2.0)
            webbrowser.open(f"http://localhost:{args.ui_port}")

        # Monitor child processes until interrupted or one exits unexpectedly
        while True:
            time.sleep(0.5)
            for name, proc in processes:
                ret = proc.poll()
                if ret is not None:
                    print(
                        f"\n{RED}{BOLD}[{name.strip()}]{RESET} exited with status code {ret}. "
                        "Shutting down remaining services..."
                    )
                    return ret

    except KeyboardInterrupt:
        print(f"\n{YELLOW}{BOLD}[CERBERUS]{RESET} Caught interrupt — stopping all services...")
        return 0
    finally:
        for _, proc in processes:
            _terminate_process_tree(proc)
        print(f"{GREEN}{BOLD}[CERBERUS]{RESET} All services stopped cleanly.")


if __name__ == "__main__":
    raise SystemExit(main())
