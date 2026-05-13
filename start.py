#!/usr/bin/env python3
"""
start.py — VulnScan Pro Single-Command Launcher
------------------------------------------------
Run this once and it handles everything:
  1. Checks Python version
  2. Creates virtual environment
  3. Installs all dependencies
  4. Checks nmap is installed
  5. Sets a default API key if not set
  6. Launches the web server
  7. Opens the dashboard in your browser

Usage:
  python start.py
"""

import os
import sys
import subprocess
import platform
import shutil
import time
import webbrowser
import secrets

if platform.system() == "Windows":
    os.system("color")

R  = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C  = "\033[96m"; DIM = "\033[2m"; BO = "\033[1m"; RS = "\033[0m"

BANNER = f"""
{C}{BO}
 __   __      _       _____                  ____
 \\ \\ / /__ _ | | _ _ / ____|  ___  __ _  _ __ _ \\_
  \\ V // _` || || ' \\\\__ \\ / __|/ _` || '_ \\| '_  |
   \\_/ \\__,_||_||_||_|___/ \\___\\\\__,_||_| |_|_| |_|
{RS}{DIM}  Web Dashboard Edition  |  v3.0.0  |  pharaoh77731 
{RS}"""

VENV_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")
BACKEND_DIR= os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
PORT       = int(os.environ.get("PORT", 5000))


def step(msg):  print(f"  {C}[*]{RS} {msg}")
def ok(msg):    print(f"  {G}[✓]{RS} {msg}")
def warn(msg):  print(f"  {Y}[!]{RS} {msg}")
def err(msg):   print(f"  {R}[✗]{RS} {msg}")
def sep():      print(f"  {DIM}{'─'*52}{RS}")


def check_python():
    step("Checking Python version...")
    v = sys.version_info
    if v.major < 3 or (v.major == 3 and v.minor < 8):
        err(f"Python 3.8+ required. You have {v.major}.{v.minor}.")
        sys.exit(1)
    ok(f"Python {v.major}.{v.minor}.{v.micro}")


def setup_venv():
    if os.path.exists(VENV_DIR):
        ok("Virtual environment already exists.")
        return
    step("Creating virtual environment (.venv)...")
    subprocess.run([sys.executable, "-m", "venv", VENV_DIR], check=True, capture_output=True)
    ok("Virtual environment created.")


def get_venv_python():
    is_win = platform.system() == "Windows"
    bindir = "Scripts" if is_win else "bin"
    ext    = ".exe" if is_win else ""
    return (
        os.path.join(VENV_DIR, bindir, f"python{ext}"),
        os.path.join(VENV_DIR, bindir, f"pip{ext}"),
    )


def install_deps(pip_exe):
    req = os.path.join(BACKEND_DIR, "requirements.txt")
    python_exe, _ = get_venv_python()
    probe = subprocess.run([python_exe, "-c", "import flask, nmap, requests"], capture_output=True)
    if probe.returncode == 0:
        ok("Dependencies already installed.")
        return
    step("Installing dependencies (first run only)...")
    subprocess.run([pip_exe, "install", "-r", req, "-q", "--disable-pip-version-check"], check=True)
    ok("All dependencies installed.")


def check_nmap():
    step("Checking for nmap...")
    if shutil.which("nmap"):
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        ok(result.stdout.split("\n")[0])
        return True
    warn("nmap not found — scanning will not work.")
    system = platform.system()
    if system == "Windows":
        print(f"  {Y}Install from: https://nmap.org/download.html{RS}")
    elif system == "Darwin":
        print(f"  {Y}Run: brew install nmap{RS}")
    else:
        print(f"  {Y}Run: sudo apt install nmap{RS}")
    return False


def ensure_api_key():
    step("Checking API key...")
    key = os.environ.get("VULNSCAN_API_KEY", "")
    if not key or key == "change-this-secret-key-in-production":
        key = secrets.token_hex(16)
        os.environ["VULNSCAN_API_KEY"] = key
        print(f"\n  {G}Generated API key:{RS} {BO}{key}{RS}")
        print(f"  {DIM}Paste this into the API Key field in the dashboard.{RS}\n")
    else:
        ok(f"API key set (from environment).")
    return key


def launch(python_exe, api_key):
    sep()
    ok(f"Launching VulnScan Pro on http://localhost:{PORT} ...")
    print(f"\n  {BO}API Key:{RS} {api_key}")
    print(f"  {DIM}Paste this in the dashboard's API Key field.{RS}\n")
    sep()
    print()

    app_file = os.path.join(BACKEND_DIR, "app.py")
    env = {**os.environ, "VULNSCAN_API_KEY": api_key, "PORT": str(PORT)}

    # Open browser after short delay
    def open_browser():
        time.sleep(2)
        webbrowser.open(f"http://localhost:{PORT}")

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    try:
        subprocess.run([python_exe, app_file], env=env, cwd=BACKEND_DIR)
    except KeyboardInterrupt:
        print(f"\n  {Y}VulnScan Pro stopped.{RS}\n")


def main():
    print(BANNER)
    print(f"  {BO}Starting VulnScan Pro...{RS}\n")
    sep()
    check_python()
    setup_venv()
    python_exe, pip_exe = get_venv_python()
    install_deps(pip_exe)
    check_nmap()
    api_key = ensure_api_key()
    print(f"\n  {G}{BO}✓ Ready!{RS}\n")
    launch(python_exe, api_key)


if __name__ == "__main__":
    main()
