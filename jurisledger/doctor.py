"""`jurisledger doctor`: is this machine set up the way JurisLedger expects?

Most "it doesn't work" reports are environment problems: two Python environments active at once,
a package installed into one and the tests run from the other, a missing Node for the browser
cross-tests, or a key file readable by other users.  Each check prints OK, WARN or FAIL with the
fix, and the exit code is non-zero if anything FAILed.
"""
from __future__ import annotations

import importlib
import os
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

Result = Tuple[str, str, str]           # (level, what, fix)


def checks() -> List[Result]:
    out: List[Result] = []
    py = sys.executable
    out.append(("OK" if sys.version_info >= (3, 10) else "FAIL", f"Python {sys.version.split()[0]} at {py}",
                "" if sys.version_info >= (3, 10) else "use Python 3.10 or newer"))
    venv, conda = os.environ.get("VIRTUAL_ENV"), os.environ.get("CONDA_PREFIX")
    if venv and conda:
        out.append(("WARN", f"two environments are active: venv {venv} and conda {conda}",
                    "run `deactivate` so only the conda environment is active, then reinstall with pip install -e \".[dev]\""))
    try:
        import cryptography
        out.append(("OK", f"cryptography {cryptography.__version__} importable from this Python", ""))
    except ImportError:
        out.append(("FAIL", "the cryptography package is not installed for this Python",
                    f"{py} -m pip install -e \".[dev]\"   (or deactivate a stray venv first)"))
    for mod in ("pytest",):
        try:
            importlib.import_module(mod)
            out.append(("OK", f"{mod} importable (run tests as: python -m pytest)", ""))
        except ImportError:
            out.append(("WARN", f"{mod} is not installed for this Python", f"{py} -m pip install -e \".[dev]\""))
    pyt = shutil.which("pytest")
    if pyt and not Path(pyt).resolve().is_relative_to(Path(sys.prefix).resolve()):
        out.append(("WARN", f"the `pytest` on PATH ({pyt}) belongs to a different Python",
                    "always run `python -m pytest`"))
    jl = shutil.which("jurisledger")
    if jl:
        try:
            first = Path(jl).read_text(errors="replace").splitlines()[0]
            if first.startswith("#!") and Path(first[2:].strip()).resolve() != Path(py).resolve():
                out.append(("WARN", f"the `jurisledger` command runs {first[2:].strip()}, but this is {py}",
                            "commands and tests are using different Pythons; deactivate the extra environment"))
        except (OSError, IndexError):
            pass
    import jurisledger
    here = Path(jurisledger.__file__).resolve().parent
    out.append(("OK", f"jurisledger {jurisledger.__version__} loaded from {here}", ""))
    node = shutil.which("node")
    if node:
        v = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip()
        major = int(v.lstrip("v").split(".")[0] or 0)
        out.append(("OK" if major >= 20 else "WARN", f"Node {v} (browser cross-tests)",
                    "" if major >= 20 else "install Node 20 or newer for the WebCrypto Ed25519 tests"))
    else:
        out.append(("WARN", "Node is not installed: the browser cross-tests will be skipped",
                    "sudo apt install nodejs   (version 20 or newer)"))
    out.append(("OK" if ssl.HAS_TLSv1_3 else "FAIL", f"{ssl.OPENSSL_VERSION}, TLS 1.3 {'available' if ssl.HAS_TLSv1_3 else 'MISSING'}",
                "" if ssl.HAS_TLSv1_3 else "validators need TLS 1.3"))
    try:
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.close()
        out.append(("OK", "can open local network ports", ""))
    except OSError as err:
        out.append(("FAIL", f"cannot open a local port: {err}", "check firewall or sandbox settings"))
    loose = [p for p in Path.cwd().glob("**/*.key.json") if os.name == "posix" and p.stat().st_mode & 0o077][:5]
    for p in loose:
        out.append(("WARN", f"{p} is readable by other users", f"chmod 600 {p}"))
    return out


def run() -> int:
    worst = 0
    for level, what, fix in checks():
        mark = {"OK": "  ok  ", "WARN": " warn ", "FAIL": " FAIL "}[level]
        print(f"[{mark}] {what}" + (f"\n         fix: {fix}" if fix else ""))
        worst = max(worst, {"OK": 0, "WARN": 1, "FAIL": 2}[level])
    print("\nAll good." if worst == 0 else "\nSome warnings above; things may still work." if worst == 1 else "\nFix the FAIL lines first.")
    return 1 if worst == 2 else 0


if __name__ == "__main__":
    sys.exit(run())
