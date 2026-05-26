"""Create the project virtual environment and install dependencies.

Usage: python bootstrap.py
"""
import os
import sys
import subprocess
from pathlib import Path

# If the running interpreter is older than required, try to find and re-run
# the script with a suitable Python interpreter (py, python3, python3.10, etc.).
REQUIRED = (3, 10)
if sys.version_info < REQUIRED:
    candidates = []
    if os.name == "nt":
        candidates = [["py", "-3.10"], ["py", "-3"], ["python3.10"], ["python3"], ["python"]]
    else:
        candidates = [["python3.10"], ["python3"], ["python"]]

    for cmd in candidates:
        try:
            check = subprocess.run(cmd + ["-c", "import sys; print(sys.version_info[0], sys.version_info[1])"], capture_output=True, text=True)
            out = check.stdout.strip().split()
            if len(out) >= 2:
                major = int(out[0])
                minor = int(out[1])
                if (major, minor) >= REQUIRED:
                    # Re-exec the script with the found interpreter and same args
                    try:
                        os.execvp(cmd[0], cmd + sys.argv)
                    except Exception:
                        # fall through to try other candidates
                        pass
        except Exception:
            continue

    print("bootstrap: no suitable Python 3.10+ interpreter found; please run with a Python 3.10+ (e.g. 'py -3.10' or 'python3')", file=sys.stderr)

import venv

ROOT = Path(__file__).parent.resolve()
VENV_DIR = ROOT / ".venv"


def venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def run(cmd, **kwargs):
    # keep output concise and avoid typing generics for older interpreters
    print("bootstrap: running:", " ".join(cmd))
    return subprocess.run(cmd, **kwargs).returncode


def create_venv() -> None:
    if VENV_DIR.exists():
        print(f"Virtualenv already exists at {VENV_DIR}")
        return
    print("Creating virtual environment at .venv ...")
    venv.create(VENV_DIR, with_pip=True)
    print("Virtualenv created.")


def install_requirements() -> None:
    py = str(venv_python())
    if not Path(py).exists():
        print("ERROR: venv python not found. Did venv creation fail?", file=sys.stderr)
        sys.exit(2)

    # upgrade pip
    run([py, "-m", "pip", "install", "--upgrade", "pip"], check=True)

    # install requirements
    req = ROOT / "requirements.txt"
    if req.exists():
        run([py, "-m", "pip", "install", "-r", str(req)], check=True)

    # install package editable so imports work
    run([py, "-m", "pip", "install", "-e", str(ROOT)], check=True)


def write_wrappers() -> None:
    # No wrapper scripts are created.
    return


def print_next_steps() -> None:
    print("\nBootstrap complete. Examples:\n")
    print(f"  {venv_python()} main.py --demo channel --client Alice --server Bob")
    print(f"  {venv_python()} -m pytest -q\n")


def main() -> None:
    if sys.version_info < (3, 10):
        print("Requires Python 3.10+")

    create_venv()
    install_requirements()
    print_next_steps()


if __name__ == "__main__":
    main()
