"""Create the project virtual environment and install dependencies.

Usage: python bootstrap.py
"""

import os
import subprocess
import sys
from pathlib import Path

# Need Python 3.10+
if sys.version_info < (3, 10):  # noqa: UP036
    print("Error: Python 3.10 or newer is required to run this project.", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).parent.resolve()
VENV_DIR = ROOT / ".venv"


def venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def main() -> None:
    if not VENV_DIR.exists():
        print("Creating virtual environment at .venv...")
        import venv

        venv.create(VENV_DIR, with_pip=True)
        print("Virtual environment created.")
    else:
        print("Virtual environment already exists.")

    py = str(venv_python())

    print("bootstrap: upgrading pip...")
    subprocess.run([py, "-m", "pip", "install", "--upgrade", "pip"], check=True)  # noqa: S603 - runs inside venv

    req = ROOT / "requirements.txt"
    if req.exists():
        print("bootstrap: installing requirements.txt...")
        subprocess.run([py, "-m", "pip", "install", "-r", str(req)], check=True)  # noqa: S603 - runs inside venv

    print("bootstrap: installing project in development mode...")
    subprocess.run([py, "-m", "pip", "install", "-e", f"{ROOT}[dev]"], check=True)  # noqa: S603 - runs inside venv

    print("\nBootstrap complete! To run the project:")
    print(f"  {venv_python()} main.py --demo channel --client Alice --server Bob")
    print(f"  {venv_python()} -m pytest -q\n")


if __name__ == "__main__":
    main()
