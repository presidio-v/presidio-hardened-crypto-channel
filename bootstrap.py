"""Create the project virtual environment and install dependencies.

Usage: python bootstrap.py
"""

import os
import subprocess
import sys
import venv
from pathlib import Path

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
    python = venv_python()
    if not python.is_file():
        print("Creating virtual environment at .venv...")
        venv.create(VENV_DIR, with_pip=True)
        print("Virtual environment created.")
    else:
        print("Virtual environment already exists.")

    print("bootstrap: upgrading pip...")
    subprocess.run(  # noqa: S603 - executes the project-local virtual environment
        [str(python), "-m", "pip", "install", "--upgrade", "pip"],
        check=True,
    )

    print("bootstrap: installing project in development mode...")
    subprocess.run(  # noqa: S603 - executes the project-local virtual environment
        [str(python), "-m", "pip", "install", "-e", f"{ROOT}[dev]"],
        check=True,
    )

    print("\nBootstrap complete! To run the project:")
    print(f"  {python} main.py --demo channel --client Alice --server Bob")
    print(f"  {python} -m pytest -q\n")


if __name__ == "__main__":
    main()
