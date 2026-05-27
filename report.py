"""Report generator for Experiment 1 — Cryptography."""

from __future__ import annotations

import os
import sys

# Added this block to auto-run inside the local .venv.
# On Windows, I couldn't activate the virtualenv in PowerShell due to execution
# policies, so this automatically launches the script in the venv.
try:
    import presidio_crypto_channel  # noqa: F401 - ignore unused import
except ImportError:
    # don't re-run to avoid infinite loops
    if ".venv" not in sys.executable:
        from pathlib import Path

        subdir = "Scripts/python.exe" if os.name == "nt" else "bin/python"
        venv_py = Path(__file__).parent / ".venv" / subdir
        if venv_py.exists():
            import subprocess

            sys.exit(subprocess.call([str(venv_py)] + sys.argv))  # noqa: S603 - runs using the venv

    print("Error: presidio-hardened-crypto-channel is not installed.", file=sys.stderr)
    print("Please run 'python bootstrap.py' first to set up the project.", file=sys.stderr)
    sys.exit(1)


import argparse
import json
import pathlib


def _load_last_run() -> dict:
    path = pathlib.Path("reports/last_run.json")
    if not path.exists():
        print("No run log found. Run main.py first.", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def print_experiment_report(data: dict) -> None:
    print("\n========================================")
    print("  Experiment 1 — Cryptography Report")
    print("========================================\n")

    for key, val in data.items():
        label = key.replace("_", " ").title()
        print(f"  {label:<25} {val}")

    print()
    hmac_on = data.get("hmac_enabled", True)
    tamper_detected = data.get("tamper_detected", False)
    tamper_accepted = data.get("tamper_accepted", False)

    print("Key Observations:")
    if tamper_detected:
        print("  * Tamper DETECTED — HMAC raised InvalidSignature before plaintext was returned.")
        print("    Takeaway: authentication (HMAC/GCM tag) provides integrity.")
    elif tamper_accepted:
        print("  * Tamper ACCEPTED silently — no integrity check was active.")
        print("    Takeaway: encryption without authentication does NOT detect bit flips.")
    else:
        print("  * No tampering attempted in this run.")

    if not hmac_on:
        print("  * HMAC was DISABLED (--no-hmac). Rerun with HMAC to compare.")

    enc_ms = data.get("avg_encrypt_ms", 0)
    kex_ms = data.get("key_exchange_ms", 0)
    if kex_ms and enc_ms:
        print(f"  * Key exchange overhead: {kex_ms} ms vs avg encrypt {enc_ms} ms per message.")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Experiment 1 report")
    parser.add_argument("--experiment", type=int, default=1)
    args = parser.parse_args()

    if args.experiment != 1:
        print(f"This script reports on experiment 1. Got: {args.experiment}", file=sys.stderr)
        sys.exit(1)

    data = _load_last_run()
    print_experiment_report(data)


if __name__ == "__main__":
    main()
