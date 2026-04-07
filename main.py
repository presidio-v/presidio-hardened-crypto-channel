"""Experiment runner for presidio-hardened-crypto-channel."""

from __future__ import annotations

import argparse
import json
import sys


def cmd_keyexchange(args: argparse.Namespace) -> None:
    from presidio_crypto_channel import run_key_exchange

    results = run_key_exchange(args.parties)
    for r in results:
        print(f"\n--- Key Exchange: {r.party_a} <-> {r.party_b} ---")
        print(f"  Session key ({r.key_length_bits}-bit): {r.session_key_hex[:32]}...")
        print(f"  Keys match:  {r.keys_match}")
        print(f"  Duration:    {r.duration_ms} ms")
        if not r.keys_match:
            print("ERROR: session keys do not match!", file=sys.stderr)
            sys.exit(1)
    print("\nPresidio hardening applied: X25519 ECDH + HKDF-SHA256 session key derivation.")


def cmd_symmetric(args: argparse.Namespace) -> None:
    from presidio_crypto_channel import run_symmetric_demo

    enc, dec = run_symmetric_demo(args.message, args.key_size)
    print(f"\n--- AES-{args.key_size}-GCM Encryption ---")
    print(f"  Plaintext:   {args.message!r}")
    print(f"  Key bits:    {enc.key_bits}")
    print(f"  Nonce:       {enc.nonce_hex}")
    print(f"  Ciphertext:  {enc.ciphertext_hex[:40]}...  ({enc.ciphertext_length} bytes)")
    print("  Auth tag:    included in ciphertext (GCM)")
    print(f"  Encrypt:     {enc.duration_ms} ms")
    print("\n--- Decryption ---")
    print(f"  Recovered:   {dec.plaintext!r}")
    print(f"  Verified:    {dec.verified}")
    print(f"  Decrypt:     {dec.duration_ms} ms")
    print("\nPresidio hardening applied: AES-256-GCM authenticated encryption.")


def cmd_channel(args: argparse.Namespace) -> None:
    from presidio_crypto_channel import run_channel

    use_hmac = not args.no_hmac
    stats = run_channel(
        client=args.client,
        server=args.server,
        messages=args.messages,
        use_hmac=use_hmac,
        tamper=args.tamper,
        duration=args.duration,
    )
    print(f"\n--- Secure Channel: {stats.client} -> {stats.server} ---")
    print(f"  HMAC enabled:       {stats.hmac_enabled}")
    print(f"  Key exchange:       {stats.key_exchange_ms} ms")
    print(f"  Messages sent:      {stats.messages_sent}")
    print(f"  Messages verified:  {stats.messages_verified}")
    print(f"  Avg encrypt:        {stats.avg_encrypt_ms} ms")
    print(f"  Avg decrypt:        {stats.avg_decrypt_ms} ms")
    print(f"  Total duration:     {stats.duration_s} s")
    if args.tamper:
        if stats.tamper_detected:
            print(
                "\n  [TAMPER] Tampering DETECTED — "
                "InvalidSignature raised before plaintext returned."
            )
        elif stats.tamper_accepted:
            print("\n  [TAMPER] Tampering ACCEPTED silently — no integrity check in place.")
    _save_run_log(stats)


def _save_run_log(stats: object) -> None:
    import dataclasses
    import pathlib

    pathlib.Path("reports").mkdir(exist_ok=True)
    data = dataclasses.asdict(stats) if dataclasses.is_dataclass(stats) else vars(stats)
    with open("reports/last_run.json", "w") as f:
        json.dump(data, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="presidio-hardened-crypto-channel demo")
    parser.add_argument(
        "--demo",
        choices=["keyexchange", "symmetric", "channel"],
        required=True,
    )
    parser.add_argument("--parties", nargs="+", default=["Alice", "Bob"])
    parser.add_argument("--message", default="Hello from Alice")
    parser.add_argument("--key-size", type=int, choices=[128, 192, 256], default=256)
    parser.add_argument("--client", default="Alice")
    parser.add_argument("--server", default="Bob")
    parser.add_argument("--messages", type=int, default=10)
    parser.add_argument("--no-hmac", action="store_true")
    parser.add_argument("--tamper", action="store_true")
    parser.add_argument("--duration", type=int, default=None)

    args = parser.parse_args()
    dispatch = {
        "keyexchange": cmd_keyexchange,
        "symmetric": cmd_symmetric,
        "channel": cmd_channel,
    }
    dispatch[args.demo](args)


if __name__ == "__main__":
    main()
