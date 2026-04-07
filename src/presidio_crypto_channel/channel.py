"""Full secure channel: ECDH handshake → AES-256-GCM session → optional HMAC integrity."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag

from .keyexchange import Party
from .security import log_security_event
from .symmetric import decrypt, encrypt

_HMAC_KEY_INFO = b"presidio-hmac-key"


def _derive_hmac_key(session_key: bytes) -> bytes:
    return hashlib.sha256(_HMAC_KEY_INFO + session_key).digest()


@dataclass
class ChannelMessage:
    seq: int
    nonce_hex: str
    ciphertext_hex: str
    mac_hex: str | None  # None when HMAC disabled


@dataclass
class ChannelStats:
    client: str
    server: str
    messages_sent: int
    messages_verified: int
    tamper_detected: bool
    tamper_accepted: bool
    hmac_enabled: bool
    key_exchange_ms: float
    avg_encrypt_ms: float
    avg_decrypt_ms: float
    duration_s: float


class SecureChannel:
    def __init__(self, client_name: str, server_name: str, use_hmac: bool = True) -> None:
        self.client_name = client_name
        self.server_name = server_name
        self.use_hmac = use_hmac

        t0 = time.perf_counter()
        client = Party(client_name)
        server = Party(server_name)
        self.session_key = client.derive_session_key(server.public_bytes())
        self.key_exchange_ms = (time.perf_counter() - t0) * 1000

        if use_hmac:
            self.hmac_key = _derive_hmac_key(self.session_key)
        else:
            self.hmac_key = b""

        log_security_event(
            "channel_established",
            client=client_name,
            server=server_name,
            hmac=use_hmac,
        )

    def _mac(self, nonce: bytes, ciphertext: bytes) -> str:
        if not self.use_hmac:
            return ""
        h = hmac.new(self.hmac_key, nonce + ciphertext, hashlib.sha256)
        return h.hexdigest()

    def send(self, seq: int, plaintext: str, tamper: bool = False) -> ChannelMessage:
        nonce, ciphertext = encrypt(plaintext, self.session_key)
        if tamper:
            ct_list = bytearray(ciphertext)
            ct_list[0] ^= 0xFF
            ciphertext = bytes(ct_list)
        mac = self._mac(nonce, ciphertext)
        return ChannelMessage(
            seq=seq,
            nonce_hex=nonce.hex(),
            ciphertext_hex=ciphertext.hex(),
            mac_hex=mac if mac else None,
        )

    def receive(self, msg: ChannelMessage) -> tuple[str | None, bool]:
        nonce = bytes.fromhex(msg.nonce_hex)
        ciphertext = bytes.fromhex(msg.ciphertext_hex)

        if self.use_hmac:
            expected = self._mac(nonce, ciphertext)
            if not hmac.compare_digest(expected, msg.mac_hex or ""):
                return None, False

        try:
            plaintext = decrypt(nonce, ciphertext, self.session_key)
            return plaintext, True
        except InvalidTag:
            return None, False


@dataclass
class ChannelRunConfig:
    client: str
    server: str
    messages: int
    use_hmac: bool
    tamper: bool
    duration: int | None = None
    _encrypt_times: list[float] = field(default_factory=list, repr=False)
    _decrypt_times: list[float] = field(default_factory=list, repr=False)


def run_channel(
    client: str,
    server: str,
    messages: int = 10,
    use_hmac: bool = True,
    tamper: bool = False,
    duration: int | None = None,
) -> ChannelStats:
    channel = SecureChannel(client, server, use_hmac=use_hmac)
    payloads = [f"Message {i} from {client} to {server}" for i in range(messages)]

    sent = 0
    verified = 0
    tamper_detected = False
    tamper_accepted = False
    encrypt_times: list[float] = []
    decrypt_times: list[float] = []

    wall_start = time.perf_counter()

    for i, payload in enumerate(payloads):
        do_tamper = tamper and i == 0

        t0 = time.perf_counter()
        msg = channel.send(i, payload, tamper=do_tamper)
        encrypt_times.append((time.perf_counter() - t0) * 1000)
        sent += 1

        t1 = time.perf_counter()
        recovered, ok = channel.receive(msg)
        decrypt_times.append((time.perf_counter() - t1) * 1000)

        if do_tamper:
            if ok:
                tamper_accepted = True
            else:
                tamper_detected = True
        elif ok:
            verified += 1

        if duration and (time.perf_counter() - wall_start) >= duration:
            break

    wall_s = time.perf_counter() - wall_start

    stats = ChannelStats(
        client=client,
        server=server,
        messages_sent=sent,
        messages_verified=verified,
        tamper_detected=tamper_detected,
        tamper_accepted=tamper_accepted,
        hmac_enabled=use_hmac,
        key_exchange_ms=round(channel.key_exchange_ms, 3),
        avg_encrypt_ms=round(sum(encrypt_times) / len(encrypt_times), 3) if encrypt_times else 0,
        avg_decrypt_ms=round(sum(decrypt_times) / len(decrypt_times), 3) if decrypt_times else 0,
        duration_s=round(wall_s, 3),
    )

    log_security_event(
        "channel_run_complete",
        messages=sent,
        verified=verified,
        tamper_detected=tamper_detected,
        hmac=use_hmac,
    )
    return stats
