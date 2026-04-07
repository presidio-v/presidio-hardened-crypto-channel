"""presidio-hardened-crypto-channel: secure channel with ECDH, AES-256-GCM, and HMAC."""

from .channel import ChannelStats, SecureChannel, run_channel
from .keyexchange import KeyExchangeResult, Party, run_key_exchange
from .security import log_security_event, run_dependency_audit, setup_logging
from .symmetric import DecryptResult, EncryptResult, run_symmetric_demo

__version__ = "0.1.0"
__all__ = [
    "Party",
    "KeyExchangeResult",
    "run_key_exchange",
    "EncryptResult",
    "DecryptResult",
    "run_symmetric_demo",
    "SecureChannel",
    "ChannelStats",
    "run_channel",
    "setup_logging",
    "log_security_event",
    "run_dependency_audit",
]

setup_logging()
