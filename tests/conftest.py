import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.protocol import encode_message
from uav.uav import UAV

# ---------- Building messages ----------

def update_message(version=2, code="LEGITIMATE FLIGHT SOFTWARE"):
    # Key order matches the README: type, firmware (version, code).
    return {
        "type": "UPDATE",
        "firmware": {"version": version, "code": code},
    }


def with_hash(message):
    # Part 1: "signature" holds the SHA-256 hex digest of the encoded
    # message (before "signature" is added). "signature" goes last.
    digest = hashlib.sha256(encode_message(message)).hexdigest()
    return {**message, "signature": digest}


def with_signature(message, private_key):
    # Part 2: "signature" holds an Ed25519 signature over the encoded
    # message (before "signature" is added), hex-encoded.
    signature = private_key.sign(encode_message(message))
    return {**message, "signature": signature.hex()}


# ---------- Delivering messages ----------

def deliver(uav, message):
    """Send a message to the UAV the same way run() does.

    Returns True if the UAV installed the message's firmware.
    Like run(), an exception while handling counts as a rejection.
    """
    try:
        uav.handle_message(message)
    except Exception as e:
        print(f"[test] UAV raised {type(e).__name__}: {e}")

    return uav.current_firmware == message["firmware"]


# ---------- Fixtures ----------

@pytest.fixture
def ground_key(tmp_path, monkeypatch):
    """A fresh ground key pair in a temp folder, used by the UAV for this test.

    Returns the private key, for signing messages as the ground server.
    """
    private_key = Ed25519PrivateKey.generate()

    (tmp_path / "ground_private.pem").write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (tmp_path / "ground_public.pem").write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    monkeypatch.setenv("LAB_KEYS_DIR", str(tmp_path))
    return private_key


@pytest.fixture
def uav_part1():
    return UAV(part=1)


@pytest.fixture
def uav_part2(ground_key):
    # Depends on ground_key so the key files exist before the UAV is created.
    return UAV(part=2)


@pytest.fixture
def uav_part3(ground_key):
    return UAV(part=3)
