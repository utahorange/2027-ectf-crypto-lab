"""Part 2: Authenticity with signatures.

Run with:  uv run pytest tests/test_part2.py
"""

from conftest import deliver, update_message, with_hash, with_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from uav.uav import UAV

# ---------- Part 2a: the UAV checks the signature ----------

def test_signed_update_is_accepted(uav_part2, ground_key):
    message = with_signature(update_message(), ground_key)

    assert deliver(uav_part2, message)


def test_hash_only_update_is_rejected(uav_part2):
    # The Part 1 attack: a valid hash is no longer enough.
    message = with_hash(update_message(code="MALICIOUS FLIGHT SOFTWARE"))

    assert not deliver(uav_part2, message)


def test_tampered_firmware_is_rejected(uav_part2, ground_key):
    # Sign the real firmware, then change the code in transit.
    message = with_signature(update_message(), ground_key)
    message["firmware"]["code"] = "MALICIOUS FLIGHT SOFTWARE"

    assert not deliver(uav_part2, message)


def test_signature_from_wrong_key_is_rejected(uav_part2):
    # The attacker has their own key pair, but not the ground server's.
    attacker_key = Ed25519PrivateKey.generate()
    message = with_signature(update_message(), attacker_key)

    assert not deliver(uav_part2, message)


def test_missing_signature_is_rejected(uav_part2):
    message = update_message()

    assert not deliver(uav_part2, message)


def test_malformed_signature_is_rejected(uav_part2):
    message = {**update_message(), "signature": "not a signature"}

    assert not deliver(uav_part2, message)


# ---------- Part 2b: the attack ----------

def test_replayed_update_is_accepted(ground_key):
    # The attacker records a real signed update and sends it again later.
    # The signature is genuine, so the UAV accepts it a second time.
    # This test passing means the attack works -- Part 3 fixes it.
    old_update = with_signature(update_message(version=2), ground_key)
    new_update = with_signature(update_message(version=3), ground_key)

    uav = UAV(part=2)
    assert deliver(uav, old_update)
    assert deliver(uav, new_update)

    # Replay the old one: the UAV rolls back to version 2.
    assert deliver(uav, old_update)
