"""Part 3: Anti-replay with a version counter.

Run with:  uv run pytest tests/test_part3.py
"""

from conftest import deliver, update_message, with_hash, with_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ---------- Part 3: the UAV only moves forward ----------

def test_newer_signed_update_is_accepted(uav_part3, ground_key):
    message = with_signature(update_message(version=2), ground_key)

    assert deliver(uav_part3, message)


def test_successive_updates_are_accepted(uav_part3, ground_key):
    for version in (2, 3, 7):
        message = with_signature(update_message(version=version), ground_key)
        assert deliver(uav_part3, message)


def test_replayed_update_is_rejected(uav_part3, ground_key):
    # The Part 2b attack: replay an old update after a newer one.
    old_update = with_signature(update_message(version=2), ground_key)
    new_update = with_signature(update_message(version=3), ground_key)

    assert deliver(uav_part3, old_update)
    assert deliver(uav_part3, new_update)

    assert not deliver(uav_part3, old_update)
    assert uav_part3.current_firmware["version"] == 3


def test_same_version_is_rejected(uav_part3, ground_key):
    # Two genuine updates both labelled v2: only the first is accepted.
    # (Different code, so deliver() can tell whether the second installed.)
    first = with_signature(update_message(version=2, code="BUILD A"), ground_key)
    second = with_signature(update_message(version=2, code="BUILD B"), ground_key)

    assert deliver(uav_part3, first)
    assert not deliver(uav_part3, second)


def test_factory_version_is_rejected(uav_part3, ground_key):
    # The UAV ships with v1, so even a genuine v1 is not new.
    message = with_signature(update_message(version=1, code="OLD BUILD"), ground_key)

    assert not deliver(uav_part3, message)


def test_bumped_version_is_rejected(uav_part3, ground_key):
    # The attacker raises the version of a captured update to get past
    # the counter. The version is signed, so this breaks the signature.
    message = with_signature(update_message(version=2), ground_key)
    message["firmware"]["version"] = 99

    assert not deliver(uav_part3, message)


def test_newer_unsigned_update_is_rejected(uav_part3):
    # A higher version is not enough on its own: it must still be signed.
    attacker_key = Ed25519PrivateKey.generate()

    assert not deliver(uav_part3, update_message(version=99))
    assert not deliver(uav_part3, with_hash(update_message(version=99)))
    assert not deliver(
        uav_part3, with_signature(update_message(version=99), attacker_key)
    )
