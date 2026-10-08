"""Part 1: Integrity with hashes.

Run with:  uv run pytest tests/test_part1.py
"""

from conftest import deliver, update_message, with_hash

# ---------- Part 1a: the UAV checks the hash ----------

def test_correct_hash_is_accepted(uav_part1):
    message = with_hash(update_message())

    assert deliver(uav_part1, message)


def test_tampered_firmware_is_rejected(uav_part1):
    # Hash the real firmware, then change the code in transit.
    message = with_hash(update_message(code="LEGITIMATE FLIGHT SOFTWARE"))
    message["firmware"]["code"] = "MALICIOUS FLIGHT SOFTWARE"

    assert not deliver(uav_part1, message)


def test_tampered_version_is_rejected(uav_part1):
    message = with_hash(update_message(version=2))
    message["firmware"]["version"] = 99

    assert not deliver(uav_part1, message)


def test_missing_hash_is_rejected(uav_part1):
    message = update_message()  # no "signature" field at all

    assert not deliver(uav_part1, message)


def test_wrong_hash_is_rejected(uav_part1):
    message = {**update_message(), "signature": "00" * 32}

    assert not deliver(uav_part1, message)


def test_malformed_hash_is_rejected(uav_part1):
    message = {**update_message(), "signature": "not a hash"}

    assert not deliver(uav_part1, message)


# ---------- Part 1b: the attack ----------

def test_attacker_who_recomputes_hash_is_accepted(uav_part1):
    # A hash only proves the message wasn't changed *after* hashing.
    # Anyone can hash their own firmware, so the UAV accepts it.
    # This test passing means the attack works -- Part 2 fixes it.
    message = with_hash(update_message(code="MALICIOUS FLIGHT SOFTWARE"))

    assert deliver(uav_part1, message)
