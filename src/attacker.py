# The attacker in this lab can:
#   - send any message to the UAV (it's on the same network)
#   - see every message the ground server sends (Part 2b: Wireshark)
# The attacker can NOT:
#   - read keys/ground_private.pem or keys/firmware.key
#
# The helpers below match the ground server's, so you can compare: same call,
# different key, different result.

import hashlib
import json
import os
import socket

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from common.protocol import encode_message

UAV_ADDRESS = ("127.0.0.1", 9000)

def send(message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.sendto(
        encode_message(message),
        UAV_ADDRESS,
    )

    sock.close()


def update_message(version, code):
    # Key order matches the README: type, firmware (version, code).
    # "signature" is added last by the helpers below.
    return {
        "type": "UPDATE",
        "firmware": {
            "version": version,
            "code": code,
        },
    }


def update_firmware(version, code):
    # No protection: no hash, no signature.
    message = update_message(version, code)

    send(message)
    print(f"[ATTACKER] Sent: {message}")

    return message


def update_firmware_with_hash(version, code):
    # Part 1 attack: a SHA256 hash needs no secret, so the attacker can
    # compute a valid one for any firmware. The Part 1 UAV accepts this.
    message = update_message(version, code)
    message["signature"] = hashlib.sha256(encode_message(message)).hexdigest()

    send(message)
    print(f"[ATTACKER] Sent: {message}")

    return message


def update_firmware_signed(version, code):
    # Part 2: the attacker doesn't have the ground private key, so it signs
    # with a brand-new key of its own. The signature is well-formed but won't
    # verify against ground_public.pem, so the Part 2 UAV rejects this.
    private_key = Ed25519PrivateKey.generate()

    message = update_message(version, code)
    message["signature"] = private_key.sign(encode_message(message)).hex()

    send(message)
    print(f"[ATTACKER] Sent: {message}")

    return message


def replay(captured):
    # Part 2b attack: send a captured packet again, unchanged. The attacker
    # didn't sign it, but the ground server did, so it still verifies.
    # `captured` is the JSON text copied from Wireshark.
    message = json.loads(captured)

    send(message)
    print(f"[ATTACKER] Replayed: {message}")

    return message


def update_firmware_encrypted(version, code):
    # Part 4: the attacker has neither the firmware key nor the ground
    # private key, so it uses brand-new ones of its own. The UAV rejects
    # this at the signature check, and couldn't decrypt it anyway.
    firmware_key = ChaCha20Poly1305.generate_key()
    private_key = Ed25519PrivateKey.generate()

    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(firmware_key).encrypt(
        nonce, code.encode(), str(version).encode()
    )

    message = {
        "type": "UPDATE",
        "firmware": {
            "version": version,
            "nonce": nonce.hex(),
            "code": ciphertext.hex(),
        },
    }
    message["signature"] = private_key.sign(encode_message(message)).hex()

    send(message)
    print(f"[ATTACKER] Sent: {message}")

    return message
