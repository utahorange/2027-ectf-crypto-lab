import hashlib
import socket

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
    print(f"[GROUND] Sent: {message}")

    return message


def update_firmware_with_hash(version, code):
    # Part 1: "signature" holds the SHA256 hex digest of the encoded message.
    message = update_message(version, code)
    message["signature"] = hashlib.sha256(encode_message(message)).hexdigest()

    send(message)
    print(f"[GROUND] Sent: {message}")

    return message


def update_firmware_signed(version, code):
    # Part 2: sign with an attacker-generated Ed25519 key, not the ground key.
    private_key = Ed25519PrivateKey.generate()

    message = update_message(version, code)
    message["signature"] = private_key.sign(encode_message(message)).hex()

    send(message)
    print(f"[GROUND] Sent: {message}")

    return message


def send_command(name, sequence):
    command = {
        "name": name,
        "sequence": sequence,
    }

    send({
        "type": "COMMAND",
        "command": command,
    })
