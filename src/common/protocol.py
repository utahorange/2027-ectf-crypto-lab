import json
import os
from pathlib import Path

def encode_message(message: dict) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode()

def decode_message(data: bytes) -> dict:
    return json.loads(data.decode())

def keys_dir() -> Path:
    # Repo-root keys/ by default. Tests point LAB_KEYS_DIR at a temp folder.
    default = Path(__file__).resolve().parents[2] / "keys"
    return Path(os.environ.get("LAB_KEYS_DIR", default))

def load_public_key():
    from cryptography.hazmat.primitives import serialization
    with open(keys_dir() / "ground_public.pem", "rb") as f:
        return serialization.load_pem_public_key(
            f.read()
        )

def load_private_key():
    from cryptography.hazmat.primitives import serialization
    with open(keys_dir() / "ground_private.pem", "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )