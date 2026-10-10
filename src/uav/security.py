import hashlib
import hmac

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from common.protocol import encode_message, load_firmware_key, load_public_key

# Helper function to extract the unsigned bytes of a message
def unsigned_bytes(message):
    unsigned = dict(message)
    unsigned.pop("signature", None)
    return encode_message(unsigned)

class Security:
    # To verify, extract the signature from the message and check it against the unsigned bytes.

    def __init__(self):
        # Part 3: newest firmware version accepted so far (the UAV ships with v1)
        self.highest_version = 1

    def verify_firmware_hash(self, message):
        # TODO: Implement SHA256 hash verification
        # 1. Extract signature from message using get()
        # 2. Extract unsigned bytes from message using unsigned_bytes()
        # 3. Use hashlib.sha256() and hexdigest() to hash the unsigned bytes
        # 4. Use hmac.compare_digest() to compare 

        return True

    def verify_firmware_signature(self, message):
        # TODO: Implement Ed25519 signature verification
        # 1. Extract signature from message using get() and convert it from hex to bytes
        # 2. Extract unsigned bytes from message using unsigned_bytes()
        # 3. Load the public key using load_public_key()
        # 4. Use public_key.verify() to verify the signature against the unsigned bytes
        # 5. Catch InvalidSignature and return False

        return True

    def verify_firmware_counter(self, message):
        # TODO: Implement anti-rollback check
        # (The signature is checked before this is called, so the version can be trusted.)
        # 1. Extract the version from message["firmware"]
        # 2. Reject it unless it is strictly newer than self.highest_version
        # 3. Otherwise, update self.highest_version and return True

        return True

    def decrypt_firmware(self, message):
        # TODO: Implement ChaCha20-Poly1305 decryption
        # (The signature is checked before this is called.)
        # 1. Extract the nonce and code (ciphertext) from message["firmware"] and convert them from hex to bytes
        # 2. Load the shared key using load_firmware_key()
        # 3. Use ChaCha20Poly1305(key).decrypt() with the version as associated data: str(version).encode()
        # 4. Return the decrypted code as a string with decode()
        # 5. Catch InvalidTag and return None

        return message["firmware"]["code"]
