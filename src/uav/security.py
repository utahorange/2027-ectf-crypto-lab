import hashlib
import hmac

from cryptography.exceptions import InvalidSignature

from common.protocol import encode_message, load_public_key


# Helper function to extract the unsigned bytes of a message
def unsigned_bytes(message):
    unsigned = dict(message)
    unsigned.pop("signature", None)
    return encode_message(unsigned)

class Security:
    # Each check receives the full message, e.g.
    # {"type": "UPDATE", "firmware": {...}, "signature": "<hex>"}
    # 
    # The ground server hashes/signs the message *before* adding "signature",
    # encoded with encode_message() from common/protocol.py.

    # To verify, extract the signature from the message and check it against the unsigned bytes.

    def verify_firmware_hash(self, message):
        # TODO: Implement SHA256 hash verification
        # Use hmac for constant-time comparison of the hash

        return True

    def verify_firmware_signature(self, message):
        # TODO: Implement Ed25519 signature verification
        # See https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
        # Catch InvalidSignature and return False

        return True

    def verify_command(self, message):
        # TODO: Implement command authentication

        return True