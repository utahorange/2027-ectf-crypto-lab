import socket

from common.protocol import decode_message
from uav.security import Security

HOST = "127.0.0.1"
PORT = 9000

# Message Format:
# {
#     "type": "UPDATE",
#     "firmware": {
#         "version": 1,
#         "code": "LEGITIMATE FLIGHT SOFTWARE",
#     },
#     "signature": "<hex>"
# }
#
# Part 4 encrypts the code, so "firmware" becomes:
#     {"version": 1, "nonce": "<hex>", "code": "<ciphertext hex>"}

class UAV:
    def __init__(self, part=1):
        # Which lab part is active: 1 = hash, 2 = signature, 3 = signature + anti-replay,
        # 4 = signature + anti-replay + encryption
        if part not in (1, 2, 3, 4):
            raise ValueError(f"part must be 1, 2, 3, or 4, got {part}")

        self.part = part
        self.security = Security()

        self.current_firmware = {
            "version": 1,
            "code": "LEGITIMATE FLIGHT SOFTWARE",
        }

    def install_firmware(self, firmware):
        print(f"[UAV] Installing firmware v{firmware['version']}")

        self.current_firmware = firmware

    def handle_message(self, message):
        msg_type = message["type"]

        if msg_type == "UPDATE":
            self.handle_update(message)

        else:
            print("[UAV] Unknown message")

    def handle_update(self, message):
        firmware = message["firmware"]

        if self.part == 1:
            verified = self.security.verify_firmware_hash(message)
        elif self.part == 2:
            verified = self.security.verify_firmware_signature(message)
        elif self.part == 3:
            # Check the signature first: the version only means something
            # once we know the ground server signed it.
            verified = self.security.verify_firmware_signature(
                message
            ) and self.security.verify_firmware_counter(message)
        else:
            # Decrypt before the counter, so an update that fails to decrypt
            # doesn't advance highest_version.
            code = None
            if self.security.verify_firmware_signature(message):
                code = self.security.decrypt_firmware(message)

            verified = code is not None and self.security.verify_firmware_counter(
                message
            )
            firmware = {"version": firmware["version"], "code": code}

        if not verified:
            print("[UAV] Firmware rejected")
            return

        print("[UAV] Firmware authenticated")

        self.install_firmware(firmware)

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((HOST, PORT))

        print(f"[UAV] Part {self.part} | Listening on {HOST}:{PORT}")

        while True:
            data, address = sock.recvfrom(65535)

            try:
                message = decode_message(data)

                print(f"[UAV] Received from {address}: {message}")

                self.handle_message(message)

            except Exception as e:
                print(f"[UAV] Invalid packet: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run the UAV")
    parser.add_argument(
        "--part",
        type=int,
        choices=[1, 2, 3, 4],
        default=1,
        help="lab part to run (1 = hash, 2 = signature, 3 = anti-replay, 4 = encryption)",
    )
    args = parser.parse_args()

    UAV(part=args.part).run()
