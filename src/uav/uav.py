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
#     "signature": "<bytes>"
# }

class UAV:
    def __init__(self):
        self.security = Security()

        self.current_firmware = {
            "version": 1,
            "code": "LEGITIMATE FLIGHT SOFTWARE",
        }

        self.last_command_sequence = 0

    def install_firmware(self, firmware):
        print(f"[UAV] Installing firmware v{firmware['version']}")

        self.current_firmware = firmware

    def execute_command(self, command):
        print(
            f"[UAV] Executing command: "
            f"{command['name']}"
        )

    def handle_message(self, message):
        msg_type = message["type"]

        if msg_type == "UPDATE":
            self.handle_update(message)

        elif msg_type == "COMMAND":
            self.handle_command(message)

        else:
            print("[UAV] Unknown message")

    def handle_update(self, message):
        firmware = message["firmware"]
        signature = message.get("signature")

        if not self.security.verify_firmware(
            firmware, 
        ):
            print("[UAV] Firmware rejected")
            return

        print("[UAV] Firmware authenticated")

        self.install_firmware(firmware)

    def handle_command(self, message):
        command = message["command"]
        signature = message.get("signature")

        if not self.security.verify_command(
            command,
            signature,
        ):
            print("[UAV] Command rejected")
            return

        print("[UAV] Command authenticated")

        self.execute_command(command)

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((HOST, PORT))

        print(f"[UAV] Listening on {HOST}:{PORT}")

        while True:
            data, address = sock.recvfrom(65535)

            try:
                message = decode_message(data)

                print(f"[UAV] Received from {address}: {message}")

                self.handle_message(message)

            except Exception as e:
                print(f"[UAV] Invalid packet: {e}")

