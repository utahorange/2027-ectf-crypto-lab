import socket

from common.protocol import encode_message

UAV_ADDRESS = ("127.0.0.1", 9000)

def send(message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.sendto(
        encode_message(message),
        UAV_ADDRESS,
    )

    sock.close()
