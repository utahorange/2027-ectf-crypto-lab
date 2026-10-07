import socket

from common.protocol import encode_message, CommandType

UAV_ADDRESS = ("127.0.0.1", 9000)

def send(message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.sendto(
        encode_message(message),
        UAV_ADDRESS,
    )

    sock.close()


def update_firmware(version, code):
    firmware = {
        "version": version,
        "code": code,
    }

    send({
        "type": CommandType.UPDATE,
        "firmware": firmware,
    })


def send_command(type, name, sequence):
    command = {
        "name": name,
        "sequence": sequence,
    }

    send({
        "type": type,
        "command": command,
    })
