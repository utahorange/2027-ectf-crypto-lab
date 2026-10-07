# 2027 ECTF Cryptography Lab
This is a small cryptography lab to practice thinking about the 2027 ECTF scenario and how we would design a system to be robust against cryptographic attacks. In the actual ECTF competition, the UAV and ground server will most likely be separate boards. 

When you start the scenario, the UAV will be continually running listening for commands. You will utilize the ground server to send legimitate commands, while using the attacker server to send malicious ones.

## Part 1a: Integrity (Verify firmware)
Let's try updating the UAV firmware.

To start the UAV, do the following:
```
cd src
uv run python -m uav.uav
```

To use the ground server to interact with the UAV, start a Python console on your terminal with `python` or `python3`. Then, run the following:
```python
import ground
msg = {
     "type": "UPDATE",
     "firmware": {
         "version": 1,
         "code": "LEGITIMATE FLIGHT SOFTWARE",
    },
}
ground.send(msg)
```

At this point in time, there is no security implemented on the UAV or ground server. 

We want to now make it so that only payloads with correct hashes are accepted, so that an attacker may not arbitrarily modify bytes in the update payload.

> **IMPORTANT NOTE**: You should only need to modify `verify_firmware()` in [`security.py`](src/uav/security.py).

### Part 1b: Attack
Now, let's try to attack this system. What does the attacker need to do to make the UAV accept an update? Try doing this and see what happens.

## Part 2a: Authenticity (Sign your firmware update)
From part 1, we should have seen that the UAV accepts any payload with a valid hash. This is problematic, we only want to accept updates from the ground server, not the attacker! We need a private-public keypair for the ground server and UAV. 
 
Let's first create this keypair. Run `uv run python generate_keys.py`. This will generate:
```
keys/
├── ground_private.pem
└── ground_public.pem
```

The private key belongs to the ground server:
```
ground_private.pem
```
The public key is distributed to the UAV:
```
ground_public.pem
```

The functions to load these keys on the ground and UAS side have been written and are in [`protocol.py`](src/common/protocol.py). Modify `security.py` to now accept this signed integrity check.

### Part 2b: Attack
Hmmm, is there anything the attacker can do now? Now that the UAV knows if the update came from the ground server, there must be nothing the attacker can do, right?...

What if the attacker can "sniff the lines" and see the communication between the ground server and UAV? (like Eve in the classic Alice and Bob scenario). Then, the attacker can execute what is known as a replay attack. Let's try this now!

1. Record a valid UDP message from the ground server with Wireshark (listen on loopback).
2. Copy the plaintext into `attacker.py`.
3. Start the scenario and send the command to the UAV from `attacker.py`.
4. See that the UAV accepts the update. Yikes.

Here, we ran a replay attack, where we replayed a valid command that we saw from the ground server. If we don't protect against this attack, an attacker can downgrade our firmware or even command it to do arbitrary things if the ground server has sent that command before.

## Part 3: Freshness/Anti-Replay
We need to have the UAV understand how "fresh" a command is and know if it sees a stale command. One classic and easy way to do this is to have a monotonically increasing counter (nonce). The UAV can remember the newest command it has accepted, and thus reject any that are old.

> **IMPORTANT NOTE**: You should only need to modify `verify_command()` in [`security.py`](src/uav/security.py).

# Additional Reading/Tips and Tricks
For what messages looked like in last year's scenario, see [this](https://rules.ectf.mitre.org/2026/specs/host_interface.html).

Some useful concepts to review:
- Cryptographic hash
- Digital signatures
- Public-key cryptography
- Ed25519 (the hash function we like to use)
- Replay attacks
- Nonces
- Sequence numbers
- Firmware rollback attacks
- Secure boot
- Root of trust
