# 2027 eCTF Cryptography Lab
This is a small cryptography lab to practice thinking about the 2027 eCTF scenario and how we would design a system to be robust against cryptographic attacks. In the actual eCTF competition, the UAV and ground server will most likely be separate boards. 

When you start the scenario, the UAV will be continually running listening for commands. You will utilize the ground server to send legitimate commands, while using the attacker server to send malicious ones.

## Checking your work
Each part has a set of tests. Run them from the repo root (the folder containing `pyproject.toml`), not from `src`:
```
uv run pytest tests/test_part1.py
uv run pytest tests/test_part2.py
```

Before you write any code, most tests will fail. That's expected: the UAV starts out accepting everything. Your goal is to get every test in a part passing.

Some tests are named `test_attacker_...` or `test_replayed_...`. These check that the attack in that part *works*, so they should pass. They show why the next part is needed.

## Part 1: Integrity with Hashes
Let's try updating the UAV firmware.

To start the UAV, do the following:
```
cd src
uv run python -m uav.uav --part 1
```

The `--part` flag tells the UAV which security check to use. You will restart the UAV with a new part number as you move through the lab.

To use the ground server to interact with the UAV, open a second terminal and start a Python console from the `src` folder:
```
cd src
uv run python
```

Then, send a firmware update with no protection at all:
```python
import ground
ground.update_firmware(2, "LEGITIMATE FLIGHT SOFTWARE")
```

Each helper prints the message it sent and returns it. The message looks like this:
```python
{
    "type": "UPDATE",
    "firmware": {
        "version": 2,
        "code": "LEGITIMATE FLIGHT SOFTWARE",
    },
    "signature": "blank for now"
}
```

At this point in time, there is no security implemented on the UAV, so it installs v2 even though nothing proves the update is genuine. 

We want to now make it so that only payloads with correct hashes are accepted, so that an attacker may not arbitrarily modify bytes in the update payload. Implement SHA256 hashing of the message (Message format says signature, but use hash for now).

The ground server computes the hash like this:
1. Build the message *without* the `"signature"` field.
2. Turn it into bytes with `encode_message()` from [`protocol.py`](src/common/protocol.py).
3. Take the SHA256 hex digest of those bytes and add it as `"signature"`, the last field.

To verify, the UAV must hash exactly the same bytes: remove `"signature"` from a copy of the message and encode it with `encode_message()`. Don't use `json.dumps()` directly. It adds spaces, so the bytes (and the hash) won't match.

> **IMPORTANT NOTE**: You should only need to modify `verify_firmware_hash()` in [`security.py`](src/uav/security.py).

When you're done, restart the UAV (stop it with Ctrl+C and run it again) so it picks up your changes. Then try both kinds of update from the ground console:
```python
ground.update_firmware(3, "LEGITIMATE FLIGHT SOFTWARE")            # no hash: should be rejected
ground.update_firmware_with_hash(3, "LEGITIMATE FLIGHT SOFTWARE")  # correct hash: should be accepted
```

Check your work with `uv run pytest tests/test_part1.py` from the repo root.

<!-- ### Part 1b: Attack
Now, let's try to attack this system. What does the attacker need to do to make the UAV accept an update? Try doing this and see what happens. -->

## Part 2: Authenticity with Signatures
From part 1, we should have seen that the UAV accepts any payload with a valid hash. This is problematic, we only want to accept updates from the ground server, not the attacker! We will use Ed25519 signatures to authenticate. We need a private-public keypair for the ground server and UAV. 
 
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

The functions to load these keys on the ground and UAV side have been written and are in [`protocol.py`](src/common/protocol.py). Modify `verify_firmware_signature()` in `security.py` to now accept this signed integrity check (Use `load_public_key()`).

The ground server signs the same bytes you hashed in Part 1: the message without `"signature"`, encoded with `encode_message()`. The `"signature"` field now holds the Ed25519 signature as hex, so convert it back to bytes before verifying.

Restart the UAV in Part 2 mode so it checks signatures instead of hashes:
```
uv run python -m uav.uav --part 2
```

Then try both kinds of update from the ground console:
```python
ground.update_firmware_with_hash(4, "LEGITIMATE FLIGHT SOFTWARE")  # hash only: should be rejected now
ground.update_firmware_signed(4, "LEGITIMATE FLIGHT SOFTWARE")     # signed: should be accepted
```

Check your work with `uv run pytest tests/test_part2.py` from the repo root.

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

Restart the UAV in Part 3 mode:
```
uv run python -m uav.uav --part 3
```

> **IMPORTANT NOTE**: You should only need to modify `verify_command()` in [`security.py`](src/uav/security.py).

# Additional Reading/Tips and Tricks
Some useful concepts to review:
- Cryptographic hash
- Digital signatures
- Public-key cryptography
- Ed25519 (the signature scheme we like to use)
- Replay attacks
- Nonces
- Sequence numbers
- Firmware rollback attacks
- Secure boot
- Root of trust
