# 2027 eCTF Cryptography Lab
This is a small cryptography lab to practice thinking about the 2027 eCTF scenario and how we would design a system to be robust against cryptographic attacks. In the actual eCTF competition, the UAV and ground server will most likely be separate boards. 

When you start the scenario, the UAV runs continuously, listening for firmware updates. You will use the ground server to send legitimate updates, and the attacker to send malicious ones.

## Requirements
- [uv](https://docs.astral.sh/uv/) (it installs Python and the dependencies for you on the first `uv run`)
- [Wireshark](https://www.wireshark.org/) (only needed for Part 2b)

## Scenario

From the eCTF website: “In the 2027 eCTF, teams will design and implement a secure bootloader for an unmanned aerial vehicle (UAV). The system must allow users to securely update and boot custom applications without compromising system integrity or leaking sensitive intellectual property.”

This lab replicates that setup on your own machine. The UAV, the ground server, and the attacker all talk to each other over UDP on `127.0.0.1:9000`:

| Role | File | How you run it |
|------|------|----------------|
| UAV | [`src/uav/uav.py`](src/uav/uav.py) | `uv run python -m uav.uav --part N` (leave it running) |
| Ground server | [`src/ground/ground.py`](src/ground/ground.py) | `import ground` in a Python console |
| Attacker | [`src/attacker.py`](src/attacker.py) | `import attacker` in a Python console |

All of these are run from the `src` folder. For example, the ground server looks like this:
```
cd src
uv run python
>>> import ground
>>> ground.update_firmware(2, "LEGITIMATE FLIGHT SOFTWARE")
```

The only file you need to edit is [`src/uav/security.py`](src/uav/security.py).

## Checking your work
Each part has a set of tests. Run them from the repo root (the folder containing `pyproject.toml`), not from `src`:
```
uv run pytest tests/test_part1.py
uv run pytest tests/test_part2.py
uv run pytest tests/test_part3.py
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
    "signature": "<blank for now>"
}
```

At this point, there is no security implemented on the UAV, so it installs v2 even though nothing proves the update is genuine. The message could have been modified in transit, and the UAV would still accept it. For message integrity, the UAV should only accept messages whose `"signature"` field holds a valid hash digest.

The ground server computes the hash like this (see `update_firmware_with_hash()` in [`ground.py`](src/ground/ground.py)):
1. Build the message *without* the `"signature"` field.
2. Turn it into bytes with `encode_message()` from [`protocol.py`](src/common/protocol.py).
3. Take the SHA256 hex digest of those bytes and add it as `"signature"`, the last field.

Implement **SHA256** hash verification in `verify_firmware_hash()` in [`security.py`](src/uav/security.py):
- Get the received hash with `message.get("signature")`.
- Hash only the `"type"` and `"firmware"` fields, not the signature itself. The provided helper `unsigned_bytes(message)` gives you exactly the bytes the ground server hashed.
- Compute the expected digest with `hashlib.sha256(...).hexdigest()`.
- Compare the two with `hmac.compare_digest()` rather than `==`, so the comparison takes the same time whether or not the hashes match (this avoids timing attacks).
- The field is called `"signature"`, but in this part it only holds a hash. Real signatures come in Part 2a.
- You only need to modify `verify_firmware_hash()`.

When you're done, restart the UAV (stop it with Ctrl+C and run it again) so it picks up your changes. Then try both kinds of update from the ground console:
```python
ground.update_firmware(3, "LEGITIMATE FLIGHT SOFTWARE")            # no hash: should be rejected
ground.update_firmware_with_hash(3, "LEGITIMATE FLIGHT SOFTWARE")  # correct hash: should be accepted
```

Check your work with `uv run pytest tests/test_part1.py` from the repo root.

## Part 2a: Authenticity with Signatures
A hash needs no secret: anyone, including an attacker, can compute a valid hash for their own firmware, and the Part 1 UAV accepts it (that's what `test_attacker_who_recomputes_hash_is_accepted` shows). This is a problem: we only want to accept updates from the ground server, not the attacker! We will use Ed25519 signatures for authentication. The ground server signs with a private key that only it knows, and the UAV verifies with the matching public key.

Let's first create this keypair. From the `src` folder, run `uv run python generate_keys.py`. This will generate (at the repo root):
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

The functions to load these keys on the ground and UAV side have been written and are in [`protocol.py`](src/common/protocol.py).

The ground server signs the same bytes you hashed in Part 1 (the message without `"signature"`, encoded with `encode_message()`), then stores the signature as a hex string in `"signature"`.

Implement **Ed25519 signature** verification in `verify_firmware_signature()` in [`security.py`](src/uav/security.py):
- Get the signature with `message.get("signature")`. It arrives as a hex string, but `verify()` expects bytes, so convert it with `bytes.fromhex()`.
- Get the signed data with `unsigned_bytes(message)`, just like in Part 1.
- Use `load_public_key()` to load the ground server's public key from `keys/ground_public.pem`.
- Call `public_key.verify(signature, data)`. Note that it doesn't return `True`/`False`: it returns `None` on success and raises `InvalidSignature` on failure. Catch `InvalidSignature` and return `False`. See the [`cryptography` Ed25519 docs](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).
- You only need to modify `verify_firmware_signature()`.

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

## Part 2b: Replay Attack
Hmmm, is there anything the attacker can do now? Now that the UAV knows if the update came from the ground server, there must be nothing the attacker can do, right?...

You'll need three terminals, all in the `src` folder: the UAV, the ground console, and an attacker console. Your signature check from Part 2a must be working, and the UAV must be running with `--part 2`.

Start the attacker console the same way as the ground console:
```
cd src
uv run python
```
```python
import attacker
```

[`attacker.py`](src/attacker.py) has the same helpers as the ground server. The difference is the key: the attacker doesn't have `ground_private.pem`, so `attacker.update_firmware_signed()` signs with a brand-new key of its own. Try forging an update:
```python
attacker.update_firmware_signed(5, "MALICIOUS FLIGHT SOFTWARE")
```
The UAV rejects it, because the signature doesn't match the ground server's public key. So far, so good.

What if the attacker can "sniff the lines" and see the communication between the ground server and UAV? (like Eve in the classic Alice and Bob scenario). Then, the attacker can execute what is known as a replay attack. Let's try this now!

1. Open Wireshark and start capturing on the loopback interface (`Loopback: lo0` on macOS, `Loopback` or `lo` on Windows/Linux). Type `udp.port == 9000` in the filter bar and press Enter, so you only see UAV traffic.
2. From the ground console, send a signed update:
   ```python
   ground.update_firmware_signed(5, "LEGITIMATE FLIGHT SOFTWARE")
   ```
   One packet appears in Wireshark.
3. Click the packet. In the details pane, right-click the **Data** line and choose **Copy → …as Printable Text**. You should get JSON starting with `{"type":"UPDATE"`.
4. Back in the ground console, send a newer update. The UAV installs v6:
   ```python
   ground.update_firmware_signed(6, "LEGITIMATE FLIGHT SOFTWARE")
   ```
5. In the attacker console, save the captured JSON (paste it between the single quotes) and replay it:
   ```python
   captured = '{"type":"UPDATE","firmware":{"version":5, ...},"signature":"..."}'
   attacker.replay(captured)
   ```
6. Watch the UAV: it prints `Firmware authenticated` and installs **v5** again. The attacker just rolled your firmware back to an older version without knowing the private key. Yikes.

**Try this too:** change `"version":5` to `"version":7` and replay it again:
```python
attacker.replay(captured.replace('"version":5', '"version":7'))
```
This time the UAV rejects it. The signature still protects the *contents* of the message; it just can't tell an old message from a new one.

Here, we ran a replay attack, where we replayed a valid update that we saw from the ground server. If we don't protect against this attack, an attacker can roll our firmware back to any older version the ground server ever signed, including one with a known vulnerability. On a real UAV, the same trick would work on any signed command the ground server has sent before.

The test `test_replayed_update_is_accepted` in [`tests/test_part2.py`](tests/test_part2.py) runs this same attack, so it should pass.

## Part 3: Anti-Replay
The signature proves *who* sent an update, but not *when*. To stop replays, the UAV needs to know how "fresh" an update is so it can spot a stale one. One classic and simple way to do this is a monotonically increasing counter. Firmware updates already carry one: the `version` field. The UAV remembers the newest version it has accepted and rejects anything that isn't newer.

This works only because `version` is covered by the signature. If the attacker bumps the version of a captured update (like the `"version":7` trick in Part 2b), the signature no longer matches and the update is rejected before the counter is even checked.

In Part 3 mode, the UAV runs your Part 2a signature check first and then calls `verify_firmware_counter()`. An update installs only if both return `True`.

Implement the anti-rollback check in `verify_firmware_counter()` in [`security.py`](src/uav/security.py):
- `self.highest_version` (set in `__init__`) holds the newest version accepted so far. It starts at `1`, the version the UAV ships with.
- Read the incoming version from `message["firmware"]["version"]`.
- Reject it unless it is **strictly** newer than `self.highest_version`. Replaying the currently installed version should fail too.
- If you accept it, update `self.highest_version` before returning `True`.
- You only need to modify `verify_firmware_counter()`. Your Part 2a signature check must already work.

Restart the UAV in Part 3 mode:
```
uv run python -m uav.uav --part 3
```

Then repeat the Part 2b attack with the UAV, ground, and attacker consoles. Capture the v5 packet in Wireshark exactly as in Part 2b, and save it as `captured` in the attacker console:
```python
ground.update_firmware_signed(5, "LEGITIMATE FLIGHT SOFTWARE")  # capture this one in Wireshark
ground.update_firmware_signed(6, "LEGITIMATE FLIGHT SOFTWARE")  # accepted: 6 > 5
attacker.replay(captured)                                      # v5 again: should be rejected now
```

The UAV prints `Firmware rejected` and stays on v6. Your Part 2a signature check still runs too, so `attacker.update_firmware_signed(99, ...)` is rejected even though 99 is newer.

Check your work with `uv run pytest tests/test_part3.py` from the repo root. The Part 2 test `test_replayed_update_is_accepted` still passes, because it runs the UAV in Part 2 mode, which has no counter.

Things to think about:
- Restarting the UAV resets `highest_version` to 1, so an old update becomes valid again. On a real device, where would the counter need to live so it survives a reboot?
- What happens if the ground server ever signs a huge version number by mistake (say `2**31`)?
- A counter needs the receiver to remember state. What alternatives (timestamps, challenge-response nonces) avoid that, and what do they need instead?

# Additional Reading/Tips and Tricks
Some useful concepts to review:
- Cryptographic hash
- Digital signatures
- Public-key cryptography
- Ed25519 (the signature scheme we like to use)
- Replay attacks
- Nonces
- Sequence numbers and monotonic counters
- Firmware rollback attacks
- Secure boot
- Root of trust
