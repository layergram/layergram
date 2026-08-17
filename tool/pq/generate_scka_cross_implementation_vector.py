#!/usr/bin/env python3
# Copyright 2026 Layergram
# SPDX-License-Identifier: Apache-2.0
"""Generate an independent ML-KEM Braid revision-1 conformance vector.

This deliberately uses only Python's standard library and the permissively
licensed mlkem-native KAT already vendored for Layergram's classical ML-KEM
boundary.  It does not import, execute, or derive from the production Rust
SCKA implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


PROTOCOL_INFO = b"LayergramV3_MLKEM768_HMAC-SHA256"
AUTH_UPDATE = b":Authenticator Update"
SCKA_KEY = b":SCKA Key"
HEADER_MAC = b":ekheader"
CIPHERTEXT_MAC = b":ciphertext"
ZERO32 = bytes(32)
AUTH_KEY = bytes([0x11]) * 32
GF_REDUCTION = 0x100B
GF_ORDER_MINUS_ONE = 65_535

TYPE_NONE = 0
TYPE_HEADER = 1
TYPE_EK = 2
TYPE_EK_CT1_ACK = 3
TYPE_CT1_ACK = 4
TYPE_CT1 = 5
TYPE_CT2 = 6


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def update_authenticator(root: bytes, update_key: bytes, epoch: int) -> tuple[bytes, bytes]:
    material = hkdf(
        root,
        update_key,
        PROTOCOL_INFO + AUTH_UPDATE + epoch.to_bytes(8, "big"),
        64,
    )
    return material[:32], material[32:]


def output_key(shared_secret: bytes, epoch: int) -> bytes:
    return hkdf(
        ZERO32,
        shared_secret,
        PROTOCOL_INFO + SCKA_KEY + epoch.to_bytes(8, "big"),
        32,
    )


def protocol_mac(mac_key: bytes, label: bytes, epoch: int, value: bytes) -> bytes:
    return hmac.new(
        mac_key,
        PROTOCOL_INFO + label + epoch.to_bytes(8, "big") + value,
        hashlib.sha256,
    ).digest()


def gf_multiply(left: int, right: int) -> int:
    result = 0
    for _ in range(16):
        if right & 1:
            result ^= left
        high = left & 0x8000
        left = (left << 1) & 0xFFFF
        if high:
            left ^= GF_REDUCTION
        right >>= 1
    return result


def gf_power(base: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = gf_multiply(result, base)
        base = gf_multiply(base, base)
        exponent >>= 1
    return result


def gf_alpha(exponent: int) -> int:
    return gf_power(2, exponent % GF_ORDER_MINUS_ONE)


def invert(matrix: list[list[int]]) -> list[list[int]]:
    size = len(matrix)
    augmented = [
        row[:] + [1 if column == row_index else 0 for column in range(size)]
        for row_index, row in enumerate(matrix)
    ]
    for column in range(size):
        pivot = next(
            (row for row in range(column, size) if augmented[row][column]), None
        )
        if pivot is None:
            raise ValueError("singular GF(2^16) matrix")
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        factor = gf_power(augmented[column][column], GF_ORDER_MINUS_ONE - 1)
        augmented[column] = [gf_multiply(value, factor) for value in augmented[column]]
        pivot_row = augmented[column][:]
        for row in range(size):
            if row == column or not augmented[row][column]:
                continue
            factor = augmented[row][column]
            augmented[row] = [
                value ^ gf_multiply(factor, pivot_value)
                for value, pivot_value in zip(augmented[row], pivot_row)
            ]
    return [row[size:] for row in augmented]


def systematic_inverse(size: int) -> list[list[int]]:
    return invert(
        [[gf_alpha(row * column) for column in range(size)] for row in range(size)]
    )


def coefficients(size: int, index: int, inverse: list[list[int]]) -> list[int]:
    if index < size:
        return [1 if column == index else 0 for column in range(size)]
    column = [gf_alpha(row * index) for row in range(size)]
    result = []
    for row in inverse:
        value = 0
        for left, right in zip(row, column):
            value ^= gf_multiply(left, right)
        result.append(value)
    return result


def erasure_chunk(message: bytes, index: int) -> bytes:
    if not message or len(message) % 32:
        raise ValueError("message must contain complete 32-byte symbols")
    symbols = [message[offset : offset + 32] for offset in range(0, len(message), 32)]
    field_symbols = [
        [int.from_bytes(symbol[offset : offset + 2], "big") for offset in range(0, 32, 2)]
        for symbol in symbols
    ]
    row = coefficients(len(symbols), index, systematic_inverse(len(symbols)))
    encoded_words = []
    for word_index in range(16):
        value = 0
        for coefficient, symbol in zip(row, field_symbols):
            value ^= gf_multiply(coefficient, symbol[word_index])
        encoded_words.append(value)
    encoded = b"".join(word.to_bytes(2, "big") for word in encoded_words)
    return index.to_bytes(2, "big") + encoded


def parse_array(block: str, name: str, length: int) -> bytes:
    match = re.search(
        rf"static const uint8_t {re.escape(name)}\[{length}\] = \{{(.*?)\}};",
        block,
        re.DOTALL,
    )
    if match is None:
        raise ValueError(f"missing {name}[{length}]")
    value = bytes(int(token, 16) for token in re.findall(r"0x([0-9a-fA-F]{2})", match.group(1)))
    if len(value) != length:
        raise ValueError(f"{name}: expected {length} bytes, found {len(value)}")
    return value


def load_mlkem768_kat(path: Path) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    text = path.read_text(encoding="utf-8")
    start = text.index("#elif MLK_CONFIG_PARAMETER_SET == 768")
    end = text.index("#elif MLK_CONFIG_PARAMETER_SET == 1024", start)
    block = text[start:end]
    d = parse_array(text[:start], "test_vector_d", 32)
    z = parse_array(text[:start], "test_vector_z", 32)
    m = parse_array(text[:start], "test_vector_m", 32)
    return (
        d,
        z,
        m,
        parse_array(block, "test_vector_pk", 1184),
        parse_array(block, "test_vector_ct", 1088),
        parse_array(block, "test_vector_ss", 32),
    )


@dataclass(frozen=True)
class Message:
    epoch: int
    message_type: int
    chunk: bytes | None = None


@dataclass
class Actor:
    actor_id: int
    state: str
    epoch: int = 1
    send_index: int = 0
    received: set[int] = field(default_factory=set)
    root_key: bytes = b""
    mac_key: bytes = b""


def append_record(
    transcript: "hashlib._Hash",
    operation: bytes,
    actor: Actor,
    message: Message,
    high_water: int,
    emitted: tuple[int, bytes] | None,
) -> str:
    transcript.update(operation)
    transcript.update(bytes([actor.actor_id]))
    transcript.update(message.epoch.to_bytes(8, "big"))
    transcript.update(bytes([message.message_type]))
    if message.chunk is None:
        transcript.update(b"\0")
    else:
        transcript.update(b"\1")
        transcript.update(message.chunk)
    transcript.update(high_water.to_bytes(8, "big"))
    if emitted is None:
        transcript.update(b"\0")
    else:
        transcript.update(b"\1")
        transcript.update(emitted[0].to_bytes(8, "big"))
        transcript.update(emitted[1])
    return transcript.copy().hexdigest()


def generate_vector(kat_path: Path) -> dict[str, str]:
    d, z, m, public_key, ciphertext, shared_secret = load_mlkem768_kat(kat_path)
    public_vector, rho = public_key[:1152], public_key[1152:]
    ct1, ct2 = ciphertext[:960], ciphertext[960:]
    header = rho + hashlib.sha3_256(public_key).digest()
    initial_root, initial_mac = update_authenticator(ZERO32, AUTH_KEY, 1)
    header_mac = protocol_mac(initial_mac, HEADER_MAC, 1, header)
    epoch_key = output_key(shared_secret, 1)
    next_root, next_mac = update_authenticator(initial_root, epoch_key, 1)
    ciphertext_mac = protocol_mac(next_mac, CIPHERTEXT_MAC, 1, ct1 + ct2)
    header_payload = header + header_mac
    ct2_payload = ct2 + ciphertext_mac

    alice = Actor(1, "keys_unsampled", root_key=initial_root, mac_key=initial_mac)
    bob = Actor(2, "no_header", root_key=initial_root, mac_key=initial_mac)
    transcript = hashlib.sha256()
    round_digests: list[str] = []
    record_digests: list[str] = []
    alice_output: bytes | None = None
    bob_output: bytes | None = None
    records = 0

    def send(actor: Actor) -> tuple[Message, int, tuple[int, bytes] | None]:
        nonlocal bob_output
        if actor.state == "keys_unsampled":
            actor.state = "keys_sampled"
            actor.send_index = 1
            return Message(actor.epoch, TYPE_HEADER, erasure_chunk(header_payload, 0)), actor.epoch - 1, None
        if actor.state == "keys_sampled":
            index = actor.send_index
            actor.send_index += 1
            return Message(actor.epoch, TYPE_HEADER, erasure_chunk(header_payload, index)), actor.epoch - 1, None
        if actor.state == "header_sent":
            index = actor.send_index
            actor.send_index += 1
            return Message(actor.epoch, TYPE_EK, erasure_chunk(public_vector, index)), actor.epoch - 1, None
        if actor.state == "ct1_received":
            index = actor.send_index
            actor.send_index += 1
            return Message(actor.epoch, TYPE_EK_CT1_ACK, erasure_chunk(public_vector, index)), actor.epoch - 1, None
        if actor.state == "header_received":
            actor.state = "ct1_sampled"
            actor.send_index = 1
            actor.root_key, actor.mac_key = next_root, next_mac
            bob_output = epoch_key
            return Message(actor.epoch, TYPE_CT1, erasure_chunk(ct1, 0)), actor.epoch - 1, (actor.epoch, epoch_key)
        if actor.state == "ct1_sampled":
            index = actor.send_index
            actor.send_index += 1
            return Message(actor.epoch, TYPE_CT1, erasure_chunk(ct1, index)), actor.epoch - 1, None
        if actor.state == "ct1_acknowledged":
            return Message(actor.epoch, TYPE_NONE), actor.epoch - 1, None
        if actor.state == "ct2_sampled":
            index = actor.send_index
            actor.send_index += 1
            return Message(actor.epoch, TYPE_CT2, erasure_chunk(ct2_payload, index)), actor.epoch - 1, None
        if actor.state in ("ek_sent_ct1_received", "no_header"):
            return Message(actor.epoch, TYPE_NONE), actor.epoch - 1, None
        raise AssertionError(f"unsupported send state {actor.state}")

    def receive(actor: Actor, message: Message) -> tuple[int, tuple[int, bytes] | None]:
        nonlocal alice_output
        high_water = actor.epoch - 1
        if actor.state == "no_header" and message.epoch == actor.epoch and message.message_type == TYPE_HEADER:
            actor.received.add(int.from_bytes(message.chunk[:2], "big"))
            if len(actor.received) == 3:
                actor.state = "header_received"
                actor.received.clear()
            return high_water, None
        if actor.state == "keys_sampled" and message.epoch == actor.epoch and message.message_type == TYPE_CT1:
            actor.state = "header_sent"
            actor.send_index = 0
            actor.received = {int.from_bytes(message.chunk[:2], "big")}
            return high_water, None
        if actor.state == "header_sent" and message.epoch == actor.epoch and message.message_type == TYPE_CT1:
            actor.received.add(int.from_bytes(message.chunk[:2], "big"))
            if len(actor.received) == 30:
                actor.state = "ct1_received"
                actor.received.clear()
            return high_water, None
        if actor.state in ("ct1_sampled", "ct1_acknowledged") and message.epoch == actor.epoch and message.message_type in (TYPE_EK, TYPE_EK_CT1_ACK):
            actor.received.add(int.from_bytes(message.chunk[:2], "big"))
            acknowledged = message.message_type == TYPE_EK_CT1_ACK
            if len(actor.received) == 36 and acknowledged:
                actor.state = "ct2_sampled"
                actor.send_index = 0
                actor.received.clear()
            elif acknowledged:
                actor.state = "ct1_acknowledged"
            return high_water, None
        if actor.state == "ct1_received" and message.epoch == actor.epoch and message.message_type == TYPE_CT2:
            actor.state = "ek_sent_ct1_received"
            actor.received = {int.from_bytes(message.chunk[:2], "big")}
            return high_water, None
        if actor.state == "ek_sent_ct1_received" and message.epoch == actor.epoch and message.message_type == TYPE_CT2:
            actor.received.add(int.from_bytes(message.chunk[:2], "big"))
            if len(actor.received) == 5:
                actor.state = "no_header"
                actor.epoch += 1
                actor.received.clear()
                actor.root_key, actor.mac_key = next_root, next_mac
                alice_output = epoch_key
                return high_water, (actor.epoch - 1, epoch_key)
            return high_water, None
        if actor.state == "ct2_sampled" and message.epoch == actor.epoch + 1:
            actor.state = "keys_unsampled"
            actor.epoch += 1
            actor.send_index = 0
            return message.epoch - 1, None
        return high_water, None

    for round_index in range(44):
        message, high_water, emitted = send(alice)
        record_digests.append(
            append_record(transcript, b"S", alice, message, high_water, emitted)
        )
        records += 1
        received_epoch, received_output = receive(bob, message)
        record_digests.append(
            append_record(transcript, b"R", bob, message, received_epoch, received_output)
        )
        records += 1
        if round_index == 43:
            round_digests.append(transcript.copy().hexdigest())
            break
        message, high_water, emitted = send(bob)
        record_digests.append(
            append_record(transcript, b"S", bob, message, high_water, emitted)
        )
        records += 1
        received_epoch, received_output = receive(alice, message)
        record_digests.append(
            append_record(transcript, b"R", alice, message, received_epoch, received_output)
        )
        records += 1
        round_digests.append(transcript.copy().hexdigest())

    if alice.state != "no_header" or alice.epoch != 2:
        raise AssertionError((alice.state, alice.epoch))
    if bob.state != "keys_unsampled" or bob.epoch != 2:
        raise AssertionError((bob.state, bob.epoch))
    if alice_output != epoch_key or bob_output != epoch_key:
        raise AssertionError("participants did not emit the same epoch key")
    if (alice.root_key, alice.mac_key) != (next_root, next_mac):
        raise AssertionError("Alice authenticator mismatch")
    if (bob.root_key, bob.mac_key) != (next_root, next_mac):
        raise AssertionError("Bob authenticator mismatch")

    vector = {
        "format": "layergram-scka-cross-implementation-v1",
        "specification": "https://signal.org/docs/specifications/mlkembraid/ revision 1 2025-09-26",
        "mlkem_source": "third_party/mlkem-native/test/expected_test_vectors.h ML-KEM-768",
        "protocol_info_hex": PROTOCOL_INFO.hex(),
        "keygen_d_hex": d.hex(),
        "keygen_z_hex": z.hex(),
        "encapsulation_m_hex": m.hex(),
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "shared_secret_hex": shared_secret.hex(),
        "header_hex": header.hex(),
        "initial_auth_root_hex": initial_root.hex(),
        "initial_auth_mac_hex": initial_mac.hex(),
        "header_mac_hex": header_mac.hex(),
        "header_payload_sha256": hashlib.sha256(header_payload).hexdigest(),
        "header_chunk_3_hex": erasure_chunk(header_payload, 3).hex(),
        "output_key_hex": epoch_key.hex(),
        "next_auth_root_hex": next_root.hex(),
        "next_auth_mac_hex": next_mac.hex(),
        "ciphertext_mac_hex": ciphertext_mac.hex(),
        "ct2_payload_sha256": hashlib.sha256(ct2_payload).hexdigest(),
        "public_vector_chunk_36_hex": erasure_chunk(public_vector, 36).hex(),
        "ciphertext1_chunk_30_hex": erasure_chunk(ct1, 30).hex(),
        "ciphertext2_chunk_5_hex": erasure_chunk(ct2_payload, 5).hex(),
        "transcript_records": str(records),
        "transcript_sha256": transcript.hexdigest(),
        "final_alice_state": "NoHeaderReceived:2",
        "final_bob_state": "KeysUnsampled:2",
    }
    vector.update(
        {
            f"round_{round_index:02d}_sha256": digest
            for round_index, digest in enumerate(round_digests)
        }
    )
    vector.update(
        {
            f"record_{record_index:03d}_sha256": digest
            for record_index, digest in enumerate(record_digests)
        }
    )
    return vector


def render(vector: dict[str, str]) -> str:
    header = [
        "# Layergram-owned independent ML-KEM Braid revision-1 vector",
        "# Generated only from the public-domain specification, Python stdlib,",
        "# and the permissively licensed mlkem-native ML-KEM-768 KAT.",
    ]
    return "\n".join(header + [f"{key}={value}" for key, value in vector.items()]) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--kat",
        type=Path,
        default=Path("third_party/mlkem-native/test/expected_test_vectors.h"),
    )
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    output = render(generate_vector(args.kat))
    if args.check is not None:
        current = args.check.read_text(encoding="utf-8")
        if current != output:
            print(f"cross-implementation vector is stale: {args.check}", file=sys.stderr)
            return 1
        print(f"cross-implementation vector matches: {args.check}")
        return 0
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
