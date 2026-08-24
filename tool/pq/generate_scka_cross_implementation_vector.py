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

LB3_SESSION_ID = bytes([0x44]) * 16
LB3_STATE_REVISION = 7
LB3_EPOCH = 1
LB3_AUTH_ROOT = bytes([0x31]) * 32
LB3_AUTH_MAC = bytes([0x72]) * 32
LB3_CONTINUATION_BYTES = 2_080
LB3_CONTINUATION = bytes(
    ((index * 29 + 7) & 0xFF) for index in range(LB3_CONTINUATION_BYTES)
)

LB3_VARIANTS = {
    "keys_unsampled": 1,
    "keys_sampled": 2,
    "header_sent": 3,
    "ct1_received": 4,
    "ek_sent_ct1_received": 5,
    "no_header_received": 6,
    "header_received": 7,
    "ct1_sampled": 8,
    "ek_received_ct1_sampled": 9,
    "ct1_acknowledged": 10,
    "ct2_sampled": 11,
}

BM3_TYPES = {
    "none": TYPE_NONE,
    "header": TYPE_HEADER,
    "encapsulation_key": TYPE_EK,
    "encapsulation_key_and_ciphertext1_ack": TYPE_EK_CT1_ACK,
    "ciphertext1_ack": TYPE_CT1_ACK,
    "ciphertext1": TYPE_CT1,
    "ciphertext2": TYPE_CT2,
}


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


def erasure_decode(chunks: list[bytes], message_bytes: int) -> bytes:
    """Recover one revision-1 erasure payload without production code."""
    if message_bytes <= 0 or message_bytes % 32:
        raise ValueError("message length must contain complete 32-byte symbols")
    source_chunks = message_bytes // 32
    if source_chunks > 36 or len(chunks) > 72:
        raise ValueError("erasure recovery exceeds revision-1 bounds")

    unique: dict[int, bytes] = {}
    for chunk in chunks:
        if len(chunk) != 34:
            raise ValueError("encoded chunk must contain an index and 32-byte symbol")
        index = int.from_bytes(chunk[:2], "big")
        if index > 65_534:
            raise ValueError("encoded chunk uses the reserved index")
        previous = unique.get(index)
        if previous is not None and not hmac.compare_digest(previous, chunk[2:]):
            raise ValueError("conflicting duplicate erasure chunk")
        unique[index] = chunk[2:]
    if len(unique) < source_chunks:
        raise ValueError("insufficient unique erasure chunks")

    selected = sorted(unique.items())[:source_chunks]
    systematic = systematic_inverse(source_chunks)
    decoding_matrix = invert(
        [coefficients(source_chunks, index, systematic) for index, _ in selected]
    )
    received_symbols = [
        [
            int.from_bytes(symbol[offset : offset + 2], "big")
            for offset in range(0, 32, 2)
        ]
        for _, symbol in selected
    ]
    recovered = bytearray()
    for row in decoding_matrix:
        for word_index in range(16):
            value = 0
            for coefficient, symbol in zip(row, received_symbols):
                value ^= gf_multiply(coefficient, symbol[word_index])
            recovered.extend(value.to_bytes(2, "big"))
    if len(recovered) != message_bytes:
        raise AssertionError("independent erasure decoder returned the wrong length")
    return bytes(recovered)


def recovery_indexes(source_chunks: int) -> list[int]:
    """Select a deterministic reordered mix of source and parity symbols."""
    return list(
        reversed(
            [
                offset if offset % 2 == 0 else source_chunks + offset * 7
                for offset in range(source_chunks)
            ]
        )
    )


def recovery_vector(message: bytes) -> tuple[list[int], bytes, bytes]:
    indexes = recovery_indexes(len(message) // 32)
    chunks = [erasure_chunk(message, index) for index in indexes]
    recovered = erasure_decode(chunks, len(message))
    if not hmac.compare_digest(recovered, message):
        raise AssertionError("mixed erasure recovery changed the payload")
    if erasure_decode(chunks + [chunks[0]], len(message)) != recovered:
        raise AssertionError("exact duplicate changed erasure recovery")
    conflicting = bytearray(chunks[0])
    conflicting[-1] ^= 1
    try:
        erasure_decode(chunks + [bytes(conflicting)], len(message))
    except ValueError:
        pass
    else:
        raise AssertionError("conflicting erasure duplicate was accepted")
    return indexes, hashlib.sha256(b"".join(chunks)).digest(), recovered


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


def load_mlkem768_kat(
    path: Path,
) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes, bytes]:
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
        parse_array(block, "test_vector_sk", 2400),
        parse_array(block, "test_vector_ct", 1088),
        parse_array(block, "test_vector_ss", 32),
    )


def encode_bm3(epoch: int, message_type: int, chunk: bytes | None) -> bytes:
    requires_chunk = message_type not in (TYPE_NONE, TYPE_CT1_ACK)
    if not 1 <= epoch <= 0x7FFF_FFFF_FFFF_FFFF:
        raise ValueError("BM3 epoch is outside the signed-63 domain")
    if requires_chunk != (chunk is not None):
        raise ValueError("BM3 message type and chunk shape disagree")
    if chunk is not None:
        if len(chunk) != 34 or int.from_bytes(chunk[:2], "big") > 65_534:
            raise ValueError("BM3 chunk is not canonical")
    total_length = 58 if requires_chunk else 24
    encoded = bytearray(total_length)
    encoded[:3] = b"BM3"
    encoded[3] = 1
    encoded[4] = 1
    encoded[5] = message_type
    encoded[7] = 24
    encoded[8:10] = total_length.to_bytes(2, "big")
    encoded[10:12] = (1).to_bytes(2, "big")
    encoded[12:20] = epoch.to_bytes(8, "big")
    if chunk is not None:
        encoded[24:] = chunk
    return bytes(encoded)


def encode_decoder(chunks: list[bytes], source_chunks: int, minimum: int = 0) -> bytes:
    if not minimum <= len(chunks) < source_chunks:
        raise ValueError("LB3 decoder progress is not incomplete and canonical")
    canonical = sorted(chunks, key=lambda chunk: int.from_bytes(chunk[:2], "big"))
    indexes = [int.from_bytes(chunk[:2], "big") for chunk in canonical]
    if any(len(chunk) != 34 for chunk in canonical):
        raise ValueError("LB3 decoder contains a malformed chunk")
    if any(index > 65_534 for index in indexes) or len(set(indexes)) != len(indexes):
        raise ValueError("LB3 decoder indexes are not canonical")
    return len(canonical).to_bytes(2, "big") + b"".join(canonical)


def encode_lb3(role: int, variant: int, body: bytes) -> bytes:
    if role not in (1, 2) or variant not in LB3_VARIANTS.values():
        raise ValueError("LB3 role or variant is not canonical")
    total_length = 136 + len(body)
    if not 136 <= total_length <= 4_434:
        raise ValueError("LB3 payload exceeds the frozen revision-1 bound")
    encoded = bytearray(136)
    encoded[:3] = b"LB3"
    encoded[3] = 1
    encoded[4] = 1
    encoded[5] = role
    encoded[6] = variant
    encoded[8:10] = (136).to_bytes(2, "big")
    encoded[10:12] = (1).to_bytes(2, "big")
    encoded[12:16] = total_length.to_bytes(4, "big")
    encoded[16:32] = LB3_SESSION_ID
    encoded[32:40] = LB3_STATE_REVISION.to_bytes(8, "big")
    encoded[40:48] = LB3_EPOCH.to_bytes(8, "big")
    encoded[48:56] = (0).to_bytes(8, "big")
    encoded[56:64] = (0).to_bytes(8, "big")
    encoded[64:96] = LB3_AUTH_ROOT
    encoded[96:128] = LB3_AUTH_MAC
    encoded[128:132] = len(body).to_bytes(4, "big")
    return bytes(encoded) + body


def codec_vectors(
    private_key: bytes,
    public_key_header: bytes,
    public_key_vector: bytes,
    header_mac: bytes,
    ciphertext_one: bytes,
    ciphertext_two: bytes,
    ciphertext_mac: bytes,
    header_payload: bytes,
    ciphertext_two_payload: bytes,
) -> dict[str, str]:
    pending = public_key_header + LB3_CONTINUATION + ciphertext_one
    if len(private_key) != 2_400 or len(pending) != 3_104:
        raise AssertionError("frozen primitive sizes changed")

    ct1_decoder = encode_decoder([erasure_chunk(ciphertext_one, 1)], 30, 1)
    ct2_decoder = encode_decoder([erasure_chunk(ciphertext_two_payload, 1)], 5, 1)
    public_decoder_one = encode_decoder([erasure_chunk(public_key_vector, 1)], 36, 1)
    public_decoder_two = encode_decoder(
        [erasure_chunk(public_key_vector, 1), erasure_chunk(public_key_vector, 4)],
        36,
    )
    empty_header_decoder = encode_decoder([], 3)
    empty_public_decoder = encode_decoder([], 36)

    bodies = {
        "keys_unsampled": b"",
        "keys_sampled": private_key + header_mac + (1).to_bytes(2, "big"),
        "header_sent": private_key + (0).to_bytes(2, "big") + ct1_decoder,
        "ct1_received": private_key + ciphertext_one + (9).to_bytes(2, "big"),
        "ek_sent_ct1_received": private_key + ciphertext_one + ct2_decoder,
        "no_header_received": empty_header_decoder,
        "header_received": public_key_header + empty_public_decoder,
        "ct1_sampled": pending + (1).to_bytes(2, "big") + public_decoder_two,
        "ek_received_ct1_sampled": pending
        + public_key_vector
        + (3).to_bytes(2, "big"),
        "ct1_acknowledged": pending + public_decoder_one,
        "ct2_sampled": ciphertext_two
        + ciphertext_mac
        + (0).to_bytes(2, "big"),
    }

    encoded_states: dict[str, bytes] = {}
    sender_variants = {
        "keys_unsampled",
        "keys_sampled",
        "header_sent",
        "ct1_received",
        "ek_sent_ct1_received",
    }
    for name, variant in LB3_VARIANTS.items():
        encoded_states[name] = encode_lb3(
            1 if name in sender_variants else 2,
            variant,
            bodies[name],
        )

    messages = {
        "none": encode_bm3(7, TYPE_NONE, None),
        "header": encode_bm3(7, TYPE_HEADER, erasure_chunk(header_payload, 3)),
        "encapsulation_key": encode_bm3(
            7, TYPE_EK, erasure_chunk(public_key_vector, 36)
        ),
        "encapsulation_key_and_ciphertext1_ack": encode_bm3(
            7, TYPE_EK_CT1_ACK, erasure_chunk(public_key_vector, 37)
        ),
        "ciphertext1_ack": encode_bm3(7, TYPE_CT1_ACK, None),
        "ciphertext1": encode_bm3(7, TYPE_CT1, erasure_chunk(ciphertext_one, 30)),
        "ciphertext2": encode_bm3(
            7, TYPE_CT2, erasure_chunk(ciphertext_two_payload, 5)
        ),
    }

    state_bundle = hashlib.sha256()
    values: dict[str, str] = {
        "codec_vector_format": "layergram-scka-lb3-bm3-conformance-v1",
        "lb3_payload_format": "1",
        "lb3_protocol_revision": "1",
        "lb3_session_id_hex": LB3_SESSION_ID.hex(),
        "lb3_state_revision": str(LB3_STATE_REVISION),
        "lb3_epoch": str(LB3_EPOCH),
        "lb3_auth_root_hex": LB3_AUTH_ROOT.hex(),
        "lb3_auth_mac_hex": LB3_AUTH_MAC.hex(),
        "continuation_dependency": "libcrux-ml-kem=0.0.10",
        "continuation_bytes": str(LB3_CONTINUATION_BYTES),
        "continuation_pattern": "byte(i)=(29*i+7)%256",
        "continuation_sha256": hashlib.sha256(LB3_CONTINUATION).hexdigest(),
        "continuation_binding": "lb3-format-1+libcrux-ml-kem-0.0.10+2080-bytes",
        "private_key_sha256": hashlib.sha256(private_key).hexdigest(),
    }
    for name, variant in LB3_VARIANTS.items():
        encoded = encoded_states[name]
        values[f"lb3_{name}_bytes"] = str(len(encoded))
        values[f"lb3_{name}_sha256"] = hashlib.sha256(encoded).hexdigest()
        state_bundle.update(bytes([variant]))
        state_bundle.update(len(encoded).to_bytes(4, "big"))
        state_bundle.update(encoded)
    values["lb3_bundle_sha256"] = state_bundle.hexdigest()

    message_bundle = hashlib.sha256()
    for name, message_type in BM3_TYPES.items():
        encoded = messages[name]
        values[f"bm3_{name}_hex"] = encoded.hex()
        message_bundle.update(bytes([message_type]))
        message_bundle.update(len(encoded).to_bytes(2, "big"))
        message_bundle.update(encoded)
    values["bm3_bundle_sha256"] = message_bundle.hexdigest()
    return values


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
    received: dict[int, bytes] = field(default_factory=dict)
    root_key: bytes = b""
    mac_key: bytes = b""
    recovered_header: bytes | None = None
    recovered_ciphertext_one: bytes | None = None


def store_chunk(actor: Actor, chunk: bytes | None) -> None:
    if chunk is None or len(chunk) != 34:
        raise ValueError("state transition requires one canonical erasure chunk")
    index = int.from_bytes(chunk[:2], "big")
    if index > 65_534:
        raise ValueError("state transition received the reserved erasure index")
    previous = actor.received.get(index)
    if previous is not None and not hmac.compare_digest(previous, chunk):
        raise ValueError("state transition received a conflicting duplicate")
    actor.received[index] = chunk


def verify_header_payload(payload: bytes, mac_key: bytes, epoch: int) -> bytes:
    if len(payload) != 96:
        raise ValueError("reconstructed header payload has the wrong length")
    header, supplied_mac = payload[:64], payload[64:]
    expected_mac = protocol_mac(mac_key, HEADER_MAC, epoch, header)
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise ValueError("reconstructed header authentication failed")
    return header


def verify_public_key_binding(header: bytes, public_vector: bytes) -> None:
    if len(header) != 64 or len(public_vector) != 1_152:
        raise ValueError("reconstructed public-key material has the wrong length")
    rho, supplied_digest = header[:32], header[32:]
    expected_digest = hashlib.sha3_256(public_vector + rho).digest()
    if not hmac.compare_digest(supplied_digest, expected_digest):
        raise ValueError("reconstructed public key is not bound to the header")


def verify_ciphertext_payload(
    payload: bytes,
    ciphertext_one: bytes,
    mac_key: bytes,
    epoch: int,
) -> bytes:
    if len(payload) != 160 or len(ciphertext_one) != 960:
        raise ValueError("reconstructed ciphertext material has the wrong length")
    ciphertext_two, supplied_mac = payload[:128], payload[128:]
    expected_mac = protocol_mac(
        mac_key, CIPHERTEXT_MAC, epoch, ciphertext_one + ciphertext_two
    )
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise ValueError("reconstructed ciphertext authentication failed")
    return ciphertext_two


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
    d, z, m, public_key, private_key, ciphertext, shared_secret = load_mlkem768_kat(
        kat_path
    )
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

    recovery = {
        "header": recovery_vector(header_payload),
        "public_vector": recovery_vector(public_vector),
        "ciphertext1": recovery_vector(ct1),
        "ciphertext2": recovery_vector(ct2_payload),
    }
    if verify_header_payload(recovery["header"][2], initial_mac, 1) != header:
        raise AssertionError("mixed header recovery changed the authenticated header")
    verify_public_key_binding(header, recovery["public_vector"][2])
    recovered_ct2 = verify_ciphertext_payload(
        recovery["ciphertext2"][2], recovery["ciphertext1"][2], next_mac, 1
    )
    if not hmac.compare_digest(recovered_ct2, ct2):
        raise AssertionError("mixed ciphertext recovery changed ciphertext part two")

    tampered_header = bytearray(header_payload)
    tampered_header[-1] ^= 1
    try:
        verify_header_payload(bytes(tampered_header), initial_mac, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("tampered header MAC was accepted")
    tampered_ciphertext = bytearray(ct2_payload)
    tampered_ciphertext[-1] ^= 1
    try:
        verify_ciphertext_payload(bytes(tampered_ciphertext), ct1, next_mac, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("tampered ciphertext MAC was accepted")

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
            store_chunk(actor, message.chunk)
            if len(actor.received) == 3:
                payload = erasure_decode(list(actor.received.values()), 96)
                actor.recovered_header = verify_header_payload(
                    payload, actor.mac_key, actor.epoch
                )
                actor.state = "header_received"
                actor.received.clear()
            return high_water, None
        if actor.state == "keys_sampled" and message.epoch == actor.epoch and message.message_type == TYPE_CT1:
            actor.state = "header_sent"
            actor.send_index = 0
            store_chunk(actor, message.chunk)
            return high_water, None
        if actor.state == "header_sent" and message.epoch == actor.epoch and message.message_type == TYPE_CT1:
            store_chunk(actor, message.chunk)
            if len(actor.received) == 30:
                actor.recovered_ciphertext_one = erasure_decode(
                    list(actor.received.values()), 960
                )
                actor.state = "ct1_received"
                actor.received.clear()
            return high_water, None
        if actor.state in ("ct1_sampled", "ct1_acknowledged") and message.epoch == actor.epoch and message.message_type in (TYPE_EK, TYPE_EK_CT1_ACK):
            store_chunk(actor, message.chunk)
            acknowledged = message.message_type == TYPE_EK_CT1_ACK
            if len(actor.received) >= 36:
                recovered_public_vector = erasure_decode(
                    list(actor.received.values()), 1_152
                )
                if actor.recovered_header is None:
                    raise AssertionError("public key completed before its header")
                verify_public_key_binding(
                    actor.recovered_header, recovered_public_vector
                )
                if not hmac.compare_digest(recovered_public_vector, public_vector):
                    raise AssertionError("transcript public key differs from the ML-KEM KAT")
            if len(actor.received) >= 36 and acknowledged:
                actor.state = "ct2_sampled"
                actor.send_index = 0
                actor.received.clear()
            elif acknowledged:
                actor.state = "ct1_acknowledged"
            return high_water, None
        if actor.state == "ct1_received" and message.epoch == actor.epoch and message.message_type == TYPE_CT2:
            actor.state = "ek_sent_ct1_received"
            store_chunk(actor, message.chunk)
            return high_water, None
        if actor.state == "ek_sent_ct1_received" and message.epoch == actor.epoch and message.message_type == TYPE_CT2:
            store_chunk(actor, message.chunk)
            if len(actor.received) == 5:
                payload = erasure_decode(list(actor.received.values()), 160)
                if actor.recovered_ciphertext_one is None:
                    raise AssertionError("ciphertext part two completed before part one")
                recovered_ciphertext_two = verify_ciphertext_payload(
                    payload,
                    actor.recovered_ciphertext_one,
                    next_mac,
                    actor.epoch,
                )
                if not hmac.compare_digest(
                    actor.recovered_ciphertext_one + recovered_ciphertext_two,
                    ciphertext,
                ):
                    raise AssertionError("transcript ciphertext differs from the ML-KEM KAT")
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
        "format": "layergram-scka-cross-implementation-v3",
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
        "receive_header_indexes": ",".join(
            str(index) for index in recovery["header"][0]
        ),
        "receive_header_chunks_sha256": recovery["header"][1].hex(),
        "receive_public_vector_indexes": ",".join(
            str(index) for index in recovery["public_vector"][0]
        ),
        "receive_public_vector_chunks_sha256": recovery["public_vector"][1].hex(),
        "receive_ciphertext1_indexes": ",".join(
            str(index) for index in recovery["ciphertext1"][0]
        ),
        "receive_ciphertext1_chunks_sha256": recovery["ciphertext1"][1].hex(),
        "receive_ciphertext2_indexes": ",".join(
            str(index) for index in recovery["ciphertext2"][0]
        ),
        "receive_ciphertext2_chunks_sha256": recovery["ciphertext2"][1].hex(),
        "receive_authentication": "header+public-key-binding+ciphertext-mac",
        "transcript_records": str(records),
        "transcript_sha256": transcript.hexdigest(),
        "final_alice_state": "NoHeaderReceived:2",
        "final_bob_state": "KeysUnsampled:2",
    }
    vector.update(
        codec_vectors(
            private_key,
            header,
            public_vector,
            header_mac,
            ct1,
            ct2,
            ciphertext_mac,
            header_payload,
            ct2_payload,
        )
    )
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
