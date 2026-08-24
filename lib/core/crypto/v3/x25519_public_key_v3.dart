// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

import 'dart:typed_data';

/// Canonical RFC 7748 X25519 public-key encoding used as a protocol identity.
abstract final class V3X25519PublicKey {
  static const int bytes = 32;

  static Uint8List validatedCopy(List<int> value, String name) {
    validate(value, name);
    return Uint8List.fromList(value);
  }

  static void validate(List<int> value, String name) {
    if (value.length != bytes) {
      throw ArgumentError.value(value.length, '$name.length', 'must be $bytes');
    }
    if (value.every((byte) => byte == 0)) {
      throw ArgumentError.value(value, name, 'must not be all zero');
    }
    // RFC 7748 field prime 2^255 - 19, little-endian. X25519 arithmetic
    // accepts aliases, but Layergram identity IDs require one unique encoding.
    const prime = <int>[
      0xed,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0x7f,
    ];
    for (var index = bytes - 1; index >= 0; index--) {
      if (value[index] < prime[index]) return;
      if (value[index] > prime[index]) {
        throw ArgumentError.value(value, name, 'must be canonical X25519');
      }
    }
    throw ArgumentError.value(value, name, 'must be canonical X25519');
  }
}
