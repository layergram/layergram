// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'lmf_v3_persistence.dart';
import 'local_identity_v3.dart';

/// Encrypted, identity/passphrase-scoped owner of one installation device key.
///
/// The seed is stored only inside the padded Aux-record boundary supplied by
/// [V3LmfRecordStore]. A second installation therefore receives a different
/// device ID even when the same BIP39 identity is restored.
final class V3DeviceKeyRepository {
  V3DeviceKeyRepository({
    required V3LmfRecordStore store,
    Random? secureRandom,
    this.maxPhysicalRecords = 8,
  })  : _store = store,
        _secureRandom = secureRandom ?? Random.secure() {
    if (maxPhysicalRecords <= 0) {
      throw ArgumentError.value(maxPhysicalRecords, 'maxPhysicalRecords');
    }
  }

  static const String recordKind = 'v3_device_key_v1';
  static const int _formatVersion = 1;
  static const int _seedBytes = 32;

  final V3LmfRecordStore _store;
  final Random _secureRandom;
  final int maxPhysicalRecords;

  Future<V3LocalDeviceHandle> loadOrCreate() async {
    final records = (await _store.readAll())
        .where((record) => record.payload['kind'] == recordKind)
        .toList(growable: false);
    if (records.length > maxPhysicalRecords) {
      throw const V3LmfPersistenceLimitException(
        'Layergram v3 device-key record limit exceeded',
      );
    }
    if (records.isNotEmpty) {
      records.sort((left, right) => left.storageId.compareTo(right.storageId));
      final selectedSeed = _decode(records.first.payload);
      try {
        for (final duplicate in records.skip(1)) {
          final candidateSeed = _decode(duplicate.payload);
          try {
            if (!_bytesEqual(selectedSeed, candidateSeed)) {
              throw const V3LmfPersistenceConflictException(
                'Divergent Layergram v3 device-key records',
              );
            }
            await _store.delete(duplicate.storageId);
          } finally {
            candidateSeed.fillRange(0, candidateSeed.length, 0);
          }
        }
        return await V3LocalDeviceHandle.fromSeed(selectedSeed);
      } finally {
        selectedSeed.fillRange(0, selectedSeed.length, 0);
      }
    }

    final seed = Uint8List.fromList(
      List<int>.generate(_seedBytes, (_) => _secureRandom.nextInt(256)),
    );
    V3LocalDeviceHandle? handle;
    try {
      if (seed.every((byte) => byte == 0)) {
        throw StateError('Operating-system CSPRNG returned an invalid seed');
      }
      handle = await V3LocalDeviceHandle.fromSeed(seed);
      await _store.write(_encode(seed));
      return handle;
    } catch (_) {
      handle?.close();
      rethrow;
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  static Map<String, dynamic> _encode(Uint8List seed) {
    return <String, dynamic>{
      'kind': recordKind,
      'version': _formatVersion,
      'seed': base64UrlEncode(seed).replaceAll('=', ''),
    };
  }

  static Uint8List _decode(Map<String, dynamic> payload) {
    if (payload.length != 3 ||
        payload['kind'] != recordKind ||
        payload['version'] != _formatVersion ||
        payload['seed'] is! String) {
      throw const FormatException('Invalid Layergram v3 device-key record');
    }
    final armored = payload['seed'] as String;
    if (armored.length != 43 || !_isCanonicalBase64Url(armored)) {
      throw const FormatException('Invalid Layergram v3 device-key seed');
    }
    late final Uint8List seed;
    try {
      seed = Uint8List.fromList(
        base64Url.decode(base64Url.normalize(armored)),
      );
    } on FormatException {
      throw const FormatException('Invalid Layergram v3 device-key seed');
    }
    if (seed.length != _seedBytes ||
        seed.every((byte) => byte == 0) ||
        base64UrlEncode(seed).replaceAll('=', '') != armored) {
      seed.fillRange(0, seed.length, 0);
      throw const FormatException('Invalid Layergram v3 device-key seed');
    }
    return seed;
  }

  static bool _isCanonicalBase64Url(String value) {
    for (final codeUnit in value.codeUnits) {
      final uppercase = codeUnit >= 0x41 && codeUnit <= 0x5a;
      final lowercase = codeUnit >= 0x61 && codeUnit <= 0x7a;
      final digit = codeUnit >= 0x30 && codeUnit <= 0x39;
      if (!uppercase &&
          !lowercase &&
          !digit &&
          codeUnit != 0x2d &&
          codeUnit != 0x5f) {
        return false;
      }
    }
    return true;
  }

  static bool _bytesEqual(Uint8List left, Uint8List right) {
    if (left.length != right.length) return false;
    var difference = 0;
    for (var index = 0; index < left.length; index++) {
      difference |= left[index] ^ right[index];
    }
    return difference == 0;
  }
}
