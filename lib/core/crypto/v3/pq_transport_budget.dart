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

import '../stego_encoder.dart';

/// Research-only sizing helpers for carrying post-quantum material through
/// the existing LMF v2 steganographic carrier.
///
/// These calculations cover raw fragment payload bytes only. A production v3
/// fragment must also budget its authenticated header, routing fields and AEAD
/// overhead. This class deliberately does not select a protocol chunk size.
abstract final class V3PqStegoBudget {
  static int fragmentCount({
    required int totalPayloadBytes,
    required int maxFragmentPayloadBytes,
  }) {
    _validateInputs(totalPayloadBytes, maxFragmentPayloadBytes);
    if (totalPayloadBytes == 0) return 0;
    return (totalPayloadBytes + maxFragmentPayloadBytes - 1) ~/
        maxFragmentPayloadBytes;
  }

  static List<int> fragmentPayloadSizes({
    required int totalPayloadBytes,
    required int maxFragmentPayloadBytes,
  }) {
    final count = fragmentCount(
      totalPayloadBytes: totalPayloadBytes,
      maxFragmentPayloadBytes: maxFragmentPayloadBytes,
    );
    if (count == 0) return const <int>[];

    final result = List<int>.filled(count, maxFragmentPayloadBytes);
    result[count - 1] =
        totalPayloadBytes - (maxFragmentPayloadBytes * (count - 1));
    return List<int>.unmodifiable(result);
  }

  static int minimumVisibleCoverCharactersForRawFragment(int byteCount) {
    if (byteCount < 0) {
      throw ArgumentError.value(byteCount, 'byteCount', 'must not be negative');
    }
    return StegoEncoder.minCoverLengthForBytes(byteCount);
  }

  static int requiredCarrierSlotsForRawFragment(int byteCount) {
    if (byteCount < 0) {
      throw ArgumentError.value(byteCount, 'byteCount', 'must not be negative');
    }
    return StegoEncoder.requiredCarrierSlotsForBytes(byteCount);
  }

  static void _validateInputs(
    int totalPayloadBytes,
    int maxFragmentPayloadBytes,
  ) {
    if (totalPayloadBytes < 0) {
      throw ArgumentError.value(
        totalPayloadBytes,
        'totalPayloadBytes',
        'must not be negative',
      );
    }
    if (maxFragmentPayloadBytes <= 0) {
      throw ArgumentError.value(
        maxFragmentPayloadBytes,
        'maxFragmentPayloadBytes',
        'must be positive',
      );
    }
  }
}
