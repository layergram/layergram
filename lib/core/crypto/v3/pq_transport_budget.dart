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
import 'lmf_v3.dart';

/// Sizing helpers for carrying post-quantum material through Layergram's
/// existing steganographic carrier.
///
/// Raw helpers remain useful for comparing candidate fragment sizes. The
/// canonical-frame helpers include the inactive LMF v3 header and full AEAD tag.
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

  static int canonicalFragmentFrameBytes(int fragmentPlaintextBytes) {
    if (fragmentPlaintextBytes <= 0 ||
        fragmentPlaintextBytes > V3LmfFrameCodec.fragmentPlaintextBytes) {
      throw ArgumentError.value(
        fragmentPlaintextBytes,
        'fragmentPlaintextBytes',
        'must be between 1 and '
            '${V3LmfFrameCodec.fragmentPlaintextBytes}',
      );
    }
    return V3LmfFrameCodec.headerBytes +
        fragmentPlaintextBytes +
        V3LmfFrameCodec.authenticationTagBytes;
  }

  static int minimumVisibleCoverCharactersForCanonicalFragment(
    int fragmentPlaintextBytes,
  ) {
    return StegoEncoder.minCoverLengthForBytes(
      canonicalFragmentFrameBytes(fragmentPlaintextBytes),
    );
  }

  static int minimumEncodedCharactersForCanonicalFragment(
    int fragmentPlaintextBytes,
  ) {
    final frameBytes = canonicalFragmentFrameBytes(fragmentPlaintextBytes);
    return StegoEncoder.minCoverLengthForBytes(frameBytes) +
        StegoEncoder.minimumHiddenLengthForBytes(frameBytes);
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
