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

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';

import '../../../../tool/pq/identity_qr_camera_harness.dart' as harness;

void main() {
  test('physical QR harness uses one canonical maximum-size v3 identity', () {
    final payload = harness.buildPhysicalQrHarnessPayload();
    expect(payload, hasLength(V3PublicIdentityCodec.maxBinaryBytes));

    final decoded = V3PublicIdentityCodec.decodeBinary(payload);
    expect(
      decoded.displayName,
      hasLength(V3PublicIdentityCodec.maxDisplayNameBytes),
    );
    expect(V3PublicIdentityCodec.encodeBinary(decoded), orderedEquals(payload));
  });

  test('physical QR harness accepts any complete canonical v3 identity', () {
    final payload = V3PublicIdentityCodec.encodeBinary(
      V3PublicIdentity(
        x25519PublicKey: Uint8List.fromList(
          List<int>.generate(32, (index) => index + 1),
        ),
        mlKem768PublicKey: Uint8List.fromList(
          List<int>.generate(
            MlKem768.publicKeyBytes,
            (index) => (index % 251) + 1,
          ),
        ),
        displayName: 'Alice',
      ),
    );

    expect(payload, hasLength(1243));
    expect(harness.isPhysicalQrHarnessAcceptedPayload(payload), isTrue);

    final corrupted = Uint8List.fromList(payload);
    corrupted[corrupted.length - 1] ^= 1;
    expect(harness.isPhysicalQrHarnessAcceptedPayload(corrupted), isFalse);
  });
}
