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

import 'ml_kem_768.dart';
import 'public_identity_v3.dart';

/// A strictly decoded public identity whose algorithm-specific checks passed.
///
/// The wrapper does not mean that a user verified the owner. It only means the
/// encoding and ML-KEM public key are structurally usable. A future handshake
/// and explicit fingerprint/SAS ceremony remain mandatory for authentication.
final class V3StructurallyValidatedPublicIdentity {
  const V3StructurallyValidatedPublicIdentity._(this.publicIdentity);

  final V3PublicIdentity publicIdentity;
}

/// Fail-closed decoder and algorithm validator for imported v3 identities.
final class V3PublicIdentityValidator {
  V3PublicIdentityValidator({required MlKem768Backend mlKem768Backend})
      : _mlKem768Backend = mlKem768Backend;

  final MlKem768Backend _mlKem768Backend;

  Future<V3StructurallyValidatedPublicIdentity> decodeBinary(
    Uint8List encoded,
  ) async {
    return validate(V3PublicIdentityCodec.decodeBinary(encoded));
  }

  Future<V3StructurallyValidatedPublicIdentity> decodeToken(
    String token,
  ) async {
    return validate(V3PublicIdentityCodec.decodeToken(token));
  }

  Future<V3StructurallyValidatedPublicIdentity> decodeLink(
    String link,
  ) async {
    return validate(V3PublicIdentityCodec.decodeLink(link));
  }

  Future<V3StructurallyValidatedPublicIdentity> validate(
    V3PublicIdentity identity,
  ) async {
    if (!await _mlKem768Backend.selfTest()) {
      throw StateError('ML-KEM-768 backend self-test failed');
    }
    switch (identity.suite) {
      case V3IdentitySuite.hybridX25519MlKem768:
        if (!await _mlKem768Backend.validatePublicKey(
          identity.mlKem768PublicKey,
        )) {
          throw const FormatException(
            'Invalid Layergram v3 ML-KEM-768 public key',
          );
        }
    }
    return V3StructurallyValidatedPublicIdentity._(identity);
  }
}
