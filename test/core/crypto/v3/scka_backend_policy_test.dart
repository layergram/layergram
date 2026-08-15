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
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('SCKA candidate receipt excludes AGPL code from the Premium base', () {
    final receipt = jsonDecode(
      File('tool/pq/scka_native_candidate.json').readAsStringSync(),
    ) as Map<String, dynamic>;

    expect(
      receipt['status'],
      'implementation-path-selected-not-production-approved',
    );

    final reference =
        receipt['referenceImplementation'] as Map<String, dynamic>;
    expect(reference['license'], 'AGPL-3.0-only');
    expect(reference['decision'], 'rejected-for-linking-or-embedding');

    final selected =
        receipt['selectedImplementationPath'] as Map<String, dynamic>;
    expect(selected['license'], 'Apache-2.0');
    expect(selected['productionRegistered'], isFalse);

    final scaffold = receipt['layergramOwnedScaffold'] as Map<String, dynamic>;
    expect(scaffold['crate'], 'layergram-scka');
    expect(scaffold['license'], 'Apache-2.0');
    expect(scaffold['rustVersion'], '1.87.0');
    expect(scaffold['cargoLockPackageCount'], 98);
    expect(scaffold['thirdPartyDependencies'], hasLength(7));
    expect(scaffold['abiVersion'], 1);
    expect(scaffold['protocolRevision'], 1);
    expect(scaffold['stateFormatVersion'], 1);
    expect(scaffold['runtimeStatus'], 'not-ready-not-registered-not-linked');

    final primitive =
        receipt['incrementalMlKemPrimitiveCandidate'] as Map<String, dynamic>;
    expect(primitive['crate'], 'libcrux-ml-kem');
    expect(primitive['version'], '0.0.10');
    expect(primitive['license'], 'Apache-2.0');
    expect(
      primitive['engineeringLicenseGate'],
      'pass-inactive-internal-adoption',
    );
    final probe = primitive['rust187ApiProbe'] as Map<String, dynamic>;
    expect(probe['result'], 'pass-adopted-inactive-wrapper');
    expect(probe['offlineLockedRerun'], isTrue);
    expect(probe['pk1Bytes'], 64);
    expect(probe['pk2Bytes'], 1152);
    expect(probe['ciphertext1Bytes'], 960);
    expect(probe['ciphertext2Bytes'], 128);
    expect(probe['encapsulationStateBytes'], 2080);
    expect(probe['sharedSecretBytes'], 32);
    for (final key in <String>[
      'runtimeOrBuildDependencyLicenses',
      'sharedNormalHashDependencyLicenses',
    ]) {
      final dependencyLicenses = primitive[key] as List<dynamic>;
      for (final license in dependencyLicenses.cast<String>()) {
        expect(license, isNot(contains('AGPL')));
        expect(license, isNot(contains('LGPL')));
        expect(license, isNot(matches(RegExp(r'(^|[^A])GPL'))));
      }
    }
    expect(File(primitive['notices'] as String).existsSync(), isTrue);
    expect(File(primitive['unicodeLicense'] as String).existsSync(), isTrue);
    expect(
      File(primitive['mitGenericArrayLicense'] as String).existsSync(),
      isTrue,
    );

    final boundary = receipt['layergramOwnedIncrementalMlKemBoundary']
        as Map<String, dynamic>;
    expect(boundary['publicAbiConnected'], isFalse);
    expect(boundary['stateMachineConnected'], isFalse);
    expect(boundary['productionRegistered'], isFalse);
    expect(boundary['exactLengthValidation'], isTrue);
    expect(
      boundary['fullPublicKeyValidationBeforeCiphertextPartTwo'],
      isTrue,
    );
    expect(boundary['partOneStateBoundToPublicKey'], isTrue);
    expect(
      boundary['encaps1SecretEmissionMatchesBraidRevision1'],
      isTrue,
    );
    expect(boundary['rawSharedSecretExcludedFromPendingState'], isTrue);
    expect(boundary['independentMlKemNativeKat'], isTrue);
    expect(boundary['independentlyReviewed'], isFalse);

    final envelopePrimitive =
        receipt['authenticatedStateEnvelopePrimitive'] as Map<String, dynamic>;
    expect(envelopePrimitive['crate'], 'aes-gcm');
    expect(envelopePrimitive['version'], '0.10.3');
    expect(envelopePrimitive['selectedLicense'], 'Apache-2.0');
    expect(envelopePrimitive['defaultFeatures'], isFalse);
    expect(envelopePrimitive['features'], <String>['aes', 'zeroize']);
    for (final license in (envelopePrimitive['runtimeOrBuildDependencyLicenses']
            as List<dynamic>)
        .cast<String>()) {
      expect(license, isNot(contains('AGPL')));
      expect(license, isNot(contains('LGPL')));
      expect(license, isNot(matches(RegExp(r'(^|[^A])GPL'))));
    }
    expect(File(envelopePrimitive['notices'] as String).existsSync(), isTrue);
    expect(
        File(envelopePrimitive['bsdLicense'] as String).existsSync(), isTrue);

    final authenticatorPrimitives =
        receipt['ratchetedAuthenticatorPrimitives'] as Map<String, dynamic>;
    for (final entry in <Map<String, dynamic>>[
      authenticatorPrimitives['hkdf'] as Map<String, dynamic>,
      authenticatorPrimitives['hmac'] as Map<String, dynamic>,
      authenticatorPrimitives['sha2'] as Map<String, dynamic>,
    ]) {
      expect(entry['selectedLicense'], 'Apache-2.0');
      expect(entry['defaultFeatures'], isFalse);
    }
    for (final license
        in (authenticatorPrimitives['runtimeOrBuildDependencyLicenses']
                as List<dynamic>)
            .cast<String>()) {
      expect(license, isNot(contains('AGPL')));
      expect(license, isNot(contains('LGPL')));
      expect(license, isNot(matches(RegExp(r'(^|[^A])GPL'))));
    }
    expect(
      File(authenticatorPrimitives['notices'] as String).existsSync(),
      isTrue,
    );

    final envelope = receipt['layergramOwnedAuthenticatedStateEnvelope']
        as Map<String, dynamic>;
    expect(envelope['algorithm'], 'AES-256-GCM');
    expect(envelope['headerBytes'], 80);
    expect(envelope['nonceBytes'], 12);
    expect(envelope['tagBytes'], 16);
    expect(envelope['maximumPayloadBytes'], 196512);
    expect(envelope['headerIsAad'], isTrue);
    expect(envelope['publicAbiConnected'], isFalse);
    expect(envelope['stateMachinePayloadFrozen'], isTrue);
    expect(envelope['productionRegistered'], isFalse);

    final payload =
        receipt['layergramOwnedStateMachinePayload'] as Map<String, dynamic>;
    expect(payload['license'], 'Apache-2.0');
    expect(payload['thirdPartyDependenciesAdded'], isEmpty);
    expect(payload['magic'], 'LB3');
    expect(payload['formatVersion'], 1);
    expect(payload['headerBytes'], 136);
    expect(payload['minimumPayloadBytes'], 136);
    expect(payload['maximumPayloadBytes'], 4434);
    expect(payload['stateVariantCount'], 11);
    expect(payload['duplicatesAndChecksOuterMetadata'], isTrue);
    expect(payload['privateAndPublicKeyValidation'], isTrue);
    expect(payload['canonicalEncoderDecoderProgress'], isTrue);
    expect(payload['bestEffortSecretZeroization'], isTrue);
    expect(payload['publicAbiConnected'], isFalse);
    expect(payload['transitionEngineConnected'], isFalse);
    expect(payload['productionRegistered'], isFalse);

    final authenticator =
        receipt['layergramOwnedRatchetedAuthenticator'] as Map<String, dynamic>;
    expect(authenticator['license'], 'Apache-2.0');
    expect(
      authenticator['protocolInfo'],
      'LayergramV3_MLKEM768_HMAC-SHA256',
    );
    expect(authenticator['authKeyBytes'], 32);
    expect(authenticator['macBytes'], 32);
    expect(authenticator['headerBytes'], 64);
    expect(authenticator['authenticatedCiphertextBytes'], 1088);
    expect(authenticator['signed63Epochs'], isTrue);
    expect(authenticator['constantTimeVerification'], isTrue);
    expect(authenticator['typedOutputKeyRatchet'], isTrue);
    expect(authenticator['ciphertextPartsTypedSeparately'], isTrue);
    expect(authenticator['immutableSuccessorState'], isTrue);
    expect(authenticator['zeroizingOutputKeyOwner'], isTrue);
    expect(authenticator['independentGoldenVectors'], isTrue);
    expect(authenticator['publicAbiConnected'], isFalse);
    expect(authenticator['transitionEngineConnected'], isFalse);
    expect(authenticator['productionRegistered'], isFalse);

    final effects = receipt['checkpointEffects'] as Map<String, dynamic>;
    expect(effects['thirdPartyCodeImported'], isFalse);
    expect(effects['runtimeDependencyAddedToInactiveNativeCrate'], isTrue);
    expect(effects['runtimeDependencyAddedToApplication'], isFalse);
    expect(effects['layergramOwnedScaffoldAdded'], isTrue);
    expect(effects['layergramOwnedErasureCodeAdded'], isTrue);
    expect(effects['incrementalMlKemBoundaryAdded'], isTrue);
    expect(effects['authenticatedStateEnvelopeBoundaryAdded'], isTrue);
    expect(effects['canonicalStateMachinePayloadAdded'], isTrue);
    expect(effects['ratchetedAuthenticatorAdded'], isTrue);
    expect(effects['pubspecChanged'], isFalse);
    expect(effects['protocolV3Activated'], isFalse);
  });

  test('Layergram SCKA dependencies are pinned, permissive, and not packaged',
      () {
    final manifest =
        File('native/layergram_scka/Cargo.toml').readAsStringSync();
    final lock = File('native/layergram_scka/Cargo.lock').readAsStringSync();
    final header = File(
      'native/layergram_scka/include/layergram_scka.h',
    ).readAsStringSync();

    expect(manifest, contains('license = "Apache-2.0"'));
    expect(
      manifest,
      contains(
        'aes = { version = "=0.8.4", default-features = false, '
        'features = ["zeroize"] }',
      ),
    );
    expect(
      manifest,
      contains(
        'aes-gcm = { version = "=0.10.3", default-features = false, '
        'features = ["aes", "zeroize"] }',
      ),
    );
    expect(
      manifest,
      contains('hkdf = { version = "=0.12.4", default-features = false }'),
    );
    expect(
      manifest,
      contains('hmac = { version = "=0.12.1", default-features = false }'),
    );
    expect(
      manifest,
      contains(
        'libcrux-ml-kem = { version = "=0.0.10", '
        'default-features = false, features = ["incremental", "mlkem768"] }',
      ),
    );
    expect(
      manifest,
      contains(
        'zeroize = { version = "=1.8.1", default-features = false }',
      ),
    );
    expect(
      manifest,
      contains('sha2 = { version = "=0.10.9", default-features = false }'),
    );
    expect(
      RegExp(r'^\[\[package\]\]$', multiLine: true).allMatches(lock),
      hasLength(98),
    );
    expect(lock, contains('name = "aes-gcm"'));
    expect(lock, contains('name = "aes"'));
    expect(lock, contains('name = "hkdf"'));
    expect(lock, contains('name = "hmac"'));
    expect(lock, contains('name = "libcrux-ml-kem"'));
    expect(lock, contains('name = "zeroize"'));
    expect(lock, contains('name = "sha2"'));
    expect(header, contains('LG_SCKA_V1_ERR_NOT_READY = -2'));

    final notices = File(
      'native/layergram_scka/THIRD_PARTY_NOTICES.md',
    ).readAsStringSync();
    expect(notices, contains('libcrux-ml-kem'));
    expect(notices, contains('hkdf'));
    expect(notices, contains('hmac'));
    expect(notices, contains('sha2'));
    expect(notices, contains('Unicode-3.0'));
    expect(notices, contains('generic-array'));
    expect(notices, contains('subtle'));
    expect(notices, contains('BSD-3-Clause'));

    for (final path in <String>[
      'pubspec.yaml',
      'LayergramMlKem.podspec',
      'ios/Podfile',
      'macos/Podfile',
      'android/app/src/main/cpp/CMakeLists.txt',
      'linux/CMakeLists.txt',
      'windows/CMakeLists.txt',
    ]) {
      expect(
        File(path).readAsStringSync(),
        isNot(contains('layergram_scka')),
        reason: '$path must not package the inactive SCKA scaffold',
      );
    }
  });

  test('incremental ML-KEM module remains internal and outside the ABI', () {
    final nativeEntry = File(
      'native/layergram_scka/src/lib.rs',
    ).readAsStringSync();
    final source = File(
      'native/layergram_scka/src/incremental_mlkem.rs',
    ).readAsStringSync();

    expect(nativeEntry, contains('mod incremental_mlkem;'));
    expect(nativeEntry, contains('mod state_envelope;'));
    expect(nativeEntry, contains('mod braid_authenticator;'));
    expect(nativeEntry, contains('mod braid_state_payload;'));
    expect(nativeEntry, isNot(contains('incremental_mlkem::')));
    expect(nativeEntry, isNot(contains('state_envelope::')));
    expect(nativeEntry, isNot(contains('braid_authenticator::')));
    expect(nativeEntry, isNot(contains('braid_state_payload::')));
    expect(source, contains('validate_pk_bytes'));
    expect(source, contains('checked_seed.zeroize()'));
    expect(source, contains('part_one: EncapsulationPartOne'));
    expect(source, contains('pub(crate) struct EncapsulationStarted'));
    expect(source, contains('pub(crate) struct EncapsulationPartTwo'));
    expect(source, contains('pub(crate) fn into_pending(self)'));
    expect(
      File('native/layergram_scka/src/state_envelope.rs').readAsStringSync(),
      contains('decrypt_in_place_detached'),
    );
    expect(
      File('specs/SCKA_INCREMENTAL_MLKEM.md').readAsStringSync(),
      contains('v3 inactive'),
    );
    final payload = File(
      'native/layergram_scka/src/braid_state_payload.rs',
    ).readAsStringSync();
    expect(payload, contains('const MAGIC: &[u8; 3] = b"LB3";'));
    expect(payload, contains('MAX_BRAID_PAYLOAD_BYTES: usize = 4_434'));
    expect(payload, contains('pub(crate) enum BraidStateVariant'));
    expect(payload, contains('key_pair_from_private_key'));
    expect(payload, contains('self.encoded.zeroize()'));
    expect(
      File('specs/SCKA_STATE_PAYLOAD.md').readAsStringSync(),
      contains('protocol v3 inactive'),
    );
    final authenticator = File(
      'native/layergram_scka/src/braid_authenticator.rs',
    ).readAsStringSync();
    expect(
      authenticator,
      contains('PROTOCOL_INFO: &[u8] = b"LayergramV3_MLKEM768_HMAC-SHA256"'),
    );
    expect(authenticator, contains('Hkdf::<Sha256>::new'));
    expect(authenticator, contains('mac.verify_slice(expected_mac)'));
    expect(authenticator, contains('self.root_key.zeroize()'));
    expect(
      File('specs/SCKA_AUTHENTICATOR.md').readAsStringSync(),
      contains('protocol v3 inactive'),
    );
  });

  test('Layergram erasure code remains owned, dependency-free, and inactive',
      () {
    final receipt = jsonDecode(
      File('tool/pq/scka_native_candidate.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    final erasure =
        receipt['layergramOwnedErasureCode'] as Map<String, dynamic>;

    expect(erasure['license'], 'Apache-2.0');
    expect(erasure['thirdPartyDependencies'], isEmpty);
    expect(erasure['symbolBytes'], 32);
    expect(erasure['encodedChunkBytes'], 34);
    expect(erasure['maximumEncodingIndex'], 65534);
    expect(erasure['maximumSourceChunks'], 36);
    expect(erasure['runtimeConnected'], isFalse);
    expect(erasure['independentlyReviewed'], isFalse);

    final source = File(
      'native/layergram_scka/src/erasure.rs',
    ).readAsStringSync();
    expect(source, contains('const FIELD_REDUCTION: u16 = 0x100b;'));
    expect(source, contains('MAX_ENCODING_INDEX: u16 = u16::MAX - 1'));
    expect(source, contains('ConflictingDuplicate'));
    expect(
      File('specs/SCKA_ERASURE_CODE.md').readAsStringSync(),
      contains('protocol v3 inactive'),
    );

    final nativeEntry = File(
      'native/layergram_scka/src/lib.rs',
    ).readAsStringSync();
    expect(nativeEntry, contains('mod erasure;'));
    expect(nativeEntry, isNot(contains('erasure::encode_chunks(')));
    expect(nativeEntry, isNot(contains('erasure::decode_message(')));
  });
}
