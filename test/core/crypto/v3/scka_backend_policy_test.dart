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
    expect(scaffold['thirdPartyDependencies'], hasLength(8));
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
    expect(boundary['stateMachineConnected'], isTrue);
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

    final entropy =
        receipt['operatingSystemEntropyPrimitive'] as Map<String, dynamic>;
    expect(entropy['crate'], 'getrandom');
    expect(entropy['version'], '0.4.3');
    expect(entropy['specification'], 'specs/ENTROPY_SOURCES.md');
    expect(entropy['selectedLicense'], 'Apache-2.0');
    expect(entropy['defaultFeatures'], isFalse);
    expect(entropy['defaultOperatingSystemBackendOnly'], isTrue);
    expect(entropy['fullBufferOrError'], isTrue);
    expect(entropy['customBackendAllowed'], isFalse);
    expect(entropy['hardwareInstructionOnlyBackendAllowed'], isFalse);
    expect(entropy['unsupportedBackendAllowed'], isFalse);
    expect(entropy['rejectedOptInBackends'], <String>[
      'custom',
      'efi_rng',
      'rdrand',
      'rndr',
      'linux_getrandom',
      'linux_raw',
      'windows_legacy',
      'unsupported',
      'extern_impl',
    ]);
    final platformSources = entropy['platformSources'] as Map<String, dynamic>;
    expect(
      platformSources['linuxAndroid'],
      'getrandom syscall; documented older-kernel fallback waits for '
      '/dev/random readiness before /dev/urandom',
    );
    expect(platformSources['windows10Plus'], 'ProcessPrng');
    expect(platformSources['macos'], 'getentropy');
    expect(platformSources['ios'], 'CCRandomGenerateBytes');
    expect(entropy['deterministicProductionHook'], isFalse);
    expect(entropy['publicAbiConnected'], isFalse);
    expect(entropy['applicationRuntimeConnected'], isFalse);
    for (final license
        in (entropy['runtimeOrBuildDependencyLicenses'] as List<dynamic>)
            .cast<String>()) {
      expect(license, isNot(contains('AGPL')));
      expect(license, isNot(matches(RegExp(r'(^|[^A])GPL'))));
    }
    expect(File(entropy['notices'] as String).existsSync(), isTrue);

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
    expect(envelope['independentlyReviewed'], isFalse);

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
    expect(payload['transitionEngineConnected'], isTrue);
    expect(payload['productionRegistered'], isFalse);
    expect(payload['independentlyReviewed'], isFalse);

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
    expect(authenticator['transitionEngineConnected'], isTrue);
    expect(authenticator['productionRegistered'], isFalse);
    expect(authenticator['independentlyReviewed'], isFalse);

    final publicMessage =
        receipt['layergramOwnedPublicMessageCodec'] as Map<String, dynamic>;
    expect(publicMessage['license'], 'Apache-2.0');
    expect(publicMessage['thirdPartyDependenciesAdded'], isEmpty);
    expect(publicMessage['magic'], 'BM3');
    expect(publicMessage['formatVersion'], 1);
    expect(publicMessage['protocolRevision'], 1);
    expect(publicMessage['headerBytes'], 24);
    expect(publicMessage['noDataMessageBytes'], 24);
    expect(publicMessage['dataMessageBytes'], 58);
    expect(publicMessage['messageTypeCount'], 7);
    expect(publicMessage['encodedChunkBytes'], 34);
    expect(publicMessage['signed63Epochs'], isTrue);
    expect(publicMessage['typeBindsPayloadClass'], isTrue);
    expect(publicMessage['emptyRevisionOneMessageAccepted'], isFalse);
    expect(publicMessage['canonicalReencodeCheck'], isTrue);
    expect(publicMessage['independentGoldenVectors'], isTrue);
    expect(publicMessage['publicAbiConnected'], isFalse);
    expect(publicMessage['transitionEngineConnected'], isTrue);
    expect(publicMessage['productionRegistered'], isFalse);
    expect(publicMessage['independentlyReviewed'], isFalse);

    final transition =
        receipt['layergramOwnedTransitionEngine'] as Map<String, dynamic>;
    expect(transition['license'], 'Apache-2.0');
    expect(transition['implementedFunctions'], <String>[
      'InitAlice',
      'InitBob',
      'KeysUnsampled.Send',
      'KeysUnsampled.Receive',
      'KeysSampled.Send',
      'KeysSampled.Receive',
      'HeaderSent.Send',
      'HeaderSent.Receive',
      'Ct1Received.Send',
      'Ct1Received.Receive',
      'EkSentCt1Received.Send',
      'EkSentCt1Received.Receive',
      'NoHeaderReceived.Send',
      'NoHeaderReceived.Receive',
      'HeaderReceived.Send',
      'HeaderReceived.Receive',
      'Ct1Sampled.Send',
      'Ct1Sampled.Receive',
      'Ct1Acknowledged.Send',
      'Ct1Acknowledged.Receive',
      'EkReceivedCt1Sampled.Send',
      'EkReceivedCt1Sampled.Receive',
    ]);
    expect(transition['firstTransitionNumber'], 1);
    expect(
      transition['implementedTransitionNumbers'],
      <int>[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    );
    expect(transition['deterministicGoldenVectors'], isTrue);
    expect(transition['immutableAuthenticatedPrior'], isTrue);
    expect(transition['detachedExactStateAndMessageCandidate'], isTrue);
    expect(transition['osEntropyBytesPerKeyGeneration'], 64);
    expect(transition['osEntropyBytesPerEncapsulation'], 32);
    expect(transition['deterministicEntropyExported'], isFalse);
    expect(transition['reexportRequiresExactCandidateReuse'], isTrue);
    expect(transition['unreliableExternalTransportAssumed'], isTrue);
    expect(transition['zeroizingNativeEpochOutput'], isTrue);
    expect(transition['authenticationPrecedesNextEpochSuccessor'], isTrue);
    expect(
      transition['headerAuthenticationPrecedesHeaderReceivedSuccessor'],
      isTrue,
    );
    expect(transition['transitionSevenOutputBoundToSendCandidate'], isTrue);
    expect(transition['rawEncapsulationSharedSecretSerialized'], isFalse);
    expect(transition['transitionEightDropsAcknowledgedCt1Encoder'], isTrue);
    expect(
      transition['transitionNineCompletesEncapsulation'],
      isTrue,
    );
    expect(
      transition['transitionNineFullPublicKeyIntegrityBeforeSuccessor'],
      isTrue,
    );
    expect(
      transition['transitionNineAuthenticatesCiphertextBeforeCt2State'],
      isTrue,
    );
    expect(transition['transitionNineRequestsEntropy'], isFalse);
    expect(transition['transitionNineEmitsEpochKey'], isFalse);
    expect(
      transition['transitionTenFullPublicKeyIntegrityBeforeSuccessor'],
      isTrue,
    );
    expect(
      transition['transitionTenPreservesCt1EncoderUntilAcknowledged'],
      isTrue,
    );
    expect(transition['transitionTenRequestsEntropy'], isFalse);
    expect(transition['transitionTenEmitsEpochKey'], isFalse);
    expect(
      transition['ct1SampledPlainCompletionImplementedByTransitionTen'],
      isTrue,
    );
    expect(
      transition['transitionElevenCompletesEncapsulation'],
      isTrue,
    );
    expect(
      transition['transitionElevenFullPublicKeyIntegrityBeforeSuccessor'],
      isTrue,
    );
    expect(
      transition['transitionElevenAuthenticatesCiphertextBeforeCt2State'],
      isTrue,
    );
    expect(transition['transitionElevenRequestsEntropy'], isFalse);
    expect(transition['transitionElevenEmitsEpochKey'], isFalse);
    expect(
      transition['ekReceivedCt1SampledAckFailClosedUntilTransitionTwelve'],
      isTrue,
    );
    expect(transition['typedTerminalAuthenticationFailure'], isTrue);
    expect(transition['publicAbiConnected'], isFalse);
    expect(transition['durableJournalConnected'], isFalse);
    expect(transition['productionRegistered'], isFalse);
    expect(transition['independentlyReviewed'], isFalse);

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
    expect(effects['publicMessageCodecAdded'], isTrue);
    expect(effects['initialTransitionEngineSliceAdded'], isTrue);
    expect(effects['operatingSystemEntropyBoundaryAdded'], isTrue);
    expect(effects['getrandomBackendOverrideGuardAdded'], isTrue);
    expect(effects['identityMnemonicFullByteRangeHardened'], isTrue);
    expect(effects['transitionThreeAdded'], isTrue);
    expect(effects['transitionFourAdded'], isTrue);
    expect(effects['transitionFiveAdded'], isTrue);
    expect(effects['transitionSixAdded'], isTrue);
    expect(effects['transitionSevenAdded'], isTrue);
    expect(effects['transitionEightAdded'], isTrue);
    expect(effects['transitionNineAdded'], isTrue);
    expect(effects['transitionTenAdded'], isTrue);
    expect(effects['transitionElevenAdded'], isTrue);
    expect(effects['pubspecChanged'], isFalse);
    expect(effects['protocolV3Activated'], isFalse);

    final remainingGates =
        (receipt['remainingGates'] as List<dynamic>).cast<String>();
    expect(remainingGates, hasLength(8));
    expect(
      remainingGates.any(
        (gate) => gate.contains('transitions 12 through 13'),
      ),
      isTrue,
    );
    expect(
      remainingGates.any(
        (gate) => gate
            .contains('every shipped Apple, Android, Windows, and Linux ABI'),
      ),
      isTrue,
    );
    expect(
      remainingGates.any(
        (gate) => gate
            .contains('independent cryptographic and implementation review'),
      ),
      isTrue,
    );
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
      contains(
        'getrandom = { version = "=0.4.3", default-features = false }',
      ),
    );
    expect(manifest, contains('cfg(getrandom_backend'));
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
    expect(lock, contains('name = "getrandom"'));
    expect(lock, contains('name = "hkdf"'));
    expect(lock, contains('name = "hmac"'));
    expect(lock, contains('name = "libcrux-ml-kem"'));
    expect(lock, contains('name = "zeroize"'));
    expect(lock, contains('name = "sha2"'));
    expect(header, contains('LG_SCKA_V1_ERR_NOT_READY = -2'));

    final entropySource = File(
      'native/layergram_scka/src/entropy.rs',
    ).readAsStringSync();
    expect(entropySource, contains('compile_error!'));
    for (final backend in <String>[
      'custom',
      'efi_rng',
      'rdrand',
      'rndr',
      'linux_getrandom',
      'linux_raw',
      'windows_legacy',
      'unsupported',
      'extern_impl',
    ]) {
      expect(entropySource, contains('getrandom_backend = "$backend"'));
    }
    expect(File('specs/ENTROPY_SOURCES.md').readAsStringSync(),
        contains('protocol v3 inactive'));

    final notices = File(
      'native/layergram_scka/THIRD_PARTY_NOTICES.md',
    ).readAsStringSync();
    expect(notices, contains('libcrux-ml-kem'));
    expect(notices, contains('hkdf'));
    expect(notices, contains('hmac'));
    expect(notices, contains('getrandom'));
    expect(notices, contains('r-efi'));
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
    expect(nativeEntry, contains('mod braid_message;'));
    expect(nativeEntry, contains('mod braid_state_payload;'));
    expect(nativeEntry, contains('mod braid_transition;'));
    expect(nativeEntry, contains('mod entropy;'));
    expect(nativeEntry, isNot(contains('incremental_mlkem::')));
    expect(nativeEntry, isNot(contains('state_envelope::')));
    expect(nativeEntry, isNot(contains('braid_authenticator::')));
    expect(nativeEntry, isNot(contains('braid_message::')));
    expect(nativeEntry, isNot(contains('braid_state_payload::')));
    expect(nativeEntry, isNot(contains('braid_transition::')));
    expect(nativeEntry, isNot(contains('entropy::')));
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
    final publicMessage = File(
      'native/layergram_scka/src/braid_message.rs',
    ).readAsStringSync();
    expect(publicMessage, contains('const MAGIC: &[u8; 3] = b"BM3";'));
    expect(publicMessage, contains('pub(crate) enum BraidMessageType'));
    expect(publicMessage, contains('decoded.encode().as_slice() != encoded'));
    expect(publicMessage, contains('BraidMessageType::Ciphertext1Ack'));
    expect(
      File('specs/SCKA_PUBLIC_MESSAGE.md').readAsStringSync(),
      contains('protocol v3 inactive'),
    );
    final transition = File(
      'native/layergram_scka/src/braid_transition.rs',
    ).readAsStringSync();
    expect(transition, contains('pub(crate) fn initialize('));
    expect(transition, contains('pub(crate) fn send('));
    expect(transition, contains('pub(crate) fn receive('));
    expect(transition, contains('send_with_entropy(prior, &mut OsEntropy)'));
    expect(transition, contains('BraidStateVariant::KeysSampled'));
    expect(transition, contains('BraidStateVariant::HeaderSent'));
    expect(transition, contains('BraidStateVariant::Ct1Received'));
    expect(transition, contains('BraidStateVariant::EkSentCt1Received'));
    expect(transition, contains('BraidStateVariant::NoHeaderReceived'));
    expect(transition, contains('BraidStateVariant::HeaderReceived'));
    expect(transition, contains('BraidStateVariant::Ct1Sampled'));
    expect(transition, contains('BraidStateVariant::EkReceivedCt1Sampled'));
    expect(transition, contains('BraidStateVariant::Ct1Acknowledged'));
    expect(transition, contains('BraidStateVariant::Ct2Sampled'));
    expect(transition, contains('send_while_header_received_with_entropy'));
    expect(transition, contains('send_while_ct1_sampled'));
    expect(transition, contains('receive_while_ct1_sampled'));
    expect(transition, contains('send_while_ek_received_ct1_sampled'));
    expect(transition, contains('receive_while_ek_received_ct1_sampled'));
    expect(transition, contains('encapsulate_part_one_from_seed'));
    expect(transition, contains('restore_encapsulation_part_one'));
    expect(transition, contains('encapsulate_part_two'));
    expect(transition, contains('validate_public_key'));
    expect(transition, contains('BraidMessageType::Header'));
    expect(transition, contains('BraidMessageType::EncapsulationKey'));
    expect(transition, contains('receive_while_header_sent'));
    expect(transition, contains('receive_while_ct1_received'));
    expect(transition, contains('receive_while_ek_sent_ct1_received'));
    expect(transition, contains('send_while_no_header_received'));
    expect(transition, contains('receive_while_no_header_received'));
    expect(transition, contains('derive_output_key'));
    expect(transition, contains('successor_auth.verify_ciphertext'));
    expect(transition, contains('authenticator.verify_header'));
    expect(transition, contains('authenticator.mac_ciphertext'));
    expect(transition, contains('BraidMessageType::None'));
    expect(
      File('specs/SCKA_TRANSITION_ENGINE.md').readAsStringSync(),
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
