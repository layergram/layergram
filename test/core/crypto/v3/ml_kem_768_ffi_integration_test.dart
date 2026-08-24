@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768_ffi.dart';

void main() {
  final libraryPath = Platform.environment['LAYERGRAM_MLKEM_TEST_LIBRARY'];
  final productionLibraryPath =
      Platform.environment['LAYERGRAM_MLKEM_PRODUCTION_LIBRARY'];
  final packagedMacOSLibraryPath =
      Platform.environment['LAYERGRAM_MLKEM_PACKAGED_MACOS_LIBRARY'];
  final skipReason = libraryPath == null
      ? 'Build the native test library with tool/pq/test_native_macos.sh'
      : false;
  final productionSkipReason = productionLibraryPath == null
      ? 'Build the production library with tool/pq/test_native_macos.sh'
      : false;

  test('macOS packaged path is derived from the app executable', () {
    expect(
      MlKem768FfiBackend.packagedMacOSLibraryPath(
        executablePath: '/Applications/Layergram.app/Contents/MacOS/Layergram',
      ),
      '/Applications/Layergram.app/Contents/Frameworks/'
      'LayergramMlKem.framework/Versions/A/LayergramMlKem',
    );
  });

  test('Linux packaged path is derived from the app executable', () {
    expect(
      MlKem768FfiBackend.packagedLinuxLibraryPath(
        executablePath: '/opt/layergram/layergram',
      ),
      '/opt/layergram/lib/liblayergram_mlkem.so',
    );
  });

  test('Windows packaged path is derived from the app executable', () {
    final path = MlKem768FfiBackend.packagedWindowsLibraryPath(
      executablePath: r'C:\Program Files\Layergram\layergram.exe',
    );
    if (Platform.isWindows) {
      expect(
        path,
        r'C:\Program Files\Layergram\layergram_mlkem.dll',
      );
    } else {
      expect(path, contains('layergram_mlkem.dll'));
    }
  });

  test('Dart calls the shipped ABI and passes upstream known-answer vectors',
      () async {
    const d =
        '934d60b35624d740b30a7f227af2ae7c678e4e04e13c5f509eade2b79aea77e2';
    const z =
        '3e2a2ea6c9c476fc4937b013c993a793d6c0ab9960695ba838f649da539ca3d0';
    const m = d;
    const expectedPublicKeySha256 =
        'c45a699a9efcb1a799578ce95f24b063b0b9ddc0879afdb3967fd9e1e3e8c247';
    const expectedCiphertextSha256 =
        '0b99b2af81971943e4ef6e6f17f42be4f3caa9fea18da0f63df1d43639a74743';
    const expectedSharedSecret =
        '0b1b32be26247cbcbe0916f8b0b729699c32a96d51efa4a4cd5b289239c8207e';

    final backend = MlKem768FfiBackend.open(libraryPath: libraryPath!);
    expect(
      backend.implementationId,
      MlKem768FfiBackend.approvedImplementationId,
    );
    expect(backend.hasTestHooks, isTrue);
    expect(await backend.selfTest(), isTrue);

    final keyPair = await backend.keyPairFromSeed(_hex('$d$z'));
    expect(
      sha256.convert(keyPair.publicKey).toString(),
      expectedPublicKeySha256,
    );
    expect(await backend.validatePublicKey(keyPair.publicKey), isTrue);
    expect(
      await backend.validatePublicKey(
        Uint8List(MlKem768.publicKeyBytes)
          ..fillRange(0, MlKem768.publicKeyBytes, 0xff),
      ),
      isFalse,
    );

    final encapsulation = await backend.encapsulateFromSeed(
      keyPair.publicKey,
      _hex(m),
    );
    expect(
      sha256.convert(encapsulation.ciphertext).toString(),
      expectedCiphertextSha256,
    );
    expect(
      _toHex(encapsulation.sharedSecret),
      expectedSharedSecret,
    );

    final decapsulated = await backend.decapsulate(
      keyPair.privateKeyHandle,
      encapsulation.ciphertext,
    );
    expect(decapsulated, orderedEquals(encapsulation.sharedSecret));

    final randomizedEncapsulation = await backend.encapsulate(
      keyPair.publicKey,
    );
    final randomizedDecapsulation = await backend.decapsulate(
      keyPair.privateKeyHandle,
      randomizedEncapsulation.ciphertext,
    );
    expect(
      randomizedDecapsulation,
      orderedEquals(randomizedEncapsulation.sharedSecret),
    );
    expect(
      randomizedEncapsulation.ciphertext,
      isNot(orderedEquals(encapsulation.ciphertext)),
    );

    final malformedCiphertext = Uint8List.fromList(encapsulation.ciphertext)
      ..[0] ^= 1;
    final rejectedSecret = await backend.decapsulate(
      keyPair.privateKeyHandle,
      malformedCiphertext,
    );
    expect(rejectedSecret, hasLength(MlKem768.sharedSecretBytes));
    expect(rejectedSecret, isNot(orderedEquals(encapsulation.sharedSecret)));

    final destroyedBefore = backend.testDestroyedHandleCount;
    await keyPair.privateKeyHandle.close();
    expect(keyPair.privateKeyHandle.isClosed, isTrue);
    expect(backend.testDestroyedHandleCount, destroyedBefore + 1);
    expect(backend.testLastDestroyedHandleWasZero, isTrue);
    await keyPair.privateKeyHandle.close();
    expect(backend.testDestroyedHandleCount, destroyedBefore + 1);

    await expectLater(
      backend.decapsulate(
        keyPair.privateKeyHandle,
        encapsulation.ciphertext,
      ),
      throwsStateError,
    );

    encapsulation.wipeSharedSecret();
    randomizedEncapsulation.wipeSharedSecret();
    decapsulated.fillRange(0, decapsulated.length, 0);
    randomizedDecapsulation.fillRange(
      0,
      randomizedDecapsulation.length,
      0,
    );
    rejectedSecret.fillRange(0, rejectedSecret.length, 0);
  }, skip: skipReason);

  test('Dart boundary rejects wrong sizes before entering native code',
      () async {
    final backend = MlKem768FfiBackend.open(libraryPath: libraryPath!);

    await expectLater(
      backend.keyPairFromSeed(
        Uint8List(MlKem768.keyGenerationSeedBytes - 1),
      ),
      throwsArgumentError,
    );
    await expectLater(
      backend.validatePublicKey(Uint8List(MlKem768.publicKeyBytes - 1)),
      throwsArgumentError,
    );
  }, skip: skipReason);

  test('production ABI owns entropy and excludes deterministic test hooks',
      () async {
    final backend = MlKem768FfiBackend.openPackagedLibrary(
      libraryPath: productionLibraryPath!,
    );
    expect(
      backend.implementationId,
      MlKem768FfiBackend.approvedImplementationId,
    );
    expect(backend.hasTestHooks, isFalse);
    expect(await backend.selfTest(), isTrue);

    final seed = Uint8List.fromList(
      List<int>.generate(MlKem768.keyGenerationSeedBytes, (index) => index),
    );
    final keyPair = await backend.keyPairFromSeed(seed);
    final encapsulation = await backend.encapsulate(keyPair.publicKey);
    final decapsulated = await backend.decapsulate(
      keyPair.privateKeyHandle,
      encapsulation.ciphertext,
    );
    expect(decapsulated, orderedEquals(encapsulation.sharedSecret));
    await expectLater(
      backend.encapsulateFromSeed(
        keyPair.publicKey,
        Uint8List(MlKem768.encapsulationSeedBytes),
      ),
      throwsStateError,
    );

    await keyPair.privateKeyHandle.close();
    seed.fillRange(0, seed.length, 0);
    encapsulation.wipeSharedSecret();
    decapsulated.fillRange(0, decapsulated.length, 0);
  }, skip: productionSkipReason);

  test('packaged policy rejects a library containing test-only exports', () {
    expect(
      () => MlKem768FfiBackend.openPackagedLibrary(
        libraryPath: libraryPath!,
      ),
      throwsStateError,
    );
  }, skip: skipReason);

  test('production backend restores the complete 24-word v3 identity vector',
      () async {
    const mnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon abandon abandon art';
    final backend = MlKem768FfiBackend.open(
      libraryPath: productionLibraryPath!,
    );
    final factory = V3LocalIdentityFactory(
      seedService: SeedService(),
      mlKem768Backend: backend,
    );
    final first = await factory.restorePrimary(
      mnemonic: mnemonic,
      displayName: 'Vector identity',
    );
    final restored = await factory.restorePrimary(
      mnemonic: mnemonic,
      displayName: 'Renamed',
    );
    try {
      expect(
        _toHex(first.publicIdentity.x25519PublicKey),
        '63714c686580e067c811207fee91fe01101b62f4c4ce409c88d6b0f83c883a2a',
      );
      expect(
        sha256.convert(first.publicIdentity.mlKem768PublicKey).toString(),
        '23c3e86da0aca0b264a8fce803fc300a3f3be12336f6fb3df06067f2a0b29ef4',
      );
      expect(
        first.publicIdentity.identityId,
        'YJACJCAEX3JH7QSS6ESDJCSBNGOBRTVIZDHK3GQIWDXFL4YJSUPW43QEVE5PEJSYTHMVYHYC4LBOE',
      );
      expect(
        first.publicIdentity.fingerprint,
        'C240-2488-04BE-D27F-C252-F124-348A-4169',
      );
      expect(
          restored.publicIdentity.identityId, first.publicIdentity.identityId);
      expect(
        restored.publicIdentity.mlKem768PublicKey,
        orderedEquals(first.publicIdentity.mlKem768PublicKey),
      );
    } finally {
      await first.close();
      await restored.close();
    }
  }, skip: productionSkipReason);

  test('packaged macOS framework traverses production ABI', () async {
    final backend = MlKem768FfiBackend.openPackagedLibrary(
      libraryPath: packagedMacOSLibraryPath!,
    );
    expect(backend.hasTestHooks, isFalse);
    expect(await backend.selfTest(), isTrue);

    final seed = Uint8List.fromList(
      List<int>.generate(MlKem768.keyGenerationSeedBytes, (index) => index),
    );
    MlKem768KeyPair? keyPair;
    MlKem768Encapsulation? encapsulation;
    Uint8List? decapsulated;
    try {
      keyPair = await backend.keyPairFromSeed(seed);
      encapsulation = await backend.encapsulate(keyPair.publicKey);
      decapsulated = await backend.decapsulate(
        keyPair.privateKeyHandle,
        encapsulation.ciphertext,
      );
      expect(decapsulated, orderedEquals(encapsulation.sharedSecret));
    } finally {
      seed.fillRange(0, seed.length, 0);
      encapsulation?.wipeSharedSecret();
      decapsulated?.fillRange(0, decapsulated.length, 0);
      await keyPair?.privateKeyHandle.close();
    }
  },
      skip: packagedMacOSLibraryPath == null
          ? 'Build and provide the packaged macOS framework'
          : false);
}

Uint8List _hex(String value) {
  final result = Uint8List(value.length ~/ 2);
  for (var index = 0; index < result.length; index++) {
    result[index] = int.parse(
      value.substring(index * 2, index * 2 + 2),
      radix: 16,
    );
  }
  return result;
}

String _toHex(Uint8List value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
