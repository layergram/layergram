import 'dart:io';
import 'dart:typed_data';

import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768_ffi.dart';

Future<void> main() async {
  try {
    final explicitLibraryPath =
        Platform.environment['LAYERGRAM_MLKEM_PACKAGED_MACOS_LIBRARY'];
    final backend = explicitLibraryPath == null
        ? MlKem768FfiBackend.openPackaged()
        : MlKem768FfiBackend.openPackagedLibrary(
            libraryPath: explicitLibraryPath,
          );
    if (backend.hasTestHooks || !await backend.selfTest()) {
      throw StateError('Packaged ML-KEM production self-test failed');
    }

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

      if (!_constantTimeEquals(decapsulated, encapsulation.sharedSecret)) {
        throw StateError(
          'Packaged ML-KEM round trip produced different secrets',
        );
      }
    } finally {
      seed.fillRange(0, seed.length, 0);
      encapsulation?.wipeSharedSecret();
      decapsulated?.fillRange(0, decapsulated.length, 0);
      await keyPair?.privateKeyHandle.close();
    }
    stdout.writeln('LAYERGRAM_MLKEM_PACKAGED_SMOKE_OK');
    exit(0);
  } catch (error, stackTrace) {
    stderr.writeln(error);
    stderr.writeln(stackTrace);
    exit(1);
  }
}

bool _constantTimeEquals(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
