import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';

void main() {
  const mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  late SeedService service;

  setUp(() {
    service = SeedService();
  });

  group('SeedService', () {
    test('derivePrivateKeyV1 reproduces the legacy sha256(seed) output exactly', () {
      final seed = service.mnemonicToSeed(mnemonic);
      final derived = service.derivePrivateKeyV1(seed);

      expect(
        _toHex(derived),
        '62a772f85e4be6226108b56c0b1cf935c2490e434adec864fe47b189f1ed517d',
      );
    });

    test('derivePrivateKeyV2 is deterministic for the same seed and purpose', () async {
      final seed = service.mnemonicToSeed(mnemonic);

      final first = await service.deriveIdentityPrivateKey(
        seed,
        version: IdentityDerivationVersion.v2,
      );
      final second = await service.deriveIdentityPrivateKey(
        seed,
        version: IdentityDerivationVersion.v2,
      );

      expect(_toHex(first), _toHex(second));
    });

    test('v1 and v2 identity derivations differ for the same seed', () async {
      final seed = service.mnemonicToSeed(mnemonic);

      final v1 = service.derivePrivateKeyV1(seed);
      final v2 = await service.deriveIdentityPrivateKey(
        seed,
        version: IdentityDerivationVersion.v2,
      );

      expect(_toHex(v2), isNot(_toHex(v1)));
    });

    test('v2 identity and passphrase derivations use distinct namespaces', () async {
      final seed = service.mnemonicToSeed(mnemonic);

      final identityV2 = await service.deriveIdentityPrivateKey(
        seed,
        version: IdentityDerivationVersion.v2,
      );
      final passphraseV2 = await service.derivePassphraseIdentityPrivateKey(
        seed,
        version: IdentityDerivationVersion.v2,
      );

      expect(_toHex(passphraseV2), isNot(_toHex(identityV2)));
    });

    test('legacy v1 passphrase and identity derivations remain identical', () async {
      final seed = service.mnemonicToSeed(mnemonic);

      final identityV1 = await service.deriveIdentityPrivateKey(
        seed,
        version: IdentityDerivationVersion.v1,
      );
      final passphraseV1 = await service.derivePassphraseIdentityPrivateKey(
        seed,
        version: IdentityDerivationVersion.v1,
      );

      expect(_toHex(passphraseV1), _toHex(identityV1));
    });
  });
}

String _toHex(List<int> bytes) {
  return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
}
