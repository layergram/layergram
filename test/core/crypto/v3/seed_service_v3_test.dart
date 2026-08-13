import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/seed_service.dart';

void main() {
  const mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  late SeedService service;

  setUp(() {
    service = SeedService();
  });

  test('v3 remains disabled as the preferred production derivation', () {
    expect(
      SeedService.preferredIdentityDerivationVersion,
      IdentityDerivationVersion.v2,
    );
  });

  test('v3 derives deterministic full-size X25519 and ML-KEM seeds', () async {
    final seed = service.mnemonicToSeed(mnemonic);
    final first = await service.deriveV3IdentityKeySeeds(seed);
    final second = await service.deriveV3IdentityKeySeeds(seed);

    expect(first.x25519Seed, hasLength(32));
    expect(first.mlKem768KeyGenerationSeed, hasLength(64));
    expect(first.x25519Seed, orderedEquals(second.x25519Seed));
    expect(
      first.mlKem768KeyGenerationSeed,
      orderedEquals(second.mlKem768KeyGenerationSeed),
    );
    expect(
      _toHex(first.x25519Seed),
      'bd40bd09b73e20f72c124ebd6f782a8be94ee11a9d2cdecb60c9697a2e7b6e11',
    );
    expect(
      _toHex(first.mlKem768KeyGenerationSeed),
      'adb82691ed7a3f930f8754a9f546bce2ce745f31582fb9464d6ca530431181d7c8177c5d583637ad480d0dbf5b7f92b0878cbd7a0e901fe698beaff48b34f0ff',
    );
  });

  test('v3 namespaces base and passphrase-derived identities separately',
      () async {
    final seed = service.mnemonicToSeed(mnemonic);
    final base = await service.deriveV3IdentityKeySeeds(seed);
    final passphrase = await service.deriveV3IdentityKeySeeds(
      seed,
      purpose: IdentityDerivationPurpose.passphraseIdentity,
    );

    expect(passphrase.x25519Seed, isNot(orderedEquals(base.x25519Seed)));
    expect(
      passphrase.mlKem768KeyGenerationSeed,
      isNot(orderedEquals(base.mlKem768KeyGenerationSeed)),
    );
  });

  test('v3 X25519 derivation is isolated from v2', () async {
    final seed = service.mnemonicToSeed(mnemonic);
    final v2 = await service.deriveIdentityPrivateKey(
      seed,
      version: IdentityDerivationVersion.v2,
    );
    final v3 = await service.derivePrivateKeyV3(seed);

    expect(v3, isNot(orderedEquals(v2)));
  });

  test('generic private-key API refuses a partial classical-only v3 identity',
      () async {
    final seed = service.mnemonicToSeed(mnemonic);

    await expectLater(
      service.deriveIdentityPrivateKey(
        seed,
        version: IdentityDerivationVersion.v3,
      ),
      throwsUnsupportedError,
    );
    await expectLater(
      service.derivePassphraseIdentityPrivateKey(
        seed,
        version: IdentityDerivationVersion.v3,
      ),
      throwsUnsupportedError,
    );
  });

  test('v3 secret seed buffers support best-effort wipe', () async {
    final seed = service.mnemonicToSeed(mnemonic);
    final material = await service.deriveV3IdentityKeySeeds(seed);

    material.wipe();

    expect(material.x25519Seed, everyElement(0));
    expect(material.mlKem768KeyGenerationSeed, everyElement(0));
  });
}

String _toHex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
