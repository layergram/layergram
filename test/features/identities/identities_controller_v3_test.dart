import 'dart:convert';
import 'dart:typed_data';

import 'package:base32/base32.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/identity_link_codec.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/v3/identity_v3_adapter.dart';
import 'package:layergram/core/crypto/v3/identity_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/features/identities/identities_controller.dart';

void main() {
  late ProviderContainer container;
  late IdentitiesController controller;
  late V3PublicIdentity identity;

  setUp(() {
    container = ProviderContainer(
      overrides: [
        protocolV3IdentityEnabledProvider.overrideWithValue(true),
      ],
    );
    addTearDown(container.dispose);
    controller = container.read(identitiesControllerProvider);
    identity = V3PublicIdentity(
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
    );
  });

  test('inactive v3 migration rejects every v3 import carrier', () {
    final inactive = ProviderContainer();
    addTearDown(inactive.dispose);
    final inactiveController = inactive.read(identitiesControllerProvider);

    expect(
      () => inactiveController.parseIdentityFromText(
        V3IdentityAdapter.encodeShareBlock(identity),
      ),
      throwsA(isA<ProtocolV3IdentityUnavailableException>()),
    );
    expect(
      () => inactiveController.parseIdentityFromLink(
        V3PublicIdentityCodec.encodeLink(identity),
      ),
      throwsA(isA<ProtocolV3IdentityUnavailableException>()),
    );
    expect(
      () => inactiveController.parseIdentityFromQrPayload(
        V3PublicIdentityCodec.encodeBinary(identity),
      ),
      throwsA(isA<ProtocolV3IdentityUnavailableException>()),
    );
  });

  test('imports the same v3 identity from text, link and binary QR', () {
    final fromText = controller.parseIdentityFromText(
      V3IdentityAdapter.encodeShareBlock(identity),
    );
    final fromLink = controller.parseIdentityFromLink(
      V3PublicIdentityCodec.encodeLink(identity),
    );
    final fromQr = controller.parseIdentityFromQrPayload(
      V3PublicIdentityCodec.encodeBinary(identity),
    );

    expect(fromText.identityId, identity.identityId);
    expect(fromLink.identityId, identity.identityId);
    expect(fromQr.identityId, identity.identityId);
    expect(fromQr.protocolVersion, 3);
    expect(fromQr.publicIdentityBase64, fromLink.publicIdentityBase64);
  });

  test('binary QR corruption fails closed', () {
    final binary = V3PublicIdentityCodec.encodeBinary(identity)..[100] ^= 1;
    expect(
      () => controller.parseIdentityFromQrPayload(binary),
      throwsFormatException,
    );
  });

  test('active v3 migration rejects newly imported legacy identities', () {
    final active = ProviderContainer(
      overrides: [
        protocolV3IdentityEnabledProvider.overrideWithValue(true),
      ],
    );
    addTearDown(active.dispose);
    final activeController = active.read(identitiesControllerProvider);
    final legacy = _legacyIdentity();

    expect(
      () => activeController.parseIdentityFromLink(
        IdentityLinkCodec.encode(legacy),
      ),
      throwsA(isA<ProtocolV3IdentityRequiredException>()),
    );
    expect(
      activeController
          .parseIdentityFromLink(
            V3PublicIdentityCodec.encodeLink(identity),
          )
          .protocolVersion,
      3,
    );
  });

  test('invalid ML-KEM public material is rejected before persistence',
      () async {
    final active = ProviderContainer(
      overrides: [
        protocolV3IdentityEnabledProvider.overrideWithValue(true),
        v3IdentityRuntimeProvider.overrideWith((ref) {
          return V3IdentityRuntime(
            seedService: ref.watch(seedServiceProvider),
            backendLoader: () => _RejectingMlKemBackend(),
          );
        }),
      ],
    );
    addTearDown(active.dispose);

    await expectLater(
      active
          .read(identitiesControllerProvider)
          .saveIdentity(V3IdentityAdapter.toRemoteIdentity(identity)),
      throwsFormatException,
    );
  });
}

LocalIdentity _legacyIdentity() {
  final publicKey =
      Uint8List.fromList(List<int>.generate(32, (index) => index + 1));
  final digest = sha256.convert(publicKey).bytes;
  return LocalIdentity(
    identityId: base32.encode(Uint8List.fromList(digest)).replaceAll('=', ''),
    publicKeyBase64: base64Encode(publicKey),
    fingerprint: digest
        .take(8)
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join('-')
        .toUpperCase(),
    displayName: 'Legacy',
    mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );
}

final class _RejectingMlKemBackend implements MlKem768Backend {
  @override
  String get implementationId => 'rejecting-test-backend';

  @override
  Future<bool> selfTest() async => true;

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async => false;

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) =>
      throw UnsupportedError('not used');

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) =>
      throw UnsupportedError('not used');

  @override
  Future<Uint8List> decapsulate(
    MlKem768PrivateKeyHandle privateKeyHandle,
    Uint8List ciphertext,
  ) =>
      throw UnsupportedError('not used');
}
