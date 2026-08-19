import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/identity_v3_adapter.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/features/identities/identities_controller.dart';

void main() {
  late ProviderContainer container;
  late IdentitiesController controller;
  late V3PublicIdentity identity;

  setUp(() {
    container = ProviderContainer();
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
}
