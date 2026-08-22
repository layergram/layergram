import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/features/home/home_controller.dart';

import 'dart:typed_data';

void main() {
  test('active v3 runtime blocks new sends to a legacy contact', () async {
    final container = ProviderContainer(
      overrides: [
        protocolV3MessagingEnabledProvider.overrideWithValue(true),
      ],
    );
    addTearDown(container.dispose);
    const legacy = RemoteIdentity(
      identityId: 'legacy-contact',
      publicKeyBase64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      fingerprint: 'AA-BB-CC-DD',
      displayName: 'Legacy',
    );

    await expectLater(
      container.read(homeControllerProvider).encryptForRecipient(
            secretText: 'must not use v2 after migration',
            recipient: legacy,
          ),
      throwsA(isA<ProtocolV3ContactMigrationRequiredException>()),
    );
  });

  test('active v3 runtime blocks the legacy composer for a v3 contact',
      () async {
    final container = ProviderContainer(
      overrides: [
        protocolV3MessagingEnabledProvider.overrideWithValue(true),
      ],
    );
    addTearDown(container.dispose);
    final identity = V3PublicIdentity(
      x25519PublicKey: Uint8List.fromList(
        List<int>.generate(32, (index) => index + 1),
      ),
      mlKem768PublicKey: Uint8List.fromList(
        List<int>.generate(
          MlKem768.publicKeyBytes,
          (index) => (index % 251) + 1,
        ),
      ),
      displayName: 'V3 contact',
    );
    final contact = RemoteIdentity(
      identityId: identity.identityId,
      publicKeyBase64: '',
      fingerprint: identity.fingerprint,
      displayName: identity.displayName,
      protocolVersion: V3PublicIdentityCodec.protocolVersion,
      publicIdentityBase64: V3PublicIdentityCodec.encodeToken(identity),
    );

    await expectLater(
      container.read(homeControllerProvider).encryptForRecipient(
            secretText: 'must use the v3 application bridge',
            recipient: contact,
          ),
      throwsA(isA<ProtocolV3OutboundRequiredException>()),
    );
  });
}
