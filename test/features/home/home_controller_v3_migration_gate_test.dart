import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/features/home/home_controller.dart';

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
}
