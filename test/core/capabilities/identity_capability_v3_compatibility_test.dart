import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/capabilities/identity_capability.dart';

void main() {
  test('legacy optional capability profiles remain source compatible', () {
    const profile = IdentityProfile(
      identityId: 'legacy-id',
      displayName: 'Legacy',
      publicKeyBase64: 'legacy-x25519-key',
    );

    expect(profile.publicKeyBase64, 'legacy-x25519-key');
    expect(profile.protocolVersion, isNull);
    expect(profile.publicIdentityBase64, isNull);
  });

  test('v3 profile can expose the complete public bundle additively', () {
    const profile = IdentityProfile(
      identityId: 'v3-id',
      displayName: 'Alice',
      fingerprint: 'AAAA-BBBB',
      protocolVersion: 3,
      publicIdentityBase64: 'complete-v3-public-bundle',
    );

    expect(profile.protocolVersion, 3);
    expect(profile.publicIdentityBase64, 'complete-v3-public-bundle');
  });
}
