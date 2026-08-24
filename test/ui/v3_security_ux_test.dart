import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/v3/application_chat_bridge_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/features/home/home_controller.dart';
import 'package:layergram/l10n/app_strings.dart';
import 'package:layergram/l10n/fs_strings_bundle.dart';
import 'package:layergram/ui/v3_contact_security_card.dart';

void main() {
  const contact = RemoteIdentity(
    identityId: 'v3-contact',
    publicKeyBase64: 'public',
    fingerprint: 'fingerprint',
    displayName: 'Alice',
    protocolVersion: 3,
    publicIdentityBase64: 'bundle',
  );

  setUpAll(() {
    AppStrings.registerStrings(FsStringsBundle.bundle);
  });

  testWidgets('v3 contact card exposes only Normal and Maximum modes',
      (tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          protocolV3ContactSecurityStatusProvider.overrideWith(
            (ref, value) async => const V3ChatContactSecurityStatus(
              phase: V3ChatContactSecurityPhase.normalActive,
              selectedMode: V3HandshakeMode.normal,
              activeSessionCount: 2,
              hasSessionsInAnotherMode: false,
            ),
          ),
        ],
        child: const MaterialApp(
          home: Scaffold(
            body: V3ContactSecurityCard(contact: contact),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    final en = FsStringsBundle.bundle['en']!;
    expect(find.text(en['security.fs.v3.card_title']!), findsOneWidget);
    expect(
        find.text(en['security.fs.v3.status.normal_active']!), findsOneWidget);
    expect(find.text('2 active device sessions'), findsOneWidget);
    expect(find.text(en['security.fs.mode.base_title']!), findsNothing);

    await tester.tap(find.text(en['security.fs.action.change_mode']!));
    await tester.pumpAndSettle();

    expect(find.text(en['security.fs.v3.normal_title']!), findsOneWidget);
    expect(find.text(en['security.fs.mode.strict_title']!), findsOneWidget);
    expect(find.text(en['security.fs.mode.base_title']!), findsNothing);
  });

  testWidgets('v3 status button opens the post-quantum security card',
      (tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          protocolV3ContactSecurityStatusProvider.overrideWith(
            (ref, value) async => const V3ChatContactSecurityStatus(
              phase: V3ChatContactSecurityPhase.setupPending,
              selectedMode: V3HandshakeMode.maximum,
              activeSessionCount: 0,
              hasSessionsInAnotherMode: true,
            ),
          ),
        ],
        child: const MaterialApp(
          home: Scaffold(
            body: V3ContactStatusButton(contact: contact, size: 24),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byType(V3ContactStatusButton));
    await tester.pumpAndSettle();

    expect(
      find.text(
        FsStringsBundle.bundle['en']!['security.fs.v3.status.setup_pending']!,
      ),
      findsOneWidget,
    );
  });

  testWidgets('unknown v3 policy is fail-closed and exposes no reset actions',
      (tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          protocolV3ContactSecurityStatusProvider.overrideWith(
            (ref, value) async => throw StateError('unavailable'),
          ),
        ],
        child: const MaterialApp(
          home: Scaffold(body: V3ContactSecurityCard(contact: contact)),
        ),
      ),
    );
    await tester.pumpAndSettle();

    final en = FsStringsBundle.bundle['en']!;
    expect(
      find.text(en['security.fs.status.broken']!),
      findsOneWidget,
    );
    expect(find.text(en['security.fs.action.change_mode']!), findsNothing);
    expect(find.text(en['security.fs.action.reset']!), findsNothing);
  });

  testWidgets('legacy contact card explains that a new v3 identity is needed',
      (tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(body: V3LegacyContactMigrationCard()),
      ),
    );

    final en = FsStringsBundle.bundle['en']!;
    expect(
      find.text(en['security.fs.v3.contact_migration_title']!),
      findsOneWidget,
    );
    expect(
      find.text(en['security.fs.v3.contact_migration_required']!),
      findsOneWidget,
    );
  });
}
