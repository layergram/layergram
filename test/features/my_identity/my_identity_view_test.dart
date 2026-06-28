import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/identity_manager.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/local_identity_vault.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/features/my_identity/my_identity_view.dart';
import 'package:layergram/l10n/app_strings.dart';

class _InMemorySecureStorageService extends SecureStorageService {
  final Map<String, String> _values = <String, String>{};

  @override
  Future<void> write(String key, String value) async {
    _values[key] = value;
  }

  @override
  Future<String?> read(String key) async {
    return _values[key];
  }

  @override
  Future<void> delete(String key) async {
    _values.remove(key);
  }

  @override
  Future<void> deleteAll() async {
    _values.clear();
  }
}

void main() {
  setUpAll(() {
    final strings = jsonDecode(
      File('assets/translations/en.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    AppStrings.registerStrings({
      'en': strings.map((key, value) => MapEntry(key, value as String)),
    });
  });

  testWidgets('identity QR exposes a save/share image action', (tester) async {
    final storage = _InMemorySecureStorageService();
    final vault = LocalIdentityVault(secureStorage: storage);
    final manager = IdentityManager(
      seedService: SeedService(),
      localIdentityVault: vault,
    );
    await manager.restoreIdentityFromMnemonic(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      displayName: 'Alice',
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(storage),
        ],
        child: MaterialApp(
          theme: ThemeData(useMaterial3: true),
          home: const MyIdentityView(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.scrollUntilVisible(
      find.text('Share or save QR PNG'),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.ensureVisible(find.text('Share or save QR PNG'));
    await tester.pumpAndSettle();
    expect(find.text('Share or save QR PNG'), findsOneWidget);

    await tester.tap(find.text('Share or save QR PNG'));
    await tester.pumpAndSettle();

    expect(find.text('Identity QR'), findsOneWidget);
    expect(
      find.textContaining('save it to Photos or Files'),
      findsOneWidget,
    );
    expect(find.text('Share or save QR PNG'), findsWidgets);
    expect(tester.takeException(), isNull);
  });
}
