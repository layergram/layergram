import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/features/identity_migration_notice/identity_migration_notice_controller.dart';
import 'package:layergram/features/identity_migration_notice/identity_migration_notice_service.dart';

class _InMemorySecureStorageService extends SecureStorageService {
  final Map<String, String> values = <String, String>{};

  @override
  Future<void> write(String key, String value) async => values[key] = value;

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> delete(String key) async => values.remove(key);

  @override
  Future<void> deleteAll() async => values.clear();
}

void main() {
  late IdentityMigrationNoticeService service;
  late IdentityMigrationNoticeController controller;

  setUp(() {
    service = IdentityMigrationNoticeService(
      _InMemorySecureStorageService(),
      isFeatureEnabled: () => true,
    );
    controller = IdentityMigrationNoticeController(
      service: service,
      loadIdentity: () async => _identityV2(),
    );
  });

  test('acknowledged presentation is shown once for the same identity',
      () async {
    var shown = 0;
    Future<bool> present() async {
      shown++;
      return true;
    }

    await controller.processIdentityIfNeeded(
      identity: _identityV2(),
      presentNotice: present,
    );
    await controller.processIdentityIfNeeded(
      identity: _identityV2(),
      presentNotice: present,
    );

    expect(shown, 1);
    expect(await service.isAcknowledged(), isTrue);
  });

  test('later choice remains pending', () async {
    var shown = 0;
    Future<bool> present() async {
      shown++;
      return false;
    }

    await controller.processIdentityIfNeeded(
      identity: _identityV2(),
      presentNotice: present,
    );
    await controller.processIdentityIfNeeded(
      identity: _identityV2(),
      presentNotice: present,
    );

    expect(shown, 2);
    expect(await service.isAcknowledged(), isFalse);
  });

  testWidgets('checkAndShowIfNeeded uses the supplied presenter',
      (tester) async {
    late IdentityMigrationNoticeController widgetController;
    var shown = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) {
            widgetController = IdentityMigrationNoticeController(
              service: service,
              loadIdentity: () async => _identityV2(),
              presentNotice: (_) async {
                shown++;
                return true;
              },
            );
            return ElevatedButton(
              onPressed: () => widgetController.checkAndShowIfNeeded(context),
              child: const Text('trigger'),
            );
          },
        ),
      ),
    );

    await tester.tap(find.text('trigger'));
    await tester.pumpAndSettle();

    expect(shown, 1);
    expect(await service.isAcknowledged(), isTrue);
  });
}

LocalIdentity _identityV2() => const LocalIdentity(
      identityId: 'modern-id',
      publicKeyBase64: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
      fingerprint: '11-22-33-44',
      displayName: 'Modern',
      mnemonic:
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      derivationVersion: IdentityDerivationVersion.v2,
      derivationAlgorithm: 'hkdf-sha256',
    );
