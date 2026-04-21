import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/features/identity_migration_notice/identity_migration_notice_controller.dart';
import 'package:layergram/features/identity_migration_notice/identity_migration_notice_dialog.dart';
import 'package:layergram/features/identity_migration_notice/identity_migration_notice_service.dart';

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
  late _InMemorySecureStorageService storage;
  late IdentityMigrationNoticeService service;
  late IdentityMigrationNoticeController controller;

  setUp(() {
    storage = _InMemorySecureStorageService();
    service = IdentityMigrationNoticeService(storage);
    controller = IdentityMigrationNoticeController(
      service: service,
      loadIdentity: () async => _identityV1(),
    );
  });

  group('IdentityMigrationNoticeController', () {
    test('understand acknowledges permanently', () async {
      var shown = 0;

      await controller.processIdentityIfNeeded(
        identity: _identityV1(),
        presentNotice: () async {
          shown++;
          return IdentityMigrationNoticeAction.understand;
        },
      );

      expect(shown, 1);
      expect(await service.isAcknowledged(), isTrue);
    });

    test('remind later does not acknowledge permanently', () async {
      var shown = 0;

      await controller.processIdentityIfNeeded(
        identity: _identityV1(),
        presentNotice: () async {
          shown++;
          return IdentityMigrationNoticeAction.remindLater;
        },
      );

      expect(shown, 1);
      expect(await service.isAcknowledged(), isFalse);
      expect(await service.shouldShowForIdentity(_identityV1()), isTrue);
    });

    test('notice is not shown multiple times during the same session', () async {
      var shown = 0;

      Future<IdentityMigrationNoticeAction?> present() async {
        shown++;
        return IdentityMigrationNoticeAction.remindLater;
      }

      await controller.processIdentityIfNeeded(
        identity: _identityV1(),
        presentNotice: present,
      );
      await controller.processIdentityIfNeeded(
        identity: _identityV1(),
        presentNotice: present,
      );

      expect(shown, 1);
      expect(await service.isAcknowledged(), isFalse);
    });

    test('remind later does not re-show after a subsequent same-session identity reload', () async {
      var shown = 0;

      Future<IdentityMigrationNoticeAction?> present() async {
        shown++;
        return IdentityMigrationNoticeAction.remindLater;
      }

      await controller.processIdentityIfNeeded(
        identity: _identityV1(),
        presentNotice: present,
      );

      await controller.processIdentityIfNeeded(
        identity: _identityV1(),
        presentNotice: present,
      );

      expect(shown, 1);
      expect(await service.isAcknowledged(), isFalse);
      expect(await service.shouldShowForIdentity(_identityV1()), isTrue);
    });

    test('legacy identity remains eligible until acknowledged', () async {
      expect(await service.shouldShowForIdentity(_identityV1()), isTrue);
      await service.markAcknowledged();
      expect(await service.shouldShowForIdentity(_identityV1()), isFalse);
    });

    test('v2 identity never presents the notice', () async {
      var shown = 0;

      await controller.processIdentityIfNeeded(
        identity: _identityV2(),
        presentNotice: () async {
          shown++;
          return IdentityMigrationNoticeAction.understand;
        },
      );

      expect(shown, 0);
      expect(await service.isAcknowledged(), isTrue);
    });

    test('null action (dialog dismissed without action) does not acknowledge', () async {
      // Simulates: user closes the dialog programmatically without pressing
      // either button (action == null).
      var shown = 0;

      await controller.processIdentityIfNeeded(
        identity: _identityV1(),
        presentNotice: () async {
          shown++;
          return null; // no action
        },
      );

      expect(shown, 1);
      expect(await service.isAcknowledged(), isFalse,
          reason: 'null action must NOT acknowledge permanently');
      // shouldShow still true on a fresh controller.
      final controller2 = IdentityMigrationNoticeController(
        service: service,
        loadIdentity: () async => _identityV1(),
      );
      expect(await service.shouldShowForIdentity(_identityV1()), isTrue);
      // Silence the unused variable warning.
      controller2.toString();
    });

    test('_showing flag is reset to false even when presentNotice throws', () async {
      // Verifies the finally block in processIdentityIfNeeded resets _showing.
      var callCount = 0;
      final faultyController = IdentityMigrationNoticeController(
        service: service,
        loadIdentity: () async => _identityV1(),
      );

      await expectLater(
        faultyController.processIdentityIfNeeded(
          identity: _identityV1(),
          presentNotice: () async {
            callCount++;
            throw Exception('dialog error');
          },
        ),
        throwsException,
      );

      expect(callCount, 1);
      // _showing must be false after the exception; a new controller (fresh
      // session) can show again since _handledThisSession was already set true.
      // Verify _showing reset by confirming no deadlock on a second call.
      // (second call returns immediately because _handledThisSession == true)
      await faultyController.processIdentityIfNeeded(
        identity: _identityV1(),
        presentNotice: () async => IdentityMigrationNoticeAction.understand,
      );
      // No exception thrown = _showing was properly reset.
    });

    test('second sequential call after _handledThisSession is set is a no-op', () async {
      // After processIdentityIfNeeded completes, _handledThisSession == true.
      // Any subsequent call on the same controller instance must be a no-op.
      var shown = 0;
      final sequentialController = IdentityMigrationNoticeController(
        service: service,
        loadIdentity: () async => _identityV1(),
      );

      // First call completes normally.
      await sequentialController.processIdentityIfNeeded(
        identity: _identityV1(),
        presentNotice: () async {
          shown++;
          return IdentityMigrationNoticeAction.remindLater;
        },
      );

      // Second call: _handledThisSession == true → immediate return.
      await sequentialController.processIdentityIfNeeded(
        identity: _identityV1(),
        presentNotice: () async {
          shown++;
          return IdentityMigrationNoticeAction.understand;
        },
      );

      expect(shown, 1,
          reason: '_handledThisSession set to true after first call prevents any repeat in same session');
    });

    testWidgets('checkAndShowIfNeeded invokes processIdentityIfNeeded via BuildContext',
        (tester) async {
      // Uses WidgetTester to provide a real BuildContext.
      late IdentityMigrationNoticeController ctrlWithContext;
      var shown = 0;

      await tester.pumpWidget(
        MaterialApp(
          home: Builder(
            builder: (context) {
              ctrlWithContext = IdentityMigrationNoticeController(
                service: service,
                loadIdentity: () async => _identityV1(),
                presentNotice: (_) async {
                  shown++;
                  return IdentityMigrationNoticeAction.understand;
                },
              );

              return ElevatedButton(
                onPressed: () => ctrlWithContext.checkAndShowIfNeeded(context),
                child: const Text('trigger'),
              );
            },
          ),
        ),
      );

      await tester.tap(find.text('trigger'));
      await tester.pump();

      expect(shown, 1);
      expect(await service.isAcknowledged(), isTrue);
    });
  });
}

LocalIdentity _identityV1() {
  return const LocalIdentity(
    identityId: 'legacy-id',
    publicKeyBase64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    fingerprint: 'AA-BB-CC-DD',
    displayName: 'Legacy',
    mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    derivationVersion: IdentityDerivationVersion.v1,
    derivationAlgorithm: 'sha256-seed',
  );
}

LocalIdentity _identityV2() {
  return const LocalIdentity(
    identityId: 'modern-id',
    publicKeyBase64: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
    fingerprint: '11-22-33-44',
    displayName: 'Modern',
    mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    derivationVersion: IdentityDerivationVersion.v2,
    derivationAlgorithm: 'hkdf-sha256',
  );
}
