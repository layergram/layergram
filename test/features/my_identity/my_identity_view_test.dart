import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/identity_manager.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/local_identity_vault.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/core/utils/clipboard_service.dart';
import 'package:layergram/features/my_identity/identity_qr_code.dart';
import 'package:layergram/features/my_identity/my_identity_view.dart';
import 'package:layergram/l10n/app_strings.dart';
import 'package:qr_flutter/qr_flutter.dart';

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

class _DelayedSecureStorageService extends _InMemorySecureStorageService {
  final firstRead = Completer<String?>();
  var _delayed = false;

  @override
  Future<String?> read(String key) {
    if (!_delayed) {
      _delayed = true;
      return firstRead.future;
    }
    return super.read(key);
  }
}

class _ThrowingSecureStorageService extends _InMemorySecureStorageService {
  @override
  Future<String?> read(String key) {
    throw StateError('test identity storage failure');
  }
}

class _FailOnceSecureStorageService extends _InMemorySecureStorageService {
  var _failNextRegistryRead = false;

  void failNextRegistryRead() {
    _failNextRegistryRead = true;
  }

  @override
  Future<String?> read(String key) {
    if (_failNextRegistryRead) {
      _failNextRegistryRead = false;
      throw StateError('transient test identity storage failure');
    }
    return super.read(key);
  }
}

class _RecordingClipboardService extends ClipboardService {
  String? lastWritten;

  @override
  Future<void> writeText(String value) async {
    lastWritten = value;
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

  testWidgets('identity loading never exposes the create identity action', (
    tester,
  ) async {
    final storage = _DelayedSecureStorageService();

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(storage),
          protocolV3IdentityEnabledProvider.overrideWithValue(false),
        ],
        child: MaterialApp(
          theme: ThemeData(useMaterial3: true),
          home: const MyIdentityView(),
        ),
      ),
    );
    await tester.pump();

    expect(find.byType(CircularProgressIndicator), findsOneWidget);
    expect(find.text('Create identity'), findsNothing);

    storage.firstRead.complete(null);
    await tester.pumpAndSettle();

    expect(find.text('No active identity'), findsOneWidget);
    expect(find.text('Retry'), findsOneWidget);
    expect(find.text('Create identity'), findsNothing);
  });

  testWidgets('identity load errors are visible and never create an identity', (
    tester,
  ) async {
    final storage = _ThrowingSecureStorageService();

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(storage),
          protocolV3IdentityEnabledProvider.overrideWithValue(false),
        ],
        child: MaterialApp(
          theme: ThemeData(useMaterial3: true),
          home: const MyIdentityView(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('No active identity'), findsOneWidget);
    expect(find.text('Retry'), findsOneWidget);
    expect(find.text('Create identity'), findsNothing);
  });

  testWidgets('retry recovers the existing identity after a transient error', (
    tester,
  ) async {
    final storage = _FailOnceSecureStorageService();
    final manager = IdentityManager(
      seedService: SeedService(),
      localIdentityVault: LocalIdentityVault(secureStorage: storage),
    );
    await manager.restoreIdentityFromMnemonic(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      displayName: 'Alice',
    );
    storage.failNextRegistryRead();

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(storage),
          protocolV3IdentityEnabledProvider.overrideWithValue(false),
        ],
        child: MaterialApp(
          theme: ThemeData(useMaterial3: true),
          home: const MyIdentityView(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('No active identity'), findsOneWidget);
    await tester.tap(find.text('Retry'));
    await tester.pumpAndSettle();

    expect(find.text('Alice'), findsOneWidget);
    expect(find.text('Create identity'), findsNothing);
  });

  testWidgets('identity QR exposes a save/share image action', (tester) async {
    const brightnessChannel = MethodChannel('layergram/screen_brightness');
    final brightnessStates = <bool>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(brightnessChannel, (call) async {
      expect(call.method, 'setQrDisplayActive');
      brightnessStates.add(call.arguments as bool);
      return null;
    });
    addTearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(brightnessChannel, null);
    });

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
          protocolV3IdentityEnabledProvider.overrideWithValue(false),
        ],
        child: MaterialApp(
          theme: ThemeData(useMaterial3: true),
          home: const MyIdentityView(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    final brandedQr = tester.widget<IdentityQrCode>(
      find.byType(IdentityQrCode),
    );
    expect(brandedQr.data, isNotEmpty);

    final qrImage = tester.widget<QrImageView>(find.byType(QrImageView));
    expect(qrImage.errorCorrectionLevel, identityQrErrorCorrectionLevel);
    expect(
      (qrImage.embeddedImage! as AssetImage).assetName,
      identityQrLogoAsset,
    );
    expect(
      qrImage.embeddedImageStyle?.size,
      const Size.square(220 * identityQrLogoScale),
    );

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

    expect(find.byKey(const ValueKey('identity-qr-actions-sheet')), findsOne);
    expect(find.text('Identity QR'), findsNothing);
    expect(find.textContaining('save it to Photos or Files'), findsNothing);
    expect(find.byType(SingleChildScrollView), findsNothing);
    expect(find.byType(IdentityQrCode), findsNWidgets(2));
    expect(find.text('Share or save QR PNG'), findsWidgets);
    expect(
      tester.widget<BottomSheet>(find.byType(BottomSheet)).backgroundColor,
      Colors.white,
    );
    expect(
      tester
          .widgetList<ModalBarrier>(find.byType(ModalBarrier))
          .any((barrier) => barrier.color == Colors.white),
      isTrue,
    );
    expect(brightnessStates, [true]);

    await tester.tapAt(const Offset(4, 4));
    await tester.pumpAndSettle();

    expect(brightnessStates, [true, false]);
    expect(tester.takeException(), isNull);
  });

  testWidgets('complete identity can be copied as direct text', (tester) async {
    final storage = _InMemorySecureStorageService();
    final clipboard = _RecordingClipboardService();
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
          clipboardServiceProvider.overrideWithValue(clipboard),
          protocolV3IdentityEnabledProvider.overrideWithValue(false),
        ],
        child: MaterialApp(
          theme: ThemeData(useMaterial3: true),
          home: const MyIdentityView(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.scrollUntilVisible(
      find.text('Copy identity as text'),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.tap(find.text('Copy identity as text'));
    await tester.pumpAndSettle();

    expect(clipboard.lastWritten, startsWith('[Layergram Identity]'));
    expect(clipboard.lastWritten, contains('Protocol: layergram/'));
    expect(clipboard.lastWritten, contains('[/Layergram Identity]'));
    expect(clipboard.lastWritten, isNot(contains('layergram://')));
    expect(find.text('Identity text copied'), findsOneWidget);
  });

  testWidgets('exported identity QR PNG contains the Layergram logo', (
    tester,
  ) async {
    final result = await tester.runAsync(() async {
      final bytes = await renderIdentityQrPng(
        jsonEncode({
          'type': 'layergram_identity',
          'identityId': 'alice',
          'publicKey': 'test-public-key',
        }),
        pixelSize: 320,
      );
      if (bytes == null || bytes.isEmpty) return null;

      final codec = await ui.instantiateImageCodec(bytes);
      final frame = await codec.getNextFrame();
      final image = frame.image;
      try {
        final rgba = await image.toByteData(format: ui.ImageByteFormat.rawRgba);
        if (rgba == null) return null;

        var brandedPixelCount = 0;
        const centerStart = 128;
        const centerEnd = 192;
        for (var y = centerStart; y < centerEnd; y++) {
          for (var x = centerStart; x < centerEnd; x++) {
            final offset = (y * image.width + x) * 4;
            final red = rgba.getUint8(offset);
            final green = rgba.getUint8(offset + 1);
            final blue = rgba.getUint8(offset + 2);
            final isLayergramCyan =
                blue > 120 && green > 100 && blue > red * 1.5;
            if (isLayergramCyan) {
              brandedPixelCount++;
            }
          }
        }

        return (
          width: image.width,
          height: image.height,
          brandedPixelCount: brandedPixelCount,
        );
      } finally {
        image.dispose();
        codec.dispose();
      }
    });

    expect(result, isNotNull);
    expect(result!.width, 320);
    expect(result.height, 320);
    expect(result.brandedPixelCount, greaterThan(100));
  });
}
