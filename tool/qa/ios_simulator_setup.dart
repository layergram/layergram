// Copyright 2026 Layergram. Licensed under the Apache License, Version 2.0.
// Temporary simulator UI preparation, never a release or physical-device entry.
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:layergram/core/security/screen_protection_service.dart';
import 'package:layergram/core/storage/secure_storage.dart';
import 'package:layergram/main.dart' as app;

Future<void> main() async {
  if (!kDebugMode || !Platform.isIOS) {
    throw StateError('Simulator UI preparation requires an iOS Debug build');
  }
  const expected = String.fromEnvironment('LAYERGRAM_QA_SIMULATOR_ID');
  final getEnvironment = DynamicLibrary.process().lookupFunction<
      Pointer<Utf8> Function(Pointer<Utf8>),
      Pointer<Utf8> Function(Pointer<Utf8>)>('getenv');
  final name = 'SIMULATOR_UDID'.toNativeUtf8();
  String? actual;
  try {
    final value = getEnvironment(name);
    actual = value == nullptr ? null : value.toDartString();
  } finally {
    calloc.free(name);
  }
  if (expected.isEmpty || actual != expected) {
    throw StateError('Exact disposable CoreSimulator environment is required');
  }
  WidgetsFlutterBinding.ensureInitialized();
  // Makes genuine onboarding/settings controls accessible in the isolated
  // simulator. This does not grant a keyboard session, fake biometrics, touch
  // FS or attest screenshot protection. Physical pair preferences stay intact.
  await ScreenProtectionService(SecureStorageService()).setEnabled(false);
  await app.runLayergramApp();
}

@pragma('vm:entry-point')
void layergramKeyboardMain() => app.layergramKeyboardMain();
