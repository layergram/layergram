import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Architectural boundary checks for the optional SYSTEM keyboard native surface.
///
/// The native files are scanned only after comments are stripped, so an
/// explanatory comment can never satisfy (or trip) a rule. `commitText` is
/// additionally pinned to the single encrypted-carrier call shape: the test
/// fails if any plaintext value could reach the host editor.
void main() {
  final root = Directory.current;

  String read(String relativePath) {
    final file = File('${root.path}/$relativePath');
    expect(
      file.existsSync(),
      isTrue,
      reason: 'Expected native SYSTEM keyboard file to exist: $relativePath',
    );
    return file.readAsStringSync();
  }

  String readCode(String relativePath) => _stripComments(read(relativePath));

  group('manifest', () {
    late String manifest;
    late String serviceBlock;

    setUpAll(() {
      manifest = read('android/app/src/main/AndroidManifest.xml');
      final start = manifest.indexOf('<service');
      final end = manifest.indexOf('</service>', start);
      expect(start, greaterThanOrEqualTo(0),
          reason: 'No <service> entry found.');
      expect(end, greaterThan(start), reason: 'Unterminated <service> entry.');
      serviceBlock = manifest.substring(start, end);
    });

    test('IME service is permission bound, exported and disabled by default',
        () {
      expect(serviceBlock,
          contains('android:name=".LayergramInputMethodService"'));
      expect(serviceBlock, contains('android:exported="true"'));
      expect(
        serviceBlock,
        contains('android:permission="android.permission.BIND_INPUT_METHOD"'),
      );
      expect(
        serviceBlock,
        contains('android:enabled="false"'),
        reason:
            'The IME component must stay disabled until an explicit app opt-in.',
      );
      expect(serviceBlock,
          contains('<action android:name="android.view.InputMethod"'));
      expect(serviceBlock, contains('android:name="android.view.im"'));
      expect(serviceBlock,
          contains('android:resource="@xml/layergram_input_method"'));
    });

    test('service and application stay in the default app process', () {
      expect(
        serviceBlock.contains('android:process'),
        isFalse,
        reason: 'The IME must run in the app default process.',
      );
      expect(
        manifest.contains('android:process='),
        isFalse,
        reason: 'No component may be moved to another process.',
      );
    });

    test('input-method descriptor does not add a new activity or process', () {
      final descriptor =
          read('android/app/src/main/res/xml/layergram_input_method.xml');
      expect(descriptor, contains('<input-method'));
      expect(descriptor,
          contains('android:supportsSwitchingToNextInputMethod="true"'));
      expect(descriptor, isNot(contains('<activity')));
    });
  });

  group('main activity hook', () {
    test(
        'binds the broker channel to the existing engine and unbinds that owner',
        () {
      final activity =
          readCode('android/app/src/main/kotlin/app/layergram/MainActivity.kt');
      expect(activity, contains('SystemKeyboardBroker.CHANNEL_NAME'));
      expect(activity, contains('SystemKeyboardBroker.bindEngine('));
      expect(activity, contains('cleanUpFlutterEngine'));
      expect(activity,
          contains('SystemKeyboardBroker.unbindEngine(flutterEngine)'));
    });
  });

  group('native sources stay local, engine-free and plaintext-free', () {
    final nativeFiles = <String>[
      'android/app/src/main/kotlin/app/layergram/LayergramInputMethodService.kt',
      'android/app/src/main/kotlin/app/layergram/SystemKeyboardBroker.kt',
      'android/app/src/main/kotlin/app/layergram/KeyboardEditorLease.kt',
    ];

    test('no new engine, key material, database or network access', () {
      const forbidden = <String>[
        'FlutterEngine(',
        'FlutterEngineGroup',
        'SecretKey',
        'KeyStore',
        'PrivateKey',
        'KeyGenerator',
        'KeyPair',
        'javax.crypto',
        'SQLiteOpenHelper',
        'openOrCreateDatabase',
        'getDatabasePath',
        'java.net.',
        'HttpURLConnection',
        'okhttp',
        'Socket(',
        'android.util.Log',
        'System.out',
      ];
      final findings = <String>[];
      for (final path in nativeFiles) {
        final code = readCode(path);
        for (final token in forbidden) {
          if (code.contains(token)) {
            findings.add('$path: $token');
          }
        }
      }
      expect(findings, isEmpty, reason: findings.join('\n'));
    });

    test('never reads host surrounding text, composes, or observes clipboard',
        () {
      const forbidden = <String>[
        'setComposingText',
        'getTextBeforeCursor',
        'getTextAfterCursor',
        'getSelectedText',
        'getSurroundingText',
        'getExtractedText',
        'startExtractingText',
        'coerceToText',
        'addPrimaryClipChangedListener',
        'EditText',
        'onExtractedTextClicked',
      ];
      final findings = <String>[];
      for (final path in nativeFiles) {
        final code = readCode(path);
        for (final token in forbidden) {
          if (code.contains(token)) {
            findings.add('$path: $token');
          }
        }
      }
      expect(findings, isEmpty, reason: findings.join('\n'));
    });

    test('commitText is only ever called with the encrypted carrier', () {
      final service = readCode(
        'android/app/src/main/kotlin/app/layergram/LayergramInputMethodService.kt',
      );
      final commitCalls =
          RegExp(r'commitText\(([^)]*)\)').allMatches(service).toList();
      expect(
        commitCalls,
        isNotEmpty,
        reason: 'The service must perform the single encrypted host insert.',
      );
      for (final call in commitCalls) {
        final arguments = call.group(1)!.replaceAll(' ', '');
        expect(
          arguments,
          'export.carrier,1',
          reason: 'Only the authorized encrypted carrier may be committed.',
        );
      }
      for (final plaintext in <String>[
        'draft',
        'carrierBuffer',
        'selectedContact'
      ]) {
        expect(
          service.contains('commitText($plaintext'),
          isFalse,
          reason: 'Plaintext value "$plaintext" must never reach commitText.',
        );
      }
    });

    test('broker strictly denies malformed grants instead of clamping', () {
      final broker = readCode(
          'android/app/src/main/kotlin/app/layergram/SystemKeyboardBroker.kt');
      expect(broker, contains('strictGrant('));
      expect(
        broker.contains('coerceIn('),
        isFalse,
        reason:
            'A malformed processing/lease value must be denied, never clamped.',
      );
    });

    test('service disables fullscreen extraction and host text learning', () {
      final service = readCode(
        'android/app/src/main/kotlin/app/layergram/LayergramInputMethodService.kt',
      );
      expect(
        service,
        contains('override fun onEvaluateFullscreenMode(): Boolean = false'),
      );
      expect(service, contains('override fun onUpdateExtractingVisibility'));
      expect(service, contains('setExtractViewShown(false)'));
      expect(
          service, contains('IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS'));
      expect(service, contains('admitsOutboundCarrierLength('));
    });

    test('password variation mirror matches the Android SDK values', () {
      final policy = readCode(
        'android/app/src/main/kotlin/app/layergram/KeyboardEditorLease.kt',
      );
      expect(
          policy, contains('INPUT_TYPE_TEXT_VARIATION_PASSWORD = 0x00000080'));
      expect(
        policy,
        contains('INPUT_TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090'),
      );
      expect(policy,
          contains('INPUT_TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x000000e0'));
      expect(policy, contains('INPUT_TYPE_TEXT_VARIATION_URI = 0x00000010'));
    });
  });
}

/// Removes block and line comments so rules only ever match real code.
String _stripComments(String source) {
  final withoutBlocks = source.replaceAll(RegExp(r'/\*[\s\S]*?\*/'), ' ');
  final buffer = StringBuffer();
  for (final line in withoutBlocks.split('\n')) {
    buffer.writeln(_stripLineComment(line));
  }
  return buffer.toString();
}

String _stripLineComment(String line) {
  var inString = false;
  for (var index = 0; index < line.length - 1; index += 1) {
    final char = line[index];
    if (char == '\\') {
      index += 1;
      continue;
    }
    if (char == '"' || char == "'") {
      inString = !inString;
      continue;
    }
    if (!inString && char == '/' && line[index + 1] == '/') {
      return line.substring(0, index);
    }
  }
  return line;
}
