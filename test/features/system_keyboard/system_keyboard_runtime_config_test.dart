import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_runtime_config.dart';

Uint8List identity(int seed) =>
    V3PublicIdentityCodec.encodeBinary(V3PublicIdentity(
        x25519PublicKey: Uint8List(32)..[0] = seed,
        mlKem768PublicKey: Uint8List.fromList(List.filled(1184, seed))));
Map<String, Object?> row() => {
      'identity': identity(11),
      'displayName': 'Contact',
      'mode': 'normal',
      'revision': 1,
      'excludedHandshakeIds': <String>[],
      'maximumRemoteDeviceId': null
    };
Map<String, Object?> config() => {
      'v': 2,
      'publicIdentity': identity(9),
      'identityKeyMaterial': Uint8List(97)..[0] = 1,
      'scopeToken': 'AAAAAAAAAAAAAAAA',
      'localDeviceId': Uint8List.fromList(List.filled(16, 1)),
      'epoch': Uint8List.fromList(List.filled(16, 2)),
      'editorNonce': 'editor',
      'idleMillis': 20000,
      'scramble': false,
      'contacts': [row()]
    };

void main() {
  test('accepts only bounded public metadata and fixed policies', () {
    final value = SystemKeyboardRuntimeConfig.parse(config());
    expect(value.contacts.single.displayName, 'Contact');
    expect(value.idleMillis, 20000);
    expect(value.scopeToken, 'AAAAAAAAAAAAAAAA');
    expect(value.policies.length, 1);
    expect(value.saveHistory, isTrue);
    expect(() => value.contacts.clear(), throwsUnsupportedError);
  });
  test('history preference is explicit, bounded and defaults on for old grants',
      () {
    expect(
        SystemKeyboardRuntimeConfig.parse(config()..['saveHistory'] = false)
            .saveHistory,
        isFalse);
    expect(SystemKeyboardRuntimeConfig.parse(config()).saveHistory, isTrue);
    expect(
        () => SystemKeyboardRuntimeConfig.parse(config()..['saveHistory'] = 1),
        throwsFormatException);
  });
  test('owns a writable copy of immutable platform-channel key material', () {
    final raw = config();
    final original = raw['identityKeyMaterial'] as Uint8List;
    raw['identityKeyMaterial'] = original.asUnmodifiableView();
    final parsed = SystemKeyboardRuntimeConfig.parse(raw);
    expect(parsed.identityKeyMaterial[0], 1);
    expect(
        () => parsed.identityKeyMaterial
            .fillRange(0, parsed.identityKeyMaterial.length, 0),
        returnsNormally);
    expect(original[0], 1);
  });
  test('unknown fields, missing fields and invalid modes deny', () {
    for (final bad in [
      config()..['key'] = 'forbidden',
      config()..['v'] = 1,
      config()..['scopeToken'] = 'keyboard-AAAAAAAAAAAAAAAA',
      config()..['scopeToken'] = 'AAAAAAAAAAAAAAA!',
      config()..['identityKeyMaterial'] = Uint8List(97),
      config()..['identityKeyMaterial'] = (Uint8List(96)..[0] = 1),
      config()..remove('epoch'),
      config()..['idleMillis'] = 0,
      config()..['idleMillis'] = 300001,
      config()..['idleMillis'] = true,
      config()..['scramble'] = 1,
      config()..['epoch'] = Uint8List(16),
      config()..['contacts'] = [],
      config()..['contacts'] = [row()..['mode'] = 'base'],
      config()..['contacts'] = [row(), row()],
      config()..['contacts'] = [row()..['identity'] = identity(9)],
    ]) {
      expect(
          () => SystemKeyboardRuntimeConfig.parse(bad), throwsFormatException);
    }
  });
  test('unbound Maximum is listed while outbound remains policy-gated', () {
    final maximum = row()..['mode'] = 'maximum';
    final parsed = SystemKeyboardRuntimeConfig.parse(
      config()..['contacts'] = [maximum],
    );
    expect(parsed.contacts.single.displayName, 'Contact');
    expect(parsed.policies.values.single.mode, FsSecurityMode.strict);
    expect(parsed.policies.values.single.maximumRemoteDeviceId, isNull);
  });
  test('Maximum accepts a canonical existing device pin only', () {
    final pinned = row()
      ..['mode'] = 'maximum'
      ..['maximumRemoteDeviceId'] =
          base64Url.encode(List.filled(16, 3)).replaceAll('=', '');
    expect(
        SystemKeyboardRuntimeConfig.parse(config()..['contacts'] = [pinned])
            .policies
            .length,
        1);
    for (final bad in [
      'pin',
      base64Url.encode(List.filled(16, 0)).replaceAll('=', '')
    ]) {
      expect(
          () => SystemKeyboardRuntimeConfig.parse(config()
            ..['contacts'] = [
              row()
                ..['mode'] = 'maximum'
                ..['maximumRemoteDeviceId'] = bad
            ]),
          throwsArgumentError);
    }
  });
}
