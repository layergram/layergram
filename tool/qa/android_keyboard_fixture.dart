// Disposable Android fixture. No user identity, archive, network or plugins.
import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'package:flutter/foundation.dart';
import 'package:flutter/scheduler.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:layergram/core/crypto/seed_service.dart';
import 'package:layergram/core/crypto/v3/application_session_runtime_v3.dart';
import 'package:layergram/core/crypto/v3/device_key_repository_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768_ffi.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/core/crypto/v3/scka_candidate_ffi.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_record_store.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_runtime_config.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_runtime_entry.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_runtime_session.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_v3_backend.dart';

final _aliceMnemonic = [
  ...List<String>.filled(11, 'abandon'),
  'about',
].join(' ');
final _bobMnemonic = [
  ...List<String>.filled(11, 'zoo'),
  'wrong',
].join(' ');

void main() => runApp(const Directionality(
    textDirection: TextDirection.ltr,
    child: Center(child: Text('Keyboard validation fixture'))));
@pragma('vm:entry-point')
void layergramKeyboardMain() => runSystemKeyboardRuntime();

class _Binding extends BindingBase with SchedulerBinding, ServicesBinding {}

@pragma('vm:entry-point')
void layergramKeyboardValidationMain() {
  _Binding();
  final fixture = _Fixture();
  fixture.channel.setMethodCallHandler(fixture.handle);
  fixture.channel.invokeMethod<void>('ready');
}

class _Fixture {
  final channel = const MethodChannel('layergram/keyboard_validation');
  var key = Uint8List.fromList(
      List.generate(32, (_) => Random.secure().nextInt(256)));
  var epoch = Uint8List.fromList(
      List.generate(16, (_) => Random.secure().nextInt(256)));
  V3LocalIdentityHandle? alice;
  V3LocalIdentityHandle? bob;
  Uint8List? deviceId;
  Uint8List? snapshot;
  SystemKeyboardRuntimeSession? remote;
  SystemKeyboardRecordStore? remoteRecords;

  SystemKeyboardRecordStore store([Uint8List? persisted]) =>
      SystemKeyboardRecordStore(
        snapshot: persisted ??
            SystemKeyboardRecordSnapshot.encode(const <V3LmfStoredRecord>[]),
        revision: 0,
        commit: (_, revision) async => revision + 1,
      );

  Future<Object?> handle(MethodCall call) async {
    if (call.method == 'request' &&
        (call.arguments as Map)['operation'] == 'delegate') {
      return handle(
          MethodCall('grant', (call.arguments as Map)['editorNonce']));
    }
    if (call.method == 'remoteRebind') {
      return remote!.rebindEditor(call.arguments as String);
    }
    if (call.method == 'exportRemoteSnapshot') {
      return SystemKeyboardRecordSnapshot.encode(
          await remoteRecords!.readAll());
    }
    if (call.method == 'initialize') {
      // Coarse, non-secret milestones locate device-specific startup stalls.
      debugPrint('QA_KEYBOARD_INITIALIZE:begin');
      final persisted = call.arguments as Map<Object?, Object?>?;
      if (persisted != null) {
        epoch = persisted['epoch'] as Uint8List;
        key = persisted['key'] as Uint8List;
      }
      final factory = V3LocalIdentityFactory(
          seedService: SeedService(),
          mlKem768Backend: MlKem768FfiBackend.openPackaged());
      debugPrint('QA_KEYBOARD_INITIALIZE:alice');
      alice = await factory.restorePrimary(mnemonic: _aliceMnemonic);
      debugPrint('QA_KEYBOARD_INITIALIZE:bob');
      bob = await factory.restorePrimary(mnemonic: _bobMnemonic);
      debugPrint('QA_KEYBOARD_INITIALIZE:localDevice');
      final localStore = store(persisted?['snapshot'] as Uint8List?);
      final localDevice =
          await V3DeviceKeyRepository(store: localStore).loadOrCreate();
      deviceId = localDevice.deviceId;
      snapshot =
          SystemKeyboardRecordSnapshot.encode(await localStore.readAll());
      localDevice.close();
      localStore.close();
      final remoteStore = store(persisted?['remoteSnapshot'] as Uint8List?);
      remoteRecords = remoteStore;
      final remoteDevice =
          await V3DeviceKeyRepository(store: remoteStore).loadOrCreate();
      final config = SystemKeyboardRuntimeConfig.parse(configFor(bob!, alice!,
          remoteDevice.deviceId, 'qa-remote-000001', 'remote-editor'));
      debugPrint('QA_KEYBOARD_INITIALIZE:remoteRuntime');
      final runtime =
          await V3ApplicationSessionRuntime.openDelegatedKeyboardSessions(
              localIdentity: bob!,
              localDevice: remoteDevice,
              scopeToken: config.scopeToken,
              store: remoteStore,
              sckaBackend: V3SckaCandidateFfiBackend.openPackaged(),
              approvedContactPolicies: config.policies);
      final backend = SystemKeyboardV3Backend(
          runtime: runtime,
          contacts: config.contacts,
          recordStore: remoteStore,
          isAuthorized: () => true);
      final clock = Stopwatch()..start();
      remote = SystemKeyboardRuntimeSession(
          backend: backend,
          identityId: bob!.publicIdentity.identityId,
          editorNonce: 'remote-editor',
          authorizedIdleMillis: 300000,
          monotonicNow: () => clock.elapsed,
          nativeIsAuthorized: () async => true);
      debugPrint('QA_KEYBOARD_INITIALIZE:ready');
      return {
        'epoch': epoch,
        'key': key,
        'snapshot': snapshot,
        'contactId': bob!.publicIdentity.identityId,
        'remoteContactId': alice!.publicIdentity.identityId
      };
    }
    if (call.method == 'grant') {
      final config = configFor(alice!, bob!, deviceId!, 'qa-local-0000001',
          call.arguments as String);
      // The app owner's one-shot grant uses the same Base64 channel contract.
      for (final name in [
        'epoch',
        'localDeviceId',
        'publicIdentity',
        'identityKeyMaterial'
      ]) {
        config[name] = base64Encode(config[name] as Uint8List);
      }
      final rows = config['contacts'] as List<Map<String, Object?>>;
      rows.first['identity'] =
          base64Encode(rows.first['identity'] as Uint8List);
      config['biometricResume'] = false;
      return {
        'status': 'ok',
        'mode': 'autonomous-v1',
        'key': base64Encode(key),
        'configuration': config
      };
    }
    if (call.method == 'remote') {
      remote!.recordUserInteraction();
      return remote!
          .handleRequest(Map<Object?, Object?>.from(call.arguments as Map));
    }
    throw PlatformException(code: 'fixtureInvalidOperation');
  }

  Map<String, Object?> configFor(
          V3LocalIdentityHandle own,
          V3LocalIdentityHandle peer,
          Uint8List device,
          String scope,
          String nonce) =>
      {
        'v': 2,
        'publicIdentity':
            V3PublicIdentityCodec.encodeBinary(own.publicIdentity),
        'identityKeyMaterial': own.exportKeyboardKeyMaterial(),
        'localDeviceId': device,
        'scopeToken': scope,
        'epoch': epoch,
        'editorNonce': nonce,
        'idleMillis': 300000,
        'scramble': false,
        'saveHistory': true,
        'contacts': [
          {
            'identity': V3PublicIdentityCodec.encodeBinary(peer.publicIdentity),
            'displayName': 'Peer',
            'mode': 'normal',
            'revision': 0,
            'excludedHandshakeIds': <String>[],
            'maximumRemoteDeviceId': null
          }
        ],
      };
}
