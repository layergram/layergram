// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/scheduler.dart';
import 'package:flutter/services.dart';

import '../../core/crypto/v3/application_session_runtime_v3.dart';
import '../../core/crypto/seed_service.dart';
import '../../core/crypto/v3/device_key_repository_v3.dart';
import '../../core/crypto/v3/local_identity_v3.dart';
import '../../core/crypto/v3/ml_kem_768_ffi.dart';
import '../../core/crypto/v3/scka_candidate_ffi.dart';
import 'system_keyboard_record_store.dart';
import 'system_keyboard_runtime_config.dart';
import 'system_keyboard_runtime_session.dart';
import 'system_keyboard_v3_backend.dart';

/// Headless services only. No app startup, plugin registrant, Hive, identity
/// vault, network client, rendering surface or FlutterViewController is created.
class _KeyboardServicesBinding extends BindingBase
    with SchedulerBinding, ServicesBinding {}

void runSystemKeyboardRuntime() {
  _KeyboardServicesBinding();
  final runtime = SystemKeyboardRuntimeEntrypoint();
  runtime.install();
}

/// One live engine can consume exactly one native grant. A close, failed start
/// or uncertain durable write is terminal; another start cannot revive it.
final class SystemKeyboardRuntimeEntrypoint {
  SystemKeyboardRuntimeEntrypoint({
    MethodChannel channel = const MethodChannel('layergram/keyboard_runtime'),
  }) : _channel = channel;

  final MethodChannel _channel;
  final Stopwatch _clock = Stopwatch()..start();
  SystemKeyboardRecordStore? _store;
  V3ApplicationSessionRuntime? _runtime;
  V3LocalIdentityHandle? _identity;
  SystemKeyboardV3Backend? _backend;
  SystemKeyboardRuntimeSession? _session;
  bool _consumed = false;
  bool _closed = false;
  Future<void>? _closing;

  void install() {
    _channel.setMethodCallHandler(_handle);
    _channel.invokeMethod<void>('ready').catchError((Object _) {
      _close();
    });
  }

  Future<bool> _check() async {
    if (_closed) return false;
    try {
      final valid = await _channel.invokeMethod<Object?>('check');
      if (valid != true || _closed) {
        _close();
        return false;
      }
      return true;
    } catch (_) {
      _close();
      return false;
    }
  }

  Future<Object?> _handle(MethodCall call) async {
    try {
      switch (call.method) {
        case 'close':
          _close();
          await _closing;
          return null;
        case 'start':
          if (_consumed || _closed) return false;
          _consumed = true;
          final config = SystemKeyboardRuntimeConfig.parse(call.arguments);
          try {
            if (!await _check()) return false;
            final raw = await _channel.invokeMethod<Object?>('load');
            final bytes = raw is Map && raw['snapshot'] is Uint8List
                ? Uint8List.fromList(raw['snapshot'] as Uint8List)
                : null;
            try {
              if (!await _check() ||
                  raw is! Map ||
                  raw.length != 2 ||
                  bytes == null ||
                  raw['revision'] is! int) {
                _close();
                return false;
              }
              _store = SystemKeyboardRecordStore(
                  snapshot: bytes,
                  revision: raw['revision'] as int,
                  commit: (snapshot, revision) async {
                    if (!await _check()) {
                      throw StateError('Keyboard session closed');
                    }
                    final next =
                        await _channel.invokeMethod<Object?>('commit', {
                      'snapshot': snapshot,
                      'revision': revision,
                    });
                    if (!await _check() || next is! int) {
                      throw StateError('Keyboard commit unavailable');
                    }
                    return next;
                  });
            } finally {
              bytes?.fillRange(0, bytes.length, 0);
            }
            final identity = await V3LocalIdentityFactory(
              seedService: SeedService(),
              mlKem768Backend: MlKem768FfiBackend.openPackaged(),
            ).restoreKeyboardSession(
              keyMaterial: config.identityKeyMaterial,
              expectedPublicIdentity: config.publicIdentity,
            );
            _identity = identity;
            if (!_store!.containsKind(V3DeviceKeyRepository.recordKind)) {
              throw StateError('Keyboard installation device key is absent');
            }
            final device =
                await V3DeviceKeyRepository(store: _store!).loadOrCreate();
            final actualDeviceId = device.deviceId;
            var difference = 0;
            for (var index = 0; index < config.localDeviceId.length; index++) {
              difference |= actualDeviceId[index] ^ config.localDeviceId[index];
            }
            if (difference != 0) {
              device.close();
              throw StateError('Keyboard installation device key mismatch');
            }
            late final V3ApplicationSessionRuntime runtime;
            try {
              runtime = await V3ApplicationSessionRuntime
                  .openDelegatedKeyboardSessions(
                localIdentity: identity,
                localDevice: device,
                scopeToken: config.scopeToken,
                store: _store!,
                sckaBackend: V3SckaCandidateFfiBackend.openPackaged(),
                approvedContactPolicies: config.policies,
              );
            } catch (_) {
              device.close();
              rethrow;
            }
            if (!await _check()) {
              await runtime.close();
              return false;
            }
            _runtime = runtime;
            final backend = SystemKeyboardV3Backend(
                runtime: runtime,
                contacts: config.contacts,
                saveHistory: config.saveHistory,
                recordStore: _store,
                handshakeDiagnostic:
                    const bool.fromEnvironment('LAYERGRAM_KEYBOARD_DIAGNOSTICS')
                        ? (category) => unawaited(_channel
                            .invokeMethod<void>(
                                'diagnosticStage', category.name)
                            .then<void>((_) {}, onError: (Object _) {}))
                        : null,
                isAuthorized: () =>
                    !_closed && (_session?.isAuthorized ?? false));
            _backend = backend;
            _session = SystemKeyboardRuntimeSession(
                backend: backend,
                identityId: config.publicIdentity.identityId,
                editorNonce: config.editorNonce,
                authorizedIdleMillis: config.idleMillis,
                monotonicNow: () => _clock.elapsed,
                nativeIsAuthorized: _check,
                scramble: config.scramble);
            return await _check();
          } finally {
            config.identityKeyMaterial
                .fillRange(0, config.identityKeyMaterial.length, 0);
          }
        case 'activity':
          // Invoked only by native physical-touch handling, never by requests.
          if (!await _check()) return false;
          final active = _session?.recordUserInteraction() ?? false;
          if (!active) _close();
          return active;
        case 'rebind':
          final session = _session;
          final arguments = call.arguments;
          if (session == null ||
              arguments is! Map ||
              arguments.length != 1 ||
              arguments['editorNonce'] is! String ||
              !await _check()) {
            _close();
            return false;
          }
          final rebound =
              await session.rebindEditor(arguments['editorNonce'] as String);
          if (!rebound || !await _check()) {
            _close();
            return false;
          }
          return true;
        case 'request':
          final session = _session;
          if (call.arguments is! Map || session == null || !await _check()) {
            return _unavailable;
          }
          final response = await session
              .handleRequest(Map<Object?, Object?>.from(call.arguments as Map));
          if (!await _check() || session.isClosed) {
            _close();
            return _unavailable;
          }
          return response;
        default:
          return _unavailable;
      }
    } catch (_) {
      // Never return error details containing protocol material to the host.
      _close();
      return call.method == 'start' ||
              call.method == 'activity' ||
              call.method == 'rebind'
          ? false
          : _unavailable;
    }
  }

  static const _unavailable = <String, Object?>{'status': 'unavailable'};

  void _close() {
    if (_closed) return;
    _closed = true;
    _session?.close();
    _backend?.close();
    _store?.close();
    _session = null;
    _backend = null;
    _store = null;
    final runtime = _runtime;
    _runtime = null;
    final identity = _identity;
    _identity = null;
    _closing = () async {
      try {
        await runtime?.close();
      } finally {
        await identity?.close();
      }
    }();
    _closing?.catchError((Object _) {});
    _channel.invokeMethod<void>('closed').catchError((Object _) {});
  }
}
