// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_app_backend.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_app_service.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_controller.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_custody.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_custody_coordinator.dart';

const SystemKeyboardContact _alice = SystemKeyboardContact(
  id: 'c-alice',
  name: 'Alice',
  fingerprint: 'FP-ALICE',
);

class _TestClock {
  Duration now = Duration.zero;

  Duration call() => now;

  void advance(Duration delta) {
    now += delta;
  }
}

class _OwnerState {
  bool lockStateReady = true;
  bool needsUnlock = false;
  String? ordinaryIdentityId = 'id-1';
  bool passphraseActive = false;
  bool ordinaryKeyTagReady = true;

  /// Number of times the owner state was actually sampled. A no-op counter used
  /// to prove that a disabled request never initializes identity-adjacent
  /// providers.
  int samples = 0;

  SystemKeyboardOwnerState snapshot() {
    samples++;
    return SystemKeyboardOwnerState(
      lockStateReady: lockStateReady,
      needsUnlock: needsUnlock,
      ordinaryIdentityId: ordinaryIdentityId,
      passphraseActive: passphraseActive,
      ordinaryKeyTagReady: ordinaryKeyTagReady,
    );
  }
}

class _FakeNativeChannel implements SystemKeyboardNativeChannel {
  SystemKeyboardChannelRequestHandler? handler;
  int configureCalls = 0;
  final List<bool> configureRequests = <bool>[];
  int revokeCalls = 0;
  int openSettingsCalls = 0;
  bool configureResult = true;
  bool persistedEnabled = true;
  Future<void> Function(bool)? beforeConfigure;

  /// When set, every `configure` call blocks until it completes.
  Completer<void>? configureBarrier;

  @override
  void setRequestHandler(SystemKeyboardChannelRequestHandler? next) {
    handler = next;
  }

  @override
  Future<bool> readEnabled() async => persistedEnabled;

  @override
  Future<bool> configure({required bool enabled}) async {
    configureCalls++;
    configureRequests.add(enabled);
    final Completer<void>? barrier = configureBarrier;
    if (barrier != null) await barrier.future;
    await beforeConfigure?.call(enabled);
    if (configureResult) persistedEnabled = enabled;
    return configureResult;
  }

  @override
  Future<void> revoke() async {
    revokeCalls++;
  }

  @override
  Future<bool> openSettings() async {
    openSettingsCalls++;
    return true;
  }
}

class _FakeOptInStore implements SystemKeyboardOptInStore {
  bool value = false;
  bool failRead = false;
  bool failWrite = false;
  int writes = 0;
  Future<void> Function(bool)? beforeWrite;

  /// When set, reads/writes block until the barrier completes.
  Completer<void>? readBarrier;
  Completer<void>? writeBarrier;

  @override
  Future<bool> read() async {
    final Completer<void>? barrier = readBarrier;
    if (barrier != null) await barrier.future;
    if (failRead) throw StateError('read failed');
    return value;
  }

  @override
  Future<void> write(bool next) async {
    writes++;
    final Completer<void>? barrier = writeBarrier;
    if (barrier != null) await barrier.future;
    await beforeWrite?.call(next);
    if (failWrite) throw StateError('write failed');
    value = next;
  }
}

class _UnusedCustodyNative implements SystemKeyboardCustodyNative {
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('No native custody operation expected in this test');
}

class _RecordingBackend
    implements SystemKeyboardBackend, SystemKeyboardSessionScopedBackend {
  int listCalls = 0;
  int prepareCalls = 0;
  int decodeCalls = 0;
  int markCalls = 0;
  int clearCalls = 0;

  List<SystemKeyboardContact> contacts = const <SystemKeyboardContact>[_alice];
  SystemKeyboardBackendExport? export = const SystemKeyboardBackendExport(
    exportHandle: 'handle-1',
    carriers: <String>['carrier-1'],
    ciphertextCodeUnits: 9,
  );
  SystemKeyboardBackendDecoded? decoded;
  Completer<void>? listBarrier;
  Completer<void>? prepareBarrier;

  @override
  Future<List<SystemKeyboardContact>> listApprovedContacts() async {
    listCalls++;
    final Completer<void>? barrier = listBarrier;
    if (barrier != null) await barrier.future;
    return contacts;
  }

  @override
  Future<SystemKeyboardBackendExport?> prepareTextOutbound(
    SystemKeyboardOutboundRequest request,
  ) async {
    prepareCalls++;
    final Completer<void>? barrier = prepareBarrier;
    if (barrier != null) await barrier.future;
    return export;
  }

  @override
  Future<void> markExported(String exportHandle) async {
    markCalls++;
  }

  @override
  Future<SystemKeyboardBackendDecoded?> decodeCarrier(String carrier) async {
    decodeCalls++;
    return decoded;
  }

  @override
  void clearSessionHandles() {
    clearCalls++;
  }
}

class _Harness {
  _Harness({
    required this.service,
    required this.clock,
    required this.owner,
    required this.channel,
    required this.store,
    required this.backend,
  });

  final SystemKeyboardAppService service;
  final _TestClock clock;
  final _OwnerState owner;
  final _FakeNativeChannel channel;
  final _FakeOptInStore store;
  final _RecordingBackend backend;

  int _requestCounter = 0;

  Future<Map<String, Object?>> request(
    String operation, {
    String nonce = 'ed-1',
    Map<String, Object?> extra = const <String, Object?>{},
  }) {
    return service.handleChannelRequest(<String, Object?>{
      'operation': operation,
      'editorNonce': nonce,
      'requestId': 'req-${_requestCounter++}',
      ...extra,
    });
  }
}

_Harness _buildHarness({
  bool optIn = true,
  bool failRead = false,
  bool failWrite = false,
  bool platformSupported = true,
  bool featureFlagEnabled = true,
  bool configureResult = true,
  Duration? maximumBackgroundDuration,
  Future<int?> Function()? readIdlePreference,
  Future<void> Function(int)? writeIdlePreference,
  Future<bool?> Function()? readScramblePreference,
  Future<void> Function(bool)? writeScramblePreference,
  Future<bool> Function()? readSaveHistoryPreference,
  Future<void> Function(bool)? writeSaveHistoryPreference,
  Future<bool> Function()? readBiometricResumePreference,
  Future<void> Function(bool)? writeBiometricResumePreference,
}) {
  final _TestClock clock = _TestClock();
  final _OwnerState owner = _OwnerState();
  final _FakeNativeChannel channel = _FakeNativeChannel()
    ..configureResult = configureResult;
  final _FakeOptInStore store = _FakeOptInStore()
    ..value = optIn
    ..failRead = failRead
    ..failWrite = failWrite;
  final _RecordingBackend backend = _RecordingBackend();
  final SystemKeyboardAppService service = SystemKeyboardAppService(
    nativeChannel: channel,
    optInStore: store,
    platformSupported: platformSupported,
    featureFlagEnabled: featureFlagEnabled,
    ownerState: owner.snapshot,
    readScramble: () => false,
    monotonicNow: clock.call,
    observeLifecycle: false,
    maximumBackgroundDuration: maximumBackgroundDuration,
    readIdlePreference: readIdlePreference,
    writeIdlePreference: writeIdlePreference,
    readScramblePreference: readScramblePreference,
    writeScramblePreference: writeScramblePreference,
    readSaveHistoryPreference: readSaveHistoryPreference,
    writeSaveHistoryPreference: writeSaveHistoryPreference,
    readBiometricResumePreference: readBiometricResumePreference,
    writeBiometricResumePreference: writeBiometricResumePreference,
  );
  service.attachBackend(backend);
  return _Harness(
    service: service,
    clock: clock,
    owner: owner,
    channel: channel,
    store: store,
    backend: backend,
  );
}

String _status(Map<String, Object?> reply) => reply['status']! as String;

Map<Object?, Object?> _data(Map<String, Object?> reply) =>
    reply['data']! as Map<Object?, Object?>;

Future<void> _tick() => Future<void>.delayed(Duration.zero);

/// Asserts a generic failure reply: non-ok and no `data` payload at all.
void _expectNoData(Map<String, Object?> reply) {
  expect(reply['status'], isNot(SystemKeyboardChannelStatus.ok));
  expect(reply.containsKey('data'), isFalse);
  expect(reply.containsKey('processingMillis'), isFalse);
  expect(reply.containsKey('leaseMillis'), isFalse);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
      'foreground warming requires ordinary unlocked consent and never delegates',
      () async {
    final h =
        _buildHarness(maximumBackgroundDuration: const Duration(seconds: 20));
    var warms = 0;
    var preparations = 0;
    h.service.attachAutonomousCustody(
      SystemKeyboardCustodyCoordinator(native: _UnusedCustodyNative()),
      (_, __, ___) async {
        preparations++;
      },
      () {},
      warm: () {
        warms++;
      },
    );
    h.owner.needsUnlock = true;
    await h.service.start();
    expect(warms, 0);
    h.owner.needsUnlock = false;
    h.service.onAppNeedsUnlockChanged(false);
    expect(warms, 1);
    h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
    expect(warms, 1);
    h.service.onAppLifecycleChanged(AppLifecycleState.resumed);
    expect(warms, 2);
    h.owner.passphraseActive = true;
    h.service.onOwnerStateChanged();
    expect(warms, 2);
    h.owner.passphraseActive = false;
    h.owner.ordinaryKeyTagReady = false;
    h.service.onOwnerStateChanged();
    expect(warms, 2);
    h.owner.ordinaryKeyTagReady = true;
    h.service.noteAppLockRequested();
    expect(warms, 2);
    h.service.onAppNeedsUnlockChanged(false);
    expect(warms, 3);
    await h.service.setEnabled(false);
    h.service.onAppLifecycleChanged(AppLifecycleState.resumed);
    expect(warms, 3);
    expect(preparations, 0);
    h.service.dispose();
  });

  test('departure alone never delegates, and request starts preparation once',
      () async {
    final h = _buildHarness(
      maximumBackgroundDuration: const Duration(seconds: 30),
    );
    await h.service.start();
    final preparation = Completer<void>();
    var attempts = 0;
    h.service.attachAutonomousCustody(
      SystemKeyboardCustodyCoordinator(native: _UnusedCustodyNative()),
      (_, __, ___) {
        attempts++;
        return preparation.future;
      },
      () {},
    );

    h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
    h.service.onAppLifecycleChanged(AppLifecycleState.paused);
    expect(attempts, 0);
    expect(
        _status(await h.request('delegate')), SystemKeyboardChannelStatus.busy);
    expect(attempts, 1);
    expect(
        _status(await h.request('delegate')), SystemKeyboardChannelStatus.busy);
    expect(attempts, 1);

    preparation.complete();
    await _tick();
    expect(_status(await h.request('delegate')),
        SystemKeyboardChannelStatus.unavailable);
  });

  test('fresh foreground visit permits a new autonomous preparation', () async {
    final h = _buildHarness(
      maximumBackgroundDuration: const Duration(seconds: 30),
    );
    await h.service.start();
    final first = Completer<void>();
    final second = Completer<void>();
    var attempts = 0;
    h.service.attachAutonomousCustody(
      SystemKeyboardCustodyCoordinator(native: _UnusedCustodyNative()),
      (_, __, ___) {
        attempts++;
        return attempts == 1 ? first.future : second.future;
      },
      () {},
    );

    h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
    expect(attempts, 0);
    expect(
        _status(await h.request('delegate')), SystemKeyboardChannelStatus.busy);
    expect(attempts, 1);
    first.complete();
    await _tick();
    expect(_status(await h.request('delegate')),
        SystemKeyboardChannelStatus.unavailable);

    h.service.onAppLifecycleChanged(AppLifecycleState.resumed);
    h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
    expect(attempts, 1);
    expect(
        _status(await h.request('delegate')), SystemKeyboardChannelStatus.busy);
    expect(attempts, 2);
    second.complete();
    await _tick();
  });

  test('foreground delegate request cannot trigger a custody transfer',
      () async {
    final h = _buildHarness();
    await h.service.start();
    var attempts = 0;
    h.service.attachAutonomousCustody(
      SystemKeyboardCustodyCoordinator(native: _UnusedCustodyNative()),
      (_, __, ___) async {
        attempts++;
      },
      () {},
    );
    expect(_status(await h.request('delegate')),
        SystemKeyboardChannelStatus.unavailable);
    expect(attempts, 0);
  });

  test('an update-like departure and return leaves V3 custody private',
      () async {
    final h = _buildHarness(
      maximumBackgroundDuration: const Duration(seconds: 30),
    );
    await h.service.start();
    var attempts = 0;
    h.service.attachAutonomousCustody(
      SystemKeyboardCustodyCoordinator(native: _UnusedCustodyNative()),
      (_, __, ___) async {
        attempts++;
      },
      () {},
    );
    h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
    h.service.onAppLifecycleChanged(AppLifecycleState.paused);
    h.service.onAppLifecycleChanged(AppLifecycleState.resumed);
    expect(attempts, 0);
    h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
    expect(attempts, 0);
    expect(
        _status(await h.request('delegate')), SystemKeyboardChannelStatus.busy);
    expect(attempts, 1);
    await _tick();
  });

  group('admission gate', () {
    test('feature disabled configures native off and never reads the backend',
        () async {
      final _Harness h = _buildHarness(featureFlagEnabled: false);
      await h.service.start();

      expect(h.service.isEnabled, isFalse);
      expect(h.channel.configureRequests, contains(false));
      expect(h.channel.handler, isNull);

      final Map<String, Object?> reply = await h.request('begin');
      expect(_status(reply), SystemKeyboardChannelStatus.unavailable);
      expect(h.backend.listCalls, 0);
      expect(h.backend.prepareCalls, 0);
    });

    test('unsupported platform configures nothing and denies', () async {
      final _Harness h = _buildHarness(platformSupported: false);
      await h.service.start();

      expect(h.service.isEnabled, isFalse);
      expect(h.channel.configureCalls, 0);
      expect(
        _status(await h.request('begin')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
    });

    test('missing consent denies before the handler exists', () async {
      final _Harness h = _buildHarness(optIn: false);
      await h.service.start();

      expect(h.service.isEnabled, isFalse);
      expect(h.channel.configureRequests, contains(false));
      expect(h.channel.configureRequests, isNot(contains(true)));
      expect(
        _status(await h.request('begin')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
    });

    test('consent read failure defaults to disabled', () async {
      final _Harness h = _buildHarness(optIn: true, failRead: true);
      await h.service.start();

      expect(h.service.isEnabled, isFalse);
      expect(h.channel.configureRequests, isNot(contains(true)));
      expect(
        _status(await h.request('begin')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
    });

    test('native configure refusal keeps admission denied', () async {
      final _Harness h = _buildHarness(optIn: true, configureResult: false);
      await h.service.start();

      expect(h.service.isEnabled, isFalse);
      expect(
        _status(await h.request('begin')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
    });

    test('lock state not ready revokes and denies without a backend read',
        () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);

      h.owner.lockStateReady = false;
      expect(
        _status(await h.request('contacts')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
    });

    test('locked owner revokes and denies without a backend read', () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);

      h.owner.needsUnlock = true;
      expect(
        _status(await h.request('contacts')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
    });

    test('active passphrase revokes and denies without a backend read',
        () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);

      h.owner.passphraseActive = true;
      expect(
        _status(await h.request('contacts')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
    });

    test('missing ordinary keyTag revokes and denies without a backend read',
        () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);

      h.owner.ordinaryKeyTagReady = false;
      expect(
        _status(await h.request('contacts')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
    });

    test('a disabled request never samples the owner state', () async {
      final _Harness h = _buildHarness(optIn: false);
      await h.service.start();
      final int samples = h.owner.samples;

      final Map<String, Object?> begin = await h.request('begin');
      expect(_status(begin), SystemKeyboardChannelStatus.unavailable);
      _expectNoData(begin);
      final Map<String, Object?> contacts = await h.request('contacts');
      expect(_status(contacts), SystemKeyboardChannelStatus.unavailable);
      _expectNoData(contacts);
      expect(h.owner.samples, samples);
      expect(h.backend.listCalls, 0);
    });

    test('a refused native configure never samples the owner state', () async {
      final _Harness h = _buildHarness(optIn: true, configureResult: false);
      await h.service.start();
      final int samples = h.owner.samples;

      final Map<String, Object?> begin = await h.request('begin');
      expect(_status(begin), SystemKeyboardChannelStatus.unavailable);
      _expectNoData(begin);
      expect(h.owner.samples, samples);
      expect(h.backend.listCalls, 0);
    });

    test('the guard re-evaluates every owner flag without a notification',
        () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      final int generation = h.service.generation;
      expect(h.service.ordinaryIdentityId, 'id-1');
      expect(h.service.admits(generation, 'id-1'), isTrue);

      // No provider event and no onOwnerStateChanged call: only the live owner
      // snapshot changes.
      h.owner.lockStateReady = false;
      expect(h.service.admits(generation, 'id-1'), isFalse);

      h.owner.lockStateReady = true;
      h.owner.needsUnlock = true;
      expect(h.service.admits(generation, 'id-1'), isFalse);

      h.owner.needsUnlock = false;
      h.owner.passphraseActive = true;
      expect(h.service.admits(generation, 'id-1'), isFalse);

      h.owner.passphraseActive = false;
      h.owner.ordinaryKeyTagReady = false;
      expect(h.service.admits(generation, 'id-1'), isFalse);
      expect(h.service.admits(generation, 'id-2'), isFalse);
      expect(h.service.admits(generation + 1, 'id-1'), isFalse);
    });
  });

  group('channel operations', () {
    test('begin, contacts, explicit select, compose, authorize and ack',
        () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      expect(h.channel.handler, isNotNull);

      final Map<String, Object?> begin = await h.request('begin');
      expect(_status(begin), SystemKeyboardChannelStatus.ok);
      expect(_data(begin)['scramble'], isFalse);
      expect(_data(begin)['idleMillis'], 60000);
      expect(begin['processingMillis'], isA<int>());
      expect(
        begin['processingMillis']! as int,
        inInclusiveRange(0, 30000),
      );
      expect(begin['leaseMillis']! as int, inInclusiveRange(1, 1000));

      final Map<String, Object?> heartbeat = await h.request('heartbeat');
      expect(_status(heartbeat), SystemKeyboardChannelStatus.ok);
      expect(heartbeat['processingMillis'], 0);

      final Map<String, Object?> contacts = await h.request('contacts');
      expect(_status(contacts), SystemKeyboardChannelStatus.ok);
      expect(
        (_data(contacts)['contacts']! as List<Object?>).length,
        1,
      );
      expect(h.backend.listCalls, 1);

      final Map<String, Object?> select = await h.request(
        'select',
        extra: <String, Object?>{'contactId': 'c-alice', 'confirm': true},
      );
      expect(_status(select), SystemKeyboardChannelStatus.ok);
      expect(_data(select)['id'], 'c-alice');
      expect(_data(select)['fingerprint'], 'FP-ALICE');

      final Map<String, Object?> prepare = await h.request(
        'prepare',
        extra: <String, Object?>{'text': 'hello'},
      );
      expect(_status(prepare), SystemKeyboardChannelStatus.ok);
      final String pendingId = _data(prepare)['pendingId']! as String;
      expect(h.backend.prepareCalls, 1);

      final Map<String, Object?> authorize = await h.request(
        'authorize',
        extra: <String, Object?>{'pendingId': pendingId},
      );
      expect(_status(authorize), SystemKeyboardChannelStatus.ok);
      expect(_data(authorize)['carrier'], 'carrier-1');

      final Map<String, Object?> ack = await h.request(
        'ack',
        extra: <String, Object?>{'pendingId': pendingId, 'commitText': true},
      );
      expect(_status(ack), SystemKeyboardChannelStatus.ok);
      expect(_data(ack)['exported'], isTrue);
      expect(h.backend.markCalls, 1);
    });

    test('select without confirmation is rejected', () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      await h.request('begin');

      final Map<String, Object?> reply = await h.request(
        'select',
        extra: <String, Object?>{'contactId': 'c-alice', 'confirm': false},
      );
      expect(_status(reply), SystemKeyboardChannelStatus.invalidSelection);
    });

    test('ack with a failed host insert never reports exported', () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      await h.request('begin');
      await h.request(
        'select',
        extra: <String, Object?>{'contactId': 'c-alice', 'confirm': true},
      );
      final Map<String, Object?> prepare = await h.request(
        'prepare',
        extra: <String, Object?>{'text': 'hello'},
      );
      final String pendingId = _data(prepare)['pendingId']! as String;
      await h.request(
        'authorize',
        extra: <String, Object?>{'pendingId': pendingId},
      );
      final Map<String, Object?> ack = await h.request(
        'ack',
        extra: <String, Object?>{'pendingId': pendingId, 'commitText': false},
      );
      expect(_status(ack), SystemKeyboardChannelStatus.ok);
      expect(_data(ack)['exported'], isFalse);
      expect(h.backend.markCalls, 0);
    });

    test('malformed requests are rejected without touching the backend',
        () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      await h.request('begin');

      expect(
        _status(await h.service.handleChannelRequest(
          <String, Object?>{'editorNonce': 'ed-1', 'requestId': 'r-x'},
        )),
        SystemKeyboardChannelStatus.invalidRequest,
      );
      expect(
        _status(await h.service.handleChannelRequest(<String, Object?>{
          'operation': 'contacts',
          'editorNonce': 'x' * 129,
          'requestId': 'r-y',
        })),
        SystemKeyboardChannelStatus.invalidRequest,
      );
      expect(
        _status(await h.request(
          'prepare',
          extra: <String, Object?>{'text': 42},
        )),
        SystemKeyboardChannelStatus.invalidRequest,
      );
      expect(
        _status(await h.request('unknown')),
        SystemKeyboardChannelStatus.invalidRequest,
      );
      expect(h.backend.listCalls, 0);
      expect(h.backend.prepareCalls, 0);
    });

    test('an unauthenticated carrier yields no preview and no data', () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      await h.request('begin');

      // The backend returns no authenticated message.
      final Map<String, Object?> reply = await h.request(
        'decode',
        extra: <String, Object?>{'carrier': 'not-a-carrier'},
      );
      expect(_status(reply), SystemKeyboardChannelStatus.noMessage);
      _expectNoData(reply);
      expect(h.backend.decodeCalls, 1);
    });
  });

  group('editor generation', () {
    test(
        'stale callbacks are rejected and an old end cannot close a newer '
        'editor', () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      expect(_status(await h.request('begin', nonce: 'ed-1')),
          SystemKeyboardChannelStatus.ok);
      expect(_status(await h.request('begin', nonce: 'ed-2')),
          SystemKeyboardChannelStatus.ok);

      expect(
        _status(await h.request('heartbeat', nonce: 'ed-1')),
        SystemKeyboardChannelStatus.unavailable,
      );
      _expectNoData(await h.request('heartbeat', nonce: 'ed-1'));
      expect(
        _status(await h.request('contacts', nonce: 'ed-1')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(
        _status(await h.request('end', nonce: 'ed-1')),
        SystemKeyboardChannelStatus.unavailable,
      );
      // The newer editor survived the stale end.
      expect(
        _status(await h.request('heartbeat', nonce: 'ed-2')),
        SystemKeyboardChannelStatus.ok,
      );
      expect(
        _status(await h.request('end', nonce: 'ed-2')),
        SystemKeyboardChannelStatus.ok,
      );
      expect(
        _status(await h.request('heartbeat', nonce: 'ed-2')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
    });
  });

  group('background deadline', () {
    test('iOS requests wait for observed departure and obey immediate lock',
        () async {
      final _Harness h = _buildHarness(
        maximumBackgroundDuration: const Duration(seconds: 20),
      );
      await h.service.start();
      expect(h.service.isEnabled, isTrue);
      _expectNoData(await h.request('begin'));
      expect(h.owner.samples, 0);
      h.service.seedAppLockConfig(enabled: true, timeoutSeconds: 0);
      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      _expectNoData(await h.request('begin'));
      expect(h.backend.listCalls, 0);
    });

    test('iOS window expires with app lock disabled and cannot be renewed',
        () async {
      final _Harness h = _buildHarness(
        maximumBackgroundDuration: const Duration(seconds: 20),
      );
      await h.service.start();
      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
      h.clock.advance(const Duration(seconds: 19));
      h.service.onAppLifecycleChanged(AppLifecycleState.paused);
      h.service.onAppLockConfigChanged(enabled: false, timeoutSeconds: 60);
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
      h.clock.advance(const Duration(seconds: 1));
      _expectNoData(await h.request('heartbeat'));
      _expectNoData(await h.request('begin'));
      expect(h.service.admits(h.service.generation, 'id-1'), isFalse);
      // Even an unlock notification cannot renew the platform window.
      h.service.onAppNeedsUnlockChanged(false);
      _expectNoData(await h.request('begin'));
      h.service.onAppLifecycleChanged(AppLifecycleState.resumed);
      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
    });

    test('shorter app lock wins over the iOS maximum window', () async {
      final _Harness h = _buildHarness(
        maximumBackgroundDuration: const Duration(seconds: 20),
      );
      h.service.seedAppLockConfig(enabled: true, timeoutSeconds: 2);
      await h.service.start();
      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
      h.clock.advance(const Duration(seconds: 2));
      _expectNoData(await h.request('heartbeat'));
    });

    test('iOS expiry suppresses an in-flight owner reply', () async {
      final _Harness h = _buildHarness(
        maximumBackgroundDuration: const Duration(seconds: 20),
      );
      await h.service.start();
      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
      h.backend.listBarrier = Completer<void>();
      final Future<Map<String, Object?>> pending = h.request('contacts');
      await _tick();
      h.clock.advance(const Duration(seconds: 20));
      h.backend.listBarrier!.complete();
      _expectNoData(await pending);
    });

    test('inactive then paused never extends the recorded background instant',
        () async {
      final _Harness h = _buildHarness();
      h.service.onAppLockConfigChanged(enabled: true, timeoutSeconds: 60);
      await h.service.start();

      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
      h.clock.advance(const Duration(seconds: 10));
      h.service.onAppLifecycleChanged(AppLifecycleState.paused);

      h.clock.advance(const Duration(seconds: 45));
      expect(
        _status(await h.request('heartbeat')),
        SystemKeyboardChannelStatus.ok,
      );

      h.clock.advance(const Duration(seconds: 10));
      expect(
        _status(await h.request('heartbeat')),
        SystemKeyboardChannelStatus.unavailable,
      );
    });

    test('zero timeout denies immediately once backgrounded', () async {
      final _Harness h = _buildHarness();
      h.service.onAppLockConfigChanged(enabled: true, timeoutSeconds: 0);
      await h.service.start();
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);

      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      expect(
        _status(await h.request('heartbeat')),
        SystemKeyboardChannelStatus.unavailable,
      );
    });

    test('time advance while the Dart timer would be suspended denies',
        () async {
      final _Harness h = _buildHarness();
      h.service.onAppLockConfigChanged(enabled: true, timeoutSeconds: 30);
      await h.service.start();
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);

      h.service.onAppLifecycleChanged(AppLifecycleState.paused);
      h.clock.advance(const Duration(seconds: 31));
      expect(
        _status(await h.request('contacts')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
    });

    test('a heartbeat never renews the authorization deadline', () async {
      final _Harness h = _buildHarness();
      h.service.onAppLockConfigChanged(enabled: true, timeoutSeconds: 10);
      await h.service.start();
      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);

      h.clock.advance(const Duration(seconds: 5));
      expect(
        _status(await h.request('heartbeat')),
        SystemKeyboardChannelStatus.ok,
      );

      h.clock.advance(const Duration(seconds: 5));
      expect(
        _status(await h.request('heartbeat')),
        SystemKeyboardChannelStatus.unavailable,
      );
    });

    test('resume fully revokes and requires a fresh begin', () async {
      final _Harness h = _buildHarness();
      h.service.onAppLockConfigChanged(enabled: true, timeoutSeconds: 10);
      await h.service.start();
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
      final int generation = h.service.generation;
      final int revokes = h.channel.revokeCalls;
      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      h.service.onAppLifecycleChanged(AppLifecycleState.resumed);

      // Resume is a full revocation: generation bumped, native revoked, the
      // previous generation no longer admissible.
      expect(h.service.generation, greaterThan(generation));
      expect(h.channel.revokeCalls, greaterThan(revokes));
      expect(h.service.admits(generation, 'id-1'), isFalse);
      _expectNoData(await h.request('heartbeat'));
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
    });

    test('detached denies and revokes immediately', () async {
      final _Harness h = _buildHarness();
      h.service.onAppLockConfigChanged(enabled: true, timeoutSeconds: 60);
      await h.service.start();
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);

      h.service.onAppLifecycleChanged(AppLifecycleState.detached);
      _expectNoData(await h.request('heartbeat'));
      expect(h.service.admits(h.service.generation, 'id-1'), isFalse);
    });

    test('the guard denies past the monotonic deadline with no provider event',
        () async {
      final _Harness h = _buildHarness();
      h.service.onAppLockConfigChanged(enabled: true, timeoutSeconds: 60);
      await h.service.start();
      final int generation = h.service.generation;
      expect(h.service.admits(generation, 'id-1'), isTrue);

      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      h.clock.advance(const Duration(seconds: 59));
      expect(h.service.admits(generation, 'id-1'), isTrue);
      // No provider notification and no lifecycle call: only the clock moved.
      h.clock.advance(const Duration(seconds: 2));
      expect(h.service.admits(generation, 'id-1'), isFalse);
    });
  });

  group('in-flight revocation', () {
    test('a synchronous lock request suppresses an in-flight reply', () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      await h.request('begin');

      final Completer<void> barrier = Completer<void>();
      h.backend.listBarrier = barrier;
      final Future<Map<String, Object?>> pending = h.request('contacts');
      await _tick();
      expect(h.backend.listCalls, 1);

      h.service.noteAppLockRequested();
      barrier.complete();
      expect(
        _status(await pending),
        SystemKeyboardChannelStatus.unavailable,
      );
    });

    test('identity away-and-back suppresses an in-flight reply', () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      await h.request('begin');

      final Completer<void> barrier = Completer<void>();
      h.backend.listBarrier = barrier;
      final Future<Map<String, Object?>> pending = h.request('contacts');
      await _tick();
      expect(h.backend.listCalls, 1);

      h.owner.ordinaryIdentityId = 'id-2';
      h.service.onOwnerStateChanged();
      h.owner.ordinaryIdentityId = 'id-1';
      h.service.onOwnerStateChanged();
      barrier.complete();
      final Map<String, Object?> reply = await pending;
      expect(_status(reply), SystemKeyboardChannelStatus.unavailable);
      _expectNoData(reply);
    });

    test(
        'a full lock timeout during a prepared backend await suppresses the '
        'reply', () async {
      final _Harness h = _buildHarness();
      h.service.onAppLockConfigChanged(enabled: true, timeoutSeconds: 5);
      await h.service.start();
      await h.request('begin');
      await h.request(
        'select',
        extra: <String, Object?>{'contactId': 'c-alice', 'confirm': true},
      );

      final Completer<void> barrier = Completer<void>();
      h.backend.prepareBarrier = barrier;
      final Future<Map<String, Object?>> pending = h.request(
        'prepare',
        extra: <String, Object?>{'text': 'hello'},
      );
      await _tick();
      expect(h.backend.prepareCalls, 1);

      // The grant lapses while the backend is still preparing and no provider
      // notification ever fires.
      h.service.onAppLifecycleChanged(AppLifecycleState.inactive);
      h.clock.advance(const Duration(seconds: 6));
      barrier.complete();

      final Map<String, Object?> reply = await pending;
      expect(_status(reply), SystemKeyboardChannelStatus.unavailable);
      _expectNoData(reply);
    });

    test('an owner change revokes the session until a new begin', () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      await h.request('begin');

      h.service.onOwnerStateChanged();
      expect(
        _status(await h.request('heartbeat')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(
        _status(await h.request('contacts')),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(h.backend.listCalls, 0);
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
    });
  });

  group('settings and lifecycle', () {
    test('enable persists the preference and configures native on', () async {
      final _Harness h = _buildHarness(optIn: false);
      await h.service.start();
      expect(h.service.isEnabled, isFalse);

      expect(await h.service.setEnabled(true), isTrue);
      expect(h.service.isEnabled, isTrue);
      expect(h.store.value, isTrue);
      expect(h.channel.configureRequests, contains(true));
    });

    test('enable persists first and stays disabled on write failure', () async {
      final _Harness h = _buildHarness(optIn: false, failWrite: true);
      await h.service.start();

      expect(await h.service.setEnabled(true), isFalse);
      expect(h.service.isEnabled, isFalse);
      expect(h.channel.configureRequests, isNot(contains(true)));
    });

    test('disable revokes before persistence and stays disabled', () async {
      final _Harness h = _buildHarness(optIn: true);
      await h.service.start();
      expect(h.service.isEnabled, isTrue);
      await h.request('begin');

      h.store.failWrite = true;
      expect(await h.service.setEnabled(false), isFalse);
      expect(h.service.isEnabled, isFalse);
      expect(h.channel.configureRequests.last, isFalse);
      expect(
        _status(await h.request('heartbeat')),
        SystemKeyboardChannelStatus.unavailable,
      );
    });

    test('failed secure opt-out cannot revive the keyboard on restart',
        () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      h.store.failWrite = true;
      await h.service.setEnabled(false);
      expect(h.store.value, isTrue);
      expect(h.channel.persistedEnabled, isFalse);
      h.service.dispose();

      final SystemKeyboardAppService restarted = SystemKeyboardAppService(
        nativeChannel: h.channel,
        optInStore: h.store,
        platformSupported: true,
        featureFlagEnabled: true,
        ownerState: h.owner.snapshot,
        readScramble: () => false,
        monotonicNow: h.clock.call,
        observeLifecycle: false,
      )..attachBackend(h.backend);
      addTearDown(restarted.dispose);
      await restarted.start();
      expect(restarted.isEnabled, isFalse);
      expect(h.channel.persistedEnabled, isFalse);
      expect(h.backend.listCalls, 0);
    });

    test('only an old enable write blocks; newer disable remains durable',
        () async {
      final _Harness h = _buildHarness(optIn: false);
      await h.service.start();
      final Completer<void> oldWrite = Completer<void>();
      final List<bool> enteredWrites = <bool>[];
      h.store.beforeWrite = (bool value) async {
        enteredWrites.add(value);
        if (value) await oldWrite.future;
      };
      final Future<bool> first = h.service.setEnabled(true);
      await _tick();
      final Future<bool> second = h.service.setEnabled(false);
      await _tick();
      expect(h.service.isEnabled, isFalse);
      expect(h.channel.persistedEnabled, isFalse);
      expect(enteredWrites, <bool>[true]);
      oldWrite.complete();
      expect(await first, isFalse);
      await second;
      expect(enteredWrites, <bool>[true, false]);
      expect(h.store.value, isFalse);
    });

    test('stale native cleanup precedes a later explicit enable', () async {
      final _Harness h = _buildHarness(optIn: false);
      await h.service.start();
      final Completer<void> oldEnable = Completer<void>();
      bool firstEnable = true;
      h.channel.beforeConfigure = (bool enabled) async {
        if (enabled && firstEnable) {
          firstEnable = false;
          await oldEnable.future;
        }
      };
      final Future<bool> first = h.service.setEnabled(true);
      await _tick();
      final Future<bool> second = h.service.setEnabled(false);
      await _tick();
      final Future<bool> third = h.service.setEnabled(true);
      await _tick();
      oldEnable.complete();
      expect(await first, isFalse);
      await second;
      expect(await third, isTrue);
      expect(h.service.isEnabled, isTrue);
      expect(h.channel.persistedEnabled, isTrue);
      expect(h.store.value, isTrue);
    });

    test('openInputMethodSettings only runs on an explicit call', () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      expect(h.channel.openSettingsCalls, 0);
      await h.service.openInputMethodSettings();
      expect(h.channel.openSettingsCalls, 1);
    });

    test('dispose is idempotent and unregisters the channel handler', () async {
      final _Harness h = _buildHarness();
      await h.service.start();
      expect(h.channel.handler, isNotNull);

      h.service.dispose();
      expect(h.service.isDisposed, isTrue);
      expect(h.channel.handler, isNull);
      h.service.dispose();
      expect(
        _status(await h.request('begin')),
        SystemKeyboardChannelStatus.unavailable,
      );
    });

    test('a delayed enable write cannot re-enable after a newer disable',
        () async {
      final _Harness h = _buildHarness(optIn: false);
      await h.service.start();
      expect(h.service.isEnabled, isFalse);

      final Completer<void> barrier = Completer<void>();
      h.store.writeBarrier = barrier;
      final Future<bool> enabling = h.service.setEnabled(true);
      await _tick();
      final Future<bool> disabling = h.service.setEnabled(false);
      // Disable is already effective in memory and native before persistence.
      expect(h.service.isEnabled, isFalse);

      barrier.complete();
      expect(await enabling, isFalse);
      await disabling;
      expect(h.service.isEnabled, isFalse);
      expect(h.store.value, isFalse);
      expect(h.channel.configureRequests, isNot(contains(true)));
    });

    test('an in-flight native enable cannot win after a newer disable',
        () async {
      final _Harness h = _buildHarness(optIn: false);
      await h.service.start();

      final Completer<void> barrier = Completer<void>();
      h.channel.configureBarrier = barrier;
      final Future<bool> enabling = h.service.setEnabled(true);
      await _tick();
      expect(h.channel.configureRequests, contains(true));

      final Future<bool> disabling = h.service.setEnabled(false);
      barrier.complete();
      expect(await enabling, isFalse);
      await disabling;
      expect(h.service.isEnabled, isFalse);
      expect(h.channel.configureRequests.last, isFalse);
      expect(h.store.value, isFalse);
    });

    test('dispose during start never configures native on', () async {
      final _Harness h = _buildHarness(optIn: true);
      final Completer<void> barrier = Completer<void>();
      h.store.readBarrier = barrier;

      final Future<void> starting = h.service.start();
      await _tick();
      h.service.dispose();
      barrier.complete();
      await starting;

      expect(h.service.isDisposed, isTrue);
      expect(h.channel.configureRequests, isNot(contains(true)));
    });

    test('dispose during an in-flight native enable forces native off',
        () async {
      final _Harness h = _buildHarness(optIn: false);
      await h.service.start();

      final Completer<void> barrier = Completer<void>();
      h.channel.configureBarrier = barrier;
      final Future<bool> enabling = h.service.setEnabled(true);
      await _tick();
      expect(h.channel.configureRequests, contains(true));

      h.service.dispose();
      barrier.complete();
      expect(await enabling, isFalse);
      expect(h.channel.configureRequests.last, isFalse);
    });
  });

  group('autonomous inactivity settings', () {
    test(
        'loads preference and applies the app lock ceiling without changing it',
        () async {
      final h = _buildHarness(readIdlePreference: () async => 120);
      addTearDown(h.service.dispose);
      await h.service.start();
      expect(h.service.idlePreferenceSeconds, 120);
      expect(h.service.effectiveIdleSeconds, 120);
      h.service.seedAppLockConfig(enabled: true, timeoutSeconds: 30);
      expect(h.service.effectiveIdleSeconds, 30);
      h.service.onAppLockConfigChanged(enabled: true, timeoutSeconds: 0);
      expect(h.service.effectiveIdleSeconds, isNull);
      expect(h.service.idlePreferenceSeconds, 120);
    });

    test('concurrent writes cannot leave an older duration persisted last',
        () async {
      final barrier = Completer<void>();
      final writes = <int>[];
      final h = _buildHarness(writeIdlePreference: (seconds) async {
        if (seconds == 30) await barrier.future;
        writes.add(seconds);
      });
      addTearDown(h.service.dispose);
      await h.service.start();
      final first = h.service.setIdlePreferenceSeconds(30);
      await _tick();
      final second = h.service.setIdlePreferenceSeconds(60);
      await _tick();
      expect(writes, isEmpty);
      barrier.complete();
      expect(await first, isTrue);
      expect(await second, isTrue);
      expect(writes, [30, 60]);
      expect(h.service.idlePreferenceSeconds, 60);
      expect(await h.service.setIdlePreferenceSeconds(0), isFalse);
      expect(writes, [30, 60]);
    });

    test('a failed duration write revokes but does not claim the change',
        () async {
      final h = _buildHarness(
          writeIdlePreference: (_) async => throw StateError('write failed'));
      addTearDown(h.service.dispose);
      await h.service.start();
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
      expect(await h.service.setIdlePreferenceSeconds(60), isFalse);
      expect(h.service.idlePreferenceSeconds, 60);
      _expectNoData(await h.request('contacts'));
    });
  });

  group('open-source system keyboard scramble setting', () {
    test('loads an independent preference and includes it in begin', () async {
      final h = _buildHarness(readScramblePreference: () async => true);
      addTearDown(h.service.dispose);
      await h.service.start();
      expect(h.service.scramblePreference, isTrue);
      expect(_data(await h.request('begin'))['scramble'], isTrue);
    });

    test('persists a change and revokes the previous editor', () async {
      final writes = <bool>[];
      final h = _buildHarness(writeScramblePreference: (value) async {
        writes.add(value);
      });
      addTearDown(h.service.dispose);
      await h.service.start();
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
      expect(await h.service.setScramblePreference(true), isTrue);
      expect(writes, [true]);
      expect(h.service.scramblePreference, isTrue);
      _expectNoData(await h.request('contacts'));
    });
  });

  group('keyboard chat history preference', () {
    test('defaults on and persists an opt-out before the next grant', () async {
      final writes = <bool>[];
      final h = _buildHarness(writeSaveHistoryPreference: (value) async {
        writes.add(value);
      });
      addTearDown(h.service.dispose);
      await h.service.start();
      expect(h.service.saveHistoryPreference, isTrue);
      expect(await h.service.setSaveHistoryPreference(false), isTrue);
      expect(writes, [false]);
      expect(h.service.saveHistoryPreference, isFalse);
    });

    test('restores opt-out and fails closed on preference read error',
        () async {
      final optedOut =
          _buildHarness(readSaveHistoryPreference: () async => false);
      addTearDown(optedOut.service.dispose);
      await optedOut.service.start();
      expect(optedOut.service.saveHistoryPreference, isFalse);

      final failed = _buildHarness(
          readSaveHistoryPreference: () async => throw StateError('read'));
      addTearDown(failed.service.dispose);
      await failed.service.start();
      expect(failed.service.saveHistoryPreference, isFalse);
    });
  });

  group('keyboard biometric resume preference', () {
    test('is off by default and revokes an existing editor before enabling',
        () async {
      final writes = <bool>[];
      final h = _buildHarness(writeBiometricResumePreference: (value) async {
        writes.add(value);
      });
      addTearDown(h.service.dispose);
      await h.service.start();
      expect(h.service.biometricResumePreference, isFalse);
      expect(_status(await h.request('begin')), SystemKeyboardChannelStatus.ok);
      expect(await h.service.setBiometricResumePreference(true), isTrue);
      expect(writes, [true]);
      expect(h.service.biometricResumePreference, isTrue);
      _expectNoData(await h.request('contacts'));
    });

    test('failed preference read or write never enables it', () async {
      final h = _buildHarness(
        readBiometricResumePreference: () async => throw StateError('read'),
        writeBiometricResumePreference: (_) async => throw StateError('write'),
      );
      addTearDown(h.service.dispose);
      await h.service.start();
      expect(h.service.biometricResumePreference, isFalse);
      expect(await h.service.setBiometricResumePreference(true), isFalse);
      expect(h.service.biometricResumePreference, isFalse);
    });
  });

  group('provider wiring', () {
    test('owner provider changes bump the generation and revoke the session',
        () async {
      final _FakeNativeChannel channel = _FakeNativeChannel();
      final _FakeOptInStore store = _FakeOptInStore()..value = true;
      final _RecordingBackend backend = _RecordingBackend();
      final ProviderContainer container = ProviderContainer(
        overrides: <Override>[
          systemKeyboardPlatformSupportedProvider.overrideWithValue(true),
          systemKeyboardFeatureFlagEnabledProvider.overrideWithValue(true),
          systemKeyboardNativeChannelProvider.overrideWithValue(channel),
          systemKeyboardOptInStoreProvider.overrideWithValue(store),
          systemKeyboardBackendFactoryProvider.overrideWithValue(
            (Ref ref, SystemKeyboardIntegrationGuard guard) => backend,
          ),
          protocolV3IdentityEnabledProvider.overrideWithValue(false),
          activeIdentityIdProvider.overrideWith((ref) => 'id-1'),
          appLockStateReadyProvider.overrideWith((ref) => true),
          appNeedsUnlockProvider.overrideWith((ref) => false),
          appLockEnabledProvider.overrideWith((ref) => false),
          appLockTimeoutProvider.overrideWith((ref) => 60),
          originalKeyTagProvider.overrideWith((ref) async => 'tag-1'),
        ],
      );
      addTearDown(container.dispose);

      await container.read(originalKeyTagProvider.future);
      final SystemKeyboardAppService service =
          container.read(systemKeyboardAppServiceProvider);
      await service.start();
      expect(service.isEnabled, isTrue);

      final Map<String, Object?> begin = await service.handleChannelRequest(
        <String, Object?>{
          'operation': 'begin',
          'editorNonce': 'ed-1',
          'requestId': 'r1',
        },
      );
      expect(_status(begin), SystemKeyboardChannelStatus.ok);

      final int generationBefore = service.generation;
      final int revokesBefore = channel.revokeCalls;
      container.read(activeIdentityIdProvider.notifier).state = 'id-2';
      await _tick();
      expect(service.generation, greaterThan(generationBefore));
      expect(channel.revokeCalls, greaterThan(revokesBefore));

      expect(
        _status(await service.handleChannelRequest(<String, Object?>{
          'operation': 'heartbeat',
          'editorNonce': 'ed-1',
          'requestId': 'r2',
        })),
        SystemKeyboardChannelStatus.unavailable,
      );

      // Away and back to the same identity must still invalidate.
      container.read(activeIdentityIdProvider.notifier).state = 'id-1';
      await _tick();
      expect(service.generation, greaterThan(generationBefore + 1));
      expect(
        _status(await service.handleChannelRequest(<String, Object?>{
          'operation': 'contacts',
          'editorNonce': 'ed-1',
          'requestId': 'r3',
        })),
        SystemKeyboardChannelStatus.unavailable,
      );
      expect(backend.listCalls, 0);

      // A fresh session is required and then works again.
      expect(
        _status(await service.handleChannelRequest(<String, Object?>{
          'operation': 'begin',
          'editorNonce': 'ed-2',
          'requestId': 'r4',
        })),
        SystemKeyboardChannelStatus.ok,
      );
    });

    test('a pre-existing zero app-lock timeout is seeded and gates immediately',
        () async {
      final _TestClock clock = _TestClock();
      final _FakeNativeChannel channel = _FakeNativeChannel();
      final _FakeOptInStore store = _FakeOptInStore()..value = true;
      final ProviderContainer container = _lockConfigContainer(
        clock: clock,
        channel: channel,
        store: store,
        lockEnabled: true,
        lockTimeoutSeconds: 0,
      );
      addTearDown(container.dispose);

      await container.read(originalKeyTagProvider.future);
      final SystemKeyboardAppService service =
          container.read(systemKeyboardAppServiceProvider);
      await service.start();
      expect(service.isEnabled, isTrue);

      final int generation = service.generation;
      expect(service.admits(generation, 'id-1'), isTrue);
      service.onAppLifecycleChanged(AppLifecycleState.inactive);

      // No provider ever changed: only the seeded lock configuration applies.
      expect(service.admits(generation, 'id-1'), isFalse);
      final SystemKeyboardAppBackend backend =
          container.read(_probeBackendProvider);
      // The real backend aborts before any storage access (Hive is not even
      // initialized in this suite).
      expect(await backend.listApprovedContacts(), isEmpty);
      expect(await backend.decodeCarrier('carrier'), isNull);
    });

    test(
        'a pre-existing positive app-lock timeout is seeded and gates at its '
        'deadline', () async {
      final _TestClock clock = _TestClock();
      final _FakeNativeChannel channel = _FakeNativeChannel();
      final _FakeOptInStore store = _FakeOptInStore()..value = true;
      final ProviderContainer container = _lockConfigContainer(
        clock: clock,
        channel: channel,
        store: store,
        lockEnabled: true,
        lockTimeoutSeconds: 5,
      );
      addTearDown(container.dispose);

      await container.read(originalKeyTagProvider.future);
      final SystemKeyboardAppService service =
          container.read(systemKeyboardAppServiceProvider);
      await service.start();
      final int generation = service.generation;

      service.onAppLifecycleChanged(AppLifecycleState.inactive);
      clock.advance(const Duration(seconds: 4));
      expect(service.admits(generation, 'id-1'), isTrue);
      clock.advance(const Duration(seconds: 2));
      expect(service.admits(generation, 'id-1'), isFalse);
      final SystemKeyboardAppBackend backend =
          container.read(_probeBackendProvider);
      expect(await backend.listApprovedContacts(), isEmpty);
    });
  });
}

/// A real [SystemKeyboardAppBackend] bound to the same container, used to prove
/// the integration guard aborts a backend call before any storage access.
final Provider<SystemKeyboardAppBackend> _probeBackendProvider =
    Provider<SystemKeyboardAppBackend>(
  (ref) => SystemKeyboardAppBackend(
    ref: ref,
    guard: ref.read(systemKeyboardAppServiceProvider),
  ),
);

ProviderContainer _lockConfigContainer({
  required _TestClock clock,
  required _FakeNativeChannel channel,
  required _FakeOptInStore store,
  required bool lockEnabled,
  required int lockTimeoutSeconds,
}) {
  return ProviderContainer(
    overrides: <Override>[
      systemKeyboardPlatformSupportedProvider.overrideWithValue(true),
      systemKeyboardFeatureFlagEnabledProvider.overrideWithValue(true),
      systemKeyboardNativeChannelProvider.overrideWithValue(channel),
      systemKeyboardOptInStoreProvider.overrideWithValue(store),
      systemKeyboardMonotonicNowProvider.overrideWithValue(clock.call),
      protocolV3IdentityEnabledProvider.overrideWithValue(false),
      activeIdentityIdProvider.overrideWith((ref) => 'id-1'),
      appLockStateReadyProvider.overrideWith((ref) => true),
      appNeedsUnlockProvider.overrideWith((ref) => false),
      appLockEnabledProvider.overrideWith((ref) => lockEnabled),
      appLockTimeoutProvider.overrideWith((ref) => lockTimeoutSeconds),
      originalKeyTagProvider.overrideWith((ref) async => 'tag-1'),
    ],
  );
}
