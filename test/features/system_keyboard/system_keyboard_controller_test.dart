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

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_controller.dart';

const SystemKeyboardContact _alice = SystemKeyboardContact(
  id: 'c-alice',
  name: 'Alice',
  fingerprint: 'FP-ALICE',
);

const SystemKeyboardContact _bob = SystemKeyboardContact(
  id: 'c-bob',
  name: 'Bob',
  fingerprint: 'FP-BOB',
);

Future<void> _tick() => Future<void>.delayed(Duration.zero);

class _FakeBackend implements SystemKeyboardBackend {
  int listCalls = 0;
  int prepareCalls = 0;
  int markExportedCalls = 0;
  int decodeCalls = 0;

  final List<String> markedHandles = <String>[];
  final List<SystemKeyboardOutboundRequest> prepareRequests =
      <SystemKeyboardOutboundRequest>[];
  final List<String> decodedCarriers = <String>[];

  List<SystemKeyboardContact> contacts = const <SystemKeyboardContact>[
    _alice,
    _bob,
  ];
  SystemKeyboardBackendExport? export = const SystemKeyboardBackendExport(
    exportHandle: 'handle-alice',
    carriers: <String>['carrier-alice'],
    ciphertextCodeUnits: 42,
  );
  SystemKeyboardBackendDecoded? decoded;
  Object? decodeError;
  Object? prepareError;
  Object? markError;

  Completer<void>? listBarrier;
  Completer<void>? prepareBarrier;
  Completer<void>? markBarrier;
  Completer<void>? decodeBarrier;

  @override
  Future<List<SystemKeyboardContact>> listApprovedContacts() async {
    listCalls++;
    final Completer<void>? barrier = listBarrier;
    if (barrier != null) {
      await barrier.future;
    }
    return contacts;
  }

  @override
  Future<SystemKeyboardBackendExport?> prepareTextOutbound(
    SystemKeyboardOutboundRequest request,
  ) async {
    prepareCalls++;
    prepareRequests.add(request);
    final Completer<void>? barrier = prepareBarrier;
    if (barrier != null) {
      await barrier.future;
    }
    final Object? error = prepareError;
    if (error != null) {
      throw error;
    }
    return export;
  }

  @override
  Future<void> markExported(String exportHandle) async {
    markExportedCalls++;
    markedHandles.add(exportHandle);
    final Completer<void>? barrier = markBarrier;
    if (barrier != null) {
      await barrier.future;
    }
    final Object? error = markError;
    if (error != null) {
      throw error;
    }
  }

  @override
  Future<SystemKeyboardBackendDecoded?> decodeCarrier(String carrier) async {
    decodeCalls++;
    decodedCarriers.add(carrier);
    final Completer<void>? barrier = decodeBarrier;
    if (barrier != null) {
      await barrier.future;
    }
    final Object? error = decodeError;
    if (error != null) {
      throw error;
    }
    return decoded;
  }
}

class _StatusBackend extends _FakeBackend
    implements SystemKeyboardContactSecurityProvider {
  String? phase = 'setupPending';
  Completer<void>? statusBarrier;
  int statusCalls = 0;

  @override
  Future<String?> securityPhaseForContact(
      String contactId, String fingerprint) async {
    statusCalls++;
    expect(contactId, _alice.id);
    expect(fingerprint, _alice.fingerprint);
    await statusBarrier?.future;
    return phase;
  }
}

class _Access {
  bool featureOptedIn = true;
  bool lockInitialized = true;
  bool lockUnlocked = true;
  bool lockRequested = false;
  bool passphraseActive = false;
  bool disposed = false;
  String? identityContextGeneration = 'ctx-1';
  int stateGeneration = 0;
  Duration? backgroundDeadline;
  bool throwOnRead = false;

  SystemKeyboardAccessSnapshot read() {
    if (throwOnRead) {
      throw StateError('access reader unavailable');
    }
    return SystemKeyboardAccessSnapshot(
      featureOptedIn: featureOptedIn,
      lockInitialized: lockInitialized,
      lockUnlocked: lockUnlocked,
      lockRequested: lockRequested,
      passphraseActive: passphraseActive,
      disposed: disposed,
      stateGeneration: stateGeneration,
      identityContextGeneration: identityContextGeneration,
      backgroundDeadline: backgroundDeadline,
    );
  }

  void bump() => stateGeneration++;
}

class _Harness {
  _Harness({
    int composeLimitCodeUnits = 4000,
    int ciphertextLimitCodeUnits = 4000,
    int maxCarrierCodeUnits = systemKeyboardDefaultMaxCarrierCodeUnits,
    Duration pendingExportTtl = const Duration(minutes: 2),
    int maxRememberedRequestIds = 64,
    int maxIdentifierLength = systemKeyboardDefaultMaxIdentifierLength,
  }) {
    controller = SystemKeyboardController(
      backend: backend,
      readAccess: access.read,
      monotonicNow: () {
        final Object? error = nowError;
        if (error != null) {
          throw error;
        }
        return now;
      },
      composeLimitCodeUnits: composeLimitCodeUnits,
      ciphertextLimitCodeUnits: ciphertextLimitCodeUnits,
      maxCarrierCodeUnits: maxCarrierCodeUnits,
      pendingExportTtl: pendingExportTtl,
      maxRememberedRequestIds: maxRememberedRequestIds,
      maxIdentifierLength: maxIdentifierLength,
    );
  }

  final _FakeBackend backend = _FakeBackend();
  final _Access access = _Access();
  Duration now = Duration.zero;
  Object? nowError;
  late final SystemKeyboardController controller;
  int _sequence = 0;

  String _nextId(String prefix) => '$prefix-${_sequence++}';

  void begin() {
    final SystemKeyboardResult<SystemKeyboardSession> session =
        controller.beginSession(editorNonce: 'editor-nonce');
    expect(session.isSuccess, isTrue, reason: 'session begin should succeed');
  }

  Future<SystemKeyboardContact> selectAlice() async {
    final SystemKeyboardResult<SystemKeyboardContact> result =
        await controller.selectContact(
      requestId: _nextId('select'),
      contactId: _alice.id,
      confirm: true,
    );
    expect(result.isSuccess, isTrue);
    return result.requireValue;
  }

  /// Binds a recipient and prepares one outbound, returning the pending id.
  Future<String> prepareOne({String text = 'hi'}) async {
    await selectAlice();
    final SystemKeyboardResult<SystemKeyboardPendingExport> prepared =
        await controller.prepareText(requestId: _nextId('prepare'), text: text);
    expect(prepared.isSuccess, isTrue, reason: 'prepare should succeed');
    return prepared.requireValue.pendingId;
  }

  /// Prepares and authorizes one outbound, returning the pending id.
  Future<String> authorizeOne({String text = 'hi'}) async {
    final String pendingId = await prepareOne(text: text);
    final SystemKeyboardResult<String> authorized =
        await controller.authorizeInsertion(
      requestId: _nextId('authorize'),
      pendingId: pendingId,
    );
    expect(authorized.isSuccess, isTrue, reason: 'authorize should succeed');
    return pendingId;
  }

  /// Simulates any admission-relevant owner event that keeps the flags as they
  /// are (the ABA shape): the generation advances, so the session is revoked.
  void ownerEvent() => access.bump();
}

void main() {
  test('selected recipient gets a fresh display-only FS phase', () async {
    final backend = _StatusBackend();
    final access = _Access();
    final controller = SystemKeyboardController(
      backend: backend,
      readAccess: access.read,
      monotonicNow: () => Duration.zero,
    );
    expect(controller.beginSession(editorNonce: 'editor').isSuccess, isTrue);
    for (final phase in [
      'setupPending',
      'normalActive',
      'maximumSetupPending',
      'maximumActive'
    ]) {
      backend.phase = phase;
      final selected = await controller.selectContact(
        requestId: 'select-$phase',
        contactId: _alice.id,
        confirm: true,
      );
      expect(selected.requireValue.securityPhase, phase);
      expect(controller.selectedContact?.securityPhase, phase);
    }
    expect(backend.statusCalls, 4);
    controller.dispose();
  });

  test('revocation during FS status lookup cannot confirm a recipient',
      () async {
    final backend = _StatusBackend()..statusBarrier = Completer<void>();
    final access = _Access();
    final controller = SystemKeyboardController(
      backend: backend,
      readAccess: access.read,
      monotonicNow: () => Duration.zero,
    );
    expect(controller.beginSession(editorNonce: 'editor').isSuccess, isTrue);
    final selection = controller.selectContact(
        requestId: 'select', contactId: _alice.id, confirm: true);
    await _tick();
    controller.revoke();
    backend.statusBarrier!.complete();
    expect((await selection).failure, SystemKeyboardFailureCode.unavailable);
    expect(controller.selectedContact, isNull);
    controller.dispose();
  });
  group('admission', () {
    test(
      'every denial state returns the same generic unavailable and never touches the backend',
      () async {
        final Map<String, void Function(_Access)> variants =
            <String, void Function(_Access)>{
          'feature not opted in': (_Access a) => a.featureOptedIn = false,
          'lock not initialized': (_Access a) => a.lockInitialized = false,
          'lock locked': (_Access a) => a.lockUnlocked = false,
          'lock requested': (_Access a) => a.lockRequested = true,
          'no identity': (_Access a) => a.identityContextGeneration = null,
          'empty identity': (_Access a) => a.identityContextGeneration = '',
          'passphrase active': (_Access a) => a.passphraseActive = true,
          'disposed': (_Access a) => a.disposed = true,
          'deadline passed': (_Access a) =>
              a.backgroundDeadline = Duration.zero,
        };

        for (final MapEntry<String, void Function(_Access)> entry
            in variants.entries) {
          final _Harness harness = _Harness();
          harness.begin();
          await harness.selectAlice();
          final int listBaseline = harness.backend.listCalls;

          entry.value(harness.access);

          final List<SystemKeyboardResult<Object?>> results =
              <SystemKeyboardResult<Object?>>[
            await harness.controller.listContacts(requestId: 'r1'),
            await harness.controller.selectContact(
              requestId: 'r2',
              contactId: _alice.id,
              confirm: true,
            ),
            await harness.controller.prepareText(
              requestId: 'r3',
              text: 'hi',
            ),
            await harness.controller.authorizeInsertion(
              requestId: 'r4',
              pendingId: 'skp0',
            ),
            await harness.controller.acknowledgeInsertion(
              requestId: 'r5',
              pendingId: 'skp0',
              commitText: true,
            ),
            await harness.controller.decodeCarrier(
              requestId: 'r6',
              carrier: 'carrier',
            ),
          ];

          for (final SystemKeyboardResult<Object?> result in results) {
            expect(
              result.failure,
              SystemKeyboardFailureCode.unavailable,
              reason: entry.key,
            );
            expect(result.value, isNull, reason: entry.key);
          }
          expect(harness.backend.listCalls, listBaseline, reason: entry.key);
          expect(harness.backend.prepareCalls, 0, reason: entry.key);
          expect(harness.backend.markExportedCalls, 0, reason: entry.key);
          expect(harness.backend.decodeCalls, 0, reason: entry.key);
          expect(harness.controller.selectedContact, isNull, reason: entry.key);
          expect(harness.controller.isSessionActive, isFalse,
              reason: entry.key);
        }
      },
    );

    test(
      'background deadline is enforced against the injected clock',
      () async {
        final _Harness harness = _Harness();
        harness.access.backgroundDeadline = const Duration(seconds: 100);
        harness.begin();

        harness.now = const Duration(seconds: 99, milliseconds: 999);
        expect(
          (await harness.controller.listContacts(requestId: 'r1')).isSuccess,
          isTrue,
        );

        harness.now = const Duration(seconds: 100);
        final SystemKeyboardResult<List<SystemKeyboardContact>> denied =
            await harness.controller.listContacts(requestId: 'r2');
        expect(denied.failure, SystemKeyboardFailureCode.unavailable);
        expect(harness.backend.listCalls, 1);
      },
    );

    test('a throwing access reader is treated as denied', () async {
      final _Harness harness = _Harness();
      harness.begin();
      harness.access.throwOnRead = true;

      final SystemKeyboardResult<List<SystemKeyboardContact>> result =
          await harness.controller.listContacts(requestId: 'r1');
      expect(result.failure, SystemKeyboardFailureCode.unavailable);
      expect(result.value, isNull);
      expect(harness.backend.listCalls, 0);
    });

    test('operations without a session are unavailable', () async {
      final _Harness harness = _Harness();
      final SystemKeyboardResult<List<SystemKeyboardContact>> result =
          await harness.controller.listContacts(requestId: 'r1');
      expect(result.failure, SystemKeyboardFailureCode.unavailable);
      expect(harness.backend.listCalls, 0);
    });

    test('a throwing monotonic clock denies instead of extending a grant',
        () async {
      final _Harness harness = _Harness();
      harness.begin();
      harness.nowError = StateError('clock unavailable');

      expect(
        (await harness.controller.listContacts(requestId: 'r1')).failure,
        SystemKeyboardFailureCode.unavailable,
      );
      expect(harness.backend.listCalls, 0);
      expect(harness.controller.isSessionActive, isFalse);
      // The session must be re-established explicitly.
      expect(
        harness.controller.beginSession(editorNonce: 'editor-nonce').failure,
        SystemKeyboardFailureCode.unavailable,
      );

      harness.nowError = null;
      harness.begin();
      expect(
        (await harness.controller.listContacts(requestId: 'r2')).isSuccess,
        isTrue,
      );
    });

    test('constructor rejects a replay memory that cannot reject replays', () {
      expect(
        () => _Harness(maxRememberedRequestIds: 0),
        throwsArgumentError,
      );
      expect(
        () => _Harness(maxIdentifierLength: 0),
        throwsArgumentError,
      );
    });
  });

  group('session lifecycle', () {
    test('begin requires a nonce and binds prepare to it', () async {
      final _Harness harness = _Harness();
      expect(
        harness.controller.beginSession(editorNonce: '').failure,
        SystemKeyboardFailureCode.invalidRequest,
      );
      harness.begin();
      await harness.selectAlice();

      final SystemKeyboardResult<SystemKeyboardPendingExport> prepared =
          await harness.controller.prepareText(requestId: 'p1', text: 'hello');
      expect(prepared.isSuccess, isTrue);

      final SystemKeyboardOutboundRequest request =
          harness.backend.prepareRequests.single;
      expect(request.requestId, 'p1');
      expect(request.contactId, _alice.id);
      expect(request.contactFingerprint, _alice.fingerprint);
      expect(request.text, 'hello');
      expect(request.editorNonce, 'editor-nonce');
      expect(request.inputSessionEpoch, greaterThan(0));
    });

    test(
      'session end clears state and invalidates in-flight decode output',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        await harness.selectAlice();
        final String pendingId = (await harness.controller.prepareText(
          requestId: 'p1',
          text: 'hi',
        ))
            .requireValue
            .pendingId;

        final Completer<void> barrier = Completer<void>();
        harness.backend.decodeBarrier = barrier;
        final Future<SystemKeyboardResult<SystemKeyboardDecodedPreview>>
            inflight = harness.controller.decodeCarrier(
          requestId: 'd1',
          carrier: 'carrier-in',
        );
        await _tick();
        harness.controller.endSession();
        barrier.complete();

        final SystemKeyboardResult<SystemKeyboardDecodedPreview> suppressed =
            await inflight;
        expect(suppressed.failure, SystemKeyboardFailureCode.unavailable);
        expect(suppressed.value, isNull);

        expect(harness.controller.selectedContact, isNull);
        expect(
          (await harness.controller.listContacts(requestId: 'r1')).failure,
          SystemKeyboardFailureCode.unavailable,
        );

        harness.begin();
        expect(
          (await harness.controller.authorizeInsertion(
            requestId: 'a1',
            pendingId: pendingId,
          ))
              .failure,
          SystemKeyboardFailureCode.noPendingExport,
        );
        expect(harness.backend.markExportedCalls, 0);
      },
    );

    test('revoke clears per-session request-id memory', () async {
      final _Harness harness = _Harness();
      harness.begin();
      expect(
        (await harness.controller.listContacts(requestId: 'r1')).isSuccess,
        isTrue,
      );
      expect(
        (await harness.controller.listContacts(requestId: 'r1')).failure,
        SystemKeyboardFailureCode.duplicateRequest,
      );

      harness.controller.revoke();
      harness.begin();
      expect(
        (await harness.controller.listContacts(requestId: 'r1')).isSuccess,
        isTrue,
      );
      expect(harness.backend.listCalls, 2);
    });
  });

  group('contacts and selection', () {
    test(
      'contacts are fetched only on request and malformed entries drop',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        expect(harness.backend.listCalls, 0);

        harness.backend.contacts = const <SystemKeyboardContact>[
          _alice,
          SystemKeyboardContact(id: '', name: 'Ghost', fingerprint: 'FP'),
          SystemKeyboardContact(id: 'c-x', name: '', fingerprint: 'FP'),
          SystemKeyboardContact(id: 'c-y', name: 'Y', fingerprint: ''),
        ];
        final SystemKeyboardResult<List<SystemKeyboardContact>> listed =
            await harness.controller.listContacts(requestId: 'r1');
        expect(
          listed.requireValue.map((SystemKeyboardContact c) => c.id).toList(),
          <String>[_alice.id],
        );
        expect(harness.backend.listCalls, 1);
      },
    );

    test(
      'selection needs explicit id and confirmation on a fresh fetch',
      () async {
        final _Harness harness = _Harness();
        harness.begin();

        final SystemKeyboardResult<SystemKeyboardContact> unconfirmed =
            await harness.controller.selectContact(
          requestId: 's1',
          contactId: _alice.id,
          confirm: false,
        );
        expect(unconfirmed.failure, SystemKeyboardFailureCode.invalidSelection);
        expect(harness.backend.listCalls, 0);
        expect(harness.controller.selectedContact, isNull);

        final SystemKeyboardResult<SystemKeyboardContact> unknown =
            await harness.controller.selectContact(
          requestId: 's2',
          contactId: 'c-unknown',
          confirm: true,
        );
        expect(unknown.failure, SystemKeyboardFailureCode.invalidSelection);
        expect(harness.backend.listCalls, 1);
        expect(harness.controller.selectedContact, isNull);

        final SystemKeyboardResult<SystemKeyboardContact> selected =
            await harness.controller.selectContact(
          requestId: 's3',
          contactId: _alice.id,
          confirm: true,
        );
        expect(selected.requireValue.id, _alice.id);
        expect(harness.controller.selectedContact?.id, _alice.id);
      },
    );

    test(
      'prepare without a confirmed recipient never reads the backend',
      () async {
        final _Harness harness = _Harness();
        harness.begin();

        final SystemKeyboardResult<SystemKeyboardPendingExport> result =
            await harness.controller.prepareText(
          requestId: 'p1',
          text: 'hello',
        );
        expect(result.failure, SystemKeyboardFailureCode.invalidSelection);
        expect(harness.backend.prepareCalls, 0);
      },
    );
  });

  group('outbound two-phase insert', () {
    test(
      'carrier stays private until authorized and ack marks exactly once',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        await harness.selectAlice();

        final String pendingId = (await harness.controller.prepareText(
          requestId: 'p1',
          text: 'secret plaintext',
        ))
            .requireValue
            .pendingId;
        expect(pendingId.contains('secret'), isFalse);
        expect(harness.backend.markExportedCalls, 0);
        expect(harness.backend.prepareRequests.single.text, 'secret plaintext');

        final SystemKeyboardResult<String> authorized = await harness.controller
            .authorizeInsertion(requestId: 'a1', pendingId: pendingId);
        expect(authorized.requireValue, 'carrier-alice');
        expect(authorized.requireValue.contains('secret plaintext'), isFalse);

        final SystemKeyboardResult<SystemKeyboardAcknowledgement> acked =
            await harness.controller.acknowledgeInsertion(
          requestId: 'k1',
          pendingId: pendingId,
          commitText: true,
        );
        expect(acked.requireValue.exported, isTrue);
        expect(harness.backend.markedHandles, <String>['handle-alice']);

        expect(
          (await harness.controller.acknowledgeInsertion(
            requestId: 'k1',
            pendingId: pendingId,
            commitText: true,
          ))
              .failure,
          SystemKeyboardFailureCode.duplicateRequest,
        );
        expect(
          (await harness.controller.acknowledgeInsertion(
            requestId: 'k2',
            pendingId: pendingId,
            commitText: true,
          ))
              .failure,
          SystemKeyboardFailureCode.noPendingExport,
        );
        expect(harness.backend.markExportedCalls, 1);
      },
    );

    test('a second authorization of the same pending never returns a carrier',
        () async {
      final _Harness harness = _Harness();
      harness.begin();
      final String pendingId = await harness.prepareOne();

      final SystemKeyboardResult<String> first =
          await harness.controller.authorizeInsertion(
        requestId: harness._nextId('authorize'),
        pendingId: pendingId,
      );
      expect(first.requireValue, 'carrier-alice');

      // A distinct request id is not a license to authorize twice.
      final SystemKeyboardResult<String> second =
          await harness.controller.authorizeInsertion(
        requestId: harness._nextId('authorize'),
        pendingId: pendingId,
      );
      expect(second.failure, SystemKeyboardFailureCode.noPendingExport);
      expect(second.value, isNull);

      // The first authorization still permits its single insertion receipt.
      expect(
        (await harness.controller.acknowledgeInsertion(
          requestId: harness._nextId('ack'),
          pendingId: pendingId,
          commitText: true,
        ))
            .failure,
        isNull,
      );
      expect(harness.backend.markExportedCalls, 1);
    });

    test('failed insertion never marks the export exported', () async {
      final _Harness harness = _Harness();
      harness.begin();
      final String pendingId = await harness.authorizeOne();

      final SystemKeyboardResult<SystemKeyboardAcknowledgement> acked =
          await harness.controller.acknowledgeInsertion(
        requestId: harness._nextId('ack'),
        pendingId: pendingId,
        commitText: false,
      );
      expect(acked.requireValue.exported, isFalse);
      expect(harness.backend.markExportedCalls, 0);
      expect(
        (await harness.controller.acknowledgeInsertion(
          requestId: harness._nextId('ack'),
          pendingId: pendingId,
          commitText: true,
        ))
            .failure,
        SystemKeyboardFailureCode.noPendingExport,
      );
    });

    test('acknowledgement requires a prior authorization', () async {
      final _Harness harness = _Harness();
      harness.begin();
      final String pendingId = await harness.prepareOne();

      final SystemKeyboardResult<SystemKeyboardAcknowledgement> result =
          await harness.controller.acknowledgeInsertion(
        requestId: harness._nextId('ack'),
        pendingId: pendingId,
        commitText: true,
      );
      expect(result.failure, SystemKeyboardFailureCode.noPendingExport);
      expect(harness.backend.markExportedCalls, 0);
    });

    test(
      'a throwing markExported after durable marking acked at most once',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        final String pendingId = await harness.authorizeOne();
        harness.backend.markError = StateError('threw after durable marking');

        final SystemKeyboardResult<SystemKeyboardAcknowledgement> first =
            await harness.controller.acknowledgeInsertion(
          requestId: harness._nextId('ack'),
          pendingId: pendingId,
          commitText: true,
        );
        expect(first.failure, SystemKeyboardFailureCode.backendError);
        expect(first.value, isNull);
        expect(harness.backend.markExportedCalls, 1);

        expect(
          (await harness.controller.acknowledgeInsertion(
            requestId: harness._nextId('ack'),
            pendingId: pendingId,
            commitText: true,
          ))
              .failure,
          SystemKeyboardFailureCode.noPendingExport,
        );
        expect(harness.backend.markExportedCalls, 1);
      },
    );

    test('authorization expires with the pending export ttl', () async {
      final _Harness harness = _Harness(
        pendingExportTtl: const Duration(seconds: 30),
      );
      harness.begin();
      final String pendingId = await harness.prepareOne();

      harness.now = const Duration(seconds: 30);
      final SystemKeyboardResult<String> stale =
          await harness.controller.authorizeInsertion(
        requestId: harness._nextId('authorize'),
        pendingId: pendingId,
      );
      expect(stale.failure, SystemKeyboardFailureCode.noPendingExport);
      expect(harness.backend.markExportedCalls, 0);
    });

    test('acknowledgement also expires with the pending export ttl', () async {
      final _Harness harness = _Harness(
        pendingExportTtl: const Duration(seconds: 30),
      );
      harness.begin();
      final String pendingId = await harness.authorizeOne();

      harness.now = const Duration(seconds: 30);
      final SystemKeyboardResult<SystemKeyboardAcknowledgement> stale =
          await harness.controller.acknowledgeInsertion(
        requestId: harness._nextId('ack'),
        pendingId: pendingId,
        commitText: true,
      );
      expect(stale.failure, SystemKeyboardFailureCode.noPendingExport);
      expect(harness.backend.markExportedCalls, 0);
    });

    test('multipart and malformed exports are rejected unmarked', () async {
      const List<SystemKeyboardBackendExport> exports =
          <SystemKeyboardBackendExport>[
        SystemKeyboardBackendExport(
          exportHandle: 'h',
          carriers: <String>['a', 'b'],
          ciphertextCodeUnits: 10,
        ),
        SystemKeyboardBackendExport(
          exportHandle: 'h',
          carriers: <String>[],
          ciphertextCodeUnits: 10,
        ),
        SystemKeyboardBackendExport(
          exportHandle: '',
          carriers: <String>['a'],
          ciphertextCodeUnits: 10,
        ),
        SystemKeyboardBackendExport(
          exportHandle: 'h',
          carriers: <String>[''],
          ciphertextCodeUnits: 10,
        ),
      ];

      for (final SystemKeyboardBackendExport export in exports) {
        final _Harness harness = _Harness();
        harness.begin();
        await harness.selectAlice();
        harness.backend.export = export;

        final SystemKeyboardResult<SystemKeyboardPendingExport> result =
            await harness.controller.prepareText(requestId: 'p1', text: 'hi');
        expect(result.failure, SystemKeyboardFailureCode.unsupportedExport);
        expect(harness.controller.hasPendingExport, isFalse);
        expect(harness.backend.markExportedCalls, 0);
        expect(
          (await harness.controller.authorizeInsertion(
            requestId: 'a1',
            pendingId: 'skp0',
          ))
              .failure,
          SystemKeyboardFailureCode.noPendingExport,
        );
      }
    });

    test('compose and ciphertext size bounds are enforced', () async {
      final _Harness harness = _Harness();
      harness.begin();
      await harness.selectAlice();

      expect(
        (await harness.controller.prepareText(
          requestId: 'p1',
          text: 'a' * 4001,
        ))
            .failure,
        SystemKeyboardFailureCode.oversize,
      );
      expect(harness.backend.prepareCalls, 0);

      expect(
        (await harness.controller.prepareText(
          requestId: 'p2',
          text: '',
        ))
            .failure,
        SystemKeyboardFailureCode.invalidRequest,
      );
      expect(harness.backend.prepareCalls, 0);

      expect(
        (await harness.controller.prepareText(
          requestId: 'p3',
          text: 'a' * 4000,
        ))
            .isSuccess,
        isTrue,
      );
      expect(harness.backend.prepareCalls, 1);

      final _Harness big = _Harness();
      big.begin();
      await big.selectAlice();
      big.backend.export = const SystemKeyboardBackendExport(
        exportHandle: 'h',
        carriers: <String>['carrier'],
        ciphertextCodeUnits: 4001,
      );
      expect(
        (await big.controller.prepareText(requestId: 'p1', text: 'hi')).failure,
        SystemKeyboardFailureCode.oversize,
      );
      expect(big.backend.markExportedCalls, 0);
      expect(
        (await big.controller.authorizeInsertion(
          requestId: 'a1',
          pendingId: 'skp0',
        ))
            .failure,
        SystemKeyboardFailureCode.noPendingExport,
      );
    });

    test('the actual carrier length is bounded, not only the declared size',
        () async {
      final _Harness harness = _Harness(ciphertextLimitCodeUnits: 64);
      harness.begin();
      await harness.selectAlice();

      harness.backend.export = SystemKeyboardBackendExport(
        exportHandle: 'h',
        carriers: <String>['c' * 65],
        ciphertextCodeUnits: 42,
      );
      expect(
        (await harness.controller.prepareText(
          requestId: harness._nextId('prepare'),
          text: 'hi',
        ))
            .failure,
        SystemKeyboardFailureCode.oversize,
      );
      expect(harness.controller.hasPendingExport, isFalse);

      harness.backend.export = SystemKeyboardBackendExport(
        exportHandle: 'h',
        carriers: <String>['c' * 64],
        ciphertextCodeUnits: 42,
      );
      expect(
        (await harness.controller.prepareText(
          requestId: harness._nextId('prepare'),
          text: 'hi',
        ))
            .isSuccess,
        isTrue,
      );
    });

    test('a negative declared ciphertext size is rejected unmarked', () async {
      final _Harness harness = _Harness();
      harness.begin();
      await harness.selectAlice();
      harness.backend.export = const SystemKeyboardBackendExport(
        exportHandle: 'h',
        carriers: <String>['carrier'],
        ciphertextCodeUnits: -1,
      );

      expect(
        (await harness.controller.prepareText(
          requestId: harness._nextId('prepare'),
          text: 'hi',
        ))
            .failure,
        SystemKeyboardFailureCode.unsupportedExport,
      );
      expect(harness.controller.hasPendingExport, isFalse);
      expect(harness.backend.markExportedCalls, 0);
    });

    test('only one pending export is retained per session', () async {
      final _Harness harness = _Harness();
      harness.begin();
      final String firstId = await harness.prepareOne();
      final int preparesAfterFirst = harness.backend.prepareCalls;

      final SystemKeyboardResult<SystemKeyboardPendingExport> second =
          await harness.controller.prepareText(
        requestId: harness._nextId('prepare'),
        text: 'second',
      );
      expect(second.failure, SystemKeyboardFailureCode.unsupportedExport);
      expect(harness.backend.prepareCalls, preparesAfterFirst);

      // A new pending is allowed only after the insertion is acknowledged.
      await harness.controller.authorizeInsertion(
        requestId: harness._nextId('authorize'),
        pendingId: firstId,
      );
      await harness.controller.acknowledgeInsertion(
        requestId: harness._nextId('ack'),
        pendingId: firstId,
        commitText: true,
      );
      expect(
        (await harness.controller.prepareText(
          requestId: harness._nextId('prepare'),
          text: 'second',
        ))
            .isSuccess,
        isTrue,
      );
      expect(harness.backend.prepareCalls, preparesAfterFirst + 1);
    });

    test('a backend export failure leaves no pending behind', () async {
      final _Harness harness = _Harness();
      harness.begin();
      await harness.selectAlice();
      harness.backend.prepareError = StateError('boom');

      expect(
        (await harness.controller.prepareText(
          requestId: harness._nextId('prepare'),
          text: 'hi',
        ))
            .failure,
        SystemKeyboardFailureCode.backendError,
      );
      expect(harness.controller.hasPendingExport, isFalse);

      harness.backend.prepareError = null;
      expect(
        (await harness.controller.prepareText(
          requestId: harness._nextId('prepare'),
          text: 'hi',
        ))
            .isSuccess,
        isTrue,
      );
    });

    test('identifier length bounds are enforced', () async {
      final _Harness harness = _Harness(maxIdentifierLength: 32);
      expect(
        harness.controller.beginSession(editorNonce: 'e' * 33).failure,
        SystemKeyboardFailureCode.invalidRequest,
      );
      harness.begin();
      await harness.selectAlice();

      expect(
        (await harness.controller.prepareText(
          requestId: 'r' * 33,
          text: 'hi',
        ))
            .failure,
        SystemKeyboardFailureCode.invalidRequest,
      );
      expect(harness.backend.prepareCalls, 0);

      final String pendingId = await harness.prepareOne();
      expect(
        (await harness.controller.authorizeInsertion(
          requestId: harness._nextId('authorize'),
          pendingId: '$pendingId${'p' * 33}',
        ))
            .failure,
        SystemKeyboardFailureCode.noPendingExport,
      );
    });
  });

  group('inbound decode', () {
    test(
      'authenticated decode previews transiently and never rebinds',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        await harness.selectAlice();
        harness.backend.decoded = const SystemKeyboardBackendDecoded(
          contact: _bob,
          text: 'hi there',
          readOnce: false,
          expired: false,
        );

        final SystemKeyboardResult<SystemKeyboardDecodedPreview> result =
            await harness.controller.decodeCarrier(
          requestId: 'd1',
          carrier: 'carrier-in',
        );
        final SystemKeyboardDecodedPreview preview = result.requireValue;
        expect(preview.contactId, _bob.id);
        expect(preview.contactName, _bob.name);
        expect(preview.fingerprint, _bob.fingerprint);
        expect(preview.text, 'hi there');
        expect(harness.controller.selectedContact?.id, _alice.id);
        expect(harness.backend.markExportedCalls, 0);
      },
    );

    test(
      'any self-destruct schedule requires the app, leaking nothing',
      () async {
        const List<SystemKeyboardBackendDecoded> decodedCases =
            <SystemKeyboardBackendDecoded>[
          SystemKeyboardBackendDecoded(
            contact: _bob,
            text: 'secret',
            readOnce: true,
            expired: false,
          ),
          SystemKeyboardBackendDecoded(
            contact: _bob,
            text: 'secret',
            readOnce: false,
            expired: true,
          ),
          // Expiry configured but not reached yet: still not previewable.
          SystemKeyboardBackendDecoded(
            contact: _bob,
            text: 'secret',
            readOnce: false,
            expired: false,
            hasExpiry: true,
          ),
          SystemKeyboardBackendDecoded(
            contact: _bob,
            text: 'secret',
            readOnce: true,
            expired: true,
            hasExpiry: true,
          ),
        ];

        for (final SystemKeyboardBackendDecoded decoded in decodedCases) {
          final _Harness harness = _Harness();
          harness.begin();
          harness.backend.decoded = decoded;

          final SystemKeyboardResult<SystemKeyboardDecodedPreview> result =
              await harness.controller.decodeCarrier(
            requestId: 'd1',
            carrier: 'carrier-in',
          );
          expect(result.failure, SystemKeyboardFailureCode.openAppRequired);
          expect(result.value, isNull);
        }
      },
    );

    test(
      'empty, oversize, missing and failing decodes all say no message',
      () async {
        final _Harness harness = _Harness(maxCarrierCodeUnits: 8);
        harness.begin();

        expect(
          (await harness.controller.decodeCarrier(
            requestId: 'd1',
            carrier: '',
          ))
              .failure,
          SystemKeyboardFailureCode.noMessage,
        );
        expect(
          (await harness.controller.decodeCarrier(
            requestId: 'd2',
            carrier: 'x' * 9,
          ))
              .failure,
          SystemKeyboardFailureCode.noMessage,
        );
        expect(
          (await harness.controller.decodeCarrier(
            requestId: 'd3',
            carrier: 'abc',
          ))
              .failure,
          SystemKeyboardFailureCode.noMessage,
        );

        harness.backend.decodeError = StateError('boom');
        expect(
          (await harness.controller.decodeCarrier(
            requestId: 'd4',
            carrier: 'abcd',
          ))
              .failure,
          SystemKeyboardFailureCode.noMessage,
        );

        harness.backend.decodeError = null;
        harness.backend.decoded = const SystemKeyboardBackendDecoded(
          contact: _bob,
          text: '',
          readOnce: false,
          expired: false,
        );
        expect(
          (await harness.controller.decodeCarrier(
            requestId: 'd5',
            carrier: 'abcde',
          ))
              .failure,
          SystemKeyboardFailureCode.noMessage,
        );
        expect(harness.backend.decodeCalls, 3);
      },
    );
  });

  group('serialization, replay and invalidation', () {
    test('overlapping operations are busy and the backend runs once', () async {
      final _Harness harness = _Harness();
      harness.begin();
      final Completer<void> barrier = Completer<void>();
      harness.backend.listBarrier = barrier;

      final Future<SystemKeyboardResult<List<SystemKeyboardContact>>> first =
          harness.controller.listContacts(requestId: 'r1');
      await _tick();

      expect(
        (await harness.controller.listContacts(requestId: 'r2')).failure,
        SystemKeyboardFailureCode.busy,
      );
      barrier.complete();
      expect((await first).isSuccess, isTrue);
      expect(harness.backend.listCalls, 1);
    });

    test(
      'overlapped duplicate request id is rejected without a second read',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        final Completer<void> barrier = Completer<void>();
        harness.backend.listBarrier = barrier;

        final Future<SystemKeyboardResult<List<SystemKeyboardContact>>> first =
            harness.controller.listContacts(requestId: 'r1');
        expect(
          (await harness.controller.listContacts(requestId: 'r1')).failure,
          SystemKeyboardFailureCode.duplicateRequest,
        );
        barrier.complete();
        await first;
        expect(harness.backend.listCalls, 1);
      },
    );

    test('replayed request ids are rejected after completion', () async {
      final _Harness harness = _Harness();
      harness.begin();
      expect(
        (await harness.controller.listContacts(requestId: 'r1')).isSuccess,
        isTrue,
      );
      expect(
        (await harness.controller.listContacts(requestId: 'r1')).failure,
        SystemKeyboardFailureCode.duplicateRequest,
      );
      expect(harness.backend.listCalls, 1);
    });

    test(
      'request-id capacity fails closed instead of forgetting old ids',
      () async {
        final _Harness harness = _Harness(maxRememberedRequestIds: 2);
        harness.begin();
        expect(
          (await harness.controller.listContacts(requestId: 'r1')).isSuccess,
          isTrue,
        );
        expect(
          (await harness.controller.listContacts(requestId: 'r2')).isSuccess,
          isTrue,
        );
        expect(harness.backend.listCalls, 2);

        // Capacity reached: a fresh id is refused, and the oldest remembered id
        // is still refused, so nothing is ever replayable in this session.
        expect(
          (await harness.controller.listContacts(requestId: 'r3')).failure,
          SystemKeyboardFailureCode.duplicateRequest,
        );
        expect(
          (await harness.controller.listContacts(requestId: 'r1')).failure,
          SystemKeyboardFailureCode.duplicateRequest,
        );
        expect(harness.backend.listCalls, 2);

        // A new session clears the memory and admits a new id again.
        harness.controller.revoke();
        harness.begin();
        expect(
          (await harness.controller.listContacts(requestId: 'r3')).isSuccess,
          isTrue,
        );
        expect(harness.backend.listCalls, 3);
      },
    );

    test('identity change during an await suppresses the result', () async {
      final _Harness harness = _Harness();
      harness.begin();
      final Completer<void> barrier = Completer<void>();
      harness.backend.listBarrier = barrier;

      final Future<SystemKeyboardResult<List<SystemKeyboardContact>>> pending =
          harness.controller.listContacts(requestId: 'r1');
      harness.access.identityContextGeneration = 'ctx-2';
      harness.access.bump();
      barrier.complete();

      final SystemKeyboardResult<List<SystemKeyboardContact>> result =
          await pending;
      expect(result.failure, SystemKeyboardFailureCode.unavailable);
      expect(result.value, isNull);
    });

    test(
      'identity changing away and back during an await still suppresses',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        final Completer<void> barrier = Completer<void>();
        harness.backend.listBarrier = barrier;

        final Future<SystemKeyboardResult<List<SystemKeyboardContact>>>
            pending = harness.controller.listContacts(requestId: 'r1');
        harness.access.identityContextGeneration = 'ctx-2';
        harness.access.bump();
        harness.access.identityContextGeneration = 'ctx-1';
        harness.access.bump();
        barrier.complete();

        final SystemKeyboardResult<List<SystemKeyboardContact>> result =
            await pending;
        expect(result.failure, SystemKeyboardFailureCode.unavailable);
        expect(result.value, isNull);
      },
    );

    test('passphrase toggling during an await suppresses the result', () async {
      final _Harness harness = _Harness();
      harness.begin();
      final Completer<void> barrier = Completer<void>();
      harness.backend.listBarrier = barrier;

      final Future<SystemKeyboardResult<List<SystemKeyboardContact>>> pending =
          harness.controller.listContacts(requestId: 'r1');
      harness.access.passphraseActive = true;
      harness.access.bump();
      harness.access.passphraseActive = false;
      harness.access.bump();
      barrier.complete();

      final SystemKeyboardResult<List<SystemKeyboardContact>> result =
          await pending;
      expect(result.failure, SystemKeyboardFailureCode.unavailable);
      expect(result.value, isNull);
    });

    test(
      'revoke during a prepare suppresses output and drops the pending export',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        await harness.selectAlice();
        final Completer<void> barrier = Completer<void>();
        harness.backend.prepareBarrier = barrier;

        final Future<SystemKeyboardResult<SystemKeyboardPendingExport>>
            pending = harness.controller.prepareText(
          requestId: 'p1',
          text: 'hello',
        );
        await _tick();
        harness.controller.revoke();
        barrier.complete();

        final SystemKeyboardResult<SystemKeyboardPendingExport> result =
            await pending;
        expect(result.failure, SystemKeyboardFailureCode.unavailable);
        expect(result.value, isNull);

        harness.begin();
        expect(
          (await harness.controller.authorizeInsertion(
            requestId: 'a1',
            pendingId: 'skp0',
          ))
              .failure,
          SystemKeyboardFailureCode.noPendingExport,
        );
        expect(harness.backend.markExportedCalls, 0);
      },
    );

    test('decode invalidated mid-await yields no plaintext', () async {
      final _Harness harness = _Harness();
      harness.begin();
      harness.backend.decoded = const SystemKeyboardBackendDecoded(
        contact: _bob,
        text: 'secret',
        readOnce: false,
        expired: false,
      );
      final Completer<void> barrier = Completer<void>();
      harness.backend.decodeBarrier = barrier;

      final Future<SystemKeyboardResult<SystemKeyboardDecodedPreview>> pending =
          harness.controller.decodeCarrier(
        requestId: 'd1',
        carrier: 'carrier-in',
      );
      harness.access.passphraseActive = true;
      harness.access.bump();
      barrier.complete();

      final SystemKeyboardResult<SystemKeyboardDecodedPreview> result =
          await pending;
      expect(result.failure, SystemKeyboardFailureCode.unavailable);
      expect(result.value, isNull);
    });

    test(
      'invalidation during an acknowledgement suppresses the result',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        final String pendingId = await harness.authorizeOne();
        final Completer<void> barrier = Completer<void>();
        harness.backend.markBarrier = barrier;

        final Future<SystemKeyboardResult<SystemKeyboardAcknowledgement>>
            pending = harness.controller.acknowledgeInsertion(
          requestId: harness._nextId('ack'),
          pendingId: pendingId,
          commitText: true,
        );
        await _tick();
        harness.controller.revoke();
        barrier.complete();

        final SystemKeyboardResult<SystemKeyboardAcknowledgement> result =
            await pending;
        expect(result.failure, SystemKeyboardFailureCode.unavailable);
        expect(result.value, isNull);
        // The durable owner-side call was already running and is allowed to end.
        expect(harness.backend.markExportedCalls, 1);
      },
    );

    test(
      'an owner event between two calls revokes the session and its state',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        final String pendingId = await harness.prepareOne();
        expect(harness.controller.selectedContact?.id, _alice.id);

        // The generation advances while nothing is in flight.
        harness.ownerEvent();

        expect(harness.controller.selectedContact, isNull);
        expect(harness.controller.isSessionActive, isFalse);
        expect(harness.controller.hasPendingExport, isFalse);
        expect(
          (await harness.controller.listContacts(
            requestId: harness._nextId('list'),
          ))
              .failure,
          SystemKeyboardFailureCode.unavailable,
        );
        expect(
          (await harness.controller.prepareText(
            requestId: harness._nextId('prepare'),
            text: 'hi',
          ))
              .failure,
          SystemKeyboardFailureCode.unavailable,
        );
        expect(
          (await harness.controller.authorizeInsertion(
            requestId: harness._nextId('authorize'),
            pendingId: pendingId,
          ))
              .failure,
          SystemKeyboardFailureCode.unavailable,
        );
        expect(
          (await harness.controller.authorizeInsertion(
            requestId: harness._nextId('authorize'),
            pendingId: pendingId,
          ))
              .failure,
          SystemKeyboardFailureCode.unavailable,
        );
        expect(harness.backend.prepareCalls, 1);
        expect(harness.backend.markExportedCalls, 0);
        expect(harness.backend.listCalls, 1);

        // Only a new explicit begin plus a new confirmation restores anything.
        harness.begin();
        expect(harness.controller.selectedContact, isNull);
        expect(
          (await harness.controller.prepareText(
            requestId: harness._nextId('prepare'),
            text: 'hi',
          ))
              .failure,
          SystemKeyboardFailureCode.invalidSelection,
        );
        await harness.selectAlice();
        expect(
          (await harness.controller.prepareText(
            requestId: harness._nextId('prepare'),
            text: 'hi',
          ))
              .isSuccess,
          isTrue,
        );
      },
    );

    test(
      'lock cycling away and back between calls still requires a new session',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        final String pendingId = await harness.prepareOne();

        harness.access.lockUnlocked = false;
        harness.access.bump();
        harness.access.lockUnlocked = true;
        harness.access.bump();

        expect(
          (await harness.controller.authorizeInsertion(
            requestId: harness._nextId('authorize'),
            pendingId: pendingId,
          ))
              .failure,
          SystemKeyboardFailureCode.unavailable,
        );
        expect(harness.controller.selectedContact, isNull);

        harness.begin();
        expect(
          (await harness.controller.authorizeInsertion(
            requestId: harness._nextId('authorize'),
            pendingId: pendingId,
          ))
              .failure,
          SystemKeyboardFailureCode.noPendingExport,
        );
        expect(harness.backend.markExportedCalls, 0);
      },
    );

    test(
      'a deadline that elapses between calls permanently revokes the session',
      () async {
        final _Harness harness = _Harness();
        harness.begin();
        final String pendingId = await harness.prepareOne();
        harness.access.backgroundDeadline = const Duration(seconds: 100);

        harness.now = const Duration(seconds: 100);
        expect(
          (await harness.controller.listContacts(
            requestId: harness._nextId('list'),
          ))
              .failure,
          SystemKeyboardFailureCode.unavailable,
        );

        // Widening or removing the deadline must never reactivate the session.
        harness.access.backgroundDeadline = const Duration(hours: 1);
        harness.access.bump();
        expect(
          (await harness.controller.listContacts(
            requestId: harness._nextId('list'),
          ))
              .failure,
          SystemKeyboardFailureCode.unavailable,
        );
        harness.access.backgroundDeadline = null;
        harness.access.bump();
        expect(
          (await harness.controller.authorizeInsertion(
            requestId: harness._nextId('authorize'),
            pendingId: pendingId,
          ))
              .failure,
          SystemKeyboardFailureCode.unavailable,
        );
        expect(harness.controller.selectedContact, isNull);
        expect(harness.controller.hasPendingExport, isFalse);
        expect(harness.backend.markExportedCalls, 0);
      },
    );

    test('a backwards owner generation fails closed', () async {
      final _Harness harness = _Harness();
      harness.access.stateGeneration = 5;
      harness.begin();
      expect(
        (await harness.controller.listContacts(
          requestId: harness._nextId('list'),
        ))
            .isSuccess,
        isTrue,
      );

      harness.access.stateGeneration = 3;
      final SystemKeyboardResult<List<SystemKeyboardContact>> result =
          await harness.controller.listContacts(
        requestId: harness._nextId('list'),
      );
      expect(result.failure, SystemKeyboardFailureCode.unavailable);
      expect(harness.controller.isSessionActive, isFalse);
    });
  });
}
