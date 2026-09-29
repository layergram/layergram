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
import 'package:layergram/features/system_keyboard/system_keyboard_runtime_session.dart';

const String kNonce = 'editor-nonce-1';
const String kIdentity = 'identity-1';
const int kIdle = 20000;

SystemKeyboardContact _contact(String id, [String name = 'Ada']) =>
    SystemKeyboardContact(
      id: id,
      name: name,
      fingerprint: 'fp-$id',
    );

Map<Object?, Object?> _request(
  String operation, {
  String requestId = 'r1',
  String nonce = kNonce,
  Map<Object?, Object?> extra = const <Object?, Object?>{},
}) =>
    <Object?, Object?>{
      'operation': operation,
      'editorNonce': nonce,
      'requestId': requestId,
      ...extra,
    };

final class _FakeBackend implements SystemKeyboardBackend {
  _FakeBackend({this.contact});

  SystemKeyboardContact? contact;
  Completer<void>? authorizeGate;
  int listCalls = 0;
  int prepareCalls = 0;
  int markExportedCalls = 0;
  int decodeCalls = 0;
  SystemKeyboardOutboundRequest? lastOutbound;
  String? lastMarkedHandle;
  String? lastCarrier;
  SystemKeyboardBackendDecoded? decoded;

  @override
  Future<List<SystemKeyboardContact>> listApprovedContacts() async {
    listCalls++;
    final SystemKeyboardContact? current = contact;
    return current == null
        ? <SystemKeyboardContact>[]
        : <SystemKeyboardContact>[current];
  }

  @override
  Future<SystemKeyboardBackendExport?> prepareTextOutbound(
    SystemKeyboardOutboundRequest request,
  ) async {
    prepareCalls++;
    lastOutbound = request;
    return SystemKeyboardBackendExport(
      exportHandle: 'handle-1',
      carriers: <String>['carrier-1'],
      ciphertextCodeUnits: 9,
    );
  }

  @override
  Future<void> markExported(String exportHandle) async {
    markExportedCalls++;
    lastMarkedHandle = exportHandle;
  }

  @override
  Future<SystemKeyboardBackendDecoded?> decodeCarrier(String carrier) async {
    decodeCalls++;
    lastCarrier = carrier;
    return decoded;
  }
}

final class _Harness {
  _Harness(
      {int? idleMillis, bool scramble = false, SystemKeyboardContact? contact})
      : backend = _FakeBackend(contact: contact) {
    session = SystemKeyboardRuntimeSession(
      backend: backend,
      identityId: kIdentity,
      editorNonce: kNonce,
      authorizedIdleMillis: idleMillis ?? kIdle,
      monotonicNow: () => now,
      nativeIsAuthorized: () async {
        nativeCalls++;
        return nativeAuthorized;
      },
      scramble: scramble,
    );
  }

  final _FakeBackend backend;
  late final SystemKeyboardRuntimeSession session;
  Duration now = Duration.zero;
  bool nativeAuthorized = true;
  int nativeCalls = 0;

  void advance(int millis) {
    now += Duration(milliseconds: millis);
  }
}

void main() {
  group('construction', () {
    test('rejects malformed identity, nonce and idle window', () {
      final SystemKeyboardBackend backend = _FakeBackend();
      SystemKeyboardRuntimeSession build({
        String identity = kIdentity,
        String nonce = kNonce,
        int idle = kIdle,
      }) =>
          SystemKeyboardRuntimeSession(
            backend: backend,
            identityId: identity,
            editorNonce: nonce,
            authorizedIdleMillis: idle,
            monotonicNow: () => Duration.zero,
            nativeIsAuthorized: () async => true,
          );

      expect(() => build(identity: ''), throwsArgumentError);
      expect(() => build(identity: 'a' * 129), throwsArgumentError);
      expect(() => build(nonce: ''), throwsArgumentError);
      expect(() => build(nonce: 'a' * 129), throwsArgumentError);
      expect(() => build(idle: 0), throwsArgumentError);
      expect(() => build(idle: 300001), throwsArgumentError);
      expect(build(idle: 1), isNotNull);
      expect(build(idle: 300000), isNotNull);
    });

    test('does not call the native check until a request arrives', () {
      final _Harness harness = _Harness();
      expect(harness.nativeCalls, 0);
      expect(harness.session.hasNativeAuthorization, isFalse);
    });
  });

  group('idle lifetime', () {
    test('continuous touches over three minutes keep a 20s window alive',
        () async {
      final _Harness harness = _Harness();
      expect(
        (await harness.session.handleRequest(_request('begin')))['status'],
        'ok',
      );
      for (int i = 0; i < 10; i++) {
        harness.advance(18000);
        expect(harness.session.recordUserInteraction(), isTrue);
      }
      expect(harness.now, const Duration(milliseconds: 180000));
      expect(harness.session.isAuthorized, isTrue);
      expect(
        harness.session.remainingIdleMillis,
        greaterThan(0),
      );

      // Polling alone must never renew: the window still expires 20s after the
      // last physical touch.
      for (int i = 0; i < 10; i++) {
        harness.advance(2000);
        harness.session.isAuthorized;
      }
      expect(harness.session.isAuthorized, isFalse);
      expect(
        (await harness.session
            .handleRequest(_request('heartbeat', requestId: 'r2')))['status'],
        'unavailable',
      );
      expect(harness.nativeCalls, greaterThan(0));
    });

    test('polling alone expires exactly at the deadline', () async {
      final _Harness harness = _Harness();
      await harness.session.handleRequest(_request('begin'));
      for (int i = 0; i < 9; i++) {
        harness.advance(2000);
        expect(harness.session.remainingIdleMillis, greaterThan(0));
      }
      harness.advance(1999);
      expect(
        (await harness.session.handleRequest(
          _request('heartbeat', requestId: 'r3'),
        ))['status'],
        'ok',
      );
      harness.advance(1);
      expect(
        (await harness.session.handleRequest(
          _request('heartbeat', requestId: 'r4'),
        ))['status'],
        'unavailable',
      );
    });

    test('a late touch cannot revive an expired window', () async {
      final _Harness harness = _Harness();
      await harness.session.handleRequest(_request('begin'));
      harness.advance(kIdle);
      expect(harness.session.isAuthorized, isFalse);
      expect(harness.session.recordUserInteraction(), isFalse);
      expect(
        (await harness.session
            .handleRequest(_request('heartbeat', requestId: 'r5')))['status'],
        'unavailable',
      );
    });

    test('a backwards clock closes the window permanently', () {
      final _Harness harness = _Harness();
      harness.advance(5000);
      expect(harness.session.isAuthorized, isTrue);
      harness.now = const Duration(milliseconds: 4999);
      expect(harness.session.isAuthorized, isFalse);
      harness.now = const Duration(milliseconds: 6000);
      expect(harness.session.recordUserInteraction(), isFalse);
      expect(harness.session.isClosed, isTrue);
    });
  });

  group('nonce and begin binding', () {
    test('fresh editor drops recipient without renewing the idle grant',
        () async {
      final h = _Harness(contact: _contact('c1'));
      expect(
          (await h.session.handleRequest(_request('begin')))['status'], 'ok');
      expect(
          (await h.session.handleRequest(_request('select',
              requestId: 'select',
              extra: {'contactId': 'c1', 'confirm': true})))['status'],
          'ok');
      h.advance(15000);
      final deadline = h.session.deadlineMonotonicMillis;
      expect(await h.session.rebindEditor('editor-nonce-2'), isTrue);
      expect(h.session.deadlineMonotonicMillis, deadline);
      expect(
          (await h.session.handleRequest(
              _request('begin', nonce: 'editor-nonce-2')))['status'],
          'ok');
      expect(
          (await h.session.handleRequest(_request('prepare',
              nonce: 'editor-nonce-2',
              requestId: 'prepare-2',
              extra: {'text': 'must choose contact again'})))['status'],
          'invalidSelection');
      h.advance(5000);
      expect(h.session.isAuthorized, isFalse,
          reason: 'rebind cannot restart the inactivity countdown');
    });

    test('mismatched nonce and a second begin are denied', () async {
      final _Harness harness = _Harness();
      expect(
        (await harness.session.handleRequest(
          _request('begin', nonce: 'other'),
        ))['status'],
        'unavailable',
      );
      expect(harness.session.isAuthorized, isTrue);
      expect(
        (await harness.session.handleRequest(_request('begin')))['status'],
        'ok',
      );
      expect(
        (await harness.session.handleRequest(
          _request('begin', requestId: 'r6'),
        ))['status'],
        'unavailable',
      );
      expect(
        (await harness.session.handleRequest(
          _request('contacts', nonce: 'other', requestId: 'r7'),
        ))['status'],
        'unavailable',
      );
      expect(harness.session.isAuthorized, isFalse);
    });

    test('end from another nonce cannot terminate the rightful session',
        () async {
      final _Harness harness = _Harness();
      await harness.session.handleRequest(_request('begin'));
      expect(
        (await harness.session.handleRequest(
          _request('end', nonce: 'other', requestId: 'r8'),
        ))['status'],
        'unavailable',
      );
      expect(harness.session.isAuthorized, isTrue);
      expect(
        (await harness.session
            .handleRequest(_request('contacts', requestId: 'r9')))['status'],
        'ok',
      );
      final Map<String, Object?> ended = await harness.session.handleRequest(
        _request('end', requestId: 'r10'),
      );
      expect(ended['status'], 'ok');
      expect(harness.session.isAuthorized, isFalse);
      expect(harness.session.isClosed, isTrue);
    });
  });

  group('native authorization', () {
    test('revoked grant yields no carrier and closes the session', () async {
      final _Harness harness = _Harness(
        contact: _contact('c1'),
      );
      await harness.session.handleRequest(_request('begin'));
      await harness.session
          .handleRequest(_request('contacts', requestId: 'r11'));
      await harness.session.handleRequest(_request(
        'select',
        requestId: 'r12',
        extra: <Object?, Object?>{'contactId': 'c1', 'confirm': true},
      ));
      final Map<String, Object?> prepared = await harness.session.handleRequest(
        _request('prepare',
            requestId: 'r13', extra: <Object?, Object?>{'text': 'hi'}),
      );
      expect(prepared['status'], 'ok');
      final String pendingId =
          (prepared['data']! as Map<String, Object?>)['pendingId']! as String;

      harness.nativeAuthorized = false;
      final Map<String, Object?> revoked = await harness.session.handleRequest(
        _request(
          'authorize',
          requestId: 'r14',
          extra: <Object?, Object?>{'pendingId': pendingId},
        ),
      );
      expect(revoked, <String, Object?>{'status': 'unavailable'});
      expect(revoked.containsKey('data'), isFalse);
      expect(harness.session.isClosed, isTrue);
      expect(harness.session.isAuthorized, isFalse);
      expect(harness.session.hasNativeAuthorization, isTrue);
    });

    test('a delayed native check crossing expiry suppresses ciphertext',
        () async {
      final _Harness harness = _Harness(contact: _contact('c1'));
      await harness.session.handleRequest(_request('begin'));
      await harness.session
          .handleRequest(_request('contacts', requestId: 'r21'));
      await harness.session.handleRequest(_request(
        'select',
        requestId: 'r22',
        extra: <Object?, Object?>{'contactId': 'c1', 'confirm': true},
      ));
      final Map<String, Object?> prepared = await harness.session.handleRequest(
        _request('prepare',
            requestId: 'r23', extra: <Object?, Object?>{'text': 'hi'}),
      );
      final String pendingId =
          (prepared['data']! as Map<String, Object?>)['pendingId']! as String;

      harness.backend.authorizeGate = Completer<void>();
      final Future<Map<String, Object?>> pending =
          harness.session.handleRequest(_request(
        'authorize',
        requestId: 'r24',
        extra: <Object?, Object?>{'pendingId': pendingId},
      ));
      // The authorize call is in flight when the idle window elapses.
      harness.advance(kIdle);
      harness.backend.authorizeGate!.complete();
      final Map<String, Object?> late = await pending;
      expect(late, <String, Object?>{'status': 'unavailable'});
      expect(late.containsKey('data'), isFalse);
      expect(harness.session.isClosed, isTrue);
    });
  });

  group('success shapes', () {
    test('each response has the exact channel shape and types', () async {
      final _Harness harness =
          _Harness(scramble: true, contact: _contact('c1'));
      final Map<String, Object?> begun = await harness.session.handleRequest(
        _request('begin'),
      );
      expect(begun.keys.toSet(),
          <String>{'status', 'processingMillis', 'leaseMillis', 'data'});
      expect(begun['status'], isA<String>());
      expect(begun['processingMillis'], isA<int>());
      expect(begun['processingMillis'] as int, inInclusiveRange(0, 30000));
      expect(begun['leaseMillis'], isA<int>());
      expect(begun['leaseMillis'] as int, inInclusiveRange(1, 1000));
      expect(
        (begun['data']! as Map<String, Object?>)['scramble'],
        isTrue,
      );

      final Map<String, Object?> beat = await harness.session.handleRequest(
        _request('heartbeat', requestId: 'r31'),
      );
      expect(beat['status'], 'ok');
      expect(beat['processingMillis'], 0);
      expect(beat['leaseMillis'], isA<int>());
      expect(beat['data'], <String, Object?>{});

      final Map<String, Object?> failure = await harness.session.handleRequest(
        _request('contacts', requestId: 'r32', nonce: 'other'),
      );
      expect(failure, <String, Object?>{'status': 'unavailable'});
    });

    test('contacts/select/prepare/authorize/ack reuse the controller',
        () async {
      final _Harness harness =
          _Harness(scramble: true, contact: _contact('c1'));
      await harness.session.handleRequest(_request('begin'));

      final Map<String, Object?> contacts = await harness.session.handleRequest(
        _request('contacts', requestId: 'r41'),
      );
      expect(contacts['status'], 'ok');
      expect(contacts['data'], <String, Object?>{
        'contacts': <Map<String, Object?>>[
          <String, Object?>{'id': 'c1', 'name': 'Ada', 'fingerprint': 'fp-c1'},
        ],
      });

      final Map<String, Object?> selected = await harness.session.handleRequest(
        _request(
          'select',
          requestId: 'r42',
          extra: <Object?, Object?>{'contactId': 'c1', 'confirm': true},
        ),
      );
      expect(selected['status'], 'ok');
      expect(selected['data'], <String, Object?>{
        'id': 'c1',
        'name': 'Ada',
        'fingerprint': 'fp-c1',
      });

      final Map<String, Object?> prepared = await harness.session.handleRequest(
        _request(
          'prepare',
          requestId: 'r43',
          extra: <Object?, Object?>{'text': 'hello'},
        ),
      );
      expect(prepared['status'], 'ok');
      final String pendingId =
          (prepared['data']! as Map<String, Object?>)['pendingId']! as String;
      expect(pendingId, isNotEmpty);
      expect(harness.backend.prepareCalls, 1);
      expect(harness.backend.lastOutbound!.contactId, 'c1');
      expect(harness.backend.lastOutbound!.contactFingerprint, 'fp-c1');
      expect(harness.backend.lastOutbound!.editorNonce, kNonce);
      expect(harness.backend.lastOutbound!.text, 'hello');

      final Map<String, Object?> authorized =
          await harness.session.handleRequest(
        _request(
          'authorize',
          requestId: 'r44',
          extra: <Object?, Object?>{'pendingId': pendingId},
        ),
      );
      expect(authorized['status'], 'ok');
      expect(authorized['data'], <String, Object?>{'carrier': 'carrier-1'});

      final Map<String, Object?> acked = await harness.session.handleRequest(
        _request(
          'ack',
          requestId: 'r45',
          extra: <Object?, Object?>{'pendingId': pendingId, 'commitText': true},
        ),
      );
      expect(acked['status'], 'ok');
      expect(acked['data'], <String, Object?>{'exported': true});
      expect(harness.backend.markExportedCalls, 1);
      expect(harness.backend.lastMarkedHandle, 'handle-1');
      expect(harness.nativeCalls, greaterThanOrEqualTo(8));
    });

    test('a duplicate request id is rejected after one use', () async {
      final _Harness harness =
          _Harness(scramble: true, contact: _contact('c1'));
      await harness.session.handleRequest(_request('begin'));
      expect(
        (await harness.session
            .handleRequest(_request('contacts', requestId: 'r51')))['status'],
        'ok',
      );
      expect(
        (await harness.session
            .handleRequest(_request('contacts', requestId: 'r51')))['status'],
        'duplicateRequest',
      );
    });
  });

  group('decode', () {
    test('decode does not automatically select the sender', () async {
      final _Harness harness = _Harness(contact: _contact('sender'));
      harness.backend.decoded = SystemKeyboardBackendDecoded(
        contact: _contact('sender', 'Bob'),
        text: 'inbound',
        readOnce: false,
        expired: false,
      );
      await harness.session.handleRequest(_request('begin'));
      await harness.session
          .handleRequest(_request('contacts', requestId: 'r61'));
      await harness.session.handleRequest(_request(
        'select',
        requestId: 'r62',
        extra: <Object?, Object?>{'contactId': 'sender', 'confirm': true},
      ));
      expect(harness.session.isAuthorized, isTrue);

      final Map<String, Object?> decoded = await harness.session.handleRequest(
        _request(
          'decode',
          requestId: 'r63',
          extra: <Object?, Object?>{'carrier': 'carrier-in'},
        ),
      );
      expect(decoded['status'], 'ok');
      expect(decoded['data'], <String, Object?>{
        'contactId': 'sender',
        'contactName': 'Bob',
        'fingerprint': 'fp-sender',
        'text': 'inbound',
      });
      expect(harness.backend.decodeCalls, 1);
      expect(harness.backend.lastCarrier, 'carrier-in');
      // No automatic sender selection: the explicit selection is untouched.
      expect(harness.session.isAuthorized, isTrue);
    });

    test('a self-destructing message requires the full app', () async {
      final _Harness harness = _Harness(contact: _contact('sender'));
      harness.backend.decoded = SystemKeyboardBackendDecoded(
        contact: _contact('sender', 'Bob'),
        text: 'inbound',
        readOnce: true,
        expired: false,
      );
      await harness.session.handleRequest(_request('begin'));
      final Map<String, Object?> denied = await harness.session.handleRequest(
        _request(
          'decode',
          requestId: 'r64',
          extra: <Object?, Object?>{'carrier': 'carrier-in'},
        ),
      );
      expect(denied, <String, Object?>{'status': 'openAppRequired'});
    });
  });

  group('request shape validation', () {
    test('malformed requests are rejected without touching the backend',
        () async {
      final _Harness harness = _Harness(scramble: true);
      await harness.session.handleRequest(_request('begin'));
      expect(
        (await harness.session.handleRequest(<Object?, Object?>{}))['status'],
        'invalidRequest',
      );
      expect(
        (await harness.session.handleRequest(_request('unknown')))['status'],
        'invalidRequest',
      );
      expect(
        (await harness.session
            .handleRequest(_request('select', requestId: 'r71')))['status'],
        'invalidRequest',
      );
      expect(
        (await harness.session
            .handleRequest(_request('ack', requestId: 'r72')))['status'],
        'invalidRequest',
      );
      expect(harness.backend.listCalls, 0);
    });
  });
}
