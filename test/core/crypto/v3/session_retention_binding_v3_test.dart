import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/handshake_persistence_v3.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/local_identity_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';
import 'package:layergram/core/crypto/v3/retention_policy_v3.dart';
import 'package:layergram/core/crypto/v3/session_retention_binding_v3.dart';

void main() {
  test('mixed scope selects each durable session retention profile', () {
    final normalId = _bytes(16, 0x11);
    final maximumId = _bytes(16, 0x51);
    final sessions = <V3CompletedHandshakeSession>[
      _session(normalId, V3HandshakeMode.normal),
      _session(maximumId, V3HandshakeMode.maximum),
    ];

    expect(
      V3SessionRetentionBinding.skippedKeyLifetimeSeconds(
        sessionId: normalId,
        completedSessions: sessions,
      ),
      V3RetentionPolicy.normalSkippedKeyLifetimeSeconds,
    );
    expect(
      V3SessionRetentionBinding.skippedKeyLifetimeSeconds(
        sessionId: maximumId,
        completedSessions: sessions,
      ),
      V3RetentionPolicy.maximumSkippedKeyLifetimeSeconds,
    );
  });

  test('missing and duplicate durable bindings fail closed', () {
    final sessionId = _bytes(16, 0x21);
    expect(
      () => V3SessionRetentionBinding.skippedKeyLifetimeSeconds(
        sessionId: sessionId,
        completedSessions: const <V3CompletedHandshakeSession>[],
      ),
      throwsA(isA<V3LmfPersistenceConflictException>()),
    );
    final duplicate = _session(sessionId, V3HandshakeMode.maximum);
    expect(
      () => V3SessionRetentionBinding.skippedKeyLifetimeSeconds(
        sessionId: sessionId,
        completedSessions: [duplicate, duplicate],
      ),
      throwsA(isA<V3LmfPersistenceConflictException>()),
    );
  });
}

V3CompletedHandshakeSession _session(
  Uint8List sessionId,
  V3HandshakeMode mode,
) =>
    V3CompletedHandshakeSession(
      handshakeId: _id(16, 0x71),
      role: V3SessionRole.initiator,
      mode: mode,
      localIdentityDigest: _id(48, 0x81),
      remoteIdentityDigest: _id(48, 0xb1),
      localDeviceId: _id(16, 0xc1),
      remoteDeviceId: _id(16, 0xd1),
      sessionId: base64UrlEncode(sessionId).replaceAll('=', ''),
      checkpointDigest: _id(32, 0xe1),
      completedAt: DateTime.utc(2026, 8, 28),
    );

String _id(int length, int start) =>
    base64UrlEncode(_bytes(length, start)).replaceAll('=', '');

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );
