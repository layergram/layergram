import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/key_schedule_v3.dart';
import 'package:layergram/core/crypto/v3/retention_policy_v3.dart';
import 'package:layergram/core/crypto/v3/triple_ratchet_state_v3.dart';

void main() {
  group('V3RetentionPolicy', () {
    test('freezes conservative normal and maximum profiles', () {
      final normal = V3RetentionPolicy.forProfile(V3RetentionProfile.normal);
      final maximum = V3RetentionPolicy.forProfile(V3RetentionProfile.maximum);

      expect(
        normal.skippedKeyLifetimeSeconds,
        180 * V3RetentionPolicy.secondsPerDay,
      );
      expect(
        normal.minimumProofLifetimeSeconds,
        365 * V3RetentionPolicy.secondsPerDay,
      );
      expect(
        maximum.skippedKeyLifetimeSeconds,
        30 * V3RetentionPolicy.secondsPerDay,
      );
      expect(
        maximum.minimumProofLifetimeSeconds,
        90 * V3RetentionPolicy.secondsPerDay,
      );
      expect(normal.automaticallyPurgesPendingInboxFrames, isFalse);
      expect(normal.automaticallyPurgesUnacknowledgedOutboxEntries, isFalse);
      expect(maximum.automaticallyPurgesPendingInboxFrames, isFalse);
      expect(maximum.automaticallyPurgesUnacknowledgedOutboxEntries, isFalse);
    });

    test('custom policy rejects a proof horizon shorter than skipped keys', () {
      expect(
        () => V3RetentionPolicy.custom(
          skippedKeyLifetimeSeconds: 100,
          minimumProofLifetimeSeconds: 99,
        ),
        throwsArgumentError,
      );
      expect(
        () => V3RetentionPolicy.custom(
          skippedKeyLifetimeSeconds: 0,
          minimumProofLifetimeSeconds: 100,
        ),
        throwsArgumentError,
      );
    });

    test('incoming proof becomes eligible only at the exact local boundary',
        () {
      final policy = V3RetentionPolicy.custom(
        skippedKeyLifetimeSeconds: 100,
        minimumProofLifetimeSeconds: 200,
      );
      final snapshot = _snapshot(receiveCounter: 2);
      final committed = DateTime.utc(2030, 1, 1);
      try {
        final early = policy.evaluateIncomingReplay(
          snapshot: snapshot,
          targetSessionId: _bytes(16, 0xa1),
          targetEpoch: 0,
          targetMessageCounter: 1,
          committedAt: committed,
          now: committed.add(const Duration(seconds: 199)),
        );
        expect(early.eligible, isFalse);
        expect(
          early.blockers,
          contains(V3RetentionBlocker.minimumAgeNotReached),
        );

        final boundary = policy.evaluateIncomingReplay(
          snapshot: snapshot,
          targetSessionId: _bytes(16, 0xa1),
          targetEpoch: 0,
          targetMessageCounter: 1,
          committedAt: committed,
          now: committed.add(const Duration(seconds: 200)),
        );
        expect(boundary.eligible, isTrue);
      } finally {
        snapshot.wipeSecrets();
      }
    });

    test('clock rollback, session mismatch and future epoch fail closed', () {
      final policy = V3RetentionPolicy.custom(
        skippedKeyLifetimeSeconds: 10,
        minimumProofLifetimeSeconds: 20,
      );
      final snapshot = _snapshot(
        lifecycle: V3RatchetLifecycle.broken,
        receiveCounter: 2,
      );
      final committed = DateTime.utc(2030, 1, 1);
      try {
        final decision = policy.evaluateIncomingReplay(
          snapshot: snapshot,
          targetSessionId: _bytes(16, 0xb1),
          targetEpoch: 1,
          targetMessageCounter: 1,
          committedAt: committed,
          now: committed.subtract(const Duration(seconds: 1)),
        );
        expect(decision.eligible, isFalse);
        expect(
          decision.blockers,
          containsAll(<V3RetentionBlocker>[
            V3RetentionBlocker.localClockMovedBackward,
            V3RetentionBlocker.sessionMismatch,
            V3RetentionBlocker.snapshotNotActive,
            V3RetentionBlocker.targetEpochAhead,
          ]),
        );
      } finally {
        snapshot.wipeSecrets();
      }
    });

    test('unexpired PQ skipped key blocks retirement and expiry releases it',
        () {
      final policy = V3RetentionPolicy.custom(
        skippedKeyLifetimeSeconds: 10,
        minimumProofLifetimeSeconds: 20,
      );
      final committed = DateTime.fromMillisecondsSinceEpoch(
        1000 * 1000,
        isUtc: true,
      );
      final snapshot = _snapshot(
        receiveCounter: 2,
        skipped: <V3PqSkippedMessageKey>[
          V3PqSkippedMessageKey(
            epoch: 0,
            messageCounter: 1,
            messageKey: _bytes(32, 0xe1),
            expiresAtUnixSeconds: 1100,
          ),
        ],
      );
      try {
        final stillUsable = policy.evaluateIncomingReplay(
          snapshot: snapshot,
          targetSessionId: _bytes(16, 0xa1),
          targetEpoch: 0,
          targetMessageCounter: 1,
          committedAt: committed,
          now: DateTime.fromMillisecondsSinceEpoch(1050 * 1000, isUtc: true),
        );
        expect(stillUsable.eligible, isFalse);
        expect(
          stillUsable.blockers,
          contains(V3RetentionBlocker.pqSkippedKeyStillUsable),
        );

        final expired = policy.evaluateIncomingReplay(
          snapshot: snapshot,
          targetSessionId: _bytes(16, 0xa1),
          targetEpoch: 0,
          targetMessageCounter: 1,
          committedAt: committed,
          now: DateTime.fromMillisecondsSinceEpoch(1100 * 1000, isUtc: true),
        );
        expect(expired.eligible, isTrue);
      } finally {
        snapshot.wipeSecrets();
      }
    });

    test('retained PQ chain blocks counters it can still derive', () {
      final policy = V3RetentionPolicy.custom(
        skippedKeyLifetimeSeconds: 10,
        minimumProofLifetimeSeconds: 20,
      );
      final snapshot = _snapshot(receiveCounter: 2);
      final committed = DateTime.utc(2030, 1, 1);
      try {
        final decision = policy.evaluateIncomingReplay(
          snapshot: snapshot,
          targetSessionId: _bytes(16, 0xa1),
          targetEpoch: 0,
          targetMessageCounter: 2,
          committedAt: committed,
          now: committed.add(const Duration(seconds: 20)),
        );
        expect(decision.eligible, isFalse);
        expect(
          decision.blockers,
          contains(V3RetentionBlocker.pqReceiveChainCanStillDerive),
        );
      } finally {
        snapshot.wipeSecrets();
      }
    });

    test('an older epoch no longer retained is independently retired', () {
      final policy = V3RetentionPolicy.custom(
        skippedKeyLifetimeSeconds: 10,
        minimumProofLifetimeSeconds: 20,
      );
      final snapshot = _snapshot(
        currentEpoch: 1,
        receivingEpoch: 1,
        epochStates: <V3PqEpochState>[
          V3PqEpochState(
            epoch: 1,
            sendingChainKey: _bytes(32, 0xb2),
            receivingChainKey: _bytes(32, 0xd2),
            receiveCounter: 1,
          ),
        ],
      );
      final committed = DateTime.utc(2030, 1, 1);
      try {
        final decision = policy.evaluateIncomingReplay(
          snapshot: snapshot,
          targetSessionId: _bytes(16, 0xa1),
          targetEpoch: 0,
          targetMessageCounter: 99,
          committedAt: committed,
          now: committed.add(const Duration(seconds: 20)),
        );
        expect(decision.eligible, isTrue);
      } finally {
        snapshot.wipeSecrets();
      }
    });

    test('a sealed old receiving chain does not block retirement', () {
      final policy = V3RetentionPolicy.custom(
        skippedKeyLifetimeSeconds: 10,
        minimumProofLifetimeSeconds: 20,
      );
      final snapshot = _snapshot(
        currentEpoch: 1,
        receivingEpoch: 1,
        epochStates: <V3PqEpochState>[
          V3PqEpochState(
            epoch: 0,
            sendingChainKey: _bytes(32, 0x92),
          ),
          V3PqEpochState(
            epoch: 1,
            sendingChainKey: _bytes(32, 0xb2),
            receivingChainKey: _bytes(32, 0xd2),
            receiveCounter: 1,
          ),
        ],
      );
      final committed = DateTime.utc(2030, 1, 1);
      try {
        final decision = policy.evaluateIncomingReplay(
          snapshot: snapshot,
          targetSessionId: _bytes(16, 0xa1),
          targetEpoch: 0,
          targetMessageCounter: 99,
          committedAt: committed,
          now: committed.add(const Duration(seconds: 20)),
        );
        expect(decision.eligible, isTrue);
      } finally {
        snapshot.wipeSecrets();
      }
    });

    test('outgoing completion requires age, complete ACK and absent outbox',
        () {
      final policy = V3RetentionPolicy.custom(
        skippedKeyLifetimeSeconds: 10,
        minimumProofLifetimeSeconds: 20,
      );
      final completed = DateTime.utc(2030, 1, 1);
      final blocked = policy.evaluateOutgoingCompletion(
        fullyAcknowledged: false,
        outboxEntryAbsent: false,
        completedAt: completed,
        now: completed.add(const Duration(seconds: 19)),
      );
      expect(blocked.eligible, isFalse);
      expect(
        blocked.blockers,
        containsAll(<V3RetentionBlocker>[
          V3RetentionBlocker.minimumAgeNotReached,
          V3RetentionBlocker.acknowledgementIncomplete,
          V3RetentionBlocker.outboxEntryStillPresent,
        ]),
      );

      final eligible = policy.evaluateOutgoingCompletion(
        fullyAcknowledged: true,
        outboxEntryAbsent: true,
        completedAt: completed,
        now: completed.add(const Duration(seconds: 20)),
      );
      expect(eligible.eligible, isTrue);
    });
  });
}

V3TripleRatchetState _snapshot({
  V3RatchetLifecycle lifecycle = V3RatchetLifecycle.active,
  int currentEpoch = 0,
  int receivingEpoch = 0,
  int receiveCounter = 1,
  List<V3PqEpochState>? epochStates,
  List<V3PqSkippedMessageKey> skipped = const <V3PqSkippedMessageKey>[],
}) {
  return V3TripleRatchetState(
    role: V3SessionRole.initiator,
    lifecycle: lifecycle,
    revision: 1,
    sessionId: _bytes(16, 0xa1),
    transcriptDigest: _bytes(48, 0x11),
    initiatorRoutingBinding: _bytes(32, 0x21),
    responderRoutingBinding: _bytes(32, 0x61),
    initiatorToResponderAckRootKey: _bytes(32, 0x81),
    responderToInitiatorAckRootKey: _bytes(32, 0xc1),
    ecRootKey: _bytes(32, 0x12),
    ecSendingChainKey: _bytes(32, 0x32),
    ecReceivingChainKey: _bytes(32, 0x52),
    ecLocalDhPrivateKey: _bytes(32, 0x72),
    ecLocalDhPublicKey: _hex(
      '5c117f7fa14c242bc843fd1bac49ad870c37b8e615da1b4fefe64859aff5245d',
    ),
    ecRemoteDhPublicKey: _bytes(32, 0x32),
    ecSendCounter: 1,
    ecReceiveCounter: 1,
    ecPreviousSendingChainLength: 0,
    pqRootKey: _bytes(32, 0x92),
    sckaStateSealKey: _bytes(32, 0xb2),
    pqCurrentEpoch: currentEpoch,
    pqSendingEpoch: currentEpoch,
    pqReceivingEpoch: receivingEpoch,
    pqEpochStates: epochStates ??
        <V3PqEpochState>[
          V3PqEpochState(
            epoch: currentEpoch,
            sendingChainKey: _bytes(32, 0xb2),
            receivingChainKey: _bytes(32, 0xd2),
            receiveCounter: receiveCounter,
          ),
        ],
    pqSkippedMessageKeys: skipped,
    nativeSckaState: _bytes(64, 0xe2),
  );
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

Uint8List _hex(String value) => Uint8List.fromList(
      List<int>.generate(
        value.length ~/ 2,
        (index) =>
            int.parse(value.substring(index * 2, index * 2 + 2), radix: 16),
      ),
    );
