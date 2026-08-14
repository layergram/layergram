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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'ec_double_ratchet_v3.dart';
import 'key_schedule_v3.dart';
import 'lmf_v3.dart';
import 'pq_message_ratchet_v3.dart';
import 'sparse_pq_ratchet_v3.dart';
import 'triple_ratchet_state_v3.dart';

/// One exact, non-mutating EC + Sparse-PQ candidate.
///
/// A send candidate may seal frames immediately, but its [nextSnapshot] still
/// has to be durably joined to the exact sealed outbox entry. A receive
/// candidate is not authenticated merely because this object exists: the
/// caller must first open the LMF frame(s) with [secretKey], then atomically
/// commit [nextSnapshot] with the resulting application effect.
final class V3TripleRatchetTransition {
  V3TripleRatchetTransition._({
    required this.header,
    required this.metadata,
    required V3MessageKeyMaterial keyMaterial,
    required this.nextSnapshot,
  }) : _keyMaterial = keyMaterial;

  final V3HybridRatchetHeader header;
  final V3LmfMessageMetadata metadata;
  final V3MessageKeyMaterial _keyMaterial;
  final V3TripleRatchetState nextSnapshot;
  bool _isClosed = false;

  bool get isClosed => _isClosed;

  SecretKey get secretKey {
    _ensureOpen();
    return _keyMaterial.secretKey;
  }

  Uint8List get messageId {
    _ensureOpen();
    return _keyMaterial.messageId;
  }

  Future<Uint8List> nonceForFragment({
    required int fragmentIndex,
    required int fragmentCount,
    required int assembledPlaintextLength,
  }) async {
    _ensureOpen();
    final encodedHeader = V3HybridRatchetHeaderCodec.encode(header);
    final headerDigest = V3LmfFrameCodec.digestHybridRatchetHeader(header);
    try {
      return await _keyMaterial.nonceForFragment(
        fragmentIndex: fragmentIndex,
        fragmentCount: fragmentCount,
        assembledPlaintextLength: assembledPlaintextLength,
        hybridRatchetHeaderLength: encodedHeader.length,
        hybridRatchetHeaderDigest: headerDigest,
      );
    } finally {
      _wipe(encodedHeader);
      _wipe(headerDigest);
    }
  }

  Future<bool> matchesNonce({
    required Uint8List candidate,
    required int fragmentIndex,
    required int fragmentCount,
    required int assembledPlaintextLength,
  }) async {
    _ensureOpen();
    final expected = await nonceForFragment(
      fragmentIndex: fragmentIndex,
      fragmentCount: fragmentCount,
      assembledPlaintextLength: assembledPlaintextLength,
    );
    try {
      return _constantTimeEqual(candidate, expected);
    } finally {
      _wipe(expected);
    }
  }

  void close() {
    if (_isClosed) return;
    _keyMaterial.close();
    nextSnapshot.wipeSecrets();
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 Triple Ratchet transition is closed');
    }
  }
}

/// Candidate-only orchestration for the inactive protocol-v3 Triple Ratchet.
///
/// Both branches always advance together and the hybrid key schedule binds the
/// visible PQ coordinates, direction, frame kind, and session. This class does
/// not persist, export, or activate a session by itself.
abstract final class V3TripleRatchetEngine {
  static Future<V3TripleRatchetTransition> send({
    required V3TripleRatchetState snapshot,
    required V3SckaBackend backend,
    required V3LmfFrameKind kind,
    int expiresAtUnixSeconds = 0,
  }) async {
    _validateRatchetKind(kind);
    final direction = _outgoingDirection(snapshot.role);
    final sessionId = snapshot.sessionId;
    final bindings = _bindings(snapshot, direction);
    final ecState = await V3EcDoubleRatchet.restore(snapshot);
    V3EcRatchetTransition? ec;
    V3PqMessageRatchetTransition? pq;
    V3MessageKeyMaterial? keys;
    V3TripleRatchetState? next;
    Uint8List? ecMessageKey;
    Uint8List? pqMessageKey;
    Uint8List? messageId;
    try {
      ec = await V3EcDoubleRatchet.send(ecState);
      pq = await V3PqMessageRatchet.send(
        snapshot: snapshot,
        backend: backend,
      );
      final header = V3HybridRatchetHeader(
        ecHeader: ec.header,
        sckaMessage: pq.message,
      );
      ecMessageKey = ec.messageKey;
      pqMessageKey = pq.messageKey;
      keys = await V3KeySchedule.deriveMessage(
        ecMessageKey: ecMessageKey,
        pqMessageKey: pqMessageKey,
        sessionId: sessionId,
        direction: direction,
        kind: kind,
        epoch: pq.message.sendingEpoch,
        messageCounter: pq.message.messageCounter,
      );
      messageId = keys.messageId;
      final metadata = V3LmfMessageMetadata(
        kind: kind,
        senderBinding: bindings.sender,
        recipientBinding: bindings.recipient,
        messageId: messageId,
        sessionId: sessionId,
        epoch: pq.message.sendingEpoch,
        messageCounter: pq.message.messageCounter,
        expiresAtUnixSeconds: expiresAtUnixSeconds,
      );
      next = pq.toTripleRatchetSnapshot(
        previous: snapshot,
        ecCandidate: ec.nextState,
      );
      final result = V3TripleRatchetTransition._(
        header: header,
        metadata: metadata,
        keyMaterial: keys,
        nextSnapshot: next,
      );
      keys = null;
      next = null;
      return result;
    } finally {
      if (messageId != null) _wipe(messageId);
      if (ecMessageKey != null) _wipe(ecMessageKey);
      if (pqMessageKey != null) _wipe(pqMessageKey);
      keys?.close();
      next?.wipeSecrets();
      pq?.close();
      ec?.close();
      ecState.close();
      _wipe(sessionId);
      _wipe(bindings.sender);
      _wipe(bindings.recipient);
    }
  }

  /// Derives a receive candidate from fragment zero and verifies all visible
  /// key-schedule bindings before its key can be used for AEAD authentication.
  static Future<V3TripleRatchetTransition> receiveFirstFragment({
    required V3TripleRatchetState snapshot,
    required V3SckaBackend backend,
    required V3LmfMessageMetadata metadata,
    required V3HybridRatchetHeader header,
    required Uint8List nonce,
    required int fragmentCount,
    required int assembledPlaintextLength,
    required int nowUnixSeconds,
    required int skippedKeyLifetimeSeconds,
  }) async {
    _validateRatchetKind(metadata.kind);
    final direction = _incomingDirection(snapshot.role);
    final sessionId = snapshot.sessionId;
    final bindings = _bindings(snapshot, direction);
    _validateIncomingCoordinates(
      metadata: metadata,
      header: header,
      sessionId: sessionId,
      senderBinding: bindings.sender,
      recipientBinding: bindings.recipient,
    );
    final ecState = await V3EcDoubleRatchet.restore(snapshot);
    V3EcRatchetTransition? ec;
    V3PqMessageRatchetTransition? pq;
    V3MessageKeyMaterial? keys;
    V3TripleRatchetState? next;
    Uint8List? ecMessageKey;
    Uint8List? pqMessageKey;
    try {
      ec = await V3EcDoubleRatchet.receive(
        state: ecState,
        header: header.ecHeader,
        nowUnixSeconds: nowUnixSeconds,
        skippedKeyLifetimeSeconds: skippedKeyLifetimeSeconds,
      );
      pq = await V3PqMessageRatchet.receive(
        snapshot: snapshot,
        backend: backend,
        message: header.sckaMessage,
        nowUnixSeconds: nowUnixSeconds,
        skippedKeyLifetimeSeconds: skippedKeyLifetimeSeconds,
      );
      ecMessageKey = ec.messageKey;
      pqMessageKey = pq.messageKey;
      keys = await V3KeySchedule.deriveMessage(
        ecMessageKey: ecMessageKey,
        pqMessageKey: pqMessageKey,
        sessionId: sessionId,
        direction: direction,
        kind: metadata.kind,
        epoch: metadata.epoch,
        messageCounter: metadata.messageCounter,
      );
      if (!keys.matchesMessageId(metadata.messageId)) {
        throw const FormatException(
          'Layergram v3 derived message identifier mismatch',
        );
      }
      final encodedHeader = V3HybridRatchetHeaderCodec.encode(header);
      final headerDigest = V3LmfFrameCodec.digestHybridRatchetHeader(header);
      try {
        final nonceMatches = await keys.matchesNonce(
          candidate: nonce,
          fragmentIndex: 0,
          fragmentCount: fragmentCount,
          assembledPlaintextLength: assembledPlaintextLength,
          hybridRatchetHeaderLength: encodedHeader.length,
          hybridRatchetHeaderDigest: headerDigest,
        );
        if (!nonceMatches) {
          throw const FormatException(
            'Layergram v3 derived fragment nonce mismatch',
          );
        }
      } finally {
        _wipe(encodedHeader);
        _wipe(headerDigest);
      }
      next = pq.toTripleRatchetSnapshot(
        previous: snapshot,
        ecCandidate: ec.nextState,
      );
      final result = V3TripleRatchetTransition._(
        header: header,
        metadata: metadata,
        keyMaterial: keys,
        nextSnapshot: next,
      );
      keys = null;
      next = null;
      return result;
    } finally {
      if (ecMessageKey != null) _wipe(ecMessageKey);
      if (pqMessageKey != null) _wipe(pqMessageKey);
      keys?.close();
      next?.wipeSecrets();
      pq?.close();
      ec?.close();
      ecState.close();
      _wipe(sessionId);
      _wipe(bindings.sender);
      _wipe(bindings.recipient);
    }
  }
}

void _validateRatchetKind(V3LmfFrameKind kind) {
  if (kind != V3LmfFrameKind.application && kind != V3LmfFrameKind.pqRatchet) {
    throw ArgumentError.value(
      kind,
      'kind',
      'Triple Ratchet transitions require application or PQ-control frames',
    );
  }
}

void _validateIncomingCoordinates({
  required V3LmfMessageMetadata metadata,
  required V3HybridRatchetHeader header,
  required Uint8List sessionId,
  required Uint8List senderBinding,
  required Uint8List recipientBinding,
}) {
  if (metadata.suite != V3LmfSuite.hybridX25519MlKem768Aes256Gcm ||
      metadata.flags != 0 ||
      !_constantTimeEqual(metadata.sessionId, sessionId) ||
      !_constantTimeEqual(metadata.senderBinding, senderBinding) ||
      !_constantTimeEqual(metadata.recipientBinding, recipientBinding) ||
      metadata.epoch != header.sckaMessage.sendingEpoch ||
      metadata.messageCounter != header.sckaMessage.messageCounter) {
    throw const FormatException(
      'Layergram v3 frame coordinates do not match the session and HR3',
    );
  }
}

({Uint8List sender, Uint8List recipient}) _bindings(
  V3TripleRatchetState snapshot,
  V3TrafficDirection direction,
) {
  final initiator = snapshot.initiatorRoutingBinding;
  final responder = snapshot.responderRoutingBinding;
  return switch (direction) {
    V3TrafficDirection.initiatorToResponder => (
        sender: initiator,
        recipient: responder
      ),
    V3TrafficDirection.responderToInitiator => (
        sender: responder,
        recipient: initiator
      ),
  };
}

V3TrafficDirection _outgoingDirection(V3SessionRole role) =>
    role == V3SessionRole.initiator
        ? V3TrafficDirection.initiatorToResponder
        : V3TrafficDirection.responderToInitiator;

V3TrafficDirection _incomingDirection(V3SessionRole role) =>
    role == V3SessionRole.initiator
        ? V3TrafficDirection.responderToInitiator
        : V3TrafficDirection.initiatorToResponder;

bool _constantTimeEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
