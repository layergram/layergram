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
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'lmf_v3.dart';
import 'lmf_v3_persistence.dart';
import 'retention_policy_v3.dart';
import 'session_commit_controller_v3.dart';
import 'sparse_pq_ratchet_v3.dart';
import 'triple_ratchet_engine_v3.dart';
import 'triple_ratchet_state_v3.dart';

typedef V3SessionSnapshotProvider = Future<V3TripleRatchetState> Function(
  Uint8List sessionId,
);

/// Resolves exact receive keys without committing a Triple Ratchet candidate.
///
/// Only one candidate per session may be pending. Competing fragment-zero
/// messages therefore remain sealed and durable instead of forking one
/// immutable committed snapshot. Continuations are resolved after their
/// fragment zero arrives, including through a later `resumeDeferred` pass.
final class V3SessionRatchetKeyResolver {
  V3SessionRatchetKeyResolver({
    required V3SckaBackend backend,
    required V3SessionSnapshotProvider snapshotProvider,
    this.skippedKeyLifetimeSeconds =
        V3RetentionPolicy.normalSkippedKeyLifetimeSeconds,
  })  : _backend = backend,
        _snapshotProvider = snapshotProvider {
    if (skippedKeyLifetimeSeconds <= 0) {
      throw ArgumentError.value(
        skippedKeyLifetimeSeconds,
        'skippedKeyLifetimeSeconds',
      );
    }
  }

  final V3SckaBackend _backend;
  final V3SessionSnapshotProvider _snapshotProvider;
  final int skippedKeyLifetimeSeconds;
  final Map<String, _PendingCandidate> _pendingBySession =
      <String, _PendingCandidate>{};
  Future<void> _operationTail = Future<void>.value();
  bool _closed = false;

  int get pendingCandidateCount => _pendingBySession.length;

  Future<SecretKey?> resolve(
    V3LmfFrame frame, {
    int? nowUnixSeconds,
  }) {
    return _serialized(() async {
      _ensureOpen();
      final sessionId = frame.metadata.sessionId;
      final sessionKey = _sessionKey(sessionId);
      final assemblyId = V3LmfFrameCodec.assemblyId(frame);
      final existing = _pendingBySession[sessionKey];
      if (existing != null) {
        if (existing.assemblyId != assemblyId) return null;
        if (!await existing.matches(frame)) {
          throw const FormatException(
            'Layergram v3 continuation does not match pending candidate',
          );
        }
        return existing.transition.secretKey;
      }
      if (frame.fragmentIndex != 0 || frame.hybridRatchetHeader == null) {
        return null;
      }

      final snapshot = await _snapshotProvider(sessionId);
      V3TripleRatchetTransition? transition;
      try {
        transition = await V3TripleRatchetEngine.receiveFirstFragment(
          snapshot: snapshot,
          backend: _backend,
          metadata: frame.metadata,
          header: frame.hybridRatchetHeader!,
          nonce: frame.nonce,
          fragmentCount: frame.fragmentCount,
          assembledPlaintextLength: frame.assembledPlaintextLength,
          nowUnixSeconds: nowUnixSeconds ??
              DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
          skippedKeyLifetimeSeconds: skippedKeyLifetimeSeconds,
        );
        final pending = _PendingCandidate(
          assemblyId: assemblyId,
          transition: transition,
          fragmentCount: frame.fragmentCount,
          assembledPlaintextLength: frame.assembledPlaintextLength,
        );
        _pendingBySession[sessionKey] = pending;
        transition = null;
        return pending.transition.secretKey;
      } finally {
        transition?.close();
        snapshot.wipeSecrets();
        _wipe(sessionId);
      }
    });
  }

  /// Transfers the candidate only after the inbox authenticated every frame.
  Future<V3TripleRatchetTransition> takeForDelivery(
    V3LmfDurableDelivery delivery,
  ) {
    return _serialized(() async {
      _ensureOpen();
      return _removePendingForDelivery(delivery).pending.takeTransition();
    });
  }

  /// Atomically binds the authenticated candidate to its exact AR3/TR3 effect.
  Future<V3SessionCommitResult> commitDelivery({
    required V3LmfDurableDelivery delivery,
    required V3SessionCommitController controller,
    DateTime? persistedAt,
  }) {
    return _serialized(() async {
      _ensureOpen();
      final removed = _removePendingForDelivery(delivery);
      final transition = removed.pending.transition;
      final expectedRevision = transition.nextSnapshot.revision - 1;
      try {
        final result = await controller.commitDelivery(
          delivery: delivery,
          expectedRevision: expectedRevision,
          persistedAt: persistedAt,
          transitionBuilder: (_, currentSnapshot, hybridRatchetHeader) {
            final candidateHeader =
                V3HybridRatchetHeaderCodec.encode(transition.header);
            final deliveryHeader =
                V3HybridRatchetHeaderCodec.encode(hybridRatchetHeader);
            try {
              if (currentSnapshot.revision != expectedRevision ||
                  !_constantTimeEqual(candidateHeader, deliveryHeader)) {
                throw const FormatException(
                  'Layergram v3 durable delivery changed ratchet candidate',
                );
              }
              return _copySnapshot(transition.nextSnapshot);
            } finally {
              _wipe(candidateHeader);
              _wipe(deliveryHeader);
            }
          },
        );
        transition.close();
        return result;
      } catch (_) {
        if (controller.requiresRecovery) {
          transition.close();
        } else {
          V3TripleRatchetState? current;
          var canRetry = false;
          final sessionId = delivery.frames.first.metadata.sessionId;
          try {
            current = await controller.snapshotForSession(sessionId);
            canRetry = current.revision == expectedRevision &&
                !_pendingBySession.containsKey(removed.sessionKey);
          } catch (_) {
            canRetry = false;
          } finally {
            current?.wipeSecrets();
            _wipe(sessionId);
          }
          if (canRetry) {
            _pendingBySession[removed.sessionKey] = removed.pending;
          } else {
            transition.close();
          }
        }
        rethrow;
      }
    });
  }

  ({String sessionKey, _PendingCandidate pending}) _removePendingForDelivery(
      V3LmfDurableDelivery delivery) {
    if (delivery.frames.isEmpty) {
      throw StateError('Layergram v3 delivery has no frames');
    }
    final target = delivery.frames.first;
    final key = _sessionKey(target.metadata.sessionId);
    final pending = _pendingBySession[key];
    if (pending == null || pending.assemblyId != delivery.assemblyId) {
      throw StateError(
          'Layergram v3 delivery has no matching ratchet candidate');
    }
    if (delivery.frames.length != pending.fragmentCount) {
      throw const FormatException(
        'Layergram v3 complete delivery shape changed before commit',
      );
    }
    _pendingBySession.remove(key);
    return (sessionKey: key, pending: pending);
  }

  /// Drops a candidate only if its unauthenticated fragment zero failed AEAD.
  Future<void> discardUnauthenticatedFirstFragment(V3LmfFrame frame) {
    return _serialized(() async {
      if (_closed || frame.fragmentIndex != 0) return;
      final key = _sessionKey(frame.metadata.sessionId);
      final pending = _pendingBySession[key];
      if (pending != null &&
          pending.assemblyId == V3LmfFrameCodec.assemblyId(frame)) {
        _pendingBySession.remove(key);
        pending.close();
      }
    });
  }

  Future<void> discardDelivery(V3LmfDurableDelivery delivery) {
    return _serialized(() async {
      if (_closed || delivery.frames.isEmpty) return;
      final key = _sessionKey(delivery.frames.first.metadata.sessionId);
      final pending = _pendingBySession[key];
      if (pending != null && pending.assemblyId == delivery.assemblyId) {
        _pendingBySession.remove(key);
        pending.close();
      }
    });
  }

  Future<void> close() {
    return _serialized(() async {
      if (_closed) return;
      _closed = true;
      for (final pending in _pendingBySession.values) {
        pending.close();
      }
      _pendingBySession.clear();
    });
  }

  Future<T> _serialized<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    final previous = _operationTail;
    _operationTail = previous.catchError((_) {}).then((_) async {
      try {
        completer.complete(await action());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('Layergram v3 session key resolver is closed');
    }
  }
}

final class _PendingCandidate {
  _PendingCandidate({
    required this.assemblyId,
    required V3TripleRatchetTransition transition,
    required this.fragmentCount,
    required this.assembledPlaintextLength,
  }) : _transition = transition;

  final String assemblyId;
  V3TripleRatchetTransition? _transition;
  final int fragmentCount;
  final int assembledPlaintextLength;

  V3TripleRatchetTransition get transition {
    final value = _transition;
    if (value == null) {
      throw StateError('Layergram v3 pending transition was transferred');
    }
    return value;
  }

  Future<bool> matches(V3LmfFrame frame) async {
    final expected = transition.metadata;
    if (frame.fragmentCount != fragmentCount ||
        frame.assembledPlaintextLength != assembledPlaintextLength ||
        frame.metadata.kind != expected.kind ||
        frame.metadata.suite != expected.suite ||
        frame.metadata.flags != expected.flags ||
        frame.metadata.epoch != expected.epoch ||
        frame.metadata.messageCounter != expected.messageCounter ||
        frame.metadata.expiresAtUnixSeconds != expected.expiresAtUnixSeconds ||
        !_constantTimeEqual(
            frame.metadata.senderBinding, expected.senderBinding) ||
        !_constantTimeEqual(
          frame.metadata.recipientBinding,
          expected.recipientBinding,
        ) ||
        !_constantTimeEqual(frame.metadata.messageId, expected.messageId) ||
        !_constantTimeEqual(frame.metadata.sessionId, expected.sessionId)) {
      return false;
    }
    final expectedHeader = V3HybridRatchetHeaderCodec.encode(transition.header);
    final expectedDigest =
        V3LmfFrameCodec.digestHybridRatchetHeader(transition.header);
    try {
      if (frame.hybridRatchetHeaderLength != expectedHeader.length ||
          !_constantTimeEqual(
            frame.hybridRatchetHeaderDigest,
            expectedDigest,
          ) ||
          (frame.fragmentIndex == 0) !=
              (frame.hybridRatchetHeaderBytes != null)) {
        return false;
      }
      return await transition.matchesNonce(
        candidate: frame.nonce,
        fragmentIndex: frame.fragmentIndex,
        fragmentCount: fragmentCount,
        assembledPlaintextLength: assembledPlaintextLength,
      );
    } finally {
      _wipe(expectedHeader);
      _wipe(expectedDigest);
    }
  }

  V3TripleRatchetTransition takeTransition() {
    final value = transition;
    _transition = null;
    return value;
  }

  void close() {
    _transition?.close();
    _transition = null;
  }
}

String _sessionKey(Uint8List sessionId) {
  if (sessionId.length != V3LmfFrameCodec.sessionIdBytes ||
      _isAllZero(sessionId)) {
    throw ArgumentError.value(sessionId, 'sessionId');
  }
  return base64UrlEncode(sessionId).replaceAll('=', '');
}

bool _constantTimeEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

bool _isAllZero(List<int> value) {
  var result = 0;
  for (final byte in value) {
    result |= byte;
  }
  return result == 0;
}

V3TripleRatchetState _copySnapshot(V3TripleRatchetState snapshot) {
  final encoded = V3TripleRatchetStateCodec.encode(snapshot);
  try {
    return V3TripleRatchetStateCodec.decode(encoded);
  } finally {
    _wipe(encoded);
  }
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
