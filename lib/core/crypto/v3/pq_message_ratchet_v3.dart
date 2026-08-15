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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'ec_double_ratchet_v3.dart';
import 'key_schedule_v3.dart';
import 'sparse_pq_ratchet_v3.dart';
import 'triple_ratchet_binding_v3.dart';
import 'triple_ratchet_state_v3.dart';

/// One non-mutating Sparse-PQ application-message transition.
///
/// It owns the exact SCKA candidate export, derived PQ message key, complete
/// epoch-chain state, and skipped-key set. The transition is usable only as
/// part of a matching EC transition and must be closed if authentication or
/// durable commit fails.
final class V3PqMessageRatchetTransition {
  V3PqMessageRatchetTransition._({
    required this.message,
    required Uint8List messageKey,
    required Uint8List rootKey,
    required this.currentEpoch,
    required this.sendingEpoch,
    required this.receivingEpoch,
    required List<V3PqEpochState> epochStates,
    required List<V3PqSkippedMessageKey> skippedMessageKeys,
    required Uint8List nativeSckaState,
    required Uint8List priorSnapshotBinding,
  })  : _messageKey = messageKey,
        _rootKey = rootKey,
        _epochStates = epochStates,
        _skippedMessageKeys = skippedMessageKeys,
        _nativeSckaState = nativeSckaState,
        _priorSnapshotBinding = priorSnapshotBinding;

  final V3SckaMessage message;
  final Uint8List _messageKey;
  final Uint8List _rootKey;
  final int currentEpoch;
  final int sendingEpoch;
  final int receivingEpoch;
  final List<V3PqEpochState> _epochStates;
  final List<V3PqSkippedMessageKey> _skippedMessageKeys;
  final Uint8List _nativeSckaState;
  final Uint8List _priorSnapshotBinding;
  bool _isClosed = false;

  bool get isClosed => _isClosed;

  Uint8List get messageKey {
    _ensureOpen();
    return Uint8List.fromList(_messageKey);
  }

  /// Combines this exact PQ candidate with the matching EC candidate in one
  /// revision of [previous]. No intermediate one-ratchet snapshot is created.
  V3TripleRatchetState toTripleRatchetSnapshot({
    required V3TripleRatchetState previous,
    required V3EcDoubleRatchetState ecCandidate,
  }) {
    _ensureOpen();
    final previousBinding = v3TripleRatchetPriorSnapshotBinding(previous);
    try {
      if (previous.lifecycle != V3RatchetLifecycle.active ||
          previous.role != ecCandidate.role ||
          ecCandidate.snapshotRevision != previous.revision + 1 ||
          !_bytesEqual(previous.sessionId, ecCandidate.sessionId) ||
          !_bytesEqual(_priorSnapshotBinding, previousBinding) ||
          !ecCandidate.matchesPriorSnapshotBinding(previousBinding)) {
        throw StateError(
          'Layergram v3 EC/PQ candidates do not share one prior snapshot',
        );
      }
    } finally {
      _wipe(previousBinding);
    }

    final ecRoot = ecCandidate.rootKey;
    final ecSending = ecCandidate.sendingChainKey;
    final ecReceiving = ecCandidate.receivingChainKey;
    final ecPrivate = ecCandidate.localDhPrivateKey;
    final ecPublic = ecCandidate.localDhPublicKey;
    final ecRemote = ecCandidate.remoteDhPublicKey;
    final ecSkipped = ecCandidate.skippedMessageKeys;
    try {
      return previous.replaceHybridState(
        expectedRevision: previous.revision,
        ecRootKey: ecRoot,
        ecSendingChainKey: ecSending,
        ecReceivingChainKey: ecReceiving,
        ecLocalDhPrivateKey: ecPrivate,
        ecLocalDhPublicKey: ecPublic,
        ecRemoteDhPublicKey: ecRemote,
        ecSendCounter: ecCandidate.sendCounter,
        ecReceiveCounter: ecCandidate.receiveCounter,
        ecPreviousSendingChainLength: ecCandidate.previousSendingChainLength,
        ecSkippedMessageKeys: ecSkipped,
        pqRootKey: _rootKey,
        pqCurrentEpoch: currentEpoch,
        pqSendingEpoch: sendingEpoch,
        pqReceivingEpoch: receivingEpoch,
        pqEpochStates: _epochStates,
        pqSkippedMessageKeys: _skippedMessageKeys,
        nativeSckaState: _nativeSckaState,
      );
    } finally {
      _wipe(ecRoot);
      _wipe(ecSending);
      if (ecReceiving != null) _wipe(ecReceiving);
      _wipe(ecPrivate);
      _wipe(ecPublic);
      _wipe(ecRemote);
      for (final value in ecSkipped) {
        value.wipeSecret();
      }
    }
  }

  void close() {
    if (_isClosed) return;
    _wipe(_messageKey);
    _wipe(_rootKey);
    _wipe(_nativeSckaState);
    _wipe(_priorSnapshotBinding);
    for (final value in _epochStates) {
      value.wipeSecrets();
    }
    for (final value in _skippedMessageKeys) {
      value.wipeSecret();
    }
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 PQ message transition is closed');
    }
  }
}

/// Layergram's deterministic KDF-chain layer above a reviewed SCKA backend.
///
/// Signal's SCKA returns a public message, the newest mutually usable epoch,
/// and occasionally one new epoch secret. This class alone chooses Layergram's
/// per-epoch message counter, derives directional chains, retains skipped
/// message keys, and never mutates the committed [V3TripleRatchetState].
abstract final class V3PqMessageRatchet {
  static const int maxCounter = 0x7fffffffffffffff;
  static const int maxSkippedMessageKeys =
      V3TripleRatchetStateCodec.maxSkippedKeysPerRatchet;

  static final Hkdf _rootKdf = Hkdf(
    hmac: Hmac.sha256(),
    outputLength: 96,
  );
  static final Hmac _chainHmac = Hmac.sha256();
  static final List<int> _rootLabel = utf8.encode(
    'layergram/v3/sparse-pq/root\u0000',
  );
  static final List<int> _messageKeyLabel = utf8.encode(
    'layergram/v3/sparse-pq/message-key\u0000',
  );
  static final List<int> _nextChainKeyLabel = utf8.encode(
    'layergram/v3/sparse-pq/next-chain-key\u0000',
  );

  static Future<V3PqMessageRatchetTransition> send({
    required V3TripleRatchetState snapshot,
    required V3SckaBackend backend,
  }) async {
    _validateSnapshotForTransition(snapshot);
    final sessionId = snapshot.sessionId;
    final nativeState = snapshot.nativeSckaState;
    final stateSealKey = snapshot.sckaStateSealKey;
    var priorSnapshotBinding = v3TripleRatchetPriorSnapshotBinding(snapshot);
    var root = snapshot.pqRootKey;
    var epochs = snapshot.pqEpochStates.toList(growable: true);
    var skipped = snapshot.pqSkippedMessageKeys.toList(growable: true);
    V3SckaSendCandidate? scka;
    Uint8List? nextNative;
    Uint8List? messageKey;
    try {
      scka = await V3SparsePqRatchet.sendCandidate(
        backend: backend,
        role: snapshot.role,
        sessionId: sessionId,
        authenticatedState: nativeState,
        stateSealKey: stateSealKey,
        expectedStateRevision: snapshot.revision,
      );
      final incorporated = await _incorporateEpochSecret(
        role: snapshot.role,
        sessionId: sessionId,
        rootKey: root,
        currentEpoch: snapshot.pqCurrentEpoch,
        epochs: epochs,
        epochSecret: scka.epochSecret,
      );
      if (!identical(incorporated.rootKey, root)) {
        _wipe(root);
        root = incorporated.rootKey;
      }
      var currentEpoch = incorporated.currentEpoch;
      var sendingEpoch = snapshot.pqSendingEpoch;
      final targetEpoch = scka.sendingEpoch;
      if (targetEpoch < sendingEpoch || targetEpoch > currentEpoch) {
        throw StateError('Layergram v3 SCKA sending epoch moved out of range');
      }
      if (targetEpoch > sendingEpoch) {
        if (targetEpoch != sendingEpoch + 1) {
          throw StateError('Layergram v3 SCKA sending epoch skipped a value');
        }
        _sealSendingChain(epochs, sendingEpoch);
        sendingEpoch = targetEpoch;
      }

      final target = _epoch(epochs, targetEpoch);
      final chain = target.sendingChainKey;
      if (chain == null) {
        throw StateError('Layergram v3 PQ sending chain is unavailable');
      }
      if (target.sendCounter >= maxCounter) {
        _wipe(chain);
        throw StateError('Layergram v3 PQ send counter is exhausted');
      }
      late final _ChainStep step;
      try {
        step = await _chainStep(chain, target.sendCounter);
      } finally {
        _wipe(chain);
      }
      messageKey = step.messageKey;
      _replaceSendingEpoch(
        epochs: epochs,
        current: target,
        nextSendingChainKey: step.nextChainKey,
        nextSendCounter: target.sendCounter + 1,
      );
      _wipe(step.nextChainKey);
      _pruneEpochs(
        epochs: epochs,
        skipped: skipped,
        sendingEpoch: sendingEpoch,
        receivingEpoch: snapshot.pqReceivingEpoch,
      );

      nextNative = scka.nextAuthenticatedState;
      final transition = V3PqMessageRatchetTransition._(
        message: scka.messageForCounter(target.sendCounter),
        messageKey: messageKey,
        rootKey: root,
        currentEpoch: currentEpoch,
        sendingEpoch: sendingEpoch,
        receivingEpoch: snapshot.pqReceivingEpoch,
        epochStates: epochs,
        skippedMessageKeys: skipped,
        nativeSckaState: nextNative,
        priorSnapshotBinding: priorSnapshotBinding,
      );
      messageKey = null;
      root = Uint8List(0);
      nextNative = null;
      priorSnapshotBinding = Uint8List(0);
      epochs = <V3PqEpochState>[];
      skipped = <V3PqSkippedMessageKey>[];
      return transition;
    } finally {
      scka?.close();
      _wipe(sessionId);
      _wipe(nativeState);
      _wipe(stateSealKey);
      _wipe(root);
      if (nextNative != null) _wipe(nextNative);
      _wipe(priorSnapshotBinding);
      if (messageKey != null) _wipe(messageKey);
      _wipeEpochs(epochs);
      _wipeSkipped(skipped);
    }
  }

  static Future<V3PqMessageRatchetTransition> receive({
    required V3TripleRatchetState snapshot,
    required V3SckaBackend backend,
    required V3SckaMessage message,
    required int nowUnixSeconds,
    required int skippedKeyLifetimeSeconds,
  }) async {
    _validateSnapshotForTransition(snapshot);
    _validatePositive(nowUnixSeconds, 'nowUnixSeconds');
    _validatePositive(skippedKeyLifetimeSeconds, 'skippedKeyLifetimeSeconds');
    if (nowUnixSeconds > maxCounter - skippedKeyLifetimeSeconds) {
      throw ArgumentError('Layergram v3 PQ skipped-key expiry overflows');
    }
    final expiresAt = nowUnixSeconds + skippedKeyLifetimeSeconds;
    final sessionId = snapshot.sessionId;
    final nativeState = snapshot.nativeSckaState;
    final stateSealKey = snapshot.sckaStateSealKey;
    var priorSnapshotBinding = v3TripleRatchetPriorSnapshotBinding(snapshot);
    var root = snapshot.pqRootKey;
    var epochs = snapshot.pqEpochStates.toList(growable: true);
    var skipped = snapshot.pqSkippedMessageKeys.toList(growable: true);
    V3SckaReceiveCandidate? scka;
    Uint8List? nextNative;
    Uint8List? messageKey;
    try {
      for (var index = skipped.length - 1; index >= 0; index--) {
        if (skipped[index].expiresAtUnixSeconds <= nowUnixSeconds) {
          skipped.removeAt(index).wipeSecret();
        }
      }
      scka = await V3SparsePqRatchet.receiveCandidate(
        backend: backend,
        role: snapshot.role,
        sessionId: sessionId,
        authenticatedState: nativeState,
        stateSealKey: stateSealKey,
        expectedStateRevision: snapshot.revision,
        message: message,
      );
      final incorporated = await _incorporateEpochSecret(
        role: snapshot.role,
        sessionId: sessionId,
        rootKey: root,
        currentEpoch: snapshot.pqCurrentEpoch,
        epochs: epochs,
        epochSecret: scka.epochSecret,
      );
      if (!identical(incorporated.rootKey, root)) {
        _wipe(root);
        root = incorporated.rootKey;
      }
      final currentEpoch = incorporated.currentEpoch;
      var receivingEpoch = snapshot.pqReceivingEpoch;
      final targetEpoch = scka.receivingEpoch;
      if (targetEpoch > currentEpoch) {
        throw StateError(
          'Layergram v3 SCKA receiving epoch moved out of range',
        );
      }
      if (targetEpoch > receivingEpoch) {
        if (targetEpoch != receivingEpoch + 1) {
          throw StateError('Layergram v3 SCKA receiving epoch skipped a value');
        }
        receivingEpoch = targetEpoch;
      }

      for (var index = 0; index < skipped.length; index++) {
        final candidate = skipped[index];
        if (candidate.epoch == targetEpoch &&
            candidate.messageCounter == message.messageCounter) {
          final selectedMessageKey = candidate.messageKey;
          messageKey = selectedMessageKey;
          skipped.removeAt(index).wipeSecret();
          _pruneEpochs(
            epochs: epochs,
            skipped: skipped,
            sendingEpoch: snapshot.pqSendingEpoch,
            receivingEpoch: receivingEpoch,
          );
          final transition = V3PqMessageRatchetTransition._(
            message: message,
            messageKey: selectedMessageKey,
            rootKey: root,
            currentEpoch: currentEpoch,
            sendingEpoch: snapshot.pqSendingEpoch,
            receivingEpoch: receivingEpoch,
            epochStates: epochs,
            skippedMessageKeys: skipped,
            nativeSckaState: nextNative = scka.nextAuthenticatedState,
            priorSnapshotBinding: priorSnapshotBinding,
          );
          messageKey = null;
          root = Uint8List(0);
          nextNative = null;
          priorSnapshotBinding = Uint8List(0);
          epochs = <V3PqEpochState>[];
          skipped = <V3PqSkippedMessageKey>[];
          return transition;
        }
      }

      final target = _retainedEpoch(epochs, targetEpoch);
      if (target == null) {
        throw const FormatException(
          'Layergram v3 PQ message epoch is no longer retained',
        );
      }
      final initialChain = target.receivingChainKey;
      if (initialChain == null) {
        throw StateError('Layergram v3 PQ receiving chain is unavailable');
      }
      var chain = initialChain;
      if (message.messageCounter < target.receiveCounter) {
        _wipe(chain);
        throw const FormatException(
          'Layergram v3 PQ message key is stale or already consumed',
        );
      }
      final missing = message.messageCounter - target.receiveCounter;
      if (missing > maxSkippedMessageKeys ||
          skipped.length + missing > maxSkippedMessageKeys) {
        _wipe(chain);
        throw const FormatException(
          'Layergram v3 PQ skipped-key limit exceeded',
        );
      }
      var counter = target.receiveCounter;
      while (counter < message.messageCounter) {
        late final _ChainStep step;
        try {
          step = await _chainStep(chain, counter);
        } finally {
          _wipe(chain);
        }
        chain = step.nextChainKey;
        skipped.add(
          V3PqSkippedMessageKey(
            epoch: targetEpoch,
            messageCounter: counter,
            messageKey: step.messageKey,
            expiresAtUnixSeconds: expiresAt,
          ),
        );
        _wipe(step.messageKey);
        counter++;
      }
      if (counter >= maxCounter) {
        _wipe(chain);
        throw StateError('Layergram v3 PQ receive counter is exhausted');
      }
      late final _ChainStep targetStep;
      try {
        targetStep = await _chainStep(chain, counter);
      } finally {
        _wipe(chain);
      }
      final selectedMessageKey = targetStep.messageKey;
      messageKey = selectedMessageKey;
      _replaceReceivingEpoch(
        epochs: epochs,
        current: target,
        nextReceivingChainKey: targetStep.nextChainKey,
        nextReceiveCounter: counter + 1,
      );
      _wipe(targetStep.nextChainKey);
      skipped.sort(_compareSkipped);
      _pruneEpochs(
        epochs: epochs,
        skipped: skipped,
        sendingEpoch: snapshot.pqSendingEpoch,
        receivingEpoch: receivingEpoch,
      );
      nextNative = scka.nextAuthenticatedState;
      final transition = V3PqMessageRatchetTransition._(
        message: message,
        messageKey: selectedMessageKey,
        rootKey: root,
        currentEpoch: currentEpoch,
        sendingEpoch: snapshot.pqSendingEpoch,
        receivingEpoch: receivingEpoch,
        epochStates: epochs,
        skippedMessageKeys: skipped,
        nativeSckaState: nextNative,
        priorSnapshotBinding: priorSnapshotBinding,
      );
      messageKey = null;
      root = Uint8List(0);
      nextNative = null;
      priorSnapshotBinding = Uint8List(0);
      epochs = <V3PqEpochState>[];
      skipped = <V3PqSkippedMessageKey>[];
      return transition;
    } finally {
      scka?.close();
      _wipe(sessionId);
      _wipe(nativeState);
      _wipe(stateSealKey);
      _wipe(root);
      if (nextNative != null) _wipe(nextNative);
      _wipe(priorSnapshotBinding);
      if (messageKey != null) _wipe(messageKey);
      _wipeEpochs(epochs);
      _wipeSkipped(skipped);
    }
  }

  static Future<({Uint8List rootKey, V3PqEpochState epoch})>
      deriveInitialEpoch({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List pqRootSeed,
  }) async {
    _validateSecret(pqRootSeed, 'pqRootSeed');
    _validateSessionId(sessionId);
    final derived = await _deriveRootMaterial(
      rootKey: sessionId,
      inputSecret: pqRootSeed,
      sessionId: sessionId,
      epoch: 0,
      initial: true,
    );
    try {
      final sending = role == V3SessionRole.initiator
          ? derived.initiatorToResponder
          : derived.responderToInitiator;
      final receiving = role == V3SessionRole.initiator
          ? derived.responderToInitiator
          : derived.initiatorToResponder;
      return (
        rootKey: Uint8List.fromList(derived.rootKey),
        epoch: V3PqEpochState(
          epoch: 0,
          sendingChainKey: sending,
          receivingChainKey: receiving,
        ),
      );
    } finally {
      derived.wipe();
    }
  }

  static Future<_IncorporatedEpoch> _incorporateEpochSecret({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List rootKey,
    required int currentEpoch,
    required List<V3PqEpochState> epochs,
    required V3SckaEpochSecret? epochSecret,
  }) async {
    if (epochSecret == null) {
      return _IncorporatedEpoch(rootKey: rootKey, currentEpoch: currentEpoch);
    }
    if (currentEpoch >= maxCounter || epochSecret.epoch != currentEpoch + 1) {
      throw StateError('Layergram v3 SCKA epoch secret is not consecutive');
    }
    final secret = epochSecret.secret;
    try {
      final derived = await _deriveRootMaterial(
        rootKey: rootKey,
        inputSecret: secret,
        sessionId: sessionId,
        epoch: epochSecret.epoch,
        initial: false,
      );
      try {
        final sending = role == V3SessionRole.initiator
            ? derived.initiatorToResponder
            : derived.responderToInitiator;
        final receiving = role == V3SessionRole.initiator
            ? derived.responderToInitiator
            : derived.initiatorToResponder;
        epochs.add(
          V3PqEpochState(
            epoch: epochSecret.epoch,
            sendingChainKey: sending,
            receivingChainKey: receiving,
          ),
        );
        return _IncorporatedEpoch(
          rootKey: Uint8List.fromList(derived.rootKey),
          currentEpoch: epochSecret.epoch,
        );
      } finally {
        derived.wipe();
      }
    } finally {
      _wipe(secret);
    }
  }

  static Future<_RootMaterial> _deriveRootMaterial({
    required Uint8List rootKey,
    required Uint8List inputSecret,
    required Uint8List sessionId,
    required int epoch,
    required bool initial,
  }) async {
    final epochBytes = Uint8List(8);
    ByteData.sublistView(epochBytes).setUint64(0, epoch, Endian.big);
    final salt = initial ? sessionId : rootKey;
    Uint8List? derived;
    try {
      derived = Uint8List.fromList(
        await (await _rootKdf.deriveKey(
          secretKey: SecretKey(inputSecret),
          nonce: salt,
          info: <int>[..._rootLabel, ...sessionId, ...epochBytes],
        ))
            .extractBytes(),
      );
      final nextRoot = Uint8List.fromList(derived.sublist(0, 32));
      final initiatorToResponder = Uint8List.fromList(derived.sublist(32, 64));
      final responderToInitiator = Uint8List.fromList(derived.sublist(64, 96));
      try {
        _requireNonZero(nextRoot, 'PQ root key');
        _requireNonZero(initiatorToResponder, 'PQ initiator chain');
        _requireNonZero(responderToInitiator, 'PQ responder chain');
        return _RootMaterial(
          rootKey: nextRoot,
          initiatorToResponder: initiatorToResponder,
          responderToInitiator: responderToInitiator,
        );
      } catch (_) {
        _wipe(nextRoot);
        _wipe(initiatorToResponder);
        _wipe(responderToInitiator);
        rethrow;
      }
    } finally {
      _wipe(epochBytes);
      if (derived != null) _wipe(derived);
    }
  }

  static Future<_ChainStep> _chainStep(
    Uint8List chainKey,
    int counter,
  ) async {
    final counterBytes = Uint8List(8);
    ByteData.sublistView(counterBytes).setUint64(0, counter, Endian.big);
    Uint8List? message;
    Uint8List? next;
    try {
      message = Uint8List.fromList(
        (await _chainHmac.calculateMac(
          <int>[..._messageKeyLabel, ...counterBytes],
          secretKey: SecretKey(chainKey),
        ))
            .bytes,
      );
      next = Uint8List.fromList(
        (await _chainHmac.calculateMac(
          <int>[..._nextChainKeyLabel, ...counterBytes],
          secretKey: SecretKey(chainKey),
        ))
            .bytes,
      );
      _requireNonZero(message, 'PQ message key');
      _requireNonZero(next, 'PQ next chain key');
      final result = _ChainStep(messageKey: message, nextChainKey: next);
      message = null;
      next = null;
      return result;
    } finally {
      _wipe(counterBytes);
      if (message != null) _wipe(message);
      if (next != null) _wipe(next);
    }
  }
}

final class _IncorporatedEpoch {
  const _IncorporatedEpoch({
    required this.rootKey,
    required this.currentEpoch,
  });

  final Uint8List rootKey;
  final int currentEpoch;
}

final class _RootMaterial {
  _RootMaterial({
    required this.rootKey,
    required this.initiatorToResponder,
    required this.responderToInitiator,
  });

  final Uint8List rootKey;
  final Uint8List initiatorToResponder;
  final Uint8List responderToInitiator;

  void wipe() {
    _wipe(rootKey);
    _wipe(initiatorToResponder);
    _wipe(responderToInitiator);
  }
}

final class _ChainStep {
  const _ChainStep({
    required this.messageKey,
    required this.nextChainKey,
  });

  final Uint8List messageKey;
  final Uint8List nextChainKey;
}

void _validateSnapshotForTransition(V3TripleRatchetState snapshot) {
  if (snapshot.lifecycle != V3RatchetLifecycle.active) {
    throw StateError('Layergram v3 Triple Ratchet session is not active');
  }
  if (snapshot.revision >= V3PqMessageRatchet.maxCounter) {
    throw StateError('Layergram v3 ratchet snapshot revision is exhausted');
  }
}

void _sealSendingChain(List<V3PqEpochState> epochs, int epochNumber) {
  final current = _epoch(epochs, epochNumber);
  final receiving = current.receivingChainKey;
  try {
    final replacement = V3PqEpochState(
      epoch: current.epoch,
      receivingChainKey: receiving,
      receiveCounter: current.receiveCounter,
    );
    _replaceEpoch(epochs, current, replacement);
  } finally {
    if (receiving != null) _wipe(receiving);
  }
}

void _replaceSendingEpoch({
  required List<V3PqEpochState> epochs,
  required V3PqEpochState current,
  required Uint8List nextSendingChainKey,
  required int nextSendCounter,
}) {
  final receiving = current.receivingChainKey;
  try {
    final replacement = V3PqEpochState(
      epoch: current.epoch,
      sendingChainKey: nextSendingChainKey,
      sendCounter: nextSendCounter,
      receivingChainKey: receiving,
      receiveCounter: current.receiveCounter,
    );
    _replaceEpoch(epochs, current, replacement);
  } finally {
    if (receiving != null) _wipe(receiving);
  }
}

void _replaceReceivingEpoch({
  required List<V3PqEpochState> epochs,
  required V3PqEpochState current,
  required Uint8List nextReceivingChainKey,
  required int nextReceiveCounter,
}) {
  final sending = current.sendingChainKey;
  try {
    final replacement = V3PqEpochState(
      epoch: current.epoch,
      sendingChainKey: sending,
      sendCounter: current.sendCounter,
      receivingChainKey: nextReceivingChainKey,
      receiveCounter: nextReceiveCounter,
    );
    _replaceEpoch(epochs, current, replacement);
  } finally {
    if (sending != null) _wipe(sending);
  }
}

void _replaceEpoch(
  List<V3PqEpochState> epochs,
  V3PqEpochState current,
  V3PqEpochState replacement,
) {
  final index = epochs.indexWhere((value) => value.epoch == current.epoch);
  if (index < 0) {
    replacement.wipeSecrets();
    throw StateError('Layergram v3 PQ epoch disappeared');
  }
  epochs[index].wipeSecrets();
  epochs[index] = replacement;
}

void _pruneEpochs({
  required List<V3PqEpochState> epochs,
  required List<V3PqSkippedMessageKey> skipped,
  required int sendingEpoch,
  required int receivingEpoch,
}) {
  epochs.sort((left, right) => left.epoch.compareTo(right.epoch));
  while (epochs.length > V3TripleRatchetStateCodec.maxRetainedPqEpochs) {
    final oldest = epochs.first;
    if (oldest.epoch == sendingEpoch || oldest.epoch == receivingEpoch) {
      throw StateError(
        'Layergram v3 SCKA advanced beyond retained active epochs',
      );
    }
    epochs.removeAt(0).wipeSecrets();
    for (var index = skipped.length - 1; index >= 0; index--) {
      if (skipped[index].epoch == oldest.epoch) {
        skipped.removeAt(index).wipeSecret();
      }
    }
  }
}

V3PqEpochState _epoch(List<V3PqEpochState> epochs, int number) {
  final retained = _retainedEpoch(epochs, number);
  if (retained != null) return retained;
  throw StateError('Layergram v3 PQ epoch is not retained');
}

V3PqEpochState? _retainedEpoch(
  List<V3PqEpochState> epochs,
  int number,
) {
  for (final value in epochs) {
    if (value.epoch == number) return value;
  }
  return null;
}

int _compareSkipped(
  V3PqSkippedMessageKey left,
  V3PqSkippedMessageKey right,
) {
  final epoch = left.epoch.compareTo(right.epoch);
  return epoch != 0
      ? epoch
      : left.messageCounter.compareTo(right.messageCounter);
}

void _validateSessionId(Uint8List value) {
  if (value.length != 16 || _isAllZero(value)) {
    throw ArgumentError.value(value, 'sessionId');
  }
}

void _validateSecret(Uint8List value, String name) {
  if (value.length != 32 || _isAllZero(value)) {
    throw ArgumentError.value(value, name, 'must be 32 non-zero bytes');
  }
}

void _validatePositive(int value, String name) {
  if (value <= 0 || value > V3PqMessageRatchet.maxCounter) {
    throw ArgumentError.value(value, name);
  }
}

void _requireNonZero(Uint8List value, String name) {
  if (_isAllZero(value)) {
    throw StateError('Layergram v3 KDF produced an all-zero $name');
  }
}

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

bool _isAllZero(List<int> value) {
  var anyNonZero = 0;
  for (final byte in value) {
    anyNonZero |= byte;
  }
  return anyNonZero == 0;
}

void _wipeEpochs(List<V3PqEpochState> values) {
  for (final value in values) {
    value.wipeSecrets();
  }
}

void _wipeSkipped(List<V3PqSkippedMessageKey> values) {
  for (final value in values) {
    value.wipeSecret();
  }
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
