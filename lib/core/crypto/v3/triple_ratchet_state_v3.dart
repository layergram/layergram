// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:typed_data';

import 'key_schedule_v3.dart';
import 'lmf_v3.dart';

/// Durable lifecycle of an authenticated v3 Triple Ratchet session.
enum V3RatchetLifecycle {
  active(1),
  suspended(2),
  rekeyRequired(3),
  broken(4);

  const V3RatchetLifecycle(this.wireId);

  final int wireId;

  static V3RatchetLifecycle fromWireId(int wireId) {
    for (final value in values) {
      if (value.wireId == wireId) return value;
    }
    throw const FormatException(
      'Unsupported Layergram v3 ratchet lifecycle',
    );
  }
}

/// One retained sparse-PQ epoch with independently directional KDF chains.
final class V3PqEpochState {
  factory V3PqEpochState({
    required int epoch,
    Uint8List? sendingChainKey,
    int sendCounter = 0,
    Uint8List? receivingChainKey,
    int receiveCounter = 0,
  }) {
    _validateCounter(epoch, 'epoch');
    _validateCounter(sendCounter, 'sendCounter');
    _validateCounter(receiveCounter, 'receiveCounter');
    if (sendingChainKey == null && receivingChainKey == null) {
      throw ArgumentError(
        'A Layergram v3 PQ epoch must retain at least one chain',
      );
    }
    if (sendingChainKey == null && sendCounter != 0) {
      throw ArgumentError.value(
        sendCounter,
        'sendCounter',
        'must be zero when the sending chain is sealed',
      );
    }
    if (receivingChainKey == null && receiveCounter != 0) {
      throw ArgumentError.value(
        receiveCounter,
        'receiveCounter',
        'must be zero when the receiving chain is sealed',
      );
    }
    Uint8List? checkedSending;
    Uint8List? checkedReceiving;
    try {
      checkedSending = sendingChainKey == null
          ? null
          : _validatedSecret(sendingChainKey, 'sendingChainKey');
      checkedReceiving = receivingChainKey == null
          ? null
          : _validatedSecret(receivingChainKey, 'receivingChainKey');
      return V3PqEpochState._(
        epoch: epoch,
        sendingChainKey: checkedSending,
        sendCounter: sendCounter,
        receivingChainKey: checkedReceiving,
        receiveCounter: receiveCounter,
      );
    } catch (_) {
      if (checkedSending != null) _wipeBytes(checkedSending);
      if (checkedReceiving != null) _wipeBytes(checkedReceiving);
      rethrow;
    }
  }

  V3PqEpochState._({
    required this.epoch,
    required Uint8List? sendingChainKey,
    required this.sendCounter,
    required Uint8List? receivingChainKey,
    required this.receiveCounter,
  })  : _sendingChainKey = sendingChainKey,
        _receivingChainKey = receivingChainKey;

  final int epoch;
  final Uint8List? _sendingChainKey;
  final int sendCounter;
  final Uint8List? _receivingChainKey;
  final int receiveCounter;
  bool _isWiped = false;

  bool get hasSendingChain => _sendingChainKey != null;
  bool get hasReceivingChain => _receivingChainKey != null;
  bool get isWiped => _isWiped;

  Uint8List? get sendingChainKey {
    _ensureNotWiped();
    return _sendingChainKey == null
        ? null
        : Uint8List.fromList(_sendingChainKey);
  }

  Uint8List? get receivingChainKey {
    _ensureNotWiped();
    return _receivingChainKey == null
        ? null
        : Uint8List.fromList(_receivingChainKey);
  }

  V3PqEpochState _copy() {
    _ensureNotWiped();
    return V3PqEpochState(
      epoch: epoch,
      sendingChainKey: _sendingChainKey,
      sendCounter: sendCounter,
      receivingChainKey: _receivingChainKey,
      receiveCounter: receiveCounter,
    );
  }

  /// Best-effort managed-memory overwrite of the chain keys in this copy.
  void wipeSecrets() {
    if (_isWiped) return;
    if (_sendingChainKey != null) _wipeBytes(_sendingChainKey);
    if (_receivingChainKey != null) _wipeBytes(_receivingChainKey);
    _isWiped = true;
  }

  void _wipe() => wipeSecrets();

  void _ensureNotWiped() {
    if (_isWiped) {
      throw StateError('Layergram v3 PQ epoch state is wiped');
    }
  }
}

/// Retained EC Double Ratchet message key for out-of-order delivery.
final class V3EcSkippedMessageKey {
  factory V3EcSkippedMessageKey({
    required Uint8List ratchetPublicKey,
    required int messageCounter,
    required Uint8List messageKey,
    required int expiresAtUnixSeconds,
  }) {
    _validateCounter(messageCounter, 'messageCounter');
    _validateExpiry(expiresAtUnixSeconds);
    return V3EcSkippedMessageKey._(
      ratchetPublicKey: _validatedX25519PublicKey(
        ratchetPublicKey,
        'ratchetPublicKey',
      ),
      messageCounter: messageCounter,
      messageKey: _validatedSecret(messageKey, 'messageKey'),
      expiresAtUnixSeconds: expiresAtUnixSeconds,
    );
  }

  V3EcSkippedMessageKey._({
    required Uint8List ratchetPublicKey,
    required this.messageCounter,
    required Uint8List messageKey,
    required this.expiresAtUnixSeconds,
  })  : _ratchetPublicKey = ratchetPublicKey,
        _messageKey = messageKey;

  final Uint8List _ratchetPublicKey;
  final int messageCounter;
  final Uint8List _messageKey;
  final int expiresAtUnixSeconds;
  bool _isWiped = false;

  Uint8List get ratchetPublicKey => Uint8List.fromList(_ratchetPublicKey);
  bool get isWiped => _isWiped;
  Uint8List get messageKey {
    _ensureNotWiped();
    return Uint8List.fromList(_messageKey);
  }

  V3EcSkippedMessageKey _copy() {
    _ensureNotWiped();
    return V3EcSkippedMessageKey(
      ratchetPublicKey: _ratchetPublicKey,
      messageCounter: messageCounter,
      messageKey: _messageKey,
      expiresAtUnixSeconds: expiresAtUnixSeconds,
    );
  }

  /// Best-effort managed-memory overwrite of the skipped key in this copy.
  void wipeSecret() {
    if (_isWiped) return;
    _wipeBytes(_messageKey);
    _isWiped = true;
  }

  void _wipe() => wipeSecret();

  void _ensureNotWiped() {
    if (_isWiped) {
      throw StateError('Layergram v3 EC skipped key is wiped');
    }
  }
}

/// Retained sparse-PQ message key for one epoch and counter.
final class V3PqSkippedMessageKey {
  factory V3PqSkippedMessageKey({
    required int epoch,
    required int messageCounter,
    required Uint8List messageKey,
    required int expiresAtUnixSeconds,
  }) {
    _validateCounter(epoch, 'epoch');
    _validateCounter(messageCounter, 'messageCounter');
    _validateExpiry(expiresAtUnixSeconds);
    return V3PqSkippedMessageKey._(
      epoch: epoch,
      messageCounter: messageCounter,
      messageKey: _validatedSecret(messageKey, 'messageKey'),
      expiresAtUnixSeconds: expiresAtUnixSeconds,
    );
  }

  V3PqSkippedMessageKey._({
    required this.epoch,
    required this.messageCounter,
    required Uint8List messageKey,
    required this.expiresAtUnixSeconds,
  }) : _messageKey = messageKey;

  final int epoch;
  final int messageCounter;
  final Uint8List _messageKey;
  final int expiresAtUnixSeconds;
  bool _isWiped = false;

  bool get isWiped => _isWiped;
  Uint8List get messageKey {
    _ensureNotWiped();
    return Uint8List.fromList(_messageKey);
  }

  V3PqSkippedMessageKey _copy() {
    _ensureNotWiped();
    return V3PqSkippedMessageKey(
      epoch: epoch,
      messageCounter: messageCounter,
      messageKey: _messageKey,
      expiresAtUnixSeconds: expiresAtUnixSeconds,
    );
  }

  /// Best-effort managed-memory overwrite of the skipped key in this copy.
  void wipeSecret() {
    if (_isWiped) return;
    _wipeBytes(_messageKey);
    _isWiped = true;
  }

  void _wipe() => wipeSecret();

  void _ensureNotWiped() {
    if (_isWiped) {
      throw StateError('Layergram v3 PQ skipped key is wiped');
    }
  }
}

/// Complete inactive Triple Ratchet snapshot committed with one v3 effect.
///
/// The ML-KEM Braid implementation remains a future reviewed native boundary.
/// [nativeSckaState] must therefore be an opaque, backend-authenticated export;
/// this Dart envelope must never contain a raw expanded ML-KEM private key.
final class V3TripleRatchetState {
  factory V3TripleRatchetState({
    required V3SessionRole role,
    required V3RatchetLifecycle lifecycle,
    required int revision,
    required Uint8List sessionId,
    required Uint8List transcriptDigest,
    required Uint8List initiatorRoutingBinding,
    required Uint8List responderRoutingBinding,
    required Uint8List initiatorToResponderAckRootKey,
    required Uint8List responderToInitiatorAckRootKey,
    required Uint8List ecRootKey,
    required Uint8List ecSendingChainKey,
    Uint8List? ecReceivingChainKey,
    required Uint8List ecLocalDhPrivateKey,
    required Uint8List ecLocalDhPublicKey,
    Uint8List? ecRemoteDhPublicKey,
    required int ecSendCounter,
    required int ecReceiveCounter,
    required int ecPreviousSendingChainLength,
    required Uint8List pqRootKey,
    required int pqCurrentEpoch,
    required int pqSendingEpoch,
    required int pqReceivingEpoch,
    required List<V3PqEpochState> pqEpochStates,
    List<V3EcSkippedMessageKey> ecSkippedMessageKeys = const [],
    List<V3PqSkippedMessageKey> pqSkippedMessageKeys = const [],
    required Uint8List nativeSckaState,
  }) {
    _validateCounter(revision, 'revision');
    _validateCounter(ecSendCounter, 'ecSendCounter');
    _validateCounter(ecReceiveCounter, 'ecReceiveCounter');
    _validateCounter(
      ecPreviousSendingChainLength,
      'ecPreviousSendingChainLength',
    );
    if (ecReceivingChainKey == null && ecReceiveCounter != 0) {
      throw ArgumentError.value(
        ecReceiveCounter,
        'ecReceiveCounter',
        'must be zero when the EC receiving chain is absent',
      );
    }
    if (ecReceivingChainKey == null && role != V3SessionRole.initiator) {
      throw ArgumentError(
        'Only the initial Layergram v3 initiator may lack an EC receiving chain',
      );
    }
    _validateCounter(pqCurrentEpoch, 'pqCurrentEpoch');
    _validateCounter(pqSendingEpoch, 'pqSendingEpoch');
    _validateCounter(pqReceivingEpoch, 'pqReceivingEpoch');
    if (pqSendingEpoch > pqCurrentEpoch || pqReceivingEpoch > pqCurrentEpoch) {
      throw ArgumentError(
        'Layergram v3 PQ direction epoch exceeds current epoch',
      );
    }
    if (nativeSckaState.isEmpty ||
        nativeSckaState.length >
            V3TripleRatchetStateCodec.maxNativeSckaStateBytes ||
        _isAllZero(nativeSckaState)) {
      throw ArgumentError.value(
        nativeSckaState.length,
        'nativeSckaState',
        'must be a non-empty, non-zero authenticated backend export within '
            'the configured bound',
      );
    }
    if (initiatorToResponderAckRootKey.length == 32 &&
        responderToInitiatorAckRootKey.length == 32 &&
        _bytesEqual(
          initiatorToResponderAckRootKey,
          responderToInitiatorAckRootKey,
        )) {
      throw ArgumentError(
          'Layergram v3 directional ACK roots must be distinct');
    }
    if (pqEpochStates.isEmpty ||
        pqEpochStates.length > V3TripleRatchetStateCodec.maxRetainedPqEpochs) {
      throw ArgumentError.value(
        pqEpochStates.length,
        'pqEpochStates.length',
      );
    }
    if (ecSkippedMessageKeys.length >
        V3TripleRatchetStateCodec.maxSkippedKeysPerRatchet) {
      throw ArgumentError.value(
        ecSkippedMessageKeys.length,
        'ecSkippedMessageKeys.length',
      );
    }
    if (pqSkippedMessageKeys.length >
        V3TripleRatchetStateCodec.maxSkippedKeysPerRatchet) {
      throw ArgumentError.value(
        pqSkippedMessageKeys.length,
        'pqSkippedMessageKeys.length',
      );
    }

    Uint8List? checkedSessionId;
    Uint8List? checkedTranscriptDigest;
    Uint8List? checkedInitiatorBinding;
    Uint8List? checkedResponderBinding;
    Uint8List? checkedAckI2R;
    Uint8List? checkedAckR2I;
    Uint8List? checkedEcRoot;
    Uint8List? checkedEcSending;
    Uint8List? checkedEcReceiving;
    Uint8List? checkedEcPrivate;
    Uint8List? checkedEcPublic;
    Uint8List? checkedEcRemote;
    Uint8List? checkedPqRoot;
    Uint8List? checkedNativeState;
    final epochs = <V3PqEpochState>[];
    final ecSkipped = <V3EcSkippedMessageKey>[];
    final pqSkipped = <V3PqSkippedMessageKey>[];
    try {
      checkedSessionId = _validatedBytes(
        sessionId,
        V3LmfFrameCodec.sessionIdBytes,
        'sessionId',
        rejectAllZero: true,
      );
      checkedTranscriptDigest = _validatedBytes(
        transcriptDigest,
        48,
        'transcriptDigest',
        rejectAllZero: true,
      );
      checkedInitiatorBinding = _validatedBytes(
        initiatorRoutingBinding,
        V3LmfFrameCodec.routingBindingBytes,
        'initiatorRoutingBinding',
        rejectAllZero: true,
      );
      checkedResponderBinding = _validatedBytes(
        responderRoutingBinding,
        V3LmfFrameCodec.routingBindingBytes,
        'responderRoutingBinding',
        rejectAllZero: true,
      );
      if (_bytesEqual(checkedInitiatorBinding, checkedResponderBinding)) {
        throw ArgumentError('Layergram v3 routing bindings must be distinct');
      }
      checkedAckI2R = _validatedSecret(
        initiatorToResponderAckRootKey,
        'initiatorToResponderAckRootKey',
      );
      checkedAckR2I = _validatedSecret(
        responderToInitiatorAckRootKey,
        'responderToInitiatorAckRootKey',
      );
      checkedEcRoot = _validatedSecret(ecRootKey, 'ecRootKey');
      checkedEcSending =
          _validatedSecret(ecSendingChainKey, 'ecSendingChainKey');
      checkedEcReceiving = ecReceivingChainKey == null
          ? null
          : _validatedSecret(ecReceivingChainKey, 'ecReceivingChainKey');
      checkedEcPrivate =
          _validatedSecret(ecLocalDhPrivateKey, 'ecLocalDhPrivateKey');
      checkedEcPublic = _validatedX25519PublicKey(
        ecLocalDhPublicKey,
        'ecLocalDhPublicKey',
      );
      checkedEcRemote = ecRemoteDhPublicKey == null
          ? null
          : _validatedX25519PublicKey(
              ecRemoteDhPublicKey,
              'ecRemoteDhPublicKey',
            );
      checkedPqRoot = _validatedSecret(pqRootKey, 'pqRootKey');
      checkedNativeState = Uint8List.fromList(nativeSckaState);
      for (final value in pqEpochStates) {
        epochs.add(value._copy());
      }
      for (final value in ecSkippedMessageKeys) {
        ecSkipped.add(value._copy());
      }
      for (final value in pqSkippedMessageKeys) {
        pqSkipped.add(value._copy());
      }
      epochs.sort((left, right) => left.epoch.compareTo(right.epoch));
      ecSkipped.sort(_compareEcSkipped);
      pqSkipped.sort(_comparePqSkipped);
      _validateEpochStates(
        epochs,
        currentEpoch: pqCurrentEpoch,
        sendingEpoch: pqSendingEpoch,
        receivingEpoch: pqReceivingEpoch,
      );
      _validateEcSkipped(ecSkipped);
      _validatePqSkipped(pqSkipped, epochs);
      return V3TripleRatchetState._(
        role: role,
        lifecycle: lifecycle,
        revision: revision,
        sessionId: checkedSessionId,
        transcriptDigest: checkedTranscriptDigest,
        initiatorRoutingBinding: checkedInitiatorBinding,
        responderRoutingBinding: checkedResponderBinding,
        initiatorToResponderAckRootKey: checkedAckI2R,
        responderToInitiatorAckRootKey: checkedAckR2I,
        ecRootKey: checkedEcRoot,
        ecSendingChainKey: checkedEcSending,
        ecReceivingChainKey: checkedEcReceiving,
        ecLocalDhPrivateKey: checkedEcPrivate,
        ecLocalDhPublicKey: checkedEcPublic,
        ecRemoteDhPublicKey: checkedEcRemote,
        ecSendCounter: ecSendCounter,
        ecReceiveCounter: ecReceiveCounter,
        ecPreviousSendingChainLength: ecPreviousSendingChainLength,
        pqRootKey: checkedPqRoot,
        pqCurrentEpoch: pqCurrentEpoch,
        pqSendingEpoch: pqSendingEpoch,
        pqReceivingEpoch: pqReceivingEpoch,
        pqEpochStates: epochs,
        ecSkippedMessageKeys: ecSkipped,
        pqSkippedMessageKeys: pqSkipped,
        nativeSckaState: checkedNativeState,
      );
    } catch (_) {
      for (final value in <Uint8List?>[
        checkedSessionId,
        checkedTranscriptDigest,
        checkedInitiatorBinding,
        checkedResponderBinding,
        checkedAckI2R,
        checkedAckR2I,
        checkedEcRoot,
        checkedEcSending,
        checkedEcReceiving,
        checkedEcPrivate,
        checkedEcPublic,
        checkedEcRemote,
        checkedPqRoot,
        checkedNativeState,
      ]) {
        if (value != null) _wipeBytes(value);
      }
      for (final value in epochs) {
        value._wipe();
      }
      for (final value in ecSkipped) {
        value._wipe();
      }
      for (final value in pqSkipped) {
        value._wipe();
      }
      rethrow;
    }
  }

  V3TripleRatchetState._({
    required this.role,
    required this.lifecycle,
    required this.revision,
    required Uint8List sessionId,
    required Uint8List transcriptDigest,
    required Uint8List initiatorRoutingBinding,
    required Uint8List responderRoutingBinding,
    required Uint8List initiatorToResponderAckRootKey,
    required Uint8List responderToInitiatorAckRootKey,
    required Uint8List ecRootKey,
    required Uint8List ecSendingChainKey,
    required Uint8List? ecReceivingChainKey,
    required Uint8List ecLocalDhPrivateKey,
    required Uint8List ecLocalDhPublicKey,
    required Uint8List? ecRemoteDhPublicKey,
    required this.ecSendCounter,
    required this.ecReceiveCounter,
    required this.ecPreviousSendingChainLength,
    required Uint8List pqRootKey,
    required this.pqCurrentEpoch,
    required this.pqSendingEpoch,
    required this.pqReceivingEpoch,
    required List<V3PqEpochState> pqEpochStates,
    required List<V3EcSkippedMessageKey> ecSkippedMessageKeys,
    required List<V3PqSkippedMessageKey> pqSkippedMessageKeys,
    required Uint8List nativeSckaState,
  })  : _sessionId = sessionId,
        _transcriptDigest = transcriptDigest,
        _initiatorRoutingBinding = initiatorRoutingBinding,
        _responderRoutingBinding = responderRoutingBinding,
        _initiatorToResponderAckRootKey = initiatorToResponderAckRootKey,
        _responderToInitiatorAckRootKey = responderToInitiatorAckRootKey,
        _ecRootKey = ecRootKey,
        _ecSendingChainKey = ecSendingChainKey,
        _ecReceivingChainKey = ecReceivingChainKey,
        _ecLocalDhPrivateKey = ecLocalDhPrivateKey,
        _ecLocalDhPublicKey = ecLocalDhPublicKey,
        _ecRemoteDhPublicKey = ecRemoteDhPublicKey,
        _pqRootKey = pqRootKey,
        _pqEpochStates = pqEpochStates,
        _ecSkippedMessageKeys = ecSkippedMessageKeys,
        _pqSkippedMessageKeys = pqSkippedMessageKeys,
        _nativeSckaState = nativeSckaState;

  final V3SessionRole role;
  final V3RatchetLifecycle lifecycle;
  final int revision;
  final Uint8List _sessionId;
  final Uint8List _transcriptDigest;
  final Uint8List _initiatorRoutingBinding;
  final Uint8List _responderRoutingBinding;
  final Uint8List _initiatorToResponderAckRootKey;
  final Uint8List _responderToInitiatorAckRootKey;
  final Uint8List _ecRootKey;
  final Uint8List _ecSendingChainKey;
  final Uint8List? _ecReceivingChainKey;
  final Uint8List _ecLocalDhPrivateKey;
  final Uint8List _ecLocalDhPublicKey;
  final Uint8List? _ecRemoteDhPublicKey;
  final int ecSendCounter;
  final int ecReceiveCounter;
  final int ecPreviousSendingChainLength;
  final Uint8List _pqRootKey;
  final int pqCurrentEpoch;
  final int pqSendingEpoch;
  final int pqReceivingEpoch;
  final List<V3PqEpochState> _pqEpochStates;
  final List<V3EcSkippedMessageKey> _ecSkippedMessageKeys;
  final List<V3PqSkippedMessageKey> _pqSkippedMessageKeys;
  final Uint8List _nativeSckaState;

  bool _isWiped = false;

  bool get isWiped => _isWiped;
  Uint8List get sessionId => Uint8List.fromList(_sessionId);
  Uint8List get transcriptDigest => Uint8List.fromList(_transcriptDigest);
  Uint8List get initiatorRoutingBinding =>
      Uint8List.fromList(_initiatorRoutingBinding);
  Uint8List get responderRoutingBinding =>
      Uint8List.fromList(_responderRoutingBinding);
  Uint8List get ecLocalDhPublicKey => Uint8List.fromList(_ecLocalDhPublicKey);
  Uint8List? get ecRemoteDhPublicKey => _ecRemoteDhPublicKey == null
      ? null
      : Uint8List.fromList(_ecRemoteDhPublicKey);

  Uint8List get initiatorToResponderAckRootKey =>
      _secretCopy(_initiatorToResponderAckRootKey);
  Uint8List get responderToInitiatorAckRootKey =>
      _secretCopy(_responderToInitiatorAckRootKey);
  Uint8List get ecRootKey => _secretCopy(_ecRootKey);
  Uint8List get ecSendingChainKey => _secretCopy(_ecSendingChainKey);
  Uint8List? get ecReceivingChainKey =>
      _ecReceivingChainKey == null ? null : _secretCopy(_ecReceivingChainKey);
  Uint8List get ecLocalDhPrivateKey => _secretCopy(_ecLocalDhPrivateKey);
  Uint8List get pqRootKey => _secretCopy(_pqRootKey);
  Uint8List get nativeSckaState => _secretCopy(_nativeSckaState);

  List<V3PqEpochState> get pqEpochStates {
    _ensureNotWiped();
    return List<V3PqEpochState>.unmodifiable(
      _pqEpochStates.map((value) => value._copy()),
    );
  }

  List<V3EcSkippedMessageKey> get ecSkippedMessageKeys {
    _ensureNotWiped();
    return List<V3EcSkippedMessageKey>.unmodifiable(
      _ecSkippedMessageKeys.map((value) => value._copy()),
    );
  }

  List<V3PqSkippedMessageKey> get pqSkippedMessageKeys {
    _ensureNotWiped();
    return List<V3PqSkippedMessageKey>.unmodifiable(
      _pqSkippedMessageKeys.map((value) => value._copy()),
    );
  }

  /// Best-effort managed-memory overwrite of all secret state owned here.
  void wipeSecrets() {
    if (_isWiped) return;
    _wipeBytes(_initiatorToResponderAckRootKey);
    _wipeBytes(_responderToInitiatorAckRootKey);
    _wipeBytes(_ecRootKey);
    _wipeBytes(_ecSendingChainKey);
    if (_ecReceivingChainKey != null) _wipeBytes(_ecReceivingChainKey);
    _wipeBytes(_ecLocalDhPrivateKey);
    _wipeBytes(_pqRootKey);
    _wipeBytes(_nativeSckaState);
    for (final value in _pqEpochStates) {
      value._wipe();
    }
    for (final value in _ecSkippedMessageKeys) {
      value._wipe();
    }
    for (final value in _pqSkippedMessageKeys) {
      value._wipe();
    }
    _isWiped = true;
  }

  Uint8List _secretCopy(Uint8List source) {
    _ensureNotWiped();
    return Uint8List.fromList(source);
  }

  void _ensureNotWiped() {
    if (_isWiped) {
      throw StateError('Layergram v3 Triple Ratchet state is wiped');
    }
  }

  /// Builds the next durable snapshot after an authenticated EC transition.
  ///
  /// The current snapshot is never mutated. PQ, ACK, routing, transcript, and
  /// native-backend state are copied exactly while the complete EC component
  /// is replaced. The caller must persist this returned snapshot atomically
  /// with the application effect before discarding the previous snapshot.
  V3TripleRatchetState replaceEcState({
    required int expectedRevision,
    required Uint8List ecRootKey,
    required Uint8List ecSendingChainKey,
    Uint8List? ecReceivingChainKey,
    required Uint8List ecLocalDhPrivateKey,
    required Uint8List ecLocalDhPublicKey,
    required Uint8List ecRemoteDhPublicKey,
    required int ecSendCounter,
    required int ecReceiveCounter,
    required int ecPreviousSendingChainLength,
    required List<V3EcSkippedMessageKey> ecSkippedMessageKeys,
    V3RatchetLifecycle? lifecycle,
  }) {
    return replaceHybridState(
      expectedRevision: expectedRevision,
      ecRootKey: ecRootKey,
      ecSendingChainKey: ecSendingChainKey,
      ecReceivingChainKey: ecReceivingChainKey,
      ecLocalDhPrivateKey: ecLocalDhPrivateKey,
      ecLocalDhPublicKey: ecLocalDhPublicKey,
      ecRemoteDhPublicKey: ecRemoteDhPublicKey,
      ecSendCounter: ecSendCounter,
      ecReceiveCounter: ecReceiveCounter,
      ecPreviousSendingChainLength: ecPreviousSendingChainLength,
      ecSkippedMessageKeys: ecSkippedMessageKeys,
      pqRootKey: _pqRootKey,
      pqCurrentEpoch: pqCurrentEpoch,
      pqSendingEpoch: pqSendingEpoch,
      pqReceivingEpoch: pqReceivingEpoch,
      pqEpochStates: _pqEpochStates,
      pqSkippedMessageKeys: _pqSkippedMessageKeys,
      nativeSckaState: _nativeSckaState,
      lifecycle: lifecycle,
    );
  }

  /// Builds one post-effect snapshot containing both ratchet candidates.
  ///
  /// Non-ACK protocol-v3 messages consume EC and PQ material together. This
  /// advances the snapshot revision exactly once while replacing both
  /// components, so the journal never needs an EC-only or PQ-only intermediate
  /// state. The current snapshot remains unchanged.
  V3TripleRatchetState replaceHybridState({
    required int expectedRevision,
    required Uint8List ecRootKey,
    required Uint8List ecSendingChainKey,
    Uint8List? ecReceivingChainKey,
    required Uint8List ecLocalDhPrivateKey,
    required Uint8List ecLocalDhPublicKey,
    required Uint8List ecRemoteDhPublicKey,
    required int ecSendCounter,
    required int ecReceiveCounter,
    required int ecPreviousSendingChainLength,
    required List<V3EcSkippedMessageKey> ecSkippedMessageKeys,
    required Uint8List pqRootKey,
    required int pqCurrentEpoch,
    required int pqSendingEpoch,
    required int pqReceivingEpoch,
    required List<V3PqEpochState> pqEpochStates,
    required List<V3PqSkippedMessageKey> pqSkippedMessageKeys,
    required Uint8List nativeSckaState,
    V3RatchetLifecycle? lifecycle,
  }) {
    _ensureNotWiped();
    if (revision != expectedRevision) {
      throw StateError('Layergram v3 ratchet snapshot revision conflict');
    }
    if (revision >= 0x7fffffffffffffff) {
      throw StateError('Layergram v3 ratchet snapshot revision is exhausted');
    }
    return V3TripleRatchetState(
      role: role,
      lifecycle: lifecycle ?? this.lifecycle,
      revision: revision + 1,
      sessionId: _sessionId,
      transcriptDigest: _transcriptDigest,
      initiatorRoutingBinding: _initiatorRoutingBinding,
      responderRoutingBinding: _responderRoutingBinding,
      initiatorToResponderAckRootKey: _initiatorToResponderAckRootKey,
      responderToInitiatorAckRootKey: _responderToInitiatorAckRootKey,
      ecRootKey: ecRootKey,
      ecSendingChainKey: ecSendingChainKey,
      ecReceivingChainKey: ecReceivingChainKey,
      ecLocalDhPrivateKey: ecLocalDhPrivateKey,
      ecLocalDhPublicKey: ecLocalDhPublicKey,
      ecRemoteDhPublicKey: ecRemoteDhPublicKey,
      ecSendCounter: ecSendCounter,
      ecReceiveCounter: ecReceiveCounter,
      ecPreviousSendingChainLength: ecPreviousSendingChainLength,
      pqRootKey: pqRootKey,
      pqCurrentEpoch: pqCurrentEpoch,
      pqSendingEpoch: pqSendingEpoch,
      pqReceivingEpoch: pqReceivingEpoch,
      pqEpochStates: pqEpochStates,
      ecSkippedMessageKeys: ecSkippedMessageKeys,
      pqSkippedMessageKeys: pqSkippedMessageKeys,
      nativeSckaState: nativeSckaState,
    );
  }
}

/// Strict binary codec for [V3TripleRatchetState].
abstract final class V3TripleRatchetStateCodec {
  static const List<int> magic = <int>[0x54, 0x52, 0x33]; // "TR3"
  static const int formatVersion = 1;
  static const int headerBytes = 496;
  static const int pqEpochRecordBytes = 96;
  static const int ecSkippedRecordBytes = 80;
  static const int pqSkippedRecordBytes = 56;
  static const int maxRetainedPqEpochs = 2;
  static const int maxSkippedKeysPerRatchet = 50;
  static const int maxNativeSckaStateBytes = 192 * 1024;
  static const int maxEncodedBytes = 256 * 1024;

  static Uint8List encode(V3TripleRatchetState state) {
    state._ensureNotWiped();
    final totalLength = headerBytes +
        state._pqEpochStates.length * pqEpochRecordBytes +
        state._ecSkippedMessageKeys.length * ecSkippedRecordBytes +
        state._pqSkippedMessageKeys.length * pqSkippedRecordBytes +
        state._nativeSckaState.length;
    if (totalLength > maxEncodedBytes) {
      throw StateError('Layergram v3 Triple Ratchet snapshot exceeds limit');
    }
    final result = Uint8List(totalLength);
    final data = ByteData.sublistView(result);
    var offset = 0;
    result.setRange(offset, offset + magic.length, magic);
    offset += magic.length;
    result[offset++] = formatVersion;
    result[offset++] = V3LmfSuite.hybridX25519MlKem768Aes256Gcm.wireId;
    result[offset++] = state.role.wireId;
    result[offset++] = state.lifecycle.wireId;
    var flags = 0;
    if (state._ecRemoteDhPublicKey != null) flags |= 1;
    if (state._ecReceivingChainKey != null) flags |= 2;
    result[offset++] = flags;
    data.setUint16(offset, headerBytes, Endian.big);
    offset += 2;
    data.setUint32(offset, totalLength, Endian.big);
    offset += 4;
    data.setUint64(offset, state.revision, Endian.big);
    offset += 8;
    offset = _writeBytes(result, offset, state._sessionId);
    offset = _writeBytes(result, offset, state._transcriptDigest);
    offset = _writeBytes(result, offset, state._initiatorRoutingBinding);
    offset = _writeBytes(result, offset, state._responderRoutingBinding);
    offset = _writeBytes(
      result,
      offset,
      state._initiatorToResponderAckRootKey,
    );
    offset = _writeBytes(
      result,
      offset,
      state._responderToInitiatorAckRootKey,
    );
    offset = _writeBytes(result, offset, state._ecRootKey);
    offset = _writeBytes(result, offset, state._ecSendingChainKey);
    if (state._ecReceivingChainKey == null) {
      offset += 32;
    } else {
      offset = _writeBytes(result, offset, state._ecReceivingChainKey);
    }
    offset = _writeBytes(result, offset, state._ecLocalDhPrivateKey);
    offset = _writeBytes(result, offset, state._ecLocalDhPublicKey);
    if (state._ecRemoteDhPublicKey == null) {
      offset += 32;
    } else {
      offset = _writeBytes(result, offset, state._ecRemoteDhPublicKey);
    }
    data.setUint64(offset, state.ecSendCounter, Endian.big);
    offset += 8;
    data.setUint64(offset, state.ecReceiveCounter, Endian.big);
    offset += 8;
    data.setUint64(
      offset,
      state.ecPreviousSendingChainLength,
      Endian.big,
    );
    offset += 8;
    offset = _writeBytes(result, offset, state._pqRootKey);
    data.setUint64(offset, state.pqCurrentEpoch, Endian.big);
    offset += 8;
    data.setUint64(offset, state.pqSendingEpoch, Endian.big);
    offset += 8;
    data.setUint64(offset, state.pqReceivingEpoch, Endian.big);
    offset += 8;
    result[offset++] = state._pqEpochStates.length;
    result[offset++] = state._ecSkippedMessageKeys.length;
    result[offset++] = state._pqSkippedMessageKeys.length;
    offset += 3; // Reserved zero bytes.
    data.setUint32(offset, state._nativeSckaState.length, Endian.big);
    offset += 4;
    if (offset != headerBytes) {
      throw StateError('Layergram v3 Triple Ratchet header drift');
    }

    for (final epoch in state._pqEpochStates) {
      final start = offset;
      data.setUint64(offset, epoch.epoch, Endian.big);
      offset += 8;
      var flags = 0;
      if (epoch._sendingChainKey != null) flags |= 1;
      if (epoch._receivingChainKey != null) flags |= 2;
      result[offset++] = flags;
      offset += 7;
      data.setUint64(offset, epoch.sendCounter, Endian.big);
      offset += 8;
      data.setUint64(offset, epoch.receiveCounter, Endian.big);
      offset += 8;
      if (epoch._sendingChainKey == null) {
        offset += 32;
      } else {
        offset = _writeBytes(result, offset, epoch._sendingChainKey);
      }
      if (epoch._receivingChainKey == null) {
        offset += 32;
      } else {
        offset = _writeBytes(result, offset, epoch._receivingChainKey);
      }
      if (offset - start != pqEpochRecordBytes) {
        throw StateError('Layergram v3 PQ epoch encoding drift');
      }
    }

    for (final skipped in state._ecSkippedMessageKeys) {
      final start = offset;
      offset = _writeBytes(result, offset, skipped._ratchetPublicKey);
      data.setUint64(offset, skipped.messageCounter, Endian.big);
      offset += 8;
      offset = _writeBytes(result, offset, skipped._messageKey);
      data.setUint64(offset, skipped.expiresAtUnixSeconds, Endian.big);
      offset += 8;
      if (offset - start != ecSkippedRecordBytes) {
        throw StateError('Layergram v3 EC skipped-key encoding drift');
      }
    }

    for (final skipped in state._pqSkippedMessageKeys) {
      final start = offset;
      data.setUint64(offset, skipped.epoch, Endian.big);
      offset += 8;
      data.setUint64(offset, skipped.messageCounter, Endian.big);
      offset += 8;
      offset = _writeBytes(result, offset, skipped._messageKey);
      data.setUint64(offset, skipped.expiresAtUnixSeconds, Endian.big);
      offset += 8;
      if (offset - start != pqSkippedRecordBytes) {
        throw StateError('Layergram v3 PQ skipped-key encoding drift');
      }
    }
    offset = _writeBytes(result, offset, state._nativeSckaState);
    if (offset != result.length) {
      throw StateError('Layergram v3 Triple Ratchet encoding drift');
    }
    return result;
  }

  static V3TripleRatchetState decode(Uint8List encoded) {
    if (encoded.length < headerBytes + 1 || encoded.length > maxEncodedBytes) {
      throw const FormatException(
        'Invalid Layergram v3 Triple Ratchet state length',
      );
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException(
          'Invalid Layergram v3 Triple Ratchet state magic',
        );
      }
    }
    if (encoded[3] != formatVersion ||
        encoded[4] != V3LmfSuite.hybridX25519MlKem768Aes256Gcm.wireId) {
      throw const FormatException(
        'Unsupported Layergram v3 Triple Ratchet state format',
      );
    }
    final role = V3SessionRole.fromWireId(encoded[5]);
    final lifecycle = V3RatchetLifecycle.fromWireId(encoded[6]);
    final flags = encoded[7];
    if ((flags & 0xfc) != 0) {
      throw const FormatException(
        'Unsupported Layergram v3 Triple Ratchet state flags',
      );
    }
    final data = ByteData.sublistView(encoded);
    if (data.getUint16(8, Endian.big) != headerBytes ||
        data.getUint32(10, Endian.big) != encoded.length) {
      throw const FormatException(
        'Non-canonical Layergram v3 Triple Ratchet state length',
      );
    }

    final sensitive = <Uint8List>[];
    final epochs = <V3PqEpochState>[];
    final ecSkipped = <V3EcSkippedMessageKey>[];
    final pqSkipped = <V3PqSkippedMessageKey>[];
    try {
      var offset = 14;
      final revision = data.getUint64(offset, Endian.big);
      offset += 8;
      final sessionId = _copyRange(encoded, offset, 16);
      offset += 16;
      final transcriptDigest = _copyRange(encoded, offset, 48);
      offset += 48;
      final initiatorBinding = _copyRange(encoded, offset, 32);
      offset += 32;
      final responderBinding = _copyRange(encoded, offset, 32);
      offset += 32;
      final ackI2R = _copySensitive(encoded, offset, sensitive);
      offset += 32;
      final ackR2I = _copySensitive(encoded, offset, sensitive);
      offset += 32;
      final ecRoot = _copySensitive(encoded, offset, sensitive);
      offset += 32;
      final ecSending = _copySensitive(encoded, offset, sensitive);
      offset += 32;
      final ecReceiving = _copySensitive(encoded, offset, sensitive);
      offset += 32;
      final receivingPresent = (flags & 2) != 0;
      if (receivingPresent == _isAllZero(ecReceiving)) {
        throw const FormatException(
          'Non-canonical Layergram v3 EC receiving-chain state',
        );
      }
      final ecPrivate = _copySensitive(encoded, offset, sensitive);
      offset += 32;
      final ecPublic = _copyRange(encoded, offset, 32);
      offset += 32;
      final remoteBytes = _copyRange(encoded, offset, 32);
      offset += 32;
      final remotePresent = (flags & 1) != 0;
      if (remotePresent == _isAllZero(remoteBytes)) {
        throw const FormatException(
          'Non-canonical Layergram v3 remote DH state',
        );
      }
      final remotePublic = remotePresent ? remoteBytes : null;
      final ecSendCounter = data.getUint64(offset, Endian.big);
      offset += 8;
      final ecReceiveCounter = data.getUint64(offset, Endian.big);
      offset += 8;
      final ecPreviousLength = data.getUint64(offset, Endian.big);
      offset += 8;
      final pqRoot = _copySensitive(encoded, offset, sensitive);
      offset += 32;
      final pqCurrentEpoch = data.getUint64(offset, Endian.big);
      offset += 8;
      final pqSendingEpoch = data.getUint64(offset, Endian.big);
      offset += 8;
      final pqReceivingEpoch = data.getUint64(offset, Endian.big);
      offset += 8;
      final epochCount = encoded[offset++];
      final ecSkippedCount = encoded[offset++];
      final pqSkippedCount = encoded[offset++];
      if (epochCount < 1 ||
          epochCount > maxRetainedPqEpochs ||
          ecSkippedCount > maxSkippedKeysPerRatchet ||
          pqSkippedCount > maxSkippedKeysPerRatchet) {
        throw const FormatException(
          'Invalid Layergram v3 Triple Ratchet state counts',
        );
      }
      if (encoded[offset] != 0 ||
          encoded[offset + 1] != 0 ||
          encoded[offset + 2] != 0) {
        throw const FormatException(
          'Non-canonical Layergram v3 Triple Ratchet reserved bytes',
        );
      }
      offset += 3;
      final nativeLength = data.getUint32(offset, Endian.big);
      offset += 4;
      if (offset != headerBytes ||
          nativeLength < 1 ||
          nativeLength > maxNativeSckaStateBytes) {
        throw const FormatException(
          'Invalid Layergram v3 native SCKA state length',
        );
      }
      final expectedLength = headerBytes +
          epochCount * pqEpochRecordBytes +
          ecSkippedCount * ecSkippedRecordBytes +
          pqSkippedCount * pqSkippedRecordBytes +
          nativeLength;
      if (expectedLength != encoded.length) {
        throw const FormatException(
          'Non-canonical Layergram v3 Triple Ratchet section lengths',
        );
      }

      for (var index = 0; index < epochCount; index++) {
        final epoch = data.getUint64(offset, Endian.big);
        offset += 8;
        final epochFlags = encoded[offset++];
        if (epochFlags == 0 || (epochFlags & 0xfc) != 0) {
          throw const FormatException('Invalid Layergram v3 PQ epoch flags');
        }
        for (var reserved = 0; reserved < 7; reserved++) {
          if (encoded[offset + reserved] != 0) {
            throw const FormatException(
              'Non-canonical Layergram v3 PQ epoch reserved bytes',
            );
          }
        }
        offset += 7;
        final sendCounter = data.getUint64(offset, Endian.big);
        offset += 8;
        final receiveCounter = data.getUint64(offset, Endian.big);
        offset += 8;
        final sendBytes = _copySensitive(encoded, offset, sensitive);
        offset += 32;
        final receiveBytes = _copySensitive(encoded, offset, sensitive);
        offset += 32;
        final hasSend = (epochFlags & 1) != 0;
        final hasReceive = (epochFlags & 2) != 0;
        if ((!hasSend && !_isAllZero(sendBytes)) ||
            (!hasReceive && !_isAllZero(receiveBytes))) {
          throw const FormatException(
            'Non-canonical Layergram v3 sealed PQ chain',
          );
        }
        epochs.add(
          V3PqEpochState(
            epoch: epoch,
            sendingChainKey: hasSend ? sendBytes : null,
            sendCounter: sendCounter,
            receivingChainKey: hasReceive ? receiveBytes : null,
            receiveCounter: receiveCounter,
          ),
        );
      }

      for (var index = 0; index < ecSkippedCount; index++) {
        final ratchetPublic = _copyRange(encoded, offset, 32);
        offset += 32;
        final counter = data.getUint64(offset, Endian.big);
        offset += 8;
        final messageKey = _copySensitive(encoded, offset, sensitive);
        offset += 32;
        final expiry = data.getUint64(offset, Endian.big);
        offset += 8;
        ecSkipped.add(
          V3EcSkippedMessageKey(
            ratchetPublicKey: ratchetPublic,
            messageCounter: counter,
            messageKey: messageKey,
            expiresAtUnixSeconds: expiry,
          ),
        );
      }

      for (var index = 0; index < pqSkippedCount; index++) {
        final epoch = data.getUint64(offset, Endian.big);
        offset += 8;
        final counter = data.getUint64(offset, Endian.big);
        offset += 8;
        final messageKey = _copySensitive(encoded, offset, sensitive);
        offset += 32;
        final expiry = data.getUint64(offset, Endian.big);
        offset += 8;
        pqSkipped.add(
          V3PqSkippedMessageKey(
            epoch: epoch,
            messageCounter: counter,
            messageKey: messageKey,
            expiresAtUnixSeconds: expiry,
          ),
        );
      }
      final nativeState = Uint8List.fromList(
        encoded.sublist(offset, offset + nativeLength),
      );
      sensitive.add(nativeState);
      offset += nativeLength;
      if (offset != encoded.length) {
        throw StateError('Layergram v3 Triple Ratchet decode drift');
      }

      late final V3TripleRatchetState state;
      try {
        state = V3TripleRatchetState(
          role: role,
          lifecycle: lifecycle,
          revision: revision,
          sessionId: sessionId,
          transcriptDigest: transcriptDigest,
          initiatorRoutingBinding: initiatorBinding,
          responderRoutingBinding: responderBinding,
          initiatorToResponderAckRootKey: ackI2R,
          responderToInitiatorAckRootKey: ackR2I,
          ecRootKey: ecRoot,
          ecSendingChainKey: ecSending,
          ecReceivingChainKey: receivingPresent ? ecReceiving : null,
          ecLocalDhPrivateKey: ecPrivate,
          ecLocalDhPublicKey: ecPublic,
          ecRemoteDhPublicKey: remotePublic,
          ecSendCounter: ecSendCounter,
          ecReceiveCounter: ecReceiveCounter,
          ecPreviousSendingChainLength: ecPreviousLength,
          pqRootKey: pqRoot,
          pqCurrentEpoch: pqCurrentEpoch,
          pqSendingEpoch: pqSendingEpoch,
          pqReceivingEpoch: pqReceivingEpoch,
          pqEpochStates: epochs,
          ecSkippedMessageKeys: ecSkipped,
          pqSkippedMessageKeys: pqSkipped,
          nativeSckaState: nativeState,
        );
      } on ArgumentError {
        throw const FormatException(
          'Invalid Layergram v3 Triple Ratchet state fields',
        );
      }
      final canonical = encode(state);
      try {
        if (!_bytesEqual(canonical, encoded)) {
          state.wipeSecrets();
          throw const FormatException(
            'Non-canonical Layergram v3 Triple Ratchet state',
          );
        }
      } finally {
        _wipeBytes(canonical);
      }
      return state;
    } finally {
      for (final value in sensitive) {
        _wipeBytes(value);
      }
      for (final value in epochs) {
        value._wipe();
      }
      for (final value in ecSkipped) {
        value._wipe();
      }
      for (final value in pqSkipped) {
        value._wipe();
      }
    }
  }
}

void _validateEpochStates(
  List<V3PqEpochState> epochs, {
  required int currentEpoch,
  required int sendingEpoch,
  required int receivingEpoch,
}) {
  for (var index = 0; index < epochs.length; index++) {
    final current = epochs[index];
    if (index > 0) {
      final previous = epochs[index - 1];
      if (current.epoch != previous.epoch + 1) {
        throw ArgumentError(
          'Layergram v3 retained PQ epochs must be unique and consecutive',
        );
      }
    }
  }
  if (epochs.last.epoch != currentEpoch) {
    throw ArgumentError(
      'Layergram v3 current PQ epoch must be the newest retained epoch',
    );
  }
  final sending = _epochByNumber(epochs, sendingEpoch);
  final receiving = _epochByNumber(epochs, receivingEpoch);
  if (sending == null || !sending.hasSendingChain) {
    throw ArgumentError('Layergram v3 sending PQ chain is unavailable');
  }
  if (receiving == null || !receiving.hasReceivingChain) {
    throw ArgumentError('Layergram v3 receiving PQ chain is unavailable');
  }
}

V3PqEpochState? _epochByNumber(List<V3PqEpochState> epochs, int epoch) {
  for (final value in epochs) {
    if (value.epoch == epoch) return value;
  }
  return null;
}

void _validateEcSkipped(List<V3EcSkippedMessageKey> skipped) {
  for (var index = 1; index < skipped.length; index++) {
    if (_compareEcSkipped(skipped[index - 1], skipped[index]) == 0) {
      throw ArgumentError('Duplicate Layergram v3 EC skipped message key');
    }
  }
}

void _validatePqSkipped(
  List<V3PqSkippedMessageKey> skipped,
  List<V3PqEpochState> epochs,
) {
  final epochNumbers = epochs.map((value) => value.epoch).toSet();
  for (var index = 0; index < skipped.length; index++) {
    if (!epochNumbers.contains(skipped[index].epoch)) {
      throw ArgumentError(
        'Layergram v3 PQ skipped key references a retired epoch',
      );
    }
    if (index > 0 &&
        _comparePqSkipped(skipped[index - 1], skipped[index]) == 0) {
      throw ArgumentError('Duplicate Layergram v3 PQ skipped message key');
    }
  }
}

int _compareEcSkipped(
  V3EcSkippedMessageKey left,
  V3EcSkippedMessageKey right,
) {
  final keyOrder =
      _compareBytes(left._ratchetPublicKey, right._ratchetPublicKey);
  if (keyOrder != 0) return keyOrder;
  return left.messageCounter.compareTo(right.messageCounter);
}

int _comparePqSkipped(
  V3PqSkippedMessageKey left,
  V3PqSkippedMessageKey right,
) {
  final epochOrder = left.epoch.compareTo(right.epoch);
  if (epochOrder != 0) return epochOrder;
  return left.messageCounter.compareTo(right.messageCounter);
}

int _compareBytes(List<int> left, List<int> right) {
  final length = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    final order = left[index].compareTo(right[index]);
    if (order != 0) return order;
  }
  return left.length.compareTo(right.length);
}

void _validateCounter(int value, String name) {
  if (value < 0 || value > 0x7fffffffffffffff) {
    throw ArgumentError.value(value, name);
  }
}

void _validateExpiry(int expiresAtUnixSeconds) {
  if (expiresAtUnixSeconds < 1 || expiresAtUnixSeconds > 0x7fffffffffffffff) {
    throw ArgumentError.value(
      expiresAtUnixSeconds,
      'expiresAtUnixSeconds',
    );
  }
}

Uint8List _validatedSecret(Uint8List value, String name) => _validatedBytes(
      value,
      32,
      name,
      rejectAllZero: true,
    );

Uint8List _validatedX25519PublicKey(Uint8List value, String name) {
  if (value.length != 32) {
    throw ArgumentError.value(
      value.length,
      '$name.length',
      'must be exactly 32 bytes',
    );
  }
  if (_isAllZero(value)) {
    throw ArgumentError.value(value, name, 'must not be all zero');
  }
  const fieldPrimeLittleEndian = <int>[
    0xed,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x7f,
  ];
  for (var index = 31; index >= 0; index--) {
    if (value[index] < fieldPrimeLittleEndian[index]) {
      return Uint8List.fromList(value);
    }
    if (value[index] > fieldPrimeLittleEndian[index]) {
      throw ArgumentError.value(value, name, 'must be canonical X25519');
    }
  }
  throw ArgumentError.value(value, name, 'must be canonical X25519');
}

Uint8List _validatedBytes(
  Uint8List value,
  int length,
  String name, {
  required bool rejectAllZero,
}) {
  if (value.length != length) {
    throw ArgumentError.value(
      value.length,
      '$name.length',
      'must be exactly $length bytes',
    );
  }
  final copy = Uint8List.fromList(value);
  if (rejectAllZero && _isAllZero(copy)) {
    _wipeBytes(copy);
    throw ArgumentError.value(value, name, 'must not be all zero');
  }
  return copy;
}

Uint8List _copyRange(Uint8List source, int offset, int length) =>
    Uint8List.fromList(source.sublist(offset, offset + length));

Uint8List _copySensitive(
  Uint8List source,
  int offset,
  List<Uint8List> sensitive,
) {
  final value = _copyRange(source, offset, 32);
  sensitive.add(value);
  return value;
}

int _writeBytes(Uint8List target, int offset, List<int> value) {
  target.setRange(offset, offset + value.length, value);
  return offset + value.length;
}

bool _isAllZero(List<int> value) {
  var accumulator = 0;
  for (final byte in value) {
    accumulator |= byte;
  }
  return accumulator == 0;
}

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipeBytes(Uint8List value) {
  value.fillRange(0, value.length, 0);
}
