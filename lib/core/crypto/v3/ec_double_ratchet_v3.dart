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

import 'key_schedule_v3.dart';
import 'lmf_v3.dart';
import 'local_identity_v3.dart';
import 'triple_ratchet_binding_v3.dart';
import 'triple_ratchet_state_v3.dart';
import 'x25519_public_key_v3.dart';

/// Canonical public header produced by one EC Double Ratchet send step.
///
/// The header is not confidential. A future reviewed Triple Ratchet envelope
/// must authenticate its exact encoding together with the LMF metadata and the
/// sparse-PQ header before any candidate transition is committed.
final class V3EcRatchetHeader {
  factory V3EcRatchetHeader({
    required Uint8List ratchetPublicKey,
    required int previousSendingChainLength,
    required int messageCounter,
  }) {
    _validateCounter(
      previousSendingChainLength,
      'previousSendingChainLength',
    );
    _validateCounter(messageCounter, 'messageCounter');
    return V3EcRatchetHeader._(
      ratchetPublicKey: _validatedX25519PublicKey(
        ratchetPublicKey,
        'ratchetPublicKey',
      ),
      previousSendingChainLength: previousSendingChainLength,
      messageCounter: messageCounter,
    );
  }

  V3EcRatchetHeader._({
    required Uint8List ratchetPublicKey,
    required this.previousSendingChainLength,
    required this.messageCounter,
  }) : _ratchetPublicKey = ratchetPublicKey;

  final Uint8List _ratchetPublicKey;
  final int previousSendingChainLength;
  final int messageCounter;

  Uint8List get ratchetPublicKey => Uint8List.fromList(_ratchetPublicKey);
}

/// Strict fixed-width encoding for [V3EcRatchetHeader].
abstract final class V3EcRatchetHeaderCodec {
  static const List<int> magic = <int>[0x44, 0x52, 0x33]; // "DR3"
  static const int formatVersion = 1;
  static const int encodedBytes = 56;

  static Uint8List encode(V3EcRatchetHeader header) {
    final result = Uint8List(encodedBytes);
    final data = ByteData.sublistView(result);
    result.setRange(0, magic.length, magic);
    result[3] = formatVersion;
    result[4] = V3LmfSuite.hybridX25519MlKem768Aes256Gcm.wireId;
    result[5] = 0;
    data.setUint16(6, encodedBytes, Endian.big);
    result.setRange(8, 40, header._ratchetPublicKey);
    data.setUint64(40, header.previousSendingChainLength, Endian.big);
    data.setUint64(48, header.messageCounter, Endian.big);
    return result;
  }

  static V3EcRatchetHeader decode(Uint8List encoded) {
    if (encoded.length != encodedBytes) {
      throw const FormatException(
        'Invalid Layergram v3 EC ratchet header length',
      );
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException(
          'Invalid Layergram v3 EC ratchet header magic',
        );
      }
    }
    if (encoded[3] != formatVersion ||
        encoded[4] != V3LmfSuite.hybridX25519MlKem768Aes256Gcm.wireId ||
        encoded[5] != 0 ||
        ByteData.sublistView(encoded).getUint16(6, Endian.big) !=
            encodedBytes) {
      throw const FormatException(
        'Unsupported Layergram v3 EC ratchet header format',
      );
    }
    final data = ByteData.sublistView(encoded);
    try {
      return V3EcRatchetHeader(
        ratchetPublicKey: Uint8List.fromList(encoded.sublist(8, 40)),
        previousSendingChainLength: data.getUint64(40, Endian.big),
        messageCounter: data.getUint64(48, Endian.big),
      );
    } on ArgumentError catch (error) {
      throw FormatException(
        'Invalid Layergram v3 EC ratchet header fields',
        error,
      );
    }
  }
}

/// Isolated EC component of one protocol-v3 Triple Ratchet session.
///
/// The state is immutable from the caller's perspective. Send and receive
/// operations return candidate transitions so failed authentication never
/// advances the committed state. Secrets are copied at every ownership
/// boundary and can be overwritten on a best-effort basis with [close].
final class V3EcDoubleRatchetState {
  factory V3EcDoubleRatchetState._({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List rootKey,
    required Uint8List sendingChainKey,
    required Uint8List? receivingChainKey,
    required Uint8List localDhPrivateKey,
    required Uint8List localDhPublicKey,
    required Uint8List remoteDhPublicKey,
    required int sendCounter,
    required int receiveCounter,
    required int previousSendingChainLength,
    required int snapshotRevision,
    required List<V3EcSkippedMessageKey> skippedMessageKeys,
    required Uint8List? priorSnapshotBinding,
  }) {
    _validateCounter(sendCounter, 'sendCounter');
    _validateCounter(receiveCounter, 'receiveCounter');
    _validateCounter(
      previousSendingChainLength,
      'previousSendingChainLength',
    );
    _validateCounter(snapshotRevision, 'snapshotRevision');
    if (receivingChainKey == null && receiveCounter != 0) {
      throw ArgumentError.value(
        receiveCounter,
        'receiveCounter',
        'must be zero when the receiving chain is absent',
      );
    }
    if (receivingChainKey == null && role != V3SessionRole.initiator) {
      throw ArgumentError(
        'Only the initial Layergram v3 initiator may lack an EC receiving chain',
      );
    }
    Uint8List? checkedSessionId;
    Uint8List? checkedRoot;
    Uint8List? checkedSending;
    Uint8List? checkedReceiving;
    Uint8List? checkedPrivate;
    Uint8List? checkedPriorSnapshotBinding;
    List<V3EcSkippedMessageKey>? checkedSkipped;
    try {
      checkedSessionId = _validatedBytes(
        sessionId,
        V3LmfFrameCodec.sessionIdBytes,
        'sessionId',
        rejectAllZero: true,
      );
      checkedRoot = _validatedSecret(rootKey, 'rootKey');
      checkedSending = _validatedSecret(sendingChainKey, 'sendingChainKey');
      checkedReceiving = receivingChainKey == null
          ? null
          : _validatedSecret(receivingChainKey, 'receivingChainKey');
      checkedPrivate = _validatedSecret(localDhPrivateKey, 'localDhPrivateKey');
      checkedPriorSnapshotBinding = priorSnapshotBinding == null
          ? null
          : _validatedBytes(
              priorSnapshotBinding,
              32,
              'priorSnapshotBinding',
              rejectAllZero: true,
            );
      final checkedPublic = _validatedX25519PublicKey(
        localDhPublicKey,
        'localDhPublicKey',
      );
      final checkedRemote = _validatedX25519PublicKey(
        remoteDhPublicKey,
        'remoteDhPublicKey',
      );
      checkedSkipped = _copyAndValidateSkipped(skippedMessageKeys);
      return V3EcDoubleRatchetState._owned(
        role: role,
        sessionId: checkedSessionId,
        rootKey: checkedRoot,
        sendingChainKey: checkedSending,
        receivingChainKey: checkedReceiving,
        localDhPrivateKey: checkedPrivate,
        localDhPublicKey: checkedPublic,
        remoteDhPublicKey: checkedRemote,
        sendCounter: sendCounter,
        receiveCounter: receiveCounter,
        previousSendingChainLength: previousSendingChainLength,
        snapshotRevision: snapshotRevision,
        skippedMessageKeys: checkedSkipped,
        priorSnapshotBinding: checkedPriorSnapshotBinding,
      );
    } catch (_) {
      if (checkedSessionId != null) _wipe(checkedSessionId);
      if (checkedRoot != null) _wipe(checkedRoot);
      if (checkedSending != null) _wipe(checkedSending);
      if (checkedReceiving != null) _wipe(checkedReceiving);
      if (checkedPrivate != null) _wipe(checkedPrivate);
      if (checkedPriorSnapshotBinding != null) {
        _wipe(checkedPriorSnapshotBinding);
      }
      if (checkedSkipped != null) {
        for (final value in checkedSkipped) {
          value.wipeSecret();
        }
      }
      rethrow;
    }
  }

  V3EcDoubleRatchetState._owned({
    required this.role,
    required Uint8List sessionId,
    required Uint8List rootKey,
    required Uint8List sendingChainKey,
    required Uint8List? receivingChainKey,
    required Uint8List localDhPrivateKey,
    required Uint8List localDhPublicKey,
    required Uint8List remoteDhPublicKey,
    required this.sendCounter,
    required this.receiveCounter,
    required this.previousSendingChainLength,
    required this.snapshotRevision,
    required List<V3EcSkippedMessageKey> skippedMessageKeys,
    required Uint8List? priorSnapshotBinding,
  })  : _sessionId = sessionId,
        _rootKey = rootKey,
        _sendingChainKey = sendingChainKey,
        _receivingChainKey = receivingChainKey,
        _localDhPrivateKey = localDhPrivateKey,
        _localDhPublicKey = localDhPublicKey,
        _remoteDhPublicKey = remoteDhPublicKey,
        _skippedMessageKeys = skippedMessageKeys,
        _priorSnapshotBinding = priorSnapshotBinding;

  final V3SessionRole role;
  final Uint8List _sessionId;
  final Uint8List _rootKey;
  final Uint8List _sendingChainKey;
  final Uint8List? _receivingChainKey;
  final Uint8List _localDhPrivateKey;
  final Uint8List _localDhPublicKey;
  final Uint8List _remoteDhPublicKey;
  final int sendCounter;
  final int receiveCounter;
  final int previousSendingChainLength;
  final int snapshotRevision;
  final List<V3EcSkippedMessageKey> _skippedMessageKeys;
  final Uint8List? _priorSnapshotBinding;
  bool _isClosed = false;

  bool get isClosed => _isClosed;
  bool get hasReceivingChain => _receivingChainKey != null;
  Uint8List get sessionId {
    _ensureOpen();
    return Uint8List.fromList(_sessionId);
  }

  Uint8List get rootKey {
    _ensureOpen();
    return _secretCopy(_rootKey);
  }

  Uint8List get sendingChainKey {
    _ensureOpen();
    return _secretCopy(_sendingChainKey);
  }

  Uint8List? get receivingChainKey {
    _ensureOpen();
    return _receivingChainKey == null ? null : _secretCopy(_receivingChainKey);
  }

  Uint8List get localDhPrivateKey {
    _ensureOpen();
    return _secretCopy(_localDhPrivateKey);
  }

  Uint8List get localDhPublicKey {
    _ensureOpen();
    return Uint8List.fromList(_localDhPublicKey);
  }

  Uint8List get remoteDhPublicKey {
    _ensureOpen();
    return Uint8List.fromList(_remoteDhPublicKey);
  }

  List<V3EcSkippedMessageKey> get skippedMessageKeys {
    _ensureOpen();
    return _copySkipped(_skippedMessageKeys);
  }

  /// Whether this candidate was derived from the exact canonical prior TR3.
  bool matchesPriorSnapshotBinding(Uint8List candidate) {
    _ensureOpen();
    final binding = _priorSnapshotBinding;
    return binding != null && _constantTimeEqual(binding, candidate);
  }

  /// Replaces only the EC component of [previous] and increments its revision.
  ///
  /// This does not persist or activate the result. The returned snapshot must
  /// still be committed through the v3 atomic application/ratchet journal.
  V3TripleRatchetState toTripleRatchetSnapshot(
    V3TripleRatchetState previous,
  ) {
    _ensureOpen();
    if (previous.role != role ||
        !_constantTimeEqual(previous.sessionId, _sessionId)) {
      throw const FormatException(
        'Layergram v3 EC state does not match Triple Ratchet snapshot',
      );
    }
    if (previous.lifecycle != V3RatchetLifecycle.active) {
      throw StateError('Layergram v3 Triple Ratchet session is not active');
    }
    if (snapshotRevision < 1 || previous.revision != snapshotRevision - 1) {
      throw StateError('Layergram v3 EC candidate snapshot revision conflict');
    }
    final priorBinding = _priorSnapshotBinding;
    if (priorBinding != null) {
      final candidateBinding = v3TripleRatchetPriorSnapshotBinding(previous);
      try {
        if (!_constantTimeEqual(priorBinding, candidateBinding)) {
          throw StateError(
            'Layergram v3 EC candidate prior snapshot conflict',
          );
        }
      } finally {
        _wipe(candidateBinding);
      }
    }
    return previous.replaceEcState(
      expectedRevision: snapshotRevision - 1,
      ecRootKey: _rootKey,
      ecSendingChainKey: _sendingChainKey,
      ecReceivingChainKey: _receivingChainKey,
      ecLocalDhPrivateKey: _localDhPrivateKey,
      ecLocalDhPublicKey: _localDhPublicKey,
      ecRemoteDhPublicKey: _remoteDhPublicKey,
      ecSendCounter: sendCounter,
      ecReceiveCounter: receiveCounter,
      ecPreviousSendingChainLength: previousSendingChainLength,
      ecSkippedMessageKeys: _skippedMessageKeys,
    );
  }

  /// Best-effort overwrite of managed-memory EC secrets in this instance.
  void close() {
    if (_isClosed) return;
    _wipe(_rootKey);
    _wipe(_sendingChainKey);
    if (_receivingChainKey != null) _wipe(_receivingChainKey);
    _wipe(_localDhPrivateKey);
    for (final skipped in _skippedMessageKeys) {
      skipped.wipeSecret();
    }
    if (_priorSnapshotBinding != null) _wipe(_priorSnapshotBinding);
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 EC Double Ratchet state closed');
    }
  }
}

/// One uncommitted EC send or receive transition.
///
/// The caller may derive the hybrid message material from [messageKey], verify
/// or seal the complete record, convert [nextState] into a TR3 snapshot, then
/// atomically persist it. Calling [close] abandons the candidate and wipes its
/// message key and next state.
final class V3EcRatchetTransition {
  V3EcRatchetTransition._({
    required this.header,
    required Uint8List messageKey,
    required V3EcDoubleRatchetState nextState,
  })  : _messageKey = messageKey,
        _nextState = nextState;

  final V3EcRatchetHeader header;
  final Uint8List _messageKey;
  final V3EcDoubleRatchetState _nextState;
  bool _isClosed = false;

  bool get isClosed => _isClosed;
  Uint8List get messageKey {
    _ensureOpen();
    return Uint8List.fromList(_messageKey);
  }

  V3EcDoubleRatchetState get nextState {
    _ensureOpen();
    return _nextState;
  }

  void close() {
    if (_isClosed) return;
    _wipe(_messageKey);
    _nextState.close();
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 EC ratchet transition closed');
    }
  }
}

/// X25519 Double Ratchet transition engine for protocol v3.
abstract final class V3EcDoubleRatchet {
  static const int maxCounter = 0x7fffffffffffffff;
  static const int maxSkippedMessageKeys =
      V3TripleRatchetStateCodec.maxSkippedKeysPerRatchet;

  static final X25519 _x25519 = X25519();
  static final Hkdf _rootKdf = Hkdf(
    hmac: Hmac.sha256(),
    outputLength: 64,
  );
  static final Hmac _chainHmac = Hmac.sha256();
  static final List<int> _rootLabel = utf8.encode(
    'layergram/v3/ec-double-ratchet/root\u0000',
  );
  static final List<int> _messageKeyLabel = utf8.encode(
    'layergram/v3/ec-double-ratchet/message-key\u0000',
  );
  static final List<int> _nextChainKeyLabel = utf8.encode(
    'layergram/v3/ec-double-ratchet/next-chain-key\u0000',
  );

  /// Initializes the EC ratchet only after the full hybrid handshake succeeds.
  ///
  /// The responder precomputes the standard first receive/send DH ratchet step
  /// because the authenticated handshake already supplies the initiator's
  /// initial ratchet public key. This preserves immediate bidirectional sending
  /// without inventing a second symmetric bootstrap chain.
  static Future<V3EcDoubleRatchetState> initializeFromHandshake(
    V3HandshakeEstablishedMaterial established,
  ) async {
    final sessionId = established.sessionKeys.sessionId;
    final initialRoot = established.sessionKeys.ecRatchetRootKey;
    final initialPrivate = established.localInitialRatchetPrivateSeed;
    final initialPublic = established.localInitialRatchetPublicKey;
    final remotePublic = established.remoteInitialRatchetPublicKey;
    Uint8List? derivedInitialPublic;
    Uint8List? dhOne;
    Uint8List? dhTwo;
    Uint8List? localPrivate;
    Uint8List? localPublic;
    Uint8List? root;
    Uint8List? sending;
    Uint8List? receiving;
    try {
      _ensureCanonicalX25519PublicKey(initialPublic, 'initial ratchet public');
      _ensureCanonicalX25519PublicKey(remotePublic, 'remote ratchet public');
      derivedInitialPublic = await _publicFromPrivate(initialPrivate);
      if (!_constantTimeEqual(derivedInitialPublic, initialPublic)) {
        throw const FormatException(
          'Layergram v3 handshake ratchet key pair mismatch',
        );
      }

      dhOne = await _dh(initialPrivate, remotePublic);
      final first = await _rootStep(initialRoot, dhOne, sessionId);
      root = first.rootKey;
      if (established.role == V3SessionRole.initiator) {
        sending = first.chainKey;
        localPrivate = Uint8List.fromList(initialPrivate);
        localPublic = Uint8List.fromList(initialPublic);
      } else {
        receiving = first.chainKey;
        final generated = await _generateKeyPair();
        localPrivate = generated.privateKey;
        localPublic = generated.publicKey;
        dhTwo = await _dh(localPrivate, remotePublic);
        final second = await _rootStep(root, dhTwo, sessionId);
        _wipe(root);
        root = second.rootKey;
        sending = second.chainKey;
      }

      return V3EcDoubleRatchetState._(
        role: established.role,
        sessionId: sessionId,
        rootKey: root,
        sendingChainKey: sending,
        receivingChainKey: receiving,
        localDhPrivateKey: localPrivate,
        localDhPublicKey: localPublic,
        remoteDhPublicKey: remotePublic,
        sendCounter: 0,
        receiveCounter: 0,
        previousSendingChainLength: 0,
        snapshotRevision: 0,
        skippedMessageKeys: const <V3EcSkippedMessageKey>[],
        priorSnapshotBinding: null,
      );
    } finally {
      _wipe(sessionId);
      _wipe(initialRoot);
      _wipe(initialPrivate);
      if (derivedInitialPublic != null) _wipe(derivedInitialPublic);
      if (dhOne != null) _wipe(dhOne);
      if (dhTwo != null) _wipe(dhTwo);
      if (localPrivate != null) _wipe(localPrivate);
      if (root != null) _wipe(root);
      if (sending != null) _wipe(sending);
      if (receiving != null) _wipe(receiving);
    }
  }

  /// Restores and validates the EC component of one canonical TR3 snapshot.
  static Future<V3EcDoubleRatchetState> restore(
    V3TripleRatchetState snapshot,
  ) async {
    if (snapshot.lifecycle != V3RatchetLifecycle.active) {
      throw StateError('Layergram v3 Triple Ratchet session is not active');
    }
    final sessionId = snapshot.sessionId;
    final root = snapshot.ecRootKey;
    final sending = snapshot.ecSendingChainKey;
    final receiving = snapshot.ecReceivingChainKey;
    final localPrivate = snapshot.ecLocalDhPrivateKey;
    final localPublic = snapshot.ecLocalDhPublicKey;
    final remotePublic = snapshot.ecRemoteDhPublicKey;
    final skipped = snapshot.ecSkippedMessageKeys;
    Uint8List? derivedPublic;
    Uint8List? priorSnapshotBinding;
    try {
      if (remotePublic == null) {
        throw const FormatException(
          'Layergram v3 EC ratchet remote public key is absent',
        );
      }
      derivedPublic = await _publicFromPrivate(localPrivate);
      if (!_constantTimeEqual(derivedPublic, localPublic)) {
        throw const FormatException(
          'Layergram v3 stored EC ratchet key pair mismatch',
        );
      }
      priorSnapshotBinding = v3TripleRatchetPriorSnapshotBinding(snapshot);
      return V3EcDoubleRatchetState._(
        role: snapshot.role,
        sessionId: sessionId,
        rootKey: root,
        sendingChainKey: sending,
        receivingChainKey: receiving,
        localDhPrivateKey: localPrivate,
        localDhPublicKey: localPublic,
        remoteDhPublicKey: remotePublic,
        sendCounter: snapshot.ecSendCounter,
        receiveCounter: snapshot.ecReceiveCounter,
        previousSendingChainLength: snapshot.ecPreviousSendingChainLength,
        snapshotRevision: snapshot.revision,
        skippedMessageKeys: skipped,
        priorSnapshotBinding: priorSnapshotBinding,
      );
    } finally {
      _wipe(sessionId);
      _wipe(root);
      _wipe(sending);
      if (receiving != null) _wipe(receiving);
      _wipe(localPrivate);
      if (derivedPublic != null) _wipe(derivedPublic);
      if (priorSnapshotBinding != null) _wipe(priorSnapshotBinding);
      for (final value in skipped) {
        value.wipeSecret();
      }
    }
  }

  /// Advances the symmetric sending chain without mutating [state].
  static Future<V3EcRatchetTransition> send(
    V3EcDoubleRatchetState state,
  ) async {
    state._ensureOpen();
    if (state.sendCounter >= maxCounter) {
      throw StateError('Layergram v3 EC send counter is exhausted');
    }
    if (state.snapshotRevision >= maxCounter) {
      throw StateError('Layergram v3 ratchet snapshot revision is exhausted');
    }
    final step = await _chainStep(state._sendingChainKey);
    V3EcDoubleRatchetState? next;
    try {
      final header = V3EcRatchetHeader(
        ratchetPublicKey: state._localDhPublicKey,
        previousSendingChainLength: state.previousSendingChainLength,
        messageCounter: state.sendCounter,
      );
      next = V3EcDoubleRatchetState._(
        role: state.role,
        sessionId: state._sessionId,
        rootKey: state._rootKey,
        sendingChainKey: step.nextChainKey,
        receivingChainKey: state._receivingChainKey,
        localDhPrivateKey: state._localDhPrivateKey,
        localDhPublicKey: state._localDhPublicKey,
        remoteDhPublicKey: state._remoteDhPublicKey,
        sendCounter: state.sendCounter + 1,
        receiveCounter: state.receiveCounter,
        previousSendingChainLength: state.previousSendingChainLength,
        snapshotRevision: state.snapshotRevision + 1,
        skippedMessageKeys: state._skippedMessageKeys,
        priorSnapshotBinding: state._priorSnapshotBinding,
      );
      final transition = V3EcRatchetTransition._(
        header: header,
        messageKey: step.messageKey!,
        nextState: next,
      );
      next = null;
      step.messageKey = null;
      return transition;
    } finally {
      _wipe(step.nextChainKey);
      if (step.messageKey != null) _wipe(step.messageKey!);
      next?.close();
    }
  }

  /// Derives a candidate receive transition for [header].
  ///
  /// Skipped keys expire only according to caller-supplied local time. The
  /// candidate must be abandoned if the future hybrid AEAD verification fails;
  /// the original [state] remains unchanged and the skipped key is not consumed.
  static Future<V3EcRatchetTransition> receive({
    required V3EcDoubleRatchetState state,
    required V3EcRatchetHeader header,
    required int nowUnixSeconds,
    required int skippedKeyLifetimeSeconds,
  }) async {
    state._ensureOpen();
    _validatePositiveCounter(nowUnixSeconds, 'nowUnixSeconds');
    _validatePositiveCounter(
      skippedKeyLifetimeSeconds,
      'skippedKeyLifetimeSeconds',
    );
    if (nowUnixSeconds > maxCounter - skippedKeyLifetimeSeconds) {
      throw ArgumentError('Layergram v3 skipped-key expiry overflows');
    }
    if (state.snapshotRevision >= maxCounter) {
      throw StateError('Layergram v3 ratchet snapshot revision is exhausted');
    }
    final expiresAt = nowUnixSeconds + skippedKeyLifetimeSeconds;

    var root = Uint8List.fromList(state._rootKey);
    var sending = Uint8List.fromList(state._sendingChainKey);
    Uint8List? receiving = state._receivingChainKey == null
        ? null
        : Uint8List.fromList(state._receivingChainKey);
    var localPrivate = Uint8List.fromList(state._localDhPrivateKey);
    var localPublic = Uint8List.fromList(state._localDhPublicKey);
    var remotePublic = Uint8List.fromList(state._remoteDhPublicKey);
    var sendCounter = state.sendCounter;
    var receiveCounter = state.receiveCounter;
    var previousLength = state.previousSendingChainLength;
    final skipped = _copySkipped(state._skippedMessageKeys);
    Uint8List? messageKey;
    V3EcDoubleRatchetState? next;
    try {
      for (var index = skipped.length - 1; index >= 0; index--) {
        if (skipped[index].expiresAtUnixSeconds <= nowUnixSeconds) {
          skipped.removeAt(index).wipeSecret();
        }
      }

      for (var index = 0; index < skipped.length; index++) {
        final candidate = skipped[index];
        if (candidate.messageCounter == header.messageCounter &&
            _constantTimeEqual(
              candidate.ratchetPublicKey,
              header._ratchetPublicKey,
            )) {
          messageKey = candidate.messageKey;
          skipped.removeAt(index).wipeSecret();
          next = V3EcDoubleRatchetState._(
            role: state.role,
            sessionId: state._sessionId,
            rootKey: root,
            sendingChainKey: sending,
            receivingChainKey: receiving,
            localDhPrivateKey: localPrivate,
            localDhPublicKey: localPublic,
            remoteDhPublicKey: remotePublic,
            sendCounter: sendCounter,
            receiveCounter: receiveCounter,
            previousSendingChainLength: previousLength,
            snapshotRevision: state.snapshotRevision + 1,
            skippedMessageKeys: skipped,
            priorSnapshotBinding: state._priorSnapshotBinding,
          );
          final transition = V3EcRatchetTransition._(
            header: header,
            messageKey: messageKey,
            nextState: next,
          );
          messageKey = null;
          next = null;
          return transition;
        }
      }

      final newRemote = !_constantTimeEqual(
        remotePublic,
        header._ratchetPublicKey,
      );
      if (newRemote) {
        if (header.previousSendingChainLength < receiveCounter) {
          throw const FormatException(
            'Layergram v3 EC previous-chain length moved backwards',
          );
        }
        final previousMissing =
            header.previousSendingChainLength - receiveCounter;
        final currentMissing = header.messageCounter;
        if ((receiving == null && previousMissing != 0) ||
            previousMissing > maxSkippedMessageKeys ||
            currentMissing > maxSkippedMessageKeys ||
            skipped.length + previousMissing + currentMissing >
                maxSkippedMessageKeys) {
          throw const FormatException(
            'Layergram v3 EC skipped-key limit exceeded',
          );
        }
        final advancedPrevious = await _skipUntil(
          chainKey: receiving,
          receiveCounter: receiveCounter,
          until: header.previousSendingChainLength,
          ratchetPublicKey: remotePublic,
          expiresAtUnixSeconds: expiresAt,
          skipped: skipped,
        );
        if (receiving != null) _wipe(receiving);
        receiving = advancedPrevious;

        previousLength = sendCounter;
        sendCounter = 0;
        receiveCounter = 0;
        _wipe(remotePublic);
        remotePublic = Uint8List.fromList(header._ratchetPublicKey);

        final dhReceive = await _dh(localPrivate, remotePublic);
        try {
          final receiveRoot =
              await _rootStep(root, dhReceive, state._sessionId);
          _wipe(root);
          root = receiveRoot.rootKey;
          if (receiving != null) _wipe(receiving);
          receiving = receiveRoot.chainKey;
        } finally {
          _wipe(dhReceive);
        }

        final generated = await _generateKeyPair();
        _wipe(localPrivate);
        localPrivate = generated.privateKey;
        _wipe(localPublic);
        localPublic = generated.publicKey;
        final dhSend = await _dh(localPrivate, remotePublic);
        try {
          final sendRoot = await _rootStep(root, dhSend, state._sessionId);
          _wipe(root);
          root = sendRoot.rootKey;
          _wipe(sending);
          sending = sendRoot.chainKey;
        } finally {
          _wipe(dhSend);
        }
      } else if (receiving == null) {
        throw const FormatException(
          'Layergram v3 EC receiving chain is not initialized',
        );
      }

      if (header.messageCounter < receiveCounter) {
        throw const FormatException(
          'Layergram v3 EC message key is stale or already consumed',
        );
      }
      final advancedCurrent = await _skipUntil(
        chainKey: receiving,
        receiveCounter: receiveCounter,
        until: header.messageCounter,
        ratchetPublicKey: remotePublic,
        expiresAtUnixSeconds: expiresAt,
        skipped: skipped,
      );
      _wipe(receiving);
      receiving = advancedCurrent;
      receiveCounter = header.messageCounter;
      if (receiveCounter >= maxCounter) {
        throw StateError('Layergram v3 EC receive counter is exhausted');
      }
      final target = await _chainStep(receiving!);
      _wipe(receiving);
      receiving = target.nextChainKey;
      messageKey = target.messageKey;
      receiveCounter++;

      next = V3EcDoubleRatchetState._(
        role: state.role,
        sessionId: state._sessionId,
        rootKey: root,
        sendingChainKey: sending,
        receivingChainKey: receiving,
        localDhPrivateKey: localPrivate,
        localDhPublicKey: localPublic,
        remoteDhPublicKey: remotePublic,
        sendCounter: sendCounter,
        receiveCounter: receiveCounter,
        previousSendingChainLength: previousLength,
        snapshotRevision: state.snapshotRevision + 1,
        skippedMessageKeys: skipped,
        priorSnapshotBinding: state._priorSnapshotBinding,
      );
      final transition = V3EcRatchetTransition._(
        header: header,
        messageKey: messageKey!,
        nextState: next,
      );
      messageKey = null;
      next = null;
      return transition;
    } finally {
      _wipe(root);
      _wipe(sending);
      if (receiving != null) _wipe(receiving);
      _wipe(localPrivate);
      _wipe(localPublic);
      _wipe(remotePublic);
      if (messageKey != null) _wipe(messageKey);
      next?.close();
      for (final value in skipped) {
        value.wipeSecret();
      }
    }
  }

  static Future<Uint8List?> _skipUntil({
    required Uint8List? chainKey,
    required int receiveCounter,
    required int until,
    required Uint8List ratchetPublicKey,
    required int expiresAtUnixSeconds,
    required List<V3EcSkippedMessageKey> skipped,
  }) async {
    if (until < receiveCounter) {
      throw const FormatException(
        'Layergram v3 EC skipped-key counter moved backwards',
      );
    }
    final missing = until - receiveCounter;
    if (missing == 0) {
      return chainKey == null ? null : Uint8List.fromList(chainKey);
    }
    if (chainKey == null) {
      throw const FormatException(
        'Layergram v3 EC receiving chain is absent',
      );
    }
    if (missing > maxSkippedMessageKeys ||
        skipped.length + missing > maxSkippedMessageKeys) {
      throw const FormatException(
        'Layergram v3 EC skipped-key limit exceeded',
      );
    }

    Uint8List? current = Uint8List.fromList(chainKey);
    try {
      for (var counter = receiveCounter; counter < until; counter++) {
        final step = await _chainStep(current!);
        try {
          _wipe(current);
          current = step.nextChainKey;
          skipped.add(
            V3EcSkippedMessageKey(
              ratchetPublicKey: ratchetPublicKey,
              messageCounter: counter,
              messageKey: step.messageKey!,
              expiresAtUnixSeconds: expiresAtUnixSeconds,
            ),
          );
        } finally {
          if (step.messageKey != null) _wipe(step.messageKey!);
          step.messageKey = null;
        }
      }
      final result = current;
      current = null;
      return result;
    } finally {
      if (current != null) _wipe(current);
    }
  }

  static Future<_RootStep> _rootStep(
    Uint8List rootKey,
    Uint8List dhOutput,
    Uint8List sessionId,
  ) async {
    final derived = Uint8List.fromList(
      await (await _rootKdf.deriveKey(
        secretKey: SecretKey(dhOutput),
        nonce: rootKey,
        info: <int>[..._rootLabel, ...sessionId],
      ))
          .extractBytes(),
    );
    try {
      final nextRoot = Uint8List.fromList(derived.sublist(0, 32));
      final chain = Uint8List.fromList(derived.sublist(32, 64));
      try {
        _requireNonZero(nextRoot, 'root key');
        _requireNonZero(chain, 'chain key');
        return _RootStep(rootKey: nextRoot, chainKey: chain);
      } catch (_) {
        _wipe(nextRoot);
        _wipe(chain);
        rethrow;
      }
    } finally {
      _wipe(derived);
    }
  }

  static Future<_ChainStep> _chainStep(Uint8List chainKey) async {
    final message = Uint8List.fromList(
      (await _chainHmac.calculateMac(
        _messageKeyLabel,
        secretKey: SecretKey(chainKey),
      ))
          .bytes,
    );
    final next = Uint8List.fromList(
      (await _chainHmac.calculateMac(
        _nextChainKeyLabel,
        secretKey: SecretKey(chainKey),
      ))
          .bytes,
    );
    try {
      _requireNonZero(message, 'message key');
      _requireNonZero(next, 'next chain key');
      return _ChainStep(messageKey: message, nextChainKey: next);
    } catch (_) {
      _wipe(message);
      _wipe(next);
      rethrow;
    }
  }

  static Future<Uint8List> _dh(
    Uint8List privateKey,
    Uint8List remotePublicKey,
  ) async {
    final pair = await _x25519.newKeyPairFromSeed(privateKey);
    final shared = await _x25519.sharedSecretKey(
      keyPair: pair,
      remotePublicKey: SimplePublicKey(
        remotePublicKey,
        type: KeyPairType.x25519,
      ),
    );
    final result = Uint8List.fromList(await shared.extractBytes());
    if (_isAllZero(result)) {
      _wipe(result);
      throw const FormatException(
        'Invalid Layergram v3 low-order X25519 public key',
      );
    }
    return result;
  }

  static Future<Uint8List> _publicFromPrivate(Uint8List privateKey) async {
    final pair = await _x25519.newKeyPairFromSeed(privateKey);
    final public = await pair.extractPublicKey();
    return Uint8List.fromList(public.bytes);
  }

  static Future<({Uint8List privateKey, Uint8List publicKey})>
      _generateKeyPair() async {
    final pair = await _x25519.newKeyPair();
    final privateKey = Uint8List.fromList(
      await pair.extractPrivateKeyBytes(),
    );
    final public = await pair.extractPublicKey();
    final publicKey = Uint8List.fromList(public.bytes);
    try {
      _requireNonZero(privateKey, 'X25519 private seed');
      _requireNonZero(publicKey, 'X25519 public key');
      return (privateKey: privateKey, publicKey: publicKey);
    } catch (_) {
      _wipe(privateKey);
      _wipe(publicKey);
      rethrow;
    }
  }
}

final class _RootStep {
  _RootStep({required this.rootKey, required this.chainKey});

  final Uint8List rootKey;
  final Uint8List chainKey;
}

final class _ChainStep {
  _ChainStep({required this.messageKey, required this.nextChainKey});

  Uint8List? messageKey;
  final Uint8List nextChainKey;
}

List<V3EcSkippedMessageKey> _copyAndValidateSkipped(
  List<V3EcSkippedMessageKey> source,
) {
  if (source.length > V3EcDoubleRatchet.maxSkippedMessageKeys) {
    throw ArgumentError.value(
      source.length,
      'skippedMessageKeys.length',
      'exceeds Layergram v3 EC skipped-key limit',
    );
  }
  final result = _copySkipped(source);
  try {
    result.sort(_compareSkipped);
    for (var index = 1; index < result.length; index++) {
      if (_compareSkipped(result[index - 1], result[index]) != 0) continue;
      throw ArgumentError('Duplicate Layergram v3 EC skipped message key');
    }
    return result;
  } catch (_) {
    for (final value in result) {
      value.wipeSecret();
    }
    rethrow;
  }
}

List<V3EcSkippedMessageKey> _copySkipped(
  List<V3EcSkippedMessageKey> source,
) {
  final result = <V3EcSkippedMessageKey>[];
  try {
    for (final value in source) {
      result.add(
        V3EcSkippedMessageKey(
          ratchetPublicKey: value.ratchetPublicKey,
          messageCounter: value.messageCounter,
          messageKey: value.messageKey,
          expiresAtUnixSeconds: value.expiresAtUnixSeconds,
        ),
      );
    }
    return result;
  } catch (_) {
    for (final value in result) {
      value.wipeSecret();
    }
    rethrow;
  }
}

int _compareSkipped(
  V3EcSkippedMessageKey left,
  V3EcSkippedMessageKey right,
) {
  final leftKey = left.ratchetPublicKey;
  final rightKey = right.ratchetPublicKey;
  for (var index = 0; index < leftKey.length; index++) {
    final order = leftKey[index].compareTo(rightKey[index]);
    if (order != 0) return order;
  }
  return left.messageCounter.compareTo(right.messageCounter);
}

Uint8List _secretCopy(Uint8List source) {
  final result = Uint8List.fromList(source);
  return result;
}

Uint8List _validatedSecret(Uint8List value, String name) => _validatedBytes(
      value,
      32,
      name,
      rejectAllZero: true,
    );

Uint8List _validatedX25519PublicKey(Uint8List value, String name) {
  _ensureCanonicalX25519PublicKey(value, name);
  return Uint8List.fromList(value);
}

void _ensureCanonicalX25519PublicKey(List<int> value, String name) {
  V3X25519PublicKey.validate(value, name);
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
  final result = Uint8List.fromList(value);
  if (rejectAllZero && _isAllZero(result)) {
    _wipe(result);
    throw ArgumentError.value(value, name, 'must not be all zero');
  }
  return result;
}

void _validateCounter(int value, String name) {
  if (value < 0 || value > V3EcDoubleRatchet.maxCounter) {
    throw ArgumentError.value(value, name);
  }
}

void _validatePositiveCounter(int value, String name) {
  if (value < 1 || value > V3EcDoubleRatchet.maxCounter) {
    throw ArgumentError.value(value, name);
  }
}

void _requireNonZero(Uint8List value, String name) {
  if (_isAllZero(value)) {
    _wipe(value);
    throw StateError('Layergram v3 derived all-zero $name');
  }
}

bool _isAllZero(List<int> value) {
  var aggregate = 0;
  for (final byte in value) {
    aggregate |= byte;
  }
  return aggregate == 0;
}

bool _constantTimeEqual(List<int> left, List<int> right) {
  var difference = left.length ^ right.length;
  final length = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipe(Uint8List value) {
  value.fillRange(0, value.length, 0);
}
