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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'hybrid_ratchet_header_v3.dart';
import 'lmf_v3.dart';
import 'lmf_v3_acknowledgement.dart';

/// Stable participant role within one authenticated protocol-v3 session.
enum V3SessionRole {
  initiator(1),
  responder(2);

  const V3SessionRole(this.wireId);

  final int wireId;

  static V3SessionRole fromWireId(int wireId) {
    for (final value in values) {
      if (value.wireId == wireId) return value;
    }
    throw const FormatException('Unsupported Layergram v3 session role');
  }
}

/// Canonical direction, independent of which endpoint is currently local.
enum V3TrafficDirection {
  initiatorToResponder(1),
  responderToInitiator(2);

  const V3TrafficDirection(this.wireId);

  final int wireId;

  static V3TrafficDirection fromWireId(int wireId) {
    for (final value in values) {
      if (value.wireId == wireId) return value;
    }
    throw const FormatException('Unsupported Layergram v3 traffic direction');
  }
}

/// Initial transcript-bound material for one inactive v3 session.
///
/// The future authenticated handshake supplies the two independent 32-byte
/// secrets and the SHA-384 digest of its complete canonical transcript. This
/// class deliberately does not define or weaken that handshake. It expands the
/// already authenticated inputs into independent Double Ratchet, sparse-PQ,
/// SCKA-state sealing, routing, and ACK domains.
final class V3SessionKeyMaterial {
  V3SessionKeyMaterial._({
    required Uint8List sessionId,
    required Uint8List transcriptDigest,
    required Uint8List initiatorRoutingBinding,
    required Uint8List responderRoutingBinding,
    required Uint8List ecRatchetRootKey,
    required Uint8List pqRatchetRootKey,
    required Uint8List sckaStateSealKey,
    required Uint8List initiatorToResponderAckRootKey,
    required Uint8List responderToInitiatorAckRootKey,
  })  : _sessionId = sessionId,
        _transcriptDigest = transcriptDigest,
        _initiatorRoutingBinding = initiatorRoutingBinding,
        _responderRoutingBinding = responderRoutingBinding,
        _ecRatchetRootKey = ecRatchetRootKey,
        _pqRatchetRootKey = pqRatchetRootKey,
        _sckaStateSealKey = sckaStateSealKey,
        _initiatorToResponderAckRootKey = initiatorToResponderAckRootKey,
        _responderToInitiatorAckRootKey = responderToInitiatorAckRootKey;

  final Uint8List _sessionId;
  final Uint8List _transcriptDigest;
  final Uint8List _initiatorRoutingBinding;
  final Uint8List _responderRoutingBinding;
  final Uint8List _ecRatchetRootKey;
  final Uint8List _pqRatchetRootKey;
  final Uint8List _sckaStateSealKey;
  final Uint8List _initiatorToResponderAckRootKey;
  final Uint8List _responderToInitiatorAckRootKey;

  bool _isClosed = false;

  bool get isClosed => _isClosed;

  Uint8List get sessionId => Uint8List.fromList(_sessionId);

  Uint8List get transcriptDigest => Uint8List.fromList(_transcriptDigest);

  Uint8List get initiatorRoutingBinding =>
      Uint8List.fromList(_initiatorRoutingBinding);

  Uint8List get responderRoutingBinding =>
      Uint8List.fromList(_responderRoutingBinding);

  Uint8List get ecRatchetRootKey {
    _ensureOpen();
    return Uint8List.fromList(_ecRatchetRootKey);
  }

  Uint8List get pqRatchetRootKey {
    _ensureOpen();
    return Uint8List.fromList(_pqRatchetRootKey);
  }

  Uint8List get sckaStateSealKey {
    _ensureOpen();
    return Uint8List.fromList(_sckaStateSealKey);
  }

  Uint8List get initiatorToResponderAckRootKey {
    _ensureOpen();
    return Uint8List.fromList(_initiatorToResponderAckRootKey);
  }

  Uint8List get responderToInitiatorAckRootKey {
    _ensureOpen();
    return Uint8List.fromList(_responderToInitiatorAckRootKey);
  }

  ({Uint8List senderBinding, Uint8List recipientBinding}) bindingsFor(
    V3TrafficDirection direction,
  ) {
    return switch (direction) {
      V3TrafficDirection.initiatorToResponder => (
          senderBinding: initiatorRoutingBinding,
          recipientBinding: responderRoutingBinding,
        ),
      V3TrafficDirection.responderToInitiator => (
          senderBinding: responderRoutingBinding,
          recipientBinding: initiatorRoutingBinding,
        ),
    };
  }

  V3TrafficDirection directionFor({
    required Uint8List senderBinding,
    required Uint8List recipientBinding,
  }) {
    if (_constantTimeEqual(senderBinding, _initiatorRoutingBinding) &&
        _constantTimeEqual(recipientBinding, _responderRoutingBinding)) {
      return V3TrafficDirection.initiatorToResponder;
    }
    if (_constantTimeEqual(senderBinding, _responderRoutingBinding) &&
        _constantTimeEqual(recipientBinding, _initiatorRoutingBinding)) {
      return V3TrafficDirection.responderToInitiator;
    }
    throw const FormatException(
      'Layergram v3 routing bindings do not match the session',
    );
  }

  void close() {
    if (_isClosed) return;
    _wipe(_ecRatchetRootKey);
    _wipe(_pqRatchetRootKey);
    _wipe(_sckaStateSealKey);
    _wipe(_initiatorToResponderAckRootKey);
    _wipe(_responderToInitiatorAckRootKey);
    _isClosed = true;
  }

  Uint8List _ackRootKeyFor(V3TrafficDirection direction) {
    _ensureOpen();
    return switch (direction) {
      V3TrafficDirection.initiatorToResponder =>
        _initiatorToResponderAckRootKey,
      V3TrafficDirection.responderToInitiator =>
        _responderToInitiatorAckRootKey,
    };
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 session key material is closed');
    }
  }
}

/// Hybrid key and deterministic nonce seed for one logical non-ACK message.
///
/// The message ID, AEAD key, and nonce seed all use independent HKDF info
/// labels. Callers must persist the resulting sealed frames before export and
/// must resend those exact bytes rather than seal changed plaintext again.
final class V3MessageKeyMaterial {
  V3MessageKeyMaterial._({
    required Uint8List messageId,
    required Uint8List aeadKey,
    required Uint8List nonceSeed,
    required Uint8List messageContext,
  })  : _messageId = messageId,
        _aeadKey = aeadKey,
        _nonceSeed = nonceSeed,
        _messageContext = messageContext;

  final Uint8List _messageId;
  final Uint8List _aeadKey;
  final Uint8List _nonceSeed;
  final Uint8List _messageContext;

  bool _isClosed = false;

  bool get isClosed => _isClosed;

  Uint8List get messageId {
    _ensureOpen();
    return Uint8List.fromList(_messageId);
  }

  SecretKey get secretKey {
    _ensureOpen();
    return SecretKey(Uint8List.fromList(_aeadKey));
  }

  /// Derives the unique 96-bit AES-GCM nonce for one canonical fragment.
  Future<Uint8List> nonceForFragment({
    required int fragmentIndex,
    required int fragmentCount,
    required int assembledPlaintextLength,
    int hybridRatchetHeaderLength = 0,
    Uint8List? hybridRatchetHeaderDigest,
  }) async {
    _ensureOpen();
    final checkedHybridDigest = _validatedHybridNonceBinding(
      kindWireId: _messageContext[3],
      hybridRatchetHeaderLength: hybridRatchetHeaderLength,
      hybridRatchetHeaderDigest: hybridRatchetHeaderDigest,
    );
    _validateFragmentContext(
      fragmentIndex: fragmentIndex,
      fragmentCount: fragmentCount,
      assembledPlaintextLength: assembledPlaintextLength,
      hybridRatchetHeaderLength: hybridRatchetHeaderLength,
    );
    final shape = Uint8List(42);
    final shapeData = ByteData.sublistView(shape)
      ..setUint16(0, fragmentIndex, Endian.big)
      ..setUint16(2, fragmentCount, Endian.big)
      ..setUint32(4, assembledPlaintextLength, Endian.big)
      ..setUint16(8, hybridRatchetHeaderLength, Endian.big);
    shape.setRange(10, shape.length, checkedHybridDigest);
    if (shapeData.lengthInBytes != shape.length) {
      throw StateError('Layergram v3 nonce context drift');
    }
    try {
      return _deriveHkdfSha256(
        inputKeyMaterial: _nonceSeed,
        salt: _zeroSalt,
        info: _concat(<List<int>>[
          _messageNonceLabel,
          _messageContext,
          _messageId,
          shape,
        ]),
        outputLength: V3LmfFrameCodec.nonceBytes,
      );
    } finally {
      _wipe(checkedHybridDigest);
      _wipe(shape);
    }
  }

  bool matchesMessageId(Uint8List candidate) {
    _ensureOpen();
    return _constantTimeEqual(candidate, _messageId);
  }

  Future<bool> matchesNonce({
    required Uint8List candidate,
    required int fragmentIndex,
    required int fragmentCount,
    required int assembledPlaintextLength,
    int hybridRatchetHeaderLength = 0,
    Uint8List? hybridRatchetHeaderDigest,
  }) async {
    final expected = await nonceForFragment(
      fragmentIndex: fragmentIndex,
      fragmentCount: fragmentCount,
      assembledPlaintextLength: assembledPlaintextLength,
      hybridRatchetHeaderLength: hybridRatchetHeaderLength,
      hybridRatchetHeaderDigest: hybridRatchetHeaderDigest,
    );
    try {
      return _constantTimeEqual(candidate, expected);
    } finally {
      _wipe(expected);
    }
  }

  void close() {
    if (_isClosed) return;
    _wipe(_aeadKey);
    _wipe(_nonceSeed);
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 message key material is closed');
    }
  }
}

/// Directional ACK key and nonce derived only from authenticated session state
/// and fields visible in the canonical ACK frame header.
final class V3AcknowledgementKeyMaterial {
  V3AcknowledgementKeyMaterial._({
    required Uint8List aeadKey,
    required Uint8List nonce,
  })  : _aeadKey = aeadKey,
        _nonce = nonce;

  final Uint8List _aeadKey;
  final Uint8List _nonce;
  bool _isClosed = false;

  SecretKey get secretKey {
    _ensureOpen();
    return SecretKey(Uint8List.fromList(_aeadKey));
  }

  Uint8List get nonce {
    _ensureOpen();
    return Uint8List.fromList(_nonce);
  }

  bool matchesNonce(Uint8List candidate) {
    _ensureOpen();
    return _constantTimeEqual(candidate, _nonce);
  }

  void close() {
    if (_isClosed) return;
    _wipe(_aeadKey);
    _wipe(_nonce);
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 acknowledgement key material is closed');
    }
  }
}

/// Inactive protocol-v3 extract-then-expand schedule.
///
/// HKDF-SHA-256 follows RFC 5869. Hybrid message derivation follows the Triple
/// Ratchet ordering recommended by Signal: the sparse-PQ message key is the
/// HKDF salt and the elliptic-curve message key is the input key material.
abstract final class V3KeySchedule {
  static const int secretBytes = 32;
  static const int transcriptDigestBytes = 48;

  static Future<V3SessionKeyMaterial> deriveSession({
    required Uint8List classicalHandshakeSecret,
    required Uint8List postQuantumHandshakeSecret,
    required Uint8List transcriptDigest,
  }) async {
    Uint8List? classicalSecret;
    Uint8List? postQuantumSecret;
    Uint8List? transcript;
    Uint8List? classicalSeed;
    Uint8List? postQuantumSeed;
    final derived = <Uint8List>[];
    try {
      classicalSecret = _validatedSecret(
        classicalHandshakeSecret,
        'classicalHandshakeSecret',
      );
      postQuantumSecret = _validatedSecret(
        postQuantumHandshakeSecret,
        'postQuantumHandshakeSecret',
      );
      transcript = _validatedBytes(
        transcriptDigest,
        transcriptDigestBytes,
        'transcriptDigest',
        rejectAllZero: true,
      );
      classicalSeed = await _deriveHkdfSha256(
        inputKeyMaterial: classicalSecret,
        salt: transcript,
        info: _sessionClassicalExtractLabel,
        outputLength: secretBytes,
      );
      postQuantumSeed = await _deriveHkdfSha256(
        inputKeyMaterial: postQuantumSecret,
        salt: transcript,
        info: _sessionPostQuantumExtractLabel,
        outputLength: secretBytes,
      );

      Future<Uint8List> expand(List<int> label, int length) async {
        final value = await _deriveHkdfSha256(
          inputKeyMaterial: classicalSeed!,
          salt: postQuantumSeed!,
          info: _concat(<List<int>>[label, transcript!]),
          outputLength: length,
        );
        derived.add(value);
        _requireDerivedNonZero(value);
        return value;
      }

      final sessionId =
          await expand(_sessionIdLabel, V3LmfFrameCodec.sessionIdBytes);
      final initiatorBinding = await expand(
        _initiatorRoutingBindingLabel,
        V3LmfFrameCodec.routingBindingBytes,
      );
      final responderBinding = await expand(
        _responderRoutingBindingLabel,
        V3LmfFrameCodec.routingBindingBytes,
      );
      final ecRoot = await expand(_ecRatchetRootLabel, secretBytes);
      final pqRoot = await expand(_pqRatchetRootLabel, secretBytes);
      final sckaStateSealKey = await expand(
        _sckaStateSealLabel,
        secretBytes,
      );
      final ackInitiatorToResponder = await expand(
        _ackInitiatorToResponderLabel,
        secretBytes,
      );
      final ackResponderToInitiator = await expand(
        _ackResponderToInitiatorLabel,
        secretBytes,
      );

      final result = V3SessionKeyMaterial._(
        sessionId: sessionId,
        transcriptDigest: Uint8List.fromList(transcript),
        initiatorRoutingBinding: initiatorBinding,
        responderRoutingBinding: responderBinding,
        ecRatchetRootKey: ecRoot,
        pqRatchetRootKey: pqRoot,
        sckaStateSealKey: sckaStateSealKey,
        initiatorToResponderAckRootKey: ackInitiatorToResponder,
        responderToInitiatorAckRootKey: ackResponderToInitiator,
      );
      derived.clear();
      return result;
    } finally {
      if (classicalSecret != null) _wipe(classicalSecret);
      if (postQuantumSecret != null) _wipe(postQuantumSecret);
      if (transcript != null) _wipe(transcript);
      if (classicalSeed != null) _wipe(classicalSeed);
      if (postQuantumSeed != null) _wipe(postQuantumSeed);
      for (final value in derived) {
        _wipe(value);
      }
    }
  }

  /// Combines one EC Double Ratchet message key and one sparse-PQ message key.
  ///
  /// ACK frames intentionally use [deriveAcknowledgement] instead. Missing,
  /// malformed, or all-zero input from either ratchet fails closed.
  static Future<V3MessageKeyMaterial> deriveMessage({
    required Uint8List ecMessageKey,
    required Uint8List pqMessageKey,
    required Uint8List sessionId,
    required V3TrafficDirection direction,
    required V3LmfFrameKind kind,
    required int epoch,
    required int messageCounter,
  }) async {
    if (kind == V3LmfFrameKind.acknowledgement) {
      throw ArgumentError.value(
        kind,
        'kind',
        'acknowledgements use the directional ACK schedule',
      );
    }
    _validateEpochAndCounter(epoch, messageCounter);
    Uint8List? ecKey;
    Uint8List? pqKey;
    Uint8List? checkedSessionId;
    Uint8List? context;
    final derived = <Uint8List>[];
    try {
      ecKey = _validatedSecret(ecMessageKey, 'ecMessageKey');
      pqKey = _validatedSecret(pqMessageKey, 'pqMessageKey');
      checkedSessionId = _validatedBytes(
        sessionId,
        V3LmfFrameCodec.sessionIdBytes,
        'sessionId',
        rejectAllZero: true,
      );
      context = _messageContext(
        sessionId: checkedSessionId,
        direction: direction,
        kind: kind,
        epoch: epoch,
        messageCounter: messageCounter,
      );
      Future<Uint8List> expand(List<int> label, int length) async {
        final value = await _deriveHkdfSha256(
          inputKeyMaterial: ecKey!,
          salt: pqKey!,
          info: _concat(<List<int>>[label, context!]),
          outputLength: length,
        );
        derived.add(value);
        _requireDerivedNonZero(value);
        return value;
      }

      final messageId =
          await expand(_messageIdLabel, V3LmfFrameCodec.messageIdBytes);
      final aeadKey = await expand(_messageAeadKeyLabel, secretBytes);
      final nonceSeed = await expand(_messageNonceSeedLabel, secretBytes);
      final result = V3MessageKeyMaterial._(
        messageId: messageId,
        aeadKey: aeadKey,
        nonceSeed: nonceSeed,
        messageContext: context,
      );
      derived.clear();
      return result;
    } finally {
      if (ecKey != null) _wipe(ecKey);
      if (pqKey != null) _wipe(pqKey);
      if (checkedSessionId != null) _wipe(checkedSessionId);
      for (final value in derived) {
        _wipe(value);
      }
    }
  }

  /// Derives a single-frame ACK key and nonce from its visible canonical
  /// metadata. Every newly sealed cumulative ACK must have a fresh message ID;
  /// retransmission reuses the exact already-sealed frame bytes.
  static Future<V3AcknowledgementKeyMaterial> deriveAcknowledgement({
    required V3SessionKeyMaterial session,
    required V3TrafficDirection direction,
    required V3LmfMessageMetadata metadata,
  }) async {
    session._ensureOpen();
    if (metadata.kind != V3LmfFrameKind.acknowledgement) {
      throw ArgumentError.value(
        metadata.kind,
        'metadata.kind',
        'must be an acknowledgement',
      );
    }
    if (!_constantTimeEqual(metadata.sessionId, session._sessionId)) {
      throw const FormatException(
        'Layergram v3 ACK session does not match key material',
      );
    }
    final expectedBindings = session.bindingsFor(direction);
    if (!_constantTimeEqual(
          metadata.senderBinding,
          expectedBindings.senderBinding,
        ) ||
        !_constantTimeEqual(
          metadata.recipientBinding,
          expectedBindings.recipientBinding,
        )) {
      throw const FormatException(
        'Layergram v3 ACK routing direction does not match key material',
      );
    }
    final context = _ackContext(metadata: metadata, direction: direction);
    final rootKey = Uint8List.fromList(session._ackRootKeyFor(direction));
    try {
      final aeadKey = await _deriveHkdfSha256(
        inputKeyMaterial: rootKey,
        salt: session._sessionId,
        info: _concat(<List<int>>[_ackAeadKeyLabel, context]),
        outputLength: secretBytes,
      );
      Uint8List? nonce;
      try {
        nonce = await _deriveHkdfSha256(
          inputKeyMaterial: rootKey,
          salt: session._sessionId,
          info: _concat(<List<int>>[_ackNonceLabel, context]),
          outputLength: V3LmfFrameCodec.nonceBytes,
        );
        _requireDerivedNonZero(aeadKey);
        _requireDerivedNonZero(nonce);
        return V3AcknowledgementKeyMaterial._(
          aeadKey: aeadKey,
          nonce: nonce,
        );
      } catch (_) {
        _wipe(aeadKey);
        if (nonce != null) _wipe(nonce);
        rethrow;
      }
    } finally {
      _wipe(rootKey);
    }
  }

  /// Derives ACK material from one already validated durable TR3 state.
  ///
  /// This boundary exists for crash-restored session controllers, which no
  /// longer retain the original handshake-only [V3SessionKeyMaterial] object.
  /// Both directional roots are supplied so [direction] selects the root
  /// internally rather than accepting an arbitrary caller-selected AEAD key.
  static Future<V3AcknowledgementKeyMaterial>
      deriveAcknowledgementFromCommittedState({
    required Uint8List sessionId,
    required Uint8List initiatorRoutingBinding,
    required Uint8List responderRoutingBinding,
    required Uint8List initiatorToResponderAckRootKey,
    required Uint8List responderToInitiatorAckRootKey,
    required V3TrafficDirection direction,
    required V3LmfMessageMetadata metadata,
  }) async {
    Uint8List? checkedSessionId;
    Uint8List? initiatorBinding;
    Uint8List? responderBinding;
    Uint8List? initiatorRoot;
    Uint8List? responderRoot;
    try {
      checkedSessionId = _validatedBytes(
        sessionId,
        V3LmfFrameCodec.sessionIdBytes,
        'sessionId',
        rejectAllZero: true,
      );
      initiatorBinding = _validatedBytes(
        initiatorRoutingBinding,
        V3LmfFrameCodec.routingBindingBytes,
        'initiatorRoutingBinding',
        rejectAllZero: true,
      );
      responderBinding = _validatedBytes(
        responderRoutingBinding,
        V3LmfFrameCodec.routingBindingBytes,
        'responderRoutingBinding',
        rejectAllZero: true,
      );
      initiatorRoot = _validatedSecret(
        initiatorToResponderAckRootKey,
        'initiatorToResponderAckRootKey',
      );
      responderRoot = _validatedSecret(
        responderToInitiatorAckRootKey,
        'responderToInitiatorAckRootKey',
      );
      if (metadata.kind != V3LmfFrameKind.acknowledgement ||
          !_constantTimeEqual(metadata.sessionId, checkedSessionId)) {
        throw const FormatException(
          'Layergram v3 ACK does not match committed session state',
        );
      }
      final expectedSender =
          direction == V3TrafficDirection.initiatorToResponder
              ? initiatorBinding
              : responderBinding;
      final expectedRecipient =
          direction == V3TrafficDirection.initiatorToResponder
              ? responderBinding
              : initiatorBinding;
      if (!_constantTimeEqual(metadata.senderBinding, expectedSender) ||
          !_constantTimeEqual(metadata.recipientBinding, expectedRecipient)) {
        throw const FormatException(
          'Layergram v3 ACK routing does not match committed session state',
        );
      }
      final context = _ackContext(metadata: metadata, direction: direction);
      final rootKey = direction == V3TrafficDirection.initiatorToResponder
          ? initiatorRoot
          : responderRoot;
      final aeadKey = await _deriveHkdfSha256(
        inputKeyMaterial: rootKey,
        salt: checkedSessionId,
        info: _concat(<List<int>>[_ackAeadKeyLabel, context]),
        outputLength: secretBytes,
      );
      Uint8List? nonce;
      try {
        nonce = await _deriveHkdfSha256(
          inputKeyMaterial: rootKey,
          salt: checkedSessionId,
          info: _concat(<List<int>>[_ackNonceLabel, context]),
          outputLength: V3LmfFrameCodec.nonceBytes,
        );
        _requireDerivedNonZero(aeadKey);
        _requireDerivedNonZero(nonce);
        return V3AcknowledgementKeyMaterial._(
          aeadKey: aeadKey,
          nonce: nonce,
        );
      } catch (_) {
        _wipe(aeadKey);
        if (nonce != null) _wipe(nonce);
        rethrow;
      }
    } finally {
      if (checkedSessionId != null) _wipe(checkedSessionId);
      if (initiatorBinding != null) _wipe(initiatorBinding);
      if (responderBinding != null) _wipe(responderBinding);
      if (initiatorRoot != null) _wipe(initiatorRoot);
      if (responderRoot != null) _wipe(responderRoot);
    }
  }
}

final Uint8List _zeroSalt = Uint8List(V3KeySchedule.secretBytes);

final List<int> _sessionClassicalExtractLabel =
    utf8.encode('layergram/v3/session/classical-extract\u0000');
final List<int> _sessionPostQuantumExtractLabel =
    utf8.encode('layergram/v3/session/post-quantum-extract\u0000');
final List<int> _sessionIdLabel = utf8.encode('layergram/v3/session/id\u0000');
final List<int> _initiatorRoutingBindingLabel =
    utf8.encode('layergram/v3/session/routing/initiator\u0000');
final List<int> _responderRoutingBindingLabel =
    utf8.encode('layergram/v3/session/routing/responder\u0000');
final List<int> _ecRatchetRootLabel =
    utf8.encode('layergram/v3/session/ec-ratchet-root\u0000');
final List<int> _pqRatchetRootLabel =
    utf8.encode('layergram/v3/session/pq-ratchet-root\u0000');
final List<int> _sckaStateSealLabel =
    utf8.encode('layergram/v3/session/scka-state-seal\u0000');
final List<int> _ackInitiatorToResponderLabel =
    utf8.encode('layergram/v3/session/ack/initiator-to-responder\u0000');
final List<int> _ackResponderToInitiatorLabel =
    utf8.encode('layergram/v3/session/ack/responder-to-initiator\u0000');
final List<int> _messageIdLabel =
    utf8.encode('layergram/v3/triple-ratchet/message-id\u0000');
final List<int> _messageAeadKeyLabel =
    utf8.encode('layergram/v3/triple-ratchet/aead-key\u0000');
final List<int> _messageNonceSeedLabel =
    utf8.encode('layergram/v3/triple-ratchet/nonce-seed\u0000');
final List<int> _messageNonceLabel =
    utf8.encode('layergram/v3/triple-ratchet/fragment-nonce\u0000');
final List<int> _ackAeadKeyLabel =
    utf8.encode('layergram/v3/ack/aead-key\u0000');
final List<int> _ackNonceLabel = utf8.encode('layergram/v3/ack/nonce\u0000');

Future<Uint8List> _deriveHkdfSha256({
  required List<int> inputKeyMaterial,
  required List<int> salt,
  required List<int> info,
  required int outputLength,
}) async {
  final algorithm = Hkdf(
    hmac: Hmac.sha256(),
    outputLength: outputLength,
  );
  final key = await algorithm.deriveKey(
    secretKey: SecretKey(inputKeyMaterial),
    nonce: salt,
    info: info,
  );
  return Uint8List.fromList(await key.extractBytes());
}

Uint8List _messageContext({
  required Uint8List sessionId,
  required V3TrafficDirection direction,
  required V3LmfFrameKind kind,
  required int epoch,
  required int messageCounter,
}) {
  final context = Uint8List(36);
  final data = ByteData.sublistView(context);
  context[0] = V3LmfFrameCodec.protocolVersion;
  context[1] = V3LmfSuite.hybridX25519MlKem768Aes256Gcm.wireId;
  context[2] = direction.wireId;
  context[3] = kind.wireId;
  data.setUint64(4, epoch, Endian.big);
  data.setUint64(12, messageCounter, Endian.big);
  context.setRange(20, 36, sessionId);
  return context;
}

Uint8List _ackContext({
  required V3LmfMessageMetadata metadata,
  required V3TrafficDirection direction,
}) {
  final context = Uint8List(128);
  final data = ByteData.sublistView(context);
  var offset = 0;
  context[offset++] = V3LmfFrameCodec.protocolVersion;
  context[offset++] = metadata.suite.wireId;
  context[offset++] = direction.wireId;
  context[offset++] = metadata.kind.wireId;
  context.setRange(offset, offset + 32, metadata.senderBinding);
  offset += 32;
  context.setRange(offset, offset + 32, metadata.recipientBinding);
  offset += 32;
  context.setRange(offset, offset + 16, metadata.messageId);
  offset += 16;
  context.setRange(offset, offset + 16, metadata.sessionId);
  offset += 16;
  data.setUint64(offset, metadata.epoch, Endian.big);
  offset += 8;
  data.setUint64(offset, metadata.messageCounter, Endian.big);
  offset += 8;
  data.setUint32(offset, metadata.expiresAtUnixSeconds, Endian.big);
  offset += 4;
  data.setUint16(offset, 0, Endian.big);
  offset += 2;
  data.setUint16(offset, 1, Endian.big);
  offset += 2;
  data.setUint32(offset, V3LmfAcknowledgementCodec.encodedBytes, Endian.big);
  offset += 4;
  if (offset != context.length) {
    throw StateError('Layergram v3 ACK key context drift');
  }
  return context;
}

void _validateEpochAndCounter(int epoch, int messageCounter) {
  if (epoch < 0 || epoch > 0x7fffffffffffffff) {
    throw ArgumentError.value(epoch, 'epoch');
  }
  if (messageCounter < 0 || messageCounter > 0x7fffffffffffffff) {
    throw ArgumentError.value(messageCounter, 'messageCounter');
  }
}

void _validateFragmentContext({
  required int fragmentIndex,
  required int fragmentCount,
  required int assembledPlaintextLength,
  required int hybridRatchetHeaderLength,
}) {
  if (fragmentCount < 1 || fragmentCount > V3LmfFrameCodec.maxFragments) {
    throw ArgumentError.value(fragmentCount, 'fragmentCount');
  }
  if (fragmentIndex < 0 || fragmentIndex >= fragmentCount) {
    throw ArgumentError.value(fragmentIndex, 'fragmentIndex');
  }
  if (assembledPlaintextLength < 1 ||
      assembledPlaintextLength > V3LmfFrameCodec.maxAssembledPlaintextBytes) {
    throw ArgumentError.value(
      assembledPlaintextLength,
      'assembledPlaintextLength',
    );
  }
  if (fragmentCount == 1 && hybridRatchetHeaderLength == 0) return;
  final expectedCount = V3LmfFrameCodec.canonicalFragmentCount(
    assembledPlaintextLength: assembledPlaintextLength,
    hybridRatchetHeaderLength: hybridRatchetHeaderLength,
  );
  if (fragmentCount != expectedCount) {
    throw ArgumentError('Non-canonical Layergram v3 fragment context');
  }
}

Uint8List _validatedHybridNonceBinding({
  required int kindWireId,
  required int hybridRatchetHeaderLength,
  required Uint8List? hybridRatchetHeaderDigest,
}) {
  final requiresHybrid = kindWireId == V3LmfFrameKind.application.wireId ||
      kindWireId == V3LmfFrameKind.pqRatchet.wireId;
  if (!requiresHybrid) {
    if (hybridRatchetHeaderDigest != null &&
        hybridRatchetHeaderDigest.length !=
            V3LmfFrameCodec.hybridRatchetHeaderDigestBytes) {
      throw ArgumentError.value(
        hybridRatchetHeaderDigest.length,
        'hybridRatchetHeaderDigest.length',
      );
    }
    if (hybridRatchetHeaderLength != 0 ||
        (hybridRatchetHeaderDigest != null &&
            !_isAllZero(hybridRatchetHeaderDigest))) {
      throw ArgumentError(
        'Layergram v3 non-ratchet nonce context cannot bind HR3',
      );
    }
    return Uint8List(V3LmfFrameCodec.hybridRatchetHeaderDigestBytes);
  }
  if (hybridRatchetHeaderLength < V3HybridRatchetHeaderCodec.minEncodedBytes ||
      hybridRatchetHeaderLength > V3HybridRatchetHeaderCodec.maxEncodedBytes) {
    throw ArgumentError.value(
      hybridRatchetHeaderLength,
      'hybridRatchetHeaderLength',
    );
  }
  if (hybridRatchetHeaderDigest == null ||
      hybridRatchetHeaderDigest.length !=
          V3LmfFrameCodec.hybridRatchetHeaderDigestBytes ||
      _isAllZero(hybridRatchetHeaderDigest)) {
    throw ArgumentError.value(
      hybridRatchetHeaderDigest,
      'hybridRatchetHeaderDigest',
    );
  }
  return Uint8List.fromList(hybridRatchetHeaderDigest);
}

Uint8List _validatedSecret(Uint8List value, String name) => _validatedBytes(
      value,
      V3KeySchedule.secretBytes,
      name,
      rejectAllZero: true,
    );

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
    _wipe(copy);
    throw ArgumentError.value(value, name, 'must not be all zero');
  }
  return copy;
}

void _requireDerivedNonZero(Uint8List value) {
  if (_isAllZero(value)) {
    throw StateError('Layergram v3 KDF produced an invalid all-zero value');
  }
}

Uint8List _concat(List<List<int>> values) {
  final length = values.fold<int>(0, (sum, value) => sum + value.length);
  final result = Uint8List(length);
  var offset = 0;
  for (final value in values) {
    result.setRange(offset, offset + value.length, value);
    offset += value.length;
  }
  return result;
}

bool _isAllZero(List<int> bytes) {
  var accumulator = 0;
  for (final value in bytes) {
    accumulator |= value;
  }
  return accumulator == 0;
}

bool _constantTimeEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipe(Uint8List bytes) {
  bytes.fillRange(0, bytes.length, 0);
}
