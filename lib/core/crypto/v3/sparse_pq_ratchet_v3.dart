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

import 'ec_double_ratchet_v3.dart';
import 'key_schedule_v3.dart';
import 'lmf_v3.dart';

/// Public SCKA message carried alongside one EC Double Ratchet header.
///
/// [nativePayload] is the canonical public message emitted by the future
/// reviewed ML-KEM Braid backend. It is not a serialized private state. The
/// visible epoch and PQ message counter let the receiver select the exact PQ
/// chain key before authenticating the enclosing LMF message.
final class V3SckaMessage {
  factory V3SckaMessage({
    required int sendingEpoch,
    required int messageCounter,
    required Uint8List nativePayload,
  }) {
    _validateCounter(sendingEpoch, 'sendingEpoch');
    _validateCounter(messageCounter, 'messageCounter');
    if (nativePayload.length > V3SckaMessageCodec.maxNativePayloadBytes) {
      throw ArgumentError.value(
        nativePayload.length,
        'nativePayload.length',
        'must not exceed ${V3SckaMessageCodec.maxNativePayloadBytes} bytes',
      );
    }
    return V3SckaMessage._(
      sendingEpoch: sendingEpoch,
      messageCounter: messageCounter,
      nativePayload: Uint8List.fromList(nativePayload),
    );
  }

  V3SckaMessage._({
    required this.sendingEpoch,
    required this.messageCounter,
    required Uint8List nativePayload,
  }) : _nativePayload = nativePayload;

  final int sendingEpoch;
  final int messageCounter;
  final Uint8List _nativePayload;

  Uint8List get nativePayload => Uint8List.fromList(_nativePayload);
}

/// Strict envelope around the backend-owned public SCKA message.
abstract final class V3SckaMessageCodec {
  static const List<int> magic = <int>[0x53, 0x4b, 0x33]; // "SK3"
  static const int formatVersion = 1;
  static const int headerBytes = 24;
  static const int maxNativePayloadBytes = 512;
  static const int maxEncodedBytes = headerBytes + maxNativePayloadBytes;

  static Uint8List encode(V3SckaMessage message) {
    final totalLength = headerBytes + message._nativePayload.length;
    final result = Uint8List(totalLength);
    final data = ByteData.sublistView(result);
    result.setRange(0, magic.length, magic);
    result[3] = formatVersion;
    result[4] = V3LmfSuite.hybridX25519MlKem768Aes256Gcm.wireId;
    result[5] = 0;
    data.setUint16(6, totalLength, Endian.big);
    data.setUint64(8, message.sendingEpoch, Endian.big);
    data.setUint64(16, message.messageCounter, Endian.big);
    result.setRange(headerBytes, totalLength, message._nativePayload);
    return result;
  }

  static V3SckaMessage decode(Uint8List encoded) {
    if (encoded.length < headerBytes || encoded.length > maxEncodedBytes) {
      throw const FormatException('Invalid Layergram v3 SCKA message length');
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException('Invalid Layergram v3 SCKA message magic');
      }
    }
    final data = ByteData.sublistView(encoded);
    if (encoded[3] != formatVersion ||
        encoded[4] != V3LmfSuite.hybridX25519MlKem768Aes256Gcm.wireId ||
        encoded[5] != 0 ||
        data.getUint16(6, Endian.big) != encoded.length) {
      throw const FormatException(
        'Unsupported Layergram v3 SCKA message format',
      );
    }
    try {
      return V3SckaMessage(
        sendingEpoch: data.getUint64(8, Endian.big),
        messageCounter: data.getUint64(16, Endian.big),
        nativePayload: Uint8List.fromList(encoded.sublist(headerBytes)),
      );
    } on ArgumentError catch (error) {
      throw FormatException('Invalid Layergram v3 SCKA message fields', error);
    }
  }
}

/// One epoch secret emitted by the SCKA.
///
/// This is input to the Layergram PQ epoch-chain schedule, not an application
/// message key. It must never be used directly for message encryption.
final class V3SckaEpochSecret {
  factory V3SckaEpochSecret({
    required int epoch,
    required Uint8List secret,
  }) {
    _validateCounter(epoch, 'epoch');
    return V3SckaEpochSecret._(
      epoch: epoch,
      secret: _validatedSecret(secret, 'secret'),
    );
  }

  V3SckaEpochSecret._({required this.epoch, required Uint8List secret})
      : _secret = secret;

  final int epoch;
  final Uint8List _secret;
  bool _isWiped = false;

  Uint8List get secret {
    if (_isWiped) {
      throw StateError('Layergram v3 SCKA epoch secret is wiped');
    }
    return Uint8List.fromList(_secret);
  }

  bool get isWiped => _isWiped;

  void wipe() {
    if (_isWiped) return;
    _wipe(_secret);
    _isWiped = true;
  }
}

/// Non-mutating SCKA send result returned by a native backend.
final class V3SckaSendCandidate {
  factory V3SckaSendCandidate({
    required Uint8List nextAuthenticatedState,
    required V3SckaMessage message,
    V3SckaEpochSecret? epochSecret,
  }) {
    final nextState = _validatedStateExport(nextAuthenticatedState);
    if (epochSecret != null && epochSecret.epoch != message.sendingEpoch) {
      _wipe(nextState);
      throw ArgumentError(
        'Layergram v3 SCKA send secret must match the sending epoch',
      );
    }
    return V3SckaSendCandidate._(
      nextAuthenticatedState: nextState,
      message: message,
      epochSecret: epochSecret,
    );
  }

  V3SckaSendCandidate._({
    required Uint8List nextAuthenticatedState,
    required this.message,
    required this.epochSecret,
  }) : _nextAuthenticatedState = nextAuthenticatedState;

  final Uint8List _nextAuthenticatedState;
  final V3SckaMessage message;
  final V3SckaEpochSecret? epochSecret;
  bool _isClosed = false;

  Uint8List get nextAuthenticatedState {
    _ensureOpen();
    return Uint8List.fromList(_nextAuthenticatedState);
  }

  bool get isClosed => _isClosed;

  void close() {
    if (_isClosed) return;
    _wipe(_nextAuthenticatedState);
    epochSecret?.wipe();
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 SCKA send candidate is closed');
    }
  }
}

/// Non-mutating SCKA receive result returned by a native backend.
final class V3SckaReceiveCandidate {
  factory V3SckaReceiveCandidate({
    required Uint8List nextAuthenticatedState,
    required int receivingEpoch,
    V3SckaEpochSecret? epochSecret,
  }) {
    _validateCounter(receivingEpoch, 'receivingEpoch');
    final nextState = _validatedStateExport(nextAuthenticatedState);
    if (epochSecret != null && epochSecret.epoch != receivingEpoch) {
      _wipe(nextState);
      throw ArgumentError(
        'Layergram v3 SCKA receive secret must match the receiving epoch',
      );
    }
    return V3SckaReceiveCandidate._(
      nextAuthenticatedState: nextState,
      receivingEpoch: receivingEpoch,
      epochSecret: epochSecret,
    );
  }

  V3SckaReceiveCandidate._({
    required Uint8List nextAuthenticatedState,
    required this.receivingEpoch,
    required this.epochSecret,
  }) : _nextAuthenticatedState = nextAuthenticatedState;

  final Uint8List _nextAuthenticatedState;
  final int receivingEpoch;
  final V3SckaEpochSecret? epochSecret;
  bool _isClosed = false;

  Uint8List get nextAuthenticatedState {
    _ensureOpen();
    return Uint8List.fromList(_nextAuthenticatedState);
  }

  bool get isClosed => _isClosed;

  void close() {
    if (_isClosed) return;
    _wipe(_nextAuthenticatedState);
    epochSecret?.wipe();
    _isClosed = true;
  }

  void _ensureOpen() {
    if (_isClosed) {
      throw StateError('Layergram v3 SCKA receive candidate is closed');
    }
  }
}

/// Native ML-KEM Braid/SCKA boundary.
///
/// A conforming backend must implement the public ML-KEM Braid specification,
/// leave every input state byte-for-byte unchanged, and return a new candidate
/// state. Its state export must be internally versioned and authenticated to
/// [role] and [sessionId]. Returning an opaque serialization without semantic
/// validation or authentication does not satisfy this contract.
///
/// No production implementation is registered yet. Therefore this interface
/// alone does not activate or claim a post-quantum Layergram session.
abstract interface class V3SckaBackend {
  Future<Uint8List> initializeAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List sharedSecret,
  });

  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
  });

  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required int messageCounter,
  });

  Future<V3SckaReceiveCandidate> receiveCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required V3SckaMessage message,
  });
}

/// Defensive adapter around a reviewed [V3SckaBackend].
///
/// Caller-owned inputs are copied before the backend sees them. Candidate
/// exports are revalidated before they are returned. The caller must commit a
/// returned candidate state atomically with the matching EC candidate and
/// application effect; merely obtaining a candidate never advances state.
abstract final class V3SparsePqRatchet {
  static const int stateSecretBytes = 32;
  static const int maxAuthenticatedStateBytes = 192 * 1024;

  static Future<Uint8List> initialize({
    required V3SckaBackend backend,
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List sharedSecret,
  }) async {
    final checkedSession = _validatedSessionId(sessionId);
    final checkedSecret = _validatedSecret(sharedSecret, 'sharedSecret');
    Uint8List? backendSession;
    Uint8List? backendSecret;
    Uint8List? backendState;
    Uint8List? candidate;
    try {
      backendSession = Uint8List.fromList(checkedSession);
      backendSecret = Uint8List.fromList(checkedSecret);
      backendState = await backend.initializeAuthenticatedState(
        role: role,
        sessionId: backendSession,
        sharedSecret: backendSecret,
      );
      candidate = _validatedStateExport(
        backendState,
      );
      await _validateBackendState(
        backend: backend,
        role: role,
        sessionId: checkedSession,
        state: candidate,
      );
      final result = Uint8List.fromList(candidate);
      return result;
    } finally {
      _wipe(checkedSession);
      _wipe(checkedSecret);
      if (backendSession != null) _wipe(backendSession);
      if (backendSecret != null) _wipe(backendSecret);
      if (backendState != null) _wipe(backendState);
      if (candidate != null) _wipe(candidate);
    }
  }

  static Future<V3SckaSendCandidate> sendCandidate({
    required V3SckaBackend backend,
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required int messageCounter,
  }) async {
    _validateCounter(messageCounter, 'messageCounter');
    final checkedSession = _validatedSessionId(sessionId);
    final checkedState = _validatedStateExport(authenticatedState);
    Uint8List? backendSession;
    Uint8List? backendState;
    V3SckaSendCandidate? candidate;
    try {
      await _validateBackendState(
        backend: backend,
        role: role,
        sessionId: checkedSession,
        state: checkedState,
      );
      backendSession = Uint8List.fromList(checkedSession);
      backendState = Uint8List.fromList(checkedState);
      candidate = await backend.sendCandidate(
        role: role,
        sessionId: backendSession,
        authenticatedState: backendState,
        messageCounter: messageCounter,
      );
      if (candidate.message.messageCounter != messageCounter) {
        throw StateError('Layergram v3 SCKA backend changed message counter');
      }
      final nextState = candidate.nextAuthenticatedState;
      try {
        await _validateBackendState(
          backend: backend,
          role: role,
          sessionId: checkedSession,
          state: nextState,
        );
      } finally {
        _wipe(nextState);
      }
      final result = candidate;
      candidate = null;
      return result;
    } finally {
      candidate?.close();
      _wipe(checkedSession);
      _wipe(checkedState);
      if (backendSession != null) _wipe(backendSession);
      if (backendState != null) _wipe(backendState);
    }
  }

  static Future<V3SckaReceiveCandidate> receiveCandidate({
    required V3SckaBackend backend,
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required V3SckaMessage message,
  }) async {
    final checkedSession = _validatedSessionId(sessionId);
    final checkedState = _validatedStateExport(authenticatedState);
    Uint8List? backendSession;
    Uint8List? backendState;
    V3SckaReceiveCandidate? candidate;
    try {
      await _validateBackendState(
        backend: backend,
        role: role,
        sessionId: checkedSession,
        state: checkedState,
      );
      backendSession = Uint8List.fromList(checkedSession);
      backendState = Uint8List.fromList(checkedState);
      candidate = await backend.receiveCandidate(
        role: role,
        sessionId: backendSession,
        authenticatedState: backendState,
        message: message,
      );
      if (candidate.receivingEpoch != message.sendingEpoch) {
        throw StateError('Layergram v3 SCKA backend changed receiving epoch');
      }
      final nextState = candidate.nextAuthenticatedState;
      try {
        await _validateBackendState(
          backend: backend,
          role: role,
          sessionId: checkedSession,
          state: nextState,
        );
      } finally {
        _wipe(nextState);
      }
      final result = candidate;
      candidate = null;
      return result;
    } finally {
      candidate?.close();
      _wipe(checkedSession);
      _wipe(checkedState);
      if (backendSession != null) _wipe(backendSession);
      if (backendState != null) _wipe(backendState);
    }
  }

  static Future<void> _validateBackendState({
    required V3SckaBackend backend,
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List state,
  }) async {
    final backendSession = Uint8List.fromList(sessionId);
    final backendState = Uint8List.fromList(state);
    try {
      await backend.validateAuthenticatedState(
        role: role,
        sessionId: backendSession,
        authenticatedState: backendState,
      );
    } finally {
      _wipe(backendSession);
      _wipe(backendState);
    }
  }
}

/// Canonical public Triple Ratchet header containing both mandatory branches.
///
/// The exact encoded bytes must become AEAD associated data in the future LMF
/// composite-header revision. Encoding this object without authenticating it
/// does not authorize a state transition.
final class V3HybridRatchetHeader {
  const V3HybridRatchetHeader({
    required this.ecHeader,
    required this.sckaMessage,
  });

  final V3EcRatchetHeader ecHeader;
  final V3SckaMessage sckaMessage;
}

/// Strict container for the EC and sparse-PQ public ratchet messages.
abstract final class V3HybridRatchetHeaderCodec {
  static const List<int> magic = <int>[0x48, 0x52, 0x33]; // "HR3"
  static const int formatVersion = 1;
  static const int headerBytes = 16;
  static const int maxEncodedBytes = headerBytes +
      V3EcRatchetHeaderCodec.encodedBytes +
      V3SckaMessageCodec.maxEncodedBytes;

  static Uint8List encode(V3HybridRatchetHeader header) {
    final ec = V3EcRatchetHeaderCodec.encode(header.ecHeader);
    final scka = V3SckaMessageCodec.encode(header.sckaMessage);
    final totalLength = headerBytes + ec.length + scka.length;
    final result = Uint8List(totalLength);
    final data = ByteData.sublistView(result);
    result.setRange(0, magic.length, magic);
    result[3] = formatVersion;
    result[4] = V3LmfSuite.hybridX25519MlKem768Aes256Gcm.wireId;
    result[5] = 0;
    data.setUint16(6, headerBytes, Endian.big);
    data.setUint16(8, totalLength, Endian.big);
    data.setUint16(10, ec.length, Endian.big);
    data.setUint16(12, scka.length, Endian.big);
    data.setUint16(14, 0, Endian.big);
    result.setRange(headerBytes, headerBytes + ec.length, ec);
    result.setRange(headerBytes + ec.length, totalLength, scka);
    return result;
  }

  static V3HybridRatchetHeader decode(Uint8List encoded) {
    if (encoded.length <
            headerBytes +
                V3EcRatchetHeaderCodec.encodedBytes +
                V3SckaMessageCodec.headerBytes ||
        encoded.length > maxEncodedBytes) {
      throw const FormatException(
        'Invalid Layergram v3 hybrid ratchet header length',
      );
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException(
          'Invalid Layergram v3 hybrid ratchet header magic',
        );
      }
    }
    final data = ByteData.sublistView(encoded);
    final ecLength = data.getUint16(10, Endian.big);
    final sckaLength = data.getUint16(12, Endian.big);
    if (encoded[3] != formatVersion ||
        encoded[4] != V3LmfSuite.hybridX25519MlKem768Aes256Gcm.wireId ||
        encoded[5] != 0 ||
        data.getUint16(6, Endian.big) != headerBytes ||
        data.getUint16(8, Endian.big) != encoded.length ||
        ecLength != V3EcRatchetHeaderCodec.encodedBytes ||
        sckaLength < V3SckaMessageCodec.headerBytes ||
        sckaLength > V3SckaMessageCodec.maxEncodedBytes ||
        data.getUint16(14, Endian.big) != 0 ||
        headerBytes + ecLength + sckaLength != encoded.length) {
      throw const FormatException(
        'Unsupported Layergram v3 hybrid ratchet header format',
      );
    }
    final ecEnd = headerBytes + ecLength;
    return V3HybridRatchetHeader(
      ecHeader: V3EcRatchetHeaderCodec.decode(
        Uint8List.fromList(encoded.sublist(headerBytes, ecEnd)),
      ),
      sckaMessage: V3SckaMessageCodec.decode(
        Uint8List.fromList(encoded.sublist(ecEnd)),
      ),
    );
  }
}

Uint8List _validatedSessionId(Uint8List value) {
  if (value.length != V3LmfFrameCodec.sessionIdBytes || _isAllZero(value)) {
    throw ArgumentError.value(value, 'sessionId');
  }
  return Uint8List.fromList(value);
}

Uint8List _validatedSecret(Uint8List value, String name) {
  if (value.length != V3SparsePqRatchet.stateSecretBytes || _isAllZero(value)) {
    throw ArgumentError.value(value, name, 'must be 32 non-zero bytes');
  }
  return Uint8List.fromList(value);
}

Uint8List _validatedStateExport(Uint8List value) {
  if (value.isEmpty ||
      value.length > V3SparsePqRatchet.maxAuthenticatedStateBytes ||
      _isAllZero(value)) {
    throw ArgumentError.value(
      value.length,
      'authenticatedState.length',
      'must be a bounded non-zero authenticated export',
    );
  }
  return Uint8List.fromList(value);
}

void _validateCounter(int value, String name) {
  if (value < 0 || value > 0x7fffffffffffffff) {
    throw ArgumentError.value(value, name);
  }
}

bool _isAllZero(Uint8List value) {
  var anyNonZero = 0;
  for (final byte in value) {
    anyNonZero |= byte;
  }
  return anyNonZero == 0;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
