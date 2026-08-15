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

export 'hybrid_ratchet_header_v3.dart';

import 'hybrid_ratchet_header_v3.dart';
import 'key_schedule_v3.dart';

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
    required int sendingEpoch,
    required Uint8List nativePayload,
    V3SckaEpochSecret? epochSecret,
  }) {
    _validateCounter(sendingEpoch, 'sendingEpoch');
    final nextState = _validatedStateExport(nextAuthenticatedState);
    if (nativePayload.length > V3SckaMessageCodec.maxNativePayloadBytes) {
      _wipe(nextState);
      throw ArgumentError.value(
        nativePayload.length,
        'nativePayload.length',
        'must not exceed ${V3SckaMessageCodec.maxNativePayloadBytes} bytes',
      );
    }
    return V3SckaSendCandidate._(
      nextAuthenticatedState: nextState,
      sendingEpoch: sendingEpoch,
      nativePayload: Uint8List.fromList(nativePayload),
      epochSecret: epochSecret,
    );
  }

  V3SckaSendCandidate._({
    required Uint8List nextAuthenticatedState,
    required this.sendingEpoch,
    required Uint8List nativePayload,
    required this.epochSecret,
  })  : _nextAuthenticatedState = nextAuthenticatedState,
        _nativePayload = nativePayload;

  final Uint8List _nextAuthenticatedState;
  final int sendingEpoch;
  final Uint8List _nativePayload;
  final V3SckaEpochSecret? epochSecret;
  bool _isClosed = false;

  Uint8List get nextAuthenticatedState {
    _ensureOpen();
    return Uint8List.fromList(_nextAuthenticatedState);
  }

  bool get isClosed => _isClosed;

  /// Builds the public SK3 envelope after the Dart Sparse-PQ layer selects the
  /// exact chain counter for [sendingEpoch]. The backend owns only the native
  /// SCKA payload and epoch; it cannot choose or rewrite Layergram counters.
  V3SckaMessage messageForCounter(int messageCounter) {
    _ensureOpen();
    return V3SckaMessage(
      sendingEpoch: sendingEpoch,
      messageCounter: messageCounter,
      nativePayload: _nativePayload,
    );
  }

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
  /// Stable build identity used for diagnostics and release inventory.
  ///
  /// This value is process-local metadata. It is not encoded into SK3, HR3,
  /// TR3, or any other protocol record.
  String get implementationId;

  /// Exact ML-KEM Braid protocol revision implemented by this backend.
  int get protocolRevision;

  /// Runs the backend's immutable implementation and primitive self-tests.
  ///
  /// A successful result is necessary but not sufficient for production
  /// approval. A production implementation may cache a successful result only
  /// within the current process and binary. Independent review and per-ABI
  /// packaging tests remain mandatory.
  Future<bool> selfTest();

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
  static const int requiredBackendProtocolRevision = 1;
  static const int maxBackendImplementationIdBytes = 96;

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
      await _ensureBackendReady(backend);
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

  /// Validates one durable native state through the admitted backend.
  ///
  /// Future checkpoint/session restore wiring must use this adapter instead of
  /// invoking [V3SckaBackend.validateAuthenticatedState] directly.
  static Future<void> validateAuthenticatedState({
    required V3SckaBackend backend,
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
  }) async {
    final checkedSession = _validatedSessionId(sessionId);
    final checkedState = _validatedStateExport(authenticatedState);
    try {
      await _ensureBackendReady(backend);
      await _validateBackendState(
        backend: backend,
        role: role,
        sessionId: checkedSession,
        state: checkedState,
      );
    } finally {
      _wipe(checkedSession);
      _wipe(checkedState);
    }
  }

  static Future<V3SckaSendCandidate> sendCandidate({
    required V3SckaBackend backend,
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
  }) async {
    final checkedSession = _validatedSessionId(sessionId);
    final checkedState = _validatedStateExport(authenticatedState);
    Uint8List? backendSession;
    Uint8List? backendState;
    V3SckaSendCandidate? candidate;
    try {
      await _ensureBackendReady(backend);
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
      );
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
      await _ensureBackendReady(backend);
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

  static Future<void> _ensureBackendReady(V3SckaBackend backend) async {
    final implementationId = backend.implementationId;
    if (!_isCanonicalImplementationId(implementationId)) {
      throw StateError(
        'Layergram v3 SCKA backend implementation ID is invalid',
      );
    }
    if (backend.protocolRevision != requiredBackendProtocolRevision) {
      throw StateError(
        'Layergram v3 SCKA backend protocol revision is unsupported',
      );
    }
    if (!await backend.selfTest()) {
      throw StateError('Layergram v3 SCKA backend self-test failed');
    }
  }
}

bool _isCanonicalImplementationId(String value) {
  if (value.isEmpty ||
      value.length > V3SparsePqRatchet.maxBackendImplementationIdBytes) {
    return false;
  }
  final first = value.codeUnitAt(0);
  final firstIsLowercase = first >= 0x61 && first <= 0x7a;
  final firstIsDigit = first >= 0x30 && first <= 0x39;
  if (!firstIsLowercase && !firstIsDigit) return false;
  for (final codeUnit in value.codeUnits) {
    final isLowercase = codeUnit >= 0x61 && codeUnit <= 0x7a;
    final isDigit = codeUnit >= 0x30 && codeUnit <= 0x39;
    final isPunctuation = codeUnit == 0x2b ||
        codeUnit == 0x2d ||
        codeUnit == 0x2e ||
        codeUnit == 0x2f ||
        codeUnit == 0x5f;
    if (!isLowercase && !isDigit && !isPunctuation) return false;
  }
  return true;
}

Uint8List _validatedSessionId(Uint8List value) {
  if (value.length != _sessionIdBytes || _isAllZero(value)) {
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

const int _sessionIdBytes = 16;
