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

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'key_schedule_v3.dart';
import 'sparse_pq_ratchet_v3.dart';

/// Typed failure returned by the engineering-only SCKA candidate ABI.
final class V3SckaCandidateNativeException implements Exception {
  const V3SckaCandidateNativeException({
    required this.operation,
    required this.status,
  });

  final String operation;
  final int status;

  @override
  String toString() =>
      'V3SckaCandidateNativeException($operation, status: $status, '
      '${_statusDescription(status)})';
}

/// FFI bridge for the opt-in SCKA candidate build.
///
/// The normal Rust build keeps every operation and self-test at `NOT_READY`.
/// Only a library compiled deliberately with Cargo feature `candidate-ffi`
/// can satisfy this class's exact ABI/build allowlist. There is intentionally
/// no application registration point. The packaged factory is consumed only
/// by the scope-owned protocol-v3 bootstrap and remains unused by `main.dart`.
///
/// The allowlist is compiled into the signed Dart application binary: ABI,
/// protocol revision, state format, every fixed size, and the implementation
/// build ID must all match before the backend object can be constructed.
final class V3SckaCandidateFfiBackend implements V3SckaBackend {
  factory V3SckaCandidateFfiBackend.open({required String libraryPath}) =>
      V3SckaCandidateFfiBackend._(
        _V3SckaCandidateBindings(DynamicLibrary.open(libraryPath)),
      );

  /// Opens the candidate ABI embedded by Layergram's explicit packaging tools.
  ///
  /// Application code must open it through
  /// `V3SessionPersistenceScope.openPackagedScka`, which owns this backend
  /// together with persistence, receive resolution, and atomic commit.
  factory V3SckaCandidateFfiBackend.openPackaged() {
    if (Platform.isIOS || Platform.isMacOS) {
      return V3SckaCandidateFfiBackend._(
        _V3SckaCandidateBindings(DynamicLibrary.process()),
      );
    }
    if (Platform.isAndroid) {
      return V3SckaCandidateFfiBackend.open(
        libraryPath: 'liblayergram_scka.so',
      );
    }
    if (Platform.isLinux) {
      return V3SckaCandidateFfiBackend.open(
        libraryPath: packagedLinuxLibraryPath(),
      );
    }
    if (Platform.isWindows) {
      return V3SckaCandidateFfiBackend.open(
        libraryPath: packagedWindowsLibraryPath(),
      );
    }
    throw UnsupportedError(
      'Packaged Layergram SCKA is not available on '
      '${Platform.operatingSystem}',
    );
  }

  /// Resolves the Linux library from the executable-owned bundle directory.
  static String packagedLinuxLibraryPath({String? executablePath}) {
    final executable = File(executablePath ?? Platform.resolvedExecutable);
    return '${executable.parent.path}/lib/liblayergram_scka.so';
  }

  /// Resolves the Windows DLL from the executable-owned bundle directory.
  ///
  /// An absolute path avoids the ambient DLL search order.
  static String packagedWindowsLibraryPath({String? executablePath}) {
    final executable = File(executablePath ?? Platform.resolvedExecutable);
    return '${executable.parent.path}${Platform.pathSeparator}'
        'layergram_scka.dll';
  }

  V3SckaCandidateFfiBackend._(this._bindings) {
    _bindings.validateAllowlist();
  }

  static const String approvedImplementationId =
      'layergram-scka-private-r1-abi1-state2-build1';

  final _V3SckaCandidateBindings _bindings;

  @override
  String get implementationId => _bindings.implementationId();

  @override
  int get protocolRevision => _bindings.protocolRevision();

  @override
  Future<bool> selfTest() async => _bindings.selfTest() == _statusOk;

  @override
  Future<Uint8List> initializeAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List sharedSecret,
    required Uint8List stateSealKey,
  }) async {
    _requireLength(sessionId, _sessionIdBytes, 'sessionId');
    _requireLength(sharedSecret, _sharedSecretBytes, 'sharedSecret');
    _requireLength(stateSealKey, _stateKeyBytes, 'stateSealKey');
    final nativeSession = _copyToNative(sessionId);
    final nativeSecret = _copyToNative(sharedSecret);
    final nativeStateKey = _copyToNative(stateSealKey);
    final nativeState = calloc<Uint8>(_maxStateBytes);
    final nativeStateLength = calloc<Uint64>();
    try {
      final status = _bindings.initialize(
        role.wireId,
        nativeSession,
        sessionId.length,
        nativeStateKey,
        stateSealKey.length,
        nativeSecret,
        sharedSecret.length,
        nativeState,
        _maxStateBytes,
        nativeStateLength,
      );
      _throwOnNativeError(status, 'initialize');
      final length = _validatedStateLength(nativeStateLength.value);
      return _copyFromNative(nativeState, length);
    } finally {
      calloc.free(nativeSession);
      _wipeNative(nativeSecret, sharedSecret.length);
      calloc.free(nativeSecret);
      _wipeNative(nativeStateKey, stateSealKey.length);
      calloc.free(nativeStateKey);
      _wipeNative(nativeState, _maxStateBytes);
      calloc.free(nativeState);
      calloc.free(nativeStateLength);
    }
  }

  @override
  Future<void> validateAuthenticatedState({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    _requireLength(sessionId, _sessionIdBytes, 'sessionId');
    _requireState(authenticatedState);
    _requireLength(stateSealKey, _stateKeyBytes, 'stateSealKey');
    _requireCounter(expectedStateRevision, 'expectedStateRevision');
    final nativeSession = _copyToNative(sessionId);
    final nativeState = _copyToNative(authenticatedState);
    final nativeStateKey = _copyToNative(stateSealKey);
    try {
      _throwOnNativeError(
        _bindings.validateState(
          role.wireId,
          nativeSession,
          sessionId.length,
          nativeStateKey,
          stateSealKey.length,
          expectedStateRevision,
          nativeState,
          authenticatedState.length,
        ),
        'validateState',
      );
    } finally {
      calloc.free(nativeSession);
      _wipeNative(nativeState, authenticatedState.length);
      calloc.free(nativeState);
      _wipeNative(nativeStateKey, stateSealKey.length);
      calloc.free(nativeStateKey);
    }
  }

  @override
  Future<V3SckaSendCandidate> sendCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
  }) async {
    _requireLength(sessionId, _sessionIdBytes, 'sessionId');
    _requireState(authenticatedState);
    _requireLength(stateSealKey, _stateKeyBytes, 'stateSealKey');
    _requireTransitionCounter(expectedStateRevision);
    final nativeSession = _copyToNative(sessionId);
    final nativePrior = _copyToNative(authenticatedState);
    final nativeStateKey = _copyToNative(stateSealKey);
    final nativeState = calloc<Uint8>(_maxStateBytes);
    final nativeStateLength = calloc<Uint64>();
    final nativeMessage = calloc<Uint8>(_maxMessageBytes);
    final nativeMessageLength = calloc<Uint64>();
    final nativeSendingEpoch = calloc<Uint64>();
    final nativeHasEpochSecret = calloc<Uint32>();
    final nativeEpochSecretEpoch = calloc<Uint64>();
    final nativeEpochSecret = calloc<Uint8>(_epochSecretBytes);
    V3SckaEpochSecret? epochSecret;
    Uint8List? state;
    Uint8List? message;
    try {
      final status = _bindings.send(
        role.wireId,
        nativeSession,
        sessionId.length,
        nativeStateKey,
        stateSealKey.length,
        expectedStateRevision,
        nativePrior,
        authenticatedState.length,
        nativeState,
        _maxStateBytes,
        nativeStateLength,
        nativeMessage,
        _maxMessageBytes,
        nativeMessageLength,
        nativeSendingEpoch,
        nativeHasEpochSecret,
        nativeEpochSecretEpoch,
        nativeEpochSecret,
        _epochSecretBytes,
      );
      _throwOnNativeError(status, 'send');
      state = _copyFromNative(
        nativeState,
        _validatedStateLength(nativeStateLength.value),
      );
      final messageLength = _validatedMessageLength(nativeMessageLength.value);
      message = _copyFromNative(nativeMessage, messageLength);
      epochSecret = _epochSecret(
        hasSecret: nativeHasEpochSecret.value,
        epoch: nativeEpochSecretEpoch.value,
        bytes: nativeEpochSecret,
      );
      final result = V3SckaSendCandidate(
        nextAuthenticatedState: state,
        stateRevision: expectedStateRevision + 1,
        sendingEpoch:
            _validatedCounter(nativeSendingEpoch.value, 'sendingEpoch'),
        nativePayload: message,
        epochSecret: epochSecret,
      );
      epochSecret = null;
      return result;
    } finally {
      epochSecret?.wipe();
      if (state != null) _wipe(state);
      if (message != null) _wipe(message);
      calloc.free(nativeSession);
      _wipeNative(nativePrior, authenticatedState.length);
      calloc.free(nativePrior);
      _wipeNative(nativeStateKey, stateSealKey.length);
      calloc.free(nativeStateKey);
      _wipeNative(nativeState, _maxStateBytes);
      calloc.free(nativeState);
      calloc.free(nativeStateLength);
      _wipeNative(nativeMessage, _maxMessageBytes);
      calloc.free(nativeMessage);
      calloc.free(nativeMessageLength);
      calloc.free(nativeSendingEpoch);
      calloc.free(nativeHasEpochSecret);
      calloc.free(nativeEpochSecretEpoch);
      _wipeNative(nativeEpochSecret, _epochSecretBytes);
      calloc.free(nativeEpochSecret);
    }
  }

  @override
  Future<V3SckaReceiveCandidate> receiveCandidate({
    required V3SessionRole role,
    required Uint8List sessionId,
    required Uint8List authenticatedState,
    required Uint8List stateSealKey,
    required int expectedStateRevision,
    required V3SckaMessage message,
  }) async {
    _requireLength(sessionId, _sessionIdBytes, 'sessionId');
    _requireState(authenticatedState);
    _requireLength(stateSealKey, _stateKeyBytes, 'stateSealKey');
    _requireTransitionCounter(expectedStateRevision);
    final payload = message.nativePayload;
    _validatedMessageLength(payload.length);
    final nativeSession = _copyToNative(sessionId);
    final nativePrior = _copyToNative(authenticatedState);
    final nativeStateKey = _copyToNative(stateSealKey);
    final nativeMessage = _copyToNative(payload);
    final nativeState = calloc<Uint8>(_maxStateBytes);
    final nativeStateLength = calloc<Uint64>();
    final nativeReceivingEpoch = calloc<Uint64>();
    final nativeHasEpochSecret = calloc<Uint32>();
    final nativeEpochSecretEpoch = calloc<Uint64>();
    final nativeEpochSecret = calloc<Uint8>(_epochSecretBytes);
    V3SckaEpochSecret? epochSecret;
    Uint8List? state;
    try {
      final status = _bindings.receive(
        role.wireId,
        nativeSession,
        sessionId.length,
        nativeStateKey,
        stateSealKey.length,
        expectedStateRevision,
        nativePrior,
        authenticatedState.length,
        nativeMessage,
        payload.length,
        nativeState,
        _maxStateBytes,
        nativeStateLength,
        nativeReceivingEpoch,
        nativeHasEpochSecret,
        nativeEpochSecretEpoch,
        nativeEpochSecret,
        _epochSecretBytes,
      );
      _throwOnNativeError(status, 'receive');
      state = _copyFromNative(
        nativeState,
        _validatedStateLength(nativeStateLength.value),
      );
      epochSecret = _epochSecret(
        hasSecret: nativeHasEpochSecret.value,
        epoch: nativeEpochSecretEpoch.value,
        bytes: nativeEpochSecret,
      );
      final result = V3SckaReceiveCandidate(
        nextAuthenticatedState: state,
        stateRevision: expectedStateRevision + 1,
        receivingEpoch: _validatedCounter(
          nativeReceivingEpoch.value,
          'receivingEpoch',
        ),
        epochSecret: epochSecret,
      );
      epochSecret = null;
      return result;
    } finally {
      epochSecret?.wipe();
      if (state != null) _wipe(state);
      _wipe(payload);
      calloc.free(nativeSession);
      _wipeNative(nativePrior, authenticatedState.length);
      calloc.free(nativePrior);
      _wipeNative(nativeStateKey, stateSealKey.length);
      calloc.free(nativeStateKey);
      _wipeNative(nativeMessage, payload.length);
      calloc.free(nativeMessage);
      _wipeNative(nativeState, _maxStateBytes);
      calloc.free(nativeState);
      calloc.free(nativeStateLength);
      calloc.free(nativeReceivingEpoch);
      calloc.free(nativeHasEpochSecret);
      calloc.free(nativeEpochSecretEpoch);
      _wipeNative(nativeEpochSecret, _epochSecretBytes);
      calloc.free(nativeEpochSecret);
    }
  }
}

final class _V3SckaCandidateBindings {
  _V3SckaCandidateBindings(DynamicLibrary library) {
    abiVersion = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_abi_version',
    );
    protocolRevision = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_protocol_revision',
    );
    stateFormatVersion = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_state_format_version',
    );
    implementationIdPointer =
        library.lookupFunction<_StringNative, _StringDart>(
      'lg_scka_v1_implementation_id',
    );
    sessionIdBytes = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_session_id_bytes',
    );
    stateKeyBytes = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_state_key_bytes',
    );
    epochSecretBytes = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_epoch_secret_bytes',
    );
    stateHeaderBytes = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_state_header_bytes',
    );
    stateTagBytes = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_state_tag_bytes',
    );
    minStateBytes = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_min_state_bytes',
    );
    maxStateBytes = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_max_state_bytes',
    );
    maxMessageBytes = library.lookupFunction<_U32Native, _U32Dart>(
      'lg_scka_v1_max_message_bytes',
    );
    selfTest = library.lookupFunction<_I32Native, _I32Dart>(
      'lg_scka_v1_self_test',
    );
    validateState = library.lookupFunction<_ValidateNative, _ValidateDart>(
      'lg_scka_v1_state_validate',
    );
    initialize = library.lookupFunction<_InitializeNative, _InitializeDart>(
      'lg_scka_v1_initialize',
    );
    send = library.lookupFunction<_SendNative, _SendDart>('lg_scka_v1_send');
    receive = library
        .lookupFunction<_ReceiveNative, _ReceiveDart>('lg_scka_v1_receive');
  }

  late final _U32Dart abiVersion;
  late final _U32Dart protocolRevision;
  late final _U32Dart stateFormatVersion;
  late final _StringDart implementationIdPointer;
  late final _U32Dart sessionIdBytes;
  late final _U32Dart stateKeyBytes;
  late final _U32Dart epochSecretBytes;
  late final _U32Dart stateHeaderBytes;
  late final _U32Dart stateTagBytes;
  late final _U32Dart minStateBytes;
  late final _U32Dart maxStateBytes;
  late final _U32Dart maxMessageBytes;
  late final _I32Dart selfTest;
  late final _ValidateDart validateState;
  late final _InitializeDart initialize;
  late final _SendDart send;
  late final _ReceiveDart receive;

  String implementationId() => implementationIdPointer().toDartString();

  void validateAllowlist() {
    final actualImplementationId = implementationId();
    if (actualImplementationId !=
        V3SckaCandidateFfiBackend.approvedImplementationId) {
      throw StateError(
        'Unapproved Layergram SCKA implementation: $actualImplementationId',
      );
    }
    final values = <String, ({int actual, int expected})>{
      'abiVersion': (actual: abiVersion(), expected: _abiVersion),
      'protocolRevision': (
        actual: protocolRevision(),
        expected: V3SparsePqRatchet.requiredBackendProtocolRevision,
      ),
      'stateFormatVersion': (
        actual: stateFormatVersion(),
        expected: _stateFormatVersion,
      ),
      'sessionIdBytes': (actual: sessionIdBytes(), expected: _sessionIdBytes),
      'stateKeyBytes': (actual: stateKeyBytes(), expected: _stateKeyBytes),
      'epochSecretBytes': (
        actual: epochSecretBytes(),
        expected: _epochSecretBytes,
      ),
      'stateHeaderBytes': (
        actual: stateHeaderBytes(),
        expected: _stateHeaderBytes,
      ),
      'stateTagBytes': (actual: stateTagBytes(), expected: _stateTagBytes),
      'minStateBytes': (actual: minStateBytes(), expected: _minStateBytes),
      'maxStateBytes': (actual: maxStateBytes(), expected: _maxStateBytes),
      'maxMessageBytes': (
        actual: maxMessageBytes(),
        expected: _maxMessageBytes,
      ),
    };
    for (final MapEntry(key: name, value: pair) in values.entries) {
      if (pair.actual != pair.expected) {
        throw StateError(
          'Incompatible Layergram SCKA candidate ABI: $name is '
          '${pair.actual}, expected ${pair.expected}',
        );
      }
    }
  }
}

V3SckaEpochSecret? _epochSecret({
  required int hasSecret,
  required int epoch,
  required Pointer<Uint8> bytes,
}) {
  if (hasSecret == 0) {
    if (epoch != 0) {
      throw const V3SckaCandidateNativeException(
        operation: 'epochSecret.absentMetadata',
        status: _statusBackend,
      );
    }
    return null;
  }
  if (hasSecret != 1) {
    throw const V3SckaCandidateNativeException(
      operation: 'epochSecret.presence',
      status: _statusBackend,
    );
  }
  return V3SckaEpochSecret(
    epoch: _validatedCounter(epoch, 'epochSecretEpoch'),
    secret: _copyFromNative(bytes, _epochSecretBytes),
  );
}

int _validatedStateLength(int value) {
  if (value < _minStateBytes || value > _maxStateBytes) {
    throw const V3SckaCandidateNativeException(
      operation: 'stateLength',
      status: _statusBackend,
    );
  }
  return value;
}

int _validatedMessageLength(int value) {
  if (value != 24 && value != 58) {
    throw const V3SckaCandidateNativeException(
      operation: 'messageLength',
      status: _statusBackend,
    );
  }
  return value;
}

int _validatedCounter(int value, String name) {
  _requireCounter(value, name);
  return value;
}

void _requireTransitionCounter(int value) {
  _requireCounter(value, 'expectedStateRevision');
  if (value == _maxCounter) {
    throw StateError('Layergram v3 native SCKA revision is exhausted');
  }
}

void _requireCounter(int value, String name) {
  if (value < 0 || value > _maxCounter) {
    throw ArgumentError.value(value, name, 'must fit the signed-63 domain');
  }
}

void _requireLength(Uint8List value, int expected, String name) {
  if (value.length != expected) {
    throw ArgumentError.value(
      value.length,
      '$name.length',
      'must be exactly $expected bytes',
    );
  }
}

void _requireState(Uint8List value) {
  if (value.length < _minStateBytes || value.length > _maxStateBytes) {
    throw ArgumentError.value(
      value.length,
      'authenticatedState.length',
      'must be between $_minStateBytes and $_maxStateBytes bytes',
    );
  }
}

Pointer<Uint8> _copyToNative(Uint8List value) {
  final pointer = calloc<Uint8>(value.length);
  pointer.asTypedList(value.length).setAll(0, value);
  return pointer;
}

Uint8List _copyFromNative(Pointer<Uint8> pointer, int length) =>
    Uint8List.fromList(pointer.asTypedList(length));

void _wipeNative(Pointer<Uint8> pointer, int length) {
  pointer.asTypedList(length).fillRange(0, length, 0);
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);

void _throwOnNativeError(int status, String operation) {
  if (status != _statusOk) {
    throw V3SckaCandidateNativeException(
      operation: operation,
      status: status,
    );
  }
}

String _statusDescription(int status) => switch (status) {
      _statusOk => 'ok',
      -1 => 'invalid argument or canonical BM3 message',
      _statusNotReady => 'candidate feature is disabled',
      -3 => 'authentication failure',
      -4 => 'state format failure',
      -5 => 'state revision failure',
      _statusBackend => 'backend or primitive failure',
      -7 => 'operating-system entropy failure',
      -8 => 'self-test failure',
      -9 => 'allocation failure',
      _ => 'unknown native status',
    };

const int _abiVersion = 1;
const int _stateFormatVersion = 2;
const int _sessionIdBytes = 16;
const int _stateKeyBytes = 32;
const int _sharedSecretBytes = 32;
const int _epochSecretBytes = 32;
const int _stateHeaderBytes = 80;
const int _stateTagBytes = 16;
const int _minStateBytes = 97;
const int _maxStateBytes = 196608;
const int _maxMessageBytes = 512;
const int _maxCounter = 0x7fffffffffffffff;
const int _statusOk = 0;
const int _statusNotReady = -2;
const int _statusBackend = -6;

typedef _U32Native = Uint32 Function();
typedef _U32Dart = int Function();
typedef _I32Native = Int32 Function();
typedef _I32Dart = int Function();
typedef _StringNative = Pointer<Utf8> Function();
typedef _StringDart = Pointer<Utf8> Function();

typedef _ValidateNative = Int32 Function(
  Uint32,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Uint64,
  Pointer<Uint8>,
  Uint64,
);
typedef _ValidateDart = int Function(
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  int,
  Pointer<Uint8>,
  int,
);

typedef _InitializeNative = Int32 Function(
  Uint32,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint64>,
);
typedef _InitializeDart = int Function(
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint64>,
);

typedef _SendNative = Int32 Function(
  Uint32,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint64>,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint64>,
  Pointer<Uint64>,
  Pointer<Uint32>,
  Pointer<Uint64>,
  Pointer<Uint8>,
  Uint64,
);
typedef _SendDart = int Function(
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint64>,
  Pointer<Uint8>,
  int,
  Pointer<Uint64>,
  Pointer<Uint64>,
  Pointer<Uint32>,
  Pointer<Uint64>,
  Pointer<Uint8>,
  int,
);

typedef _ReceiveNative = Int32 Function(
  Uint32,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint64>,
  Pointer<Uint64>,
  Pointer<Uint32>,
  Pointer<Uint64>,
  Pointer<Uint8>,
  Uint64,
);
typedef _ReceiveDart = int Function(
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint64>,
  Pointer<Uint64>,
  Pointer<Uint32>,
  Pointer<Uint64>,
  Pointer<Uint8>,
  int,
);
