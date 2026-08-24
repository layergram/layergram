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

import 'ml_kem_768.dart';

/// Error returned by Layergram's narrow native ML-KEM ABI.
class MlKem768NativeException implements Exception {
  const MlKem768NativeException({
    required this.operation,
    required this.status,
  });

  final String operation;
  final int status;

  @override
  String toString() => 'MlKem768NativeException($operation, status: $status, '
      '${_statusDescription(status)})';
}

/// Protocol-v3 FFI backend for the Layergram-owned ML-KEM-768 ABI.
///
/// Constructing this object does not activate protocol v3. Packaged-library
/// loading is explicit and is not wired into the app runtime or protocol
/// selection. Encapsulation entropy never crosses Dart; the native wrapper
/// obtains it directly from the operating-system CSPRNG.
final class MlKem768FfiBackend implements MlKem768Backend {
  factory MlKem768FfiBackend.open({
    required String libraryPath,
  }) {
    return MlKem768FfiBackend.fromDynamicLibrary(
      DynamicLibrary.open(libraryPath),
    );
  }

  factory MlKem768FfiBackend.fromDynamicLibrary(DynamicLibrary library) {
    return MlKem768FfiBackend._(_MlKem768Bindings(library));
  }

  factory MlKem768FfiBackend._fromPackagedLibrary(DynamicLibrary library) {
    return MlKem768FfiBackend._(
      _MlKem768Bindings(library),
      requirePackagedAllowlist: true,
    );
  }

  /// Opens one explicitly located production package and applies the same
  /// fail-closed allowlist used by [openPackaged].
  ///
  /// Packaging verification tools use this factory before an artifact is
  /// installed into its final app-bundle location. Protocol runtime code uses
  /// [openPackaged] so the location itself is platform-owned as well.
  factory MlKem768FfiBackend.openPackagedLibrary({
    required String libraryPath,
  }) {
    return MlKem768FfiBackend._fromPackagedLibrary(
      DynamicLibrary.open(libraryPath),
    );
  }

  /// Opens the production library packaged for the current Flutter target.
  ///
  /// iOS links the ABI into the signed application process. Android and Windows
  /// package a shared library for the platform loader. macOS and Linux resolve
  /// the embedded library from an absolute app-bundle path. Calling this
  /// factory remains an explicit engineering action and does not select
  /// protocol v3.
  factory MlKem768FfiBackend.openPackaged() {
    if (Platform.isIOS) {
      return MlKem768FfiBackend._fromPackagedLibrary(
        DynamicLibrary.process(),
      );
    }
    if (Platform.isMacOS) {
      return MlKem768FfiBackend.openPackagedLibrary(
        libraryPath: packagedMacOSLibraryPath(),
      );
    }
    if (Platform.isAndroid) {
      return MlKem768FfiBackend._fromPackagedLibrary(
        DynamicLibrary.open('liblayergram_mlkem.so'),
      );
    }
    if (Platform.isWindows) {
      return MlKem768FfiBackend.openPackagedLibrary(
        libraryPath: packagedWindowsLibraryPath(),
      );
    }
    if (Platform.isLinux) {
      return MlKem768FfiBackend.openPackagedLibrary(
        libraryPath: packagedLinuxLibraryPath(),
      );
    }
    throw UnsupportedError(
      'Packaged ML-KEM-768 backend is not available on '
      '${Platform.operatingSystem}',
    );
  }

  /// Resolves the embedded macOS framework relative to the app executable.
  ///
  /// [executablePath] is exposed for deterministic packaging tests; production
  /// callers leave it unset.
  static String packagedMacOSLibraryPath({String? executablePath}) {
    final executable = File(executablePath ?? Platform.resolvedExecutable);
    final contentsDirectory = executable.parent.parent;
    return '${contentsDirectory.path}/Frameworks/LayergramMlKem.framework/'
        'Versions/A/LayergramMlKem';
  }

  /// Resolves the Linux shared library relative to the app executable.
  ///
  /// [executablePath] is exposed for deterministic packaging tests; production
  /// callers leave it unset.
  static String packagedLinuxLibraryPath({String? executablePath}) {
    final executable = File(executablePath ?? Platform.resolvedExecutable);
    return '${executable.parent.path}/lib/liblayergram_mlkem.so';
  }

  /// Resolves the Windows DLL from the executable-owned bundle directory.
  static String packagedWindowsLibraryPath({String? executablePath}) {
    final executable = File(executablePath ?? Platform.resolvedExecutable);
    return '${executable.parent.path}${Platform.pathSeparator}'
        'layergram_mlkem.dll';
  }

  MlKem768FfiBackend._(
    this._bindings, {
    bool requirePackagedAllowlist = false,
  }) {
    if (requirePackagedAllowlist) {
      _bindings.validatePackagedAllowlist();
    } else {
      _bindings.validateAbi();
    }
  }

  static const String approvedImplementationId =
      'mlkem-native-v2.0.0-d1b2fe782888bdb7+layergram-abi1';

  final _MlKem768Bindings _bindings;

  @override
  String get implementationId => _bindings.implementationId();

  @override
  Future<bool> selfTest() async => _bindings.selfTest() == _nativeOk;

  @override
  Future<MlKem768KeyPair> keyPairFromSeed(Uint8List seed) async {
    _requireLength(seed, MlKem768.keyGenerationSeedBytes, 'seed');
    final nativeSeed = _copyToNative(seed);
    final nativePublicKey = calloc<Uint8>(MlKem768.publicKeyBytes);
    final nativeHandle = calloc<Pointer<Void>>();
    try {
      final status = _bindings.keyPairFromSeed(
        nativeSeed,
        seed.length,
        nativePublicKey,
        MlKem768.publicKeyBytes,
        nativeHandle,
      );
      _throwOnNativeError(status, 'keyPairFromSeed');
      final handlePointer = nativeHandle.value;
      if (handlePointer == nullptr) {
        throw const MlKem768NativeException(
          operation: 'keyPairFromSeed.nullHandle',
          status: _nativeBackendError,
        );
      }

      late final _MlKem768FfiPrivateKeyHandle handle;
      try {
        handle = _MlKem768FfiPrivateKeyHandle(_bindings, handlePointer);
      } catch (_) {
        _bindings.privateKeyDestroy(handlePointer);
        rethrow;
      }
      return MlKem768KeyPair(
        publicKey: _copyFromNative(
          nativePublicKey,
          MlKem768.publicKeyBytes,
        ),
        privateKeyHandle: handle,
      );
    } finally {
      _wipeNative(nativeSeed, seed.length);
      calloc.free(nativeSeed);
      calloc.free(nativePublicKey);
      calloc.free(nativeHandle);
    }
  }

  @override
  Future<bool> validatePublicKey(Uint8List publicKey) async {
    _requireLength(publicKey, MlKem768.publicKeyBytes, 'publicKey');
    final nativePublicKey = _copyToNative(publicKey);
    try {
      final status = _bindings.validatePublicKey(
        nativePublicKey,
        publicKey.length,
      );
      if (status == _nativeOk) return true;
      if (status == _nativeInvalidPublicKey) return false;
      _throwOnNativeError(status, 'validatePublicKey');
      return false;
    } finally {
      calloc.free(nativePublicKey);
    }
  }

  @override
  Future<MlKem768Encapsulation> encapsulate(Uint8List publicKey) async {
    _requireLength(publicKey, MlKem768.publicKeyBytes, 'publicKey');
    final nativePublicKey = _copyToNative(publicKey);
    final nativeCiphertext = calloc<Uint8>(MlKem768.ciphertextBytes);
    final nativeSharedSecret = calloc<Uint8>(MlKem768.sharedSecretBytes);
    try {
      final status = _bindings.encapsulate(
        nativePublicKey,
        publicKey.length,
        nativeCiphertext,
        MlKem768.ciphertextBytes,
        nativeSharedSecret,
        MlKem768.sharedSecretBytes,
      );
      _throwOnNativeError(status, 'encapsulate');
      return MlKem768Encapsulation(
        ciphertext: _copyFromNative(
          nativeCiphertext,
          MlKem768.ciphertextBytes,
        ),
        sharedSecret: _copyFromNative(
          nativeSharedSecret,
          MlKem768.sharedSecretBytes,
        ),
      );
    } finally {
      calloc.free(nativePublicKey);
      calloc.free(nativeCiphertext);
      _wipeNative(nativeSharedSecret, MlKem768.sharedSecretBytes);
      calloc.free(nativeSharedSecret);
    }
  }

  /// Deterministic FIPS 203 `Encaps_Internal` boundary used by KATs.
  ///
  /// Normal protocol code calls [encapsulate], which obtains entropy inside
  /// native code. This hook is absent from production libraries and does not
  /// wipe [encapsSeed] because its test caller retains ownership.
  Future<MlKem768Encapsulation> encapsulateFromSeed(
    Uint8List publicKey,
    Uint8List encapsSeed,
  ) async {
    _requireLength(publicKey, MlKem768.publicKeyBytes, 'publicKey');
    _requireLength(
      encapsSeed,
      MlKem768.encapsulationSeedBytes,
      'encapsSeed',
    );
    final nativePublicKey = _copyToNative(publicKey);
    final nativeSeed = _copyToNative(encapsSeed);
    final nativeCiphertext = calloc<Uint8>(MlKem768.ciphertextBytes);
    final nativeSharedSecret = calloc<Uint8>(MlKem768.sharedSecretBytes);
    try {
      final status = _bindings.testEncapsulateFromSeed(
        nativePublicKey,
        publicKey.length,
        nativeSeed,
        encapsSeed.length,
        nativeCiphertext,
        MlKem768.ciphertextBytes,
        nativeSharedSecret,
        MlKem768.sharedSecretBytes,
      );
      _throwOnNativeError(status, 'encapsulateFromSeed');
      return MlKem768Encapsulation(
        ciphertext: _copyFromNative(
          nativeCiphertext,
          MlKem768.ciphertextBytes,
        ),
        sharedSecret: _copyFromNative(
          nativeSharedSecret,
          MlKem768.sharedSecretBytes,
        ),
      );
    } finally {
      calloc.free(nativePublicKey);
      _wipeNative(nativeSeed, encapsSeed.length);
      calloc.free(nativeSeed);
      calloc.free(nativeCiphertext);
      _wipeNative(nativeSharedSecret, MlKem768.sharedSecretBytes);
      calloc.free(nativeSharedSecret);
    }
  }

  @override
  Future<Uint8List> decapsulate(
    MlKem768PrivateKeyHandle privateKeyHandle,
    Uint8List ciphertext,
  ) async {
    if (privateKeyHandle is! _MlKem768FfiPrivateKeyHandle ||
        !identical(privateKeyHandle._bindings, _bindings)) {
      throw ArgumentError.value(
        privateKeyHandle,
        'privateKeyHandle',
        'must belong to this ML-KEM backend',
      );
    }
    _requireLength(ciphertext, MlKem768.ciphertextBytes, 'ciphertext');
    final handlePointer = privateKeyHandle._openPointer;
    final nativeCiphertext = _copyToNative(ciphertext);
    final nativeSharedSecret = calloc<Uint8>(MlKem768.sharedSecretBytes);
    try {
      final status = _bindings.decapsulate(
        handlePointer,
        nativeCiphertext,
        ciphertext.length,
        nativeSharedSecret,
        MlKem768.sharedSecretBytes,
      );
      _throwOnNativeError(status, 'decapsulate');
      return _copyFromNative(
        nativeSharedSecret,
        MlKem768.sharedSecretBytes,
      );
    } finally {
      calloc.free(nativeCiphertext);
      _wipeNative(nativeSharedSecret, MlKem768.sharedSecretBytes);
      calloc.free(nativeSharedSecret);
    }
  }

  /// Whether this dynamic library was compiled with non-production test hooks.
  bool get hasTestHooks => _bindings.hasTestHooks;

  int get testDestroyedHandleCount => _bindings.testDestroyedHandleCount();

  bool get testLastDestroyedHandleWasZero =>
      _bindings.testLastDestroyedHandleWasZero();
}

final class _MlKem768FfiPrivateKeyHandle
    implements MlKem768PrivateKeyHandle, Finalizable {
  _MlKem768FfiPrivateKeyHandle(this._bindings, this._pointer) {
    _bindings.privateKeyFinalizer.attach(
      this,
      _pointer,
      detach: _detachToken,
    );
  }

  final _MlKem768Bindings _bindings;
  final Object _detachToken = Object();
  Pointer<Void> _pointer;

  @override
  bool get isClosed => _pointer == nullptr;

  Pointer<Void> get _openPointer {
    if (isClosed) {
      throw StateError('ML-KEM-768 private-key handle is closed');
    }
    return _pointer;
  }

  @override
  Future<void> close() async {
    if (isClosed) return;
    _bindings.privateKeyFinalizer.detach(_detachToken);
    final pointer = _pointer;
    _pointer = nullptr;
    _bindings.privateKeyDestroy(pointer);
  }
}

final class _MlKem768Bindings {
  _MlKem768Bindings(DynamicLibrary library) {
    abiVersion = library.lookupFunction<_Uint32Native, _Uint32Dart>(
      'lg_mlkem768_abi_version',
    );
    implementationIdPointer =
        library.lookupFunction<_StringNative, _StringDart>(
      'lg_mlkem768_implementation_id',
    );
    publicKeyBytes = library.lookupFunction<_Uint32Native, _Uint32Dart>(
      'lg_mlkem768_public_key_bytes',
    );
    privateKeyBytes = library.lookupFunction<_Uint32Native, _Uint32Dart>(
      'lg_mlkem768_private_key_bytes',
    );
    ciphertextBytes = library.lookupFunction<_Uint32Native, _Uint32Dart>(
      'lg_mlkem768_ciphertext_bytes',
    );
    sharedSecretBytes = library.lookupFunction<_Uint32Native, _Uint32Dart>(
      'lg_mlkem768_shared_secret_bytes',
    );
    keygenSeedBytes = library.lookupFunction<_Uint32Native, _Uint32Dart>(
      'lg_mlkem768_keygen_seed_bytes',
    );
    encapsSeedBytes = library.lookupFunction<_Uint32Native, _Uint32Dart>(
      'lg_mlkem768_encaps_seed_bytes',
    );
    keyPairFromSeed = library.lookupFunction<_KeyPairNative, _KeyPairDart>(
      'lg_mlkem768_keypair_from_seed',
    );
    validatePublicKey = library
        .lookupFunction<_ValidatePublicKeyNative, _ValidatePublicKeyDart>(
      'lg_mlkem768_validate_public_key',
    );
    encapsulate = library.lookupFunction<_EncapsulateNative, _EncapsulateDart>(
      'lg_mlkem768_encapsulate',
    );
    decapsulate = library.lookupFunction<_DecapsulateNative, _DecapsulateDart>(
      'lg_mlkem768_decapsulate',
    );
    privateKeyDestroyPointer = library.lookup<NativeFunction<_DestroyNative>>(
      'lg_mlkem768_private_key_destroy',
    );
    privateKeyDestroy = privateKeyDestroyPointer.asFunction<_DestroyDart>();
    privateKeyFinalizer = NativeFinalizer(privateKeyDestroyPointer.cast());
    selfTest = library.lookupFunction<_Int32Native, _Int32Dart>(
      'lg_mlkem768_self_test',
    );

    _testEncapsulateFromSeed = _lookupOptionalTestEncapsulate(
      library,
      'lg_mlkem768_test_encapsulate_from_seed',
    );
    _testDestroyedHandleCount = _lookupOptionalUint64(
      library,
      'lg_mlkem768_test_destroyed_handle_count',
    );
    _testLastDestroyWasZero = _lookupOptionalInt32(
      library,
      'lg_mlkem768_test_last_destroy_was_zero',
    );
  }

  late final _Uint32Dart abiVersion;
  late final _StringDart implementationIdPointer;
  late final _Uint32Dart publicKeyBytes;
  late final _Uint32Dart privateKeyBytes;
  late final _Uint32Dart ciphertextBytes;
  late final _Uint32Dart sharedSecretBytes;
  late final _Uint32Dart keygenSeedBytes;
  late final _Uint32Dart encapsSeedBytes;
  late final _KeyPairDart keyPairFromSeed;
  late final _ValidatePublicKeyDart validatePublicKey;
  late final _EncapsulateDart encapsulate;
  late final _DecapsulateDart decapsulate;
  late final Pointer<NativeFunction<_DestroyNative>> privateKeyDestroyPointer;
  late final _DestroyDart privateKeyDestroy;
  late final NativeFinalizer privateKeyFinalizer;
  late final _Int32Dart selfTest;
  _TestEncapsulateDart? _testEncapsulateFromSeed;
  _Uint64Dart? _testDestroyedHandleCount;
  _Int32Dart? _testLastDestroyWasZero;

  String implementationId() => implementationIdPointer().toDartString();

  bool get hasTestHooks =>
      _testEncapsulateFromSeed != null &&
      _testDestroyedHandleCount != null &&
      _testLastDestroyWasZero != null;

  bool get hasAnyTestHooks =>
      _testEncapsulateFromSeed != null ||
      _testDestroyedHandleCount != null ||
      _testLastDestroyWasZero != null;

  int testEncapsulateFromSeed(
    Pointer<Uint8> publicKey,
    int publicKeyLength,
    Pointer<Uint8> seed,
    int seedLength,
    Pointer<Uint8> ciphertext,
    int ciphertextLength,
    Pointer<Uint8> sharedSecret,
    int sharedSecretLength,
  ) {
    final function = _testEncapsulateFromSeed;
    if (function == null) {
      throw StateError(
        'Deterministic ML-KEM encapsulation is unavailable in production',
      );
    }
    return function(
      publicKey,
      publicKeyLength,
      seed,
      seedLength,
      ciphertext,
      ciphertextLength,
      sharedSecret,
      sharedSecretLength,
    );
  }

  int testDestroyedHandleCount() {
    final function = _testDestroyedHandleCount;
    if (function == null) {
      throw StateError('ML-KEM test hooks are not available');
    }
    return function();
  }

  bool testLastDestroyedHandleWasZero() {
    final function = _testLastDestroyWasZero;
    if (function == null) {
      throw StateError('ML-KEM test hooks are not available');
    }
    return function() == 1;
  }

  void validateAbi() {
    final values = <String, ({int actual, int expected})>{
      'abiVersion': (actual: abiVersion(), expected: 1),
      'publicKeyBytes': (
        actual: publicKeyBytes(),
        expected: MlKem768.publicKeyBytes,
      ),
      'privateKeyBytes': (
        actual: privateKeyBytes(),
        expected: MlKem768.privateKeyBytes,
      ),
      'ciphertextBytes': (
        actual: ciphertextBytes(),
        expected: MlKem768.ciphertextBytes,
      ),
      'sharedSecretBytes': (
        actual: sharedSecretBytes(),
        expected: MlKem768.sharedSecretBytes,
      ),
      'keygenSeedBytes': (
        actual: keygenSeedBytes(),
        expected: MlKem768.keyGenerationSeedBytes,
      ),
      'encapsSeedBytes': (
        actual: encapsSeedBytes(),
        expected: MlKem768.encapsulationSeedBytes,
      ),
    };
    for (final MapEntry(key: name, value: pair) in values.entries) {
      if (pair.actual != pair.expected) {
        throw StateError(
          'Incompatible Layergram ML-KEM ABI: $name is ${pair.actual}, '
          'expected ${pair.expected}',
        );
      }
    }
  }

  void validatePackagedAllowlist() {
    validateAbi();
    final actualImplementationId = implementationId();
    if (actualImplementationId != MlKem768FfiBackend.approvedImplementationId) {
      throw StateError(
        'Unapproved Layergram ML-KEM implementation: '
        '$actualImplementationId',
      );
    }
    if (hasAnyTestHooks) {
      throw StateError(
        'Packaged Layergram ML-KEM exposes non-production test hooks',
      );
    }
  }
}

_TestEncapsulateDart? _lookupOptionalTestEncapsulate(
  DynamicLibrary library,
  String symbol,
) {
  try {
    return library
        .lookupFunction<_TestEncapsulateNative, _TestEncapsulateDart>(symbol);
  } on ArgumentError {
    return null;
  }
}

_Uint64Dart? _lookupOptionalUint64(
  DynamicLibrary library,
  String symbol,
) {
  try {
    return library.lookupFunction<_Uint64Native, _Uint64Dart>(symbol);
  } on ArgumentError {
    return null;
  }
}

_Int32Dart? _lookupOptionalInt32(
  DynamicLibrary library,
  String symbol,
) {
  try {
    return library.lookupFunction<_Int32Native, _Int32Dart>(symbol);
  } on ArgumentError {
    return null;
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

void _requireLength(Uint8List value, int expected, String name) {
  if (value.length != expected) {
    throw ArgumentError.value(
      value.length,
      '$name.length',
      'must be exactly $expected bytes',
    );
  }
}

void _throwOnNativeError(int status, String operation) {
  if (status != _nativeOk) {
    throw MlKem768NativeException(operation: operation, status: status);
  }
}

String _statusDescription(int status) => switch (status) {
      _nativeOk => 'ok',
      -1 => 'invalid argument',
      -2 => 'allocation failure',
      _nativeInvalidPublicKey => 'invalid public key',
      -4 => 'invalid private key',
      _nativeBackendError => 'backend failure',
      -6 => 'invalid private-key handle',
      -7 => 'self-test failure',
      -8 => 'operating-system entropy failure',
      _ => 'unknown native status',
    };

const int _nativeOk = 0;
const int _nativeInvalidPublicKey = -3;
const int _nativeBackendError = -5;

typedef _Uint32Native = Uint32 Function();
typedef _Uint32Dart = int Function();
typedef _Uint64Native = Uint64 Function();
typedef _Uint64Dart = int Function();
typedef _Int32Native = Int32 Function();
typedef _Int32Dart = int Function();
typedef _StringNative = Pointer<Utf8> Function();
typedef _StringDart = Pointer<Utf8> Function();
typedef _KeyPairNative = Int32 Function(
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Pointer<Void>>,
);
typedef _KeyPairDart = int Function(
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Void>>,
);
typedef _ValidatePublicKeyNative = Int32 Function(
  Pointer<Uint8>,
  Uint64,
);
typedef _ValidatePublicKeyDart = int Function(Pointer<Uint8>, int);
typedef _EncapsulateNative = Int32 Function(
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
);
typedef _EncapsulateDart = int Function(
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
);
typedef _TestEncapsulateNative = Int32 Function(
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
);
typedef _TestEncapsulateDart = int Function(
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
);
typedef _DecapsulateNative = Int32 Function(
  Pointer<Void>,
  Pointer<Uint8>,
  Uint64,
  Pointer<Uint8>,
  Uint64,
);
typedef _DecapsulateDart = int Function(
  Pointer<Void>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
);
typedef _DestroyNative = Void Function(Pointer<Void>);
typedef _DestroyDart = void Function(Pointer<Void>);
