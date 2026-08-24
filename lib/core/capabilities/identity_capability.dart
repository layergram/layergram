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

import '../domain/identity_id.dart';

/// Profile information for a local identity.
///
/// Contains the essential identifying information for a user's local identity
/// including display name, fingerprint, and public key data.
class IdentityProfile {
  /// Creates an [IdentityProfile] instance.
  ///
  /// [identityId] - Unique identifier for the identity
  /// [displayName] - Human-readable display name
  /// [fingerprint] - Optional cryptographic fingerprint
  /// [publicKeyBase64] - Optional base64-encoded public key
  const IdentityProfile({
    required this.identityId,
    required this.displayName,
    this.fingerprint,
    this.publicKeyBase64,
    this.protocolVersion,
    this.publicIdentityBase64,
  });

  /// Unique identifier for this identity.
  final IdentityId identityId;

  /// Human-readable display name for the identity.
  final String displayName;

  /// Cryptographic fingerprint of the identity.
  final String? fingerprint;

  /// Base64-encoded public key for cryptographic operations.
  final String? publicKeyBase64;

  /// Wire protocol version for [publicIdentityBase64], when available.
  ///
  /// Nullable and additive so existing optional capability implementations
  /// remain source compatible while the public protocol evolves.
  final int? protocolVersion;

  /// Complete versioned public-identity bundle.
  ///
  /// For protocol v3 this contains every public component required by the
  /// hybrid suite. It never contains a mnemonic, private key, or passphrase.
  final String? publicIdentityBase64;
}

/// Multi-identity management capability interface.
///
/// This capability provides functionality for managing multiple user identities,
/// including creation, deletion, and switching between active identities.
/// In the open-source build, this is implemented by [NoIdentityCapability]
/// which provides no-op implementations.
///
/// Premium implementations should provide:
/// - Identity creation and import/export
/// - Secure storage of multiple identities
/// - Active identity switching
/// - Identity profile management
abstract class IdentityCapability {
  /// Whether the multi-identity feature set is available.
  ///
  /// Returns `true` for premium builds with multi-identity support,
  /// `false` for the open-source build.
  bool get isAvailable;

  /// Stream of all local identities available on the device.
  ///
  /// Returns a stream that emits the current list of local identities
  /// whenever the list changes. In OSS, this returns an empty stream.
  Stream<List<IdentityProfile>> watchLocalIdentities();

  /// Stream of the currently active identity ID.
  ///
  /// Returns a stream that emits the current active identity ID
  /// whenever it changes. In OSS, this returns a stream that always emits `null`.
  Stream<IdentityId?> watchActiveIdentityId();

  /// Sets the active identity to the specified ID.
  ///
  /// [identityId] - The identity ID to set as active
  Future<void> setActiveIdentityId(IdentityId identityId);
}

/// No-op implementation of [IdentityCapability] for the open-source build.
///
/// This class provides stub implementations that return default values
/// and perform no-ops for all multi-identity operations.
/// It's used in the open-source build where multi-identity functionality
/// is not available.
///
/// All methods return appropriate default values:
/// - [isAvailable] always returns `false`
/// - [watchLocalIdentities] returns an empty stream
/// - [watchActiveIdentityId] returns a stream that always emits `null`
/// - [setActiveIdentityId] is a no-op
class NoIdentityCapability implements IdentityCapability {
  /// Creates a [NoIdentityCapability] instance.
  const NoIdentityCapability();

  @override
  bool get isAvailable => false;

  @override
  Stream<List<IdentityProfile>> watchLocalIdentities() =>
      Stream.value(const <IdentityProfile>[]);

  @override
  Stream<IdentityId?> watchActiveIdentityId() => Stream.value(null);

  @override
  Future<void> setActiveIdentityId(IdentityId identityId) async {}
}
