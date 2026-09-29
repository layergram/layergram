// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import 'dart:typed_data';

import '../../core/crypto/fs_security_mode.dart';
import '../../core/crypto/models.dart';
import '../../core/crypto/v3/application_session_runtime_v3.dart';
import '../../core/crypto/v3/identity_v3_adapter.dart';
import '../../core/crypto/v3/local_identity_v3.dart';
import '../../core/crypto/v3/public_identity_v3.dart';

/// Public metadata from one freshly authenticated native grant. This is never
/// read from preferences or disk and carries no identity, device or archive key.
final class SystemKeyboardRuntimeConfig {
  SystemKeyboardRuntimeConfig._({
    required this.publicIdentity,
    required this.identityKeyMaterial,
    required this.scopeToken,
    required this.localDeviceId,
    required this.epoch,
    required this.editorNonce,
    required this.idleMillis,
    required this.scramble,
    required this.saveHistory,
    required this.contacts,
    required this.policies,
  });

  final V3PublicIdentity publicIdentity;

  /// Volatile one-grant identity material. The runtime consumes and wipes it.
  final Uint8List identityKeyMaterial;
  final String scopeToken;
  final Uint8List localDeviceId;
  final Uint8List epoch;
  final String editorNonce;
  final int idleMillis;
  final bool scramble;
  final bool saveHistory;
  final List<RemoteIdentity> contacts;
  final Map<String, V3EstablishedSessionPolicy> policies;

  factory SystemKeyboardRuntimeConfig.parse(Object? raw) {
    if (raw is! Map ||
        (raw.length != 10 && raw.length != 11) ||
        (raw.length == 11 && !raw.containsKey('saveHistory')) ||
        raw['v'] != 2 ||
        raw['publicIdentity'] is! Uint8List ||
        raw['identityKeyMaterial'] is! Uint8List ||
        raw['scopeToken'] is! String ||
        raw['localDeviceId'] is! Uint8List ||
        raw['epoch'] is! Uint8List ||
        raw['editorNonce'] is! String ||
        raw['idleMillis'] is! int ||
        raw['scramble'] is! bool ||
        raw['contacts'] is! List ||
        (raw.containsKey('saveHistory') && raw['saveHistory'] is! bool)) {
      throw const FormatException('Invalid keyboard runtime configuration');
    }
    final identity =
        V3PublicIdentityCodec.decodeBinary(raw['publicIdentity'] as Uint8List);
    // Platform-channel typed data may be backed by an immutable view. The
    // keyboard owns and wipes this copy after the one-shot grant is consumed.
    final keyMaterial =
        Uint8List.fromList(raw['identityKeyMaterial'] as Uint8List);
    final scopeToken = raw['scopeToken'] as String;
    final device = Uint8List.fromList(raw['localDeviceId'] as Uint8List);
    final epoch = Uint8List.fromList(raw['epoch'] as Uint8List);
    final nonce = raw['editorNonce'] as String;
    final idle = raw['idleMillis'] as int;
    final rows = raw['contacts'] as List;
    if (!RegExp(r'^[A-Za-z0-9_-]{16}$').hasMatch(scopeToken) ||
        keyMaterial.length != V3LocalIdentityFactory.keyboardKeyMaterialBytes ||
        keyMaterial[0] != V3LocalIdentityFactory.keyboardKeyMaterialVersion ||
        device.length != 16 ||
        !device.any((b) => b != 0) ||
        epoch.length != 16 ||
        !epoch.any((b) => b != 0) ||
        nonce.isEmpty ||
        nonce.length > 128 ||
        idle < 1 ||
        idle > 300000 ||
        rows.isEmpty ||
        rows.length > 64) {
      throw const FormatException('Invalid keyboard runtime bounds');
    }
    final contacts = <RemoteIdentity>[];
    final policies = <String, V3EstablishedSessionPolicy>{};
    for (final row in rows) {
      if (row is! Map ||
          row.length != 6 ||
          row['identity'] is! Uint8List ||
          row['displayName'] is! String ||
          row['mode'] is! String ||
          row['revision'] is! int ||
          row['excludedHandshakeIds'] is! List ||
          (row['maximumRemoteDeviceId'] != null &&
              row['maximumRemoteDeviceId'] is! String)) {
        throw const FormatException('Invalid keyboard contact configuration');
      }
      final contact =
          V3PublicIdentityCodec.decodeBinary(row['identity'] as Uint8List);
      final name = row['displayName'] as String;
      final excluded = row['excludedHandshakeIds'] as List;
      final revision = row['revision'] as int;
      if (name.isEmpty ||
          name.length > 128 ||
          policies.containsKey(contact.identityId) ||
          contact.identityId == identity.identityId ||
          excluded.length > 4096 ||
          excluded.any((id) => id is! String) ||
          revision < 0 ||
          revision > 9007199254740991) {
        throw const FormatException('Invalid keyboard contact bounds');
      }
      final mode = switch (row['mode']) {
        'normal' => FsSecurityMode.advanced,
        'maximum' => FsSecurityMode.strict,
        _ => throw const FormatException('Invalid keyboard contact mode'),
      };
      final policy = V3EstablishedSessionPolicy(
          mode: mode,
          revision: revision,
          excludedHandshakeIds: excluded.cast<String>(),
          maximumRemoteDeviceId: row['maximumRemoteDeviceId'] as String?);
      contacts.add(V3IdentityAdapter.toRemoteIdentity(contact)
          .copyWith(displayName: name));
      policies[contact.identityId] = policy;
    }
    return SystemKeyboardRuntimeConfig._(
        publicIdentity: identity,
        identityKeyMaterial: keyMaterial,
        scopeToken: scopeToken,
        localDeviceId: device,
        epoch: epoch,
        editorNonce: nonce,
        idleMillis: idle,
        scramble: raw['scramble'] as bool,
        saveHistory: raw['saveHistory'] as bool? ?? true,
        contacts: List.unmodifiable(contacts),
        policies: Map.unmodifiable(policies));
  }
}
