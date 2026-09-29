// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import 'dart:convert';

import '../../core/crypto/fs_security_mode.dart';
import '../../core/crypto/models.dart';
import '../../core/crypto/v3/identity_v3_adapter.dart';
import '../../core/crypto/v3/public_identity_v3.dart';

/// Builds the bounded contact snapshot handed to an autonomous iOS keyboard.
///
/// A freshly imported V3 contact has no local FS policy yet. Initializing the
/// default Normal policy here lets the keyboard send its first readable message
/// without requiring an earlier send from the app. The runtime's initializer
/// refuses to create a policy beside existing handshake state, so a recovery
/// case never silently becomes a fresh Normal setup.
Future<List<Map<String, Object?>>> prepareKeyboardCustodyContacts({
  required Iterable<RemoteIdentity> contacts,
  required FsSecurityMode Function(V3PublicIdentity) modeFor,
  required V3SessionEligibilityPolicy? Function(V3PublicIdentity) policyFor,
  required Future<V3SessionEligibilityPolicy> Function(V3PublicIdentity)
      initializeNormalPolicy,
  required bool Function() admitted,
}) async {
  final rows = <Map<String, Object?>>[];
  for (final contact in contacts) {
    if (!admitted()) return const [];
    if (contact.protocolVersion != V3PublicIdentityCodec.protocolVersion) {
      continue;
    }
    final V3PublicIdentity identity;
    FsSecurityMode mode;
    V3SessionEligibilityPolicy? policy;
    try {
      identity = V3IdentityAdapter.fromRemoteIdentity(contact);
      mode = modeFor(identity);
      policy = policyFor(identity);
      if (policy == null && mode != FsSecurityMode.strict) {
        policy = await initializeNormalPolicy(identity);
        mode = modeFor(identity);
      }
    } catch (_) {
      // Malformed or recovery-required contacts are never delegated.
      continue;
    }
    if (!admitted()) return const [];
    if (policy?.isValid != true || mode == FsSecurityMode.base) {
      continue;
    }
    rows.add({
      'identity': base64Encode(V3PublicIdentityCodec.encodeBinary(identity)),
      'displayName': contact.displayName,
      'mode': mode == FsSecurityMode.strict ? 'maximum' : 'normal',
      'revision': policy!.revision,
      'excludedHandshakeIds': policy.excludedHandshakeIds.toList(),
      'maximumRemoteDeviceId': policy.maximumRemoteDeviceId,
    });
    if (rows.length > 64) return const [];
  }
  return rows;
}
