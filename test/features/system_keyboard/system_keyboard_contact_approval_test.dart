// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_security_mode.dart';
import 'package:layergram/core/crypto/v3/identity_v3_adapter.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_contact_approval.dart';

V3PublicIdentity _identity(String name, int offset) => V3PublicIdentity(
      x25519PublicKey: Uint8List.fromList(List<int>.generate(
        V3PublicIdentityCodec.x25519PublicKeyBytes,
        (index) => ((index + offset) % 255) + 1,
      )),
      mlKem768PublicKey: Uint8List.fromList(List<int>.generate(
        MlKem768.publicKeyBytes,
        (index) => ((index + offset) % 255) + 1,
      )),
      displayName: name,
    );

V3SessionEligibilityPolicy _policy({String? maximumDevice}) =>
    V3SessionEligibilityPolicy(
      isValid: true,
      revision: 1,
      excludedHandshakeIds: const [],
      maximumRemoteDeviceId: maximumDevice,
    );

void main() {
  test('fresh unverified V3 contact enters autonomous Normal keyboard',
      () async {
    final alice = _identity('Mac', 1);
    V3SessionEligibilityPolicy? savedPolicy;
    var initializations = 0;
    final rows = await prepareKeyboardCustodyContacts(
      contacts: [V3IdentityAdapter.toRemoteIdentity(alice)],
      modeFor: (_) => FsSecurityMode.advanced,
      policyFor: (_) => savedPolicy,
      initializeNormalPolicy: (_) async {
        initializations++;
        return savedPolicy = _policy();
      },
      admitted: () => true,
    );
    expect(initializations, 1);
    expect(rows, hasLength(1));
    expect(rows.single['displayName'], 'Mac');
    expect(rows.single['mode'], 'normal');
    expect(rows.single['revision'], 1);
    expect(rows.single['identity'], isA<String>());
  });

  test('existing Maximum and recovery state cannot become fresh Normal',
      () async {
    final maximum = _identity('Maximum', 2);
    final recovery = _identity('Recovery', 3);
    var initializations = 0;
    final rows = await prepareKeyboardCustodyContacts(
      contacts: [
        V3IdentityAdapter.toRemoteIdentity(maximum),
        V3IdentityAdapter.toRemoteIdentity(recovery),
      ],
      modeFor: (identity) => identity.identityId == maximum.identityId
          ? FsSecurityMode.strict
          : FsSecurityMode.advanced,
      policyFor: (identity) => identity.identityId == maximum.identityId
          ? _policy(maximumDevice: 'pinned-device')
          : null,
      initializeNormalPolicy: (_) async {
        initializations++;
        throw StateError('durable handshake requires recovery');
      },
      admitted: () => true,
    );
    expect(initializations, 1);
    expect(rows, hasLength(1));
    expect(rows.single['displayName'], 'Maximum');
    expect(rows.single['mode'], 'maximum');
    expect(rows.single['maximumRemoteDeviceId'], 'pinned-device');
  });

  test('unbound Maximum stays visible while explicit Base stays out', () async {
    final maximum = _identity('Maximum', 4);
    final base = _identity('Base', 5);
    var initializations = 0;
    final rows = await prepareKeyboardCustodyContacts(
      contacts: [
        V3IdentityAdapter.toRemoteIdentity(maximum),
        V3IdentityAdapter.toRemoteIdentity(base),
      ],
      modeFor: (identity) => identity.identityId == maximum.identityId
          ? FsSecurityMode.strict
          : FsSecurityMode.base,
      policyFor: (_) => _policy(),
      initializeNormalPolicy: (_) async {
        initializations++;
        return _policy();
      },
      admitted: () => true,
    );
    expect(rows, hasLength(1));
    expect(rows.single['displayName'], 'Maximum');
    expect(rows.single['mode'], 'maximum');
    expect(rows.single['maximumRemoteDeviceId'], isNull);
    expect(initializations, 0);
  });
}
