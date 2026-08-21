import 'dart:convert';

import '../../core/crypto/models.dart';
import '../../core/storage/secure_storage.dart';

final class IdentityMigrationNoticeTarget {
  const IdentityMigrationNoticeTarget({
    required this.identityId,
    required this.protocolVersion,
    this.persistAcknowledgement = true,
  });

  factory IdentityMigrationNoticeTarget.fromLocalIdentity(
    LocalIdentity identity,
  ) =>
      IdentityMigrationNoticeTarget(
        identityId: identity.identityId,
        protocolVersion: identity.protocolVersion,
      );

  final String identityId;
  final int protocolVersion;
  final bool persistAcknowledgement;
}

class IdentityMigrationNoticeService {
  IdentityMigrationNoticeService(
    SecureStorageService storage, {
    bool Function()? isFeatureEnabled,
  })  : _storage = storage,
        _isFeatureEnabled = isFeatureEnabled ?? (() => false);

  static const String _acknowledgedIdentityKey =
      'protocol_v3_migration_notice_identity_v1';

  final SecureStorageService _storage;
  final bool Function() _isFeatureEnabled;
  IdentityMigrationNoticeTarget? _lastTarget;
  final Set<String> _sessionAcknowledged = <String>{};

  // Compatibility entry point used by the migration controller. The stored
  // value is the local identity ID, so restoring a different 24-word identity
  // cannot inherit another identity's acknowledgement.
  Future<bool> isAcknowledged() async =>
      (await _acknowledgedIdentityIds()).isNotEmpty;

  Future<void> markAcknowledged() async {
    final target = _lastTarget;
    if (target == null) return;
    await markAcknowledgedForTarget(target);
  }

  Future<void> markAcknowledgedForIdentity(LocalIdentity identity) async {
    await markAcknowledgedForTarget(
      IdentityMigrationNoticeTarget.fromLocalIdentity(identity),
    );
  }

  Future<void> markAcknowledgedForTarget(
    IdentityMigrationNoticeTarget target,
  ) async {
    _lastTarget = target;
    if (!target.persistAcknowledgement) {
      _sessionAcknowledged.add(target.identityId);
      return;
    }
    final acknowledged = await _acknowledgedIdentityIds()
      ..add(target.identityId);
    await _writeAcknowledgedIdentityIds(acknowledged);
  }

  Future<void> remindLater() async {
    final target = _lastTarget;
    if (target == null) return;
    _sessionAcknowledged.remove(target.identityId);
    if (!target.persistAcknowledgement) return;
    final acknowledged = await _acknowledgedIdentityIds()
      ..remove(target.identityId);
    await _writeAcknowledgedIdentityIds(acknowledged);
  }

  Future<void> synchronizeIdentityState(LocalIdentity? identity) async {
    _lastTarget = identity == null
        ? null
        : IdentityMigrationNoticeTarget.fromLocalIdentity(identity);
  }

  Future<bool> shouldShowForIdentity(LocalIdentity? identity) async {
    return shouldShowForTarget(
      identity == null
          ? null
          : IdentityMigrationNoticeTarget.fromLocalIdentity(identity),
    );
  }

  Future<bool> shouldShowForTarget(
    IdentityMigrationNoticeTarget? target,
  ) async {
    if (!_isFeatureEnabled() || target == null) return false;
    _lastTarget = target;
    final acknowledged = _sessionAcknowledged.contains(target.identityId) ||
        (target.persistAcknowledgement &&
            (await _acknowledgedIdentityIds()).contains(target.identityId));
    return target.protocolVersion < 3 && !acknowledged;
  }

  bool shouldShowLegacyIdentityNotice(
    LocalIdentity? identity,
    bool acknowledged, {
    required bool featureEnabled,
  }) {
    return featureEnabled &&
        identity != null &&
        identity.protocolVersion < 3 &&
        !acknowledged;
  }

  Future<Set<String>> _acknowledgedIdentityIds() async {
    final encoded = await _storage.read(_acknowledgedIdentityKey);
    if (encoded == null || encoded.isEmpty) return <String>{};
    try {
      final decoded = jsonDecode(encoded);
      if (decoded is List && decoded.every((value) => value is String)) {
        return decoded
            .cast<String>()
            .where((value) => value.isNotEmpty)
            .toSet();
      }
    } on FormatException {
      // Version 1 stored one plain identity ID; migrate it on the next write.
    }
    return <String>{encoded};
  }

  Future<void> _writeAcknowledgedIdentityIds(Set<String> values) async {
    if (values.isEmpty) {
      await _storage.delete(_acknowledgedIdentityKey);
      return;
    }
    final sorted = values.toList(growable: false)..sort();
    await _storage.write(_acknowledgedIdentityKey, jsonEncode(sorted));
  }
}
