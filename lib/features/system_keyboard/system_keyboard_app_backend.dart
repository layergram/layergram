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

/// Real app-owner backend for the experimental SYSTEM keyboard bridge.
///
/// Everything sensitive happens here, inside the already running Layergram
/// application: saved V3 contacts, the existing V3 application session runtime,
/// the repository context lease and the durable outbound/projection history.
/// The pure [SystemKeyboardController] never sees a key, the database or the
/// wire format.
///
/// Fail-closed rules implemented here:
/// * Every call captures the app-owner generation plus the ordinary identity id
///   and re-checks the *full* integration admission (feature, consent, native
///   configuration, lock readiness/unlock/request, passphrase, ordinary keyTag
///   and the absolute monotonic background deadline) before every provider
///   access and after every `await`. A lock, timeout, identity, passphrase,
///   opt-in or context change therefore kills an in-flight operation instead of
///   letting it complete against a stale owner.
/// * Only V3 contacts (`protocolVersion == 3` with a public identity token) are
///   surfaced, using their saved display name and fingerprint. The recipient is
///   never inferred from the host application.
/// * `prepare` creates the app-owned default Normal policy only for a fresh,
///   saved and fingerprint-matched contact. An active session can send an
///   application message; a fresh Normal setup can send an authenticated
///   identity-only pre-session message that also advances setup. Maximum and
///   recovery states remain fail-closed. Nothing here changes an existing FS
///   mode or pins a device as a side effect of a send.
/// * The durable export stays app-owned. The opaque handle retained here is
///   dropped on revoke, but the durable pending recovery state is never
///   deleted, so the full app can always recover the outbound.
library;

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/crypto/fs_security_mode.dart';
import '../../core/crypto/models.dart';
import '../../core/crypto/passphrase_service.dart';
import '../../core/crypto/stego_decoder.dart';
import '../../core/crypto/v3/application_chat_bridge_v3.dart';
import '../../core/crypto/v3/application_payload_v3.dart';
import '../../core/crypto/v3/application_session_runtime_v3.dart';
// `V3HandshakeMode` is declared in the `local_identity_v3` library; the
// `handshake_v3` file is only a `part of` it and must not be imported directly.
import '../../core/crypto/v3/local_identity_v3.dart';
import '../../core/crypto/v3/public_identity_v3.dart';
import '../../core/providers.dart';
import '../../core/storage/messages_repository_core.dart';
import 'system_keyboard_controller.dart';

/// Bound for opaque identifiers crossing the native channel contract.
const int systemKeyboardSurfaceIdentifierMaxLength = 128;

/// Bound for display names and fingerprints surfaced to the native UI.
const int systemKeyboardSurfaceLabelMaxLength = 128;

/// Bound for the outbound encrypted carrier handed to the native layer.
const int systemKeyboardSurfaceOutboundCarrierMaxLength = 4000;

/// Read-only view of the app owner used to bind and re-check one backend call.
///
/// The service owns the implementation; this seam lets the backend abort the
/// moment the lock, identity or opt-in generation it started under is gone.
abstract interface class SystemKeyboardIntegrationGuard {
  /// Current monotonic app-owner generation.
  int get generation;

  /// Ordinary (non-passphrase) identity currently bound to the app, if any.
  String? get ordinaryIdentityId;

  /// Whether [generation] plus [identityId] still describe the live owner.
  bool admits(int generation, String? identityId);
}

/// Backend that can be told to drop in-memory session handles without ever
/// deleting durable recovery state.
abstract interface class SystemKeyboardSessionScopedBackend {
  /// Clears in-memory handles only. Durable pending exports stay recoverable.
  void clearSessionHandles();
}

/// Fail-closed backend used in ordinary builds.
///
/// It never touches storage, keys or the runtime: every call resolves to "no
/// data", so an unsupported build can never serve the keyboard.
class SystemKeyboardDisabledBackend
    implements SystemKeyboardBackend, SystemKeyboardSessionScopedBackend {
  /// Creates the disabled backend.
  const SystemKeyboardDisabledBackend();

  @override
  Future<List<SystemKeyboardContact>> listApprovedContacts() async =>
      const <SystemKeyboardContact>[];

  @override
  Future<SystemKeyboardBackendExport?> prepareTextOutbound(
    SystemKeyboardOutboundRequest request,
  ) async =>
      null;

  @override
  Future<void> markExported(String exportHandle) async {}

  @override
  Future<SystemKeyboardBackendDecoded?> decodeCarrier(String carrier) async =>
      null;

  @override
  void clearSessionHandles() {}
}

/// Real backend bound to the existing app owner providers.
class SystemKeyboardAppBackend
    implements
        SystemKeyboardBackend,
        SystemKeyboardSessionScopedBackend,
        SystemKeyboardContactSecurityProvider {
  /// Creates the backend. [ref] is the owning provider container reference and
  /// [guard] is the live app-owner snapshot.
  SystemKeyboardAppBackend({
    required Ref ref,
    required SystemKeyboardIntegrationGuard guard,
  })  : _ref = ref,
        _guard = guard;

  final Ref _ref;
  final SystemKeyboardIntegrationGuard _guard;

  /// At most one opaque handle is retained: the controller already enforces a
  /// single unconsumed pending export per input session.
  final Map<String, _PinnedExport> _pinned = <String, _PinnedExport>{};
  int _handleCounter = 0;
  int _callGeneration = 0;
  String? _callIdentity;

  // ── SystemKeyboardBackend ─────────────────────────────────────────────────

  @override
  Future<List<SystemKeyboardContact>> listApprovedContacts() async {
    if (!_beginCall()) return const <SystemKeyboardContact>[];
    final List<RemoteIdentity> saved;
    try {
      saved = await _savedContacts();
    } catch (_) {
      return const <SystemKeyboardContact>[];
    }
    if (!_stillValid()) return const <SystemKeyboardContact>[];
    final List<SystemKeyboardContact> surface = <SystemKeyboardContact>[];
    for (final RemoteIdentity contact in saved) {
      if (!_isSurfaceV3Contact(contact)) continue;
      final SystemKeyboardContact? mapped = _surfaceContact(
        contact.identityId,
        contact.displayName,
        contact.fingerprint,
      );
      if (mapped != null) surface.add(mapped);
    }
    return List<SystemKeyboardContact>.unmodifiable(surface);
  }

  @override
  Future<String?> securityPhaseForContact(
      String contactId, String fingerprint) async {
    if (!_beginCall()) return null;
    final contact = await _savedContact(contactId);
    if (!_stillValid() ||
        contact == null ||
        !_isSurfaceV3Contact(contact) ||
        contact.fingerprint != fingerprint) {
      return null;
    }
    final keyTag = _ordinaryKeyTag();
    if (keyTag == null) return null;
    final bridge = await _openBridge(keyTag);
    if (bridge == null || !_stillValid()) return null;
    final mode = bridge.modeForContact(contact);
    final status = await bridge.securityStatus(
      contact: contact,
      selectedMode: mode,
      eligibilityPolicy: bridge.eligibilityForContact(contact),
      requireEligibilityPolicy: true,
    );
    if (!_stillValid()) return null;
    if (mode == V3HandshakeMode.maximum) {
      return switch (status.phase) {
        V3ChatContactSecurityPhase.setupRequired => 'maximumSetupRequired',
        V3ChatContactSecurityPhase.setupPending => 'maximumSetupPending',
        V3ChatContactSecurityPhase.recoveryRequired =>
          'maximumRecoveryRequired',
        _ => status.phase.name,
      };
    }
    return status.phase.name;
  }

  @override
  Future<SystemKeyboardBackendExport?> prepareTextOutbound(
    SystemKeyboardOutboundRequest request,
  ) async {
    if (!_beginCall()) return null;

    // Freshly fetch the saved contact: the fingerprint confirmed by the user in
    // the keyboard must still match the saved record.
    final RemoteIdentity? contact = await _savedContact(request.contactId);
    if (!_stillValid()) return null;
    if (contact == null || !_isSurfaceV3Contact(contact)) return null;
    if (contact.fingerprint != request.contactFingerprint) return null;

    // Ordinary identity only: a passphrase context is never surfaced here.
    final String? keyTag = _ordinaryKeyTag();
    if (keyTag == null || keyTag.isEmpty) return null;

    final V3ApplicationChatBridge? bridge = await _openBridge(keyTag);
    if (bridge == null || !_stillValid()) return null;

    // The selected, fingerprint-matched saved contact is an explicit app-owned
    // boundary. It may initialize the default Normal policy only while the
    // runtime proves the contact has no existing setup. Missing policy beside
    // durable setup, recovery and Maximum remain fail-closed.
    final V3HandshakeMode mode = bridge.modeForContact(contact);
    V3SessionEligibilityPolicy? policy = bridge.eligibilityForContact(contact);
    if (policy == null) {
      if (mode != V3HandshakeMode.normal) return null;
      try {
        policy = await bridge.ensureContactPolicy(
          contact,
          V3HandshakeMode.normal,
        );
      } catch (_) {
        return null;
      }
      if (!_stillValid()) return null;
    }
    final V3ChatContactSecurityStatus status;
    try {
      status = await bridge.securityStatus(
        contact: contact,
        selectedMode: mode,
        eligibilityPolicy: policy,
        requireEligibilityPolicy: true,
      );
    } catch (_) {
      return null;
    }
    if (!_stillValid()) return null;
    final bool allowsNormalPreFs = mode == V3HandshakeMode.normal &&
        (status.phase == V3ChatContactSecurityPhase.setupRequired ||
            status.phase == V3ChatContactSecurityPhase.setupPending);
    if (!status.isActive && !allowsNormalPreFs) return null;

    final V3ChatOutboundExport export;
    try {
      export = await bridge.prepareOutbound(
        contact: contact,
        mode: mode,
        carrierMode: V3ChatCarrierMode.text,
        text: request.text,
        eligibilityPolicy: policy,
        eligibilityForContact: bridge.eligibilityForContact,
        maxCarrierCharacters: systemKeyboardSurfaceOutboundCarrierMaxLength,
      );
    } catch (_) {
      return null;
    }
    if (!_stillValid()) return null;
    if (export.purpose != V3ChatOutboundPurpose.application &&
        export.purpose != V3ChatOutboundPurpose.preFs) {
      return null;
    }
    if (export.parts.length != 1) return null;
    final String carrier = export.parts.single;
    if (carrier.isEmpty ||
        carrier.length > systemKeyboardSurfaceOutboundCarrierMaxLength) {
      return null;
    }

    final String handle = 'skx${_handleCounter++}';
    // Retain exactly the pinned bridge/export binding for the later ack. The
    // durable export itself is never deleted.
    _pinned
      ..clear()
      ..[handle] = _PinnedExport(
        bridge: bridge,
        export: export,
        generation: _callGeneration,
        identityId: _callIdentity,
      );
    return SystemKeyboardBackendExport(
      exportHandle: handle,
      carriers: <String>[carrier],
      ciphertextCodeUnits: carrier.length,
    );
  }

  @override
  Future<void> markExported(String exportHandle) async {
    final _PinnedExport? pinned = _pinned.remove(exportHandle);
    if (pinned == null) {
      throw StateError('System keyboard export handle is unknown');
    }
    // Use the pinned bridge and export, never a freshly opened context.
    if (!_guard.admits(pinned.generation, pinned.identityId)) {
      throw StateError('System keyboard export context is no longer valid');
    }
    await pinned.bridge.markExported(pinned.export);
  }

  @override
  Future<SystemKeyboardBackendDecoded?> decodeCarrier(String carrier) async {
    if (!_beginCall()) return null;
    if (carrier.isEmpty || carrier.length > StegoDecoder.maxCarrierCodeUnits) {
      return null;
    }

    final List<RemoteIdentity> saved;
    try {
      saved = await _savedContacts();
    } catch (_) {
      return null;
    }
    if (!_stillValid()) return null;
    final List<RemoteIdentity> contacts =
        saved.where(_isSurfaceV3Contact).toList(growable: false);
    if (contacts.isEmpty) return null;

    final String? keyTag = _ordinaryKeyTag();
    if (keyTag == null || keyTag.isEmpty) return null;
    final V3ApplicationChatBridge? bridge = await _openBridge(keyTag);
    if (bridge == null || !_stillValid()) return null;

    final V3ChatInboundResult inbound;
    try {
      inbound = await bridge.receiveCarrier(
        carrier: carrier,
        contacts: contacts,
        modeForContact: bridge.modeForContact,
        eligibilityForContact: bridge.eligibilityForContact,
        ensureEligibilityForContact: bridge.ensureContactPolicy,
        pinMaximumDevice: bridge.pinMaximumDevice,
      );
    } on FormatException {
      return null;
    } catch (_) {
      return null;
    }
    if (!_stillValid()) return null;

    switch (inbound.status) {
      case V3ChatInboundStatus.handshakeProgress:
      case V3ChatInboundStatus.handshakeResponse:
      case V3ChatInboundStatus.sessionEstablished:
        _bumpRegistryVersion();
        return null;
      case V3ChatInboundStatus.delivered:
        break;
      case V3ChatInboundStatus.pending:
      case V3ChatInboundStatus.expired:
      case V3ChatInboundStatus.acknowledgementApplied:
      case V3ChatInboundStatus.committedReplay:
      case V3ChatInboundStatus.notForThisInstallation:
      case V3ChatInboundStatus.invalid:
        return null;
    }

    final RemoteIdentity? contact = inbound.contact;
    final V3ApplicationPayload? payload = inbound.payload;
    if (contact == null || payload == null) return null;
    final SystemKeyboardContact? sender = _surfaceContact(
      contact.identityId,
      contact.displayName,
      contact.fingerprint,
    );
    if (sender == null) return null;
    final String text = payload.text;
    if (text.isEmpty || text.length > StegoDecoder.maxCarrierCodeUnits) {
      return null;
    }
    // The controller turns read-once / expiry into "open the app"; the preview
    // is never marked read, never loaded from the durable body store and never
    // copied to the clipboard here. The bridge already projected history.
    return SystemKeyboardBackendDecoded(
      contact: sender,
      text: text,
      readOnce: payload.deleteAfterRead,
      expired: false,
      hasExpiry: payload.expireAfterUnixSeconds != null,
    );
  }

  @override
  void clearSessionHandles() {
    _pinned.clear();
  }

  // ── internals ─────────────────────────────────────────────────────────────

  bool _beginCall() {
    final int generation = _guard.generation;
    final String? identity = _guard.ordinaryIdentityId;
    if (identity == null || identity.isEmpty) return false;
    if (!_guard.admits(generation, identity)) return false;
    _callGeneration = generation;
    _callIdentity = identity;
    return true;
  }

  bool _stillValid() {
    final String? identity = _callIdentity;
    if (identity == null) return false;
    return _guard.admits(_callGeneration, identity);
  }

  Future<RemoteIdentity?> _savedContact(String contactId) async {
    try {
      final List<RemoteIdentity> saved = await _savedContacts();
      for (final RemoteIdentity contact in saved) {
        if (contact.identityId == contactId) return contact;
      }
    } catch (_) {
      return null;
    }
    return null;
  }

  Future<List<RemoteIdentity>> _savedContacts() async {
    final repository = _ref.read(identitiesRepositoryProvider);
    await repository.waitForReadyContext();
    return repository.watchRemote().first;
  }

  /// Opens the existing app-owned V3 runtime plus an ephemeral repository
  /// context lease. The runtime provider binds it to the captured ordinary
  /// identity before opening it; the legacy X25519 identity ID and the hybrid
  /// V3 identity ID use different digests and must not be compared directly.
  Future<V3ApplicationChatBridge?> _openBridge(String keyTag) async {
    try {
      final V3ApplicationSessionRuntime? runtime =
          await _ref.read(v3ApplicationSessionRuntimeProvider.future);
      if (runtime == null) return null;
      if (!_stillValid()) return null;
      final MessagesRepositoryCore repository =
          _ref.read(messagesRepositoryProvider);
      if (!_stillValid()) return null;
      final MessagesRepositoryContextLease lease =
          await repository.acquireContextLease();
      if (!_stillValid()) return null;
      return V3ApplicationChatBridge(
        runtime: runtime,
        messagesRepository: repository,
        keyTag: keyTag,
        repositoryContextLease: lease,
      );
    } catch (_) {
      return null;
    }
  }

  String? _ordinaryKeyTag() {
    try {
      final PassphraseState passphrase = _ref.read(passphraseProvider);
      if (passphrase.isActive) return null;
      // Only a fully resolved value is accepted: a loading or failed keyTag
      // provider must never fall back to a possibly stale tag.
      final AsyncValue<String?> tag = _ref.read(originalKeyTagProvider);
      if (tag is AsyncData<String?>) {
        final String? value = tag.value;
        if (value != null && value.isNotEmpty) return value;
      }
    } catch (_) {
      return null;
    }
    return null;
  }

  void _bumpRegistryVersion() {
    try {
      _ref.read(fsRegistryVersionProvider.notifier).state++;
    } catch (_) {
      // UI refresh only; never affects admission.
    }
  }

  static bool _isSurfaceV3Contact(RemoteIdentity contact) =>
      contact.protocolVersion == V3PublicIdentityCodec.protocolVersion &&
      (contact.publicIdentityBase64?.isNotEmpty ?? false);

  static SystemKeyboardContact? _surfaceContact(
    String id,
    String name,
    String fingerprint,
  ) {
    if (id.isEmpty || id.length > systemKeyboardSurfaceIdentifierMaxLength) {
      return null;
    }
    if (name.isEmpty || name.length > systemKeyboardSurfaceLabelMaxLength) {
      return null;
    }
    if (fingerprint.isEmpty ||
        fingerprint.length > systemKeyboardSurfaceLabelMaxLength) {
      return null;
    }
    return SystemKeyboardContact(
      id: id,
      name: name,
      fingerprint: fingerprint,
    );
  }
}

class _PinnedExport {
  _PinnedExport({
    required this.bridge,
    required this.export,
    required this.generation,
    required this.identityId,
  });

  final V3ApplicationChatBridge bridge;
  final V3ChatOutboundExport export;
  final int generation;
  final String? identityId;
}
