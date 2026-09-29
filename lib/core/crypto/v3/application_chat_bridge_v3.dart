// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../stego_encoder.dart';
import '../stego_decoder.dart';
import '../../storage/messages_repository_core.dart';
import '../fs_security_mode.dart';
import '../fs_message_classification.dart';
import '../models.dart';
import 'application_payload_v3.dart';
import 'application_session_runtime_v3.dart';
import 'application_transport_v3.dart';
import 'combined_carrier_v3.dart';
import 'handshake_persistence_v3.dart';
import 'handshake_transport_v3.dart';
import 'handshake_frame_inbox_v3.dart';
import 'hybrid_ratchet_header_v3.dart';
import 'identity_v3_adapter.dart';
import 'key_schedule_v3.dart';
import 'lmf_v3.dart';
import 'local_identity_v3.dart';
import 'prefs_bootstrap_v3.dart';
import 'prefs_envelope_v3.dart';
import 'public_identity_v3.dart';

enum V3ChatCarrierMode { text, link, steganography }

/// Outbound purpose of one carrier export.
///
/// [preFs] is the explicitly authorised Normal-mode pre-session bootstrap: the
/// user text plus handshake control travel together, and the text itself is
/// only identity-encrypted (`preFs`), never forward secret and never
/// post-quantum.
enum V3ChatOutboundPurpose { handshake, preFs, application, acknowledgement }

enum V3ChatContactSecurityPhase {
  setupRequired,
  setupPending,
  normalActive,
  maximumActive,
  recoveryRequired,
}

/// Non-secret security state used by contact and chat presentation.
final class V3ChatContactSecurityStatus {
  const V3ChatContactSecurityStatus({
    required this.phase,
    required this.selectedMode,
    required this.activeSessionCount,
    required this.hasSessionsInAnotherMode,
  });

  final V3ChatContactSecurityPhase phase;
  final V3HandshakeMode selectedMode;
  final int activeSessionCount;
  final bool hasSessionsInAnotherMode;

  bool get isActive =>
      phase == V3ChatContactSecurityPhase.normalActive ||
      phase == V3ChatContactSecurityPhase.maximumActive;
}

final class V3ChatCoverCapacityException implements Exception {
  const V3ChatCoverCapacityException(this.missingCharacters);

  final int missingCharacters;
}

/// Raised before any mutation when user text cannot fit the selected carrier's
/// preFs bootstrap budget. The caller keeps the user's draft.
final class V3ChatPreFsCapacityException implements Exception {
  const V3ChatPreFsCapacityException(this.reason);

  final String reason;

  @override
  String toString() => 'V3ChatPreFsCapacityException: $reason';
}

/// Non-secret preFs bootstrap metadata attached to an outbound export.
final class V3ChatPreFsOutboundMetadata {
  const V3ChatPreFsOutboundMetadata({
    required this.messageId,
    required this.contextId,
    required this.dataFragmentCount,
    required this.dataPartCount,
    required this.controlPartCount,
    required this.carrierMode,
    required this.timestampUnixSeconds,
    this.deferredPartCount = 0,
  });

  final String messageId;
  final String contextId;
  final int dataFragmentCount;
  final int dataPartCount;
  final int controlPartCount;
  final V3ChatCarrierMode carrierMode;
  final int timestampUnixSeconds;
  final int deferredPartCount;

  static const String securityLabel = V3PreFsSecurityFacts.label;
  static const bool classicalIdentityOnly = true;
  static const bool forwardSecrecy = false;
  static const bool postQuantum = false;
  static const bool isEstablishedV3Session = false;
}

/// Non-secret preFs bootstrap metadata attached to an inbound result.
final class V3ChatPreFsInboundMetadata {
  const V3ChatPreFsInboundMetadata({
    required this.messageId,
    required this.contextId,
    required this.receivedDataFragments,
    required this.dataFragmentCount,
    required this.receivedControlFragments,
    required this.controlFragmentCount,
    required this.dataComplete,
    required this.controlComplete,
    required this.acknowledgementEmitted,
  });

  final String messageId;
  final String contextId;
  final int receivedDataFragments;
  final int dataFragmentCount;
  final int receivedControlFragments;
  final int controlFragmentCount;
  final bool dataComplete;
  final bool controlComplete;
  final bool acknowledgementEmitted;

  static const String securityLabel = V3PreFsSecurityFacts.label;
}

/// Next-stage bridge/UI seam: pending preFs bootstrap state plus the exact
/// security label that must be shown for identity-only pre-session text.
final class V3ChatPreFsStatus {
  const V3ChatPreFsStatus({
    required this.hasPendingBootstrap,
    required this.pendingDataPartCount,
    required this.pendingControlPartCount,
    required this.pendingAcknowledgementPartCount,
    required this.requiresAcknowledgedRetransmission,
  });

  final bool hasPendingBootstrap;
  final int pendingDataPartCount;
  final int pendingControlPartCount;
  final int pendingAcknowledgementPartCount;
  final bool requiresAcknowledgedRetransmission;

  static const String securityLabel = V3PreFsSecurityFacts.label;
  static const bool classicalIdentityOnly = true;
  static const bool forwardSecrecy = false;
  static const bool postQuantum = false;
  static const bool isEstablishedV3Session = false;
}

/// Exact independently shareable carrier parts returned to the chat UI.
final class V3ChatOutboundExport {
  V3ChatOutboundExport._({
    required this.purpose,
    required Iterable<String> parts,
    required this.localIdentityId,
    required this.remoteIdentityId,
    required this.carrierMode,
    required this.policyRevision,
    Iterable<_V3ChatApplicationPart?>? applicationParts,
    Iterable<_V3ChatPreFsPart?>? preFsParts,
    this.handshakeId,
    this.messageExport,
    this.preFsMetadata,
    this.restored = false,
  })  : parts = List<String>.unmodifiable(parts),
        _applicationParts = List<_V3ChatApplicationPart?>.unmodifiable(
          applicationParts ?? const [],
        ),
        _preFsParts = List<_V3ChatPreFsPart?>.unmodifiable(
          preFsParts ?? const [],
        ) {
    if (this.parts.isEmpty) {
      throw ArgumentError('Layergram v3 export must contain at least one part');
    }
    if (localIdentityId.isEmpty ||
        remoteIdentityId.isEmpty ||
        policyRevision < 0) {
      throw ArgumentError('Layergram v3 export context binding is invalid');
    }
    if (this.parts.any(
          (part) => part.length > V3LmfFrameCodec.maxStegoInputCodeUnits,
        )) {
      throw ArgumentError('Layergram v3 export contains a non-portable part');
    }
    if (_applicationParts.isNotEmpty &&
        _applicationParts.length != this.parts.length) {
      throw ArgumentError('Layergram v3 export part binding mismatch');
    }
    if (_preFsParts.isNotEmpty && _preFsParts.length != this.parts.length) {
      throw ArgumentError('Layergram v3 preFs export part binding mismatch');
    }
  }

  final V3ChatOutboundPurpose purpose;
  final List<String> parts;
  final String localIdentityId;
  final String remoteIdentityId;
  final V3ChatCarrierMode carrierMode;
  final int policyRevision;
  final String? handshakeId;
  final V3ApplicationMessageExport? messageExport;
  final V3ChatPreFsOutboundMetadata? preFsMetadata;
  final bool restored;
  final List<_V3ChatApplicationPart?> _applicationParts;
  final List<_V3ChatPreFsPart?> _preFsParts;

  bool get isMultipart => parts.length > 1;

  /// True when some user text is carried by the classical identity-only preFs
  /// bootstrap instead of an established v3 session.
  bool get carriesPreFs => preFsMetadata != null;

  /// Clipboard-friendly bundle. Every non-empty line remains independently
  /// importable and below the common carrier limit.
  String get bundledText => parts.join('\n');
}

enum V3ChatInboundStatus {
  pending,
  delivered,
  expired,
  handshakeProgress,
  handshakeResponse,
  sessionEstablished,
  acknowledgementApplied,
  committedReplay,
  notForThisInstallation,
  invalid,
}

final class V3ChatInboundResult {
  V3ChatInboundResult({
    required this.status,
    this.contact,
    this.payload,
    V3ChatOutboundExport? response,
    Iterable<V3ChatOutboundExport> responses = const [],
    this.preFs,
  }) : responses = List<V3ChatOutboundExport>.unmodifiable(
          <V3ChatOutboundExport>[
            ...responses,
            if (response != null) response,
          ],
        );

  final V3ChatInboundStatus status;
  final RemoteIdentity? contact;
  final V3ApplicationPayload? payload;
  final V3ChatPreFsInboundMetadata? preFs;

  /// Every independently useful response produced by one carrier import.
  final List<V3ChatOutboundExport> responses;

  /// Convenience single response, preferring session-advancing traffic. Use
  /// [responses] when a carrier produced more than one response.
  V3ChatOutboundExport? get response {
    if (responses.isEmpty) return null;
    for (final candidate in responses) {
      if (candidate.purpose == V3ChatOutboundPurpose.handshake) {
        return candidate;
      }
    }
    for (final candidate in responses) {
      if (candidate.purpose == V3ChatOutboundPurpose.application) {
        return candidate;
      }
    }
    return responses.first;
  }

  bool get hasUserMessage => payload != null;
}

typedef V3HandshakeModeResolver = V3HandshakeMode Function(
  RemoteIdentity contact,
);

typedef V3SessionEligibilityResolver = V3SessionEligibilityPolicy? Function(
  RemoteIdentity contact,
);

typedef V3SessionEligibilityEnsurer = Future<V3SessionEligibilityPolicy>
    Function(RemoteIdentity contact, V3HandshakeMode mode);

typedef V3MaximumDevicePinCommit = Future<void> Function(
  RemoteIdentity contact,
  String remoteDeviceId,
);

/// Optional local QA categories. No exception text, identifier, key, carrier
/// or application plaintext is passed to the observer.
enum V3ChatHandshakeDiagnostic {
  fragmentAccepted,
  fragmentDuplicate,
  committedReplay,
  responsePrepared,
  sessionEstablished,
  addressedElsewhere,
  initiatorProofRejected,
  responderProofRejected,
  transcriptMismatch,
  deviceMismatch,
  resetRejected,
  malformed,
}

/// Application-facing adapter between chat identities and the durable v3
/// transport runtime.
///
/// It never treats generation as delivery. New sends and setup messages are
/// already durable when returned; pending setup is retried byte-for-byte, and
/// incoming carrier parts may be lost, duplicated, delayed or reordered.
final class V3ApplicationChatBridge {
  V3ApplicationChatBridge({
    required V3ApplicationSessionRuntime runtime,
    required MessagesRepositoryCore messagesRepository,
    required String? keyTag,
    MessagesRepositoryContextLease? repositoryContextLease,
    V3PreFsPendingStore? preFsPendingStore,
    bool preFsBootstrapEnabled = true,
    Random? preFsRandom,
  })  : _runtime = runtime,
        _messagesRepository = messagesRepository,
        _keyTag = keyTag,
        _repositoryContextLease = repositoryContextLease,
        _preFsPendingStoreValue =
            preFsPendingStore ?? runtime.preFsPendingStore,
        _preFsBootstrapEnabled = preFsBootstrapEnabled,
        _preFsRandom = preFsRandom,
        handshakeDiagnostic = null {
    if (runtime.isEstablishedSessionOnly) {
      throw ArgumentError(
          'Restricted runtimes require the restricted chat bridge');
    }
  }

  factory V3ApplicationChatBridge.forEstablishedSessions({
    required V3ApplicationSessionRuntime runtime,
  }) {
    if (!runtime.isEstablishedSessionOnly) {
      throw ArgumentError.value(
          runtime, 'runtime', 'restricted runtime required');
    }
    return V3ApplicationChatBridge._restricted(runtime: runtime);
  }

  /// The keyboard owns a bounded protocol working set but does not open the
  /// app message repository. User text is returned to its native surface;
  /// handshake and preFs replay state remain durable in the delegated store.
  factory V3ApplicationChatBridge.forDelegatedKeyboard({
    required V3ApplicationSessionRuntime runtime,
    void Function(V3ChatHandshakeDiagnostic)? handshakeDiagnostic,
  }) {
    if (!runtime.isDelegatedKeyboardSession) {
      throw ArgumentError.value(
          runtime, 'runtime', 'delegated runtime required');
    }
    return V3ApplicationChatBridge._delegated(
        runtime: runtime, handshakeDiagnostic: handshakeDiagnostic);
  }

  V3ApplicationChatBridge._delegated({
    required V3ApplicationSessionRuntime runtime,
    this.handshakeDiagnostic,
  })  : _runtime = runtime,
        _messagesRepository = null,
        _keyTag = null,
        _repositoryContextLease = null,
        _preFsPendingStoreValue = runtime.preFsPendingStore,
        _preFsBootstrapEnabled = true,
        _preFsRandom = null;

  // Configurable only on the delegated QA seam. Diagnostics cannot change an
  // authentication or persistence result, including if an observer throws.
  final void Function(V3ChatHandshakeDiagnostic)? handshakeDiagnostic;

  void _diagnoseHandshake(V3ChatHandshakeDiagnostic category) {
    try {
      handshakeDiagnostic?.call(category);
    } catch (_) {}
  }

  V3ApplicationChatBridge._restricted({
    required V3ApplicationSessionRuntime runtime,
  })  : _runtime = runtime,
        _messagesRepository = null,
        _keyTag = null,
        _repositoryContextLease = null,
        _preFsPendingStoreValue = null,
        _preFsBootstrapEnabled = false,
        _preFsRandom = null,
        handshakeDiagnostic = null;

  final V3ApplicationSessionRuntime _runtime;
  final MessagesRepositoryCore? _messagesRepository;
  final String? _keyTag;
  final MessagesRepositoryContextLease? _repositoryContextLease;
  final V3PreFsPendingStore? _preFsPendingStoreValue;
  V3PreFsPendingStore get _preFsPendingStore =>
      _preFsPendingStoreValue ??
      (throw StateError('Restricted bridge has no pre-FS store'));

  /// Explicit policy boundary. When false, Normal-mode pre-session text is
  /// refused rather than silently dropped into a handshake-only branch.
  final bool _preFsBootstrapEnabled;

  final Random? _preFsRandom;

  bool get _restricted => _runtime.isEstablishedSessionOnly;

  MessagesRepositoryCore _requireMessagesRepository() {
    final repository = _messagesRepository;
    if (repository == null) {
      throw StateError(
        'Layergram v3 established-session bridge has no message repository',
      );
    }
    return repository;
  }

  String get localIdentityId => _runtime.localPublicIdentity.identityId;

  V3HandshakeMode modeForContact(RemoteIdentity contact) {
    final mode = _runtime.protocolV3ModeForIdentity(
      V3IdentityAdapter.fromRemoteIdentity(contact),
    );
    return mode == FsSecurityMode.strict
        ? V3HandshakeMode.maximum
        : V3HandshakeMode.normal;
  }

  V3SessionEligibilityPolicy? eligibilityForContact(RemoteIdentity contact) {
    return _runtime.protocolV3EligibilityForIdentity(
      V3IdentityAdapter.fromRemoteIdentity(contact),
    );
  }

  Future<V3SessionEligibilityPolicy> ensureContactPolicy(
    RemoteIdentity contact,
    V3HandshakeMode mode,
  ) {
    return _runtime.ensureProtocolV3ContactPolicy(
      remoteIdentity: V3IdentityAdapter.fromRemoteIdentity(contact),
      mode: mode == V3HandshakeMode.maximum
          ? FsSecurityMode.strict
          : FsSecurityMode.advanced,
    );
  }

  Future<void> setContactSecurityMode(
    RemoteIdentity contact,
    FsSecurityMode mode,
  ) {
    return _runtime.setProtocolV3ContactMode(
      remoteIdentity: V3IdentityAdapter.fromRemoteIdentity(contact),
      mode: mode,
    );
  }

  Future<V3SessionEligibilityPolicy> pinMaximumDevice(
    RemoteIdentity contact,
    String remoteDeviceId,
  ) {
    return _runtime.pinProtocolV3MaximumDevice(
      remoteIdentity: V3IdentityAdapter.fromRemoteIdentity(contact),
      remoteDeviceId: remoteDeviceId,
    );
  }

  Future<V3ChatContactSecurityStatus> securityStatus({
    required RemoteIdentity contact,
    required V3HandshakeMode selectedMode,
    V3SessionEligibilityPolicy? eligibilityPolicy,
    bool requireEligibilityPolicy = false,
  }) async {
    final remote = V3IdentityAdapter.fromRemoteIdentity(contact);
    final sessions = await _runtime.sessionsForRemoteIdentity(remote);
    final maximumPinMissing = selectedMode == V3HandshakeMode.maximum &&
        eligibilityPolicy?.maximumRemoteDeviceId == null;
    if (requireEligibilityPolicy &&
        eligibilityPolicy == null &&
        sessions.isNotEmpty) {
      return V3ChatContactSecurityStatus(
        phase: V3ChatContactSecurityPhase.recoveryRequired,
        selectedMode: selectedMode,
        activeSessionCount: 0,
        hasSessionsInAnotherMode: true,
      );
    }
    if (maximumPinMissing &&
        sessions.any((session) => session.mode == selectedMode)) {
      return V3ChatContactSecurityStatus(
        phase: V3ChatContactSecurityPhase.recoveryRequired,
        selectedMode: selectedMode,
        activeSessionCount: 0,
        hasSessionsInAnotherMode:
            sessions.any((session) => session.mode != selectedMode),
      );
    }
    final matchingSessions = sessions
        .where(
          (session) =>
              session.mode == selectedMode &&
              (selectedMode != V3HandshakeMode.maximum ||
                  session.remoteDeviceId ==
                      eligibilityPolicy!.maximumRemoteDeviceId) &&
              (eligibilityPolicy == null ||
                  !eligibilityPolicy.excludedHandshakeIds
                      .contains(session.handshakeId)),
        )
        .toList(growable: false);
    final hasOtherMode =
        sessions.any((session) => session.mode != selectedMode);
    if (_runtime.requiresRecovery || eligibilityPolicy?.isValid == false) {
      return V3ChatContactSecurityStatus(
        phase: V3ChatContactSecurityPhase.recoveryRequired,
        selectedMode: selectedMode,
        activeSessionCount: matchingSessions.length,
        hasSessionsInAnotherMode: hasOtherMode,
      );
    }
    if (matchingSessions.isNotEmpty) {
      var activeSessionCount = matchingSessions.length;
      if (selectedMode == V3HandshakeMode.normal && _preFsBootstrapEnabled) {
        final contactDigest = _armored(_identityDigest(remote));
        activeSessionCount = 0;
        for (final session in matchingSessions) {
          final bootstrap = await _preFsPendingStore.isBootstrapHandshake(
            contactDigest,
            session.handshakeId,
          );
          if (!bootstrap ||
              session.role == V3SessionRole.responder ||
              await _preFsPendingStore.isPeerFsReady(
                contactDigest,
                session.handshakeId,
              )) {
            activeSessionCount++;
          }
        }
        if (activeSessionCount == 0) {
          return V3ChatContactSecurityStatus(
            phase: V3ChatContactSecurityPhase.setupPending,
            selectedMode: selectedMode,
            activeSessionCount: 0,
            hasSessionsInAnotherMode: hasOtherMode,
          );
        }
        final newDeviceReplies = await _pendingRepliesForNewDevices(
          remote: remote,
          activeDeviceIds:
              matchingSessions.map((session) => session.remoteDeviceId).toSet(),
          excludedHandshakeIds:
              eligibilityPolicy?.excludedHandshakeIds ?? const <String>{},
        );
        if (newDeviceReplies.isNotEmpty) {
          return V3ChatContactSecurityStatus(
            phase: V3ChatContactSecurityPhase.setupPending,
            selectedMode: selectedMode,
            activeSessionCount: activeSessionCount,
            hasSessionsInAnotherMode: hasOtherMode,
          );
        }
      }
      return V3ChatContactSecurityStatus(
        phase: selectedMode == V3HandshakeMode.maximum
            ? V3ChatContactSecurityPhase.maximumActive
            : V3ChatContactSecurityPhase.normalActive,
        selectedMode: selectedMode,
        activeSessionCount: activeSessionCount,
        hasSessionsInAnotherMode: hasOtherMode,
      );
    }
    if (_restricted) {
      // Handshake repair lookups are denied on a restricted runtime, and an
      // absent established session is never treated as a reason to start one.
      return V3ChatContactSecurityStatus(
        phase: V3ChatContactSecurityPhase.setupRequired,
        selectedMode: selectedMode,
        activeSessionCount: 0,
        hasSessionsInAnotherMode: hasOtherMode,
      );
    }
    final pending = await _runtime.pendingHandshakeForRemoteIdentity(
      remoteIdentity: remote,
      mode: selectedMode,
      excludedHandshakeIds:
          eligibilityPolicy?.excludedHandshakeIds ?? const <String>{},
    );
    if (requireEligibilityPolicy &&
        eligibilityPolicy == null &&
        pending != null) {
      return V3ChatContactSecurityStatus(
        phase: V3ChatContactSecurityPhase.recoveryRequired,
        selectedMode: selectedMode,
        activeSessionCount: 0,
        hasSessionsInAnotherMode: hasOtherMode,
      );
    }
    return V3ChatContactSecurityStatus(
      phase: pending == null
          ? V3ChatContactSecurityPhase.setupRequired
          : V3ChatContactSecurityPhase.setupPending,
      selectedMode: selectedMode,
      activeSessionCount: 0,
      hasSessionsInAnotherMode: hasOtherMode,
    );
  }

  Future<Set<String>> handshakeIdsForContact(RemoteIdentity contact) async {
    final remote = V3IdentityAdapter.fromRemoteIdentity(contact);
    return Set<String>.unmodifiable(
      (await _runtime.sessionsForRemoteIdentity(remote))
          .map((session) => session.handshakeId),
    );
  }

  Future<T> commitContactPolicyBoundary<T>({
    required RemoteIdentity contact,
    required Future<T> Function(Set<String> handshakeIds) persist,
  }) {
    return _runtime.commitContactPolicyBoundary(
      remoteIdentity: V3IdentityAdapter.fromRemoteIdentity(contact),
      persist: persist,
    );
  }

  Future<T> initializeContactPolicy<T>({
    required RemoteIdentity contact,
    required Future<T> Function() persist,
  }) {
    return _runtime.initializeContactPolicy(
      remoteIdentity: V3IdentityAdapter.fromRemoteIdentity(contact),
      persist: persist,
    );
  }

  Future<V3ChatOutboundExport> prepareOutbound({
    required RemoteIdentity contact,
    required V3HandshakeMode mode,
    required V3ChatCarrierMode carrierMode,
    required String text,
    String coverText = '',
    int? timestampUnixSeconds,
    int? expireAfterUnixSeconds,
    bool deleteAfterRead = false,
    bool backupExcluded = false,
    V3SessionEligibilityPolicy? eligibilityPolicy,
    V3SessionEligibilityResolver? eligibilityForContact,
    Object? maxCarrierCharacters = V3LmfFrameCodec.portableShareCharacterLimit,
  }) async {
    final carrierLimit = _effectiveCarrierLimit(
      carrierMode,
      _normalizedCarrierLimit(maxCarrierCharacters),
    );
    eligibilityPolicy =
        eligibilityForContact?.call(contact) ?? eligibilityPolicy;
    if (eligibilityPolicy?.isValid == false) {
      throw StateError('Layergram v3 contact policy requires recovery');
    }
    final remote = V3IdentityAdapter.fromRemoteIdentity(contact);
    final sessions = await _runtime.sessionsForRemoteIdentity(remote);
    final maximumPinMissing = mode == V3HandshakeMode.maximum &&
        eligibilityPolicy?.maximumRemoteDeviceId == null;
    if (maximumPinMissing && sessions.any((session) => session.mode == mode)) {
      throw StateError(
        'Maximum-mode Layergram v3 device pin requires recovery',
      );
    }
    final selectedSessions = sessions
        .where(
          (session) =>
              session.mode == mode &&
              (mode != V3HandshakeMode.maximum ||
                  session.remoteDeviceId ==
                      eligibilityPolicy!.maximumRemoteDeviceId) &&
              (eligibilityPolicy == null ||
                  !eligibilityPolicy.excludedHandshakeIds
                      .contains(session.handshakeId)),
        )
        .toList(growable: false);
    var hasSelectedModeSession = selectedSessions.isNotEmpty;
    final bootstrapUnreadyHandshakeIds = <String>{};
    var everyReadySessionSupportsCombinedCarrier =
        selectedSessions.isNotEmpty && mode == V3HandshakeMode.normal;
    if (_preFsBootstrapEnabled &&
        hasSelectedModeSession &&
        mode == V3HandshakeMode.normal) {
      final contactDigest = _armored(_identityDigest(remote));
      for (final session in selectedSessions) {
        final bootstrap = await _preFsPendingStore.isBootstrapHandshake(
          contactDigest,
          session.handshakeId,
        );
        if (!bootstrap) {
          everyReadySessionSupportsCombinedCarrier = false;
          continue;
        }
        // An initiator persists its session before the peer receives the
        // confirmation. In simultaneous handshakes the newest local session
        // may therefore still be absent remotely; keep sending readable
        // preFs text until that peer proves it can receive application data.
        if (session.role == V3SessionRole.initiator &&
            !await _preFsPendingStore.isPeerFsReady(
              contactDigest,
              session.handshakeId,
            )) {
          bootstrapUnreadyHandshakeIds.add(session.handshakeId);
        }
      }
      hasSelectedModeSession =
          bootstrapUnreadyHandshakeIds.length < selectedSessions.length;
    }
    if (!hasSelectedModeSession) {
      if (text.isEmpty) {
        // Transporting handshake/FS control never requires a blank user send:
        // the caller can simply retransmit pending control on its own.
        final pending = await _pendingOrNewOffer(
          remote: remote,
          mode: mode,
          eligibilityPolicy: eligibilityPolicy,
        );
        return _handshakeExport(
          pending,
          remoteIdentityId: contact.identityId,
          policyRevision: eligibilityPolicy?.revision ?? 0,
          carrierMode: carrierMode,
          coverText: coverText,
          maxCarrierCharacters: carrierLimit,
        );
      }
      if (mode == V3HandshakeMode.maximum) {
        // Maximum is intentionally unchanged: no classical pre-session text
        // is ever carried, and the strict handshake-only export is preserved.
        final pending = await _pendingOrNewOffer(
          remote: remote,
          mode: mode,
          eligibilityPolicy: eligibilityPolicy,
        );
        return _handshakeExport(
          pending,
          remoteIdentityId: contact.identityId,
          policyRevision: eligibilityPolicy?.revision ?? 0,
          carrierMode: carrierMode,
          coverText: coverText,
          maxCarrierCharacters: carrierLimit,
        );
      }
      if (!_preFsBootstrapEnabled) {
        _preflightCarrier(carrierMode, coverText);
        final pending = await _pendingOrNewOffer(
          remote: remote,
          mode: mode,
          eligibilityPolicy: eligibilityPolicy,
        );
        return _handshakeExport(
          pending,
          remoteIdentityId: contact.identityId,
          policyRevision: eligibilityPolicy?.revision ?? 0,
          carrierMode: carrierMode,
          coverText: coverText,
          maxCarrierCharacters: carrierLimit,
        );
      }
      return _preparePreFsBootstrap(
        contact: contact,
        remote: remote,
        carrierMode: carrierMode,
        coverText: coverText,
        text: text,
        timestampUnixSeconds: timestampUnixSeconds,
        expireAfterUnixSeconds: expireAfterUnixSeconds,
        deleteAfterRead: deleteAfterRead,
        backupExcluded: backupExcluded,
        eligibilityPolicy: eligibilityPolicy,
        maxCarrierCharacters: carrierLimit,
      );
    }

    // A newly negotiating installation shares the identity key but does not
    // yet have an application ratchet. One ordinary Normal-mode message must
    // therefore be readable by *every* installation from one carrier. Keep
    // the established sessions intact and let their next messages use FS once
    // the parallel handshake has finished. The identity-only downgrade of
    // this particular message is authenticated and displayed as a gray shield.
    if (_preFsBootstrapEnabled &&
        mode == V3HandshakeMode.normal &&
        text.isNotEmpty) {
      final newDeviceReplies = await _pendingRepliesForNewDevices(
        remote: remote,
        activeDeviceIds: {
          for (final session in selectedSessions)
            if (!bootstrapUnreadyHandshakeIds.contains(session.handshakeId))
              session.remoteDeviceId,
        },
        excludedHandshakeIds:
            eligibilityPolicy?.excludedHandshakeIds ?? const <String>{},
      );
      if (newDeviceReplies.isNotEmpty) {
        return _preparePreFsBootstrap(
          contact: contact,
          remote: remote,
          carrierMode: carrierMode,
          coverText: coverText,
          text: text,
          timestampUnixSeconds: timestampUnixSeconds,
          expireAfterUnixSeconds: expireAfterUnixSeconds,
          deleteAfterRead: deleteAfterRead,
          backupExcluded: backupExcluded,
          eligibilityPolicy: eligibilityPolicy,
          maxCarrierCharacters: carrierLimit,
          preferredHandshakeIds: newDeviceReplies,
          identityWideNormalFallback: true,
        );
      }
      if (selectedSessions.length > 1 &&
          carrierMode == V3ChatCarrierMode.steganography) {
        return _preparePreFsBootstrap(
          contact: contact,
          remote: remote,
          carrierMode: carrierMode,
          coverText: coverText,
          text: text,
          timestampUnixSeconds: timestampUnixSeconds,
          expireAfterUnixSeconds: expireAfterUnixSeconds,
          deleteAfterRead: deleteAfterRead,
          backupExcluded: backupExcluded,
          eligibilityPolicy: eligibilityPolicy,
          maxCarrierCharacters: carrierLimit,
          identityWideNormalFallback: true,
          skipControl: true,
        );
      }
      if (carrierMode != V3ChatCarrierMode.steganography &&
          _applicationCarrierWorstCaseCharacters(
                text: text,
                senderDisplayName:
                    _runtime.localIdentity.publicIdentity.displayName,
                targetCount: selectedSessions.length,
                carrierMode: carrierMode,
              ) >
              carrierLimit) {
        // The application runtime commits ratchet state as it seals frames.
        // A carrier-capacity failure after that point would strand an unsent
        // message. Use one identity-wide carrier before mutating any ratchet.
        return _preparePreFsBootstrap(
          contact: contact,
          remote: remote,
          carrierMode: carrierMode,
          coverText: coverText,
          text: text,
          timestampUnixSeconds: timestampUnixSeconds,
          expireAfterUnixSeconds: expireAfterUnixSeconds,
          deleteAfterRead: deleteAfterRead,
          backupExcluded: backupExcluded,
          eligibilityPolicy: eligibilityPolicy,
          maxCarrierCharacters: carrierLimit,
          identityWideNormalFallback: true,
          skipControl: true,
        );
      }
    }

    final effectiveExcludedHandshakeIds = <String>{
      ...?eligibilityPolicy?.excludedHandshakeIds,
      ...bootstrapUnreadyHandshakeIds,
    };
    if (carrierMode != V3ChatCarrierMode.steganography &&
        _applicationCarrierWorstCaseCharacters(
              text: text,
              senderDisplayName: _runtime.localPublicIdentity.displayName,
              targetCount: selectedSessions.length,
              carrierMode: carrierMode,
            ) >
            carrierLimit) {
      // Reject before a ratchet commit; a multi-part user export must not
      // strand a sent state when the selected transport has a smaller limit.
      throw const V3ChatPreFsCapacityException(
        'one Layergram message does not fit this carrier',
      );
    }
    final effectiveTimestamp = timestampUnixSeconds ?? _nowUnixSeconds();
    {
      final message = await _runtime.sendApplicationMessageToIdentity(
        remoteIdentity: remote,
        expectedMode: mode,
        text: text,
        timestampUnixSeconds: effectiveTimestamp,
        expireAfterUnixSeconds: expireAfterUnixSeconds,
        deleteAfterRead: deleteAfterRead,
        backupExcluded: backupExcluded,
        excludedHandshakeIds: effectiveExcludedHandshakeIds,
        maximumRemoteDeviceId: eligibilityPolicy?.maximumRemoteDeviceId,
        maximumRemoteDeviceIdResolver: () =>
            (eligibilityForContact?.call(contact) ?? eligibilityPolicy)
                ?.maximumRemoteDeviceId,
      );
      if (_messagesRepository != null) {
        await _runtime.reconcileMessageRepository(
          messagesRepository: _requireMessagesRepository(),
          keyTag: _keyTag,
          repositoryContextLease: _repositoryContextLease,
        );
      }
      final encodedParts = await _encodeApplicationWithOptionalAcks(
        message.frames,
        runtime: _runtime,
        preFsPendingStore: _preFsPendingStoreValue,
        remoteIdentityDigest: selectedSessions.first.remoteIdentityDigest,
        allowCombinedCarrier: everyReadySessionSupportsCombinedCarrier,
        carrierMode: carrierMode,
        coverText: coverText,
        maxTotalCharacters: carrierLimit,
      );
      final singlePart = _singleApplicationCarrier(
        encodedParts,
        carrierMode: carrierMode,
        maxCarrierCharacters: carrierLimit,
      );
      final applicationBindings = <_V3ChatApplicationPart?>[
        for (final target in message.targets)
          for (final frame in target.frames)
            _V3ChatApplicationPart(
              assemblyId: target.assemblyId,
              fragmentIndex: frame.fragmentIndex,
            ),
      ];
      final applicationExport = V3ChatOutboundExport._(
        purpose: V3ChatOutboundPurpose.application,
        localIdentityId: localIdentityId,
        remoteIdentityId: contact.identityId,
        carrierMode: carrierMode,
        policyRevision: eligibilityPolicy?.revision ?? 0,
        parts: singlePart,
        messageExport: message,
        applicationParts: singlePart.length == 1 && encodedParts.length > 1
            ? const <_V3ChatApplicationPart?>[null]
            : applicationBindings,
      );
      return applicationExport;
    }
  }

  V3ChatOutboundExport _combineMixedDeviceExports(
    V3ChatOutboundExport preFs,
    V3ChatOutboundExport application,
  ) {
    if (preFs.purpose != V3ChatOutboundPurpose.preFs ||
        application.purpose != V3ChatOutboundPurpose.application ||
        preFs.localIdentityId != application.localIdentityId ||
        preFs.remoteIdentityId != application.remoteIdentityId ||
        preFs.carrierMode != application.carrierMode ||
        preFs.policyRevision != application.policyRevision) {
      throw StateError('Mixed-device Layergram export binding mismatch');
    }
    return V3ChatOutboundExport._(
      purpose: V3ChatOutboundPurpose.application,
      localIdentityId: application.localIdentityId,
      remoteIdentityId: application.remoteIdentityId,
      carrierMode: application.carrierMode,
      policyRevision: application.policyRevision,
      parts: [...preFs.parts, ...application.parts],
      messageExport: application.messageExport,
      preFsMetadata: preFs.preFsMetadata,
      restored: preFs.restored || application.restored,
      preFsParts: [
        ...preFs._preFsParts,
        for (final _ in application.parts) null,
      ],
      applicationParts: [
        for (final _ in preFs.parts) null,
        ...application._applicationParts,
      ],
    );
  }

  Future<V3ApplicationHandshakeExport> _pendingOrNewOffer({
    required V3PublicIdentity remote,
    required V3HandshakeMode mode,
    required V3SessionEligibilityPolicy? eligibilityPolicy,
  }) async {
    final excluded =
        eligibilityPolicy?.excludedHandshakeIds ?? const <String>{};
    final existing = await _runtime.pendingHandshakeForRemoteIdentity(
      remoteIdentity: remote,
      mode: mode,
      excludedHandshakeIds: excluded,
    );
    if (existing != null) return existing;
    return _runtime.createOffer(
      remoteIdentity: remote,
      mode: mode,
      excludedHandshakeIds: excluded,
    );
  }

  Future<Set<String>> _pendingRepliesForNewDevices({
    required V3PublicIdentity remote,
    required Set<String> activeDeviceIds,
    required Set<String> excludedHandshakeIds,
  }) async {
    final pending = await _runtime.pendingHandshakesForRemoteIdentity(
      remoteIdentity: remote,
      mode: V3HandshakeMode.normal,
      excludedHandshakeIds: excludedHandshakeIds,
    );
    final ids = <String>{};
    for (final candidate in pending) {
      if (candidate.kind != V3HandshakeRecordKind.reply) continue;
      final opened = await V3HandshakeTransport.open(
        frames: candidate.frames,
        initiatorIdentity: remote,
        responderIdentity: _runtime.localIdentity.publicIdentity,
      );
      try {
        final reply = opened.decodeReply();
        final deviceId = reply.initiatorDeviceId;
        try {
          if (!activeDeviceIds.contains(_armored(deviceId))) {
            ids.add(candidate.handshakeId);
          }
        } finally {
          _wipe(deviceId);
        }
      } finally {
        opened.close();
      }
    }
    return ids;
  }

  /// Normal-mode only: seal user text with the long-term identity X25519 key
  /// and carry the handshake/control fragments alongside it.
  ///
  /// Data parts are placed before control parts so the user text is readable
  /// even when control transport is lost, duplicated or reordered. Nothing is
  /// recorded durably until the whole message has been sealed and carrier
  /// encoded, so an over-budget draft is rejected before any mutation.
  Future<V3ChatOutboundExport> _preparePreFsBootstrap({
    required RemoteIdentity contact,
    required V3PublicIdentity remote,
    required V3ChatCarrierMode carrierMode,
    required String coverText,
    required String text,
    required int? timestampUnixSeconds,
    required int? expireAfterUnixSeconds,
    required bool deleteAfterRead,
    required bool backupExcluded,
    required V3SessionEligibilityPolicy? eligibilityPolicy,
    required int maxCarrierCharacters,
    Uint8List? logicalMessageId,
    Set<String>? preferredHandshakeIds,
    bool persistOutgoing = true,
    bool identityWideNormalFallback = false,
    bool skipControl = false,
  }) async {
    final local = _runtime.localIdentity;
    final timestamp = timestampUnixSeconds ?? _nowUnixSeconds();
    final extraTargetHeaderBytes =
        preferredHandshakeIds == null || identityWideNormalFallback
            ? 0
            : V3PreFsEnvelopeCodec.deviceIdBytes;
    final envelopeBudget = _preFsEnvelopeBudget(
      carrierMode,
      maxCarrierCharacters: maxCarrierCharacters,
      coverText: coverText,
    );
    if (envelopeBudget <=
        V3PreFsEnvelopeCodec.headerBytes +
            extraTargetHeaderBytes +
            V3PreFsEnvelopeCodec.authenticationTagBytes +
            1) {
      throw V3ChatCoverCapacityException(
        StegoEncoder.missingCoverCapacityForBytes(
          coverText,
          V3PreFsEnvelopeCodec.headerBytes +
              extraTargetHeaderBytes +
              V3PreFsEnvelopeCodec.authenticationTagBytes +
              1,
        ),
      );
    }
    final maxPlaintextPerFragment =
        V3PreFsCarrierBudget.oversizedUserTextLimitFor(
            envelopeBudget - extraTargetHeaderBytes);
    final textBytes = Uint8List.fromList(utf8.encode(text));
    if (textBytes.isEmpty) {
      throw const V3ChatPreFsCapacityException('user text is empty');
    }
    if (textBytes.length > V3ApplicationPayloadCodec.maxTextBytes) {
      throw const V3ChatPreFsCapacityException(
        'user text exceeds the maximum preFs message size',
      );
    }
    textBytes.fillRange(0, textBytes.length, 0);
    final messageId = logicalMessageId == null
        ? _secureRandomBytes(V3PreFsEnvelopeCodec.messageIdBytes, _preFsRandom)
        : Uint8List.fromList(logicalMessageId);
    if (messageId.length != V3PreFsEnvelopeCodec.messageIdBytes) {
      _wipe(messageId);
      throw ArgumentError.value(logicalMessageId, 'logicalMessageId');
    }
    final contextId = V3PreFsEnvelopeCodec.deriveContextId(
      localIdentity: local.publicIdentity,
      remoteIdentity: remote,
    );
    Uint8List? senderDigest;
    Uint8List? recipientDigest;
    Uint8List? recipientDeviceId;
    Uint8List? encodedPayload;
    try {
      senderDigest = V3PreFsEnvelopeCodec.identityDigest(local.publicIdentity);
      recipientDigest = V3PreFsEnvelopeCodec.identityDigest(remote);
      final payload = V3ApplicationPayload(
        messageId: messageId,
        senderIdentityDigest: senderDigest,
        recipientIdentityDigest: recipientDigest,
        text: text,
        timestampUnixSeconds: timestamp,
        senderDisplayName: _preFsDisplayName(local.publicIdentity.displayName),
        expireAfterUnixSeconds: expireAfterUnixSeconds,
        deleteAfterRead: deleteAfterRead,
        backupExcluded: backupExcluded,
      );
      encodedPayload = V3ApplicationPayloadCodec.encode(payload);
      final dataOnlyProbe = _encodePreFsCombinedPayload(encodedPayload, null);
      final dataOnlyLength = dataOnlyProbe.length;
      try {
        if (dataOnlyLength > maxPlaintextPerFragment) {
          throw const V3ChatPreFsCapacityException(
            'user text does not fit one preFs carrier',
          );
        }
      } finally {
        _wipe(dataOnlyProbe);
      }
      final contactDigestKey = _armored(recipientDigest);
      final prior =
          await _preFsPendingStore.pendingForContact(contactDigestKey);
      final previouslyBundled = <String>{};
      final priorBundleDigests = <Set<String>>[];
      for (final entry in prior) {
        final entryDigests = <String>{};
        for (final bytes in entry.bundledControlFrames) {
          final digest = _preFsFrameDigestKey(bytes);
          previouslyBundled.add(digest);
          entryDigests.add(digest);
          _wipe(bytes);
        }
        if (entryDigests.isNotEmpty) priorBundleDigests.add(entryDigests);
      }
      final allPendingCandidates = skipControl
          ? const <V3ApplicationHandshakeExport>[]
          : await _runtime.pendingHandshakesForRemoteIdentity(
              remoteIdentity: remote,
              mode: V3HandshakeMode.normal,
              excludedHandshakeIds:
                  eligibilityPolicy?.excludedHandshakeIds ?? const <String>{},
            );
      final replies = allPendingCandidates
          .where((candidate) =>
              candidate.kind == V3HandshakeRecordKind.reply &&
              (preferredHandshakeIds == null ||
                  preferredHandshakeIds.contains(candidate.handshakeId)))
          .toList(growable: false);
      final pendingCandidates = preferredHandshakeIds == null && replies.isEmpty
          ? allPendingCandidates
          : replies;
      if (preferredHandshakeIds != null && pendingCandidates.isEmpty) {
        throw StateError('Pending device negotiation is no longer available');
      }
      // Spread concurrent device replies over ordinary user messages. The
      // durable pending list is stable; prior sends rotate the chosen record.
      // A pending responder reply takes precedence over this installation's
      // own offer, which is essential when the two peers initiated together.
      V3ApplicationHandshakeExport? pending = skipControl
          ? null
          : pendingCandidates.isEmpty
              ? await _pendingOrNewOffer(
                  remote: remote,
                  mode: V3HandshakeMode.normal,
                  eligibilityPolicy: eligibilityPolicy,
                )
              : pendingCandidates[prior.length % pendingCandidates.length];
      if (preferredHandshakeIds != null && !identityWideNormalFallback) {
        final opened = await V3HandshakeTransport.open(
          frames: pending!.frames,
          initiatorIdentity: remote,
          responderIdentity: local.publicIdentity,
        );
        try {
          recipientDeviceId = opened.decodeReply().initiatorDeviceId;
        } finally {
          opened.close();
        }
      }
      if (!skipControl && carrierMode != V3ChatCarrierMode.steganography) {
        // When both peers initiate at once, a pending reply can hide this
        // installation's completed initiator confirmation. The responder
        // cannot decrypt FS application data until that confirmation arrives.
        for (final session
            in await _runtime.sessionsForRemoteIdentity(remote)) {
          if (session.role != V3SessionRole.initiator ||
              !await _preFsPendingStore.isBootstrapHandshake(
                  contactDigestKey, session.handshakeId) ||
              await _preFsPendingStore.isPeerFsReady(
                  contactDigestKey, session.handshakeId)) {
            continue;
          }
          final confirmation = await _runtime.retryHandshake(
            handshakeId: session.handshakeId,
            remoteIdentity: remote,
          );
          if (confirmation?.kind != V3HandshakeRecordKind.confirmation ||
              !confirmation!.frames.any((frame) {
                final bytes = V3LmfFrameCodec.encodeBinary(frame);
                try {
                  return !previouslyBundled
                      .contains(_preFsFrameDigestKey(bytes));
                } finally {
                  _wipe(bytes);
                }
              })) {
            continue;
          }
          pending = confirmation;
          break;
        }
      }
      final controlFrames = pending?.frames ?? const <V3LmfFrame>[];
      Uint8List? controlBytes;
      Uint8List? controlTransferId;
      var controlFragmentIndex = 0;
      var controlFragmentCount = 0;
      var controlChunkBytes = 0;
      final bundledFrameBytes = <Uint8List>[];
      final bundledFrameLines = <String>[];
      if (controlFrames.isNotEmpty &&
          carrierMode != V3ChatCarrierMode.steganography) {
        // The carrier decoder already accepts a preFs envelope followed by
        // ordinary authenticated LMF frames on separate lines. Use that
        // existing wire format to move several handshake fragments with one
        // visible user message, without waiting for additional sends.
        final envelopeBytes = V3PreFsEnvelopeCodec.headerBytes +
            extraTargetHeaderBytes +
            V3PreFsEnvelopeCodec.authenticationTagBytes +
            dataOnlyLength;
        final tokenPrefixLength = carrierMode == V3ChatCarrierMode.text
            ? V3PreFsCarrierBudget.tokenPrefix.length
            : 'layergram://p/'.length;
        var remaining = maxCarrierCharacters -
            tokenPrefixLength -
            _unpaddedBase64Length(envelopeBytes);
        final frameBytes = <Uint8List>[];
        final frameLines = <String>[];
        final frameDigests = <String>[];
        for (final frame in controlFrames) {
          final bytes = V3LmfFrameCodec.encodeBinary(frame);
          frameBytes.add(bytes);
          frameDigests.add(_preFsFrameDigestKey(bytes));
          frameLines.add(carrierMode == V3ChatCarrierMode.text
              ? V3ApplicationTransport.encodeText(frame)
              : V3ApplicationTransport.encodeLink(frame));
        }
        final unsent = <int>[
          for (var index = 0; index < frameBytes.length; index++)
            if (!previouslyBundled.contains(frameDigests[index])) index,
        ];
        final frameDigestSet = frameDigests.toSet();
        final priorBundleCount = priorBundleDigests
            .where((entry) => entry.any(frameDigestSet.contains))
            .length;
        final start =
            frameBytes.isEmpty ? 0 : priorBundleCount % frameBytes.length;
        final candidateIndexes = unsent.isNotEmpty
            ? unsent
            : <int>[
                for (var offset = 0; offset < frameBytes.length; offset++)
                  (start + offset) % frameBytes.length,
              ];
        final selectedIndexes = <int>{};
        for (final index in candidateIndexes) {
          final line = frameLines[index];
          if (line.length + 1 > remaining ||
              bundledFrameLines.length >= V3LmfFrameCodec.maxFragments - 1) {
            continue;
          }
          bundledFrameBytes.add(frameBytes[index]);
          bundledFrameLines.add(line);
          selectedIndexes.add(index);
          remaining -= line.length + 1;
        }
        for (var index = 0; index < frameBytes.length; index++) {
          if (!selectedIndexes.contains(index)) _wipe(frameBytes[index]);
        }
      }
      if (controlFrames.isNotEmpty && bundledFrameLines.isEmpty) {
        final availableControlBytes = maxPlaintextPerFragment - dataOnlyLength;
        for (final frame in controlFrames) {
          if (availableControlBytes <= 0) break;
          final frameBytes = V3LmfFrameCodec.encodeBinary(frame);
          // Text and link carriers can usually carry a complete handshake
          // frame beside the user's message. Keep stego on the established
          // small fragments so its tested 4,000-character budget is unchanged.
          final wholeFrame = carrierMode != V3ChatCarrierMode.steganography &&
              frameBytes.length <= availableControlBytes;
          final proposedChunkBytes = wholeFrame
              ? frameBytes.length
              : min(_preFsControlChunkBytes, availableControlBytes);
          final digest = Uint8List.fromList(
            crypto.sha256
                .convert(wholeFrame
                    ? <int>[..._preFsWholeFrameTransferDomain, ...frameBytes]
                    : frameBytes)
                .bytes
                .take(16)
                .toList(),
          );
          final transferKey = _armored(digest);
          int? storedChunkBytes;
          for (final entry in prior) {
            final prefix = 'ctl:$transferKey:';
            if (!entry.contextId.startsWith(prefix)) continue;
            final suffix = entry.contextId.substring(prefix.length).split(':');
            final candidate = suffix.length == 2
                ? int.tryParse(suffix.first)
                : suffix.length == 1
                    ? _preFsControlChunkBytes
                    : null;
            if (candidate != null && candidate > 0) {
              storedChunkBytes = candidate;
              break;
            }
          }
          final chunkBytes = storedChunkBytes ?? proposedChunkBytes;
          if (chunkBytes > availableControlBytes) {
            _wipe(frameBytes);
            _wipe(digest);
            continue;
          }
          final count = (frameBytes.length + chunkBytes - 1) ~/ chunkBytes;
          if (count > V3PreFsEnvelopeCodec.maxFragmentCount) {
            _wipe(frameBytes);
            _wipe(digest);
            continue;
          }
          final sent = <int>{};
          for (final entry in prior) {
            final prefix = 'ctl:$transferKey:';
            if (!entry.contextId.startsWith(prefix)) continue;
            final suffix = entry.contextId.substring(prefix.length).split(':');
            final entryChunkBytes = suffix.length == 2
                ? int.tryParse(suffix.first)
                : suffix.length == 1
                    ? _preFsControlChunkBytes
                    : null;
            final index = int.tryParse(suffix.last);
            if (entryChunkBytes == chunkBytes && index != null) {
              sent.add(index);
            }
          }
          var next = -1;
          for (var index = 0; index < count; index++) {
            if (!sent.contains(index)) {
              next = index;
              break;
            }
          }
          if (next < 0) {
            _wipe(frameBytes);
            _wipe(digest);
            continue;
          }
          final start = next * chunkBytes;
          final end = (start + chunkBytes).clamp(0, frameBytes.length);
          controlBytes = Uint8List.fromList(frameBytes.sublist(start, end));
          controlTransferId = digest;
          controlFragmentIndex = next;
          controlFragmentCount = count;
          controlChunkBytes = chunkBytes;
          _wipe(frameBytes);
          break;
        }
      }
      var combined = _encodePreFsCombinedPayload(
        encodedPayload,
        controlBytes,
        controlTransferId: controlTransferId,
        controlFragmentIndex: controlFragmentIndex,
        controlFragmentCount: controlFragmentCount,
      );
      if (combined.length > maxPlaintextPerFragment && controlBytes != null) {
        _wipe(combined);
        _wipe(controlBytes);
        _wipe(controlTransferId!);
        controlBytes = null;
        controlTransferId = null;
        combined = _encodePreFsCombinedPayload(encodedPayload, null);
      }
      if (combined.length > maxPlaintextPerFragment) {
        _wipe(combined);
        throw const V3ChatPreFsCapacityException(
          'user text does not fit one preFs carrier',
        );
      }
      final envelope = await V3PreFsEnvelopeCodec.seal(
        localIdentity: local,
        remoteIdentity: remote,
        senderDeviceId: _runtime.localDeviceId,
        recipientDeviceId: recipientDeviceId,
        identityWideNormalFallback: identityWideNormalFallback,
        kind: V3PreFsEnvelopeKind.data,
        messageId: messageId,
        contextId: contextId,
        fragmentIndex: 0,
        fragmentCount: 1,
        controlFragmentCount: controlBytes == null ? 0 : 1,
        plaintext: combined,
        timestampUnixSeconds: timestamp,
        random: _preFsRandom,
      );
      final messageIdKey = _armored(messageId);
      final contextIdKey = controlTransferId == null
          ? _armored(contextId)
          : 'ctl:${_armored(controlTransferId)}:$controlChunkBytes:$controlFragmentIndex';
      final purpose = controlBytes == null && bundledFrameLines.isEmpty
          ? V3PreFsPendingPurpose.data
          : V3PreFsPendingPurpose.control;
      final entryId = '$messageIdKey:${purpose.wireName}:0';
      final encodedEnvelope = _encodePreFsEnvelope(
        envelope,
        carrierMode: carrierMode,
        coverText: coverText,
        maxTotalCharacters: maxCarrierCharacters,
      );
      final encodedCarrier = bundledFrameLines.isEmpty
          ? encodedEnvelope
          : '$encodedEnvelope\n${bundledFrameLines.join('\n')}';
      if (encodedCarrier.length > maxCarrierCharacters) {
        throw const V3ChatPreFsCapacityException(
          'preFs combined text exceeds the configured carrier limit',
        );
      }
      final entries = <V3PreFsPendingEntry>[
        V3PreFsPendingEntry(
          entryId: entryId,
          contactDigest: contactDigestKey,
          messageId: messageIdKey,
          contextId: contextIdKey,
          purpose: purpose,
          partIndex: 0,
          partCount: 1,
          carrierMode: carrierMode.name,
          envelopeBytes: envelope,
          bundledControlFrames: bundledFrameBytes,
          createdAtUnixSeconds: timestamp,
          exported: false,
        ),
      ];
      await _preFsPendingStore.record(entries);
      if (pending != null) {
        await _preFsPendingStore.markBootstrapHandshake(
          contactDigest: contactDigestKey,
          handshakeId: pending.handshakeId,
        );
      }
      if (persistOutgoing) {
        await _persistPreFsPayload(
          payload,
          senderId: localIdentityId,
          recipientId: contact.identityId,
          direction: 'outgoing',
        );
      }
      _wipe(combined);
      if (controlBytes != null) _wipe(controlBytes);
      if (controlTransferId != null) _wipe(controlTransferId);
      for (final bytes in bundledFrameBytes) {
        _wipe(bytes);
      }
      return V3ChatOutboundExport._(
        purpose: V3ChatOutboundPurpose.preFs,
        localIdentityId: localIdentityId,
        remoteIdentityId: contact.identityId,
        carrierMode: carrierMode,
        policyRevision: eligibilityPolicy?.revision ?? 0,
        parts: <String>[encodedCarrier],
        handshakeId: pending?.handshakeId,
        preFsMetadata: V3ChatPreFsOutboundMetadata(
          messageId: messageIdKey,
          contextId: contextIdKey,
          dataFragmentCount: 1,
          dataPartCount: 1,
          controlPartCount:
              (controlBytes == null ? 0 : 1) + bundledFrameLines.length,
          carrierMode: carrierMode,
          timestampUnixSeconds: timestamp,
        ),
        preFsParts: <_V3ChatPreFsPart?>[
          _V3ChatPreFsPart(entryId: entryId, purpose: purpose),
        ],
      );
    } finally {
      messageId.fillRange(0, messageId.length, 0);
      contextId.fillRange(0, contextId.length, 0);
      senderDigest?.fillRange(0, senderDigest.length, 0);
      recipientDigest?.fillRange(0, recipientDigest.length, 0);
      if (recipientDeviceId != null) _wipe(recipientDeviceId);
      encodedPayload?.fillRange(0, encodedPayload.length, 0);
    }
  }

  /// Next-stage bridge/UI seam for preFs presentation and retransmission.
  Future<V3ChatPreFsStatus> preFsStatusForContact(
    RemoteIdentity contact,
  ) async {
    final remote = V3IdentityAdapter.fromRemoteIdentity(contact);
    final digest = _armored(_identityDigest(remote));
    final entries = await _preFsPendingStore.pendingForContact(digest);
    var data = 0;
    var control = 0;
    var acknowledgement = 0;
    for (final entry in entries) {
      switch (entry.purpose) {
        case V3PreFsPendingPurpose.data:
          data++;
        case V3PreFsPendingPurpose.control:
          control++;
        case V3PreFsPendingPurpose.acknowledgement:
          acknowledgement++;
      }
    }
    return V3ChatPreFsStatus(
      hasPendingBootstrap: entries.isNotEmpty,
      pendingDataPartCount: data,
      pendingControlPartCount: control,
      pendingAcknowledgementPartCount: acknowledgement,
      requiresAcknowledgedRetransmission: data > 0,
    );
  }

  Future<void> markExported(
    V3ChatOutboundExport export, {
    int? partIndex,
  }) async {
    if (export.localIdentityId != localIdentityId) {
      throw StateError('Layergram v3 export belongs to another local context');
    }
    final currentPolicy = _runtime.protocolV3EligibilityForIdentityId(
      export.remoteIdentityId,
    );
    if (currentPolicy != null &&
        currentPolicy.revision != export.policyRevision) {
      throw StateError('Layergram v3 export policy was superseded');
    }
    if (export._preFsParts.isNotEmpty) {
      if (partIndex == null) {
        for (final part in export._preFsParts) {
          if (part != null) {
            await _preFsPendingStore.markExported(part.entryId);
          }
        }
      } else {
        if (partIndex < 0 || partIndex >= export.parts.length) {
          throw RangeError.index(partIndex, export.parts, 'partIndex');
        }
        final part = export._preFsParts[partIndex];
        if (part != null) {
          await _preFsPendingStore.markExported(part.entryId);
        }
      }
      if (export.purpose == V3ChatOutboundPurpose.preFs) return;
    }
    final message = export.messageExport;
    if (message == null) return;
    if (partIndex == null) {
      await _runtime.markMessageExported(message);
      return;
    }
    if (partIndex < 0 || partIndex >= export.parts.length) {
      throw RangeError.index(partIndex, export.parts, 'partIndex');
    }
    if (export.parts.length == 1 && message.frames.length > 1) {
      await _runtime.markMessageExported(message);
      return;
    }
    final part = export._applicationParts[partIndex];
    if (part == null) return;
    await _runtime.markMessagePartExported(
      message,
      assemblyId: part.assemblyId,
      fragmentIndex: part.fragmentIndex,
    );
  }

  /// Rehydrates exact durable setup, message, and ACK frames for one contact.
  /// Carrier encoding is deliberately reapplied from the sealed bytes, so a
  /// restart never requires regenerating handshake or ratchet cryptography.
  Future<List<V3ChatOutboundExport>> pendingExportsForContact({
    required RemoteIdentity contact,
    required V3ChatCarrierMode carrierMode,
    String coverText = '',
    Object? maxCarrierCharacters = V3LmfFrameCodec.portableShareCharacterLimit,
  }) async {
    final carrierLimit = _effectiveCarrierLimit(
      carrierMode,
      _normalizedCarrierLimit(maxCarrierCharacters),
    );
    final remote = V3IdentityAdapter.fromRemoteIdentity(contact);
    final mode = modeForContact(contact);
    final policy = eligibilityForContact(contact);
    if (policy?.isValid == false) {
      throw StateError('Layergram v3 contact policy requires recovery');
    }
    final exports = <V3ChatOutboundExport>[];

    final acknowledgementFrames = <V3LmfFrame>[];
    final remoteDigestBytes = _identityDigest(remote);
    try {
      final remoteDigest = _armored(remoteDigestBytes);
      for (final frame in await _runtime.pendingAcknowledgementFrames()) {
        final session = await _runtime.completedSessionForFrame(frame);
        if (session?.remoteIdentityDigest == remoteDigest &&
            !await _preFsPendingStore.isBootstrapHandshake(
              remoteDigest,
              session!.handshakeId,
            )) {
          acknowledgementFrames.add(frame);
        }
      }
    } finally {
      _wipe(remoteDigestBytes);
    }
    if (acknowledgementFrames.isNotEmpty) {
      exports.add(
        V3ChatOutboundExport._(
          purpose: V3ChatOutboundPurpose.acknowledgement,
          localIdentityId: localIdentityId,
          remoteIdentityId: contact.identityId,
          carrierMode: carrierMode,
          policyRevision: policy?.revision ?? 0,
          parts: _encodeFrames(
            acknowledgementFrames,
            carrierMode: carrierMode,
            coverText: coverText,
            maxTotalCharacters: carrierLimit,
          ),
          restored: true,
        ),
      );
    }

    final handshakes = await _runtime.pendingHandshakesForRemoteIdentity(
      remoteIdentity: remote,
      mode: mode,
      excludedHandshakeIds: policy?.excludedHandshakeIds ?? const <String>{},
    );
    for (final handshake in handshakes) {
      final handshakeIsBootstrap = mode == V3HandshakeMode.normal &&
          await _preFsPendingStore.isBootstrapHandshake(
            _armored(_identityDigest(remote)),
            handshake.handshakeId,
          );
      if (!handshakeIsBootstrap) {
        exports.add(
          _handshakeExport(
            handshake,
            remoteIdentityId: contact.identityId,
            policyRevision: policy?.revision ?? 0,
            carrierMode: carrierMode,
            coverText: coverText,
            maxCarrierCharacters: carrierLimit,
          ),
        );
      }
    }

    final preFsExports = await _preFsPendingExportsForContact(
      contact: contact,
      remote: remote,
      carrierMode: carrierMode,
      coverText: coverText,
      policyRevision: policy?.revision ?? 0,
      maxCarrierCharacters: carrierLimit,
    );
    exports.addAll(preFsExports);
    final preFsByMessageId = <String, V3ChatOutboundExport>{
      for (final export in preFsExports)
        if (export.preFsMetadata != null)
          export.preFsMetadata!.messageId: export,
    };

    final sessions = await _runtime.sessionsForRemoteIdentity(remote);
    final sessionIds = sessions.map((session) => session.sessionId).toSet();
    final sessionsById = <String, V3CompletedHandshakeSession>{
      for (final session in sessions) session.sessionId: session,
    };
    for (final message in await _runtime.pendingMessageExports()) {
      if (message.targets.isEmpty ||
          !message.targets.every(
            (target) => sessionIds.contains(target.sessionId),
          )) {
        continue;
      }
      final targetSessions = message.targets
          .map((target) => sessionsById[target.sessionId])
          .whereType<V3CompletedHandshakeSession>()
          .toList(growable: false);
      final supportsCombinedCarrier = !_restricted &&
          mode == V3HandshakeMode.normal &&
          targetSessions.length == message.targets.length &&
          targetSessions.isNotEmpty &&
          await Future.wait(
            targetSessions.map(
              (session) => _preFsPendingStore.isBootstrapHandshake(
                session.remoteIdentityDigest,
                session.handshakeId,
              ),
            ),
          ).then((values) => values.every((value) => value));
      final restoredParts = await _encodeApplicationWithOptionalAcks(
        message.frames,
        runtime: _runtime,
        preFsPendingStore: _preFsPendingStoreValue,
        remoteIdentityDigest: targetSessions.first.remoteIdentityDigest,
        allowCombinedCarrier: supportsCombinedCarrier,
        carrierMode: carrierMode,
        coverText: coverText,
        maxTotalCharacters: carrierLimit,
      );
      final singleRestoredPart = _singleApplicationCarrier(
        restoredParts,
        carrierMode: carrierMode,
        maxCarrierCharacters: carrierLimit,
      );
      final applicationExport = V3ChatOutboundExport._(
        purpose: V3ChatOutboundPurpose.application,
        localIdentityId: localIdentityId,
        remoteIdentityId: contact.identityId,
        carrierMode: carrierMode,
        policyRevision: policy?.revision ?? 0,
        parts: singleRestoredPart,
        messageExport: message,
        restored: true,
        applicationParts:
            singleRestoredPart.length == 1 && restoredParts.length > 1
                ? const <_V3ChatApplicationPart?>[null]
                : [
                    for (final target in message.targets)
                      for (final frame in target.frames)
                        _V3ChatApplicationPart(
                          assemblyId: target.assemblyId,
                          fragmentIndex: frame.fragmentIndex,
                        ),
                  ],
      );
      final preFs = message.alsoSentIdentityOnly
          ? preFsByMessageId[message.logicalMessageId]
          : null;
      if (preFs != null) {
        exports.remove(preFs);
        exports.add(_combineMixedDeviceExports(preFs, applicationExport));
      } else {
        exports.add(applicationExport);
      }
    }
    return List<V3ChatOutboundExport>.unmodifiable(exports);
  }

  /// Rehydrates exact durable preFs bootstrap parts for one contact.
  ///
  /// Only parts sealed for the requested carrier mode are returned byte for
  /// byte. Parts sealed for another mode stay pending untouched instead of
  /// being silently dropped or re-sealed.
  Future<List<V3ChatOutboundExport>> _preFsPendingExportsForContact({
    required RemoteIdentity contact,
    required V3PublicIdentity remote,
    required V3ChatCarrierMode carrierMode,
    required String coverText,
    required int policyRevision,
    required int maxCarrierCharacters,
  }) async {
    final contactDigest = _armored(_identityDigest(remote));
    final entries = await _preFsPendingStore.pendingForContact(contactDigest);
    if (entries.isEmpty) return const <V3ChatOutboundExport>[];
    final grouped = <String, List<V3PreFsPendingEntry>>{};
    var deferred = 0;
    for (final entry in entries) {
      if (entry.carrierMode != carrierMode.name) {
        deferred++;
        continue;
      }
      (grouped[entry.messageId] ??= <V3PreFsPendingEntry>[]).add(entry);
    }
    final exports = <V3ChatOutboundExport>[];
    for (final group in grouped.values) {
      group.sort((left, right) {
        final byPurpose = left.purpose.index.compareTo(right.purpose.index);
        if (byPurpose != 0) return byPurpose;
        return left.partIndex.compareTo(right.partIndex);
      });
      final parts = <String>[];
      final preFsParts = <_V3ChatPreFsPart?>[];
      for (final entry in group) {
        final encodedEnvelope = _encodePreFsEnvelope(
          entry.envelopeBytes,
          carrierMode: carrierMode,
          coverText: coverText,
          maxTotalCharacters: maxCarrierCharacters,
        );
        final bundledFrameBytes = entry.bundledControlFrames;
        try {
          final bundledLines = <String>[];
          for (final bytes in bundledFrameBytes) {
            final frame = V3LmfFrameCodec.decodeBinary(bytes);
            bundledLines.add(carrierMode == V3ChatCarrierMode.text
                ? V3ApplicationTransport.encodeText(frame)
                : V3ApplicationTransport.encodeLink(frame));
          }
          parts.add(bundledLines.isEmpty
              ? encodedEnvelope
              : '$encodedEnvelope\n${bundledLines.join('\n')}');
        } finally {
          for (final bytes in bundledFrameBytes) {
            _wipe(bytes);
          }
        }
        preFsParts.add(
          _V3ChatPreFsPart(entryId: entry.entryId, purpose: entry.purpose),
        );
      }
      final dataCount = group
          .where((entry) => entry.purpose == V3PreFsPendingPurpose.data)
          .length;
      exports.add(
        V3ChatOutboundExport._(
          purpose: V3ChatOutboundPurpose.preFs,
          localIdentityId: localIdentityId,
          remoteIdentityId: contact.identityId,
          carrierMode: carrierMode,
          policyRevision: policyRevision,
          parts: parts,
          restored: true,
          preFsMetadata: V3ChatPreFsOutboundMetadata(
            messageId: group.first.messageId,
            contextId: group.first.contextId,
            dataFragmentCount: dataCount,
            dataPartCount: dataCount,
            controlPartCount: group.fold<int>(
              0,
              (count, entry) =>
                  count +
                  (entry.bundledControlFrameCount > 0
                      ? entry.bundledControlFrameCount
                      : entry.purpose == V3PreFsPendingPurpose.control
                          ? 1
                          : 0),
            ),
            carrierMode: carrierMode,
            timestampUnixSeconds: group
                .map((entry) => entry.createdAtUnixSeconds)
                .reduce((left, right) => left < right ? left : right),
            deferredPartCount: deferred,
          ),
          preFsParts: preFsParts,
        ),
      );
    }
    return List<V3ChatOutboundExport>.unmodifiable(exports);
  }

  Future<V3ChatInboundResult> receiveCarrier({
    required String carrier,
    required Iterable<RemoteIdentity> contacts,
    required V3HandshakeModeResolver modeForContact,
    V3SessionEligibilityResolver? eligibilityForContact,
    V3SessionEligibilityEnsurer? ensureEligibilityForContact,
    V3MaximumDevicePinCommit? pinMaximumDevice,
    V3ChatCarrierMode? responseCarrierMode,
    String acknowledgementCoverText = '',
    DateTime? receivedAt,
    int? nowUnixSeconds,
  }) async {
    final decodedCarrier = _decodeCarrier(carrier);
    final effectiveResponseMode = responseCarrierMode ?? decodedCarrier.mode;
    final effectiveAcknowledgementCover = acknowledgementCoverText.isNotEmpty
        ? acknowledgementCoverText
        : decodedCarrier.visibleCoverText ?? '';
    final v3Contacts = <({RemoteIdentity model, V3PublicIdentity public})>[];
    for (final contact in contacts) {
      if (contact.protocolVersion != V3PublicIdentityCodec.protocolVersion) {
        continue;
      }
      try {
        v3Contacts.add(
          (
            model: contact,
            public: V3IdentityAdapter.fromRemoteIdentity(contact)
          ),
        );
      } on FormatException {
        continue;
      }
    }
    final frames = decodedCarrier.frames;
    final producedResponses = <V3ChatOutboundExport>[];
    V3ChatInboundResult? selected;
    var shouldReconcile = false;

    for (final encoded in decodedCarrier.preFsEnvelopes) {
      final result = await _receivePreFsEnvelope(
        encoded: encoded,
        companionFrames: decodedCarrier.preFsEnvelopes.length == 1
            ? frames
            : const <V3LmfFrame>[],
        contacts: v3Contacts,
        modeForContact: modeForContact,
        eligibilityForContact: eligibilityForContact,
        ensureEligibilityForContact: ensureEligibilityForContact,
        pinMaximumDevice: pinMaximumDevice,
        responseCarrierMode: effectiveResponseMode,
        acknowledgementCoverText: effectiveAcknowledgementCover,
        receivedAt: receivedAt,
        nowUnixSeconds: nowUnixSeconds,
      );
      producedResponses.addAll(result.responses);
      selected = _preferInboundResult(selected, result);
    }

    // A carrier may place an application frame before the final handshake
    // confirmation so the visible user message stays first on the wire. The
    // responder does not have that session until it accepts the confirmation.
    // Apply authenticated handshake frames first, then process application and
    // ACK frames in their original order; otherwise the application is skipped
    // as addressed to an unknown session and only the control is reported.
    for (final frame in [
      ...frames
          .where((frame) => frame.metadata.kind == V3LmfFrameKind.handshake),
      ...frames
          .where((frame) => frame.metadata.kind != V3LmfFrameKind.handshake),
    ]) {
      if (frame.metadata.kind == V3LmfFrameKind.handshake) {
        if (_restricted) {
          // A restricted runtime has no private identity or device key and
          // never routes bootstrap frames into the handshake controller.
          final contact = _contactForInboundFrame(frame, v3Contacts);
          selected = _preferInboundResult(
            selected,
            contact == null
                ? V3ChatInboundResult(
                    status: V3ChatInboundStatus.notForThisInstallation,
                  )
                : V3ChatInboundResult(
                    status: V3ChatInboundStatus.invalid,
                    contact: contact.model,
                  ),
          );
          continue;
        }
        final contact = _contactForInboundFrame(frame, v3Contacts);
        if (contact == null) {
          selected = _preferInboundResult(
            selected,
            V3ChatInboundResult(
              status: V3ChatInboundStatus.notForThisInstallation,
            ),
          );
          continue;
        }
        var eligibility = eligibilityForContact?.call(contact.model);
        final selectedMode = modeForContact(contact.model);
        if (eligibility == null && ensureEligibilityForContact != null) {
          // The ensurer owns the runtime's atomic policy-initialization
          // boundary. Wrapping it in initializeContactPolicy again would
          // enqueue a serialized runtime operation from inside the same
          // operation and deadlock the first inbound handshake.
          eligibility = await ensureEligibilityForContact(
            contact.model,
            selectedMode,
          );
        }
        if (eligibility?.isValid == false) {
          selected = _preferInboundResult(
            selected,
            V3ChatInboundResult(
              status: V3ChatInboundStatus.invalid,
              contact: contact.model,
            ),
          );
          continue;
        }
        late final V3ApplicationHandshakeInboundResult inbound;
        try {
          inbound = await _runtime.receiveHandshakeFrame(
            frame: frame,
            remoteIdentity: contact.public,
            expectedMode: selectedMode,
            excludedHandshakeIds:
                eligibility?.excludedHandshakeIds ?? const <String>{},
            maximumRemoteDeviceId: eligibility?.maximumRemoteDeviceId,
            maximumRemoteDeviceIdResolver: () => eligibilityForContact
                ?.call(contact.model)
                ?.maximumRemoteDeviceId,
            onSessionEstablished: selectedMode == V3HandshakeMode.maximum &&
                    pinMaximumDevice != null
                ? (session) => pinMaximumDevice(
                      contact.model,
                      session.remoteDeviceId,
                    )
                : null,
            receivedAt: receivedAt,
          );
        } on V3HandshakeAddressedElsewhereException {
          _diagnoseHandshake(V3ChatHandshakeDiagnostic.addressedElsewhere);
          selected = _preferInboundResult(
            selected,
            V3ChatInboundResult(
              status: V3ChatInboundStatus.notForThisInstallation,
            ),
          );
          continue;
        } on FormatException catch (error) {
          _diagnoseHandshake(switch (error.message) {
            'Layergram v3 initiator proof verification failed' =>
              V3ChatHandshakeDiagnostic.initiatorProofRejected,
            'Layergram v3 responder proof verification failed' =>
              V3ChatHandshakeDiagnostic.responderProofRejected,
            'Layergram v3 reply transcript binding mismatch' =>
              V3ChatHandshakeDiagnostic.transcriptMismatch,
            'Layergram v3 responder ratchet key mismatch' =>
              V3ChatHandshakeDiagnostic.deviceMismatch,
            'Layergram v3 handshake was reset' =>
              V3ChatHandshakeDiagnostic.resetRejected,
            _ => V3ChatHandshakeDiagnostic.malformed,
          });
          if (decodedCarrier.preFsEnvelopes.isEmpty ||
              selected?.status != V3ChatInboundStatus.delivered) {
            rethrow;
          }
          // The independently authenticated user text has already been
          // committed. A broken appended handshake line must not hide it.
          continue;
        }
        final response = inbound.outbound == null
            ? null
            : _handshakeExport(
                inbound.outbound!,
                remoteIdentityId: contact.model.identityId,
                // Completing a Maximum-mode reply pins the peer device inside
                // receiveHandshakeFrame. That durable pin advances the policy
                // revision before the confirmation becomes exportable, so bind
                // the export to the post-transition policy rather than the
                // snapshot taken before processing the frame.
                policyRevision:
                    eligibilityForContact?.call(contact.model)?.revision ??
                        eligibility?.revision ??
                        0,
                carrierMode: effectiveResponseMode,
                coverText: effectiveAcknowledgementCover,
              );
        _diagnoseHandshake(response != null
            ? V3ChatHandshakeDiagnostic.responsePrepared
            : inbound.session != null
                ? V3ChatHandshakeDiagnostic.sessionEstablished
                : switch (inbound.status) {
                    V3HandshakeFrameInboxStatus.accepted =>
                      V3ChatHandshakeDiagnostic.fragmentAccepted,
                    V3HandshakeFrameInboxStatus.duplicate =>
                      V3ChatHandshakeDiagnostic.fragmentDuplicate,
                    V3HandshakeFrameInboxStatus.committedReplay =>
                      V3ChatHandshakeDiagnostic.committedReplay,
                    V3HandshakeFrameInboxStatus.complete =>
                      V3ChatHandshakeDiagnostic.malformed,
                  });
        if (response != null) producedResponses.add(response);
        selected = _preferInboundResult(
          selected,
          V3ChatInboundResult(
            status: response != null
                ? V3ChatInboundStatus.handshakeResponse
                : inbound.session != null
                    ? V3ChatInboundStatus.sessionEstablished
                    : V3ChatInboundStatus.handshakeProgress,
            contact: contact.model,
          ),
        );
        continue;
      }

      final session = await _runtime.completedSessionForFrame(frame);
      final routedContact = session == null
          ? null
          : _contactForSession(session.remoteIdentityDigest, v3Contacts);
      if (routedContact == null) {
        selected = _preferInboundResult(
          selected,
          V3ChatInboundResult(
            status: V3ChatInboundStatus.notForThisInstallation,
          ),
        );
        continue;
      }
      final eligibility = eligibilityForContact?.call(routedContact.model);
      if ((eligibilityForContact != null && eligibility == null) ||
          eligibility?.isValid == false) {
        selected = _preferInboundResult(
          selected,
          V3ChatInboundResult(
            status: V3ChatInboundStatus.invalid,
            contact: routedContact.model,
          ),
        );
        continue;
      }
      late final V3ApplicationMessageInboundResult inbound;
      try {
        inbound = await _runtime.receiveApplicationFrame(
          frame: frame,
          receivedAt: receivedAt,
          nowUnixSeconds: nowUnixSeconds,
          expectedMode: modeForContact(routedContact.model),
          excludedHandshakeIds: eligibility?.excludedHandshakeIds,
          maximumRemoteDeviceId: eligibility?.maximumRemoteDeviceId,
          maximumRemoteDeviceIdResolver: () => eligibilityForContact
              ?.call(routedContact.model)
              ?.maximumRemoteDeviceId,
        );
      } on FormatException {
        if (frame.metadata.kind != V3LmfFrameKind.acknowledgement ||
            (!decodedCarrier.isCombined && decodedCarrier.frames.length < 2)) {
          rethrow;
        }
        // An appended ACK may legitimately outlive the already collected
        // sender outbox record. It is transport-only and cannot invalidate or
        // hide the preceding application result in the same authenticated
        // bundle; malformed/unmatched ACKs are simply not applied. This also
        // applies to the keyboard's single newline-separated text insertion.
        continue;
      }
      if (!_restricted &&
          (inbound.status == V3ApplicationInboundStatus.delivered ||
              inbound.status == V3ApplicationInboundStatus.committedReplay)) {
        await _preFsPendingStore.markPeerFsReady(
          contactDigest: session!.remoteIdentityDigest,
          handshakeId: session.handshakeId,
          preFsFenceUnixSeconds: inbound.payload?.timestampUnixSeconds ??
              nowUnixSeconds ??
              _nowUnixSeconds(),
        );
      }
      final contact = inbound.payload == null
          ? routedContact.model
          : _contactForPayload(inbound.payload!, v3Contacts);
      final supportsCombinedCarrier = !_restricted &&
          session != null &&
          await _preFsPendingStore.isBootstrapHandshake(
            session.remoteIdentityDigest,
            session.handshakeId,
          );
      final response =
          inbound.acknowledgementFrame == null || supportsCombinedCarrier
              ? null
              : V3ChatOutboundExport._(
                  purpose: V3ChatOutboundPurpose.acknowledgement,
                  localIdentityId: localIdentityId,
                  remoteIdentityId: routedContact.model.identityId,
                  carrierMode: effectiveResponseMode,
                  policyRevision: eligibility?.revision ?? 0,
                  parts: _encodeFrames(
                    [inbound.acknowledgementFrame!],
                    carrierMode: effectiveResponseMode,
                    coverText: effectiveAcknowledgementCover,
                  ),
                );
      if (response != null) producedResponses.add(response);
      final status = switch (inbound.status) {
        V3ApplicationInboundStatus.pending => V3ChatInboundStatus.pending,
        V3ApplicationInboundStatus.delivered => V3ChatInboundStatus.delivered,
        V3ApplicationInboundStatus.expired => V3ChatInboundStatus.expired,
        V3ApplicationInboundStatus.committedReplay =>
          V3ChatInboundStatus.committedReplay,
        V3ApplicationInboundStatus.acknowledgementApplied =>
          V3ChatInboundStatus.acknowledgementApplied,
        V3ApplicationInboundStatus.notForThisInstallation =>
          V3ChatInboundStatus.notForThisInstallation,
        V3ApplicationInboundStatus.invalidPayload ||
        V3ApplicationInboundStatus.identityMismatch =>
          V3ChatInboundStatus.invalid,
      };
      if (status == V3ChatInboundStatus.delivered ||
          status == V3ChatInboundStatus.committedReplay) {
        shouldReconcile = true;
      }
      final candidate = V3ChatInboundResult(
        status: status,
        contact: contact,
        payload: inbound.payload,
      );
      // L3B always places the user application first. Its result is the
      // carrier's user-visible outcome; appended transport ACKs must not hide
      // a pending/invalid application result merely because ACK priority is
      // higher in legacy single-frame response handling.
      if (!(decodedCarrier.isCombined &&
          frame.metadata.kind == V3LmfFrameKind.acknowledgement &&
          selected != null)) {
        selected = _preferInboundResult(selected, candidate);
      }
    }

    if (shouldReconcile && _messagesRepository != null) {
      await _runtime.reconcileMessageRepository(
        messagesRepository: _requireMessagesRepository(),
        keyTag: _keyTag,
        repositoryContextLease: _repositoryContextLease,
        nowUnixSeconds: nowUnixSeconds,
      );
    }
    final preferred =
        selected ?? V3ChatInboundResult(status: V3ChatInboundStatus.invalid);
    return V3ChatInboundResult(
      status: preferred.status,
      contact: preferred.contact,
      payload: preferred.payload,
      preFs: preferred.preFs,
      responses: producedResponses,
    );
  }

  Future<V3ChatInboundResult> _receivePreFsEnvelope({
    required Uint8List encoded,
    required List<V3LmfFrame> companionFrames,
    required List<({RemoteIdentity model, V3PublicIdentity public})> contacts,
    required V3HandshakeModeResolver modeForContact,
    required V3SessionEligibilityResolver? eligibilityForContact,
    required V3SessionEligibilityEnsurer? ensureEligibilityForContact,
    required V3MaximumDevicePinCommit? pinMaximumDevice,
    required V3ChatCarrierMode responseCarrierMode,
    required String acknowledgementCoverText,
    required DateTime? receivedAt,
    required int? nowUnixSeconds,
  }) async {
    late final Uint8List senderDigest;
    try {
      senderDigest = V3PreFsEnvelopeCodec.peekSenderIdentityDigest(encoded);
    } on FormatException {
      return V3ChatInboundResult(status: V3ChatInboundStatus.invalid);
    }
    ({RemoteIdentity model, V3PublicIdentity public})? contact;
    try {
      for (final candidate in contacts) {
        final digest = _identityDigest(candidate.public);
        try {
          if (_bytesEqual(digest, senderDigest)) {
            contact = candidate;
            break;
          }
        } finally {
          _wipe(digest);
        }
      }
    } finally {
      _wipe(senderDigest);
    }
    if (contact == null) {
      return V3ChatInboundResult(
        status: V3ChatInboundStatus.notForThisInstallation,
      );
    }

    late final V3PreFsEnvelope envelope;
    try {
      envelope = await V3PreFsEnvelopeCodec.open(
        localIdentity: _runtime.localIdentity,
        remoteIdentity: contact.public,
        encoded: encoded,
      );
    } on FormatException {
      return V3ChatInboundResult(
        status: V3ChatInboundStatus.invalid,
        contact: contact.model,
      );
    }

    final recipientDeviceId = envelope.recipientDeviceId;
    if (recipientDeviceId != null) {
      final localDeviceId = _runtime.localDeviceId;
      try {
        if (!_bytesEqual(recipientDeviceId, localDeviceId)) {
          return V3ChatInboundResult(
            status: V3ChatInboundStatus.notForThisInstallation,
            contact: contact.model,
          );
        }
      } finally {
        _wipe(recipientDeviceId);
        _wipe(localDeviceId);
      }
    }

    // Maximum never accepts identity-only application data, including data
    // from a newly restored installation of the same long-term identity.
    if (modeForContact(contact.model) == V3HandshakeMode.maximum) {
      return V3ChatInboundResult(
        status: V3ChatInboundStatus.invalid,
        contact: contact.model,
      );
    }

    final contactDigest = _armored(
      V3PreFsEnvelopeCodec.identityDigest(contact.public),
    );
    final messageIdKey = _armored(envelope.messageId);
    final contextIdKey = _armored(envelope.contextId);
    final now = nowUnixSeconds ?? _nowUnixSeconds();
    final sessions = await _runtime.sessionsForRemoteIdentity(contact.public);
    final senderDeviceId = envelope.senderDeviceId;
    final senderDeviceKey = senderDeviceId == null
        ? await _legacyCompanionOfferDeviceId(
            contact: contact.public,
            frames: companionFrames,
          )
        : _armored(senderDeviceId);
    if (senderDeviceId != null) _wipe(senderDeviceId);
    for (final session in sessions) {
      if (session.mode != V3HandshakeMode.normal) continue;
      // A peer's completed FS session fences only that installation. A second
      // installation can restore the same long-term identity but has its own
      // device key and must be allowed to send its first readable message.
      // Legacy v1 envelopes lack a device ID. A complete companion offer can
      // identify a new installation; otherwise retain the conservative
      // identity-wide fence for ambiguous in-flight messages.
      if (senderDeviceKey != null &&
          session.remoteDeviceId != senderDeviceKey) {
        continue;
      }
      final fence = await _preFsPendingStore.preFsFenceFor(
        contactDigest,
        session.handshakeId,
      );
      if (fence != null &&
          envelope.timestampUnixSeconds > fence &&
          !envelope.identityWideNormalFallback) {
        return V3ChatInboundResult(
          status: V3ChatInboundStatus.invalid,
          contact: contact.model,
        );
      }
    }

    switch (envelope.kind) {
      case V3PreFsEnvelopeKind.data:
        return _receivePreFsData(
          envelope: envelope,
          contact: contact,
          contactDigest: contactDigest,
          messageIdKey: messageIdKey,
          contextIdKey: contextIdKey,
          responseCarrierMode: responseCarrierMode,
          acknowledgementCoverText: acknowledgementCoverText,
          modeForContact: modeForContact,
          eligibilityForContact: eligibilityForContact,
          ensureEligibilityForContact: ensureEligibilityForContact,
          pinMaximumDevice: pinMaximumDevice,
          receivedAt: receivedAt,
          nowUnixSeconds: now,
        );
      case V3PreFsEnvelopeKind.control:
        return _receivePreFsControl(
          envelope: envelope,
          contact: contact,
          contactDigest: contactDigest,
          messageIdKey: messageIdKey,
          contextIdKey: contextIdKey,
          modeForContact: modeForContact,
          eligibilityForContact: eligibilityForContact,
          ensureEligibilityForContact: ensureEligibilityForContact,
          pinMaximumDevice: pinMaximumDevice,
          responseCarrierMode: responseCarrierMode,
          acknowledgementCoverText: acknowledgementCoverText,
          receivedAt: receivedAt,
          nowUnixSeconds: now,
        );
      case V3PreFsEnvelopeKind.acknowledgement:
        final plaintext = envelope.plaintext;
        try {
          if (plaintext.length != 32) {
            return V3ChatInboundResult(
              status: V3ChatInboundStatus.invalid,
              contact: contact.model,
            );
          }
          final acknowledged = Uint8List.fromList(
            plaintext.sublist(0, V3PreFsEnvelopeCodec.messageIdBytes),
          );
          try {
            await _preFsPendingStore.acknowledgeData(
              contactDigest,
              _armored(acknowledged),
            );
          } finally {
            _wipe(acknowledged);
          }
        } finally {
          _wipe(plaintext);
        }
        return V3ChatInboundResult(
          status: V3ChatInboundStatus.acknowledgementApplied,
          contact: contact.model,
        );
    }
  }

  Future<String?> _legacyCompanionOfferDeviceId({
    required V3PublicIdentity contact,
    required List<V3LmfFrame> frames,
  }) async {
    if (frames.isEmpty ||
        frames.any((frame) =>
            frame.metadata.kind != V3LmfFrameKind.handshake ||
            frame.metadata.messageCounter != 0)) {
      return null;
    }
    try {
      final record = await V3HandshakeTransport.open(
        frames: frames,
        initiatorIdentity: contact,
        responderIdentity: _runtime.localIdentity.publicIdentity,
      );
      if (record.kind != V3HandshakeRecordKind.offer) return null;
      final offer = record.decodeOffer();
      if (offer.mode != V3HandshakeMode.normal) return null;
      final deviceId = offer.initiatorDeviceId;
      try {
        return _armored(deviceId);
      } finally {
        _wipe(deviceId);
      }
    } on FormatException {
      return null;
    }
  }

  Future<V3ChatInboundResult> _receivePreFsData({
    required V3PreFsEnvelope envelope,
    required ({RemoteIdentity model, V3PublicIdentity public}) contact,
    required String contactDigest,
    required String messageIdKey,
    required String contextIdKey,
    required V3ChatCarrierMode responseCarrierMode,
    required String acknowledgementCoverText,
    required V3HandshakeModeResolver modeForContact,
    required V3SessionEligibilityResolver? eligibilityForContact,
    required V3SessionEligibilityEnsurer? ensureEligibilityForContact,
    required V3MaximumDevicePinCommit? pinMaximumDevice,
    required DateTime? receivedAt,
    required int nowUnixSeconds,
  }) async {
    var initialEligibility = eligibilityForContact?.call(contact.model);
    final producedResponses = <V3ChatOutboundExport>[];
    if (initialEligibility == null && ensureEligibilityForContact != null) {
      initialEligibility = await ensureEligibilityForContact(
        contact.model,
        modeForContact(contact.model),
      );
    }
    if (initialEligibility?.isValid == false) {
      return V3ChatInboundResult(
        status: V3ChatInboundStatus.invalid,
        contact: contact.model,
      );
    }
    if (await _preFsPendingStore.hasReplayKeyFor(
      contactDigest,
      messageIdKey,
    )) {
      final assembly = await _preFsPendingStore.inboundAssembly(
        contactDigest,
        messageIdKey,
      );
      return V3ChatInboundResult(
        status: V3ChatInboundStatus.committedReplay,
        contact: contact.model,
        preFs: _preFsMetadata(
          envelope: envelope,
          receivedDataFragments: assembly?.receivedDataFragments ?? 0,
          dataFragmentCount: envelope.fragmentCount,
          receivedControlFragments: assembly?.controlFragments.length ?? 0,
          controlFragmentCount: assembly?.controlFragmentCount ?? 0,
          acknowledgementEmitted: false,
        ),
      );
    }
    final plaintext = envelope.plaintext;
    Uint8List? assembled;
    try {
      final acceptance = await _preFsPendingStore.acceptDataFragment(
        contactDigest: contactDigest,
        messageId: messageIdKey,
        contextId: contextIdKey,
        fragmentIndex: envelope.fragmentIndex,
        fragmentCount: envelope.fragmentCount,
        plaintext: plaintext,
        nowUnixSeconds: nowUnixSeconds,
      );
      final assembly = await _preFsPendingStore.inboundAssembly(
        contactDigest,
        messageIdKey,
      );
      final metadata = _preFsMetadata(
        envelope: envelope,
        receivedDataFragments: assembly?.receivedDataFragments ?? 0,
        dataFragmentCount: envelope.fragmentCount,
        receivedControlFragments: assembly?.controlFragments.length ?? 0,
        controlFragmentCount: assembly?.controlFragmentCount ?? 0,
        acknowledgementEmitted: false,
      );
      if (!acceptance.dataComplete) {
        return V3ChatInboundResult(
          status: V3ChatInboundStatus.pending,
          contact: contact.model,
          preFs: metadata,
        );
      }
      assembled = assembly?.assembleData();
      if (assembled == null) {
        return V3ChatInboundResult(
          status: V3ChatInboundStatus.pending,
          contact: contact.model,
          preFs: metadata,
        );
      }
      late final _V3PreFsCombinedPayload combined;
      try {
        combined = _decodePreFsCombinedPayload(assembled);
      } on FormatException {
        return V3ChatInboundResult(
          status: V3ChatInboundStatus.invalid,
          contact: contact.model,
          preFs: metadata,
        );
      }
      late final V3ApplicationPayload payload;
      try {
        payload = V3ApplicationPayloadCodec.decode(combined.applicationPayload);
      } on FormatException {
        return V3ChatInboundResult(
          status: V3ChatInboundStatus.invalid,
          contact: contact.model,
          preFs: metadata,
        );
      }
      final payloadSender = payload.senderIdentityDigest;
      final payloadRecipient = payload.recipientIdentityDigest;
      try {
        if (!_bytesEqual(payloadSender, envelope.senderIdentityDigest) ||
            !_bytesEqual(payloadRecipient, envelope.recipientIdentityDigest)) {
          return V3ChatInboundResult(
            status: V3ChatInboundStatus.invalid,
            contact: contact.model,
            preFs: metadata,
          );
        }
      } finally {
        _wipe(payloadSender);
        _wipe(payloadRecipient);
      }
      await _persistPreFsPayload(
        payload,
        senderId: contact.model.identityId,
        recipientId: localIdentityId,
        direction: 'incoming',
      );
      await _preFsPendingStore.noteInboundData(contactDigest, messageIdKey);
      await _preFsPendingStore.completeInboundAssembly(
        contactDigest,
        messageIdKey,
      );
      if (combined.controlFrame != null) {
        try {
          final transferId = _armored(combined.controlTransferId!);
          final transferMessageId = 'ctl:$transferId';
          final accepted = await _preFsPendingStore.acceptDataFragment(
            contactDigest: contactDigest,
            messageId: transferMessageId,
            contextId: contextIdKey,
            fragmentIndex: combined.controlFragmentIndex,
            fragmentCount: combined.controlFragmentCount,
            plaintext: combined.controlFrame!,
            nowUnixSeconds: nowUnixSeconds,
          );
          if (!accepted.dataComplete) {
            throw const _V3PreFsControlPending();
          }
          final controlAssembly = await _preFsPendingStore.inboundAssembly(
            contactDigest,
            transferMessageId,
          );
          final frameBytes = controlAssembly?.assembleData();
          if (frameBytes == null) throw const _V3PreFsControlPending();
          final frame = V3LmfFrameCodec.decodeBinary(frameBytes);
          var eligibility = eligibilityForContact?.call(contact.model);
          final selectedMode = modeForContact(contact.model);
          if (eligibility == null && ensureEligibilityForContact != null) {
            eligibility = await ensureEligibilityForContact(
              contact.model,
              selectedMode,
            );
          }
          if (eligibility?.isValid != false) {
            final handshake = await _runtime.receiveHandshakeFrame(
              frame: frame,
              remoteIdentity: contact.public,
              expectedMode: selectedMode,
              excludedHandshakeIds:
                  eligibility?.excludedHandshakeIds ?? const <String>{},
              maximumRemoteDeviceId: eligibility?.maximumRemoteDeviceId,
              maximumRemoteDeviceIdResolver: () => eligibilityForContact
                  ?.call(contact.model)
                  ?.maximumRemoteDeviceId,
              onSessionEstablished: selectedMode == V3HandshakeMode.maximum &&
                      pinMaximumDevice != null
                  ? (session) => pinMaximumDevice(
                        contact.model,
                        session.remoteDeviceId,
                      )
                  : null,
              receivedAt: receivedAt,
            );
            if (handshake.outbound != null) {
              producedResponses.add(_handshakeExport(
                handshake.outbound!,
                remoteIdentityId: contact.model.identityId,
                policyRevision:
                    eligibilityForContact?.call(contact.model)?.revision ??
                        eligibility?.revision ??
                        0,
                carrierMode: responseCarrierMode,
                coverText: acknowledgementCoverText,
              ));
            }
            await _preFsPendingStore.completeInboundAssembly(
              contactDigest,
              transferMessageId,
            );
          }
        } on _V3PreFsControlPending {
          // The authenticated control stream is incomplete; user data was
          // already delivered and the next ordinary message continues it.
        } on FormatException {
          // User data remains valid and independently deliverable. Malformed
          // piggyback control never invalidates authenticated application data.
        }
      }
      return V3ChatInboundResult(
        status: V3ChatInboundStatus.delivered,
        contact: contact.model,
        payload: payload,
        responses: producedResponses,
        preFs: _preFsMetadata(
          envelope: envelope,
          receivedDataFragments: envelope.fragmentCount,
          dataFragmentCount: envelope.fragmentCount,
          receivedControlFragments: metadata.receivedControlFragments,
          controlFragmentCount: metadata.controlFragmentCount,
          acknowledgementEmitted: false,
        ),
      );
    } finally {
      _wipe(plaintext);
      if (assembled != null) _wipe(assembled);
    }
  }

  Future<V3ChatInboundResult> _receivePreFsControl({
    required V3PreFsEnvelope envelope,
    required ({RemoteIdentity model, V3PublicIdentity public}) contact,
    required String contactDigest,
    required String messageIdKey,
    required String contextIdKey,
    required V3HandshakeModeResolver modeForContact,
    required V3SessionEligibilityResolver? eligibilityForContact,
    required V3SessionEligibilityEnsurer? ensureEligibilityForContact,
    required V3MaximumDevicePinCommit? pinMaximumDevice,
    required V3ChatCarrierMode responseCarrierMode,
    required String acknowledgementCoverText,
    required DateTime? receivedAt,
    required int nowUnixSeconds,
  }) async {
    var eligibility = eligibilityForContact?.call(contact.model);
    final selectedMode = modeForContact(contact.model);
    if (eligibility == null && ensureEligibilityForContact != null) {
      eligibility = await ensureEligibilityForContact(
        contact.model,
        selectedMode,
      );
    }
    if (eligibility?.isValid == false) {
      return V3ChatInboundResult(
        status: V3ChatInboundStatus.invalid,
        contact: contact.model,
      );
    }
    final plaintext = envelope.plaintext;
    late final V3LmfFrame frame;
    try {
      frame = V3LmfFrameCodec.decodeBinary(plaintext);
    } on FormatException {
      return V3ChatInboundResult(
        status: V3ChatInboundStatus.invalid,
        contact: contact.model,
      );
    } finally {
      _wipe(plaintext);
    }
    final acceptance = await _preFsPendingStore.acceptControlFragment(
      contactDigest: contactDigest,
      messageId: messageIdKey,
      contextId: contextIdKey,
      controlFragmentIndex: envelope.fragmentIndex,
      controlFragmentCount: envelope.controlFragmentCount,
      nowUnixSeconds: nowUnixSeconds,
    );
    final assembly = await _preFsPendingStore.inboundAssembly(
      contactDigest,
      messageIdKey,
    );
    final metadata = _preFsMetadata(
      envelope: envelope,
      receivedDataFragments: assembly?.receivedDataFragments ?? 0,
      dataFragmentCount: assembly?.dataFragmentCount ?? 0,
      receivedControlFragments: assembly?.controlFragments.length ?? 0,
      controlFragmentCount: assembly?.controlFragmentCount ?? 0,
      acknowledgementEmitted: false,
    );
    if (acceptance.duplicate) {
      return V3ChatInboundResult(
        status: V3ChatInboundStatus.handshakeProgress,
        contact: contact.model,
        preFs: metadata,
      );
    }
    final inbound = await _runtime.receiveHandshakeFrame(
      frame: frame,
      remoteIdentity: contact.public,
      expectedMode: selectedMode,
      excludedHandshakeIds:
          eligibility?.excludedHandshakeIds ?? const <String>{},
      maximumRemoteDeviceId: eligibility?.maximumRemoteDeviceId,
      maximumRemoteDeviceIdResolver: () =>
          eligibilityForContact?.call(contact.model)?.maximumRemoteDeviceId,
      onSessionEstablished:
          selectedMode == V3HandshakeMode.maximum && pinMaximumDevice != null
              ? (session) => pinMaximumDevice(
                    contact.model,
                    session.remoteDeviceId,
                  )
              : null,
      receivedAt: receivedAt,
    );
    final response = inbound.outbound == null
        ? null
        : _handshakeExport(
            inbound.outbound!,
            remoteIdentityId: contact.model.identityId,
            policyRevision:
                eligibilityForContact?.call(contact.model)?.revision ??
                    eligibility?.revision ??
                    0,
            carrierMode: responseCarrierMode,
            coverText: acknowledgementCoverText,
          );
    return V3ChatInboundResult(
      status: response != null
          ? V3ChatInboundStatus.handshakeResponse
          : inbound.session != null
              ? V3ChatInboundStatus.sessionEstablished
              : V3ChatInboundStatus.handshakeProgress,
      contact: contact.model,
      preFs: metadata,
      response: response,
    );
  }

  V3ChatPreFsInboundMetadata _preFsMetadata({
    required V3PreFsEnvelope envelope,
    required int receivedDataFragments,
    required int dataFragmentCount,
    required int receivedControlFragments,
    required int controlFragmentCount,
    required bool acknowledgementEmitted,
  }) {
    final messageId = envelope.messageId;
    final contextId = envelope.contextId;
    try {
      return V3ChatPreFsInboundMetadata(
        messageId: _armored(messageId),
        contextId: _armored(contextId),
        receivedDataFragments: receivedDataFragments,
        dataFragmentCount: dataFragmentCount,
        receivedControlFragments: receivedControlFragments,
        controlFragmentCount: controlFragmentCount,
        dataComplete:
            dataFragmentCount > 0 && receivedDataFragments >= dataFragmentCount,
        controlComplete: controlFragmentCount > 0 &&
            receivedControlFragments >= controlFragmentCount,
        acknowledgementEmitted: acknowledgementEmitted,
      );
    } finally {
      _wipe(messageId);
      _wipe(contextId);
    }
  }

  Future<String?> loadPlaintext(String messageRecordId) async {
    final repository = _requireMessagesRepository();
    final established = await _runtime.loadProjectedPlaintext(
      messagesRepository: repository,
      messageRecordId: messageRecordId,
      keyTag: _keyTag,
      repositoryContextLease: _repositoryContextLease,
    );
    if (established != null) return established;
    final records = _repositoryContextLease == null
        ? await repository.getAllMessages()
        : await repository.getAllMessagesInContext(
            _repositoryContextLease,
          );
    for (final record in records) {
      if (record.id == messageRecordId &&
          record.fsClassification == FsMessageClassification.preFs) {
        final presentation =
            await _runtime.presentationStateForMessage(messageRecordId);
        if (presentation?.isDeleted == true ||
            (record.deleteAfterRead &&
                presentation?.readAtUnixSeconds != null)) {
          return null;
        }
        return record.text;
      }
    }
    return null;
  }

  Future<void> _persistPreFsPayload(
    V3ApplicationPayload payload, {
    required String senderId,
    required String recipientId,
    required String direction,
  }) async {
    // A delegated keyboard has no access to the application's message
    // repository. The authenticated payload is returned to its caller while
    // the replay/FS journal is committed through the delegated record store.
    if (_messagesRepository == null && _runtime.isDelegatedKeyboardSession) {
      return;
    }
    final repository = _requireMessagesRepository();
    final record = MessageRecord(
      id: '${V3ApplicationPayloadCodec.messageRecordIdPrefix}'
          '${payload.stableMessageId}',
      senderId: senderId,
      recipientId: recipientId,
      direction: direction,
      timestamp: payload.timestampUnixSeconds,
      text: payload.text,
      expireAfter: payload.expireAfterUnixSeconds,
      deleteAfterRead: payload.deleteAfterRead,
      keyTag: _keyTag,
      isFsEncrypted: false,
      protocolVersion: V3PublicIdentityCodec.protocolVersion,
      fsClassification: FsMessageClassification.preFs,
      backupExcluded: payload.backupExcluded,
    );
    final lease = _repositoryContextLease;
    if (lease == null) {
      await repository.add(record);
    } else {
      await repository.addInContext(lease, record);
    }
  }

  V3ChatOutboundExport _handshakeExport(
    V3ApplicationHandshakeExport export, {
    required String remoteIdentityId,
    required int policyRevision,
    required V3ChatCarrierMode carrierMode,
    required String coverText,
    int maxCarrierCharacters = V3LmfFrameCodec.portableShareCharacterLimit,
  }) {
    return V3ChatOutboundExport._(
      purpose: V3ChatOutboundPurpose.handshake,
      localIdentityId: localIdentityId,
      remoteIdentityId: remoteIdentityId,
      carrierMode: carrierMode,
      policyRevision: policyRevision,
      parts: _encodeFrames(
        export.frames,
        carrierMode: carrierMode,
        coverText: coverText,
        maxTotalCharacters: maxCarrierCharacters,
      ),
      handshakeId: export.handshakeId,
      restored: export.restored,
    );
  }

  ({RemoteIdentity model, V3PublicIdentity public})? _contactForInboundFrame(
    V3LmfFrame frame,
    List<({RemoteIdentity model, V3PublicIdentity public})> contacts,
  ) {
    final sender = frame.metadata.senderBinding;
    final recipient = frame.metadata.recipientBinding;
    final local = _routingBinding(_runtime.localPublicIdentity);
    try {
      if (!_bytesEqual(recipient, local)) return null;
      for (final contact in contacts) {
        final candidate = _routingBinding(contact.public);
        try {
          if (_bytesEqual(sender, candidate)) return contact;
        } finally {
          _wipe(candidate);
        }
      }
      return null;
    } finally {
      _wipe(sender);
      _wipe(recipient);
      _wipe(local);
    }
  }

  RemoteIdentity? _contactForPayload(
    V3ApplicationPayload payload,
    List<({RemoteIdentity model, V3PublicIdentity public})> contacts,
  ) {
    final sender = payload.senderIdentityDigest;
    try {
      for (final contact in contacts) {
        final candidate = _identityDigest(contact.public);
        try {
          if (_bytesEqual(sender, candidate)) return contact.model;
        } finally {
          _wipe(candidate);
        }
      }
      return null;
    } finally {
      _wipe(sender);
    }
  }

  ({RemoteIdentity model, V3PublicIdentity public})? _contactForSession(
    String remoteIdentityDigest,
    List<({RemoteIdentity model, V3PublicIdentity public})> contacts,
  ) {
    for (final contact in contacts) {
      final candidate = _identityDigest(contact.public);
      try {
        if (_armored(candidate) == remoteIdentityDigest) return contact;
      } finally {
        _wipe(candidate);
      }
    }
    return null;
  }
}

final class _V3ChatApplicationPart {
  const _V3ChatApplicationPart({
    required this.assemblyId,
    required this.fragmentIndex,
  });

  final String assemblyId;
  final int fragmentIndex;
}

final class _V3ChatPreFsPart {
  const _V3ChatPreFsPart({
    required this.entryId,
    required this.purpose,
  });

  final String entryId;
  final V3PreFsPendingPurpose purpose;
}

final class _V3PreFsCombinedPayload {
  const _V3PreFsCombinedPayload(
    this.applicationPayload,
    this.controlFrame, {
    this.controlTransferId,
    this.controlFragmentIndex = 0,
    this.controlFragmentCount = 0,
  });

  final Uint8List applicationPayload;
  final Uint8List? controlFrame;
  final Uint8List? controlTransferId;
  final int controlFragmentIndex;
  final int controlFragmentCount;
}

final class _V3PreFsControlPending implements Exception {
  const _V3PreFsControlPending();
}

const int _preFsControlChunkBytes = 320;
const List<int> _preFsWholeFrameTransferDomain = <int>[
  0x50,
  0x43,
  0x31,
  0x2f,
  0x77,
  0x68,
  0x6f,
  0x6c,
  0x65,
]; // PC1/whole

int _unpaddedBase64Length(int byteCount) =>
    4 * ((byteCount + 2) ~/ 3) - ((3 - byteCount % 3) % 3);

/// Conservative preflight for text/link application output. It assumes the
/// largest valid HR3 header and one independent encrypted frame per active
/// device. Overestimating merely selects the explicitly gray identity-wide
/// carrier; underestimating could commit a ratchet send that cannot be copied.
int _applicationCarrierWorstCaseCharacters({
  required String text,
  required String senderDisplayName,
  required int targetCount,
  required V3ChatCarrierMode carrierMode,
}) {
  if (targetCount < 1 || carrierMode == V3ChatCarrierMode.steganography) {
    throw ArgumentError('text/link application preflight requires a target');
  }
  final nameBytes = utf8.encode(senderDisplayName).length;
  final payloadBytes = V3ApplicationPayloadCodec.headerBytes +
      min<int>(nameBytes, V3ApplicationPayloadCodec.maxDisplayNameBytes) +
      utf8.encode(text).length;
  final hybridBytes = V3HybridRatchetHeaderCodec.maxEncodedBytes;
  final tokenPrefixBytes = V3LmfFrameCodec.tokenPrefix.length +
      (carrierMode == V3ChatCarrierMode.link
          ? '${V3LmfFrameCodec.scheme}://${V3LmfFrameCodec.messageHost}/'.length
          : 0);
  final firstBytes = V3LmfFrameCodec.firstFragmentPlaintextCapacity(
    hybridRatchetHeaderLength: hybridBytes,
  );
  var remaining = payloadBytes;
  var total = 0;
  var fragmentIndex = 0;
  while (remaining > 0) {
    final plaintextBytes = min<int>(
      remaining,
      fragmentIndex == 0 ? firstBytes : V3LmfFrameCodec.fragmentPlaintextBytes,
    );
    final binaryBytes = V3LmfFrameCodec.headerBytes +
        V3LmfFrameCodec.authenticationTagBytes +
        (fragmentIndex == 0 ? hybridBytes : 0) +
        plaintextBytes;
    total += tokenPrefixBytes + _unpaddedBase64Length(binaryBytes);
    remaining -= plaintextBytes;
    fragmentIndex++;
  }
  return total * targetCount + fragmentIndex * targetCount - 1;
}

String _preFsFrameDigestKey(Uint8List frameBytes) => _armored(
      Uint8List.fromList(
        crypto.sha256.convert(frameBytes).bytes.take(16).toList(),
      ),
    );

Uint8List _encodePreFsCombinedPayload(
  Uint8List applicationPayload,
  Uint8List? controlFrame, {
  Uint8List? controlTransferId,
  int controlFragmentIndex = 0,
  int controlFragmentCount = 0,
}) {
  final controlLength = controlFrame?.length ?? 0;
  if ((controlFrame == null) != (controlTransferId == null) ||
      (controlTransferId != null && controlTransferId.length != 16)) {
    throw ArgumentError('invalid preFs control chunk');
  }
  final encoded = Uint8List(31 + applicationPayload.length + controlLength);
  encoded.setRange(0, 3, const <int>[0x50, 0x43, 0x31]); // PC1
  final data = ByteData.sublistView(encoded);
  data.setUint32(3, applicationPayload.length, Endian.big);
  data.setUint16(7, controlLength, Endian.big);
  data.setUint16(9, controlFragmentIndex, Endian.big);
  data.setUint16(11, controlFragmentCount, Endian.big);
  if (controlTransferId != null) encoded.setRange(13, 29, controlTransferId);
  data.setUint16(29, 0, Endian.big);
  encoded.setRange(31, 31 + applicationPayload.length, applicationPayload);
  if (controlFrame != null) {
    encoded.setRange(
      31 + applicationPayload.length,
      encoded.length,
      controlFrame,
    );
  }
  return encoded;
}

_V3PreFsCombinedPayload _decodePreFsCombinedPayload(Uint8List encoded) {
  if (encoded.length < 32 ||
      encoded[0] != 0x50 ||
      encoded[1] != 0x43 ||
      encoded[2] != 0x31) {
    throw const FormatException('Invalid Layergram preFs combined payload');
  }
  final data = ByteData.sublistView(encoded);
  final applicationLength = data.getUint32(3, Endian.big);
  final controlLength = data.getUint16(7, Endian.big);
  final controlFragmentIndex = data.getUint16(9, Endian.big);
  final controlFragmentCount = data.getUint16(11, Endian.big);
  if (applicationLength < 1 ||
      31 + applicationLength + controlLength != encoded.length ||
      data.getUint16(29, Endian.big) != 0 ||
      (controlLength == 0 &&
          (controlFragmentIndex != 0 || controlFragmentCount != 0)) ||
      (controlLength > 0 &&
          (controlFragmentCount < 1 ||
              controlFragmentIndex >= controlFragmentCount))) {
    throw const FormatException('Invalid Layergram preFs combined lengths');
  }
  return _V3PreFsCombinedPayload(
    Uint8List.fromList(encoded.sublist(31, 31 + applicationLength)),
    controlLength == 0
        ? null
        : Uint8List.fromList(encoded.sublist(31 + applicationLength)),
    controlTransferId:
        controlLength == 0 ? null : Uint8List.fromList(encoded.sublist(13, 29)),
    controlFragmentIndex: controlFragmentIndex,
    controlFragmentCount: controlFragmentCount,
  );
}

void _preflightCarrier(V3ChatCarrierMode carrierMode, String coverText) {
  if (carrierMode != V3ChatCarrierMode.steganography) return;
  if (!StegoEncoder.canEncodeBytesWithinCharacterLimit(
    coverText,
    V3LmfFrameCodec.maxPortableStegoFrameBytes,
    V3LmfFrameCodec.portableShareCharacterLimit,
  )) {
    throw V3ChatCoverCapacityException(
      StegoEncoder.missingCoverCapacityForBytes(
        coverText,
        V3LmfFrameCodec.maxPortableStegoFrameBytes,
      ),
    );
  }
}

V3ChatInboundResult _preferInboundResult(
  V3ChatInboundResult? current,
  V3ChatInboundResult candidate,
) {
  if (current == null ||
      _inboundPriority(candidate.status) >= _inboundPriority(current.status)) {
    return candidate;
  }
  return current;
}

int _inboundPriority(V3ChatInboundStatus status) => switch (status) {
      V3ChatInboundStatus.delivered => 9,
      V3ChatInboundStatus.handshakeResponse => 8,
      V3ChatInboundStatus.sessionEstablished => 7,
      V3ChatInboundStatus.acknowledgementApplied => 6,
      V3ChatInboundStatus.committedReplay => 5,
      V3ChatInboundStatus.handshakeProgress => 4,
      V3ChatInboundStatus.pending => 3,
      V3ChatInboundStatus.expired => 2,
      V3ChatInboundStatus.notForThisInstallation => 1,
      V3ChatInboundStatus.invalid => 0,
    };

List<String> _encodeFrames(
  Iterable<V3LmfFrame> frames, {
  required V3ChatCarrierMode carrierMode,
  required String coverText,
  int maxTotalCharacters = V3LmfFrameCodec.portableShareCharacterLimit,
}) {
  final encoded = frames
      .map(
        (frame) => switch (carrierMode) {
          V3ChatCarrierMode.text => V3ApplicationTransport.encodeText(frame),
          V3ChatCarrierMode.link => V3ApplicationTransport.encodeLink(frame),
          V3ChatCarrierMode.steganography => V3ApplicationTransport.encodeStego(
              frame: frame,
              coverText: coverText,
            ),
        },
      )
      .toList(growable: false);
  if (encoded.any((part) => part.length > maxTotalCharacters)) {
    throw const V3ChatPreFsCapacityException(
      'Layergram v3 frame exceeds the configured carrier limit',
    );
  }
  return encoded;
}

Future<List<String>> _encodeApplicationWithOptionalAcks(
  List<V3LmfFrame> applicationFrames, {
  required V3ApplicationSessionRuntime runtime,
  required V3PreFsPendingStore? preFsPendingStore,
  required String remoteIdentityDigest,
  required bool allowCombinedCarrier,
  required V3ChatCarrierMode carrierMode,
  required String coverText,
  required int maxTotalCharacters,
}) async {
  final encoded = _encodeFrames(
    applicationFrames,
    carrierMode: carrierMode,
    coverText: coverText,
    maxTotalCharacters: maxTotalCharacters,
  );
  if (!allowCombinedCarrier ||
      applicationFrames.isEmpty ||
      preFsPendingStore == null) {
    return encoded;
  }

  final pending = <V3LmfFrame>[];
  for (final acknowledgement in await runtime.pendingAcknowledgementFrames()) {
    final session = await runtime.completedSessionForFrame(acknowledgement);
    if (session?.remoteIdentityDigest == remoteIdentityDigest &&
        await preFsPendingStore.isBootstrapHandshake(
          remoteIdentityDigest,
          session!.handshakeId,
        )) {
      pending.add(acknowledgement);
    }
  }
  if (pending.isEmpty) return encoded;

  // Pick a stable, uniformly distributed window from the fresh random message
  // ID. Retrying one durable message reproduces its carrier, while newly
  // prepared messages do not lock onto one position when the ACK queue grows
  // at the same rate as a monotonic counter.
  var selector = 0;
  for (final byte in applicationFrames.first.metadata.messageId) {
    selector = ((selector * 257) ^ byte) & 0x7fffffff;
  }
  final start = selector % pending.length;
  final rotated = <V3LmfFrame>[
    ...pending.skip(start),
    ...pending.take(start),
  ];
  final maxAcks = min(
    rotated.length,
    V3CombinedCarrierCodec.maxFrames - 1,
  );
  for (var count = maxAcks; count > 0; count--) {
    final bundle = <V3LmfFrame>[
      applicationFrames.first,
      ...rotated.take(count),
    ];
    try {
      final combined = switch (carrierMode) {
        V3ChatCarrierMode.text => V3CombinedCarrierCodec.encodeText(
            bundle,
            maxTotalCharacters: maxTotalCharacters,
          ),
        V3ChatCarrierMode.link => V3CombinedCarrierCodec.encodeLink(
            bundle,
            maxTotalCharacters: maxTotalCharacters,
          ),
        V3ChatCarrierMode.steganography => V3CombinedCarrierCodec.encodeStego(
            frames: bundle,
            coverText: coverText,
            maxTotalCharacters: maxTotalCharacters,
          ),
      };
      return <String>[combined, ...encoded.skip(1)];
    } on ArgumentError {
      // Data has priority. Retry with fewer ACKs, then retain every ACK if no
      // combined carrier fits the configured transport budget.
    } on StateError {
      // Steganographic cover capacity is likewise a retryable bundle limit.
    }
  }
  return encoded;
}

/// One user action exports exactly one carrier. Text and links can contain
/// several independently authenticated v3 frames on separate lines; their
/// individual ratchet sessions remain intact. Steganography is one cover, so
/// callers must choose identity-wide Normal fallback before producing more
/// than one frame for that mode.
List<String> _singleApplicationCarrier(
  List<String> parts, {
  required V3ChatCarrierMode carrierMode,
  required int maxCarrierCharacters,
}) {
  if (parts.length <= 1) return parts;
  if (carrierMode != V3ChatCarrierMode.steganography) {
    final joined = parts.join('\n');
    if (joined.length <= maxCarrierCharacters) return <String>[joined];
  }
  throw const V3ChatPreFsCapacityException(
    'one Layergram message does not fit this carrier',
  );
}

/// One decoded carrier bundle.
///
/// A bundle may legitimately mix established LMF v3 frame lines and preFs
/// envelope lines, so each becomes an independently authenticated item.
typedef _DecodedCarrier = ({
  List<V3LmfFrame> frames,
  List<Uint8List> preFsEnvelopes,
  V3ChatCarrierMode mode,
  String? visibleCoverText,
  bool isCombined,
});

_DecodedCarrier _decodeCarrier(String carrier) {
  final normalized = carrier.trim();
  if (normalized.isEmpty ||
      normalized.length >
          V3LmfFrameCodec.portableShareCharacterLimit *
              V3LmfFrameCodec.maxFragments) {
    throw const FormatException('Invalid Layergram v3 carrier');
  }
  final lines = const LineSplitter()
      .convert(normalized)
      .map((line) => line.trim())
      .where((line) => line.isNotEmpty)
      .toList(growable: false);
  final preFsFirst = lines.length > 1 &&
      (V3PreFsTransport.isTextPart(lines.first) ||
          V3PreFsTransport.isLinkPart(lines.first));
  final frames = <V3LmfFrame>[];
  final preFsEnvelopes = <Uint8List>[];
  var sawText = false;
  var sawLink = false;
  var sawCombined = false;
  for (final line in lines) {
    if (V3CombinedCarrierCodec.isTextPart(line)) {
      sawText = true;
      sawCombined = true;
      frames.addAll(V3CombinedCarrierCodec.decodeText(line));
    } else if (V3CombinedCarrierCodec.isLinkPart(line)) {
      sawLink = true;
      sawCombined = true;
      frames.addAll(V3CombinedCarrierCodec.decodeLink(line));
    } else if (line.startsWith(V3LmfFrameCodec.tokenPrefix)) {
      sawText = true;
      try {
        frames.add(V3ApplicationTransport.decodeText(line));
      } on FormatException {
        if (!preFsFirst) rethrow;
      }
    } else if (line.startsWith(
      '${V3LmfFrameCodec.scheme}://${V3LmfFrameCodec.messageHost}/',
    )) {
      sawLink = true;
      try {
        frames.add(V3ApplicationTransport.decodeLink(line));
      } on FormatException {
        if (!preFsFirst) rethrow;
      }
    } else if (V3PreFsTransport.isTextPart(line)) {
      sawText = true;
      preFsEnvelopes.add(V3PreFsTransport.decodeText(line));
    } else if (V3PreFsTransport.isLinkPart(line)) {
      sawLink = true;
      preFsEnvelopes.add(V3PreFsTransport.decodeLink(line));
    } else if (V3CombinedCarrierCodec.looksLikeStegoPart(line)) {
      if (lines.length != 1) {
        throw const FormatException(
          'Layergram steganographic carriers are single-part',
        );
      }
      sawCombined = true;
      frames.addAll(V3CombinedCarrierCodec.decodeStego(line));
    } else if (V3PreFsTransport.looksLikeStegoPart(line)) {
      if (lines.length != 1) {
        throw const FormatException(
          'Layergram steganographic carriers are single-part',
        );
      }
      preFsEnvelopes.add(V3PreFsTransport.decodeStego(line));
    } else {
      if (lines.length != 1) {
        throw const FormatException('Invalid Layergram v3 carrier bundle');
      }
      frames.add(V3ApplicationTransport.decodeStego(carrier));
    }
  }
  if (lines.length > V3LmfFrameCodec.maxFragments) {
    throw const FormatException('Too many Layergram v3 carrier parts');
  }
  if (frames.isEmpty && preFsEnvelopes.isEmpty) {
    throw const FormatException('Invalid Layergram v3 carrier');
  }
  final isStego = !sawText && !sawLink;
  return (
    frames: List<V3LmfFrame>.unmodifiable(frames),
    preFsEnvelopes: List<Uint8List>.unmodifiable(preFsEnvelopes),
    mode: isStego
        ? V3ChatCarrierMode.steganography
        : (sawText ? V3ChatCarrierMode.text : V3ChatCarrierMode.link),
    visibleCoverText: isStego ? StegoDecoder.visibleCoverText(carrier) : null,
    isCombined: sawCombined,
  );
}

int? _normalizedCarrierLimit(Object? value) {
  if (value == null) return null;
  if (value is! int ||
      value < 1000 ||
      value > V3LmfFrameCodec.maxStegoInputCodeUnits) {
    throw ArgumentError.value(value, 'maxCarrierCharacters');
  }
  return value;
}

int _effectiveCarrierLimit(V3ChatCarrierMode mode, int? configured) {
  final absolute = mode == V3ChatCarrierMode.steganography
      ? V3LmfFrameCodec.maxStegoInputCodeUnits
      : 6000;
  return configured == null ? absolute : configured.clamp(1000, absolute);
}

int _preFsEnvelopeBudget(
  V3ChatCarrierMode carrierMode, {
  required int maxCarrierCharacters,
  required String coverText,
}) {
  int armorBudget(int prefixLength) {
    final armored = maxCarrierCharacters - prefixLength;
    if (armored < 4) return 0;
    return (armored * 3) ~/ 4;
  }

  switch (carrierMode) {
    case V3ChatCarrierMode.text:
      return armorBudget(V3PreFsCarrierBudget.tokenPrefix.length);
    case V3ChatCarrierMode.link:
      return armorBudget('layergram://p/'.length);
    case V3ChatCarrierMode.steganography:
      var low = 0;
      var high = V3PreFsCarrierBudget.maxStegoEnvelopeBytes;
      while (low < high) {
        final candidate = (low + high + 1) ~/ 2;
        if (StegoEncoder.canEncodeBytesWithinCharacterLimit(
          coverText,
          candidate,
          maxCarrierCharacters,
        )) {
          low = candidate;
        } else {
          high = candidate - 1;
        }
      }
      return low;
  }
}

String _encodePreFsEnvelope(
  Uint8List envelope, {
  required V3ChatCarrierMode carrierMode,
  required String coverText,
  int maxTotalCharacters = V3LmfFrameCodec.portableShareCharacterLimit,
}) =>
    switch (carrierMode) {
      V3ChatCarrierMode.text =>
        V3PreFsTransport.encodeText(envelope).length <= maxTotalCharacters
            ? V3PreFsTransport.encodeText(envelope)
            : throw const V3ChatPreFsCapacityException(
                'preFs text exceeds limit'),
      V3ChatCarrierMode.link =>
        V3PreFsTransport.encodeLink(envelope).length <= maxTotalCharacters
            ? V3PreFsTransport.encodeLink(envelope)
            : throw const V3ChatPreFsCapacityException(
                'preFs link exceeds limit'),
      V3ChatCarrierMode.steganography => V3PreFsTransport.encodeStego(
          envelope: envelope,
          coverText: coverText,
          maxTotalCharacters: maxTotalCharacters,
        ),
    };

String _preFsDisplayName(String value) {
  final trimmed = value.trim();
  if (trimmed.isEmpty) return '';
  if (utf8.encode(trimmed).length <= 32) return trimmed;
  var end = trimmed.length;
  while (end > 0 && utf8.encode(trimmed.substring(0, end)).length > 32) {
    end--;
  }
  return trimmed.substring(0, end);
}

int _nowUnixSeconds() => DateTime.now().millisecondsSinceEpoch ~/ 1000;

Uint8List _routingBinding(V3PublicIdentity identity) => Uint8List.fromList(
      crypto.sha256.convert(identity.identityBindingBytes).bytes,
    );

Uint8List _identityDigest(V3PublicIdentity identity) => Uint8List.fromList(
      crypto.sha384.convert(identity.identityBindingBytes).bytes,
    );

String _armored(Uint8List value) => base64UrlEncode(value).replaceAll('=', '');

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);

Uint8List _secureRandomBytes(int length, Random? random) {
  final source = random ?? Random.secure();
  final bytes = Uint8List(length);
  for (var index = 0; index < length; index++) {
    bytes[index] = source.nextInt(256);
  }
  return bytes;
}
