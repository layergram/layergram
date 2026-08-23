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
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../stego_encoder.dart';
import '../stego_decoder.dart';
import '../../storage/messages_repository_core.dart';
import '../fs_security_mode.dart';
import '../models.dart';
import 'application_payload_v3.dart';
import 'application_session_runtime_v3.dart';
import 'application_transport_v3.dart';
import 'identity_v3_adapter.dart';
import 'lmf_v3.dart';
import 'local_identity_v3.dart';
import 'public_identity_v3.dart';

enum V3ChatCarrierMode { text, link, steganography }

enum V3ChatOutboundPurpose { handshake, application, acknowledgement }

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
    this.handshakeId,
    this.messageExport,
    this.restored = false,
  })  : parts = List<String>.unmodifiable(parts),
        _applicationParts = List<_V3ChatApplicationPart?>.unmodifiable(
          applicationParts ?? const [],
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
          (part) => part.length > V3LmfFrameCodec.portableShareCharacterLimit,
        )) {
      throw ArgumentError('Layergram v3 export contains a non-portable part');
    }
    if (_applicationParts.isNotEmpty &&
        _applicationParts.length != this.parts.length) {
      throw ArgumentError('Layergram v3 export part binding mismatch');
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
  final bool restored;
  final List<_V3ChatApplicationPart?> _applicationParts;

  bool get isMultipart => parts.length > 1;

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
  const V3ChatInboundResult({
    required this.status,
    this.contact,
    this.payload,
    this.response,
  });

  final V3ChatInboundStatus status;
  final RemoteIdentity? contact;
  final V3ApplicationPayload? payload;
  final V3ChatOutboundExport? response;

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
  })  : _runtime = runtime,
        _messagesRepository = messagesRepository,
        _keyTag = keyTag;

  final V3ApplicationSessionRuntime _runtime;
  final MessagesRepositoryCore _messagesRepository;
  final String? _keyTag;

  String get localIdentityId =>
      _runtime.localIdentity.publicIdentity.identityId;

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
      return V3ChatContactSecurityStatus(
        phase: selectedMode == V3HandshakeMode.maximum
            ? V3ChatContactSecurityPhase.maximumActive
            : V3ChatContactSecurityPhase.normalActive,
        selectedMode: selectedMode,
        activeSessionCount: matchingSessions.length,
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
  }) async {
    eligibilityPolicy =
        eligibilityForContact?.call(contact) ?? eligibilityPolicy;
    _preflightCarrier(carrierMode, coverText);
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
    final hasSelectedModeSession = sessions.any(
      (session) =>
          session.mode == mode &&
          (mode != V3HandshakeMode.maximum ||
              session.remoteDeviceId ==
                  eligibilityPolicy!.maximumRemoteDeviceId) &&
          (eligibilityPolicy == null ||
              !eligibilityPolicy.excludedHandshakeIds
                  .contains(session.handshakeId)),
    );
    if (!hasSelectedModeSession) {
      final pending = await _runtime.pendingHandshakeForRemoteIdentity(
            remoteIdentity: remote,
            mode: mode,
            excludedHandshakeIds:
                eligibilityPolicy?.excludedHandshakeIds ?? const <String>{},
          ) ??
          await _runtime.createOffer(
            remoteIdentity: remote,
            mode: mode,
            excludedHandshakeIds:
                eligibilityPolicy?.excludedHandshakeIds ?? const <String>{},
          );
      return _handshakeExport(
        pending,
        remoteIdentityId: contact.identityId,
        policyRevision: eligibilityPolicy?.revision ?? 0,
        carrierMode: carrierMode,
        coverText: coverText,
      );
    }

    final message = await _runtime.sendApplicationMessageToIdentity(
      remoteIdentity: remote,
      expectedMode: mode,
      text: text,
      timestampUnixSeconds: timestampUnixSeconds,
      expireAfterUnixSeconds: expireAfterUnixSeconds,
      deleteAfterRead: deleteAfterRead,
      backupExcluded: backupExcluded,
      excludedHandshakeIds: eligibilityPolicy?.excludedHandshakeIds,
      maximumRemoteDeviceId: eligibilityPolicy?.maximumRemoteDeviceId,
      maximumRemoteDeviceIdResolver: () =>
          (eligibilityForContact?.call(contact) ?? eligibilityPolicy)
              ?.maximumRemoteDeviceId,
    );
    await _runtime.reconcileMessageRepository(
      messagesRepository: _messagesRepository,
      keyTag: _keyTag,
    );
    return V3ChatOutboundExport._(
      purpose: V3ChatOutboundPurpose.application,
      localIdentityId: localIdentityId,
      remoteIdentityId: contact.identityId,
      carrierMode: carrierMode,
      policyRevision: eligibilityPolicy?.revision ?? 0,
      parts: _encodeFrames(
        message.frames,
        carrierMode: carrierMode,
        coverText: coverText,
      ),
      messageExport: message,
      applicationParts: [
        for (final target in message.targets)
          for (final frame in target.frames)
            _V3ChatApplicationPart(
              assemblyId: target.assemblyId,
              fragmentIndex: frame.fragmentIndex,
            ),
      ],
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
    final message = export.messageExport;
    if (message == null) return;
    if (partIndex == null) {
      await _runtime.markMessageExported(message);
      return;
    }
    if (partIndex < 0 || partIndex >= export.parts.length) {
      throw RangeError.index(partIndex, export.parts, 'partIndex');
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
  }) async {
    _preflightCarrier(carrierMode, coverText);
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
        if (session?.remoteIdentityDigest == remoteDigest) {
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
          ),
          restored: true,
        ),
      );
    }

    final handshake = await _runtime.pendingHandshakeForRemoteIdentity(
      remoteIdentity: remote,
      mode: mode,
      excludedHandshakeIds: policy?.excludedHandshakeIds ?? const <String>{},
    );
    if (handshake != null) {
      exports.add(
        _handshakeExport(
          handshake,
          remoteIdentityId: contact.identityId,
          policyRevision: policy?.revision ?? 0,
          carrierMode: carrierMode,
          coverText: coverText,
        ),
      );
    }

    final sessions = await _runtime.sessionsForRemoteIdentity(remote);
    final sessionIds = sessions.map((session) => session.sessionId).toSet();
    for (final message in await _runtime.pendingMessageExports()) {
      if (message.targets.isEmpty ||
          !message.targets.every(
            (target) => sessionIds.contains(target.sessionId),
          )) {
        continue;
      }
      exports.add(
        V3ChatOutboundExport._(
          purpose: V3ChatOutboundPurpose.application,
          localIdentityId: localIdentityId,
          remoteIdentityId: contact.identityId,
          carrierMode: carrierMode,
          policyRevision: policy?.revision ?? 0,
          parts: _encodeFrames(
            message.frames,
            carrierMode: carrierMode,
            coverText: coverText,
          ),
          messageExport: message,
          restored: true,
          applicationParts: [
            for (final target in message.targets)
              for (final frame in target.frames)
                _V3ChatApplicationPart(
                  assemblyId: target.assemblyId,
                  fragmentIndex: frame.fragmentIndex,
                ),
          ],
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
    final decodedCarrier = _decodeCarrierFrames(carrier);
    final effectiveResponseMode = responseCarrierMode ?? decodedCarrier.mode;
    final effectiveAcknowledgementCover = acknowledgementCoverText.isNotEmpty
        ? acknowledgementCoverText
        : decodedCarrier.visibleCoverText ?? '';
    _preflightCarrier(
      effectiveResponseMode,
      effectiveAcknowledgementCover,
    );
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
    V3ChatInboundResult? selected;
    var shouldReconcile = false;
    for (final frame in frames) {
      if (frame.metadata.kind == V3LmfFrameKind.handshake) {
        final contact = _contactForInboundFrame(frame, v3Contacts);
        if (contact == null) {
          selected = _preferInboundResult(
            selected,
            const V3ChatInboundResult(
              status: V3ChatInboundStatus.notForThisInstallation,
            ),
          );
          continue;
        }
        var eligibility = eligibilityForContact?.call(contact.model);
        final selectedMode = modeForContact(contact.model);
        if (eligibility == null && ensureEligibilityForContact != null) {
          eligibility = await _runtime.initializeContactPolicy(
            remoteIdentity: contact.public,
            persist: () => ensureEligibilityForContact(
              contact.model,
              selectedMode,
            ),
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
        final inbound = await _runtime.receiveHandshakeFrame(
          frame: frame,
          remoteIdentity: contact.public,
          expectedMode: selectedMode,
          excludedHandshakeIds:
              eligibility?.excludedHandshakeIds ?? const <String>{},
          maximumRemoteDeviceId: eligibility?.maximumRemoteDeviceId,
          maximumRemoteDeviceIdResolver: () =>
              eligibilityForContact?.call(contact.model)?.maximumRemoteDeviceId,
          onSessionEstablished: selectedMode == V3HandshakeMode.maximum &&
                  pinMaximumDevice != null
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
                policyRevision: eligibility?.revision ?? 0,
                carrierMode: effectiveResponseMode,
                coverText: effectiveAcknowledgementCover,
              );
        selected = _preferInboundResult(
          selected,
          V3ChatInboundResult(
            status: response != null
                ? V3ChatInboundStatus.handshakeResponse
                : inbound.session != null
                    ? V3ChatInboundStatus.sessionEstablished
                    : V3ChatInboundStatus.handshakeProgress,
            contact: contact.model,
            response: response,
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
          const V3ChatInboundResult(
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
      final inbound = await _runtime.receiveApplicationFrame(
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
      final contact = inbound.payload == null
          ? routedContact.model
          : _contactForPayload(inbound.payload!, v3Contacts);
      final response = inbound.acknowledgementFrame == null
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
      selected = _preferInboundResult(
        selected,
        V3ChatInboundResult(
          status: status,
          contact: contact,
          payload: inbound.payload,
          response: response,
        ),
      );
    }

    if (shouldReconcile) {
      await _runtime.reconcileMessageRepository(
        messagesRepository: _messagesRepository,
        keyTag: _keyTag,
        nowUnixSeconds: nowUnixSeconds,
      );
    }
    return selected ??
        const V3ChatInboundResult(status: V3ChatInboundStatus.invalid);
  }

  Future<String?> loadPlaintext(String messageRecordId) {
    return _runtime.loadProjectedPlaintext(
      messagesRepository: _messagesRepository,
      messageRecordId: messageRecordId,
      keyTag: _keyTag,
    );
  }

  V3ChatOutboundExport _handshakeExport(
    V3ApplicationHandshakeExport export, {
    required String remoteIdentityId,
    required int policyRevision,
    required V3ChatCarrierMode carrierMode,
    required String coverText,
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
    final local = _routingBinding(_runtime.localIdentity.publicIdentity);
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
}) {
  return frames
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
}

({
  List<V3LmfFrame> frames,
  V3ChatCarrierMode mode,
  String? visibleCoverText,
}) _decodeCarrierFrames(String carrier) {
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
  final isTextBundle = lines.isNotEmpty &&
      lines.every((line) => line.startsWith(V3LmfFrameCodec.tokenPrefix));
  final isLinkBundle = lines.isNotEmpty &&
      lines.every(
        (line) => line.startsWith(
          '${V3LmfFrameCodec.scheme}://${V3LmfFrameCodec.messageHost}/',
        ),
      );
  if (isTextBundle || isLinkBundle) {
    if (lines.length > V3LmfFrameCodec.maxFragments) {
      throw const FormatException('Too many Layergram v3 carrier parts');
    }
    return (
      frames: lines
          .map(
            isTextBundle
                ? V3ApplicationTransport.decodeText
                : V3ApplicationTransport.decodeLink,
          )
          .toList(growable: false),
      mode: isTextBundle ? V3ChatCarrierMode.text : V3ChatCarrierMode.link,
      visibleCoverText: null,
    );
  }
  return (
    frames: [V3ApplicationTransport.decodeStego(carrier)],
    mode: V3ChatCarrierMode.steganography,
    visibleCoverText: StegoDecoder.visibleCoverText(carrier),
  );
}

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
