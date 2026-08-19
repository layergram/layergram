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
import '../../storage/messages_repository_core.dart';
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

final class V3ChatCoverCapacityException implements Exception {
  const V3ChatCoverCapacityException(this.missingCharacters);

  final int missingCharacters;
}

/// Exact independently shareable carrier parts returned to the chat UI.
final class V3ChatOutboundExport {
  V3ChatOutboundExport._({
    required this.purpose,
    required Iterable<String> parts,
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
  }) async {
    _preflightCarrier(carrierMode, coverText);
    final remote = V3IdentityAdapter.fromRemoteIdentity(contact);
    final sessions = await _runtime.sessionsForRemoteIdentity(remote);
    if (sessions.isEmpty) {
      final pending = await _runtime.pendingHandshakeForRemoteIdentity(
            remoteIdentity: remote,
            mode: mode,
          ) ??
          await _runtime.createOffer(
            remoteIdentity: remote,
            mode: mode,
          );
      return _handshakeExport(
        pending,
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
    );
    await _runtime.reconcileMessageRepository(
      messagesRepository: _messagesRepository,
      keyTag: _keyTag,
    );
    return V3ChatOutboundExport._(
      purpose: V3ChatOutboundPurpose.application,
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

  Future<V3ChatInboundResult> receiveCarrier({
    required String carrier,
    required Iterable<RemoteIdentity> contacts,
    required V3HandshakeModeResolver modeForContact,
    V3ChatCarrierMode responseCarrierMode = V3ChatCarrierMode.text,
    String acknowledgementCoverText = '',
    DateTime? receivedAt,
    int? nowUnixSeconds,
  }) async {
    _preflightCarrier(responseCarrierMode, acknowledgementCoverText);
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
    final frames = _decodeCarrierFrames(carrier);
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
        final inbound = await _runtime.receiveHandshakeFrame(
          frame: frame,
          remoteIdentity: contact.public,
          expectedMode: modeForContact(contact.model),
          receivedAt: receivedAt,
        );
        final response = inbound.outbound == null
            ? null
            : _handshakeExport(
                inbound.outbound!,
                carrierMode: responseCarrierMode,
                coverText: acknowledgementCoverText,
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

      final inbound = await _runtime.receiveApplicationFrame(
        frame: frame,
        receivedAt: receivedAt,
        nowUnixSeconds: nowUnixSeconds,
      );
      final contact = inbound.payload == null
          ? _contactForInboundFrame(frame, v3Contacts)?.model
          : _contactForPayload(inbound.payload!, v3Contacts);
      final response = inbound.acknowledgementFrame == null
          ? null
          : V3ChatOutboundExport._(
              purpose: V3ChatOutboundPurpose.acknowledgement,
              parts: _encodeFrames(
                [inbound.acknowledgementFrame!],
                carrierMode: responseCarrierMode,
                coverText: acknowledgementCoverText,
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
    required V3ChatCarrierMode carrierMode,
    required String coverText,
  }) {
    return V3ChatOutboundExport._(
      purpose: V3ChatOutboundPurpose.handshake,
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

List<V3LmfFrame> _decodeCarrierFrames(String carrier) {
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
    return lines
        .map(
          isTextBundle
              ? V3ApplicationTransport.decodeText
              : V3ApplicationTransport.decodeLink,
        )
        .toList(growable: false);
  }
  return [V3ApplicationTransport.decode(carrier).frame];
}

Uint8List _routingBinding(V3PublicIdentity identity) => Uint8List.fromList(
      crypto.sha256.convert(identity.identityBindingBytes).bytes,
    );

Uint8List _identityDigest(V3PublicIdentity identity) => Uint8List.fromList(
      crypto.sha384.convert(identity.identityBindingBytes).bytes,
    );

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
