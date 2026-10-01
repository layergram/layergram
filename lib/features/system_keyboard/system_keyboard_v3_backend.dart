// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import 'dart:convert';

import '../../core/crypto/models.dart';
import '../../core/crypto/v3/application_chat_bridge_v3.dart';
import '../../core/crypto/v3/application_session_runtime_v3.dart';
import '../../core/crypto/v3/identity_v3_adapter.dart';
import '../../core/crypto/v3/local_identity_v3.dart';
import '../../core/crypto/v3/lmf_v3.dart';
import '../../core/crypto/v3/lmf_v3_persistence.dart';
import 'system_keyboard_controller.dart';
import 'system_keyboard_history.dart';

const _keyboardControlOutboxKind = 'v3_keyboard_control_outbox_v1';
const _keyboardCarrierLimit = 4000;

/// Text-only backend over a native-custodied runtime and an approved address
/// book. The delegate can negotiate Normal V3 sessions and send readable
/// pre-FS text using only the live, revocable keyboard grant.
final class SystemKeyboardV3Backend
    implements SystemKeyboardBackend, SystemKeyboardContactSecurityProvider {
  SystemKeyboardV3Backend({
    required V3ApplicationSessionRuntime runtime,
    required Iterable<RemoteIdentity> contacts,
    required bool Function() isAuthorized,
    bool saveHistory = true,
    V3LmfRecordStore? recordStore,
    void Function(V3ChatHandshakeDiagnostic)? handshakeDiagnostic,
  })  : _runtime = runtime,
        _bridge = runtime.isDelegatedKeyboardSession
            ? V3ApplicationChatBridge.forDelegatedKeyboard(
                runtime: runtime, handshakeDiagnostic: handshakeDiagnostic)
            : V3ApplicationChatBridge.forEstablishedSessions(runtime: runtime),
        _isAuthorized = isAuthorized,
        _saveHistory = saveHistory,
        _recordStore = recordStore {
    if (runtime.isDelegatedKeyboardSession && recordStore == null) {
      throw ArgumentError('Delegated keyboard requires a durable record store');
    }
    for (final contact in contacts) {
      final identity = V3IdentityAdapter.fromRemoteIdentity(contact);
      if (_contacts.length >= 64 ||
          _contacts.containsKey(contact.identityId) ||
          contact.identityId.length > 128 ||
          contact.displayName.isEmpty ||
          contact.displayName.length > 128 ||
          contact.fingerprint.isEmpty ||
          contact.fingerprint.length > 128 ||
          runtime.protocolV3EligibilityForIdentity(identity)?.isValid != true) {
        throw const FormatException('Invalid approved keyboard contact');
      }
      _contacts[contact.identityId] = contact;
    }
  }

  final V3ApplicationSessionRuntime _runtime;
  final V3ApplicationChatBridge _bridge;
  final bool Function() _isAuthorized;
  final bool _saveHistory;
  final V3LmfRecordStore? _recordStore;
  final Map<String, RemoteIdentity> _contacts = {};
  V3ChatOutboundExport? _pending;
  V3ChatOutboundExport? _pendingReceipt;
  final Map<String, V3ChatOutboundExport> _receipts = {};
  String? _pendingHandle;
  final List<String> _pendingControlRecordIds = [];
  int _nextHandle = 0;
  bool _closed = false;

  void close() {
    _closed = true;
    _pending = null;
    _pendingReceipt = null;
    _receipts.clear();
    _pendingHandle = null;
    _pendingControlRecordIds.clear();
    _contacts.clear();
  }

  void _check() {
    if (_closed || !_isAuthorized() || _runtime.requiresRecovery) {
      close();
      throw StateError('Keyboard runtime unavailable');
    }
  }

  @override
  Future<List<SystemKeyboardContact>> listApprovedContacts() async {
    _check();
    return _contacts.values.map(_surface).toList(growable: false);
  }

  @override
  Future<String?> securityPhaseForContact(
      String contactId, String fingerprint) async {
    _check();
    final contact = _contacts[contactId];
    if (contact == null || contact.fingerprint != fingerprint) return null;
    final policy = _bridge.eligibilityForContact(contact);
    final mode = _bridge.modeForContact(contact);
    final status = await _bridge.securityStatus(
      contact: contact,
      selectedMode: mode,
      eligibilityPolicy: policy,
      requireEligibilityPolicy: true,
    );
    _check();
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
      SystemKeyboardOutboundRequest request) async {
    _check();
    final contact = _contacts[request.contactId];
    if (contact == null ||
        contact.fingerprint != request.contactFingerprint ||
        _pending != null ||
        request.text.isEmpty ||
        request.text.length > _keyboardCarrierLimit) {
      return null;
    }
    final policy = _bridge.eligibilityForContact(contact);
    if (policy == null || !policy.isValid) return null;
    final mode = _bridge.modeForContact(contact);
    final status = await _bridge.securityStatus(
        contact: contact,
        selectedMode: mode,
        eligibilityPolicy: policy,
        requireEligibilityPolicy: true);
    _check();
    final allowsNormalPreFs = _runtime.isDelegatedKeyboardSession &&
        mode == V3HandshakeMode.normal &&
        (status.phase == V3ChatContactSecurityPhase.setupRequired ||
            status.phase == V3ChatContactSecurityPhase.setupPending);
    if (!status.isActive && !allowsNormalPreFs) return null;
    final export = await _bridge.prepareOutbound(
        contact: contact,
        mode: mode,
        carrierMode: V3ChatCarrierMode.text,
        text: request.text,
        eligibilityPolicy: policy,
        eligibilityForContact: _bridge.eligibilityForContact,
        maxCarrierCharacters: _keyboardCarrierLimit);
    _check();
    // Preserve every canonical frame, in order, in one text insertion. The app
    // decoder accepts this same newline-separated bundle without re-encoding.
    var carrier = export.parts.join('\n');
    if (export.purpose != V3ChatOutboundPurpose.application &&
            export.purpose != V3ChatOutboundPurpose.preFs ||
        export.parts.isEmpty ||
        export.parts.length > 64 ||
        export.parts.any((part) => part.isEmpty) ||
        carrier.length > _keyboardCarrierLimit) {
      // The exact pending export remains recoverable in the containing app.
      return null;
    }
    if (_runtime.isDelegatedKeyboardSession) {
      final preFs = export.preFsMetadata;
      if (preFs != null) {
        if (_saveHistory) {
          await SystemKeyboardHistory.recordPreFs(
            store: _recordStore!,
            stableMessageId: preFs.messageId,
            localIdentityId: _runtime.localPublicIdentity.identityId,
            contactId: contact.identityId,
            direction: 'outgoing',
            text: request.text,
            timestampUnixSeconds: preFs.timestampUnixSeconds,
          );
        }
      } else if (!_saveHistory) {
        final id = export.messageExport?.logicalMessageId;
        if (id == null) throw StateError('Keyboard message ID unavailable');
        await _runtime.suppressKeyboardChatHistory('v3m:$id');
      }
      _check();
    }
    _pendingControlRecordIds.clear();
    final control = await _queuedControlsFor(contact.identityId);
    _check();
    for (final record in control) {
      final part = record.payload['part'] as String;
      if (export.parts.length + _pendingControlRecordIds.length + 1 > 64 ||
          carrier.length + part.length + 1 > _keyboardCarrierLimit) {
        break;
      }
      carrier = '$carrier\n$part';
      _pendingControlRecordIds.add(record.storageId);
    }
    // A reply carries the exact acknowledgement of the latest message decoded
    // here, only to its authenticated, explicitly selected contact. Older
    // receipts remain available through ordinary app recovery.
    final receipt = _receipts[contact.identityId];
    if (receipt != null && export.parts.length + receipt.parts.length <= 64) {
      final combined = '$carrier\n${receipt.parts.join('\n')}';
      if (combined.length <= _keyboardCarrierLimit) {
        carrier = combined;
        _pendingReceipt = receipt;
      }
    }
    final handle = 'k${_nextHandle++}';
    _pending = export;
    _pendingHandle = handle;
    return SystemKeyboardBackendExport(
        exportHandle: handle,
        carriers: [carrier],
        ciphertextCodeUnits: carrier.length);
  }

  @override
  Future<void> markExported(String exportHandle) async {
    _check();
    final export = _pending;
    if (export == null || exportHandle != _pendingHandle) {
      throw StateError('Keyboard export is unavailable');
    }
    // Consume the handle before awaiting; an uncertain acknowledgement cannot
    // be repeated. The V3 exact-byte recovery journal is retained independently.
    _pending = null;
    _pendingHandle = null;
    final receipt = _pendingReceipt;
    _pendingReceipt = null;
    final controlRecordIds = List<String>.of(_pendingControlRecordIds);
    _pendingControlRecordIds.clear();
    if (receipt != null &&
        identical(_receipts[export.remoteIdentityId], receipt)) {
      _receipts.remove(export.remoteIdentityId);
    }
    await _bridge.markExported(export);
    final recordStore = _recordStore;
    if (recordStore != null) {
      for (final id in controlRecordIds) {
        await recordStore.delete(id);
      }
    }
    _check();
  }

  @override
  Future<SystemKeyboardBackendDecoded?> decodeCarrier(String carrier) async {
    _check();
    if (carrier.isEmpty ||
        carrier.length > systemKeyboardDefaultMaxCarrierCodeUnits) {
      return null;
    }
    final inbound = await _bridge.receiveCarrier(
        carrier: carrier,
        contacts: _contacts.values.toList(growable: false),
        modeForContact: _bridge.modeForContact,
        eligibilityForContact: _bridge.eligibilityForContact);
    _check();
    if (_runtime.isDelegatedKeyboardSession) {
      await _enqueueResponses(inbound.responses);
      _check();
    }
    if (inbound.status != V3ChatInboundStatus.delivered ||
        inbound.contact == null ||
        inbound.payload == null) {
      return null;
    }
    final payload = inbound.payload!;
    final saved = _contacts[inbound.contact!.identityId];
    if (saved == null ||
        saved.fingerprint != inbound.contact!.fingerprint ||
        payload.text.isEmpty ||
        payload.text.length > systemKeyboardDefaultMaxCarrierCodeUnits) {
      return null;
    }
    if (_runtime.isDelegatedKeyboardSession) {
      if (inbound.preFs != null) {
        if (_saveHistory && !payload.deleteAfterRead) {
          await SystemKeyboardHistory.recordPreFs(
            store: _recordStore!,
            stableMessageId: payload.stableMessageId,
            localIdentityId: _runtime.localPublicIdentity.identityId,
            contactId: saved.identityId,
            direction: 'incoming',
            text: payload.text,
            timestampUnixSeconds: payload.timestampUnixSeconds,
            expireAfterUnixSeconds: payload.expireAfterUnixSeconds,
            backupExcluded: payload.backupExcluded,
          );
        }
      } else if (!_saveHistory || payload.deleteAfterRead) {
        await _runtime
            .suppressKeyboardChatHistory('v3m:${payload.stableMessageId}');
      }
      _check();
    }
    final receipt = inbound.response;
    if (!payload.deleteAfterRead &&
        payload.expireAfterUnixSeconds == null &&
        receipt?.purpose == V3ChatOutboundPurpose.acknowledgement) {
      _receipts[saved.identityId] = receipt!;
    }
    return SystemKeyboardBackendDecoded(
        contact: _surface(saved),
        text: payload.text,
        readOnce: payload.deleteAfterRead,
        expired: false,
        hasExpiry: payload.expireAfterUnixSeconds != null);
  }

  static SystemKeyboardContact _surface(RemoteIdentity contact) =>
      SystemKeyboardContact(
          id: contact.identityId,
          name: contact.displayName,
          fingerprint: contact.fingerprint);

  Future<List<V3LmfStoredRecord>> _queuedControlsFor(String contactId) async {
    final recordStore = _recordStore;
    if (recordStore == null) return const [];
    final queued = (await recordStore.readAll())
        .where((record) =>
            record.payload['kind'] == _keyboardControlOutboxKind &&
            record.payload['contactId'] == contactId)
        .toList(growable: false);
    queued.sort((a, b) {
      final left = a.payload['sequence'] as int;
      final right = b.payload['sequence'] as int;
      final order = left.compareTo(right);
      return order == 0 ? a.storageId.compareTo(b.storageId) : order;
    });
    final contact = _contacts[contactId];
    final policy =
        contact == null ? null : _bridge.eligibilityForContact(contact);
    if (policy == null || !policy.isValid) {
      throw StateError('Keyboard control policy unavailable');
    }
    if (policy.excludedHandshakeIds.isEmpty) return queued;
    final eligible = <V3LmfStoredRecord>[];
    for (final record in queued) {
      final frame =
          V3LmfFrameCodec.decodeToken(record.payload['part'] as String);
      final handshakeId = frame.metadata.kind == V3LmfFrameKind.handshake
          ? base64Url.encode(frame.metadata.sessionId).replaceAll('=', '')
          : (await _runtime.completedSessionForFrame(frame))?.handshakeId;
      _check();
      if (handshakeId != null &&
          policy.excludedHandshakeIds.contains(handshakeId)) {
        // A contact-policy boundary retires queued transport parts as well as
        // sessions. Keep keys/history intact; never append reset setup or ACK
        // bytes beside a new readable message after a custody reopen.
        await recordStore.delete(record.storageId);
        _check();
      } else {
        eligible.add(record);
      }
    }
    return eligible;
  }

  Future<void> _enqueueResponses(List<V3ChatOutboundExport> responses) async {
    final recordStore = _recordStore;
    if (recordStore == null || responses.isEmpty) return;
    final existing = (await recordStore.readAll())
        .where((record) => record.payload['kind'] == _keyboardControlOutboxKind)
        .toList(growable: false);
    if (existing.length > 128) {
      throw StateError('Keyboard control outbox capacity exceeded');
    }
    final exact = <String>{
      for (final record in existing)
        '${record.payload['contactId']}\u0000${record.payload['part']}',
    };
    var sequence = 0;
    for (final record in existing) {
      final stored = record.payload['sequence'];
      if (stored is! int || stored < 0 || stored >= 9007199254740991) {
        throw StateError('Invalid keyboard control outbox sequence');
      }
      if (stored >= sequence) sequence = stored + 1;
    }
    for (final response in responses) {
      if (response.purpose != V3ChatOutboundPurpose.handshake &&
          response.purpose != V3ChatOutboundPurpose.acknowledgement) {
        continue;
      }
      if (!_contacts.containsKey(response.remoteIdentityId) ||
          response.parts.length > 64) {
        throw StateError('Keyboard control response is outside grant');
      }
      for (final part in response.parts) {
        if (part.isEmpty || part.length > _keyboardCarrierLimit) {
          throw StateError('Keyboard control response exceeds carrier');
        }
        final key = '${response.remoteIdentityId}\u0000$part';
        if (!exact.add(key)) continue;
        if (exact.length > 128) {
          throw StateError('Keyboard control outbox capacity exceeded');
        }
        if (sequence >= 9007199254740991) {
          throw StateError('Keyboard control outbox sequence exhausted');
        }
        await recordStore.write({
          'kind': _keyboardControlOutboxKind,
          'v': 1,
          'contactId': response.remoteIdentityId,
          'part': part,
          'sequence': sequence++,
        });
      }
    }
  }
}
