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

/// Pure Dart, backend-agnostic core for the **SYSTEM keyboard** bridge.
///
/// This library contains no cryptography, no persistence and no key material.
/// It owns a single input session and decides, for every operation, whether the
/// host is currently allowed to use the SYSTEM keyboard at all. All sensitive
/// work (contact store, V3 encryption/decryption, durable export/outbox
/// bookkeeping) stays behind [SystemKeyboardBackend], which is executed
/// exclusively inside the existing app owner.
///
/// Invariants enforced here:
/// * Admission is denied by default and is re-checked before any backend read,
///   after every `await` and again before returning.
/// * Any admission-relevant change – flags, identity generation or the owner's
///   monotonic `stateGeneration` – permanently revokes the active input session
///   the moment it is observed, including *between* operations. A fresh
///   [SystemKeyboardController.beginSession] and a new explicit recipient
///   confirmation are then required. A revoked session never unlocks itself
///   when the owner's values toggle back.
/// * An elapsed background deadline revokes the session permanently as well; a
///   later, later-arriving or absent deadline never reactivates it.
/// * Every admission failure surfaces as the single generic
///   [SystemKeyboardFailureCode.unavailable]; no reason, identity, lock or
///   passphrase metadata reaches the host.
/// * No plaintext is stored or logged. The only plaintext result is a transient
///   inbound decode preview handed to the Flutter caller; it is never stored.
/// * The core never unlocks, never invents a fallback identity, never extends or
///   renews a grant/deadline, and never marks an inbound message read.
/// * No plaintext is ever returned by prepare/authorize/acknowledge; the native
///   layer only receives the opaque pending id and, on explicit authorization,
///   the already-encrypted carrier.
library;

/// Monotonic clock. Returns time elapsed since an arbitrary fixed origin.
///
/// Must never move backwards; the caller (app owner) supplies it.
typedef SystemKeyboardMonotonicNow = Duration Function();

/// Synchronously reads the owner's current admission-relevant state.
///
/// Called before and after every backend interaction. Implementations must be
/// cheap, must not perform I/O and must not throw; a throwing reader is treated
/// as a denied snapshot.
typedef SystemKeyboardAccessReader = SystemKeyboardAccessSnapshot Function();

/// Ceiling for the encoded carrier handed to [SystemKeyboardController.decode].
///
/// Matches `StegoDecoder.maxCarrierCodeUnits` (262144). Kept as a local default
/// so this core stays free of crypto imports; the method-channel adapter should
/// inject `StegoDecoder.maxCarrierCodeUnits` explicitly.
const int systemKeyboardDefaultMaxCarrierCodeUnits = 262144;

/// Bounded text bundle for the autonomous V3 extension (4,000-character draft).
const int systemKeyboardAutonomousMaxOutboundCarrierCodeUnits = 32768;

/// Default bound for caller-supplied opaque identifier strings.
///
/// Applies to request ids, the native editor nonce and pending ids. Keeps the
/// replay memory and the backend call surface bounded regardless of host input.
const int systemKeyboardDefaultMaxIdentifierLength = 256;

/// Generic, deliberately coarse failure taxonomy.
///
/// [unavailable] is the single answer for *every* access/admission problem, so
/// the host cannot use failures as an oracle. The remaining codes describe
/// caller-visible protocol mistakes or benign inbound conditions and carry no
/// identity/lock/passphrase information.
enum SystemKeyboardFailureCode {
  /// Access denied, session missing, or the request was invalidated mid-flight.
  unavailable,

  /// Another operation owns the controller; nothing was executed.
  busy,

  /// This `requestId` was already used in the current input session.
  duplicateRequest,

  /// Caller misuse: empty request id, empty message text, empty editor nonce,
  /// empty pending id, or an identifier longer than the configured bound.
  invalidRequest,

  /// No confirmed, freshly approved recipient is bound to the request.
  invalidSelection,

  /// The backend produced something this core cannot safely insert, or the
  /// session already holds an unconsumed pending export.
  unsupportedExport,

  /// A size bound was exceeded (compose text or ciphertext).
  oversize,

  /// Unknown, stale, already authorized-away or already acknowledged pending id.
  noPendingExport,

  /// Inbound carrier had no message: unrecognized, empty, oversize or no data.
  noMessage,

  /// Inbound message self-destructs; only the full app may open it.
  openAppRequired,

  /// The backend failed while access was still valid.
  backendError,
}

/// Result envelope. A failure never carries a value and never carries a reason
/// beyond [failure].
class SystemKeyboardResult<T> {
  /// Wraps a successful value.
  const SystemKeyboardResult.success(this.value) : failure = null;

  /// Wraps a failure code. [value] is always `null`.
  const SystemKeyboardResult.failure(this.failure) : value = null;

  /// Successful payload, if any.
  final T? value;

  /// Failure code, if any.
  final SystemKeyboardFailureCode? failure;

  /// Whether this result carries a value.
  bool get isSuccess => failure == null;

  /// Whether this result carries a failure code.
  bool get isFailure => failure != null;

  /// Returns [value] or throws if this is a failure.
  T get requireValue {
    final T? current = value;
    if (current == null) {
      throw StateError('SystemKeyboardResult has no value ($failure)');
    }
    return current;
  }
}

/// One approved contact as supplied by the app owner's contact store.
class SystemKeyboardContact {
  /// Creates a contact reference. All three fields are non-secret references.
  const SystemKeyboardContact({
    required this.id,
    required this.name,
    required this.fingerprint,
    this.securityPhase,
  });

  /// Stable opaque contact id used for explicit selection.
  final String id;

  /// Display name.
  final String name;

  /// Safety-fingerprint string shown for verification.
  final String fingerprint;

  /// Fresh V3 status at confirmation time. Null means that no status was proven.
  final String? securityPhase;

  /// Whether every reference field is present and non-empty.
  bool get isWellFormed =>
      id.isNotEmpty && name.isNotEmpty && fingerprint.isNotEmpty;
}

/// Admission snapshot read from the app owner before and after every operation.
///
/// The owner is responsible for keeping this in sync with the real lock,
/// identity and passphrase state; the controller only samples it.
class SystemKeyboardAccessSnapshot {
  /// Creates a snapshot. [stateGeneration] must be monotonic: the owner bumps
  /// it on *any* identity, reload, lock, opt-in or passphrase event, even when
  /// the value changes back to a previous one.
  const SystemKeyboardAccessSnapshot({
    required this.featureOptedIn,
    required this.lockInitialized,
    required this.lockUnlocked,
    required this.lockRequested,
    required this.passphraseActive,
    required this.disposed,
    required this.stateGeneration,
    this.identityContextGeneration,
    this.backgroundDeadline,
  });

  /// Fully denied snapshot (also the value used for a throwing reader).
  const SystemKeyboardAccessSnapshot.denied()
      : featureOptedIn = false,
        lockInitialized = false,
        lockUnlocked = false,
        lockRequested = true,
        passphraseActive = false,
        disposed = true,
        stateGeneration = 0,
        identityContextGeneration = null,
        backgroundDeadline = null;

  /// User enabled the SYSTEM keyboard feature.
  final bool featureOptedIn;

  /// App-lock state has been initialized.
  final bool lockInitialized;

  /// App lock is currently unlocked.
  final bool lockUnlocked;

  /// A lock is being requested; no operation may start.
  final bool lockRequested;

  /// A passphrase is currently active; no operation may start.
  final bool passphraseActive;

  /// The owner has been disposed.
  final bool disposed;

  /// Monotonic generation counter bumped by the owner on every relevant event.
  final int stateGeneration;

  /// Opaque binding to the currently selected ordinary identity. `null` (or
  /// empty) means no ordinary identity is present.
  final String? identityContextGeneration;

  /// Optional absolute monotonic instant after which admission is denied.
  final Duration? backgroundDeadline;

  /// Whether an ordinary identity is bound.
  bool get hasOrdinaryIdentity =>
      identityContextGeneration != null &&
      identityContextGeneration!.isNotEmpty;

  /// Whether a background deadline is configured at all, expired or not.
  bool get hasBackgroundDeadline => backgroundDeadline != null;

  /// Whether every non-time admission flag is satisfied.
  bool get admitsWithoutDeadline =>
      !disposed &&
      featureOptedIn &&
      lockInitialized &&
      lockUnlocked &&
      !lockRequested &&
      hasOrdinaryIdentity &&
      !passphraseActive;
}

/// Opaque handle for one native editor input session.
class SystemKeyboardSession {
  /// Creates a session handle bound to the native editor nonce.
  const SystemKeyboardSession({required this.editorNonce});

  /// Opaque nonce supplied by the native editor for this session.
  final String editorNonce;
}

/// Opaque reference to a prepared-but-not-yet-inserted outbound message.
class SystemKeyboardPendingExport {
  /// Creates the handle.
  const SystemKeyboardPendingExport({required this.pendingId});

  /// Opaque pending id; contains no plaintext and no key material.
  final String pendingId;
}

/// Outcome of [SystemKeyboardController.acknowledgeInsertion].
class SystemKeyboardAcknowledgement {
  /// Creates the outcome.
  const SystemKeyboardAcknowledgement({required this.exported});

  /// Whether the backend was told the outbound was successfully inserted.
  final bool exported;
}

/// Transient authenticated inbound preview.
///
/// Never stored and never logged by the controller; it exists only as the
/// return value of one decode call.
class SystemKeyboardDecodedPreview {
  /// Creates a preview. [text] is plaintext and must not be persisted by the
  /// caller beyond the immediate UI need.
  const SystemKeyboardDecodedPreview({
    required this.contactId,
    required this.contactName,
    required this.fingerprint,
    required this.text,
  });

  /// Authenticated sender id.
  final String contactId;

  /// Authenticated sender display name.
  final String contactName;

  /// Authenticated sender fingerprint.
  final String fingerprint;

  /// Plaintext payload. Transient.
  final String text;
}

/// Fully text-only outbound preparation request.
///
/// There is intentionally no option for message kind, `deleteAfterRead` or
/// `expireAfter`: text with `deleteAfterRead = false` and `expireAfter = null`
/// is the only shape this core can produce.
class SystemKeyboardOutboundRequest {
  /// Creates the request.
  const SystemKeyboardOutboundRequest({
    required this.requestId,
    required this.contactId,
    required this.contactFingerprint,
    required this.text,
    required this.editorNonce,
    required this.inputSessionEpoch,
  });

  /// Caller request id used for replay protection.
  final String requestId;

  /// Recipient id explicitly selected by the user.
  final String contactId;

  /// Recipient fingerprint captured at selection time.
  final String contactFingerprint;

  /// Plaintext body to encrypt. Held only for the duration of the call.
  final String text;

  /// Opaque native editor nonce of the owning session.
  final String editorNonce;

  /// Controller input-session epoch at request time.
  final int inputSessionEpoch;
}

/// Backend result of preparing one text outbound.
class SystemKeyboardBackendExport {
  /// Creates the export description.
  const SystemKeyboardBackendExport({
    required this.exportHandle,
    required this.carriers,
    required this.ciphertextCodeUnits,
  });

  /// Opaque durable export handle owned by the app; used later for ack.
  final String exportHandle;

  /// Encoded carrier(s). The core currently supports exactly one part.
  final List<String> carriers;

  /// Declared size of the produced ciphertext in code units. Advisory only:
  /// the core independently bounds the actual carrier length.
  final int ciphertextCodeUnits;
}

/// Authenticated inbound decode produced by the app owner.
class SystemKeyboardBackendDecoded {
  /// Creates the decoded record.
  const SystemKeyboardBackendDecoded({
    required this.contact,
    required this.text,
    required this.readOnce,
    required this.expired,
    this.hasExpiry = false,
  });

  /// Authenticated sender.
  final SystemKeyboardContact contact;

  /// Authenticated plaintext.
  final String text;

  /// Message self-destructs after being opened in the app.
  final bool readOnce;

  /// Message has already expired.
  final bool expired;

  /// Message carries *any* expiry/deletion schedule, expired or not. The
  /// SYSTEM keyboard preview is only for plain text with no schedule at all.
  final bool hasExpiry;
}

/// Injected owner-side backend. Runs exclusively inside the existing app owner.
///
/// A method-channel adapter is expected to implement this by delegating to the
/// existing V3 chat bridge and history:
/// * [listApprovedContacts] → approved contact repository.
/// * [prepareTextOutbound] → V3 `prepareOutbound` in text mode (durable export).
/// * [markExported] → outbox/history acknowledgement after successful insert.
/// * [decodeCarrier] → carrier decode + V3 ingress authentication.
///
/// The core never sees keys, the database or the wire format.
abstract interface class SystemKeyboardBackend {
  /// Returns the currently approved contacts. Called only for an explicit list
  /// or selection request.
  Future<List<SystemKeyboardContact>> listApprovedContacts();

  /// Prepares one text-only outbound and returns an opaque durable handle plus
  /// its single carrier. Returns `null` when nothing could be prepared. Must
  /// not mark the export as exported.
  Future<SystemKeyboardBackendExport?> prepareTextOutbound(
    SystemKeyboardOutboundRequest request,
  );

  /// Marks a durable export as exported. Called at most once per export.
  Future<void> markExported(String exportHandle);

  /// Decodes a carrier. Returns `null` when there is no authenticated message.
  Future<SystemKeyboardBackendDecoded?> decodeCarrier(String carrier);

  // No mark-read method exists by design.
}

/// Optional presentation-only V3 status lookup for the explicitly selected
/// contact. Implementations must not infer the status from contact metadata.
abstract interface class SystemKeyboardContactSecurityProvider {
  Future<String?> securityPhaseForContact(
    String contactId,
    String fingerprint,
  );
}

/// Single-owner controller for the SYSTEM keyboard bridge.
///
/// Exactly one operation runs at a time; anything else is rejected with
/// [SystemKeyboardFailureCode.busy] (or
/// [SystemKeyboardFailureCode.duplicateRequest] for a reused request id).
///
/// Every operation re-samples the owner's admission snapshot first. Sampling a
/// change – flags, identity generation or `stateGeneration` – revokes the
/// session *before* the operation is considered, so a change that happens
/// between two calls invalidates the second one just as reliably as a change
/// that happens inside an `await`.
class SystemKeyboardController {
  /// Creates the controller.
  ///
  /// [backend] performs all sensitive work. [readAccess] supplies the current
  /// admission snapshot. [monotonicNow] is a monotonic clock in the same origin
  /// as [SystemKeyboardAccessSnapshot.backgroundDeadline].
  ///
  /// Throws [ArgumentError] when [maxRememberedRequestIds] is below 1 (a
  /// zero-capacity replay memory could not reject a replay at all) or when
  /// [maxIdentifierLength] is below 1.
  SystemKeyboardController({
    required SystemKeyboardBackend backend,
    required SystemKeyboardAccessReader readAccess,
    required SystemKeyboardMonotonicNow monotonicNow,
    this.composeLimitCodeUnits = 4000,
    this.ciphertextLimitCodeUnits = 4000,
    this.maxCarrierCodeUnits = systemKeyboardDefaultMaxCarrierCodeUnits,
    this.pendingExportTtl = const Duration(minutes: 2),
    this.maxRememberedRequestIds = 64,
    this.maxIdentifierLength = systemKeyboardDefaultMaxIdentifierLength,
  })  : _backend = backend,
        _readAccess = readAccess,
        _now = monotonicNow {
    if (maxRememberedRequestIds < 1) {
      throw ArgumentError.value(
        maxRememberedRequestIds,
        'maxRememberedRequestIds',
        'must be at least 1 so replays can be rejected',
      );
    }
    if (maxIdentifierLength < 1) {
      throw ArgumentError.value(
        maxIdentifierLength,
        'maxIdentifierLength',
        'must be at least 1',
      );
    }
  }

  final SystemKeyboardBackend _backend;
  final SystemKeyboardAccessReader _readAccess;
  final SystemKeyboardMonotonicNow _now;

  /// Maximum plaintext compose size in UTF-16 code units.
  final int composeLimitCodeUnits;

  /// Maximum accepted declared ciphertext size in UTF-16 code units.
  final int ciphertextLimitCodeUnits;

  /// Maximum accepted inbound carrier length in UTF-16 code units.
  final int maxCarrierCodeUnits;

  /// How long a prepared export stays authorizable.
  final Duration pendingExportTtl;

  /// Bound on remembered request ids per input session. Once the bound is
  /// reached the session fails closed instead of forgetting old ids.
  final int maxRememberedRequestIds;

  /// Bound on caller-supplied opaque identifier lengths.
  final int maxIdentifierLength;

  SystemKeyboardSession? _session;
  int _sessionEpoch = 0;
  int _stateEpoch = 0;
  int _pendingCounter = 0;
  bool _operationInFlight = false;
  bool _disposed = false;
  SystemKeyboardAccessSnapshot _lastObserved =
      const SystemKeyboardAccessSnapshot.denied();
  int? _lastStateGeneration;

  /// Sticky: set when an admission-relevant change, an elapsed deadline, a
  /// non-monotonic clock or a backward generation was observed. Only an
  /// explicit [beginSession] against a currently admitting, monotonic snapshot
  /// clears it.
  bool _stateRevoked = false;
  Duration? _lastObservedNow;
  SystemKeyboardContact? _selectedContact;
  final Map<String, _PendingExport> _pendingExports =
      <String, _PendingExport>{};
  final List<String> _requestIds = <String>[];
  bool _requestIdsSaturated = false;

  /// Currently confirmed recipient, if any. Never inferred from host context,
  /// chat, package or decode sender. Always `null` once the session has been
  /// revoked, so a stale selection can never be observed.
  SystemKeyboardContact? get selectedContact =>
      validateSession() ? _selectedContact : null;

  /// Whether an input session is currently bound to a native editor nonce.
  bool get isSessionActive => validateSession();

  /// Checks a live editor lease without accessing the backend or renewing it.
  bool validateSession() {
    final snapshot = _observe();
    final now = _safeNow();
    if (_disposed ||
        _stateRevoked ||
        _session == null ||
        now == null ||
        !_admits(snapshot, now)) {
      _revokeForAdmissionLoss();
      return false;
    }
    return true;
  }

  /// Whether [dispose] has been called.
  bool get isDisposed => _disposed;

  /// Whether a prepared export is still held (awaiting authorization or ack).
  ///
  /// The core retains at most one carrier at a time.
  bool get hasPendingExport => _pendingExports.isNotEmpty;

  /// Binds a new input session to [editorNonce].
  ///
  /// Synchronous by design: the host reports editor lifecycle events on the
  /// platform thread. Any previous session is torn down. A session that was
  /// revoked by an observed state change requires exactly this call before any
  /// further operation is allowed.
  SystemKeyboardResult<SystemKeyboardSession> beginSession({
    required String editorNonce,
  }) {
    if (!_isValidIdentifier(editorNonce)) {
      return const SystemKeyboardResult<SystemKeyboardSession>.failure(
        SystemKeyboardFailureCode.invalidRequest,
      );
    }
    final SystemKeyboardAccessSnapshot snapshot = _observe();
    final Duration? now = _safeNow();
    if (_disposed ||
        now == null ||
        _operationInFlight ||
        !_admits(snapshot, now)) {
      _stateRevoked = true;
      _teardown();
      return const SystemKeyboardResult<SystemKeyboardSession>.failure(
        SystemKeyboardFailureCode.unavailable,
      );
    }
    // This call is the explicit re-admission that a revocation requires.
    _stateRevoked = false;
    _teardown();
    final SystemKeyboardSession session = SystemKeyboardSession(
      editorNonce: editorNonce,
    );
    _session = session;
    return SystemKeyboardResult<SystemKeyboardSession>.success(session);
  }

  /// Ends the input session. Clears selection, pending exports and request-id
  /// memory, and synchronously invalidates results of in-flight operations.
  void endSession() => _teardown();

  /// Revokes everything: same teardown as [endSession], intended for lock,
  /// identity or passphrase state events reported by the owner.
  void revoke() {
    _stateRevoked = true;
    _teardown();
  }

  /// Tears down and permanently closes this controller.
  void dispose() {
    _disposed = true;
    _stateRevoked = true;
    _teardown();
  }

  /// Lists approved contacts. Only explicit calls read the contact store.
  Future<SystemKeyboardResult<List<SystemKeyboardContact>>> listContacts({
    required String requestId,
  }) async {
    final SystemKeyboardResult<List<SystemKeyboardContact>>? rejected =
        _preflight<List<SystemKeyboardContact>>(requestId);
    if (rejected != null) {
      return rejected;
    }
    final int stateEpoch = _stateEpoch;
    final int sessionEpoch = _sessionEpoch;
    try {
      final List<SystemKeyboardContact> contacts = _wellFormed(
        await _backend.listApprovedContacts(),
      );
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<List<SystemKeyboardContact>>();
      }
      return SystemKeyboardResult<List<SystemKeyboardContact>>.success(
        List<SystemKeyboardContact>.unmodifiable(contacts),
      );
    } catch (_) {
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<List<SystemKeyboardContact>>();
      }
      return const SystemKeyboardResult<List<SystemKeyboardContact>>.failure(
        SystemKeyboardFailureCode.backendError,
      );
    } finally {
      _release();
    }
  }

  /// Binds a recipient. Requires `confirm == true` and an explicit [contactId]
  /// present in a *freshly fetched* approved contact list.
  Future<SystemKeyboardResult<SystemKeyboardContact>> selectContact({
    required String requestId,
    required String contactId,
    required bool confirm,
  }) async {
    final SystemKeyboardResult<SystemKeyboardContact>? rejected =
        _preflight<SystemKeyboardContact>(requestId);
    if (rejected != null) {
      return rejected;
    }
    if (!_isValidIdentifier(contactId) || !confirm) {
      _release();
      return const SystemKeyboardResult<SystemKeyboardContact>.failure(
        SystemKeyboardFailureCode.invalidSelection,
      );
    }
    final int stateEpoch = _stateEpoch;
    final int sessionEpoch = _sessionEpoch;
    try {
      final List<SystemKeyboardContact> contacts = _wellFormed(
        await _backend.listApprovedContacts(),
      );
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<SystemKeyboardContact>();
      }
      final List<SystemKeyboardContact> matches = contacts
          .where((SystemKeyboardContact contact) => contact.id == contactId)
          .toList(growable: false);
      if (matches.length != 1) {
        return const SystemKeyboardResult<SystemKeyboardContact>.failure(
          SystemKeyboardFailureCode.invalidSelection,
        );
      }
      final match = matches.single;
      String? securityPhase;
      if (_backend is SystemKeyboardContactSecurityProvider) {
        securityPhase =
            await (_backend as SystemKeyboardContactSecurityProvider)
                .securityPhaseForContact(match.id, match.fingerprint);
        if (!_stillValid(stateEpoch, sessionEpoch)) {
          return _unavailable<SystemKeyboardContact>();
        }
      }
      final selected = SystemKeyboardContact(
        id: match.id,
        name: match.name,
        fingerprint: match.fingerprint,
        securityPhase: securityPhase,
      );
      _pendingExports.clear();
      _selectedContact = selected;
      return SystemKeyboardResult<SystemKeyboardContact>.success(
        selected,
      );
    } catch (_) {
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<SystemKeyboardContact>();
      }
      return const SystemKeyboardResult<SystemKeyboardContact>.failure(
        SystemKeyboardFailureCode.backendError,
      );
    } finally {
      _release();
    }
  }

  /// Prepares a text-only outbound. Returns only an opaque pending id; no
  /// carrier and no plaintext leaves this call, and nothing is marked exported.
  ///
  /// At most one unconsumed pending export exists per session: a second prepare
  /// is rejected with [SystemKeyboardFailureCode.unsupportedExport] until the
  /// current one is authorized away, acknowledged, or expires, so the core
  /// never retains more than one ciphertext.
  ///
  /// A pending export created by the backend but rejected here is left durable
  /// in the app so it can be recovered, and is never marked exported.
  Future<SystemKeyboardResult<SystemKeyboardPendingExport>> prepareText({
    required String requestId,
    required String text,
  }) async {
    final SystemKeyboardResult<SystemKeyboardPendingExport>? rejected =
        _preflight<SystemKeyboardPendingExport>(requestId);
    if (rejected != null) {
      return rejected;
    }
    final SystemKeyboardSession? session = _session;
    final SystemKeyboardContact? selected = _selectedContact;
    if (session == null) {
      _release();
      return _unavailable<SystemKeyboardPendingExport>();
    }
    if (selected == null) {
      _release();
      return const SystemKeyboardResult<SystemKeyboardPendingExport>.failure(
        SystemKeyboardFailureCode.invalidSelection,
      );
    }
    if (text.isEmpty) {
      _release();
      return const SystemKeyboardResult<SystemKeyboardPendingExport>.failure(
        SystemKeyboardFailureCode.invalidRequest,
      );
    }
    if (text.length > composeLimitCodeUnits) {
      _release();
      return const SystemKeyboardResult<SystemKeyboardPendingExport>.failure(
        SystemKeyboardFailureCode.oversize,
      );
    }
    final preparedNow = _safeNow();
    if (preparedNow == null) {
      _revokeForAdmissionLoss();
      _release();
      return _unavailable<SystemKeyboardPendingExport>();
    }
    _pendingExports.removeWhere(
      (_, pending) => preparedNow - pending.createdAt >= pendingExportTtl,
    );
    if (_pendingExports.isNotEmpty) {
      _release();
      return const SystemKeyboardResult<SystemKeyboardPendingExport>.failure(
        SystemKeyboardFailureCode.unsupportedExport,
      );
    }
    final int stateEpoch = _stateEpoch;
    final int sessionEpoch = _sessionEpoch;
    try {
      final SystemKeyboardBackendExport? export =
          await _backend.prepareTextOutbound(
        SystemKeyboardOutboundRequest(
          requestId: requestId,
          contactId: selected.id,
          contactFingerprint: selected.fingerprint,
          text: text,
          editorNonce: session.editorNonce,
          inputSessionEpoch: sessionEpoch,
        ),
      );
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<SystemKeyboardPendingExport>();
      }
      final SystemKeyboardFailureCode? unusable = _unusableExport(
        export,
        ciphertextLimitCodeUnits,
      );
      if (unusable != null) {
        return SystemKeyboardResult<SystemKeyboardPendingExport>.failure(
          unusable,
        );
      }
      if (export!.carriers.length != 1) {
        return const SystemKeyboardResult<SystemKeyboardPendingExport>.failure(
          SystemKeyboardFailureCode.unsupportedExport,
        );
      }
      final String pendingId = 'skp${_pendingCounter++}';
      final Duration? preparedAt = _safeNow();
      if (preparedAt == null) {
        _revokeForAdmissionLoss();
        return _unavailable<SystemKeyboardPendingExport>();
      }
      _pendingExports[pendingId] = _PendingExport(
        exportHandle: export.exportHandle,
        carrier: export.carriers.single,
        createdAt: preparedAt,
      );
      return SystemKeyboardResult<SystemKeyboardPendingExport>.success(
        SystemKeyboardPendingExport(pendingId: pendingId),
      );
    } catch (_) {
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<SystemKeyboardPendingExport>();
      }
      return const SystemKeyboardResult<SystemKeyboardPendingExport>.failure(
        SystemKeyboardFailureCode.backendError,
      );
    } finally {
      _release();
    }
  }

  /// Explicitly authorizes insertion of a prepared outbound.
  ///
  /// Authorizing is one-shot per pending: the carrier is returned at most once,
  /// so a second call – even with a fresh [requestId] – fails with
  /// [SystemKeyboardFailureCode.noPendingExport]. The pending id is consumed
  /// *before* anything else can observe it. Returns the already-encrypted
  /// carrier only while the pending export is fresh (within [pendingExportTtl])
  /// and access is still admitted. Never returns plaintext.
  Future<SystemKeyboardResult<String>> authorizeInsertion({
    required String requestId,
    required String pendingId,
  }) async {
    final SystemKeyboardResult<String>? rejected = _preflight<String>(
      requestId,
    );
    if (rejected != null) {
      return rejected;
    }
    final int stateEpoch = _stateEpoch;
    final int sessionEpoch = _sessionEpoch;
    try {
      if (!_isValidIdentifier(pendingId)) {
        return const SystemKeyboardResult<String>.failure(
          SystemKeyboardFailureCode.noPendingExport,
        );
      }
      final _PendingExport? pending = _pendingExports[pendingId];
      if (pending == null || pending.acknowledged || pending.authorized) {
        return const SystemKeyboardResult<String>.failure(
          SystemKeyboardFailureCode.noPendingExport,
        );
      }
      final Duration? now = _safeNow();
      if (now == null) {
        _revokeForAdmissionLoss();
        return _unavailable<String>();
      }
      if (now - pending.createdAt >= pendingExportTtl) {
        _pendingExports.remove(pendingId);
        return const SystemKeyboardResult<String>.failure(
          SystemKeyboardFailureCode.noPendingExport,
        );
      }
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<String>();
      }
      pending.authorized = true;
      return SystemKeyboardResult<String>.success(pending.carrier);
    } finally {
      _release();
    }
  }

  /// Reports the native insertion outcome and marks the export exported only
  /// once, and only when [commitText] is `true`.
  ///
  /// The pending id is consumed before the backend call: a repeated
  /// acknowledgement can never mark the same export twice even when
  /// [SystemKeyboardBackend.markExported] throws *after* the durable marking
  /// already happened. The acknowledgement deadline is checked like the
  /// authorization deadline, so a stale pending can never reach the backend.
  ///
  /// If access is invalidated before [SystemKeyboardBackend.markExported] is
  /// invoked, the call is suppressed and nothing is marked. If invalidation
  /// happens while the backend call is already running, the result is
  /// suppressed but the durable app-owned operation is allowed to finish: this
  /// core cannot cancel or zeroize it, and makes no such promise.
  Future<SystemKeyboardResult<SystemKeyboardAcknowledgement>>
      acknowledgeInsertion({
    required String requestId,
    required String pendingId,
    required bool commitText,
  }) async {
    final SystemKeyboardResult<SystemKeyboardAcknowledgement>? rejected =
        _preflight<SystemKeyboardAcknowledgement>(requestId);
    if (rejected != null) {
      return rejected;
    }
    final int stateEpoch = _stateEpoch;
    final int sessionEpoch = _sessionEpoch;
    try {
      if (!_isValidIdentifier(pendingId)) {
        return const SystemKeyboardResult<
                SystemKeyboardAcknowledgement>.failure(
            SystemKeyboardFailureCode.noPendingExport);
      }
      final _PendingExport? pending = _pendingExports[pendingId];
      if (pending == null || pending.acknowledged || !pending.authorized) {
        return const SystemKeyboardResult<
                SystemKeyboardAcknowledgement>.failure(
            SystemKeyboardFailureCode.noPendingExport);
      }
      final Duration? now = _safeNow();
      if (now == null) {
        _revokeForAdmissionLoss();
        return _unavailable<SystemKeyboardAcknowledgement>();
      }
      if (now - pending.createdAt >= pendingExportTtl) {
        _pendingExports.remove(pendingId);
        return const SystemKeyboardResult<
                SystemKeyboardAcknowledgement>.failure(
            SystemKeyboardFailureCode.noPendingExport);
      }
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<SystemKeyboardAcknowledgement>();
      }
      if (!commitText) {
        pending.acknowledged = true;
        _pendingExports.remove(pendingId);
        return const SystemKeyboardResult<
                SystemKeyboardAcknowledgement>.success(
            SystemKeyboardAcknowledgement(exported: false));
      }
      // Consume before the await: whether the backend throws before or after
      // the durable marking, this pending can never be marked again.
      pending.acknowledged = true;
      _pendingExports.remove(pendingId);
      await _backend.markExported(pending.exportHandle);
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<SystemKeyboardAcknowledgement>();
      }
      return const SystemKeyboardResult<SystemKeyboardAcknowledgement>.success(
        SystemKeyboardAcknowledgement(exported: true),
      );
    } catch (_) {
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<SystemKeyboardAcknowledgement>();
      }
      return const SystemKeyboardResult<SystemKeyboardAcknowledgement>.failure(
        SystemKeyboardFailureCode.backendError,
      );
    } finally {
      _release();
    }
  }

  /// Authenticates and previews an inbound carrier.
  ///
  /// Any self-destruct schedule – read-once, already expired, or merely
  /// carrying an expiry – is reported as
  /// [SystemKeyboardFailureCode.openAppRequired] with no plaintext and no
  /// sender metadata. Unrecognized, empty or oversize input and missing data all
  /// collapse into [SystemKeyboardFailureCode.noMessage]. Nothing is ever marked
  /// read and the selected recipient is never changed by a decode.
  Future<SystemKeyboardResult<SystemKeyboardDecodedPreview>> decodeCarrier({
    required String requestId,
    required String carrier,
  }) async {
    final SystemKeyboardResult<SystemKeyboardDecodedPreview>? rejected =
        _preflight<SystemKeyboardDecodedPreview>(requestId);
    if (rejected != null) {
      return rejected;
    }
    final int stateEpoch = _stateEpoch;
    final int sessionEpoch = _sessionEpoch;
    try {
      if (carrier.isEmpty || carrier.length > maxCarrierCodeUnits) {
        return const SystemKeyboardResult<SystemKeyboardDecodedPreview>.failure(
          SystemKeyboardFailureCode.noMessage,
        );
      }
      final SystemKeyboardBackendDecoded? decoded =
          await _backend.decodeCarrier(carrier);
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<SystemKeyboardDecodedPreview>();
      }
      if (decoded == null ||
          !decoded.contact.isWellFormed ||
          decoded.text.isEmpty) {
        return const SystemKeyboardResult<SystemKeyboardDecodedPreview>.failure(
          SystemKeyboardFailureCode.noMessage,
        );
      }
      if (decoded.readOnce || decoded.expired || decoded.hasExpiry) {
        return const SystemKeyboardResult<SystemKeyboardDecodedPreview>.failure(
          SystemKeyboardFailureCode.openAppRequired,
        );
      }
      return SystemKeyboardResult<SystemKeyboardDecodedPreview>.success(
        SystemKeyboardDecodedPreview(
          contactId: decoded.contact.id,
          contactName: decoded.contact.name,
          fingerprint: decoded.contact.fingerprint,
          text: decoded.text,
        ),
      );
    } catch (_) {
      if (!_stillValid(stateEpoch, sessionEpoch)) {
        return _unavailable<SystemKeyboardDecodedPreview>();
      }
      // No oracle: backend decode failures look exactly like "no message".
      return const SystemKeyboardResult<SystemKeyboardDecodedPreview>.failure(
        SystemKeyboardFailureCode.noMessage,
      );
    } finally {
      _release();
    }
  }

  // ── internals ──────────────────────────────────────────────────────────────

  SystemKeyboardResult<T>? _preflight<T>(String requestId) {
    if (!_isValidIdentifier(requestId)) {
      return SystemKeyboardResult<T>.failure(
        SystemKeyboardFailureCode.invalidRequest,
      );
    }
    final SystemKeyboardAccessSnapshot snapshot = _observe();
    if (_disposed || _stateRevoked || _session == null) {
      return _unavailable<T>();
    }
    if (_requestIds.contains(requestId)) {
      return SystemKeyboardResult<T>.failure(
        SystemKeyboardFailureCode.duplicateRequest,
      );
    }
    if (_operationInFlight) {
      return SystemKeyboardResult<T>.failure(SystemKeyboardFailureCode.busy);
    }
    final Duration? now = _safeNow();
    if (now == null || !_admits(snapshot, now)) {
      // Sampling a denial (including an elapsed deadline) revokes for good.
      _revokeForAdmissionLoss();
      return _unavailable<T>();
    }
    if (_requestIdsSaturated) {
      // Old ids are never forgotten: at capacity the session fails closed until
      // the host begins a new one. Failing here keeps the memory bounded.
      return SystemKeyboardResult<T>.failure(
        SystemKeyboardFailureCode.duplicateRequest,
      );
    }
    _requestIds.add(requestId);
    if (_requestIds.length >= maxRememberedRequestIds) {
      _requestIdsSaturated = true;
    }
    _operationInFlight = true;
    return null;
  }

  void _release() => _operationInFlight = false;

  void _teardown() {
    _session = null;
    _sessionEpoch++;
    _selectedContact = null;
    // Consuming pending entries invalidates any in-flight acknowledge so the
    // core can never report a second marking.
    for (final _PendingExport pending in _pendingExports.values) {
      pending.acknowledged = true;
    }
    _pendingExports.clear();
    _requestIds.clear();
    _requestIdsSaturated = false;
  }

  /// Revokes permanently after an admission loss observed between two calls.
  void _revokeForAdmissionLoss() {
    _stateRevoked = true;
    _teardown();
  }

  bool _admits(SystemKeyboardAccessSnapshot snapshot, Duration now) {
    if (!snapshot.admitsWithoutDeadline) {
      return false;
    }
    if (snapshot.backgroundDeadline != null) {
      if (now >= snapshot.backgroundDeadline!) {
        return false;
      }
      return true;
    }
    return true;
  }

  bool _stillValid(int stateEpoch, int sessionEpoch) {
    final SystemKeyboardAccessSnapshot snapshot = _observe();
    if (_disposed ||
        _stateRevoked ||
        _session == null ||
        _sessionEpoch != sessionEpoch ||
        _stateEpoch != stateEpoch) {
      return false;
    }
    final Duration? now = _safeNow();
    if (now == null) {
      _stateRevoked = true;
      _teardown();
      return false;
    }
    if (!_admits(snapshot, now)) {
      _stateRevoked = true;
      _teardown();
      return false;
    }
    return true;
  }

  /// Samples the owner state. Any admission-relevant change – or any advance of
  /// the owner's monotonic `stateGeneration`, which catches change-away-and-back
  /// – synchronously tears the active session down and marks every operation
  /// (in flight or not) invalid until [beginSession] is called again.
  ///
  /// The generation is also required to be monotonic: a decrease fails closed.
  SystemKeyboardAccessSnapshot _observe() {
    SystemKeyboardAccessSnapshot snapshot;
    try {
      snapshot = _readAccess();
    } catch (_) {
      snapshot = const SystemKeyboardAccessSnapshot.denied();
    }
    final bool changed = _lastStateGeneration == null ||
        snapshot.stateGeneration != _lastStateGeneration ||
        !_sameAdmissionState(snapshot, _lastObserved);
    _lastObserved = snapshot;
    if (_lastStateGeneration != null &&
        snapshot.stateGeneration < _lastStateGeneration!) {
      // The owner's generation must never move backwards; treat it as a
      // revocation rather than trusting a replayed epoch.
      _stateRevoked = true;
      _teardown();
    }
    _lastStateGeneration = snapshot.stateGeneration;
    if (changed) {
      _stateEpoch++;
      if (_session != null) {
        _stateRevoked = true;
        _teardown();
      }
    }
    return snapshot;
  }

  /// Reads the injected monotonic clock. A throwing clock yields `null`, which
  /// every caller treats as a denial; no cached or fallback instant is used.
  Duration? _safeNow() {
    Duration now;
    try {
      now = _now();
    } catch (_) {
      return null;
    }
    final Duration? previous = _lastObservedNow;
    if (previous != null && now < previous) {
      // A clock that moved backwards can no longer bound any deadline.
      return null;
    }
    _lastObservedNow = now;
    return now;
  }

  bool _isValidIdentifier(String value) =>
      value.trim().isNotEmpty && value.length <= maxIdentifierLength;

  /// Classifies a backend export. The declared ciphertext size is advisory: the
  /// actual carrier length is bounded here as well, because the backend is the
  /// only place the cipher is authenticated and the core must not hand an
  /// unbounded string to the native layer.
  static SystemKeyboardFailureCode? _unusableExport(
    SystemKeyboardBackendExport? export,
    int ciphertextLimit,
  ) {
    if (export == null || export.exportHandle.isEmpty) {
      return SystemKeyboardFailureCode.unsupportedExport;
    }
    if (export.carriers.isEmpty ||
        export.carriers.any((String carrier) => carrier.isEmpty)) {
      return SystemKeyboardFailureCode.unsupportedExport;
    }
    if (export.ciphertextCodeUnits <= 0) {
      // A real ciphertext is never empty; a non-positive claim is malformed.
      return SystemKeyboardFailureCode.unsupportedExport;
    }
    if (export.ciphertextCodeUnits > ciphertextLimit) {
      return SystemKeyboardFailureCode.oversize;
    }
    if (export.carriers.any(
      (String carrier) => carrier.length > ciphertextLimit,
    )) {
      // The actual carrier must fit too; a small declared size is not proof.
      return SystemKeyboardFailureCode.oversize;
    }
    return null;
  }

  static bool _sameAdmissionState(
    SystemKeyboardAccessSnapshot a,
    SystemKeyboardAccessSnapshot b,
  ) =>
      a.featureOptedIn == b.featureOptedIn &&
      a.lockInitialized == b.lockInitialized &&
      a.lockUnlocked == b.lockUnlocked &&
      a.lockRequested == b.lockRequested &&
      a.passphraseActive == b.passphraseActive &&
      a.disposed == b.disposed &&
      a.identityContextGeneration == b.identityContextGeneration &&
      a.backgroundDeadline == b.backgroundDeadline;

  static List<SystemKeyboardContact> _wellFormed(
    List<SystemKeyboardContact> contacts,
  ) =>
      contacts
          .where((SystemKeyboardContact contact) => contact.isWellFormed)
          .toList(growable: false);

  static SystemKeyboardResult<T> _unavailable<T>() =>
      SystemKeyboardResult<T>.failure(SystemKeyboardFailureCode.unavailable);
}

class _PendingExport {
  _PendingExport({
    required this.exportHandle,
    required this.carrier,
    required this.createdAt,
  });

  final String exportHandle;
  final String carrier;
  final Duration createdAt;
  bool authorized = false;
  bool acknowledged = false;
}
