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

/// Pure request router for one **externally authenticated** keyboard runtime.
///
/// This library is deliberately narrow. It is created only from a grant the
/// native host already authenticated and it can never read storage, request a
/// grant, renew one or restart itself. It owns no key material, no plaintext
/// source (host/surrounding text/clipboard) and no crypto: every sensitive
/// operation is delegated to the existing [SystemKeyboardController], whose
/// recipient selection, wire format and admission rules are reused unchanged.
///
/// Its whole purpose is to bind that controller to one editor nonce
/// ([editorNonce]) and one inactivity window ([authorizedIdleMillis]):
///
/// * `begin` is accepted exactly once, for the constructor's exact nonce, so a
///   second `begin` can never reset or renew the window;
/// * `heartbeat` only validates: it never renews anything and reports
///   `processingMillis == 0`;
/// * an [SystemKeyboardIdleSession] started once at construction is the
///   authority for [isAuthorized]. Because the controller's access snapshot has
///   no `backgroundDeadline`, idle denial is expressed through
///   `lockUnlocked: isAuthorized`, which the controller already samples before
///   and after every operation;
/// * [recordUserInteraction] is reserved for native code that has already
///   validated an intentional physical touch. No request field, poll,
///   heartbeat or backend mutation can reach it.
///
/// Contract with the native host: every success result is only a *candidate*.
/// The native extension **must** independently revalidate its own grant
/// immediately before displaying or inserting any returned data; this class
/// cannot see OS lock, keyboard visibility, capture or Full Access state.
///
/// This is an independent pure router, not an integration with the restricted
/// V3 runtime: it never loads that runtime and never claims delivery.
library;

import 'system_keyboard_controller.dart';
import 'system_keyboard_idle_policy.dart';

/// Monotonic clock shared by this router, in the same origin as
/// [SystemKeyboardIdleSession] readings. Must never move backwards.
typedef SystemKeyboardRuntimeMonotonicNow = Duration Function();

/// Status of one externally authenticated keyboard runtime.
///
/// The strings are exactly the channel contract used by
/// `SystemKeyboardAppService`; they are redeclared locally so this file stays a
/// pure-Dart library with no Flutter/plugin/Riverpod dependency.
abstract final class SystemKeyboardRuntimeStatus {
  /// Success.
  static const String ok = 'ok';

  /// Every denial: closed session, elapsed idle window, wrong nonce, missing
  /// native authorization or an invalidated in-flight operation.
  static const String unavailable = 'unavailable';

  /// Another operation owns the controller.
  static const String busy = 'busy';

  /// The `requestId` was already used in this input session.
  static const String duplicateRequest = 'duplicateRequest';

  /// Malformed or oversized request shape.
  static const String invalidRequest = 'invalidRequest';

  /// No confirmed, freshly approved recipient is bound.
  static const String invalidSelection = 'invalidSelection';

  /// The controller refused to hold the prepared outbound.
  static const String unsupportedExport = 'unsupportedExport';

  /// A size bound was exceeded.
  static const String oversize = 'oversize';

  /// Unknown, stale or already consumed pending id.
  static const String noPendingExport = 'noPendingExport';

  /// No authenticated inbound message.
  static const String noMessage = 'noMessage';

  /// Inbound message self-destructs; only the full app may open it.
  static const String openAppRequired = 'openAppRequired';

  /// The backend failed while access was still valid.
  static const String backendError = 'backendError';
}

/// One request-router session over the existing controller.
///
/// The constructor throws [ArgumentError] for a malformed identity, nonce or
/// idle duration, so a caller cannot start a session with an unbounded window.
final class SystemKeyboardRuntimeSession {
  /// Starts a session from an already authenticated native grant.
  ///
  /// [identityId] and [editorNonce] are bounded opaque references (nonempty,
  /// at most 128 code units). [authorizedIdleMillis] is the fixed inactivity
  /// window (1..300000 ms) used once at construction. [monotonicNow] supplies
  /// every idle reading; [nativeIsAuthorized] revalidates the current
  /// FullAccess/editor/capture/epoch grant on the native side and is awaited
  /// before and after every async sensitive operation.
  SystemKeyboardRuntimeSession({
    required SystemKeyboardBackend backend,
    required this.identityId,
    required String editorNonce,
    required int authorizedIdleMillis,
    required SystemKeyboardRuntimeMonotonicNow monotonicNow,
    required Future<bool> Function() nativeIsAuthorized,
    bool scramble = false,
  })  : _editorNonce = editorNonce,
        _backend = backend,
        _nativeIsAuthorized = nativeIsAuthorized,
        _now = monotonicNow,
        _scramble = scramble {
    _checkIdentifier(identityId, 'identityId');
    _checkIdentifier(editorNonce, 'editorNonce');
    if (authorizedIdleMillis < 1 || authorizedIdleMillis > maxIdleMillis) {
      throw ArgumentError.value(
        authorizedIdleMillis,
        'authorizedIdleMillis',
        'must be between 1 and $maxIdleMillis',
      );
    }
    final Duration start;
    try {
      start = monotonicNow();
    } catch (_) {
      throw ArgumentError.value(
        monotonicNow,
        'monotonicNow',
        'must be callable at construction',
      );
    }
    final SystemKeyboardIdleSession? idle = SystemKeyboardIdleSession.start(
      startMonotonicMillis: start.inMilliseconds,
      authorizedDurationMillis: authorizedIdleMillis,
    );
    if (idle == null) {
      throw ArgumentError.value(
        start,
        'monotonicNow',
        'must return a nonnegative monotonic reading',
      );
    }
    _idle = idle;
    _authorizedIdleMillis = authorizedIdleMillis;
    _controller = _newController();
    _lastObserved = start;
    _observeIdle(start);
  }

  /// Upper bound of the accepted inactivity window.
  static const int maxIdleMillis = 300000;

  /// Upper bound of any identifier accepted by this router.
  static const int maxIdentifierLength = 128;

  /// Ceiling the granted native lease can never exceed.
  static const int maxLeaseMillis = 1000;

  /// Conservative elapsed-time ceiling used when the clock is unusable.
  static const int maxProcessingMillis = 30000;

  /// Opaque reference to the grant's ordinary identity. Never used to look up
  /// storage; only projected into the controller's access snapshot.
  final String identityId;

  /// The current editor nonce. Rebinding clears all editor-local state while
  /// preserving the original native grant and its inactivity deadline.
  String get editorNonce => _editorNonce;
  String _editorNonce;
  final SystemKeyboardBackend _backend;

  final SystemKeyboardRuntimeMonotonicNow _now;
  final Future<bool> Function() _nativeIsAuthorized;
  final bool _scramble;

  late final SystemKeyboardIdleSession _idle;
  late final int _authorizedIdleMillis;
  late SystemKeyboardController _controller;

  SystemKeyboardController _newController() => SystemKeyboardController(
        backend: _backend,
        readAccess: _accessSnapshot,
        monotonicNow: _now,
        ciphertextLimitCodeUnits:
            systemKeyboardAutonomousMaxOutboundCarrierCodeUnits,
      );

  /// Binds a fresh host editor inside the same live native custody grant.
  /// No touch is synthesized and neither native nor Dart inactivity is renewed.
  /// The old recipient, preview, pending handle and request IDs are discarded.
  Future<bool> rebindEditor(String newNonce) async {
    if (!_isIdentifier(newNonce) ||
        newNonce == _editorNonce ||
        !_started ||
        _closed ||
        !await _recheckNative()) {
      return false;
    }
    _controller.dispose();
    _editorNonce = newNonce;
    _controller = _newController();
    _started = false;
    return isAuthorized;
  }

  SystemKeyboardIdleObservation? _lastIdle;
  Duration _lastObserved = Duration.zero;
  bool _started = false;
  bool _closed = false;
  bool _nativeChecked = false;
  bool _disposed = false;

  /// Whether the window is still usable: nonclosed and idle-active.
  ///
  /// A clock that throws or moves backwards closes the session permanently.
  bool get isAuthorized {
    if (_closed) return false;
    Duration now;
    try {
      now = _now();
    } catch (_) {
      close();
      return false;
    }
    final bool active = _observeIdle(now).isActive;
    if (!active) close();
    return active;
  }

  /// Last observed absolute monotonic idle deadline, or `null` before the
  /// first observation.
  int? get deadlineMonotonicMillis => _lastIdle?.deadlineMonotonicMillis;

  /// Idle milliseconds left, or `0` once the window is terminal.
  int get remainingIdleMillis => _lastIdle?.remainingMillis ?? 0;

  /// Whether [close] has been called or the window was lost.
  bool get isClosed => _closed;

  /// Whether the native authorization callback was used at least once.
  bool get hasNativeAuthorization => _nativeChecked;

  /// Reports one intentional physical native touch.
  ///
  /// Renews only an already active window, using the current monotonic clock,
  /// and returns whether the window is usable afterwards. A poll, heartbeat,
  /// backend mutation or request field must never call this.
  bool recordUserInteraction() {
    if (_closed) return false;
    Duration now;
    try {
      now = _now();
    } catch (_) {
      close();
      return false;
    }
    final SystemKeyboardIdleObservation? previous = _lastIdle;
    if (previous != null && now < _lastObserved) {
      close();
      return false;
    }
    final SystemKeyboardIdleObservation renewed =
        _idle.recordUserInteraction(now.inMilliseconds);
    _lastObserved = now;
    _lastIdle = renewed;
    if (!renewed.isActive) {
      close();
      return false;
    }
    return true;
  }

  /// Permanently closes this router: the idle window is revoked and the
  /// controller disposed. Idempotent, synchronous and never recreates state.
  void close() {
    if (_disposed) return;
    _disposed = true;
    _closed = true;
    _idle.revoke();
    _lastIdle = null;
    try {
      _controller.dispose();
    } catch (_) {
      // Disposal is best effort; the window is already revoked.
    }
  }

  /// Routes one native `request` call. Never throws.
  Future<Map<String, Object?>> handleRequest(
    Map<Object?, Object?> arguments,
  ) async {
    final Object? operationRaw = arguments['operation'];
    final Object? nonceRaw = arguments['editorNonce'];
    final Object? requestIdRaw = arguments['requestId'];
    if (operationRaw is! String ||
        !_isIdentifier(nonceRaw) ||
        !_isIdentifier(requestIdRaw)) {
      return _failure(SystemKeyboardRuntimeStatus.invalidRequest);
    }
    final String operation = operationRaw;
    final String nonce = nonceRaw! as String;
    final String requestId = requestIdRaw! as String;

    // `end` must stay able to tear down its own editor even while denied, and
    // must never close a newer or foreign editor.
    if (operation == 'end') return _handleEnd(nonce);
    if (operation == 'begin') {
      if (nonce != editorNonce || !await _recheckNative()) {
        return _failure(SystemKeyboardRuntimeStatus.unavailable);
      }
      return _handleBegin(nonce);
    }
    if (nonce != editorNonce || _closed) {
      close();
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    final Duration? entry = _safeNow();
    if (entry == null) {
      close();
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    if (operation == 'heartbeat') {
      // Validation only: no backend access, no request-id memory, no renewal
      // and deliberately no idle sampling that could renew the window.
      if (!await _recheckNative() ||
          !_controller.validateSession() ||
          !isAuthorized) {
        return _failure(SystemKeyboardRuntimeStatus.unavailable);
      }
      return _success(
        data: const <String, Object?>{},
        entry: entry,
        heartbeat: true,
      );
    }
    return _dispatch(operation, requestId, arguments, entry);
  }

  // ── operations ────────────────────────────────────────────────────────────

  Map<String, Object?> _handleBegin(String nonce) {
    if (nonce != editorNonce) {
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    if (_started || _closed) {
      // A session already exists for this grant: a second begin must never
      // reset request-id memory, pending exports or the idle window.
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    final Duration? entry = _safeNow();
    if (entry == null || !isAuthorized) {
      close();
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    final SystemKeyboardResult<SystemKeyboardSession> result =
        _controller.beginSession(editorNonce: editorNonce);
    if (result.isFailure) {
      close();
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    _started = true;
    return _success(
      data: <String, Object?>{
        'scramble': _scramble,
        'idleMillis': _authorizedIdleMillis
      },
      entry: entry,
      heartbeat: false,
    );
  }

  Map<String, Object?> _handleEnd(String nonce) {
    if (nonce != editorNonce) {
      // Another editor cannot terminate this session.
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    final Duration? entry = _safeNow();
    close();
    return <String, Object?>{
      'status': SystemKeyboardRuntimeStatus.ok,
      'processingMillis': entry == null ? 0 : _processingMillis(entry),
      'leaseMillis': 1,
      'data': const <String, Object?>{},
    };
  }

  Future<Map<String, Object?>> _dispatch(
    String operation,
    String requestId,
    Map<Object?, Object?> arguments,
    Duration entry,
  ) {
    switch (operation) {
      case 'contacts':
        return _runCore<List<SystemKeyboardContact>>(
          entry: entry,
          call: () => _controller.listContacts(requestId: requestId),
          toData: _contactsData,
        );
      case 'select':
        final Object? contactId = arguments['contactId'];
        final Object? confirm = arguments['confirm'];
        if (contactId is! String || confirm is! bool) {
          return Future<Map<String, Object?>>.value(
            _failure(SystemKeyboardRuntimeStatus.invalidRequest),
          );
        }
        return _runCore<SystemKeyboardContact>(
          entry: entry,
          call: () => _controller.selectContact(
            requestId: requestId,
            contactId: contactId,
            confirm: confirm,
          ),
          toData: _contactData,
        );
      case 'prepare':
        final Object? text = arguments['text'];
        if (text is! String) {
          return Future<Map<String, Object?>>.value(
            _failure(SystemKeyboardRuntimeStatus.invalidRequest),
          );
        }
        return _runCore<SystemKeyboardPendingExport>(
          entry: entry,
          call: () => _controller.prepareText(
            requestId: requestId,
            text: text,
          ),
          toData: (SystemKeyboardPendingExport pending) =>
              <String, Object?>{'pendingId': pending.pendingId},
        );
      case 'authorize':
        final Object? pendingId = arguments['pendingId'];
        if (pendingId is! String) {
          return Future<Map<String, Object?>>.value(
            _failure(SystemKeyboardRuntimeStatus.invalidRequest),
          );
        }
        return _runCore<String>(
          entry: entry,
          call: () => _controller.authorizeInsertion(
            requestId: requestId,
            pendingId: pendingId,
          ),
          toData: (String carrier) => <String, Object?>{'carrier': carrier},
        );
      case 'ack':
        final Object? pendingId = arguments['pendingId'];
        final Object? commitText = arguments['commitText'];
        if (pendingId is! String || commitText is! bool) {
          return Future<Map<String, Object?>>.value(
            _failure(SystemKeyboardRuntimeStatus.invalidRequest),
          );
        }
        return _runCore<SystemKeyboardAcknowledgement>(
          entry: entry,
          call: () => _controller.acknowledgeInsertion(
            requestId: requestId,
            pendingId: pendingId,
            commitText: commitText,
          ),
          toData: (SystemKeyboardAcknowledgement ack) =>
              <String, Object?>{'exported': ack.exported},
        );
      case 'decode':
        final Object? carrier = arguments['carrier'];
        if (carrier is! String) {
          return Future<Map<String, Object?>>.value(
            _failure(SystemKeyboardRuntimeStatus.invalidRequest),
          );
        }
        return _runCore<SystemKeyboardDecodedPreview>(
          entry: entry,
          call: () => _controller.decodeCarrier(
            requestId: requestId,
            carrier: carrier,
          ),
          toData: _previewData,
        );
      default:
        return Future<Map<String, Object?>>.value(
          _failure(SystemKeyboardRuntimeStatus.invalidRequest),
        );
    }
  }

  /// Runs one delegated controller call around native authorization checks.
  ///
  /// The native check runs *before* the sensitive call and again *after* it.
  /// A false/erroring check, or an idle expiry observed by either recheck,
  /// closes the session permanently and suppresses whatever the controller
  /// produced, so a revoked pending operation can never return a carrier or a
  /// preview.
  Future<Map<String, Object?>> _runCore<T>({
    required Duration entry,
    required Future<SystemKeyboardResult<T>> Function() call,
    required Object? Function(T value) toData,
  }) async {
    if (!await _recheckNative()) {
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    if (_closed || !isAuthorized) {
      close();
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    SystemKeyboardResult<T> result;
    try {
      result = await call();
    } catch (_) {
      close();
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    if (!await _recheckNative()) {
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    if (_closed || !isAuthorized) {
      close();
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    final SystemKeyboardFailureCode? failure = result.failure;
    if (failure != null) return _failure(_statusFor(failure));
    final T? value = result.value;
    if (value == null) {
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    final Object? data = toData(value);
    if (data == null) {
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    return _success(data: data, entry: entry, heartbeat: false);
  }

  Future<bool> _recheckNative() async {
    _nativeChecked = true;
    bool authorized;
    try {
      authorized = await _nativeIsAuthorized();
    } catch (_) {
      authorized = false;
    }
    if (!authorized || _closed || !isAuthorized) {
      close();
      return false;
    }
    return true;
  }

  // ── response shapes ───────────────────────────────────────────────────────

  Map<String, Object?> _success({
    required Object data,
    required Duration entry,
    required bool heartbeat,
  }) {
    if (_closed || !isAuthorized) {
      close();
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    final int? leaseMillis = _leaseMillis();
    if (leaseMillis == null) {
      close();
      return _failure(SystemKeyboardRuntimeStatus.unavailable);
    }
    return <String, Object?>{
      'status': SystemKeyboardRuntimeStatus.ok,
      'processingMillis': heartbeat ? 0 : _processingMillis(entry),
      'leaseMillis': leaseMillis,
      'data': data,
    };
  }

  static Map<String, Object?> _failure(String status) =>
      <String, Object?>{'status': status};

  int? _leaseMillis() {
    if (_closed) return null;
    final int remaining = remainingIdleMillis;
    if (remaining <= 0) return null;
    // The requested lease is granted for at most one second; the idle window
    // and the native grant remain the real ceilings.
    return remaining > maxLeaseMillis ? maxLeaseMillis : remaining;
  }

  int _processingMillis(Duration entry) {
    final Duration? now = _safeNow();
    if (now == null) return maxProcessingMillis;
    final int millis = (now - entry).inMilliseconds;
    if (millis <= 0) return 0;
    return millis > maxProcessingMillis ? maxProcessingMillis : millis;
  }

  // ── admission snapshot ────────────────────────────────────────────────────

  SystemKeyboardAccessSnapshot _accessSnapshot() {
    final bool authorized = isAuthorized;
    return SystemKeyboardAccessSnapshot(
      featureOptedIn: authorized,
      lockInitialized: true,
      lockUnlocked: authorized,
      lockRequested: !authorized,
      passphraseActive: false,
      disposed: _closed,
      stateGeneration: 1,
      identityContextGeneration: identityId,
      backgroundDeadline: null,
    );
  }

  SystemKeyboardIdleObservation _observeIdle(Duration now) {
    final SystemKeyboardIdleObservation observation =
        _idle.observe(now.inMilliseconds);
    if (now >= _lastObserved) _lastObserved = now;
    _lastIdle = observation;
    if (!observation.isActive) close();
    return observation;
  }

  Duration? _safeNow() {
    Duration now;
    try {
      now = _now();
    } catch (_) {
      return null;
    }
    if (now < _lastObserved) {
      close();
      return null;
    }
    return now;
  }

  // ── data mapping (same shapes as the app-owner service) ───────────────────

  static Object? _contactsData(List<SystemKeyboardContact> contacts) {
    final List<Map<String, Object?>> mapped = <Map<String, Object?>>[];
    for (final SystemKeyboardContact contact in contacts) {
      final Map<String, Object?>? entry = _contactMap(contact);
      if (entry != null) mapped.add(entry);
    }
    return <String, Object?>{'contacts': mapped};
  }

  static Object? _contactData(SystemKeyboardContact contact) =>
      _contactMap(contact);

  static Object? _previewData(SystemKeyboardDecodedPreview preview) {
    if (_contactFields(
            preview.contactId, preview.contactName, preview.fingerprint) ==
        null) {
      return null;
    }
    if (preview.text.isEmpty ||
        preview.text.length > systemKeyboardDefaultMaxCarrierCodeUnits) {
      return null;
    }
    // A decode never selects the authenticated sender as recipient: the
    // controller keeps the explicit selection untouched.
    return <String, Object?>{
      'contactId': preview.contactId,
      'contactName': preview.contactName,
      'fingerprint': preview.fingerprint,
      'text': preview.text,
    };
  }

  static Map<String, Object?>? _contactMap(SystemKeyboardContact contact) {
    final fields =
        _contactFields(contact.id, contact.name, contact.fingerprint);
    if (fields != null && contact.securityPhase != null) {
      fields['securityPhase'] = contact.securityPhase;
    }
    return fields;
  }

  static Map<String, Object?>? _contactFields(
    String id,
    String name,
    String fingerprint,
  ) {
    if (!_bounded(id)) return null;
    if (!_bounded(name) || !_bounded(fingerprint)) return null;
    return <String, Object?>{
      'id': id,
      'name': name,
      'fingerprint': fingerprint,
    };
  }

  static bool _bounded(String value) =>
      value.trim().isNotEmpty && value.length <= maxIdentifierLength;

  static bool _isIdentifier(Object? value) =>
      value is String && _bounded(value);

  static void _checkIdentifier(String value, String name) {
    if (!_bounded(value)) {
      throw ArgumentError.value(
        value,
        name,
        'must be nonempty and at most $maxIdentifierLength code units',
      );
    }
  }

  static String _statusFor(SystemKeyboardFailureCode code) => switch (code) {
        SystemKeyboardFailureCode.unavailable =>
          SystemKeyboardRuntimeStatus.unavailable,
        SystemKeyboardFailureCode.busy => SystemKeyboardRuntimeStatus.busy,
        SystemKeyboardFailureCode.duplicateRequest =>
          SystemKeyboardRuntimeStatus.duplicateRequest,
        SystemKeyboardFailureCode.invalidRequest =>
          SystemKeyboardRuntimeStatus.invalidRequest,
        SystemKeyboardFailureCode.invalidSelection =>
          SystemKeyboardRuntimeStatus.invalidSelection,
        SystemKeyboardFailureCode.unsupportedExport =>
          SystemKeyboardRuntimeStatus.unsupportedExport,
        SystemKeyboardFailureCode.oversize =>
          SystemKeyboardRuntimeStatus.oversize,
        SystemKeyboardFailureCode.noPendingExport =>
          SystemKeyboardRuntimeStatus.noPendingExport,
        SystemKeyboardFailureCode.noMessage =>
          SystemKeyboardRuntimeStatus.noMessage,
        SystemKeyboardFailureCode.openAppRequired =>
          SystemKeyboardRuntimeStatus.openAppRequired,
        SystemKeyboardFailureCode.backendError =>
          SystemKeyboardRuntimeStatus.backendError,
      };
}
