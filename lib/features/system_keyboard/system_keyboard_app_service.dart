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

/// App-owner integration for the experimental SYSTEM keyboard.
///
/// This is the only place that decides whether the host keyboard may reach the
/// app owner at all, and the only place that answers the native `request`
/// channel. It owns:
///
/// * the off-by-default mobile compile-time feature gate and the
///   independent user opt-in stored through the existing secure storage;
/// * the admission snapshot consumed by [SystemKeyboardController], including a
///   synchronous "a lock has been requested" flag and an independent monotonic
///   background deadline that does not depend on the app lock's own timer;
/// * a monotonic generation that is bumped on every admission-relevant owner
///   change so a revoked session can never be revived by an event that changes
///   state away and back;
/// * the strict native channel request shape, bounds and operation routing,
///   including monotonic `processingMillis` and a `leaseMillis` that never
///   widens the app-owner background grant.
///
/// Nothing here unlocks the app, starts an engine, prompts for biometry, reads
/// the clipboard or renews an authorization deadline. Every admission failure
/// collapses into the single generic `unavailable` status.
library;

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/capabilities/layergram_capabilities.dart';
import '../../core/crypto/passphrase_service.dart';
import '../../core/crypto/stego_decoder.dart';
import '../../core/providers.dart';
import '../../core/storage/secure_storage.dart';
import '../../utils/app_platform.dart';
import 'system_keyboard_app_backend.dart';
import 'system_keyboard_controller.dart';

/// Compile-time gate for the experimental SYSTEM keyboard.
///
/// Ordinary builds compile this to `false`: the settings entry is hidden, the
/// native component is configured off and no key, contact or runtime read can
/// happen from a keyboard request.
const bool systemKeyboardExperimentalEnabled = bool.fromEnvironment(
  'LAYERGRAM_EXPERIMENTAL_SYSTEM_KEYBOARD',
  defaultValue: false,
);

/// Method channel used by the native broker (coordination contract v1).
const String systemKeyboardChannelName = 'layergram/system_keyboard';

/// Monotonic clock shared by the app-owner integration.
final Stopwatch _systemKeyboardStopwatch = Stopwatch()..start();

/// Default monotonic clock, based on [Stopwatch] so it never moves backwards.
Duration systemKeyboardMonotonicNow() => _systemKeyboardStopwatch.elapsed;

// ── channel status codes ────────────────────────────────────────────────────

/// Status strings of the native coordination contract v1.
abstract final class SystemKeyboardChannelStatus {
  /// Success.
  static const String ok = 'ok';

  /// Every lock, passphrase, opt-in, context or engine denial.
  static const String unavailable = 'unavailable';
  static const String busy = 'busy';
  static const String noMessage = 'noMessage';
  static const String invalidSelection = 'invalidSelection';
  static const String oversize = 'oversize';
  static const String unsupportedExport = 'unsupportedExport';
  static const String invalidRequest = 'invalidRequest';
  static const String noPendingExport = 'noPendingExport';
  static const String openAppRequired = 'openAppRequired';
  static const String duplicateRequest = 'duplicateRequest';
  static const String backendError = 'backendError';
}

// ── owner state seam ────────────────────────────────────────────────────────

/// Synchronous, side-effect-free view of the admission-relevant app state.
@immutable
class SystemKeyboardOwnerState {
  /// Creates an owner snapshot.
  const SystemKeyboardOwnerState({
    required this.lockStateReady,
    required this.needsUnlock,
    required this.ordinaryIdentityId,
    required this.passphraseActive,
    required this.ordinaryKeyTagReady,
  });

  /// Fully denied snapshot, also used when the reader throws.
  const SystemKeyboardOwnerState.denied()
      : lockStateReady = false,
        needsUnlock = true,
        ordinaryIdentityId = null,
        passphraseActive = true,
        ordinaryKeyTagReady = false;

  /// App lock state has finished loading.
  final bool lockStateReady;

  /// App lock is currently engaged or being engaged.
  final bool needsUnlock;

  /// Active ordinary identity id, if any.
  final String? ordinaryIdentityId;

  /// A passphrase context is active; the SYSTEM keyboard is ordinary-only.
  final bool passphraseActive;

  /// The ordinary keyTag needed by the V3 storage context is available.
  final bool ordinaryKeyTagReady;
}

/// Reads [SystemKeyboardOwnerState] synchronously.
typedef SystemKeyboardOwnerStateReader = SystemKeyboardOwnerState Function();

// ── opt-in storage ──────────────────────────────────────────────────────────

/// Independent, global (not identity-specific) SYSTEM keyboard preference.
abstract interface class SystemKeyboardOptInStore {
  /// Reads the preference. Missing or failing storage means "disabled".
  Future<bool> read();

  /// Persists the preference. Throws when persistence fails.
  Future<void> write(bool value);
}

/// [SystemKeyboardOptInStore] backed by the existing secure storage service.
class SecureSystemKeyboardOptInStore implements SystemKeyboardOptInStore {
  /// Creates the store.
  SecureSystemKeyboardOptInStore(this._storage);

  final SecureStorageService _storage;

  /// Secure storage key. Global, additive and independent of identity data.
  static const String storageKey = 'system_keyboard_opt_in';

  @override
  Future<bool> read() async {
    try {
      return (await _storage.read(storageKey)) == 'true';
    } catch (_) {
      return false;
    }
  }

  @override
  Future<void> write(bool value) =>
      _storage.write(storageKey, value ? 'true' : 'false');
}

// ── native channel seam ─────────────────────────────────────────────────────

/// Handler for inbound native requests.
typedef SystemKeyboardChannelRequestHandler = Future<Map<String, Object?>>
    Function(Map<Object?, Object?> arguments);

/// Narrow seam over the native method channel, so the service is testable
/// without any platform plugin.
abstract interface class SystemKeyboardNativeChannel {
  /// Registers (or clears, with `null`) the inbound request handler.
  void setRequestHandler(SystemKeyboardChannelRequestHandler? handler);

  /// Reads the persisted native opt-in and component state, never OS selection.
  Future<bool> readEnabled();

  /// Persists the native opt-in flag and flips the permission-bound component.
  Future<bool> configure({required bool enabled});

  /// Clears all native editor/service state. Carries no metadata.
  Future<void> revoke();

  /// Opens the Android input-method settings screen. Explicit user action only.
  Future<bool> openSettings();
}

/// Production [SystemKeyboardNativeChannel] over `layergram/system_keyboard`.
class MethodChannelSystemKeyboardNativeChannel
    implements SystemKeyboardNativeChannel {
  /// Creates the channel adapter, optionally over an injected [channel].
  MethodChannelSystemKeyboardNativeChannel({MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(systemKeyboardChannelName);

  final MethodChannel _channel;

  @override
  void setRequestHandler(SystemKeyboardChannelRequestHandler? handler) {
    if (handler == null) {
      _channel.setMethodCallHandler(null);
      return;
    }
    _channel.setMethodCallHandler((MethodCall call) async {
      if (call.method != 'request') {
        throw MissingPluginException(
          'Unsupported system keyboard channel method: ${call.method}',
        );
      }
      final Object? raw = call.arguments;
      final Map<Object?, Object?> arguments = raw is Map
          ? Map<Object?, Object?>.from(raw)
          : const <Object?, Object?>{};
      return handler(arguments);
    });
  }

  @override
  Future<bool> readEnabled() async {
    try {
      return await _channel.invokeMethod<bool>('readEnabled') ?? false;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<bool> configure({required bool enabled}) async {
    try {
      final bool? accepted = await _channel.invokeMethod<bool>(
        'configure',
        <String, Object?>{'enabled': enabled},
      );
      return accepted ?? false;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<void> revoke() async {
    try {
      await _channel.invokeMethod<void>('revoke');
    } catch (_) {
      // Detached engine: nothing to revoke.
    }
  }

  @override
  Future<bool> openSettings() async {
    try {
      final bool? opened = await _channel.invokeMethod<bool>('openSettings');
      return opened ?? false;
    } catch (_) {
      return false;
    }
  }
}

// ── service ─────────────────────────────────────────────────────────────────

/// App-owner service for the experimental SYSTEM keyboard.
class SystemKeyboardAppService extends ChangeNotifier
    with WidgetsBindingObserver
    implements SystemKeyboardIntegrationGuard {
  /// Creates the service. All platform and storage access is injected.
  SystemKeyboardAppService({
    required SystemKeyboardNativeChannel nativeChannel,
    required SystemKeyboardOptInStore optInStore,
    required bool platformSupported,
    required bool featureFlagEnabled,
    required SystemKeyboardOwnerStateReader ownerState,
    required bool Function() readScramble,
    required SystemKeyboardMonotonicNow monotonicNow,
    bool observeLifecycle = true,
    Duration? maximumBackgroundDuration,
  })  : _nativeChannel = nativeChannel,
        _optInStore = optInStore,
        _platformSupported = platformSupported,
        _featureFlagEnabled = featureFlagEnabled,
        _ownerState = ownerState,
        _readScramble = readScramble,
        _now = monotonicNow,
        _observeLifecycle = observeLifecycle,
        _maximumBackgroundDuration = maximumBackgroundDuration;

  final SystemKeyboardNativeChannel _nativeChannel;
  final SystemKeyboardOptInStore _optInStore;
  final bool _platformSupported;
  final bool _featureFlagEnabled;
  final SystemKeyboardOwnerStateReader _ownerState;
  final bool Function() _readScramble;
  final SystemKeyboardMonotonicNow _now;
  final bool _observeLifecycle;
  final Duration? _maximumBackgroundDuration;
  Duration? _platformBackgroundDeadline;

  Duration? get _effectiveBackgroundDeadline {
    final Duration? platform = _platformBackgroundDeadline;
    return platform == null
        ? _backgroundDeadline
        : _earlier(_backgroundDeadline, platform);
  }

  SystemKeyboardController? _controller;
  SystemKeyboardBackend? _backend;

  bool _started = false;
  bool _disposed = false;
  bool _observing = false;
  bool _optInLoaded = false;
  bool _optIn = false;
  bool _nativeConfigured = false;

  /// Monotonic intent token for every enable/disable/start transition. A
  /// completion that observes a newer token must not assign a preference or
  /// reconfigure the native component.
  int _preferenceIntent = 0;
  Future<void> _storeQueue = Future<void>.value();
  Future<void> _nativeQueue = Future<void>.value();

  bool _appLockEnabled = false;
  int _appLockTimeoutSeconds = 60;
  bool _lockRequested = false;
  Duration? _backgroundAt;
  Duration? _backgroundDeadline;

  int _generation = 0;
  String? _editorNonce;
  int _editorGeneration = 0;
  Duration? _lastNow;

  /// Whether the compile-time feature and platform allow the keyboard at all.
  bool get isSupportedOnThisPlatform =>
      _platformSupported && _featureFlagEnabled;

  bool get _gateActive => _platformSupported && _featureFlagEnabled;

  /// Whether the user preference has been loaded.
  bool get isStarted => _started;

  /// Whether the service has been disposed.
  bool get isDisposed => _disposed;

  /// Whether the native component is currently configured on for this user.
  bool get isEnabled => _optInLoaded && _optIn && _nativeConfigured;

  /// Whether the settings switch may be interacted with.
  bool get isInteractive => _started && !_disposed && _optInLoaded;

  /// Monotonic app-owner generation, bumped on every admission-relevant event.
  @override
  int get generation => _generation;

  @override
  String? get ordinaryIdentityId {
    // The owner state is only sampled while the gate is fully open, so a
    // disabled build never initializes identity-adjacent providers.
    if (!_platformSupported ||
        !_featureFlagEnabled ||
        // A bounded iOS extension session starts only after Flutter observed
        // departure. An early native request cannot race a zero-timeout lock.
        (_maximumBackgroundDuration != null && _backgroundAt == null) ||
        !_optInLoaded ||
        !_optIn ||
        !_nativeConfigured ||
        _disposed) {
      return null;
    }
    try {
      final String? id = _ownerState().ordinaryIdentityId;
      return (id != null && id.isNotEmpty) ? id : null;
    } catch (_) {
      return null;
    }
  }

  @override
  bool admits(int generation, String? identityId) {
    if (_disposed || !_started) return false;
    if (generation != _generation) return false;
    // Full admission, re-evaluated from the live owner: feature and consent and
    // native configuration, lock readiness/unlock/request, passphrase and
    // ordinary keyTag readiness. A timeout can elapse with no provider event at
    // all, so the monotonic deadline is always compared here too.
    final SystemKeyboardAccessSnapshot snapshot = _readAccess();
    if (!snapshot.admitsWithoutDeadline) return false;
    final String? current = snapshot.identityContextGeneration;
    if (current == null || identityId == null || current != identityId) {
      return false;
    }
    final Duration? now = _safeNow();
    if (now == null) return false;
    final Duration? deadline = snapshot.backgroundDeadline;
    return deadline == null || now < deadline;
  }

  // ── lifecycle ─────────────────────────────────────────────────────────────

  /// Loads consent, configures the native component once and starts serving.
  ///
  /// Safe to call more than once; only the first call does work. Every awaited
  /// step is guarded by the monotonic preference intent, so a disable that
  /// happens while startup is still loading can never be overwritten.
  Future<void> start() async {
    if (_started || _disposed) return;
    _started = true;
    final int intent = ++_preferenceIntent;
    if (_observeLifecycle) {
      try {
        WidgetsBinding.instance.addObserver(this);
        _observing = true;
      } catch (_) {
        _observing = false;
      }
    }
    if (!_platformSupported) {
      _optInLoaded = true;
      _notify();
      return;
    }
    if (!_featureFlagEnabled) {
      // Ordinary build: hide the surface and make sure the native component is
      // off. No consent, key, contact or runtime read happens here.
      _optInLoaded = true;
      _optIn = false;
      _nativeConfigured = false;
      await _applyNativePreference(intent, false);
      if (_isStale(intent)) return;
      _notify();
      return;
    }
    bool stored = false;
    try {
      stored = await _optInStore.read();
    } catch (_) {
      stored = false;
    }
    if (_isStale(intent)) return;
    // Restoration requires agreement between independent persisted switches.
    // A failed secure-store opt-out must not revive an already disabled native
    // component after a process restart.
    if (stored) {
      try {
        stored = await _nativeChannel.readEnabled();
      } catch (_) {
        stored = false;
      }
      if (_isStale(intent)) return;
    }
    _optIn = stored;
    _optInLoaded = true;
    // The handler must exist before the native side can ever be enabled.
    _nativeChannel.setRequestHandler(handleChannelRequest);
    if (stored) {
      final bool accepted = await _applyNativePreference(intent, true);
      if (_isStale(intent)) return;
      _nativeConfigured = accepted;
    } else {
      await _applyNativePreference(intent, false);
      if (_isStale(intent)) return;
      _nativeConfigured = false;
    }
    _notify();
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    // Invalidate every in-flight preference completion before tearing down.
    _preferenceIntent++;
    _generation++;
    _controller?.dispose();
    _controller = null;
    _clearEditorBinding();
    _clearSessionScopedBackend();
    if (_observing) {
      try {
        WidgetsBinding.instance.removeObserver(this);
      } catch (_) {
        // Binding already gone.
      }
      _observing = false;
    }
    _nativeChannel.setRequestHandler(null);
    unawaited(_invokeNative(
        (SystemKeyboardNativeChannel channel) => channel.revoke()));
    super.dispose();
  }

  // ── settings / native control ─────────────────────────────────────────────

  /// Applies the user opt-in.
  ///
  /// Disabling revokes synchronously *before* any storage or native call, so a
  /// failed write can never leave the keyboard enabled. Enabling persists the
  /// preference first: a failed write stays disabled. Both directions are
  /// serialized in separate storage/native queues and guarded by an intent
  /// token, so a delayed enable completion can
  /// never re-enable the keyboard after a newer disable.
  Future<bool> setEnabled(bool value) async {
    if (!_platformSupported || !_featureFlagEnabled || _disposed) return false;
    final int intent = ++_preferenceIntent;
    if (!value) {
      // Revoke first: the in-memory and native state is disabled before any
      // asynchronous persistence can fail.
      _optIn = false;
      _nativeConfigured = false;
      _revokeEverything();
      _notify();
      // Persist native denial independently of a slow or failing secure write.
      final Future<bool> nativeDisabled = _applyNativePreference(intent, false);
      await _persistPreference(intent, false);
      await nativeDisabled;
      return false;
    }
    final bool persisted = await _persistPreference(intent, true);
    if (!persisted || _isStale(intent)) return false;
    _optIn = true;
    _nativeConfigured = false;
    _revokeEverything();
    _notify();
    final bool accepted = await _applyNativePreference(intent, true);
    if (_isStale(intent)) return false;
    if (!accepted) {
      // Native refused: stay disabled, durably as well.
      _optIn = false;
      _nativeConfigured = false;
      _revokeEverything();
      _notify();
      await _persistPreference(intent, false);
      await _applyNativePreference(intent, false);
      return false;
    }
    _nativeConfigured = true;
    _notify();
    return true;
  }

  /// Opens the Android input-method settings screen on an explicit user click.
  Future<bool> openInputMethodSettings() async {
    if (!_platformSupported || _disposed) return false;
    try {
      return await _nativeChannel.openSettings();
    } catch (_) {
      return false;
    }
  }

  // ── preference serialization ──────────────────────────────────────────────

  bool _isStale(int intent) => _disposed || intent != _preferenceIntent;

  /// Writes run in order. A write already in flight may finish after its intent
  /// is revoked, but can never finish after a newer write has been applied.
  Future<bool> _persistPreference(int intent, bool value) {
    final Future<bool> operation = _storeQueue.then((_) async {
      for (int attempt = 0; attempt < 2; attempt++) {
        if (_isStale(intent)) return false;
        try {
          await _optInStore.write(value);
          return !_isStale(intent);
        } catch (_) {
          // Retry once while current; the live gate is already denied.
        }
      }
      return false;
    });
    _storeQueue = operation.then<void>((_) {}, onError: (Object _) {});
    return operation;
  }

  /// Includes stale-enable cleanup in the same queue as later requests, so
  /// cleanup cannot switch off a subsequent explicitly accepted enable.
  Future<bool> _applyNativePreference(int intent, bool enabled) {
    final Future<bool> operation = _nativeQueue.then((_) async {
      if (_isStale(intent)) return false;
      final bool accepted = await _configureNative(enabled);
      if (_isStale(intent)) {
        if (enabled) await _configureNative(false);
        return false;
      }
      return accepted;
    });
    _nativeQueue = operation.then<void>((_) {}, onError: (Object _) {});
    return operation;
  }

  void _notify() {
    if (_disposed) return;
    notifyListeners();
  }

  // ── owner events ──────────────────────────────────────────────────────────

  /// Called synchronously at the start of the app's lock request.
  ///
  /// The flag is cleared only after a real unlock, never by a timeout value.
  void noteAppLockRequested() {
    if (_disposed || !_gateActive) return;
    _lockRequested = true;
    _revokeEverything();
    _notify();
  }

  /// Observes the app-lock provider. Only an actual unlock clears the request.
  void onAppNeedsUnlockChanged(bool needsUnlock) {
    if (_disposed || !_gateActive) return;
    if (needsUnlock) {
      _revokeEverything();
      _notify();
      return;
    }
    _lockRequested = false;
    _backgroundAt = null;
    _backgroundDeadline = null;
    _revokeEverything();
    _notify();
  }

  /// Seeds the app-lock configuration from the owner's current values.
  ///
  /// Called once when the service is created, before any listener can fire.
  /// Without this a lock configuration that already existed before the
  /// provider was created (for example enabled with a zero timeout) would leave
  /// the service on its "disabled" default and no background deadline would be
  /// enforced. It neither revokes nor notifies: it only records state.
  void seedAppLockConfig({
    required bool enabled,
    required int timeoutSeconds,
  }) {
    if (_disposed) return;
    _appLockEnabled = enabled;
    _appLockTimeoutSeconds = timeoutSeconds;
    if (!enabled) {
      _backgroundDeadline = null;
    } else {
      final Duration? backgroundAt = _backgroundAt;
      if (backgroundAt != null) {
        final Duration candidate =
            backgroundAt + Duration(seconds: timeoutSeconds);
        _backgroundDeadline = _earlier(_backgroundDeadline, candidate);
      }
    }
  }

  /// Observes app-lock configuration changes (enabled flag, timeout).
  void onAppLockConfigChanged({
    required bool enabled,
    required int timeoutSeconds,
  }) {
    if (_disposed || !_gateActive) return;
    _appLockEnabled = enabled;
    _appLockTimeoutSeconds = timeoutSeconds;
    if (!enabled) {
      _backgroundDeadline = null;
    } else {
      final Duration? backgroundAt = _backgroundAt;
      if (backgroundAt != null) {
        final Duration candidate =
            backgroundAt + Duration(seconds: timeoutSeconds);
        _backgroundDeadline = _earlier(_backgroundDeadline, candidate);
      }
    }
    _revokeEverything();
    _notify();
  }

  /// Bumps the generation and revokes core plus native after any owner change.
  void onOwnerStateChanged() {
    if (_disposed || !_gateActive) return;
    _revokeEverything();
    _notify();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    onAppLifecycleChanged(state);
  }

  /// Forwarded lifecycle handling. Registered through [WidgetsBindingObserver].
  ///
  /// The first transition away from `resumed` records the background instant
  /// exactly once: a later `paused` never extends it. Resuming revokes the old
  /// editor and clears the timestamp, while the app-lock provider and the
  /// synchronous request flag remain authoritative.
  void onAppLifecycleChanged(AppLifecycleState state) {
    if (_disposed || !_gateActive) return;
    if (state == AppLifecycleState.resumed) {
      _platformBackgroundDeadline = null;
      _backgroundAt = null;
      _backgroundDeadline = null;
      // Resuming is a full revocation: the integration generation, the core
      // session, the editor binding and the native editor state all go away.
      // The app-lock provider and the synchronous request flag stay
      // authoritative until an actual unlock clears them.
      _revokeEverything();
      _notify();
      return;
    }
    if (state == AppLifecycleState.detached) {
      // Detached is terminal: deny and revoke, never keep a grant.
      _backgroundDeadline = Duration.zero;
      _revokeEverything();
      _notify();
      return;
    }
    final Duration? now = _safeNow();
    if (now == null) {
      // Without a monotonic instant no deadline can bound the grant: deny and
      // revoke instead of leaving the previous deadline in place.
      _backgroundDeadline = Duration.zero;
      _revokeEverything();
      _notify();
      return;
    }
    _backgroundAt ??= now;
    final Duration? maximum = _maximumBackgroundDuration;
    if (maximum != null) {
      _platformBackgroundDeadline ??= now + maximum;
    }
    if (_appLockEnabled) {
      final Duration candidate =
          _backgroundAt! + Duration(seconds: _appLockTimeoutSeconds);
      _backgroundDeadline = _earlier(_backgroundDeadline, candidate);
    }
    _notify();
  }

  // ── backend wiring ────────────────────────────────────────────────────────

  /// Attaches the controller over [backend]. Called once by the provider.
  void attachBackend(SystemKeyboardBackend backend) {
    if (_disposed) return;
    _backend = backend;
    _controller = SystemKeyboardController(
      backend: backend,
      readAccess: _readAccess,
      monotonicNow: _now,
      composeLimitCodeUnits: systemKeyboardSurfaceOutboundCarrierMaxLength,
      ciphertextLimitCodeUnits: systemKeyboardSurfaceOutboundCarrierMaxLength,
      maxCarrierCodeUnits: StegoDecoder.maxCarrierCodeUnits,
      maxIdentifierLength: systemKeyboardSurfaceIdentifierMaxLength,
    );
  }

  // ── channel request handling ──────────────────────────────────────────────

  /// Handles one native `request` call. Never throws.
  Future<Map<String, Object?>> handleChannelRequest(
    Map<Object?, Object?> arguments,
  ) async {
    final Duration? entry = _safeNow();
    if (entry == null || _disposed || !_started) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    final Object? operationRaw = arguments['operation'];
    final Object? nonceRaw = arguments['editorNonce'];
    final Object? requestIdRaw = arguments['requestId'];
    if (operationRaw is! String ||
        !_isValidIdentifier(nonceRaw) ||
        !_isValidIdentifier(requestIdRaw)) {
      return _failure(SystemKeyboardChannelStatus.invalidRequest);
    }
    final String operation = operationRaw;
    final String editorNonce = nonceRaw! as String;
    final String requestId = requestIdRaw! as String;

    // `end` carries no content and must stay able to tear down its own editor
    // even while the app is locked. It must never close a newer editor.
    if (operation == 'end') {
      return _handleEnd(editorNonce, entry);
    }
    if (operation == 'begin') {
      return _handleBegin(editorNonce, entry);
    }
    if (editorNonce != _editorNonce) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    if (operation == 'heartbeat') {
      return _handleHeartbeat(entry);
    }
    final SystemKeyboardController? controller = _controller;
    if (controller == null) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    final int editorGeneration = _editorGeneration;
    switch (operation) {
      case 'contacts':
        return _runCore<List<SystemKeyboardContact>>(
          editorGeneration: editorGeneration,
          entry: entry,
          call: () => controller.listContacts(requestId: requestId),
          toData: _contactsData,
        );
      case 'select':
        {
          final Object? contactId = arguments['contactId'];
          final Object? confirm = arguments['confirm'];
          if (contactId is! String || confirm is! bool) {
            return _failure(SystemKeyboardChannelStatus.invalidRequest);
          }
          return _runCore<SystemKeyboardContact>(
            editorGeneration: editorGeneration,
            entry: entry,
            call: () => controller.selectContact(
              requestId: requestId,
              contactId: contactId,
              confirm: confirm,
            ),
            toData: _contactData,
          );
        }
      case 'prepare':
        {
          final Object? text = arguments['text'];
          if (text is! String) {
            return _failure(SystemKeyboardChannelStatus.invalidRequest);
          }
          return _runCore<SystemKeyboardPendingExport>(
            editorGeneration: editorGeneration,
            entry: entry,
            call: () => controller.prepareText(
              requestId: requestId,
              text: text,
            ),
            toData: (SystemKeyboardPendingExport pending) =>
                <String, Object?>{'pendingId': pending.pendingId},
          );
        }
      case 'authorize':
        {
          final Object? pendingId = arguments['pendingId'];
          if (pendingId is! String) {
            return _failure(SystemKeyboardChannelStatus.invalidRequest);
          }
          return _runCore<String>(
            editorGeneration: editorGeneration,
            entry: entry,
            call: () => controller.authorizeInsertion(
              requestId: requestId,
              pendingId: pendingId,
            ),
            toData: (String carrier) => <String, Object?>{'carrier': carrier},
          );
        }
      case 'ack':
        {
          final Object? pendingId = arguments['pendingId'];
          final Object? commitText = arguments['commitText'];
          if (pendingId is! String || commitText is! bool) {
            return _failure(SystemKeyboardChannelStatus.invalidRequest);
          }
          return _runCore<SystemKeyboardAcknowledgement>(
            editorGeneration: editorGeneration,
            entry: entry,
            call: () => controller.acknowledgeInsertion(
              requestId: requestId,
              pendingId: pendingId,
              commitText: commitText,
            ),
            toData: (SystemKeyboardAcknowledgement ack) =>
                <String, Object?>{'exported': ack.exported},
          );
        }
      case 'decode':
        {
          final Object? carrier = arguments['carrier'];
          if (carrier is! String) {
            return _failure(SystemKeyboardChannelStatus.invalidRequest);
          }
          return _runCore<SystemKeyboardDecodedPreview>(
            editorGeneration: editorGeneration,
            entry: entry,
            call: () => controller.decodeCarrier(
              requestId: requestId,
              carrier: carrier,
            ),
            toData: _previewData,
          );
        }
      default:
        return _failure(SystemKeyboardChannelStatus.invalidRequest);
    }
  }

  Map<String, Object?> _handleBegin(String editorNonce, Duration entry) {
    final SystemKeyboardController? controller = _controller;
    if (controller == null) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    final SystemKeyboardResult<SystemKeyboardSession> result =
        controller.beginSession(editorNonce: editorNonce);
    if (result.isFailure) {
      _clearEditorBinding();
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    _editorNonce = editorNonce;
    _editorGeneration++;
    // A new editor generation drops any handle left by the previous session;
    // the durable app-owned export itself is never deleted.
    _clearSessionScopedBackend();
    final bool scramble = _safeReadScramble();
    return _success(
      data: <String, Object?>{'scramble': scramble},
      entry: entry,
      editorGeneration: _editorGeneration,
      heartbeat: false,
    );
  }

  Map<String, Object?> _handleHeartbeat(Duration entry) {
    final SystemKeyboardController? controller = _controller;
    if (controller == null || !controller.validateSession()) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    // A heartbeat validates the live session only: no backend I/O, no request
    // id memory and no deadline renewal.
    return _success(
      data: const <String, Object?>{},
      entry: entry,
      editorGeneration: _editorGeneration,
      heartbeat: true,
    );
  }

  Map<String, Object?> _handleEnd(String editorNonce, Duration entry) {
    if (editorNonce != _editorNonce) {
      // End from an older editor: never touch the newer one.
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    _controller?.endSession();
    _clearEditorBinding();
    _clearSessionScopedBackend();
    return <String, Object?>{
      'status': SystemKeyboardChannelStatus.ok,
      'processingMillis': _processingMillis(entry),
      'leaseMillis': 1,
      'data': const <String, Object?>{},
    };
  }

  Future<Map<String, Object?>> _runCore<T>({
    required int editorGeneration,
    required Duration entry,
    required Future<SystemKeyboardResult<T>> Function() call,
    required Object? Function(T value) toData,
  }) async {
    SystemKeyboardResult<T> result;
    try {
      result = await call();
    } catch (_) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    if (_disposed || _editorGeneration != editorGeneration) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    final SystemKeyboardFailureCode? failure = result.failure;
    if (failure != null) {
      return _failure(_statusFor(failure));
    }
    final T? value = result.value;
    if (value == null) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    final Object? data = toData(value);
    if (data == null) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    return _success(
      data: data,
      entry: entry,
      editorGeneration: editorGeneration,
      heartbeat: false,
    );
  }

  Map<String, Object?> _success({
    required Object data,
    required Duration entry,
    required int editorGeneration,
    required bool heartbeat,
  }) {
    final int processingMillis = heartbeat ? 0 : _processingMillis(entry);
    if (!_admissionStillValid(editorGeneration)) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    final int? leaseMillis = _leaseMillis();
    if (leaseMillis == null) {
      return _failure(SystemKeyboardChannelStatus.unavailable);
    }
    return <String, Object?>{
      'status': SystemKeyboardChannelStatus.ok,
      'processingMillis': processingMillis,
      'leaseMillis': leaseMillis,
      'data': data,
    };
  }

  // ── admission snapshot ────────────────────────────────────────────────────

  SystemKeyboardAccessSnapshot _readAccess() {
    // Fail closed *before* touching the owner state: an unsupported or disabled
    // keyboard must never initialize the passphrase or keyTag providers just
    // because a native request arrived.
    if (!_platformSupported ||
        !_featureFlagEnabled ||
        (_maximumBackgroundDuration != null && _backgroundAt == null) ||
        !_optInLoaded ||
        !_optIn ||
        !_nativeConfigured ||
        _disposed) {
      return SystemKeyboardAccessSnapshot(
        featureOptedIn: false,
        lockInitialized: false,
        lockUnlocked: false,
        lockRequested: true,
        passphraseActive: false,
        disposed: _disposed,
        stateGeneration: _generation,
        identityContextGeneration: null,
        backgroundDeadline: _effectiveBackgroundDeadline,
      );
    }
    SystemKeyboardOwnerState owner;
    try {
      owner = _ownerState();
    } catch (_) {
      owner = const SystemKeyboardOwnerState.denied();
    }
    final String? identity = owner.ordinaryIdentityId;
    final bool identityReady =
        identity != null && identity.isNotEmpty && owner.ordinaryKeyTagReady;
    return SystemKeyboardAccessSnapshot(
      featureOptedIn: true,
      lockInitialized: owner.lockStateReady,
      lockUnlocked: !owner.needsUnlock,
      lockRequested: _lockRequested,
      passphraseActive: owner.passphraseActive,
      disposed: _disposed,
      stateGeneration: _generation,
      identityContextGeneration: identityReady ? identity : null,
      backgroundDeadline: _effectiveBackgroundDeadline,
    );
  }

  bool _admissionStillValid(int editorGeneration) {
    if (_disposed || !_started || _editorGeneration != editorGeneration) {
      return false;
    }
    final SystemKeyboardAccessSnapshot snapshot = _readAccess();
    if (!snapshot.admitsWithoutDeadline) return false;
    final Duration? deadline = snapshot.backgroundDeadline;
    if (deadline != null) {
      final Duration? now = _safeNow();
      if (now == null || now >= deadline) return false;
    }
    return true;
  }

  int? _leaseMillis() {
    final Duration? now = _safeNow();
    if (now == null) return null;
    final Duration? deadline = _effectiveBackgroundDeadline;
    if (deadline == null) return 1000;
    final Duration remaining = deadline - now;
    if (remaining <= Duration.zero) return null;
    final int millis = remaining.inMilliseconds;
    if (millis <= 0) return null;
    return millis > 1000 ? 1000 : millis;
  }

  int _processingMillis(Duration entry) {
    final Duration? now = _safeNow();
    if (now == null) {
      // A non-monotonic clock can no longer bound the grant: report the
      // ceiling, which makes the native deadline expire conservatively.
      return 30000;
    }
    final int millis = (now - entry).inMilliseconds;
    if (millis <= 0) return 0;
    return millis > 30000 ? 30000 : millis;
  }

  // ── data mapping ──────────────────────────────────────────────────────────

  Object? _contactsData(List<SystemKeyboardContact> contacts) {
    final List<Map<String, Object?>> mapped = <Map<String, Object?>>[];
    for (final SystemKeyboardContact contact in contacts) {
      final Map<String, Object?>? entry =
          _contactMap(contact.id, contact.name, contact.fingerprint);
      if (entry != null) mapped.add(entry);
    }
    return <String, Object?>{'contacts': mapped};
  }

  Object? _contactData(SystemKeyboardContact contact) =>
      _contactMap(contact.id, contact.name, contact.fingerprint);

  Object? _previewData(SystemKeyboardDecodedPreview preview) {
    final Map<String, Object?>? contact = _contactMap(
      preview.contactId,
      preview.contactName,
      preview.fingerprint,
    );
    if (contact == null) return null;
    if (preview.text.isEmpty ||
        preview.text.length > StegoDecoder.maxCarrierCodeUnits) {
      return null;
    }
    return <String, Object?>{
      'contactId': contact['id'],
      'contactName': contact['name'],
      'fingerprint': contact['fingerprint'],
      'text': preview.text,
    };
  }

  static Map<String, Object?>? _contactMap(
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
    return <String, Object?>{
      'id': id,
      'name': name,
      'fingerprint': fingerprint,
    };
  }

  // ── internals ─────────────────────────────────────────────────────────────

  void _revokeEverything() {
    _generation++;
    _controller?.revoke();
    _clearEditorBinding();
    _clearSessionScopedBackend();
    unawaited(_invokeNative(
        (SystemKeyboardNativeChannel channel) => channel.revoke()));
  }

  void _clearEditorBinding() {
    _editorNonce = null;
    _editorGeneration++;
  }

  void _clearSessionScopedBackend() {
    // Typed as `Object?` so the `is` check promotes to the non-nullable
    // session-scoped interface without relying on an intersection promotion.
    final Object? backend = _backend;
    if (backend is SystemKeyboardSessionScopedBackend) {
      backend.clearSessionHandles();
    }
  }

  Future<bool> _configureNative(bool enabled) async {
    try {
      return await _nativeChannel.configure(enabled: enabled);
    } catch (_) {
      return false;
    }
  }

  Future<void> _invokeNative(
    Future<void> Function(SystemKeyboardNativeChannel channel) action,
  ) async {
    try {
      await action(_nativeChannel);
    } catch (_) {
      // Detached engine or absent plugin: nothing to do.
    }
  }

  bool _safeReadScramble() {
    try {
      return _readScramble();
    } catch (_) {
      return false;
    }
  }

  Duration? _safeNow() {
    Duration now;
    try {
      now = _now();
    } catch (_) {
      return null;
    }
    final Duration? previous = _lastNow;
    if (previous != null && now < previous) {
      return null;
    }
    _lastNow = now;
    return now;
  }

  static Duration _earlier(Duration? current, Duration candidate) {
    if (current == null) return candidate;
    return candidate < current ? candidate : current;
  }

  static bool _isValidIdentifier(Object? value) =>
      value is String &&
      value.isNotEmpty &&
      value.length <= systemKeyboardSurfaceIdentifierMaxLength;

  static Map<String, Object?> _failure(String status) =>
      <String, Object?>{'status': status};

  static String _statusFor(SystemKeyboardFailureCode code) => switch (code) {
        SystemKeyboardFailureCode.unavailable =>
          SystemKeyboardChannelStatus.unavailable,
        SystemKeyboardFailureCode.busy => SystemKeyboardChannelStatus.busy,
        SystemKeyboardFailureCode.duplicateRequest =>
          SystemKeyboardChannelStatus.duplicateRequest,
        SystemKeyboardFailureCode.invalidRequest =>
          SystemKeyboardChannelStatus.invalidRequest,
        SystemKeyboardFailureCode.invalidSelection =>
          SystemKeyboardChannelStatus.invalidSelection,
        SystemKeyboardFailureCode.unsupportedExport =>
          SystemKeyboardChannelStatus.unsupportedExport,
        SystemKeyboardFailureCode.oversize =>
          SystemKeyboardChannelStatus.oversize,
        SystemKeyboardFailureCode.noPendingExport =>
          SystemKeyboardChannelStatus.noPendingExport,
        SystemKeyboardFailureCode.noMessage =>
          SystemKeyboardChannelStatus.noMessage,
        SystemKeyboardFailureCode.openAppRequired =>
          SystemKeyboardChannelStatus.openAppRequired,
        SystemKeyboardFailureCode.backendError =>
          SystemKeyboardChannelStatus.backendError,
      };
}

// ── providers ───────────────────────────────────────────────────────────────

/// Whether the platform can host the native SYSTEM keyboard at all.
final systemKeyboardPlatformSupportedProvider = Provider<bool>(
  (ref) => AppPlatform.isAndroid || AppPlatform.isIOS,
);

/// Whether this build was compiled with the experimental feature.
///
/// Kept behind a provider so the gate is testable without rebuilding, while the
/// production value stays the compile-time constant.
final systemKeyboardFeatureFlagEnabledProvider = Provider<bool>(
  (ref) => systemKeyboardExperimentalEnabled,
);

/// Whether the experimental SYSTEM keyboard surface is active in this build.
final systemKeyboardFeatureActiveProvider = Provider<bool>(
  (ref) =>
      ref.watch(systemKeyboardFeatureFlagEnabledProvider) &&
      ref.watch(systemKeyboardPlatformSupportedProvider),
);

/// Neutral optional preference adapter for downstream presentation only.
///
/// It defaults to `false`, is never persisted here, and only *adds* to the
/// existing capability check before `begin.scramble` is sent.
final systemKeyboardScramblePreferenceProvider = Provider<bool>((ref) => false);

/// Native channel seam.
final systemKeyboardNativeChannelProvider =
    Provider<SystemKeyboardNativeChannel>(
  (ref) => MethodChannelSystemKeyboardNativeChannel(),
);

/// Monotonic clock seam. Production uses the process [Stopwatch]; tests inject
/// a fake clock so deadlines can be advanced without provider notifications.
final systemKeyboardMonotonicNowProvider = Provider<SystemKeyboardMonotonicNow>(
  (ref) => systemKeyboardMonotonicNow,
);

/// Opt-in preference store.
final systemKeyboardOptInStoreProvider = Provider<SystemKeyboardOptInStore>(
  (ref) => SecureSystemKeyboardOptInStore(ref.watch(secureStorageProvider)),
);

/// Builds the owner backend for one service instance.
typedef SystemKeyboardBackendFactory = SystemKeyboardBackend Function(
  Ref ref,
  SystemKeyboardIntegrationGuard guard,
);

/// Default backend factory (real app-owner integration).
final systemKeyboardBackendFactoryProvider =
    Provider<SystemKeyboardBackendFactory>(
  (ref) => (Ref ownerRef, SystemKeyboardIntegrationGuard ownerGuard) =>
      SystemKeyboardAppBackend(ref: ownerRef, guard: ownerGuard),
);

/// The single app-owner service instance.
///
/// Created once per container; Riverpod keeps a plain [Provider] alive, so the
/// widget tree can watch it without re-running initialization. In ordinary
/// builds it attaches the disabled backend and never subscribes to identity,
/// passphrase or keyTag providers.
final systemKeyboardAppServiceProvider = Provider<SystemKeyboardAppService>(
  (ref) {
    final bool featureActive = ref.watch(systemKeyboardFeatureActiveProvider);
    final SystemKeyboardAppService service = SystemKeyboardAppService(
      nativeChannel: ref.watch(systemKeyboardNativeChannelProvider),
      optInStore: ref.watch(systemKeyboardOptInStoreProvider),
      platformSupported: ref.watch(systemKeyboardPlatformSupportedProvider),
      featureFlagEnabled: ref.watch(systemKeyboardFeatureFlagEnabledProvider),
      ownerState: () {
        final PassphraseState passphrase = ref.read(passphraseProvider);
        final AsyncValue<String?> keyTagValue =
            ref.read(originalKeyTagProvider);
        final String? keyTag =
            keyTagValue is AsyncData<String?> ? keyTagValue.value : null;
        return SystemKeyboardOwnerState(
          lockStateReady: ref.read(appLockStateReadyProvider),
          needsUnlock: ref.read(appNeedsUnlockProvider),
          ordinaryIdentityId: ref.read(activeIdentityIdProvider),
          passphraseActive: passphrase.isActive,
          ordinaryKeyTagReady:
              !passphrase.isActive && keyTag != null && keyTag.isNotEmpty,
        );
      },
      readScramble: () {
        final LayergramCapabilities capabilities =
            ref.read(layergramCapabilitiesProvider);
        final bool preference =
            ref.read(systemKeyboardScramblePreferenceProvider);
        return preference &&
            capabilities.secureKeyboard.isAvailable &&
            capabilities.secureKeyboard.supportsScramble;
      },
      monotonicNow: ref.watch(systemKeyboardMonotonicNowProvider),
      maximumBackgroundDuration:
          AppPlatform.isIOS ? const Duration(seconds: 20) : null,
    );

    if (featureActive) {
      service.attachBackend(
        ref.watch(systemKeyboardBackendFactoryProvider)(ref, service),
      );
      // Seed the app-lock configuration that already exists before any
      // listener can fire, so a pre-existing zero/positive timeout is enforced
      // even when the providers never change again.
      service.seedAppLockConfig(
        enabled: ref.read(appLockEnabledProvider),
        timeoutSeconds: ref.read(appLockTimeoutProvider),
      );
      void bump() => service.onOwnerStateChanged();
      ref.listen<String?>(activeIdentityIdProvider, (_, __) => bump());
      ref.listen<int>(identityReloadTokenProvider, (_, __) => bump());
      ref.listen<PassphraseState>(passphraseProvider, (_, __) => bump());
      ref.listen<AsyncValue<String?>>(
          originalKeyTagProvider, (_, __) => bump());
      ref.listen<bool>(appLockStateReadyProvider, (_, __) => bump());
      ref.listen<bool>(
        appNeedsUnlockProvider,
        (_, bool? next) => service.onAppNeedsUnlockChanged(next ?? true),
      );
      ref.listen<bool>(appLockEnabledProvider, (_, bool? next) {
        service.onAppLockConfigChanged(
          enabled: next ?? false,
          timeoutSeconds: ref.read(appLockTimeoutProvider),
        );
      });
      ref.listen<int>(appLockTimeoutProvider, (_, int? next) {
        service.onAppLockConfigChanged(
          enabled: ref.read(appLockEnabledProvider),
          timeoutSeconds: next ?? 0,
        );
      });
    } else {
      service.attachBackend(const SystemKeyboardDisabledBackend());
    }
    ref.onDispose(service.dispose);
    return service;
  },
);
