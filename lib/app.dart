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

import 'dart:async';

import 'package:easy_localization/easy_localization.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'core/capabilities/chat_folders_capability.dart';
import 'core/crypto/fs_passphrase_preferences.dart';
import 'core/crypto/fs_startup_restore.dart';
import 'core/crypto/models.dart';
import 'core/crypto/stego_decoder.dart';
import 'core/providers.dart';
import 'core/security/app_lock_idle_controller.dart';
import 'core/security/external_ingress_coordinator.dart';
import 'features/identities/add_identity_view.dart';
import 'features/identities/identities_controller.dart';
import 'features/home/chat_view.dart';
import 'features/home/home_controller.dart';
import 'features/onboarding/create_or_restore_view.dart';
import 'features/security/unlock_view.dart';
import 'features/security/app_lock_gate.dart';
import 'features/shell/app_shell.dart';
import 'l10n/app_strings.dart';
import 'theme/app_theme.dart';
import 'ui/layergram_background.dart';
import 'ui/privacy_shield_overlay.dart';
import 'utils/app_platform.dart';
import 'utils/deep_links.dart';
import 'utils/sharing.dart';

class IdentityStartupGate extends StatelessWidget {
  const IdentityStartupGate({
    super.key,
    required this.identityFuture,
    required this.onRetry,
    required this.missingIdentityBuilder,
    required this.readyBuilder,
  });

  final Future<LocalIdentity?> identityFuture;
  final VoidCallback onRetry;
  final WidgetBuilder missingIdentityBuilder;
  final WidgetBuilder readyBuilder;

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<LocalIdentity?>(
      future: identityFuture,
      builder: (context, snapshot) {
        if (snapshot.connectionState != ConnectionState.done) {
          return const Scaffold(
            backgroundColor: Colors.transparent,
            body: Center(child: CircularProgressIndicator()),
          );
        }
        if (snapshot.hasError) {
          return Scaffold(
            backgroundColor: Colors.transparent,
            body: Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      Icons.person_off_outlined,
                      size: 44,
                      color: Theme.of(context).colorScheme.error,
                    ),
                    const SizedBox(height: 12),
                    Text(
                      AppStrings.t(context, 'noActiveIdentity'),
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 16),
                    FilledButton.icon(
                      onPressed: onRetry,
                      icon: const Icon(Icons.refresh),
                      label: Text(AppStrings.t(context, 'retry')),
                    ),
                  ],
                ),
              ),
            ),
          );
        }
        if (snapshot.data == null) {
          return missingIdentityBuilder(context);
        }
        return readyBuilder(context);
      },
    );
  }
}

class LayergramApp extends ConsumerStatefulWidget {
  const LayergramApp({super.key});

  @override
  ConsumerState<LayergramApp> createState() => _LayergramAppState();
}

class _LayergramAppState extends ConsumerState<LayergramApp>
    with WidgetsBindingObserver {
  late Future<LocalIdentity?> _identityFuture;
  late final Future<void> _lockStateFuture;
  late final AppLockIdleController _appLockIdleController;
  late final ExternalIngressCoordinator _externalIngress;
  final _deepLinks = DeepLinks();
  final _sharing = Sharing();
  StreamSubscription<Uri>? _linkSub;
  final _navKey = GlobalKey<NavigatorState>();
  final _lockNavKey = GlobalKey<NavigatorState>();
  StreamSubscription<List<SharedMediaFile>>? _sharedTextSub;
  ProviderSubscription<int>? _identityReloadSub;
  ProviderSubscription<bool>? _appLockEnabledSub;
  ProviderSubscription<int>? _appLockTimeoutSub;
  ProviderSubscription<bool>? _appNeedsUnlockSub;
  ProviderSubscription<int>? _appLockRequestSub;
  ProviderSubscription<PassphrasePreferences>? _passphrasePreferencesSub;
  bool _checkingPendingShare = false;
  bool _streamDeepLinkObserved = false;
  bool _externalIngressOperationActive = false;
  bool _lockRequested = false;
  final Set<String> _sharedTextsInFlight = <String>{};
  final Map<String, DateTime> _recentSharedTexts = <String, DateTime>{};
  final List<List<SharedMediaFile>> _opaqueSharedMediaBatches =
      <List<SharedMediaFile>>[];

  static const Duration _sharedTextDedupWindow = Duration(seconds: 4);
  static const int _maxOpaqueSharedMediaBatches = 4;
  static const int _maxOpaqueSharedMediaItemsPerBatch = 4;

  @override
  void initState() {
    super.initState();
    _appLockIdleController = AppLockIdleController(
      onLockRequired: () {
        if (!mounted) return;
        ref.read(appLockRequestTokenProvider.notifier).state++;
      },
    );
    _externalIngress = ExternalIngressCoordinator(
      maxTotalCodeUnits: StegoDecoder.maxCarrierCodeUnits,
    );
    WidgetsBinding.instance.addObserver(this);
    _lockStateFuture = _loadLockState();
    _reloadIdentity();
    _identityReloadSub = ref.listenManual<int>(
      identityReloadTokenProvider,
      (prev, next) {
        if (!mounted) return;
        _reloadIdentity();
        setState(() {});
      },
    )..read();
    _appLockEnabledSub = ref.listenManual<bool>(
      appLockEnabledProvider,
      (prev, next) {
        _appLockIdleController.updateLockConfig(
          enabled: next,
          timeoutSeconds: ref.read(appLockTimeoutProvider),
        );
      },
    )..read();
    _appLockTimeoutSub = ref.listenManual<int>(
      appLockTimeoutProvider,
      (prev, next) {
        _appLockIdleController.updateLockConfig(
          enabled: ref.read(appLockEnabledProvider),
          timeoutSeconds: next,
        );
      },
    )..read();
    _appNeedsUnlockSub = ref.listenManual<bool>(
      appNeedsUnlockProvider,
      (prev, next) {
        if (prev == null) return;
        if (next) {
          FocusManager.instance.primaryFocus?.unfocus();
          _appLockIdleController.onLocked();
        } else {
          _appLockIdleController.onUnlocked();
          // Refresh the identity future before any queued carrier can drain.
          // Otherwise a synchronous unlock notification could observe the
          // already-completed, locked startup future and consume the carrier
          // before identity restore has finished.
          _reloadIdentity();
          unawaited(
            _identityFuture.then((_) async {
              if (!_mayStartExternalIngress()) return;
              unawaited(
                ref.read(homeControllerProvider).warmSessionDisplayKeys(),
              );
              await _loadPendingSharedText();
              await _resumePendingExternalInputs();
            }),
          );
        }
      },
    )..read();
    _appLockRequestSub = ref.listenManual<int>(
      appLockRequestTokenProvider,
      (prev, next) {
        if (prev == null || next == prev) return;
        _requestAppLock();
      },
    )..read();
    _passphrasePreferencesSub = ref.listenManual<PassphrasePreferences>(
      passphrasePreferencesProvider,
      (prev, next) {
        final tc = ref.read(fsPassphraseTimeoutControllerProvider);
        tc.configure(
          timeout: next.timeout,
          expelOnScreenLock: next.expelOnScreenLock,
        );
        final pp = ref.read(passphraseProvider);
        if (pp.isActive && !tc.isActive) {
          tc.start();
        } else if (!pp.isActive && tc.isActive) {
          tc.stop();
        }
      },
    )..read();
    _loadScreenProtectionState();
    _loadTooltipState();
    _loadCoverMessageLengthLimit();
    _loadPreviewState();
    _loadSessionDecryptionCacheState();
    _startDeepLinks();
    _startSharedIntents();
  }

  Future<void> _loadTooltipState() async {
    final service = ref.read(tooltipServiceProvider);
    if (!AppPlatform.supportsHoverTooltips) {
      ref.read(tooltipsEnabledProvider.notifier).state = false;
      return;
    }
    final enabled = await service.isEnabled();
    ref.read(tooltipsEnabledProvider.notifier).state = enabled;
  }

  Future<void> _loadPreviewState() async {
    final service = ref.read(previewServiceProvider);
    final hidden = await service.isHidden();
    ref.read(hideChatPreviewProvider.notifier).state = hidden;
  }

  Future<void> _loadCoverMessageLengthLimit() async {
    final service = ref.read(coverMessageLengthLimitServiceProvider);
    final limit = await service.getLimit();
    if (!mounted) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      ref.read(coverMessageLengthLimitProvider.notifier).state = limit;
    });
  }

  Future<void> _loadSessionDecryptionCacheState() async {
    final service = ref.read(sessionDecryptionCacheServiceProvider);
    final enabled = await service.isEnabled();
    await _lockStateFuture;
    if (!mounted) return;
    ref.read(sessionDecryptionCacheEnabledProvider.notifier).state = enabled;
    if (enabled &&
        ref.read(appLockStateReadyProvider) &&
        !ref.read(appNeedsUnlockProvider)) {
      unawaited(ref.read(homeControllerProvider).warmSessionDisplayKeys());
    }
  }

  Future<void> _loadScreenProtectionState() async {
    final service = ref.read(screenProtectionServiceProvider);
    final enabled = await service.isEnabled();
    ref.read(screenProtectionEnabledProvider.notifier).state = enabled;
    await service.applyToPlatform(enabled);
  }

  void _startDeepLinks() {
    _linkSub?.cancel();
    _linkSub = _deepLinks.uriLinkStream.listen((uri) {
      _streamDeepLinkObserved = true;
      final value = uri.toString();
      if (value.isEmpty || value.length > StegoDecoder.maxCarrierCodeUnits) {
        return;
      }
      ref.read(pendingDeepLinkProvider.notifier).state = value;
    });

    _deepLinks.getInitialLinkString().then((value) {
      if (!mounted) return;
      if (_streamDeepLinkObserved) return;
      if (value == null || value.isEmpty) return;
      if (value.length > StegoDecoder.maxCarrierCodeUnits) return;
      ref.read(pendingDeepLinkProvider.notifier).state = value;
    });
  }

  void _startSharedIntents() {
    if (!AppPlatform.isAndroid && !AppPlatform.isIOS) return;

    _sharedTextSub?.cancel();
    final stream = _sharing.mediaStream;
    _sharedTextSub = stream.listen(
      _acceptSharedMediaBatch,
    );

    Future.microtask(_loadPendingSharedText);
  }

  Future<void> _loadPendingSharedText() async {
    if ((!AppPlatform.isAndroid && !AppPlatform.isIOS) ||
        _checkingPendingShare) {
      return;
    }

    _checkingPendingShare = true;
    try {
      final files = await _sharing.getInitialMedia();
      if (!mounted) return;

      if (files.isNotEmpty && !_mayStartExternalIngress()) {
        _enqueueOpaqueSharedMediaBatch(files);
        return;
      }

      final initialText = _firstSharedText(files);
      if (initialText != null) {
        // Acknowledge the platform share only in the unlocked processing
        // path, after the coordinator has retained its bounded in-memory copy.
        ref.read(pendingSharedTextProvider.notifier).state = initialText;
        return;
      }

      // iOS consumePendingText is destructive. Leave that durable handoff in
      // the app-group store until the user has unlocked Layergram.
      if (!_mayStartExternalIngress()) return;
      final pendingText = await _sharing.takePendingText();
      if (!mounted) return;
      if (pendingText == null) return;
      ref.read(pendingSharedTextProvider.notifier).state = pendingText;
    } finally {
      _checkingPendingShare = false;
    }
  }

  String? _firstSharedText(List<SharedMediaFile> files) {
    for (final file in files) {
      final text = extractSharedText(file);
      if (text != null &&
          text.length <= StegoDecoder.maxCarrierCodeUnits &&
          text.trim().isNotEmpty) {
        return text.trim();
      }
    }
    return null;
  }

  void _acceptSharedMediaBatch(List<SharedMediaFile> files) {
    if (!mounted || files.isEmpty) return;
    if (!_mayStartExternalIngress()) {
      _enqueueOpaqueSharedMediaBatch(files);
      return;
    }
    final sharedText = _firstSharedText(files);
    if (sharedText == null) return;
    _stageExternalIngress(ExternalIngressKind.sharedText, sharedText);
  }

  void _enqueueOpaqueSharedMediaBatch(List<SharedMediaFile> files) {
    if (files.isEmpty ||
        _opaqueSharedMediaBatches.length >= _maxOpaqueSharedMediaBatches) {
      return;
    }
    _opaqueSharedMediaBatches.add(
      List<SharedMediaFile>.unmodifiable(
        files.take(_maxOpaqueSharedMediaItemsPerBatch),
      ),
    );
  }

  void _stageOpaqueSharedMediaBatches() {
    while (_mayStartExternalIngress() && _opaqueSharedMediaBatches.isNotEmpty) {
      final batch = _opaqueSharedMediaBatches.first;
      final sharedText = _firstSharedText(batch);
      if (sharedText == null) {
        _opaqueSharedMediaBatches.removeAt(0);
        continue;
      }
      if (!_externalIngress.enqueue(
        kind: ExternalIngressKind.sharedText,
        text: sharedText,
      )) {
        return;
      }
      _opaqueSharedMediaBatches.removeAt(0);
    }
  }

  bool _claimSharedText(String text) {
    if (text.length > StegoDecoder.maxCarrierCodeUnits) {
      return false;
    }
    final normalized = text.trim();
    if (normalized.isEmpty) {
      return false;
    }

    final now = DateTime.now();
    _recentSharedTexts.removeWhere(
      (_, processedAt) => now.difference(processedAt) > _sharedTextDedupWindow,
    );

    if (_sharedTextsInFlight.contains(normalized)) {
      return false;
    }

    final lastProcessed = _recentSharedTexts[normalized];
    if (lastProcessed != null &&
        now.difference(lastProcessed) < _sharedTextDedupWindow) {
      return false;
    }

    _sharedTextsInFlight.add(normalized);
    return true;
  }

  void _releaseSharedText(String text, {required bool processed}) {
    final normalized = text.trim();
    if (normalized.isEmpty) {
      return;
    }
    _sharedTextsInFlight.remove(normalized);
    if (processed) {
      _recentSharedTexts[normalized] = DateTime.now();
    }
  }

  bool _isShareRedirectLink(String text) {
    final uri = Uri.tryParse(text.trim());
    if (uri == null || uri.scheme.isEmpty) {
      return false;
    }
    return uri.scheme.toLowerCase().startsWith('sharemedia-') &&
        uri.path.toLowerCase() == 'share';
  }

  bool _isIdentityLink(String text) {
    return text.trim().toLowerCase().startsWith('layergram://i/');
  }

  bool _isMessageLink(String text) {
    return text.trim().toLowerCase().startsWith('layergram://m/');
  }

  Future<void> _handleIncomingLink(String text) async {
    if (!_isExternalIngressUnlocked()) {
      _externalIngress.enqueue(
        kind: ExternalIngressKind.deepLink,
        text: text,
      );
      return;
    }
    if (text.length > StegoDecoder.maxCarrierCodeUnits) return;
    final normalized = text.trim();
    if (normalized.isEmpty) {
      return;
    }
    if (_isShareRedirectLink(normalized)) {
      Future.microtask(_loadPendingSharedText);
      return;
    }
    if (_isIdentityLink(normalized)) {
      _openSharedIdentity(normalized);
      return;
    }
    if (_isMessageLink(normalized)) {
      await _processSharedText(normalized);
      return;
    }

    final nav = _navKey.currentState;
    if (nav == null) return;
    unawaited(
      nav.push(
        MaterialPageRoute(
          builder: (_) => AddIdentityView(initialText: normalized),
        ),
      ),
    );
  }

  bool _isSharedIdentity(String text) {
    final normalized = text.trim();
    if (normalized.isEmpty) return false;

    final identities = ref.read(identitiesControllerProvider);
    try {
      if (normalized.startsWith('layergram://')) {
        identities.parseIdentityFromLink(normalized);
      } else {
        identities.parseIdentityFromText(normalized);
      }
      return true;
    } catch (_) {
      return false;
    }
  }

  void _openSharedIdentity(String text) {
    final nav = _navKey.currentState;
    if (nav == null) return;
    unawaited(
      nav.push(
        MaterialPageRoute(
          builder: (_) => AddIdentityView(initialText: text),
        ),
      ),
    );
  }

  Future<void> _processSharedText(String text) async {
    if (!_isExternalIngressUnlocked()) {
      _externalIngress.enqueue(
        kind: ExternalIngressKind.sharedText,
        text: text,
      );
      return;
    }
    if (text.length > StegoDecoder.maxCarrierCodeUnits) return;
    final normalized = text.trim();
    if (normalized.isEmpty) return;

    if (_isSharedIdentity(normalized)) {
      _openSharedIdentity(normalized);
      return;
    }

    final outcome =
        await ref.read(homeControllerProvider).decodeHiddenMessage(normalized);
    if (!mounted) return;
    if (!_isExternalIngressUnlocked()) {
      _externalIngress.enqueue(
        kind: ExternalIngressKind.sharedText,
        text: normalized,
      );
      return;
    }

    switch (outcome.kind) {
      case DecodeKind.success:
        final senderId = outcome.payload?.senderId;
        final sender = senderId == null
            ? null
            : await ref
                .read(identitiesRepositoryProvider)
                .getRemoteById(senderId);
        if (!mounted || !_isExternalIngressUnlocked()) {
          _externalIngress.enqueue(
            kind: ExternalIngressKind.sharedText,
            text: normalized,
          );
          return;
        }

        final ctx = _navKey.currentContext;
        if (ctx == null || !ctx.mounted) return;
        final messenger = ScaffoldMessenger.of(ctx);
        final strings = AppStrings.t;

        if (sender == null) {
          messenger.showSnackBar(
            SnackBar(content: Text(strings(ctx, 'unknownSender'))),
          );
          return;
        }
        _navKey.currentState?.push(
          MaterialPageRoute(builder: (_) => ChatView(contact: sender)),
        );
        break;
      case DecodeKind.v3Control:
        final contact = outcome.v3Inbound?.contact;
        final ctx = _navKey.currentContext;
        if (contact == null || ctx == null || !ctx.mounted) return;
        _navKey.currentState?.push(
          MaterialPageRoute(builder: (_) => ChatView(contact: contact)),
        );
        break;
      default:
        {
          final ctx = _navKey.currentContext;
          if (ctx == null || !ctx.mounted) return;
          ScaffoldMessenger.of(ctx).showSnackBar(
            SnackBar(content: Text(AppStrings.t(ctx, 'noMessageFoundDesc'))),
          );
        }
        break;
    }
  }

  Future<void> _loadLockState() async {
    final service = ref.read(appLockServiceProvider);
    final enabled = await service.isEnabled();
    final timeout = await service.getTimeoutSeconds();
    final forcePin = await service.getForcePin();
    final biometricSupported = await service.isBiometricSupported();
    if (!mounted) return;
    ref.read(appLockTimeoutProvider.notifier).state = timeout;
    ref.read(appLockForcePinProvider.notifier).state =
        forcePin || !biometricSupported;
    ref.read(appLockEnabledProvider.notifier).state = enabled;
    ref.read(appNeedsUnlockProvider.notifier).state = enabled;
    _appLockIdleController.updateLockConfig(
      enabled: enabled,
      timeoutSeconds: timeout,
    );
    ref.read(appLockStateReadyProvider.notifier).state = true;
    if (!enabled) {
      unawaited(_resumePendingExternalInputs());
    }
  }

  void _reloadIdentity() {
    _identityFuture = _lockStateFuture.then((_) async {
      if (!mounted || ref.read(appNeedsUnlockProvider)) return null;
      final identity =
          await ref.read(identityManagerProvider).getLocalIdentity();
      if (!mounted || ref.read(appNeedsUnlockProvider)) return null;
      final nextId = identity?.identityId;
      final currentId = ref.read(activeIdentityIdProvider);
      if (currentId != nextId) {
        ref.read(activeIdentityIdProvider.notifier).state = nextId;
      }
      if (nextId != null && !ref.read(appNeedsUnlockProvider)) {
        unawaited(ref.read(homeControllerProvider).warmSessionDisplayKeys());
      }
      // Load persisted FS state after identity is loaded
      if (!ref.read(appNeedsUnlockProvider)) {
        await _loadPersistedFsState();
      }
      return identity;
    });
  }

  bool _isExternalIngressUnlocked() =>
      mounted &&
      ref.read(appLockStateReadyProvider) &&
      !ref.read(appNeedsUnlockProvider);

  bool _mayStartExternalIngress() =>
      _isExternalIngressUnlocked() && !_lockRequested;

  void _requestAppLock() {
    if (!mounted || ref.read(appNeedsUnlockProvider) || _lockRequested) return;
    _lockRequested = true;
    FocusManager.instance.primaryFocus?.unfocus();
    setState(() {});
    if (!_externalIngressOperationActive) {
      _commitRequestedAppLock();
    }
  }

  void _commitRequestedAppLock() {
    if (!mounted || !_lockRequested || _externalIngressOperationActive) return;
    ref.read(appNeedsUnlockProvider.notifier).state = true;
    _lockRequested = false;
    setState(() {});
  }

  bool _stageExternalIngress(ExternalIngressKind kind, String value) {
    final accepted = _externalIngress.enqueue(kind: kind, text: value);
    if (accepted && _mayStartExternalIngress()) {
      unawaited(_resumePendingExternalInputs());
    }
    return accepted;
  }

  void _stagePendingProviderInputs() {
    final pendingLink = ref.read(pendingDeepLinkProvider);
    if (pendingLink != null && pendingLink.isNotEmpty) {
      if (_externalIngress.enqueue(
        kind: ExternalIngressKind.deepLink,
        text: pendingLink,
      )) {
        ref.read(pendingDeepLinkProvider.notifier).state = null;
      }
    }
    final pendingShare = ref.read(pendingSharedTextProvider);
    if (pendingShare != null && pendingShare.isNotEmpty) {
      if (_externalIngress.enqueue(
        kind: ExternalIngressKind.sharedText,
        text: pendingShare,
      )) {
        ref.read(pendingSharedTextProvider.notifier).state = null;
      }
    }
  }

  Future<void> _processExternalIngressItem(ExternalIngressItem item) async {
    _externalIngressOperationActive = true;
    try {
      switch (item.kind) {
        case ExternalIngressKind.deepLink:
          await _handleIncomingLink(item.text);
        case ExternalIngressKind.sharedText:
          final normalized = item.text.trim();
          if (!_claimSharedText(normalized)) return;
          var processed = false;
          try {
            _sharing.reset();
            await _sharing.clearPendingShare();
            await _processSharedText(normalized);
            processed = _isExternalIngressUnlocked();
          } finally {
            _releaseSharedText(normalized, processed: processed);
          }
      }
    } finally {
      _externalIngressOperationActive = false;
      _commitRequestedAppLock();
    }
  }

  Future<void> _resumePendingExternalInputs() async {
    if (!_mayStartExternalIngress()) return;
    _stageOpaqueSharedMediaBatches();
    _stagePendingProviderInputs();
    await _identityFuture;
    if (!_mayStartExternalIngress()) return;
    // A provider can temporarily retain one deep link and one share if the
    // bounded coordinator was full. Drain once, restage those spill slots,
    // then drain them so the user's handoff cannot become stranded.
    for (var pass = 0; pass < 3; pass++) {
      await _externalIngress.drain(
        mayProcess: _mayStartExternalIngress,
        handler: _processExternalIngressItem,
      );
      if (!_mayStartExternalIngress()) return;
      _stageOpaqueSharedMediaBatches();
      _stagePendingProviderInputs();
      if (_externalIngress.pendingCount == 0 &&
          _opaqueSharedMediaBatches.isEmpty) {
        return;
      }
    }
  }

  Future<void> _loadPersistedFsState() async {
    await restorePersistedFsRuntimeState(ref.read);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    final screenProtectionEnabled = ref.read(screenProtectionEnabledProvider);
    final isSharing = ref.read(isSharingProvider);
    if (screenProtectionEnabled && !isSharing) {
      ref.read(privacyShieldVisibleProvider.notifier).state =
          state != AppLifecycleState.resumed;
    } else {
      ref.read(privacyShieldVisibleProvider.notifier).state = false;
    }

    if (state == AppLifecycleState.resumed) {
      Future.microtask(_loadPendingSharedText);
      if (!ref.read(appNeedsUnlockProvider)) {
        unawaited(ref.read(homeControllerProvider).warmSessionDisplayKeys());
      }
    } else {
      ref.read(homeControllerProvider).clearSessionDecryptionCache();
    }

    // Passphrase timeout controller lifecycle (§11.3)
    ref
        .read(fsPassphraseTimeoutControllerProvider)
        .onAppLifecycleChanged(state);

    final lockEnabled = ref.read(appLockEnabledProvider);
    if (!lockEnabled) return;
    _appLockIdleController.onAppLifecycleChanged(state);
  }

  @override
  void dispose() {
    _linkSub?.cancel();
    _sharedTextSub?.cancel();
    _identityReloadSub?.close();
    _appLockEnabledSub?.close();
    _appLockTimeoutSub?.close();
    _appNeedsUnlockSub?.close();
    _appLockRequestSub?.close();
    _passphrasePreferencesSub?.close();
    _externalIngress.close();
    _opaqueSharedMediaBatches.clear();
    ref.read(fsPassphraseTimeoutControllerProvider).dispose();
    _appLockIdleController.dispose();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // Keeps the single v3 runtime owner synchronized with identity and
    // passphrase and app-lock changes. It resolves to null without loading or
    // retaining a native runtime while activation is disabled or the app is
    // locked.
    ref.watch(v3ApplicationSessionRuntimeProvider);
    final themeMode = ref.watch(themeModeProvider);
    final needsUnlock = ref.watch(appNeedsUnlockProvider);
    final lockStateReady = ref.watch(appLockStateReadyProvider);
    final screenProtectionEnabled = ref.watch(screenProtectionEnabledProvider);
    final privacyShieldVisible = ref.watch(privacyShieldVisibleProvider);
    final tooltipsEnabled = ref.watch(tooltipsEnabledProvider);
    final tooltipsVisible =
        AppPlatform.supportsHoverTooltips && tooltipsEnabled;

    ref.listen<String?>(pendingDeepLinkProvider, (prev, next) {
      if (next == null || next.isEmpty) return;
      if (_stageExternalIngress(ExternalIngressKind.deepLink, next)) {
        ref.read(pendingDeepLinkProvider.notifier).state = null;
      }
    });

    ref.listen<String?>(pendingSharedTextProvider, (prev, next) {
      if (next == null || next.isEmpty) return;
      if (_stageExternalIngress(ExternalIngressKind.sharedText, next)) {
        ref.read(pendingSharedTextProvider.notifier).state = null;
      }
    });

    return MaterialApp(
      title: 'Layergram',
      debugShowCheckedModeBanner: false,
      navigatorKey: _navKey,
      theme: AppTheme.light(),
      darkTheme: AppTheme.dark(),
      themeMode: themeMode,
      locale: context.locale,
      supportedLocales: context.supportedLocales,
      localizationsDelegates: context.localizationDelegates,
      builder: (context, child) {
        return Listener(
          behavior: HitTestBehavior.translucent,
          onPointerDown: (_) => _appLockIdleController.onUserInteraction(),
          onPointerSignal: (_) => _appLockIdleController.onUserInteraction(),
          onPointerPanZoomStart: (_) =>
              _appLockIdleController.onUserInteraction(),
          child: TooltipVisibility(
            visible: tooltipsVisible,
            child: Stack(
              fit: StackFit.expand,
              children: [
                AppLockGate(
                  lockStateReady: lockStateReady && !_lockRequested,
                  needsUnlock: needsUnlock,
                  lockNavigatorKey: _lockNavKey,
                  unlockBuilder: (_) => UnlockView(
                    onUnlocked: () {
                      ref.read(appNeedsUnlockProvider.notifier).state = false;
                    },
                  ),
                  child: LayergramBackground(
                    child: child ?? const SizedBox(),
                  ),
                ),
                if (screenProtectionEnabled && privacyShieldVisible)
                  const PrivacyShieldOverlay(),
              ],
            ),
          ),
        );
      },
      home: IdentityStartupGate(
        identityFuture: _identityFuture,
        onRetry: () {
          _reloadIdentity();
          setState(() {});
        },
        missingIdentityBuilder: (context) => CreateOrRestoreView(
          onCompleted: (bool isRestore) {
            _reloadIdentity();
            if (isRestore) {
              // After restore, go to messages (default index 0)
              ref.read(appShellInitialIndexProvider.notifier).state = null;
            } else {
              // After create, go to my identity page
              // Calculate index: 1 (home) + extraFolders + 1 (identities) = myIdentity index
              final caps = ref.read(layergramCapabilitiesProvider);
              final extraFolders = caps.chatFolders.isAvailable
                  ? (ref.read(chatFoldersProvider).valueOrNull ?? const [])
                  : const <ChatFolder>[];
              final myIdentityIndex = 1 + extraFolders.length + 1;
              ref.read(appShellInitialIndexProvider.notifier).state =
                  myIdentityIndex;
            }
            setState(() {});
          },
        ),
        readyBuilder: (context) => const AppShell(),
      ),
    );
  }
}
