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
import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui' show FrameTiming;

import 'package:easy_localization/easy_localization.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'core/capabilities/chat_folders_capability.dart';
import 'core/crypto/aux_record_cipher.dart';
import 'core/crypto/fs_double_ratchet.dart';
import 'core/crypto/fs_passphrase_preferences.dart';
import 'core/providers.dart';
import 'core/security/app_lock_idle_controller.dart';
import 'features/identities/add_identity_view.dart';
import 'features/identities/identities_controller.dart';
import 'features/home/chat_view.dart';
import 'features/home/home_controller.dart';
import 'features/onboarding/create_or_restore_view.dart';
import 'features/security/unlock_view.dart';
import 'features/shell/app_shell.dart';
import 'l10n/app_strings.dart';
import 'theme/app_theme.dart';
import 'ui/layergram_background.dart';
import 'ui/privacy_shield_overlay.dart';
import 'utils/app_platform.dart';
import 'utils/deep_links.dart';
import 'utils/sharing.dart';

class LayergramApp extends ConsumerStatefulWidget {
  const LayergramApp({super.key});

  @override
  ConsumerState<LayergramApp> createState() => _LayergramAppState();
}

class _LayergramAppState extends ConsumerState<LayergramApp>
    with WidgetsBindingObserver {
  late Future _identityFuture;
  late final AppLockIdleController _appLockIdleController;
  final _deepLinks = DeepLinks();
  final _sharing = Sharing();
  StreamSubscription<Uri>? _linkSub;
  final _navKey = GlobalKey<NavigatorState>();
  StreamSubscription<List<SharedMediaFile>>? _sharedTextSub;
  ProviderSubscription<int>? _identityReloadSub;
  ProviderSubscription<bool>? _appLockEnabledSub;
  ProviderSubscription<int>? _appLockTimeoutSub;
  ProviderSubscription<bool>? _appNeedsUnlockSub;
  ProviderSubscription<PassphrasePreferences>? _passphrasePreferencesSub;
  bool _checkingPendingShare = false;
  final ListQueue<bool> _recentSlowFrames = ListQueue<bool>();
  final Set<String> _sharedTextsInFlight = <String>{};
  final Map<String, DateTime> _recentSharedTexts = <String, DateTime>{};

  static const Duration _sharedTextDedupWindow = Duration(seconds: 4);

  @override
  void initState() {
    super.initState();
    _appLockIdleController = AppLockIdleController(
      onLockRequired: () {
        if (!mounted) return;
        ref.read(appNeedsUnlockProvider.notifier).state = true;
      },
    );
    WidgetsBinding.instance.addObserver(this);
    WidgetsBinding.instance.addTimingsCallback(_handleFrameTimings);
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
        if (next) {
          _appLockIdleController.onLocked();
        } else {
          _appLockIdleController.onUnlocked();
          unawaited(ref.read(homeControllerProvider).warmSessionDisplayKeys());
        }
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
    _loadLockState();
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
    ref.read(sessionDecryptionCacheEnabledProvider.notifier).state = enabled;
    if (enabled && !ref.read(appNeedsUnlockProvider)) {
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
      ref.read(pendingDeepLinkProvider.notifier).state = uri.toString();
    });

    _deepLinks.getInitialLinkString().then((value) {
      if (!mounted) return;
      if (value == null || value.trim().isEmpty) return;
      ref.read(pendingDeepLinkProvider.notifier).state = value;
    });
  }

  void _startSharedIntents() {
    if (!AppPlatform.isAndroid && !AppPlatform.isIOS) return;

    _sharedTextSub?.cancel();
    final stream = _sharing.mediaStream;
    _sharedTextSub = stream.listen(
      (files) {
        final sharedText = _firstSharedText(files);
        if (sharedText == null) return;
        ref.read(pendingSharedTextProvider.notifier).state = sharedText;
      },
    );

    Future.microtask(_loadPendingSharedText);
  }

  void _handleFrameTimings(List<FrameTiming> timings) {
    for (final timing in timings) {
      final buildMicros = timing.buildDuration.inMicroseconds;
      final rasterMicros = timing.rasterDuration.inMicroseconds;
      final totalMicros = timing.totalSpan.inMicroseconds;
      final slow =
          buildMicros >= 14000 || rasterMicros >= 16000 || totalMicros >= 28000;
      _recentSlowFrames.addLast(slow);
      if (_recentSlowFrames.length > 24) {
        _recentSlowFrames.removeFirst();
      }
    }

    if (_recentSlowFrames.length < 12) {
      return;
    }

    final slowCount = _recentSlowFrames.where((slow) => slow).length;
    final reducedEffects = ref.read(reducedEffectsProvider);
    if (!reducedEffects && slowCount >= 6) {
      ref.read(reducedEffectsProvider.notifier).state = true;
    } else if (reducedEffects && slowCount <= 1) {
      ref.read(reducedEffectsProvider.notifier).state = false;
    }
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

      final initialText = _firstSharedText(files);
      if (initialText != null) {
        await _sharing.clearPendingShare();
        if (!mounted) return;
        ref.read(pendingSharedTextProvider.notifier).state = initialText;
        return;
      }

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
      if (text != null && text.trim().isNotEmpty) {
        return text.trim();
      }
    }
    return null;
  }

  bool _claimSharedText(String text) {
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
    _recentSharedTexts[normalized] = now;
    return true;
  }

  void _releaseSharedText(String text) {
    final normalized = text.trim();
    if (normalized.isEmpty) {
      return;
    }
    _sharedTextsInFlight.remove(normalized);
    _recentSharedTexts[normalized] = DateTime.now();
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
    final normalized = text.trim();
    if (normalized.isEmpty) {
      return;
    }
    if (_isShareRedirectLink(normalized)) {
      Future.microtask(_loadPendingSharedText);
      return;
    }
    if (_isIdentityLink(normalized)) {
      await _openSharedIdentity(normalized);
      return;
    }
    if (_isMessageLink(normalized)) {
      await _processSharedText(normalized);
      return;
    }

    final nav = _navKey.currentState;
    if (nav == null) return;
    await nav.push(
      MaterialPageRoute(
        builder: (_) => AddIdentityView(initialText: normalized),
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

  Future<void> _openSharedIdentity(String text) async {
    final nav = _navKey.currentState;
    if (nav == null) return;
    await nav.push(
      MaterialPageRoute(
        builder: (_) => AddIdentityView(initialText: text),
      ),
    );
  }

  Future<void> _processSharedText(String text) async {
    final normalized = text.trim();
    if (normalized.isEmpty) return;

    if (_isSharedIdentity(normalized)) {
      await _openSharedIdentity(normalized);
      return;
    }

    final outcome =
        await ref.read(homeControllerProvider).decodeHiddenMessage(normalized);
    if (!mounted) return;

    switch (outcome.kind) {
      case DecodeKind.success:
        final senderId = outcome.payload?.senderId;
        final sender = senderId == null
            ? null
            : await ref
                .read(identitiesRepositoryProvider)
                .getRemoteById(senderId);
        if (!mounted) return;

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
    ref.read(appLockTimeoutProvider.notifier).state = timeout;
    ref.read(appLockForcePinProvider.notifier).state =
        forcePin || !biometricSupported;
    ref.read(appLockEnabledProvider.notifier).state = enabled;
    ref.read(appNeedsUnlockProvider.notifier).state = enabled;
    _appLockIdleController.updateLockConfig(
      enabled: enabled,
      timeoutSeconds: timeout,
    );
  }

  void _reloadIdentity() {
    _identityFuture = ref
        .read(identityManagerProvider)
        .getLocalIdentity()
        .then((identity) async {
      final nextId = identity?.identityId;
      final currentId = ref.read(activeIdentityIdProvider);
      if (currentId != nextId) {
        ref.read(activeIdentityIdProvider.notifier).state = nextId;
      }
      if (nextId != null && !ref.read(appNeedsUnlockProvider)) {
        unawaited(ref.read(homeControllerProvider).warmSessionDisplayKeys());
      }
      // Load persisted FS state after identity is loaded
      await _loadPersistedFsState();
      return identity;
    });
  }

  Future<void> _loadPersistedFsState() async {
    try {
      // Get the private key (identity or passphrase-derived)
      final privateKeyB64 =
          await ref.read(identityManagerProvider).getLocalPrivateKeyBase64();
      if (privateKeyB64 == null) {
        return;
      }

      // Derive aux storage key
      final keyBytes = Uint8List.fromList(base64Decode(privateKeyB64));
      final auxKey = await AuxRecordCipher.deriveAuxStorageKey(keyBytes);

      // Set up aux repository context
      final auxRepo = ref.read(auxRecordRepositoryProvider);
      auxRepo.setActiveContext(
        scopeToken: 'primary',
        auxStorageKey: auxKey,
      );

      // Load persisted FS states
      await ref.read(fsStatePersistenceServiceProvider).loadPersistedState();

      // Load persisted ratchet states into cache
      final ratchetStates = await ref
          .read(fsRatchetPersistenceServiceProvider)
          .loadAllRatchetStates();
      final cache = <String, RatchetState>{};
      for (final state in ratchetStates) {
        cache[state.sessionId] = state;
      }
      ref.read(fsRatchetStateCacheProvider.notifier).state = cache;
    } catch (_) {
      // Silently fail - FS state will start fresh (legacyOnly)
    }
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
      _recentSlowFrames.clear();
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
    _passphrasePreferencesSub?.close();
    ref.read(fsPassphraseTimeoutControllerProvider).dispose();
    _appLockIdleController.dispose();
    WidgetsBinding.instance.removeTimingsCallback(_handleFrameTimings);
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final themeMode = ref.watch(themeModeProvider);
    final needsUnlock = ref.watch(appNeedsUnlockProvider);
    final screenProtectionEnabled = ref.watch(screenProtectionEnabledProvider);
    final privacyShieldVisible = ref.watch(privacyShieldVisibleProvider);
    final reducedEffects = ref.watch(reducedEffectsProvider);
    final backgroundAnimationPaused =
        ref.watch(backgroundAnimationPausedProvider);
    final tooltipsEnabled = ref.watch(tooltipsEnabledProvider);
    final tooltipsVisible =
        AppPlatform.supportsHoverTooltips && tooltipsEnabled;

    ref.listen<String?>(pendingDeepLinkProvider, (prev, next) {
      if (next == null || next.trim().isEmpty) return;
      Future.microtask(() async {
        await _handleIncomingLink(next);
        if (mounted) {
          ref.read(pendingDeepLinkProvider.notifier).state = null;
        }
      });
    });

    ref.listen<String?>(pendingSharedTextProvider, (prev, next) {
      if (next == null || next.trim().isEmpty) return;
      Future.microtask(() async {
        final normalized = next.trim();
        if (!_claimSharedText(normalized)) {
          if (mounted && ref.read(pendingSharedTextProvider) == next) {
            ref.read(pendingSharedTextProvider.notifier).state = null;
          }
          return;
        }

        try {
          _sharing.reset();
          await _sharing.clearPendingShare();
          await _processSharedText(normalized);
        } finally {
          _releaseSharedText(normalized);
          if (mounted && ref.read(pendingSharedTextProvider) == next) {
            ref.read(pendingSharedTextProvider.notifier).state = null;
          }
        }
      });
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
        final mediaQuery = MediaQuery.maybeOf(context);
        final effectiveReducedEffects =
            reducedEffects || (mediaQuery?.disableAnimations ?? false);
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
                LayergramBackground(
                  reducedEffects: effectiveReducedEffects,
                  pauseAnimation: backgroundAnimationPaused,
                  child: child ?? const SizedBox(),
                ),
                if (screenProtectionEnabled && privacyShieldVisible)
                  const PrivacyShieldOverlay(),
              ],
            ),
          ),
        );
      },
      home: FutureBuilder(
        future: _identityFuture,
        builder: (context, snapshot) {
          if (snapshot.connectionState != ConnectionState.done) {
            return const Scaffold(
              backgroundColor: Colors.transparent,
              body: Center(child: CircularProgressIndicator()),
            );
          }
          if (snapshot.data == null) {
            return CreateOrRestoreView(
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
            );
          }
          if (needsUnlock) {
            return UnlockView(
              onUnlocked: () {
                ref.read(appNeedsUnlockProvider.notifier).state = false;
              },
            );
          }
          return const AppShell();
        },
      ),
    );
  }
}
