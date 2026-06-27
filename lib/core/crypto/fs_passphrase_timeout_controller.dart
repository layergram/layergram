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

import 'package:flutter/widgets.dart';

import 'fs_passphrase_preferences.dart';

/// Controls the automatic expulsion of passphrase-derived contexts (spec §11.3).
///
/// **Timeout behavior (spec §11.3):**
/// - A configurable timer runs while the passphrase context is active.
/// - On timeout, [onExpel] is called → passphrase wiped from RAM.
/// - Timer resets on user interaction ([onUserInteraction]).
/// - Backgrounding keeps the timer running until expiry (§11.3 — "keep
///   passphrase active until timeout expires").
/// - Manual lock → immediate expulsion.
/// - App killed → passphrase lost naturally (no timer needed).
///
/// **Screen lock behavior (spec §11.4):**
/// - Optional: if [expelOnScreenLock] is true, the passphrase is expelled
///   immediately when the screen locks (app becomes inactive/paused).
/// - Default: false (timeout-based expulsion only).
///
/// **First activation (§11.3.1):**
/// - Uses hardcoded default timeout (2 minutes) until user changes it.
class FsPassphraseTimeoutController {
  FsPassphraseTimeoutController({
    required void Function() onExpel,
    DateTime Function()? clock,
  })  : _onExpel = onExpel,
        _clock = clock ?? (() => DateTime.now());

  final void Function() _onExpel;
  final DateTime Function() _clock;

  Timer? _timer;
  DateTime? _lastBackgroundedAt;
  bool _active = false;
  PassphraseTimeout _timeout = PassphraseTimeout.defaultTimeout;
  bool _expelOnScreenLock = false;

  // ---------------------------------------------------------------------------
  // Configuration
  // ---------------------------------------------------------------------------

  /// Updates the timeout and screen lock settings.
  ///
  /// If the passphrase context is active, the timer is rearmed with the new
  /// timeout immediately.
  void configure({
    required PassphraseTimeout timeout,
    required bool expelOnScreenLock,
  }) {
    _timeout = timeout;
    _expelOnScreenLock = expelOnScreenLock;
    if (_active && !_timeout.isManual) {
      _armTimer();
    } else if (_active && _timeout.isManual) {
      _cancelTimer();
    }
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /// Starts the timeout controller when a passphrase context becomes active.
  void start() {
    _active = true;
    _lastBackgroundedAt = null;
    if (!_timeout.isManual) {
      _armTimer();
    }
  }

  /// Stops the timeout controller (passphrase deactivated or app disposing).
  void stop() {
    _active = false;
    _cancelTimer();
    _lastBackgroundedAt = null;
  }

  /// Whether the controller is actively guarding a passphrase context.
  bool get isActive => _active;

  /// The currently configured timeout.
  PassphraseTimeout get timeout => _timeout;

  /// Whether screen lock expulsion is enabled.
  bool get expelOnScreenLock => _expelOnScreenLock;

  // ---------------------------------------------------------------------------
  // User interaction
  // ---------------------------------------------------------------------------

  /// Resets the timeout timer on user interaction.
  ///
  /// Call this when the user taps, types, or otherwise interacts with the app
  /// while a passphrase context is active.
  void onUserInteraction() {
    if (!_active || _timeout.isManual) return;
    _armTimer();
  }

  /// Immediately expels the passphrase (manual lock action).
  void expelNow() {
    if (!_active) return;
    _doExpel();
  }

  // ---------------------------------------------------------------------------
  // App lifecycle
  // ---------------------------------------------------------------------------

  /// Handles app lifecycle state changes.
  ///
  /// **Spec §11.3 behavior:**
  /// - Backgrounding: timer continues running (timeout-based expulsion).
  /// - Screen lock (inactive/paused) + [_expelOnScreenLock]: immediate expulsion.
  /// - Resume: check if timeout elapsed while backgrounded.
  void onAppLifecycleChanged(AppLifecycleState state) {
    if (!_active) return;

    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      if (_expelOnScreenLock) {
        _doExpel();
        return;
      }
      _lastBackgroundedAt = _clock();
      _cancelTimer();
      return;
    }

    if (state == AppLifecycleState.inactive) {
      _lastBackgroundedAt ??= _clock();
      if (_expelOnScreenLock) {
        _doExpel();
        return;
      }
      _cancelTimer();
      return;
    }

    if (state != AppLifecycleState.resumed) return;

    final last = _lastBackgroundedAt;
    _lastBackgroundedAt = null;

    if (!_active) return;

    if (_timeout.isManual) return;

    if (last != null) {
      final elapsed = _clock().difference(last);
      if (elapsed >= _timeout.duration) {
        _doExpel();
        return;
      }
    }

    _armTimer();
  }

  // ---------------------------------------------------------------------------
  // Dispose
  // ---------------------------------------------------------------------------

  void dispose() {
    _cancelTimer();
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  void _armTimer() {
    _cancelTimer();
    _timer = Timer(_timeout.duration, _doExpel);
  }

  void _cancelTimer() {
    _timer?.cancel();
    _timer = null;
  }

  void _doExpel() {
    _active = false;
    _cancelTimer();
    _lastBackgroundedAt = null;
    _onExpel();
  }
}
