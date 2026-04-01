import 'dart:async';

import 'package:flutter/widgets.dart';

class AppLockIdleController {
  AppLockIdleController({
    required void Function() onLockRequired,
  }) : _onLockRequired = onLockRequired;

  final void Function() _onLockRequired;

  Timer? _foregroundTimer;
  DateTime? _lastBackgroundedAt;
  bool _enabled = false;
  bool _locked = true;
  int _timeoutSeconds = 60;

  void updateLockConfig({
    required bool enabled,
    required int timeoutSeconds,
  }) {
    _enabled = enabled;
    _timeoutSeconds = timeoutSeconds;

    if (!_enabled) {
      _cancelForegroundTimer();
      _lastBackgroundedAt = null;
      _locked = false;
      return;
    }

    if (_locked || _timeoutSeconds <= 0) {
      _cancelForegroundTimer();
      return;
    }

    _armForegroundTimer();
  }

  void onUserInteraction() {
    if (!_enabled || _locked || _timeoutSeconds <= 0) return;
    _armForegroundTimer();
  }

  void onUnlocked() {
    _locked = false;
    _lastBackgroundedAt = null;
    if (!_enabled || _timeoutSeconds <= 0) {
      _cancelForegroundTimer();
      return;
    }
    _armForegroundTimer();
  }

  void onLocked() {
    _locked = true;
    _cancelForegroundTimer();
  }

  void onAppLifecycleChanged(AppLifecycleState state) {
    if (!_enabled) return;

    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      _lastBackgroundedAt = DateTime.now();
      _cancelForegroundTimer();
      return;
    }

    if (state == AppLifecycleState.inactive) {
      _lastBackgroundedAt ??= DateTime.now();
      _cancelForegroundTimer();
      return;
    }

    if (state != AppLifecycleState.resumed) return;

    final last = _lastBackgroundedAt;
    _lastBackgroundedAt = null;

    if (last != null) {
      if (_timeoutSeconds <= 0) {
        _requireLock();
        return;
      }

      final elapsed = DateTime.now().difference(last).inSeconds;
      if (elapsed >= _timeoutSeconds) {
        _requireLock();
        return;
      }
    }

    if (!_locked && _timeoutSeconds > 0) {
      _armForegroundTimer();
    }
  }

  void dispose() {
    _cancelForegroundTimer();
  }

  void _armForegroundTimer() {
    _cancelForegroundTimer();
    _foregroundTimer = Timer(Duration(seconds: _timeoutSeconds), _requireLock);
  }

  void _cancelForegroundTimer() {
    _foregroundTimer?.cancel();
    _foregroundTimer = null;
  }

  void _requireLock() {
    _locked = true;
    _cancelForegroundTimer();
    _onLockRequired();
  }
}
