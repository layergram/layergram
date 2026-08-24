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

import 'package:flutter/services.dart';

/// Temporarily raises display brightness while a QR presentation surface is
/// open. Mobile hosts preserve and restore their previous per-display setting.
class QrDisplayBrightnessController {
  QrDisplayBrightnessController({MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(_channelName);

  static const _channelName = 'layergram/screen_brightness';

  final MethodChannel _channel;
  bool _active = false;

  Future<void> enhance() async {
    if (_active) return;
    try {
      await _channel.invokeMethod<void>('setQrDisplayActive', true);
      _active = true;
    } on MissingPluginException {
      // Desktop and test hosts may not expose a brightness API.
    } on PlatformException {
      // Brightness is an optional presentation enhancement.
    }
  }

  Future<void> restore() async {
    if (!_active) return;
    _active = false;
    try {
      await _channel.invokeMethod<void>('setQrDisplayActive', false);
    } on MissingPluginException {
      // The host disappeared or does not expose a brightness API.
    } on PlatformException {
      // Do not make closing the QR surface depend on the enhancement.
    }
  }
}
