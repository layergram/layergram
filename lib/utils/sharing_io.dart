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
import 'package:receive_sharing_intent/receive_sharing_intent.dart'
    as rsi;

typedef SharedMediaFile = rsi.SharedMediaFile;

const MethodChannel _sharingChannel = MethodChannel('layergram/sharing');
final RegExp _shareRedirectPattern = RegExp(
  r'^sharemedia-[a-z0-9.-]+:share$',
  caseSensitive: false,
);

String? _sanitizeSharedText(String? raw) {
  final normalized = raw?.trim();
  if (normalized == null || normalized.isEmpty) {
    return null;
  }
  if (_shareRedirectPattern.hasMatch(normalized)) {
    return null;
  }
  return normalized;
}

String? extractSharedText(SharedMediaFile file) {
  final message = _sanitizeSharedText(file.message);
  if (message != null) {
    return message;
  }

  switch (file.type) {
    case rsi.SharedMediaType.text:
    case rsi.SharedMediaType.url:
      return _sanitizeSharedText(file.path);
    default:
      return null;
  }
}

class Sharing {
  Sharing();

  Stream<List<SharedMediaFile>> get mediaStream =>
      rsi.ReceiveSharingIntent.instance.getMediaStream();

  Future<List<SharedMediaFile>> getInitialMedia() =>
      rsi.ReceiveSharingIntent.instance.getInitialMedia();

  Future<String?> takePendingText() async {
    try {
      final text = await _sharingChannel.invokeMethod<String>('consumePendingText');
      return _sanitizeSharedText(text);
    } on MissingPluginException {
      return null;
    }
  }

  Future<void> clearPendingShare() async {
    try {
      await _sharingChannel.invokeMethod<void>('clearPendingShare');
    } on MissingPluginException {
      return;
    }
  }

  void reset() => rsi.ReceiveSharingIntent.instance.reset();
}
