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

/// Web-safe stub for sharing intents.
String? extractSharedText(SharedMediaFile file) {
  final message = _sanitizeSharedText(file.message);
  if (message != null) {
    return message;
  }

  final path = _sanitizeSharedText(file.path);
  if (path != null) {
    return path;
  }

  return null;
}

class Sharing {
  Sharing();

  Stream<List<SharedMediaFile>> get mediaStream => const Stream.empty();

  Future<List<SharedMediaFile>> getInitialMedia() async => const [];

  Future<String?> takePendingText() async => null;

  Future<void> clearPendingShare() async {}

  void reset() {}
}

/// Minimal placeholder so code compiles; real class comes from receive_sharing_intent on mobile.
class SharedMediaFile {
  const SharedMediaFile({this.message, this.path});

  final String? message;
  final String? path;
}
