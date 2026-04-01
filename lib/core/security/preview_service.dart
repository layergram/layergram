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

import '../storage/secure_storage.dart';

class PreviewService {
  PreviewService(this._storage);

  static const _hidePreviewKey = 'hide_chat_preview';

  final SecureStorageService _storage;

  Future<bool> isHidden() async {
    try {
      final raw = await _storage.read(_hidePreviewKey);
      if (raw == null) return false; // default: show preview
      if (raw == '1') return true;
      if (raw == '0') return false;
      return raw.toLowerCase() == 'true';
    } catch (_) {
      return false;
    }
  }

  Future<void> setHidden(bool hidden) {
    return _storage.write(_hidePreviewKey, hidden ? '1' : '0');
  }
}
