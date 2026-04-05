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

class CoverMessageLengthLimitService {
  CoverMessageLengthLimitService(this._storage);

  static const int defaultLimit = 4000;
  static const List<int?> supportedLimits = <int?>[null, 4000, 2000, 1000];
  static const _limitKey = 'cover_message_total_length_limit';
  static const _noLimitValue = 'none';

  final SecureStorageService _storage;

  Future<int?> getLimit() async {
    try {
      final raw = await _storage.read(_limitKey);
      if (raw == null || raw.trim().isEmpty) return defaultLimit;
      if (raw == _noLimitValue) return null;
      final parsed = int.tryParse(raw);
      if (supportedLimits.contains(parsed)) {
        return parsed;
      }
      return defaultLimit;
    } catch (_) {
      return defaultLimit;
    }
  }

  Future<void> setLimit(int? limit) {
    if (!supportedLimits.contains(limit)) {
      throw ArgumentError.value(
        limit,
        'limit',
        'Unsupported cover message length limit',
      );
    }
    return _storage.write(
      _limitKey,
      limit == null ? _noLimitValue : '$limit',
    );
  }
}
