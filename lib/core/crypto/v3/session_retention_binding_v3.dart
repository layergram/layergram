// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';
import 'dart:typed_data';

import 'handshake_persistence_v3.dart';
import 'local_identity_v3.dart';
import 'lmf_v3_persistence.dart';
import 'retention_policy_v3.dart';

/// Maps a TR3 session to the Normal/Maximum mode in its durable HP3 binding.
///
/// A scope can contain both profiles, so absence or ambiguity must never fall
/// back to the longer Normal lifetime.
abstract final class V3SessionRetentionBinding {
  static int skippedKeyLifetimeSeconds({
    required Uint8List sessionId,
    required Iterable<V3CompletedHandshakeSession> completedSessions,
  }) {
    final encodedSessionId = base64UrlEncode(sessionId).replaceAll('=', '');
    final matches = completedSessions
        .where((session) => session.sessionId == encodedSessionId)
        .toList(growable: false);
    if (matches.length != 1) {
      throw const V3LmfPersistenceConflictException(
        'Layergram v3 session has no unique retention binding',
      );
    }
    final profile = switch (matches.single.mode) {
      V3HandshakeMode.normal => V3RetentionProfile.normal,
      V3HandshakeMode.maximum => V3RetentionProfile.maximum,
    };
    return V3RetentionPolicy.forProfile(profile).skippedKeyLifetimeSeconds;
  }
}
