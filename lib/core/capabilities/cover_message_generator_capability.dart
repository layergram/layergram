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

import '../domain/identity_id.dart';

/// On-device cover message generation.
///
/// Premium implementations can use local LLMs / Apple Intelligence / other
/// on-device models.
abstract class CoverMessageGeneratorCapability {
  /// Whether the generator is available (premium).
  bool get isAvailable;

  /// Generates a cover message.
  ///
  /// Implementations should be deterministic enough to feel stable, but still
  /// provide variety.
  Future<String> generate({
    required String languageCode,
    List<String> recentMessages,
    String? tone,
    IdentityId? recipientId,
  });
}

class NoCoverMessageGeneratorCapability implements CoverMessageGeneratorCapability {
  const NoCoverMessageGeneratorCapability();

  @override
  bool get isAvailable => false;

  @override
  Future<String> generate({
    required String languageCode,
    List<String> recentMessages = const <String>[],
    String? tone,
    IdentityId? recipientId,
  }) {
    // OSS: premium feature is wired but disabled.
    // If invoked anyway, behave as a safe no-op.
    return Future.value('');
  }
}
