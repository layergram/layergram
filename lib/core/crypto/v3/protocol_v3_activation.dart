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

/// Single fail-closed activation policy for protocol v3 application seams.
///
/// The three reviewed production decisions remain separate constants so a
/// future partial edit fails closed. Identity sharing must never move ahead of
/// the messaging/session owner, otherwise users could distribute identities
/// that the active app cannot use.
abstract final class ProtocolV3Activation {
  static const bool identitySharing = true;
  static const bool messaging = true;
  static const bool productionApproved = true;

  static const bool isActive =
      identitySharing && messaging && productionApproved;
}
