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

/// Identity-scoped capability for the sole HP3 -> initial TR3 coordinator.
///
/// The persistence scope creates one instance and does not expose it. The
/// handshake, session, and handoff controllers retain the same object and
/// compare it by identity. Constructing another instance therefore cannot
/// authorize a direct cross-controller call.
final class V3InitialSessionHandoffAuthority {
  V3InitialSessionHandoffAuthority();
}
