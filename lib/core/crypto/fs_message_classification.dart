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

/// Internal classification of message security level.
///
/// Spec reference: §7.6, §9.5, §16 — Protocol checklist.
///
/// ```text
/// legacy           — message encrypted with long-term identity key only
/// fs_with_fallback — message encrypted with FS and also with legacy key
/// fs_only          — message encrypted with FS only (not legacy-decryptable)
/// ```
enum FsMessageSecurity {
  /// Message encrypted with long-term identity key only.
  legacy,

  /// Message encrypted with FS and also with legacy identity-key fallback.
  fsWithFallback,

  /// Message encrypted with FS only; not decryptable by the legacy key.
  fsOnly,
}
