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

enum BackupStage {
  preparing,
  exporting,
  encrypting,
  uploading,
  downloading,
  decrypting,
  importing,
  done,
}

class BackupProgress {
  const BackupProgress({
    required this.stage,
    required this.fraction,
  });

  /// Current stage.
  final BackupStage stage;

  /// 0..1 overall progress.
  final double fraction;
}

typedef BackupProgressCallback = void Function(BackupProgress progress);

/// Encrypted cloud backup.
///
/// OSS core provides a no-op implementation; Premium can provide providers
/// (Dropbox/iCloud/Google Drive) and an encrypted backup engine.
abstract class BackupCapability {
  bool get isAvailable;

  Future<void> createBackup({
    required IdentityId identityId,
    BackupProgressCallback? onProgress,
  });

  Future<void> restoreBackup({
    required IdentityId identityId,
    BackupProgressCallback? onProgress,
  });
}

class NoBackupCapability implements BackupCapability {
  const NoBackupCapability();

  @override
  bool get isAvailable => false;

  @override
  Future<void> createBackup({
    required IdentityId identityId,
    BackupProgressCallback? onProgress,
  }) async {
    // OSS: premium feature is wired but disabled.
    // If invoked anyway, behave as a safe no-op.
    onProgress?.call(const BackupProgress(stage: BackupStage.done, fraction: 1));
  }

  @override
  Future<void> restoreBackup({
    required IdentityId identityId,
    BackupProgressCallback? onProgress,
  }) async {
    // OSS: premium feature is wired but disabled.
    // If invoked anyway, behave as a safe no-op.
    onProgress?.call(const BackupProgress(stage: BackupStage.done, fraction: 1));
  }
}
