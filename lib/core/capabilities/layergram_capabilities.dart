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

import 'backup_capability.dart';
import 'chat_folders_capability.dart';
import 'cover_message_generator_capability.dart';
import 'identity_capability.dart';
import 'media_light_capability.dart';
import 'secure_keyboard_capability.dart';

/// Container for all Layergram capability implementations.
///
/// This class provides a centralized location for all premium and core capabilities.
/// In the open-source build, this is wired to stub implementations that return
/// default values and behave as safe no-ops for premium features.
/// 
/// Premium builds can override the provider that exposes this container or provide
/// a different instance without changing the core feature code.
/// 
/// Example usage:
/// ```dart
/// final capabilities = ref.watch(layergramCapabilitiesProvider);
/// if (capabilities.backup.isAvailable) {
///   await capabilities.backup.createBackup();
/// }
/// ```
class LayergramCapabilities {
  /// Creates a [LayergramCapabilities] instance with specified capabilities.
  /// 
  /// All parameters default to their respective "No*" stub implementations
  /// for the open-source build.
  /// 
  /// [identity] - Multi-identity management capability
  /// [backup] - Encrypted cloud backup capability  
  /// [coverGenerator] - AI cover message generation capability
  /// [chatFolders] - Custom chat folder organization capability
  /// [mediaLight] - Photo and audio attachment capability
  /// [secureKeyboard] - In-app secure keyboard capability for touch devices
  const LayergramCapabilities({
    this.identity = const NoIdentityCapability(),
    this.backup = const NoBackupCapability(),
    this.coverGenerator = const NoCoverMessageGeneratorCapability(),
    this.chatFolders = const NoChatFoldersCapability(),
    this.mediaLight = const NoMediaLightCapability(),
    this.secureKeyboard = const NoSecureKeyboardCapability(),
  });

  /// Multi-identity management capability.
  /// 
  /// Handles creation, deletion, and switching between multiple user identities.
  /// In OSS, this is a [NoIdentityCapability] no-op implementation.
  final IdentityCapability identity;

  /// Encrypted cloud backup capability.
  /// 
  /// Provides secure backup and restore of user data to cloud storage.
  /// In OSS, this is a [NoBackupCapability] no-op implementation.
  final BackupCapability backup;

  /// AI cover message generation capability.
  /// 
  /// Generates realistic cover messages to hide encrypted content.
  /// In OSS, this is a [NoCoverMessageGeneratorCapability] no-op implementation.
  final CoverMessageGeneratorCapability coverGenerator;

  /// Custom chat folder organization capability.
  /// 
  /// Allows users to organize chats into custom folders.
  /// In OSS, this is a [NoChatFoldersCapability] that provides only the "All Chats" folder.
  final ChatFoldersCapability chatFolders;

  /// Photo and audio attachment capability.
  /// 
  /// Handles encrypted photo and audio attachments in messages.
  /// In OSS, this is a [NoMediaLightCapability] no-op implementation.
  final MediaLightCapability mediaLight;

  /// In-app secure keyboard capability.
  /// 
  /// Can provide a touch-only keyboard session without invoking the system IME.
  /// In OSS, this is a [NoSecureKeyboardCapability] no-op implementation.
  final SecureKeyboardCapability secureKeyboard;

  /// Creates a copy of this [LayergramCapabilities] with overridden capabilities.
  /// 
  /// Useful for premium builds to selectively override specific capabilities
  /// while keeping others as OSS stubs.
  /// 
  /// [identity] - Optional override for identity capability
  /// [backup] - Optional override for backup capability
  /// [coverGenerator] - Optional override for cover generator capability
  /// [chatFolders] - Optional override for chat folders capability
  /// [mediaLight] - Optional override for media capability
  /// [secureKeyboard] - Optional override for secure keyboard capability
  /// Returns a new [LayergramCapabilities] instance with specified overrides.
  LayergramCapabilities copyWith({
    IdentityCapability? identity,
    BackupCapability? backup,
    CoverMessageGeneratorCapability? coverGenerator,
    ChatFoldersCapability? chatFolders,
    MediaLightCapability? mediaLight,
    SecureKeyboardCapability? secureKeyboard,
  }) {
    return LayergramCapabilities(
      identity: identity ?? this.identity,
      backup: backup ?? this.backup,
      coverGenerator: coverGenerator ?? this.coverGenerator,
      chatFolders: chatFolders ?? this.chatFolders,
      mediaLight: mediaLight ?? this.mediaLight,
      secureKeyboard: secureKeyboard ?? this.secureKeyboard,
    );
  }
}
