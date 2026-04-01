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

/// Chat folders/collections.
///
/// Core OSS always has an implicit "all chats" folder (the existing "Messaggi"
/// entry in the main navigation).
///
/// Premium can expose additional user-defined folders and chat-to-folder
/// membership.
const String kAllChatsFolderId = 'all';

class ChatFolder {
  const ChatFolder({
    required this.id,
    required this.label,
  });

  /// Stable folder identifier (identity-scoped in premium).
  final String id;

  /// Display label (user-defined in premium).
  final String label;
}

abstract class ChatFoldersCapability {
  /// Whether the folders feature is available (premium).
  ///
  /// Even when false, the app still has the implicit [kAllChatsFolderId] folder.
  bool get isAvailable;

  /// User-defined folders, excluding the implicit [kAllChatsFolderId].
  Stream<List<ChatFolder>> watchFolders();

  /// The set of chat peerIds (RemoteIdentity.identityId) that are inside a
  /// specific folder.
  ///
  /// The implicit [kAllChatsFolderId] is not queried via this API.
  Stream<Set<String>> watchChatIdsInFolder(String folderId);
}

class NoChatFoldersCapability implements ChatFoldersCapability {
  const NoChatFoldersCapability();

  @override
  bool get isAvailable => false;

  @override
  Stream<List<ChatFolder>> watchFolders() => Stream.value(const <ChatFolder>[]);

  @override
  Stream<Set<String>> watchChatIdsInFolder(String folderId) =>
      Stream.value(const <String>{});
}
