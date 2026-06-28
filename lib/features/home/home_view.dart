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

import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:easy_localization/easy_localization.dart';

import '../../core/capabilities/chat_folders_capability.dart';
import '../../core/crypto/models.dart';
import '../../core/providers.dart';
import '../../l10n/app_strings.dart';
import '../../ui/passphrase_button.dart';
import '../identities/identities_controller.dart';
import 'chat_view.dart';
import 'home_controller.dart';

class _GlobalChatHit {
  const _GlobalChatHit({
    required this.chatId,
    required this.contact,
    required this.messageId,
    required this.snippet,
    required this.timestamp,
  });

  final String chatId;
  final RemoteIdentity contact;
  final String messageId;
  final String snippet;
  final int timestamp;
}

class _PendingEmbeddedSearch {
  const _PendingEmbeddedSearch({
    required this.chatId,
    required this.query,
    required this.messageId,
  });

  final String chatId;
  final String query;
  final String messageId;
}

class _ClearSearchIntent extends Intent {
  const _ClearSearchIntent();
}

class HomeView extends ConsumerStatefulWidget {
  const HomeView({super.key});

  @override
  ConsumerState<HomeView> createState() => _HomeViewState();
}

class _HomeViewState extends ConsumerState<HomeView> {
  final _searchCtrl = TextEditingController();
  final _searchFocusNode = FocusNode();
  final GlobalKey _searchFieldKey = GlobalKey(debugLabel: 'home_search_field');
  GlobalKey<ChatViewState> _embeddedChatKey = GlobalKey<ChatViewState>();
  String? _embeddedContactId;
  RemoteIdentity? _selectedContact;
  List<RemoteIdentity> _contacts = const [];
  Map<String, int> _lastMessageByContact = const {};
  Set<String>? _currentAllowedPeerIds;
  bool _sentToNarrow = false;
  bool _disposed = false;
  // Stores composer state for handoff between narrow↔wide transitions
  Map<String, dynamic>? _pendingComposerState;
  bool _isGlobalSearching = false;
  bool _globalSearchInProgress = false;
  String _globalSearchQuery = '';
  int _globalSearchGeneration = 0;
  List<_GlobalChatHit> _globalMessageHits = const [];
  _PendingEmbeddedSearch? _pendingEmbeddedSearch;

  String _peerIdOf(MessageRecord m) {
    return m.direction == 'incoming' ? m.senderId : m.recipientId;
  }

  static const Map<String, String> _yesterdayLexicon = {
    'en': 'Yesterday',
    'it': 'Ieri',
    'es': 'Ayer',
    'pt': 'Ontem',
    'pt_PT': 'Ontem',
    'ru': 'Вчера',
    'id': 'Kemarin',
    'ar': 'أمس',
    'fr': 'Hier',
    'de': 'Gestern',
    'hi': 'कल',
    'nl': 'Gisteren',
    'fa': 'دیروز',
    'ro': 'Ieri',
    'pl': 'Wczoraj',
    'zh': '昨天',
    'tr': 'Dün',
    'ja': '昨日',
    'ko': '어제',
    'vi': 'Hôm qua',
    'th': 'เมื่อวาน',
    'el': 'Χθες',
    'bn': 'গতকাল',
    'mr': 'काल',
    'ur': 'کل',
    'fi': 'Eilen',
    'no': 'I går',
    'sv': 'Igår',
    'uk': 'Вчора',
    'sq': 'Dje',
    'ca': 'Ahir',
    'sw': 'Jana',
    'ha': 'Jiya',
    'tl': 'Kahapon',
    'ms': 'Semalam',
    'ta': 'நேற்று',
    'te': 'నిన్న',
    'gu': 'ગઈકાલે',
    'kn': 'ನಿನ್ನೆ',
    'pa': 'ਕੱਲ੍ਹ',
    'am': 'ትናንት',
    'yo': 'Àná',
  };

  String _formatLastMessageTime(BuildContext context, int timestampSeconds) {
    final locale = Localizations.localeOf(context);
    final dt = DateTime.fromMillisecondsSinceEpoch(timestampSeconds * 1000);
    final now = DateTime.now();
    final today = DateTime(now.year, now.month, now.day);
    final msgDay = DateTime(dt.year, dt.month, dt.day);
    final diffDays = today.difference(msgDay).inDays;

    if (diffDays == 0) {
      return DateFormat.Hm(locale.toLanguageTag()).format(dt);
    }
    if (diffDays == 1) {
      final lang = locale.languageCode;
      final country = locale.countryCode;
      final key = country != null ? '${lang}_$country' : lang;
      return _yesterdayLexicon[key] ??
          _yesterdayLexicon[lang] ??
          _yesterdayLexicon['en']!;
    }
    if (diffDays <= 7) {
      return DateFormat.E(locale.toLanguageTag()).format(dt);
    }
    return DateFormat.yMd(locale.toLanguageTag()).format(dt);
  }

  Future<void> _startNewChat() async {
    if (_contacts.isEmpty) return;
    final isNarrow = MediaQuery.of(context).size.width < 980;
    final outerContext = context;
    final outerRef = ref;
    final searchCtrl = TextEditingController();
    await showModalBottomSheet<void>(
      context: outerContext,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (modalContext) {
        final maxSheetHeight = MediaQuery.of(modalContext).size.height * 0.75;
        return SafeArea(
          child: SizedBox(
            height: maxSheetHeight,
            child: Column(
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
                  child: Row(
                    children: [
                      const Icon(Icons.chat_bubble_outline),
                      const SizedBox(width: 8),
                      Text(AppStrings.t(context, 'newChat'),
                          style: const TextStyle(
                              fontSize: 16, fontWeight: FontWeight.w600)),
                    ],
                  ),
                ),
                const Divider(height: 1),
                StatefulBuilder(
                  builder: (_, setStateModal) {
                    final query = searchCtrl.text.trim().toLowerCase();
                    final filtered = _contacts
                        .where((c) =>
                            query.isEmpty ||
                            c.displayName.toLowerCase().contains(query) ||
                            c.fingerprint.toLowerCase().contains(query))
                        .toList();
                    return Expanded(
                      child: Column(
                        children: [
                          Padding(
                            padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
                            child: TextField(
                              controller: searchCtrl,
                              autofocus: false,
                              decoration: InputDecoration(
                                prefixIcon: const Icon(Icons.search),
                                hintText:
                                    AppStrings.t(context, 'searchContact'),
                              ),
                              onChanged: (q) {
                                setStateModal(() {});
                              },
                              onTapOutside: (_) =>
                                  FocusScope.of(modalContext).unfocus(),
                            ),
                          ),
                          const Divider(height: 1),
                          Expanded(
                            child: ListView.separated(
                              itemCount: filtered.length,
                              separatorBuilder: (_, __) =>
                                  const Divider(height: 1, thickness: 0.2),
                              itemBuilder: (_, index) {
                                final c = filtered[index];
                                return ListTile(
                                  leading: CircleAvatar(
                                    backgroundColor: const Color(0xFF25D366)
                                        .withValues(alpha: 0.18),
                                    child: Text(c.displayName.isNotEmpty
                                        ? c.displayName[0].toUpperCase()
                                        : '?'),
                                  ),
                                  title: Text(c.displayName),
                                  subtitle: Text(c.fingerprint),
                                  onTap: () {
                                    Navigator.of(modalContext).pop();
                                    outerRef
                                        .read(encodeRecipientProvider.notifier)
                                        .state = c;
                                    if (isNarrow) {
                                      _openChat(c);
                                    } else {
                                      _selectContact(c);
                                    }
                                  },
                                );
                              },
                            ),
                          ),
                        ],
                      ),
                    );
                  },
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  void _selectContact(RemoteIdentity c) {
    setState(() {
      _selectedContact = c;
    });
  }

  Future<void> _handleGlobalSearch(String rawQuery) async {
    final query = rawQuery.trim();
    _globalSearchQuery = query;
    final generation = ++_globalSearchGeneration;

    if (query.isEmpty) {
      setState(() {
        _isGlobalSearching = false;
        _globalSearchInProgress = false;
        _globalMessageHits = const [];
      });
      return;
    }

    setState(() {
      _isGlobalSearching = true;
      _globalSearchInProgress = true;
      _globalMessageHits = const [];
    });

    final repo = ref.read(messagesRepositoryProvider);
    final controller = ref.read(homeControllerProvider);
    final allowedPeerIds = _currentAllowedPeerIds;
    final restrictToFolder = allowedPeerIds != null;
    final allMessages = List<MessageRecord>.from(await repo.getAllMessages())
      ..sort((a, b) {
        final byTs = b.timestamp.compareTo(a.timestamp);
        if (byTs != 0) return byTs;
        return b.id.compareTo(a.id);
      });
    final contactsCache = <String, RemoteIdentity>{
      for (final c in _contacts) c.identityId: c,
    };
    final identitiesRepo = ref.read(identitiesRepositoryProvider);
    final lowerQuery = query.toLowerCase();
    final hits = <_GlobalChatHit>[];

    // Process in chunks so we can show partial results quickly
    const chunkSize = 20;
    for (var i = 0; i < allMessages.length; i += chunkSize) {
      if (!mounted || _disposed || generation != _globalSearchGeneration) {
        return;
      }

      final end = (i + chunkSize).clamp(0, allMessages.length);
      final chunk = allMessages.sublist(i, end);

      for (final message in chunk) {
        if (message.ciphertextBase64 == null || message.nonceBase64 == null) {
          continue;
        }
        final peerId = message.direction == 'incoming'
            ? message.senderId
            : message.recipientId;
        if (peerId.isEmpty) continue;
        if (restrictToFolder && !allowedPeerIds.contains(peerId)) {
          continue;
        }

        RemoteIdentity? contact = contactsCache[peerId];
        contact ??= await identitiesRepo.getRemoteById(peerId);
        if (contact == null) continue;
        contactsCache[peerId] = contact;

        final decrypted = await controller.decryptForDisplay(
          message: message,
          contact: contact,
        );
        if (decrypted == null) continue;
        if (!decrypted.toLowerCase().contains(lowerQuery)) continue;

        hits.add(_GlobalChatHit(
          chatId: peerId,
          contact: contact,
          messageId: message.id,
          snippet: _buildSnippet(decrypted, query),
          timestamp: message.timestamp,
        ));
      }

      // Publish partial results after each chunk
      if (!mounted || _disposed || generation != _globalSearchGeneration) {
        return;
      }
      setState(() {
        _globalMessageHits = List.unmodifiable(hits);
      });
    }

    if (!mounted || _disposed || generation != _globalSearchGeneration) {
      return;
    }
    setState(() {
      _globalSearchInProgress = false;
      _globalMessageHits = List.unmodifiable(hits);
    });
  }

  @override
  void initState() {
    super.initState();
  }

  @override
  void dispose() {
    _disposed = true;
    _searchFocusNode.dispose();
    _searchCtrl.dispose();
    super.dispose();
  }

  void _clearSearch() {
    if (_searchCtrl.text.isEmpty) return;
    setState(() {
      _searchCtrl.clear();
    });
    _handleGlobalSearch('');
  }

  Widget _buildSearchField(BuildContext context, {required bool isNarrow}) {
    final t = AppStrings.t;
    final decoration = InputDecoration(
      prefixIcon: const Icon(Icons.search),
      hintText: t(context, 'search'),
      labelText: isNarrow ? null : null,
      suffixIcon: _searchCtrl.text.isEmpty
          ? null
          : IconButton(
              tooltip: t(context, 'clear'),
              icon: const Icon(Icons.close),
              onPressed: _clearSearch,
            ),
    );

    return Shortcuts(
      key: _searchFieldKey,
      shortcuts: {
        LogicalKeySet(LogicalKeyboardKey.escape): const _ClearSearchIntent(),
      },
      child: Actions(
        actions: {
          _ClearSearchIntent: CallbackAction<_ClearSearchIntent>(
            onInvoke: (_) {
              _clearSearch();
              return null;
            },
          ),
        },
        child: TextField(
          focusNode: _searchFocusNode,
          controller: _searchCtrl,
          decoration: decoration,
          onTapOutside: (_) => FocusScope.of(context).unfocus(),
          onChanged: (value) {
            setState(() {});
            _handleGlobalSearch(value);
          },
        ),
      ),
    );
  }

  Future<void> _decodeFromClipboard() async {
    final messenger = ScaffoldMessenger.of(context);
    final source = await ref.read(clipboardServiceProvider).readText();
    if (!mounted || source.isEmpty) return;

    final isNarrow = MediaQuery.of(context).size.width < 980;

    // Check if it's an identity link first
    if (source.trim().startsWith('layergram://i/')) {
      try {
        final identity = ref
            .read(identitiesControllerProvider)
            .parseIdentityFromLink(source);
        await ref.read(identitiesControllerProvider).saveIdentity(identity);

        if (!mounted) return;
        messenger.showSnackBar(
          SnackBar(
              content: Text(AppStrings.t(context,
                  'contactNameSaved'))), // Reusing existing translation
        );

        // Open the chat with the newly imported contact
        ref.read(encodeRecipientProvider.notifier).state = identity;
        if (isNarrow) {
          await _openChat(identity);
        } else {
          _selectContact(identity);
        }
        return;
      } catch (e) {
        if (!mounted) return;
        messenger.showSnackBar(
          SnackBar(
              content: Text(AppStrings.t(context, 'invalidLayergramLink'))),
        );
        return;
      }
    }

    final outcome = await ref.read(homeControllerProvider).decodeHiddenMessage(
          source,
          hintContactId: _selectedContact?.identityId,
        );
    if (!mounted) {
      return;
    }

    switch (outcome.kind) {
      case DecodeKind.success:
        final senderId = outcome.payload!.senderId;
        final sender = await ref
            .read(identitiesRepositoryProvider)
            .getRemoteById(senderId);
        if (!mounted) {
          return;
        }
        if (sender != null) {
          ref.read(encodeRecipientProvider.notifier).state = sender;
          if (isNarrow) {
            await _openChat(sender);
          } else {
            final sameChat = _selectedContact?.identityId == sender.identityId;
            final chatState = _embeddedChatKey.currentState;
            if (sameChat && chatState != null) {
              chatState.refreshAfterDecodedMessage();
            } else {
              _selectContact(sender);
            }
          }
        } else {
          messenger.showSnackBar(
            SnackBar(content: Text(AppStrings.t(context, 'unknownSender'))),
          );
        }
        break;
      case DecodeKind.fsLost:
        messenger.showSnackBar(
          SnackBar(
              content: Text(AppStrings.t(context, 'security.fs.message_lost'))),
        );
        break;
      default:
        messenger.showSnackBar(
          SnackBar(content: Text(AppStrings.t(context, 'noMessageFoundDesc'))),
        );
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    // Aggiungi context.locale per forzare il rebuild quando cambia la lingua
    Localizations.maybeLocaleOf(context);

    final selectedFolderId = ref.watch(selectedChatFolderIdProvider);
    final chatsInFolderAsync = selectedFolderId == kAllChatsFolderId
        ? const AsyncValue.data(<String>{})
        : ref.watch(chatIdsInFolderProvider(selectedFolderId));
    final allowedPeerIds = selectedFolderId == kAllChatsFolderId
        ? null
        : chatsInFolderAsync.maybeWhen(
            data: (ids) => ids,
            orElse: () => null,
          );
    _currentAllowedPeerIds = allowedPeerIds;
    final isFolderLoading =
        selectedFolderId != kAllChatsFolderId && chatsInFolderAsync.isLoading;

    final pinnedByChatId =
        ref.watch(pinnedChatsProvider).valueOrNull ?? const <String, int>{};

    final extraFolders =
        ref.watch(chatFoldersProvider).valueOrNull ?? const <ChatFolder>[];
    String? extraFolderLabel;
    for (final f in extraFolders) {
      if (f.id == selectedFolderId) {
        extraFolderLabel = f.label;
        break;
      }
    }
    final homeTitle = selectedFolderId == kAllChatsFolderId
        ? t(context, 'home')
        : (extraFolderLabel ?? t(context, 'home'));

    final screenWidth = MediaQuery.of(context).size.width;
    final showFab = screenWidth < 980;

    if (!_disposed && showFab && _selectedContact != null && !_sentToNarrow) {
      _sentToNarrow = true;
      final contact = _selectedContact!;
      // Capture composer state from embedded ChatView before it gets destroyed
      final state = _embeddedChatKey.currentState?.composerState;
      if (state != null) {
        _pendingComposerState = state;
      }
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted || _disposed) {
          return;
        }
        _openChat(contact);
      });
    } else if (!showFab && !_sentToNarrow) {
      // Only relevant when not awaiting a narrow pop
    }

    final appBar = showFab
        ? AppBar(
            title: Text(homeTitle, overflow: TextOverflow.ellipsis),
            actions: const [PassphraseButton(), SizedBox(width: 8)],
          )
        : null;

    return Scaffold(
      backgroundColor: Colors.transparent,
      appBar: appBar,
      body: StreamBuilder<List<RemoteIdentity>>(
        stream: ref.read(identitiesRepositoryProvider).watchRemote(),
        builder: (context, contactsSnapshot) {
          final allContacts = contactsSnapshot.data ?? const <RemoteIdentity>[];
          // Cache contacts for modal/new chat usage.
          _contacts = allContacts;
          final query = _searchCtrl.text.trim().toLowerCase();
          final isNarrow = MediaQuery.of(context).size.width < 980;
          final theme = Theme.of(context);
          final pasteDecodeButtonStyle = FilledButton.styleFrom(
            minimumSize: const Size.fromHeight(48),
            backgroundColor: theme.colorScheme.primary,
            foregroundColor: theme.colorScheme.onPrimary,
          );

          final selectedContact = _selectedContact;

          final contactsPane = Padding(
            padding: const EdgeInsets.fromLTRB(12, 12, 8, 12),
            child: Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: FilledButton.icon(
                            onPressed: _decodeFromClipboard,
                            icon: const Icon(Icons.paste_outlined),
                            label: Text(t(context, 'pasteDecode')),
                            style: pasteDecodeButtonStyle,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Tooltip(
                          message: t(context, 'newMessage'),
                          child: FilledButton(
                            onPressed: _startNewChat,
                            style: FilledButton.styleFrom(
                              padding: EdgeInsets.zero,
                              minimumSize: const Size(48, 48),
                            ),
                            child: const Icon(Icons.edit_note),
                          ),
                        ),
                        const SizedBox(width: 8),
                        const PassphraseButton(),
                      ],
                    ),
                    const SizedBox(height: 10),
                    _buildSearchField(context, isNarrow: false),
                    const SizedBox(height: 10),
                    Expanded(
                      child: StreamBuilder<List<MessageRecord>>(
                        stream: ref.read(messagesRepositoryProvider).watchAll(),
                        builder: (context, messagesSnapshot) {
                          if (isFolderLoading) {
                            return const Center(
                                child: CircularProgressIndicator());
                          }

                          final allMessages = messagesSnapshot.data ?? [];
                          final effectiveTag =
                              ref.watch(effectiveKeyTagProvider);
                          final keyFilteredMessages = allMessages.where((m) {
                            if (effectiveTag == null) return true;
                            return m.keyTag == effectiveTag;
                          });
                          final visibleMessages = allowedPeerIds == null
                              ? keyFilteredMessages.toList()
                              : keyFilteredMessages.where((m) {
                                  final peerId = m.direction == 'incoming'
                                      ? m.senderId
                                      : m.recipientId;
                                  return allowedPeerIds.contains(peerId);
                                }).toList();
                          final messagesByPeer =
                              <String, List<MessageRecord>>{};
                          final lastByPeer = <String, int>{};
                          for (final m in visibleMessages) {
                            final peerId = m.direction == 'incoming'
                                ? m.senderId
                                : m.recipientId;
                            messagesByPeer.putIfAbsent(peerId, () => []).add(m);

                            final existing = lastByPeer[peerId];
                            if (existing == null || m.timestamp > existing) {
                              lastByPeer[peerId] = m.timestamp;
                            }
                          }
                          _lastMessageByContact = lastByPeer;

                          final filteredContacts = allContacts.where((c) {
                            if (!lastByPeer.containsKey(c.identityId)) {
                              return false;
                            }
                            if (allowedPeerIds != null &&
                                !allowedPeerIds.contains(c.identityId)) {
                              return false;
                            }
                            if (query.isEmpty) return true;
                            return c.displayName
                                    .toLowerCase()
                                    .contains(query) ||
                                c.fingerprint.toLowerCase().contains(query);
                          }).toList()
                            ..sort((a, b) {
                              final aPinned =
                                  pinnedByChatId.containsKey(a.identityId);
                              final bPinned =
                                  pinnedByChatId.containsKey(b.identityId);
                              if (aPinned != bPinned) return aPinned ? -1 : 1;
                              if (aPinned && bPinned) {
                                final byPin =
                                    (pinnedByChatId[b.identityId] ?? 0)
                                        .compareTo(
                                            pinnedByChatId[a.identityId] ?? 0);
                                if (byPin != 0) {
                                  return byPin;
                                }
                              }
                              final byLast = (lastByPeer[b.identityId] ?? 0)
                                  .compareTo(lastByPeer[a.identityId] ?? 0);
                              if (byLast != 0) return byLast;
                              return a.displayName
                                  .toLowerCase()
                                  .compareTo(b.displayName.toLowerCase());
                            });

                          final selectedContact = _selectedContact;
                          final selectedMatchesSearch =
                              selectedContact != null &&
                                  (query.isEmpty ||
                                      selectedContact.displayName
                                          .toLowerCase()
                                          .contains(query) ||
                                      selectedContact.fingerprint
                                          .toLowerCase()
                                          .contains(query));
                          final selectedAllowedInFolder = selectedContact !=
                                  null &&
                              (allowedPeerIds == null ||
                                  allowedPeerIds
                                      .contains(selectedContact.identityId));
                          final shouldKeepSelectedEmptyChat = selectedContact !=
                                  null &&
                              !lastByPeer
                                  .containsKey(selectedContact.identityId) &&
                              selectedMatchesSearch &&
                              selectedAllowedInFolder &&
                              !filteredContacts.any((c) =>
                                  c.identityId == selectedContact.identityId);
                          if (shouldKeepSelectedEmptyChat) {
                            filteredContacts.insert(0, selectedContact);
                          }

                          final isSelectedInHits = _isGlobalSearching &&
                              _globalMessageHits.any((h) =>
                                  h.chatId == _selectedContact?.identityId);

                          // Only perform auto-selection/deselection if both streams have delivered their first event.
                          // Otherwise, during layout transitions, the empty initial state would incorrectly unmount the active chat.
                          final hasDataToFilter = messagesSnapshot.hasData &&
                              contactsSnapshot.hasData;

                          if (hasDataToFilter &&
                              _selectedContact != null &&
                              !isSelectedInHits &&
                              !filteredContacts.any((c) =>
                                  c.identityId ==
                                  _selectedContact!.identityId)) {
                            WidgetsBinding.instance.addPostFrameCallback((_) {
                              if (!mounted) {
                                return;
                              }
                              ref.read(encodeRecipientProvider.notifier).state =
                                  null;
                              setState(() => _selectedContact = null);
                            });
                          }

                          if (hasDataToFilter &&
                              !isNarrow &&
                              _selectedContact == null &&
                              filteredContacts.isNotEmpty) {
                            final remembered =
                                ref.read(encodeRecipientProvider);
                            final candidate = remembered != null &&
                                    filteredContacts.any((c) =>
                                        c.identityId == remembered.identityId)
                                ? remembered
                                : filteredContacts.first;
                            WidgetsBinding.instance.addPostFrameCallback((_) {
                              if (!mounted) {
                                return;
                              }
                              ref.read(encodeRecipientProvider.notifier).state =
                                  candidate;
                              _selectContact(candidate);
                            });
                          }

                          final showGlobalSection = _globalSearchInProgress ||
                              _globalMessageHits.isNotEmpty;

                          if (filteredContacts.isEmpty) {
                            if (showGlobalSection) {
                              return ListView(
                                padding: const EdgeInsets.only(bottom: 4),
                                children: [
                                  _buildGlobalSearchResultsSection(
                                      isNarrow: false),
                                ],
                              );
                            }
                            final key = allContacts.isEmpty
                                ? 'noIdentitiesYet'
                                : 'noMessagesYet';
                            return Center(child: Text(t(context, key)));
                          }

                          final totalItems = filteredContacts.length +
                              (showGlobalSection ? 1 : 0);

                          return ListView.builder(
                            itemCount: totalItems,
                            padding: const EdgeInsets.only(bottom: 4),
                            itemBuilder: (context, index) {
                              if (showGlobalSection &&
                                  index == filteredContacts.length) {
                                return _buildGlobalSearchResultsSection(
                                    isNarrow: false);
                              }
                              final c = filteredContacts[index];
                              final isPinned =
                                  pinnedByChatId.containsKey(c.identityId);
                              final isSelected =
                                  selectedContact?.identityId == c.identityId;
                              final borderColor = isSelected
                                  ? theme.colorScheme.primary
                                      .withValues(alpha: 0.6)
                                  : theme.colorScheme.outline
                                      .withValues(alpha: 0.35);
                              final bgColor = isSelected
                                  ? theme.colorScheme.primary
                                      .withValues(alpha: 0.08)
                                  : theme.colorScheme.surfaceContainerHighest;
                              final hidePreview =
                                  ref.watch(hideChatPreviewProvider);
                              final isSearching = query.isNotEmpty;
                              final contactMessages =
                                  messagesByPeer[c.identityId] ?? [];
                              final hasMessages = contactMessages.isNotEmpty;
                              final showPreview = !hidePreview || isSearching;
                              return Padding(
                                padding:
                                    const EdgeInsets.symmetric(vertical: 6),
                                child: GestureDetector(
                                  onTap: () {
                                    ref
                                        .read(encodeRecipientProvider.notifier)
                                        .state = c;
                                    _selectContact(c);
                                    if (isNarrow) _openChat(c);
                                  },
                                  onLongPressStart: (details) =>
                                      _showChatContextMenu(context, c,
                                          position: details.globalPosition),
                                  onSecondaryTapDown: (details) =>
                                      _showChatContextMenu(context, c,
                                          position: details.globalPosition),
                                  child: Container(
                                    decoration: BoxDecoration(
                                      color: bgColor,
                                      borderRadius: BorderRadius.circular(18),
                                      border: Border.all(
                                          color: borderColor, width: 1),
                                    ),
                                    padding: const EdgeInsets.symmetric(
                                        horizontal: 12, vertical: 10),
                                    child: Row(
                                      children: [
                                        CircleAvatar(
                                          backgroundColor:
                                              const Color(0xFF25D366)
                                                  .withValues(alpha: 0.18),
                                          child: Text(c.displayName.isNotEmpty
                                              ? c.displayName[0].toUpperCase()
                                              : '?'),
                                        ),
                                        const SizedBox(width: 12),
                                        Expanded(
                                          child: Column(
                                            crossAxisAlignment:
                                                CrossAxisAlignment.start,
                                            children: [
                                              Text(c.displayName,
                                                  style: theme
                                                      .textTheme.titleMedium),
                                              const SizedBox(height: 2),
                                              if (hasMessages)
                                                FutureBuilder<
                                                    DecryptedMessagePreview?>(
                                                  future: ref
                                                      .read(
                                                          homeControllerProvider)
                                                      .getLastDecryptableMessagePreview(
                                                          messages:
                                                              contactMessages,
                                                          contact: c),
                                                  builder: (context, snap) {
                                                    if (!snap.hasData) {
                                                      return Text('',
                                                          style: theme.textTheme
                                                              .bodySmall);
                                                    }

                                                    final preview = snap.data!;

                                                    // This will be called synchronously during the build pass,
                                                    // but we defer updating the state to avoid build-phase exceptions.
                                                    if (_lastMessageByContact[
                                                            c.identityId] !=
                                                        preview.timestamp) {
                                                      WidgetsBinding.instance
                                                          .addPostFrameCallback(
                                                              (_) {
                                                        if (mounted &&
                                                            _lastMessageByContact[c
                                                                    .identityId] !=
                                                                preview
                                                                    .timestamp) {
                                                          setState(() {
                                                            _lastMessageByContact[
                                                                    c.identityId] =
                                                                preview
                                                                    .timestamp;
                                                          });
                                                        }
                                                      });
                                                    }

                                                    if (showPreview) {
                                                      return Text(preview.text,
                                                          maxLines: 1,
                                                          overflow: TextOverflow
                                                              .ellipsis,
                                                          style: theme.textTheme
                                                              .bodySmall);
                                                    }

                                                    return Text('',
                                                        style: theme.textTheme
                                                            .bodySmall);
                                                  },
                                                )
                                              else
                                                Text('',
                                                    style: theme
                                                        .textTheme.bodySmall),
                                            ],
                                          ),
                                        ),
                                        const SizedBox(width: 8),
                                        Column(
                                          crossAxisAlignment:
                                              CrossAxisAlignment.end,
                                          children: [
                                            Row(
                                              mainAxisSize: MainAxisSize.min,
                                              children: [
                                                if (isPinned)
                                                  Icon(Icons.push_pin,
                                                      size: 20,
                                                      color: theme
                                                          .colorScheme.primary),
                                                Icon(
                                                  c.verified
                                                      ? Icons.verified_outlined
                                                      : Icons.error_outline,
                                                  color: c.verified
                                                      ? theme
                                                          .colorScheme.primary
                                                      : Colors.orange,
                                                ),
                                              ],
                                            ),
                                            const SizedBox(height: 4),
                                            if ((_lastMessageByContact[
                                                        c.identityId] ??
                                                    0) >
                                                0)
                                              Text(
                                                _formatLastMessageTime(
                                                    context,
                                                    _lastMessageByContact[
                                                        c.identityId]!),
                                                style:
                                                    theme.textTheme.bodySmall,
                                              ),
                                          ],
                                        ),
                                      ],
                                    ),
                                  ),
                                ),
                              );
                            },
                          );
                        },
                      ),
                    ),
                  ],
                ),
              ),
            ),
          );

          Widget buildChatPane() {
            if (selectedContact == null) {
              return Padding(
                padding: const EdgeInsets.fromLTRB(8, 0, 12, 12),
                child: Card(
                  color: Colors.transparent,
                  surfaceTintColor: Colors.transparent,
                  shadowColor: Colors.transparent,
                  elevation: 0,
                  child: Center(child: Text(t(context, 'noIdentitiesYet'))),
                ),
              );
            }
            // Check provider for handoff data from narrow ChatView (survives State recreation)
            final providerPending = ref.read(pendingComposerStateProvider);
            if (providerPending != null) {
              _pendingComposerState = providerPending;
              _embeddedContactId = null; // Force new ChatView instance
              // Defer provider clear to avoid writing during build
              WidgetsBinding.instance.addPostFrameCallback((_) {
                if (mounted) {
                  ref.read(pendingComposerStateProvider.notifier).state = null;
                }
              });
            }
            // Recreate GlobalKey when contact changes so ChatView resets for new contact
            if (_embeddedContactId != selectedContact.identityId) {
              _embeddedContactId = selectedContact.identityId;
              _embeddedChatKey = GlobalKey<ChatViewState>();
            }
            final pending = _pendingComposerState;
            // Clear pending state after consuming it
            if (pending != null) {
              WidgetsBinding.instance.addPostFrameCallback((_) {
                if (mounted) _pendingComposerState = null;
              });
            }
            final pendingSearch = (_pendingEmbeddedSearch != null &&
                    _pendingEmbeddedSearch!.chatId ==
                        selectedContact.identityId)
                ? _pendingEmbeddedSearch
                : null;
            if (pendingSearch != null) {
              WidgetsBinding.instance.addPostFrameCallback((_) {
                if (mounted && _pendingEmbeddedSearch == pendingSearch) {
                  _pendingEmbeddedSearch = null;
                }
              });
            }
            return Padding(
              padding: const EdgeInsets.fromLTRB(8, 0, 12, 12),
              child: ChatView(
                key: _embeddedChatKey,
                contact: selectedContact,
                embedded: true,
                initialCover: pending?['cover'] as String?,
                initialSecret: pending?['secret'] as String?,
                initialExpiry: pending?['expiry'] as int?,
                initialDeleteAfterRead: pending?['deleteAfterRead'] as bool?,
                initialLinkMode: pending?['linkMode'] as bool?,
                initialIsSearching: pending?['isSearching'] as bool?,
                initialSearchIndex: pending?['searchIndex'] as int?,
                initialGlobalSearchQuery: (pending?['isSearching'] == true)
                    ? (pending?['searchQuery'] as String?)
                    : pendingSearch?.query,
                initialGlobalSearchMessageId: (pending?['isSearching'] == true)
                    ? (pending?['searchMessageId'] as String?)
                    : pendingSearch?.messageId,
              ),
            );
          }

          if (isNarrow) {
            return Padding(
              padding: const EdgeInsets.fromLTRB(12, 12, 12, 12),
              child: Card(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: FilledButton.icon(
                              onPressed: _decodeFromClipboard,
                              icon: const Icon(Icons.paste_outlined),
                              label: Text(t(context, 'pasteDecode')),
                              style: pasteDecodeButtonStyle,
                            ),
                          ),
                          const SizedBox(width: 8),
                          Tooltip(
                            message: t(context, 'newMessage'),
                            child: FilledButton(
                              onPressed: _startNewChat,
                              style: FilledButton.styleFrom(
                                padding: EdgeInsets.zero,
                                minimumSize: const Size(48, 48),
                              ),
                              child: const Icon(Icons.edit_note),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 10),
                      _buildSearchField(context, isNarrow: true),
                      const SizedBox(height: 10),
                      Expanded(
                        child: StreamBuilder<List<MessageRecord>>(
                          stream:
                              ref.read(messagesRepositoryProvider).watchAll(),
                          builder: (context, messagesSnapshot) {
                            if (isFolderLoading) {
                              return const Center(
                                  child: CircularProgressIndicator());
                            }

                            final allMessages = messagesSnapshot.data ?? [];
                            final effectiveTagN =
                                ref.watch(effectiveKeyTagProvider);
                            final keyFilteredMessagesN = allMessages.where((m) {
                              if (effectiveTagN == null) return true;
                              return m.keyTag == effectiveTagN;
                            });
                            final visibleMessages = allowedPeerIds == null
                                ? keyFilteredMessagesN.toList()
                                : keyFilteredMessagesN.where((m) {
                                    final peerId = _peerIdOf(m);
                                    return allowedPeerIds.contains(peerId);
                                  }).toList();
                            final messagesByPeerN =
                                <String, List<MessageRecord>>{};
                            final lastByPeerTs = <String, int>{};
                            for (final m in visibleMessages) {
                              final peerId = _peerIdOf(m);
                              messagesByPeerN
                                  .putIfAbsent(peerId, () => [])
                                  .add(m);
                              final existing = lastByPeerTs[peerId];
                              if (existing == null || m.timestamp > existing) {
                                lastByPeerTs[peerId] = m.timestamp;
                              }
                            }
                            _lastMessageByContact = lastByPeerTs;
                            final query = _searchCtrl.text.trim().toLowerCase();

                            final peerIds = lastByPeerTs.keys.toList()
                              ..sort((a, b) {
                                final aPinned = pinnedByChatId.containsKey(a);
                                final bPinned = pinnedByChatId.containsKey(b);
                                if (aPinned != bPinned) {
                                  return aPinned ? -1 : 1;
                                }
                                if (aPinned && bPinned) {
                                  final aPin = pinnedByChatId[a] ?? 0;
                                  final bPin = pinnedByChatId[b] ?? 0;
                                  final byPin = bPin.compareTo(aPin);
                                  if (byPin != 0) {
                                    return byPin;
                                  }
                                }
                                return (lastByPeerTs[b] ?? 0)
                                    .compareTo(lastByPeerTs[a] ?? 0);
                              });

                            final filtered = peerIds.where((peerId) {
                              if (allowedPeerIds != null &&
                                  !allowedPeerIds.contains(peerId)) {
                                return false;
                              }
                              final contact = allContacts
                                  .cast<RemoteIdentity?>()
                                  .firstWhere(
                                    (c) => c?.identityId == peerId,
                                    orElse: () => null,
                                  );
                              final name = contact?.displayName.toLowerCase() ??
                                  peerId.toLowerCase();
                              return query.isEmpty || name.contains(query);
                            }).toList();

                            final showGlobalSection = _globalSearchInProgress ||
                                _globalMessageHits.isNotEmpty;

                            if (filtered.isEmpty) {
                              if (showGlobalSection) {
                                return ListView(
                                  padding: const EdgeInsets.only(bottom: 4),
                                  children: [
                                    _buildGlobalSearchResultsSection(
                                        isNarrow: true),
                                  ],
                                );
                              }
                              return Center(
                                  child: Text(t(context, 'noMessagesYet')));
                            }

                            final totalItems =
                                filtered.length + (showGlobalSection ? 1 : 0);

                            return ListView.builder(
                              itemCount: totalItems,
                              padding: const EdgeInsets.only(bottom: 4),
                              itemBuilder: (context, index) {
                                if (showGlobalSection &&
                                    index == filtered.length) {
                                  return _buildGlobalSearchResultsSection(
                                      isNarrow: true);
                                }
                                final peerId = filtered[index];
                                final isPinned =
                                    pinnedByChatId.containsKey(peerId);
                                final contactMessages =
                                    messagesByPeerN[peerId] ?? [];
                                final contact = allContacts
                                    .cast<RemoteIdentity?>()
                                    .firstWhere(
                                      (c) => c?.identityId == peerId,
                                      orElse: () => null,
                                    );
                                final hidePreviewNarrow =
                                    ref.watch(hideChatPreviewProvider);
                                final isSearchingNarrow = query.isNotEmpty;
                                final showPreviewNarrow =
                                    !hidePreviewNarrow || isSearchingNarrow;

                                return GestureDetector(
                                  onTap: contact == null
                                      ? null
                                      : () {
                                          _openChat(contact);
                                        },
                                  onLongPressStart: (details) => contact != null
                                      ? _showChatContextMenu(context, contact,
                                          position: details.globalPosition)
                                      : null,
                                  onSecondaryTapDown: (details) => contact !=
                                          null
                                      ? _showChatContextMenu(context, contact,
                                          position: details.globalPosition)
                                      : null,
                                  child: (contact != null &&
                                          contactMessages.isNotEmpty)
                                      ? FutureBuilder<DecryptedMessagePreview?>(
                                          future: ref
                                              .read(homeControllerProvider)
                                              .getLastDecryptableMessagePreview(
                                                  messages: contactMessages,
                                                  contact: contact),
                                          builder: (context, snap) {
                                            final preview = snap.data;
                                            return ListTile(
                                              title: Text(contact.displayName),
                                              subtitle: (showPreviewNarrow &&
                                                      preview != null)
                                                  ? Text(
                                                      preview.text,
                                                      maxLines: 1,
                                                      overflow:
                                                          TextOverflow.ellipsis,
                                                    )
                                                  : const Text(''),
                                              trailing: Row(
                                                mainAxisSize: MainAxisSize.min,
                                                children: [
                                                  if (isPinned)
                                                    Icon(
                                                      Icons.push_pin,
                                                      size: 20,
                                                      color: Theme.of(context)
                                                          .colorScheme
                                                          .primary,
                                                    ),
                                                  const SizedBox(width: 4),
                                                  if (preview != null)
                                                    Text(
                                                      _formatLastMessageTime(
                                                          context,
                                                          preview.timestamp),
                                                    )
                                                  else if ((lastByPeerTs[
                                                              peerId] ??
                                                          0) >
                                                      0)
                                                    Text(
                                                      _formatLastMessageTime(
                                                          context,
                                                          lastByPeerTs[
                                                              peerId]!),
                                                    ),
                                                ],
                                              ),
                                            );
                                          },
                                        )
                                      : ListTile(
                                          title: Text(
                                              contact?.displayName ?? peerId),
                                          subtitle: const Text(''),
                                          trailing: Row(
                                            mainAxisSize: MainAxisSize.min,
                                            children: [
                                              if (isPinned)
                                                Icon(
                                                  Icons.push_pin,
                                                  size: 20,
                                                  color: Theme.of(context)
                                                      .colorScheme
                                                      .primary,
                                                ),
                                              const SizedBox(width: 4),
                                              if ((lastByPeerTs[peerId] ?? 0) >
                                                  0)
                                                Text(
                                                  _formatLastMessageTime(
                                                      context,
                                                      lastByPeerTs[peerId]!),
                                                ),
                                            ],
                                          ),
                                        ),
                                );
                              },
                            );
                          },
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            );
          }

          return SafeArea(
            top: true,
            bottom: false,
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                SizedBox(width: 320, child: contactsPane),
                Expanded(child: buildChatPane()),
              ],
            ),
          );
        },
      ),
    );
  }

  Future<void> _openChat(
    RemoteIdentity contact, {
    String? initialSearchQuery,
    String? initialSearchMessageId,
  }) async {
    _selectedContact = contact;
    _sentToNarrow = true;
    ref.read(encodeRecipientProvider.notifier).state = contact;

    // Pass any pending composer state to the narrow ChatView
    final pending = _pendingComposerState;
    _pendingComposerState = null;

    final result = await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ChatView(
          contact: contact,
          initialCover: pending?['cover'] as String?,
          initialSecret: pending?['secret'] as String?,
          initialExpiry: pending?['expiry'] as int?,
          initialDeleteAfterRead: pending?['deleteAfterRead'] as bool?,
          initialLinkMode: pending?['linkMode'] as bool?,
          initialIsSearching: pending?['isSearching'] as bool?,
          initialSearchIndex: pending?['searchIndex'] as int?,
          initialGlobalSearchQuery: (pending?['isSearching'] == true)
              ? (pending?['searchQuery'] as String?)
              : initialSearchQuery,
          initialGlobalSearchMessageId: (pending?['isSearching'] == true)
              ? (pending?['searchMessageId'] as String?)
              : initialSearchMessageId,
        ),
      ),
    );
    if (!mounted || _disposed) {
      return;
    }

    if (result is Map) {
      // ChatView handed off state when resizing to wide — store it for the embedded ChatView.
      // Set pending state BEFORE setState so any rebuild triggered by setState sees it.
      _pendingComposerState = {
        'cover': result['cover'] as String? ?? '',
        'secret': result['secret'] as String? ?? '',
        'expiry': result['expiry'] as int?,
        'deleteAfterRead': (result['deleteAfterRead'] as bool?) ?? false,
        'linkMode': (result['linkMode'] as bool?) ?? true,
        'isSearching': result['isSearching'] as bool? ?? false,
        'searchQuery': result['searchQuery'] as String? ?? '',
        'searchIndex': result['searchIndex'] as int?,
        'searchMessageId': result['searchMessageId'] as String?,
      };
      _embeddedContactId = null;
      setState(() {
        _sentToNarrow = false;
        if (result.containsKey('contact')) {
          _selectedContact = result['contact'] as RemoteIdentity?;
        } else {
          _selectedContact = null;
        }
      });
    } else {
      setState(() {
        _sentToNarrow = false;
      });
      final isNowWide = MediaQuery.of(context).size.width >= 980;
      if (!isNowWide) {
        setState(() {
          _selectedContact = null;
        });
      }
    }
  }

  void _showChatContextMenu(BuildContext menuContext, RemoteIdentity contact,
      {Offset? position}) {
    final t = AppStrings.t;
    final selectedFolderId = ref.read(selectedChatFolderIdProvider);
    final pinnedByChatId =
        ref.read(pinnedChatsProvider).valueOrNull ?? const <String, int>{};
    final isPinned = pinnedByChatId.containsKey(contact.identityId);

    final RenderBox overlay =
        Overlay.of(context).context.findRenderObject() as RenderBox;
    final menuPosition = position != null
        ? RelativeRect.fromRect(
            Rect.fromLTWH(position.dx, position.dy, 0, 0),
            Offset.zero & overlay.size,
          )
        : const RelativeRect.fromLTRB(100, 100, 100, 100);

    showMenu(
      context: context,
      position: menuPosition,
      items: [
        PopupMenuItem(
          value: 'pin',
          child: Row(
            children: [
              Icon(
                isPinned ? Icons.push_pin : Icons.push_pin_outlined,
                size: 20,
              ),
              const SizedBox(width: 12),
              Text(t(context, isPinned ? 'unpinChat' : 'pinChat')),
            ],
          ),
        ),
        PopupMenuItem(
          value: 'delete',
          child: Row(
            children: [
              const Icon(
                Icons.delete_outline,
                size: 20,
              ),
              const SizedBox(width: 12),
              Text(t(context, 'deleteChat')),
            ],
          ),
        ),
      ],
    ).then((value) async {
      if (value == null) {
        return;
      }

      switch (value) {
        case 'pin':
          await ref.read(chatMetaRepositoryProvider).togglePinned(
                folderId: selectedFolderId,
                chatId: contact.identityId,
              );
          break;
        case 'delete':
          if (!menuContext.mounted) {
            return;
          }
          final confirmed = await showDialog<bool>(
            context: menuContext,
            builder: (context) => AlertDialog(
              title: Text(t(context, 'deleteChat')),
              content: Text(t(context, 'deleteChatConfirm')),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(false),
                  child: Text(t(context, 'cancel')),
                ),
                TextButton(
                  onPressed: () => Navigator.of(context).pop(true),
                  child: Text(t(context, 'delete')),
                ),
              ],
            ),
          );
          if (confirmed == true) {
            final effectiveTag = ref.read(effectiveKeyTagProvider);
            await ref
                .read(messagesRepositoryProvider)
                .deleteForContactByKeyFilter(
                  contact.identityId,
                  effectiveTag: effectiveTag,
                );
          }
          break;
      }
    });
  }

  Future<void> _openGlobalSearchHit(_GlobalChatHit hit) async {
    final query = _globalSearchQuery;
    if (query.isEmpty) {
      return;
    }
    final isNarrow = MediaQuery.of(context).size.width < 980;

    if (isNarrow) {
      await _openChat(
        hit.contact,
        initialSearchQuery: query,
        initialSearchMessageId: hit.messageId,
      );
      return;
    }

    final sameChat = _selectedContact?.identityId == hit.chatId;
    ref.read(encodeRecipientProvider.notifier).state = hit.contact;

    if (sameChat) {
      final chatState = _embeddedChatKey.currentState;
      if (chatState != null) {
        chatState.jumpToGlobalSearchResult(query, hit.messageId);
        return;
      }
    }

    setState(() {
      _selectedContact = hit.contact;
      _pendingEmbeddedSearch = _PendingEmbeddedSearch(
        chatId: hit.chatId,
        query: query,
        messageId: hit.messageId,
      );
    });
  }

  Widget _buildGlobalSearchResultsSection({required bool isNarrow}) {
    final hasResults = _globalMessageHits.isNotEmpty;
    final isLoading = _globalSearchInProgress;
    final shouldShow = hasResults || isLoading;
    if (!shouldShow) {
      return const SizedBox.shrink();
    }

    final theme = Theme.of(context);
    final labelStyle = theme.textTheme.labelSmall?.copyWith(
      fontWeight: FontWeight.w600,
      letterSpacing: 0.6,
      color: theme.colorScheme.secondary,
    );
    final header = Row(
      children: [
        Text(AppStrings.t(context, 'home').toUpperCase(), style: labelStyle),
        const Spacer(),
        if (isLoading)
          const SizedBox(
            width: 16,
            height: 16,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
      ],
    );

    final results = _globalMessageHits;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        const Divider(height: 24),
        header,
        const SizedBox(height: 8),
        if (results.isEmpty && isLoading)
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 12),
            child: SizedBox.shrink(),
          ),
        for (final hit in results) ...[
          ListTile(
            contentPadding: const EdgeInsets.symmetric(horizontal: 8),
            title: Text(hit.contact.displayName),
            subtitle:
                Text(hit.snippet, maxLines: 2, overflow: TextOverflow.ellipsis),
            trailing: Text(
              _formatLastMessageTime(context, hit.timestamp),
              style: theme.textTheme.bodySmall,
            ),
            onTap: () => _openGlobalSearchHit(hit),
          ),
          const Divider(height: 1, thickness: 0.2),
        ],
      ],
    );
  }

  String _buildSnippet(String text, String query) {
    final lower = text.toLowerCase();
    final lowerQuery = query.toLowerCase();
    final matchIndex = lower.indexOf(lowerQuery);
    if (matchIndex == -1) {
      return text.length <= 120 ? text : '${text.substring(0, 117)}…';
    }

    final start = math.max(0, matchIndex - 20);
    final end = math.min(text.length, matchIndex + query.length + 40);
    final prefix = start > 0 ? '…' : '';
    final suffix = end < text.length ? '…' : '';
    return '$prefix${text.substring(start, end)}$suffix';
  }
}
