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

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/crypto/models.dart';
import '../../core/providers.dart';
import '../../l10n/app_strings.dart';
import '../../ui/passphrase_button.dart';
import 'add_identity_view.dart';
import 'identities_controller.dart';
import 'identity_detail_view.dart';

class IdentitiesListView extends ConsumerStatefulWidget {
  const IdentitiesListView({super.key});

  @override
  ConsumerState<IdentitiesListView> createState() => _IdentitiesListViewState();
}

class _IdentitiesListViewState extends ConsumerState<IdentitiesListView> {
  RemoteIdentity? _selected;
  bool _pendingSelect = false;
  TextEditingController? _nameCtrl;
  final _searchCtrl = TextEditingController();
  bool _saving = false;
  String? _myIdentityId;

  @override
  void initState() {
    super.initState();
    _loadMyIdentity();
  }

  Future<void> _loadMyIdentity() async {
    final myId = await ref.read(identityManagerProvider).getLocalIdentity();
    if (mounted && myId != null) {
      setState(() => _myIdentityId = myId.identityId);
    }
  }

  @override
  void dispose() {
    _nameCtrl?.dispose();
    _searchCtrl.dispose();
    super.dispose();
  }

  void _selectIdentity(RemoteIdentity it) {
    _nameCtrl?.dispose();
    _nameCtrl = TextEditingController(text: it.displayName);
    setState(() {
      _selected = it;
      _saving = false;
    });
  }

  Future<void> _saveName() async {
    if (_selected == null || _nameCtrl == null) return;
    final newName = _nameCtrl!.text.trim();
    if (newName.isEmpty || newName == _selected!.displayName) return;
    setState(() => _saving = true);
    await ref.read(identitiesControllerProvider).setDisplayName(_selected!, newName);
    if (!mounted) return;
    setState(() {
      _saving = false;
      _selected = _selected?.copyWith(displayName: newName);
    });
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(AppStrings.t(context, 'contactNameSaved'))),
    );
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final isWide = MediaQuery.of(context).size.width >= 980;

    return Scaffold(
      backgroundColor: Colors.transparent,
      appBar: AppBar(
        title: Text(t(context, 'identities')),
        actions: const [PassphraseButton(), SizedBox(width: 8)],
      ),
      body: StreamBuilder<List<RemoteIdentity>>(
        stream: ref.read(identitiesControllerProvider).watchAll(),
        builder: (context, snapshot) {
          var identities = snapshot.data ?? const [];
          
          final query = _searchCtrl.text.trim().toLowerCase();
          if (query.isNotEmpty) {
            identities = identities.where((it) {
              return it.displayName.toLowerCase().contains(query);
            }).toList();
          }

          if (isWide && identities.isNotEmpty) {
            final stillExists = _selected != null &&
                identities.any((i) => i.identityId == _selected!.identityId);
            if (!stillExists && !_pendingSelect) {
              _pendingSelect = true;
              WidgetsBinding.instance.addPostFrameCallback((_) {
                if (!mounted) return;
                _pendingSelect = false;
                _selectIdentity(identities.first);
              });
            }
          }

          final listContent = identities.isEmpty
              ? Center(child: Text(t(context, 'noIdentitiesYet')))
              : ListView.separated(
                  padding: EdgeInsets.fromLTRB(12, 12, 12, isWide ? 12 : 90),
                  itemCount: identities.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 8),
                  itemBuilder: (context, index) {
                    final it = identities[index];
                    final isSelected = isWide && _selected?.identityId == it.identityId;
                    final isMe = _myIdentityId != null && it.identityId == _myIdentityId;
                    return ListTile(
                      selected: isSelected,
                      selectedTileColor: Theme.of(context)
                          .colorScheme
                          .primary
                          .withValues(alpha: 0.08),
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(12)),
                      title: Text(it.displayName),
                      subtitle: Text(it.fingerprint),
                      trailing: Icon(
                        isMe
                            ? Icons.person
                            : (it.verified ? Icons.verified : Icons.error_outline),
                        color: isMe
                            ? Theme.of(context).colorScheme.primary
                            : (it.verified
                                ? Theme.of(context).colorScheme.primary
                                : Colors.orange),
                      ),
                      onTap: () {
                        if (isWide) {
                          _selectIdentity(it);
                        } else {
                          showModalBottomSheet<void>(
                            context: context,
                            useSafeArea: true,
                            isScrollControlled: true,
                            builder: (ctx) {
                              return DraggableScrollableSheet(
                                expand: false,
                                initialChildSize: 0.95,
                                maxChildSize: 0.95,
                                minChildSize: 0.5,
                                builder: (context, scrollCtrl) {
                                  return IdentityDetailView(
                                    identity: it,
                                    scrollController: scrollCtrl,
                                  );
                                },
                              );
                            },
                          );
                        }
                      },
                    );
                  },
                );

          final listView = Column(
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(12, 12, 12, 0),
                child: TextField(
                  controller: _searchCtrl,
                  decoration: InputDecoration(
                    prefixIcon: const Icon(Icons.search),
                    labelText: t(context, 'searchContact'),
                  ),
                  onTapOutside: (_) => FocusScope.of(context).unfocus(),
                  onChanged: (_) => setState(() {}),
                ),
              ),
              Expanded(child: listContent),
            ],
          );

          if (!isWide) return listView;

          final selected = _selected;
          if (selected == null) return listView;
          final isSelectedMe =
              _myIdentityId != null && selected.identityId == _myIdentityId;

          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(width: 340, child: listView),
              const VerticalDivider(width: 1, thickness: 1, color: Colors.white24),
              Expanded(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(16),
                  child: Align(
                    alignment: Alignment.topCenter,
                    child: Card(
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                          TextField(
                            controller: _nameCtrl,
                            enabled: !_saving,
                            onSubmitted: (_) => _saveName(),
                            onChanged: (_) => setState(() {}),
                            decoration: InputDecoration(
                              labelText: t(context, 'contactNameLabel'),
                              hintText: t(context, 'contactNameHint'),
                              helperText: t(context, 'contactNameHelper'),
                            ),
                          ),
                          const SizedBox(height: 12),
                          SelectableText(
                              '${t(context, 'identityIdLabel')}: ${selected.identityId}'),
                          const SizedBox(height: 8),
                          SelectableText(
                              '${t(context, 'fingerprintLabel')}: ${selected.fingerprint}'),
                          const SizedBox(height: 8),
                          SelectableText(
                              '${t(context, 'publicKeyLabel')}: ${selected.publicKeyBase64}'),
                          const SizedBox(height: 16),
                            Wrap(
                              spacing: 8,
                              runSpacing: 8,
                              children: [
                                if (!isSelectedMe)
                                  FilledButton.tonal(
                                    onPressed: _saving
                                        ? null
                                        : () async {
                                            final toggled = !selected.verified;
                                            setState(() {
                                              _selected = selected.copyWith(verified: toggled);
                                            });
                                            await ref
                                                .read(identitiesControllerProvider)
                                                .setVerified(selected, toggled);
                                            if (!context.mounted) return;
                                            final messenger = ScaffoldMessenger.of(context);
                                            messenger.showSnackBar(
                                              SnackBar(
                                                content: Text(
                                                  t(
                                                    context,
                                                    toggled
                                                        ? 'contactMarkedVerified'
                                                        : 'contactMarkedUnverified',
                                                  ),
                                                ),
                                              ),
                                            );
                                        },
                                    child: Text(
                                      selected.verified
                                          ? t(context, 'markUnverified')
                                          : t(context, 'markVerified'),
                                    ),
                                  ),
                                if (_myIdentityId == null ||
                                    selected.identityId != _myIdentityId)
                                  FilledButton(
                                    style: FilledButton.styleFrom(
                                        backgroundColor: Colors.red),
                                    onPressed: _saving
                                      ? null
                                      : () async {
                                          final confirm = await showDialog<bool>(
                                            context: context,
                                            builder: (ctx) => AlertDialog(
                                              title: Text(t(ctx, 'deleteContactConfirmTitle')),
                                              content: Text(t(ctx, 'deleteContactConfirmMsg')),
                                              actions: [
                                                TextButton(
                                                  onPressed: () => Navigator.of(ctx).pop(false),
                                                  child: Text(t(ctx, 'cancel')),
                                                ),
                                                TextButton(
                                                  onPressed: () => Navigator.of(ctx).pop(true),
                                                  child: Text(
                                                    t(ctx, 'delete'),
                                                    style: TextStyle(color: Theme.of(ctx).colorScheme.error),
                                                  ),
                                                ),
                                              ],
                                            ),
                                          );
                                          if (confirm == true) {
                                            await ref
                                                .read(identitiesControllerProvider)
                                                .delete(selected.identityId);
                                            if (!context.mounted) return;
                                            ScaffoldMessenger.of(context).showSnackBar(
                                              SnackBar(
                                                content: Text(t(context, 'contactDeleted')),
                                              ),
                                            );
                                            if (identities.isNotEmpty) {
                                              _selectIdentity(identities.first);
                                            } else {
                                              setState(() => _selected = null);
                                            }
                                          }
                                        },
                                  child: Text(t(context, 'delete')),
                                ),
                                if (_nameCtrl != null &&
                                    _nameCtrl!.text.trim() !=
                                        selected.displayName)
                                  FilledButton(
                                    onPressed: _saving ? null : _saveName,
                                    child: Text(t(context, 'saveName')),
                                  ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ],
          );
        },
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () {
          if (isWide) {
            showDialog(
              context: context,
              builder: (_) => Dialog(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 520),
                  child: const AddIdentityView(),
                ),
              ),
            );
          } else {
            Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const AddIdentityView()),
            );
          }
        },
        icon: const Icon(Icons.person_add_alt_1),
        label: Text(t(context, 'addIdentity')),
      ),
    );
  }
}
