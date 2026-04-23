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
import '../contact_verification/contact_verification_view.dart';
import '../home/chat_view.dart';
import 'identities_controller.dart';

class IdentityDetailView extends ConsumerStatefulWidget {
  const IdentityDetailView({super.key, required this.identity, this.scrollController});

  final RemoteIdentity identity;
  final ScrollController? scrollController;

  @override
  ConsumerState<IdentityDetailView> createState() => _IdentityDetailViewState();
}

class _IdentityDetailViewState extends ConsumerState<IdentityDetailView> {
  TextEditingController? _nameCtrl;
  bool _saving = false;
  String? _myIdentityId;
  late RemoteIdentity _identity;

  @override
  void initState() {
    super.initState();
    _identity = widget.identity;
    _nameCtrl = TextEditingController(text: _identity.displayName);
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
    super.dispose();
  }

  Future<void> _saveName() async {
    final newName = _nameCtrl?.text.trim() ?? '';
    if (newName.isEmpty || newName == widget.identity.displayName) return;
    setState(() => _saving = true);
    await ref
        .read(identitiesControllerProvider)
        .setDisplayName(widget.identity, newName);
    if (!mounted) return;
    setState(() => _saving = false);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(AppStrings.t(context, 'contactNameSaved'))),
    );
    Navigator.of(context).pop();
  }

  Future<void> _handleVerifyAction() async {
    if (_identity.verified) {
      final messenger = ScaffoldMessenger.of(context);
      final snackText = AppStrings.t(
        context,
        'verifyContactRevokedSnackbar',
        namedArgs: {'name': _identity.displayName},
      );
      await ref
          .read(identitiesControllerProvider)
          .revokeContactVerification(_identity);
      if (!mounted) return;
      setState(() {
        _identity = _identity.copyWith(verified: false);
      });
      messenger.showSnackBar(SnackBar(content: Text(snackText)));
      return;
    }

    final result = await showContactVerificationCeremony(
      context,
      ref,
      _identity,
    );
    if (!mounted) return;
    if (result == true) {
      setState(() {
        _identity = _identity.copyWith(verified: true);
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final isMe = _myIdentityId != null && _identity.identityId == _myIdentityId;

    return Scaffold(
      backgroundColor: Colors.transparent,
      appBar: AppBar(title: Text(_nameCtrl?.text ?? '')),
      body: SafeArea(
        child: ListView(
          controller: widget.scrollController,
          padding: EdgeInsets.fromLTRB(
            16,
            16,
            16,
            MediaQuery.of(context).viewPadding.bottom + 32,
          ),
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    TextField(
                      controller: _nameCtrl,
                      enabled: !_saving,
                      onSubmitted: (_) => _saveName(),
                      decoration: InputDecoration(
                        labelText: t(context, 'contactNameLabel'),
                        hintText: t(context, 'contactNameHint'),
                        helperText: t(context, 'contactNameHelper'),
                      ),
                    ),
                    const SizedBox(height: 12),
                    SelectableText(
                        '${t(context, 'identityIdLabel')}: ${_identity.identityId}'),
                    const SizedBox(height: 8),
                    SelectableText(
                        '${t(context, 'fingerprintLabel')}: ${_identity.fingerprint}'),
                    const SizedBox(height: 8),
                    SelectableText(
                        '${t(context, 'publicKeyLabel')}: ${_identity.publicKeyBase64}'),
                    const SizedBox(height: 16),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        // Open chat button (always shown)
                        FilledButton.tonal(
                          onPressed: _saving
                              ? null
                              : () {
                                  // Set the recipient and navigate to chat
                                  ref.read(encodeRecipientProvider.notifier).state = _identity;
                                  Navigator.of(context).push(
                                    MaterialPageRoute(
                                      builder: (_) => ChatView(contact: _identity),
                                    ),
                                  );
                                },
                          child: Text(t(context, 'home')),
                        ),
                        if (!isMe)
                          FilledButton.tonal(
                            onPressed: _saving ? null : _handleVerifyAction,
                            child: Text(
                              _identity.verified
                                  ? t(context, 'verifyContactCtaRevokeVerification')
                                  : t(context, 'verifyContactCtaVerifyNow'),
                            ),
                          ),
                        if (!isMe)
                          FilledButton(
                            style:
                                FilledButton.styleFrom(backgroundColor: Colors.red),
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
                                        .delete(widget.identity.identityId);
                                    if (!context.mounted) return;
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      SnackBar(
                                        content: Text(
                                          t(context, 'contactDeleted'),
                                        ),
                                      ),
                                    );
                                    Navigator.of(context).pop();
                                  }
                                },
                            child: Text(t(context, 'delete')),
                          ),
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
          ],
        ),
      ),
    );
  }
}
