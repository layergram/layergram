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
import '../identities/identities_controller.dart';
import 'contact_sas_service.dart';

/// Opens the contact verification ceremony.
///
/// Returns `true` if the user confirmed a match (and the contact is now
/// marked as verified), `false` if they explicitly declared a mismatch,
/// and `null` if they dismissed the sheet without choosing.
Future<bool?> showContactVerificationCeremony(
  BuildContext context,
  WidgetRef ref,
  RemoteIdentity contact,
) {
  return showModalBottomSheet<bool>(
    context: context,
    isScrollControlled: true,
    useSafeArea: true,
    showDragHandle: true,
    builder: (_) {
      return DraggableScrollableSheet(
        expand: false,
        initialChildSize: 0.85,
        maxChildSize: 0.95,
        minChildSize: 0.5,
        builder: (ctx, scrollCtrl) {
          return ContactVerificationView(
            contact: contact,
            scrollController: scrollCtrl,
          );
        },
      );
    },
  );
}

class ContactVerificationView extends ConsumerStatefulWidget {
  const ContactVerificationView({
    super.key,
    required this.contact,
    this.scrollController,
  });

  final RemoteIdentity contact;
  final ScrollController? scrollController;

  @override
  ConsumerState<ContactVerificationView> createState() =>
      _ContactVerificationViewState();
}

class _ContactVerificationViewState
    extends ConsumerState<ContactVerificationView> {
  Future<ContactSasCode>? _codeFuture;

  @override
  void initState() {
    super.initState();
    _codeFuture = _loadCode();
  }

  Future<ContactSasCode> _loadCode() async {
    final sas = ref.read(contactSasServiceProvider);
    final local = await ref.read(identityManagerProvider).getLocalIdentity();
    if (local == null) {
      throw StateError('Local identity not initialized');
    }
    return sas.derive(
      localPublicKeyBase64: local.publicKeyBase64,
      peerPublicKeyBase64: widget.contact.publicKeyBase64,
    );
  }

  Future<void> _confirmMatch() async {
    final messengerName = widget.contact.displayName;
    final messenger = ScaffoldMessenger.of(context);
    final snackbarText = AppStrings.t(
      context,
      'verifyContactVerifiedSnackbar',
      namedArgs: {'name': messengerName},
    );

    await ref
        .read(identitiesControllerProvider)
        .markContactVerified(widget.contact);

    if (!mounted) return;
    Navigator.of(context).pop(true);
    messenger.showSnackBar(SnackBar(content: Text(snackbarText)));
  }

  Future<void> _rejectMatch() async {
    final t = AppStrings.t;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          title: Text(t(dialogContext, 'verifyContactMismatchTitle')),
          content: Text(t(dialogContext, 'verifyContactMismatchBody')),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(true),
              child: Text(t(dialogContext, 'verifyContactMismatchAcknowledge')),
            ),
          ],
        );
      },
    );
    if (!mounted) return;
    if (confirmed == true) {
      Navigator.of(context).pop(false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final theme = Theme.of(context);

    return SafeArea(
      child: FutureBuilder<ContactSasCode>(
        future: _codeFuture,
        builder: (context, snapshot) {
          if (snapshot.connectionState != ConnectionState.done) {
            return const SizedBox(
              height: 320,
              child: Center(child: CircularProgressIndicator()),
            );
          }
          if (snapshot.hasError || snapshot.data == null) {
            return Padding(
              padding: const EdgeInsets.all(24),
              child: Text(
                t(context, 'verifyContactTitle'),
                style: theme.textTheme.titleLarge,
              ),
            );
          }

          final code = snapshot.data!;
          return ListView(
            controller: widget.scrollController,
            padding: const EdgeInsets.fromLTRB(24, 8, 24, 24),
            children: [
              Text(
                t(context, 'verifyContactTitle'),
                style: theme.textTheme.titleLarge,
              ),
              const SizedBox(height: 12),
              Text(
                t(
                  context,
                  'verifyContactCeremonyIntro',
                  namedArgs: {'name': widget.contact.displayName},
                ),
                style: theme.textTheme.bodyMedium,
              ),
              const SizedBox(height: 24),
              _CodeCard(
                label: t(context, 'verifyContactDigitsLabel'),
                value: _formatDigits(code.digits),
                isMonospace: true,
              ),
              const SizedBox(height: 12),
              _CodeCard(
                label: t(context, 'verifyContactEmojiLabel'),
                value: code.emojiGlyphs.join('   '),
                isMonospace: false,
                isLarge: true,
              ),
              const SizedBox(height: 24),
              FilledButton.icon(
                onPressed: _confirmMatch,
                icon: const Icon(Icons.check_circle_outline),
                label: Text(t(context, 'verifyContactMatch')),
                style: FilledButton.styleFrom(
                  minimumSize: const Size.fromHeight(48),
                ),
              ),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: _rejectMatch,
                icon: const Icon(Icons.report_gmailerrorred_outlined),
                label: Text(t(context, 'verifyContactDoNotMatch')),
                style: OutlinedButton.styleFrom(
                  minimumSize: const Size.fromHeight(48),
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  String _formatDigits(String digits) {
    if (digits.length != 6) return digits;
    return '${digits.substring(0, 3)} ${digits.substring(3)}';
  }
}

class _CodeCard extends StatelessWidget {
  const _CodeCard({
    required this.label,
    required this.value,
    required this.isMonospace,
    this.isLarge = false,
  });

  final String label;
  final String value;
  final bool isMonospace;
  final bool isLarge;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final valueStyle = (isLarge
            ? theme.textTheme.headlineMedium
            : theme.textTheme.headlineSmall)
        ?.copyWith(
      fontFamily: isMonospace ? 'monospace' : null,
      letterSpacing: isMonospace ? 2.0 : null,
      fontWeight: FontWeight.w600,
    );

    return Card(
      elevation: 0,
      color: theme.colorScheme.surfaceContainerHighest,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label.toUpperCase(),
              style: theme.textTheme.labelSmall?.copyWith(
                letterSpacing: 1.0,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 8),
            Center(
              child: SelectableText(
                value,
                style: valueStyle,
                textAlign: TextAlign.center,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
