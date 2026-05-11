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

import '../../core/providers.dart';
import '../../l10n/app_strings.dart';
import 'chat_view.dart';
import 'home_controller.dart';

class DecodeView extends ConsumerStatefulWidget {
  const DecodeView({super.key});

  @override
  ConsumerState<DecodeView> createState() => _DecodeViewState();
}

class _DecodeViewState extends ConsumerState<DecodeView> {
  DecodeOutcome? _outcome;

  Future<void> _replyToSender(DecodeOutcome outcome) async {
    final payload = outcome.payload;
    if (payload == null) return;

    final messenger = ScaffoldMessenger.of(context);
    final controller = DefaultTabController.of(context);
    final sender = await ref
        .read(identitiesRepositoryProvider)
        .getRemoteById(payload.senderId);
    if (sender == null) {
      if (mounted) {
        messenger.showSnackBar(
          SnackBar(content: Text(AppStrings.t(context, 'senderNotFound'))),
        );
      }
      return;
    }

    ref.read(encodeRecipientProvider.notifier).state = sender;
    controller.animateTo(1);
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              FilledButton(
                onPressed: () async {
                  final source =
                      await ref.read(clipboardServiceProvider).readText();
                  final outcome = await ref
                      .read(homeControllerProvider)
                      .decodeHiddenMessage(source);
                  if (!mounted) return;
                  setState(() => _outcome = outcome);

                  if (outcome.kind == DecodeKind.success &&
                      outcome.payload != null) {
                    final sender = await ref
                        .read(identitiesRepositoryProvider)
                        .getRemoteById(outcome.payload!.senderId);
                    if (!context.mounted) return;
                    if (sender != null) {
                      await Navigator.of(context).push(
                        MaterialPageRoute(builder: (_) => ChatView(contact: sender)),
                      );
                    } else {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text(t(context, 'unknownSender'))),
                      );
                    }
                  }
                },
                child: Text(t(context, 'pasteDecode')),
              ),
              const SizedBox(height: 12),
              Expanded(
                child: _outcome == null
                    ? const SizedBox.shrink()
                    : _OutcomeView(
                        outcome: _outcome!,
                        onReply: () => _replyToSender(_outcome!),
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _OutcomeView extends StatelessWidget {
  const _OutcomeView({required this.outcome, required this.onReply});

  final DecodeOutcome outcome;
  final VoidCallback onReply;

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;

    if (outcome.kind == DecodeKind.fsLost) {
      return SelectableText(t(context, 'security.fs.message_lost'));
    }

    if (outcome.kind != DecodeKind.success || outcome.payload == null) {
      return SelectableText(t(context, 'noMessageFoundDesc'));
    }

    final payload = outcome.payload!;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          decoration: ShapeDecoration(
            color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.08),
            shape: ContinuousRectangleBorder(
              borderRadius: BorderRadius.circular(28),
              side: BorderSide(
                color: Theme.of(context).colorScheme.outlineVariant,
              ),
            ),
          ),
          child: SelectableText(payload.text),
        ),
        const SizedBox(height: 8),
        Text('${t(context, 'sender')}: ${payload.senderDisplayName ?? payload.senderId}'),
        const SizedBox(height: 12),
        FilledButton.icon(
          onPressed: onReply,
          icon: const Icon(Icons.reply),
          label: Text(t(context, 'replyToSender')),
        ),
      ],
    );
  }
}
