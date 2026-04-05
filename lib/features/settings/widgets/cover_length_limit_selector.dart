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

import '../../../core/providers.dart';
import '../../../core/security/cover_message_length_limit_service.dart';
import '../../../l10n/app_strings.dart';

class CoverLengthLimitSelector extends ConsumerWidget {
  const CoverLengthLimitSelector({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;
    final selectedLimit = ref.watch(coverMessageLengthLimitProvider);
    final service = ref.read(coverMessageLengthLimitServiceProvider);

    String limitLabel(int? limit) {
      if (limit == null) {
        return t(context, 'noLimit');
      }
      return '$limit';
    }

    return ListTile(
      leading: const Icon(Icons.rule_outlined),
      title: Text(t(context, 'coverLengthLimit')),
      subtitle: Text(limitLabel(selectedLimit)),
      onTap: () async {
        final selected = await showModalBottomSheet<(bool, int?)?>(
          context: context,
          builder: (context) => SafeArea(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                ListTile(title: Text(t(context, 'coverLengthLimit'))),
                ...CoverMessageLengthLimitService.supportedLimits.map(
                  (limit) => ListTile(
                    title: Text(limitLabel(limit)),
                    leading: selectedLimit == limit
                        ? const Icon(Icons.check, color: Colors.green)
                        : const SizedBox(width: 24),
                    onTap: () => Navigator.of(context).pop((true, limit)),
                  ),
                ),
              ],
            ),
          ),
        );
        if (selected == null || !selected.$1) {
          return;
        }
        ref.read(coverMessageLengthLimitProvider.notifier).state = selected.$2;
        await service.setLimit(selected.$2);
      },
    );
  }
}
