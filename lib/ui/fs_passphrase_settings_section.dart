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

import '../core/crypto/fs_passphrase_preferences.dart';
import '../core/providers.dart';
import '../l10n/app_strings.dart';

/// "Security for this identity" settings section (spec §11.2, §14.2).
///
/// Visible **only** while a passphrase-derived context is active.
/// When the passphrase is expelled, this section must be removed from the
/// UI immediately — no placeholder, no disabled state, no badge.
class FsPassphraseSettingsSection extends ConsumerWidget {
  const FsPassphraseSettingsSection({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isActive = ref.watch(isPassphraseActiveProvider);
    if (!isActive) return const SizedBox.shrink();

    final t = AppStrings.t;
    final prefs = ref.watch(passphrasePreferencesProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ListTile(
          leading: const Icon(Icons.shield_outlined),
          title: Text(t(context, 'security.pp.section_title')),
          subtitle: Text(t(context, 'security.pp.section_subtitle')),
        ),

        // ── Passphrase timeout (§11.3) ────────────────────────────────────
        ListTile(
          title: Text(t(context, 'security.pp.timeout_title')),
          subtitle: Text(t(context, 'security.pp.timeout_subtitle')),
          trailing: DropdownButton<PassphraseTimeout>(
            value: prefs.timeout,
            underline: const SizedBox.shrink(),
            onChanged: (value) {
              if (value == null) return;
              ref.read(passphrasePreferencesProvider.notifier).updateTimeout(value);
            },
            items: PassphraseTimeout.values.map((to) {
              return DropdownMenuItem(
                value: to,
                child: Text(
                  _timeoutLabel(context, to),
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              );
            }).toList(),
          ),
        ),

        // ── Screen lock expulsion (§11.4) ─────────────────────────────────
        SwitchListTile.adaptive(
          value: prefs.expelOnScreenLock,
          title: Text(t(context, 'security.pp.screen_lock_title')),
          subtitle: Text(t(context, 'security.pp.screen_lock_subtitle')),
          onChanged: (value) {
            ref
                .read(passphrasePreferencesProvider.notifier)
                .updateExpelOnScreenLock(value);
          },
        ),

        // ── History mode (§12.2) ──────────────────────────────────────────
        ListTile(
          title: Text(t(context, 'security.pp.history_title')),
          trailing: DropdownButton<PassphraseHistoryMode>(
            value: prefs.historyMode,
            underline: const SizedBox.shrink(),
            onChanged: (value) {
              if (value == null) return;
              ref
                  .read(passphrasePreferencesProvider.notifier)
                  .updateHistoryMode(value);
            },
            items: PassphraseHistoryMode.values.map((hm) {
              return DropdownMenuItem(
                value: hm,
                child: Text(
                  _historyModeLabel(context, hm),
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              );
            }).toList(),
          ),
        ),

        // ── FS persistence mode (§11.5) ───────────────────────────────────
        ListTile(
          title: Text(t(context, 'security.pp.fs_persistence_title')),
          trailing: DropdownButton<PassphraseFsPersistence>(
            value: prefs.fsPersistence,
            underline: const SizedBox.shrink(),
            onChanged: (value) {
              if (value == null) return;
              ref
                  .read(passphrasePreferencesProvider.notifier)
                  .updateFsPersistence(value);
            },
            items: PassphraseFsPersistence.values.map((fp) {
              return DropdownMenuItem(
                value: fp,
                child: Text(
                  _fsPersistenceLabel(context, fp),
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              );
            }).toList(),
          ),
        ),

        const SizedBox(height: 8),

        // ── Expel now ─────────────────────────────────────────────────────
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: OutlinedButton.icon(
            onPressed: () {
              ref.read(passphraseProvider.notifier).deactivate();
            },
            icon: const Icon(Icons.logout),
            label: Text(t(context, 'security.pp.expel_now')),
            style: OutlinedButton.styleFrom(
              foregroundColor: Theme.of(context).colorScheme.error,
            ),
          ),
        ),
        const SizedBox(height: 16),
      ],
    );
  }

  String _timeoutLabel(BuildContext context, PassphraseTimeout to) {
    final t = AppStrings.t;
    switch (to) {
      case PassphraseTimeout.seconds30:
        return t(context, 'security.pp.timeout_30s');
      case PassphraseTimeout.minutes1:
        return t(context, 'security.pp.timeout_1m');
      case PassphraseTimeout.minutes2:
        return t(context, 'security.pp.timeout_2m');
      case PassphraseTimeout.minutes5:
        return t(context, 'security.pp.timeout_5m');
      case PassphraseTimeout.minutes10:
        return t(context, 'security.pp.timeout_10m');
      case PassphraseTimeout.manual:
        return t(context, 'security.pp.timeout_manual');
    }
  }

  String _historyModeLabel(BuildContext context, PassphraseHistoryMode hm) {
    final t = AppStrings.t;
    switch (hm) {
      case PassphraseHistoryMode.keepEncrypted:
        return t(context, 'security.pp.history_keep');
      case PassphraseHistoryMode.volatile_:
        return t(context, 'security.pp.history_volatile');
      case PassphraseHistoryMode.ephemeral:
        return t(context, 'security.pp.history_ephemeral');
    }
  }

  String _fsPersistenceLabel(
      BuildContext context, PassphraseFsPersistence fp) {
    final t = AppStrings.t;
    switch (fp) {
      case PassphraseFsPersistence.persistent:
        return t(context, 'security.pp.fs_persistent');
      case PassphraseFsPersistence.ephemeral:
        return t(context, 'security.pp.fs_ephemeral');
    }
  }
}
