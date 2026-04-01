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
import '../../ui/passphrase_button.dart';
import '../../utils/app_platform.dart';
import '../home/home_controller.dart';
import '../premium/backup_view.dart';
import '../premium/cover_generator_view.dart';
import '../premium/multi_identity_view.dart';
import 'about_view.dart';
import 'widgets/app_lock_settings.dart';
import 'widgets/data_reset_section.dart';
import 'widgets/language_selector.dart';
import 'widgets/premium_tile.dart';
import 'widgets/theme_selector.dart';

class SettingsView extends ConsumerWidget {
  const SettingsView({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;
    final caps = ref.watch(layergramCapabilitiesProvider);
    final showTooltipSetting = AppPlatform.supportsHoverTooltips;
    final tooltipsEnabled = ref.watch(tooltipsEnabledProvider);
    final tooltipService = ref.read(tooltipServiceProvider);
    final screenProtectionEnabled = ref.watch(screenProtectionEnabledProvider);
    final screenProtectionService = ref.read(screenProtectionServiceProvider);
    final hideChatPreview = ref.watch(hideChatPreviewProvider);
    final previewService = ref.read(previewServiceProvider);
    final sessionDecryptionCacheEnabled =
        ref.watch(sessionDecryptionCacheEnabledProvider);
    final sessionDecryptionCacheService =
        ref.read(sessionDecryptionCacheServiceProvider);
    // Aggiungi context.locale per forzare il rebuild quando cambia la lingua
    Localizations.maybeLocaleOf(context);

    return Scaffold(
      backgroundColor: Colors.transparent,
      appBar: AppBar(
        title: Text(t(context, 'settings')),
        actions: const [PassphraseButton(), SizedBox(width: 8)],
      ),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 24),
        children: [
          ListTile(
            title: Text(t(context, 'security')),
            subtitle: Text(t(context, 'privacyShield')),
          ),
          SwitchListTile.adaptive(
            value: screenProtectionEnabled,
            title: Text(t(context, 'screenProtection')),
            subtitle: Text(t(context, 'screenProtectionSubtitle')),
            onChanged: (value) async {
              ref.read(screenProtectionEnabledProvider.notifier).state = value;
              if (!value) {
                ref.read(privacyShieldVisibleProvider.notifier).state = false;
              }
              await screenProtectionService.setEnabled(value);
            },
          ),
          AppLockSettings(),
          const SizedBox(height: 8),
          if (showTooltipSetting) ...[
            SwitchListTile.adaptive(
              value: tooltipsEnabled,
              title: Text(t(context, 'enableButtonDescriptions')),
              subtitle: Text(t(context, 'enableButtonDescriptionsSubtitle')),
              onChanged: (value) async {
                ref.read(tooltipsEnabledProvider.notifier).state = value;
                await tooltipService.setEnabled(value);
              },
            ),
            const SizedBox(height: 8),
          ],
          SwitchListTile.adaptive(
            value: hideChatPreview,
            title: Text(t(context, 'hideChatPreview')),
            subtitle: Text(t(context, 'hideChatPreviewSubtitle')),
            onChanged: (value) async {
              ref.read(hideChatPreviewProvider.notifier).state = value;
              await previewService.setHidden(value);
            },
          ),
          const SizedBox(height: 8),
          SwitchListTile.adaptive(
            value: sessionDecryptionCacheEnabled,
            title: Text(t(context, 'sessionDecryptionCache')),
            subtitle: Text(t(context, 'sessionDecryptionCacheSubtitle')),
            onChanged: (value) async {
              ref.read(sessionDecryptionCacheEnabledProvider.notifier).state =
                  value;
              await sessionDecryptionCacheService.setEnabled(value);
              final controller = ref.read(homeControllerProvider);
              if (!value) {
                controller.clearSessionDecryptionCache();
                return;
              }
              if (!ref.read(appNeedsUnlockProvider)) {
                await controller.warmSessionDisplayKeys();
              }
            },
          ),
          const SizedBox(height: 8),
          ThemeSelector(),
          const SizedBox(height: 8),
          LanguageSelector(),
          const SizedBox(height: 8),

          if (caps.backup.isAvailable || caps.coverGenerator.isAvailable || caps.identity.isAvailable) ...[
            ListTile(
              leading: const Icon(Icons.workspace_premium_outlined),
              title: Text(t(context, 'premiumFeatures')),
            ),
            if (caps.backup.isAvailable)
              PremiumTile(
                isAvailable: caps.backup.isAvailable,
                icon: Icons.cloud_outlined,
                titleKey: 'premiumBackupTitle',
                subtitleKey: 'premiumBackupSubtitle',
                onTap: () {
                  Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => const BackupView()),
                  );
                },
              ),
            if (caps.coverGenerator.isAvailable)
              PremiumTile(
                isAvailable: caps.coverGenerator.isAvailable,
                icon: Icons.auto_awesome,
                titleKey: 'premiumCoverTitle',
                subtitleKey: 'premiumCoverSubtitle',
                onTap: () {
                  Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => const CoverGeneratorView()),
                  );
                },
              ),
            if (caps.identity.isAvailable)
              PremiumTile(
                isAvailable: caps.identity.isAvailable,
                icon: Icons.switch_account_outlined,
                titleKey: 'premiumMultiIdentityTitle',
                subtitleKey: 'premiumMultiIdentitySubtitle',
                onTap: () {
                  Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => const MultiIdentityView()),
                  );
                },
              ),
            const SizedBox(height: 8),
          ],

          ListTile(
            title: Text(t(context, 'privacyFirst')),
            subtitle: Text(t(context, 'localOnlyVersion')),
          ),
          const SizedBox(height: 8),
          ListTile(
            leading: const Icon(Icons.info_outline),
            title: Text(t(context, 'aboutApp')),
            onTap: () {
              Navigator.of(context).push(
                MaterialPageRoute(builder: (_) => const AboutView()),
              );
            },
          ),
          const SizedBox(height: 24),
          DataResetSection(),
        ],
      ),
    );
  }
}
