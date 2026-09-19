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

/// Experimental SYSTEM keyboard settings surface.
///
/// The entry point is only rendered when the compile-time feature is enabled on
/// a supported platform. Copy is provided locally in Italian and English on
/// purpose: this is a local experimental increment and must not change the
/// global localization catalogues or claim a released feature.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'system_keyboard_app_service.dart';

/// Settings tile for the experimental SYSTEM keyboard.
class SystemKeyboardSettingsTile extends ConsumerWidget {
  /// Creates the tile.
  const SystemKeyboardSettingsTile({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final SystemKeyboardAppService service =
        ref.watch(systemKeyboardAppServiceProvider);
    return ListenableBuilder(
      listenable: service,
      builder: (BuildContext context, Widget? _) {
        final _SystemKeyboardStrings strings =
            _SystemKeyboardStrings.of(context);
        final bool enabled = service.isEnabled;
        final bool interactive = service.isInteractive;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            SwitchListTile.adaptive(
              key: const ValueKey('system-keyboard-opt-in'),
              value: enabled,
              title: Text(strings.title),
              subtitle: Text(strings.subtitle),
              onChanged: interactive
                  ? (bool value) async {
                      if (!value) {
                        await service.setEnabled(false);
                        return;
                      }
                      final bool confirmed =
                          await _confirmEnable(context, strings);
                      if (!confirmed) return;
                      await service.setEnabled(true);
                    }
                  : null,
            ),
            if (enabled)
              ListTile(
                key: const ValueKey('system-keyboard-open-settings'),
                leading: const Icon(Icons.settings_outlined),
                title: Text(strings.openSettings),
                subtitle: Text(strings.openSettingsSubtitle),
                onTap: () => service.openInputMethodSettings(),
              ),
          ],
        );
      },
    );
  }

  Future<bool> _confirmEnable(
    BuildContext context,
    _SystemKeyboardStrings strings,
  ) async {
    final bool? confirmed = await showDialog<bool>(
      context: context,
      builder: (BuildContext dialogContext) => AlertDialog(
        title: Text(strings.dialogTitle),
        content: SingleChildScrollView(child: Text(strings.dialogBody)),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: Text(strings.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: Text(strings.confirm),
          ),
        ],
      ),
    );
    return confirmed ?? false;
  }
}

class _SystemKeyboardStrings {
  const _SystemKeyboardStrings({
    required this.title,
    required this.subtitle,
    required this.dialogTitle,
    required this.dialogBody,
    required this.confirm,
    required this.cancel,
    required this.openSettings,
    required this.openSettingsSubtitle,
  });

  final String title;
  final String subtitle;
  final String dialogTitle;
  final String dialogBody;
  final String confirm;
  final String cancel;
  final String openSettings;
  final String openSettingsSubtitle;

  static _SystemKeyboardStrings of(BuildContext context) {
    final String code =
        Localizations.maybeLocaleOf(context)?.languageCode ?? 'en';
    return code == 'it' ? _italian : _english;
  }

  static const _SystemKeyboardStrings _english = _SystemKeyboardStrings(
    title: 'System keyboard (experimental)',
    subtitle: 'Encrypt from other apps with explicitly chosen recipients.',
    dialogTitle: 'Enable the experimental system keyboard?',
    dialogBody: 'The system keyboard is an experimental preview. Text you '
        'type or preview is shown in Layergram\'s own keyboard window while '
        'another app is in the foreground, and is never inserted into that '
        'app\'s editor. Outside Layergram\'s main window, operating system '
        'screenshot and accessibility protections may be weaker. The existing '
        'app lock deadline still applies, and the keyboard works only while '
        'Layergram is alive and its ordinary identity is unlocked. You must '
        'choose every recipient explicitly: the keyboard never infers a chat '
        'recipient from the host app. No decrypted keys leave the app.',
    confirm: 'Enable',
    cancel: 'Cancel',
    openSettings: 'Open keyboard settings',
    openSettingsSubtitle:
        'Choose the Layergram keyboard in Android input method settings.',
  );

  static const _SystemKeyboardStrings _italian = _SystemKeyboardStrings(
    title: 'Tastiera di sistema (sperimentale)',
    subtitle: 'Cifra da altre app con destinatari scelti esplicitamente.',
    dialogTitle: 'Attivare la tastiera di sistema sperimentale?',
    dialogBody: 'La tastiera di sistema è un\'anteprima sperimentale. Il testo '
        'che digiti o visualizzi è mostrato nella finestra della tastiera di '
        'Layergram mentre un\'altra app è in primo piano e non viene mai '
        'inserito nell\'editor di quell\'app. Fuori dalla finestra principale '
        'di Layergram, le protezioni del sistema operativo contro screenshot e '
        'accessibilità possono essere più deboli. La scadenza del blocco app '
        'esistente resta valida e la tastiera funziona solo mentre Layergram è '
        'attiva e l\'identità ordinaria è sbloccata. Devi scegliere ogni '
        'destinatario esplicitamente: la tastiera non deduce mai il '
        'destinatario dalla chat dell\'app ospite. Nessuna chiave decifrata '
        'lascia l\'app.',
    confirm: 'Attiva',
    cancel: 'Annulla',
    openSettings: 'Apri impostazioni tastiera',
    openSettingsSubtitle:
        'Scegli la tastiera Layergram nelle impostazioni di sistema Android.',
  );
}
