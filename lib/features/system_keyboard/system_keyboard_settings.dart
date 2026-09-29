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
import 'package:local_auth/local_auth.dart';

import '../../core/providers.dart';
import '../../utils/app_platform.dart';
import 'system_keyboard_app_service.dart';
import 'system_keyboard_idle_policy.dart';
import 'system_keyboard_setup_guide.dart';

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
            ListTile(
              key: const ValueKey('system-keyboard-setup-guide'),
              leading: const Icon(Icons.keyboard_outlined),
              title: Text(Localizations.localeOf(context).languageCode == 'it'
                  ? 'Come attivare la tastiera'
                  : 'How to set up the keyboard'),
              onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(
                builder: (_) => const SystemKeyboardSetupGuide(),
              )),
            ),
            if (enabled &&
                (AppPlatform.isAndroid ||
                    ((AppPlatform.isIOS || AppPlatform.isAndroid) &&
                        systemKeyboardAutonomousEnabled)))
              ListTile(
                title: Text(Localizations.localeOf(context).languageCode == 'it'
                    ? 'Blocco per inattività della tastiera'
                    : 'Keyboard inactivity lock'),
                subtitle: Text(Localizations.localeOf(context).languageCode ==
                        'it'
                    ? 'Riparte a ogni tocco. Il blocco app può ridurre questo intervallo.'
                    : 'Restarts with each touch. The app lock may shorten this interval.'),
                trailing: DropdownButton<int>(
                  key: const ValueKey('system-keyboard-idle-seconds'),
                  value: service.idlePreferenceSeconds,
                  items: [
                    for (final seconds
                        in SystemKeyboardIdlePolicy.supportedIdleSeconds)
                      DropdownMenuItem(
                          value: seconds, child: Text('$seconds s'))
                  ],
                  onChanged: interactive
                      ? (seconds) async {
                          if (seconds == null) return;
                          final saved =
                              await service.setIdlePreferenceSeconds(seconds);
                          if (!saved && context.mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                                content: Text(Localizations.localeOf(context)
                                            .languageCode ==
                                        'it'
                                    ? 'Impossibile salvare la preferenza.'
                                    : 'Unable to save the preference.')));
                          }
                        }
                      : null,
                ),
              ),
            if (enabled &&
                (AppPlatform.isIOS || AppPlatform.isAndroid) &&
                systemKeyboardAutonomousEnabled)
              SwitchListTile.adaptive(
                key: const ValueKey('system-keyboard-scramble'),
                value: service.scramblePreference,
                title: Text(Localizations.localeOf(context).languageCode == 'it'
                    ? 'Mescola i tasti'
                    : 'Shuffle keys'),
                subtitle: Text(
                    Localizations.localeOf(context).languageCode == 'it'
                        ? 'Riordina le lettere quando apri la tastiera.'
                        : 'Rearrange letters when you open the keyboard.'),
                onChanged: interactive
                    ? (value) async {
                        await service.setScramblePreference(value);
                      }
                    : null,
              ),
            if (enabled &&
                (AppPlatform.isIOS || AppPlatform.isAndroid) &&
                systemKeyboardAutonomousEnabled)
              SwitchListTile.adaptive(
                key: const ValueKey('system-keyboard-save-history'),
                value: service.saveHistoryPreference,
                title: Text(Localizations.localeOf(context).languageCode == 'it'
                    ? 'Salva le conversazioni della tastiera nelle chat'
                    : 'Save keyboard conversations in chats'),
                subtitle: Text(Localizations.localeOf(context).languageCode ==
                        'it'
                    ? 'I messaggi cifrati e decifrati appariranno nella chat del contatto.'
                    : 'Encrypted and decrypted messages appear in the contact chat.'),
                onChanged: interactive
                    ? (value) async {
                        final saved =
                            await service.setSaveHistoryPreference(value);
                        if (!saved && context.mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                            content: Text(
                                Localizations.localeOf(context).languageCode ==
                                        'it'
                                    ? 'Impossibile salvare la preferenza.'
                                    : 'Unable to save the preference.'),
                          ));
                        }
                      }
                    : null,
              ),
            if (enabled &&
                (AppPlatform.isIOS || AppPlatform.isAndroid) &&
                systemKeyboardAutonomousEnabled)
              SwitchListTile.adaptive(
                key: const ValueKey('system-keyboard-biometric-resume'),
                value: service.biometricResumePreference,
                title: Text(Localizations.localeOf(context).languageCode == 'it'
                    ? 'Riapri la tastiera con biometria'
                    : 'Reopen keyboard with biometrics'),
                subtitle: Text(Localizations.localeOf(context).languageCode ==
                        'it'
                    ? 'Una credenziale protetta dalla biometria consente di riaprire la sessione anche dopo una lunga inattività, finché la tastiera mantiene la custodia FS. Dopo il blocco tocca un tasto; se la custodia non è più valida, apri Layergram.'
                    : 'A biometric-protected credential can reopen the session after long inactivity while the keyboard retains FS custody. After an idle lock, tap a key; if custody is no longer valid, open Layergram.'),
                onChanged: interactive
                    ? (value) async {
                        final biometrics = ref.read(appLockServiceProvider);
                        final supported = !value ||
                            (await biometrics.isBiometricSupported() &&
                                (!AppPlatform.isAndroid ||
                                    (await biometrics.availableBiometrics())
                                        .contains(BiometricType.strong)));
                        if (!supported) {
                          if (context.mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                              content: Text(Localizations.localeOf(context)
                                          .languageCode ==
                                      'it'
                                  ? 'Attiva una biometria compatibile nelle impostazioni del dispositivo.'
                                  : 'Enable a compatible biometric in device settings.'),
                            ));
                          }
                          return;
                        }
                        final saved =
                            await service.setBiometricResumePreference(value);
                        if (!saved && context.mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                            content: Text(
                                Localizations.localeOf(context).languageCode ==
                                        'it'
                                    ? 'Impossibile salvare la preferenza.'
                                    : 'Unable to save the preference.'),
                          ));
                        }
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
            if (enabled &&
                (AppPlatform.isIOS || AppPlatform.isAndroid) &&
                const bool.fromEnvironment('LAYERGRAM_KEYBOARD_DIAGNOSTICS'))
              ListTile(
                key: const ValueKey('system-keyboard-lost-fs-fixture-reset'),
                leading: const Icon(Icons.restart_alt),
                title: const Text('Ripristina FS tastiera (test)'),
                subtitle: const Text(
                    'Solo se lo stato FS di questa tastiera è irrecuperabile. Identità, contatti e chat restano.'),
                onTap: () async {
                  final confirmed = await showDialog<bool>(
                    context: context,
                    builder: (dialogContext) => AlertDialog(
                      title: const Text('Avvia nuova FS su questo dispositivo?'),
                      content: const Text(
                          'La vecchia FS di questo dispositivo non potrà proseguire. Identità, contatti e chat restano. Il controllo rifiuta il reset se lo stato è recuperabile.'),
                      actions: [
                        TextButton(
                          onPressed: () =>
                              Navigator.of(dialogContext).pop(false),
                          child: const Text('Annulla'),
                        ),
                        FilledButton(
                          onPressed: () =>
                              Navigator.of(dialogContext).pop(true),
                          child: const Text('Avvia nuova FS'),
                        ),
                      ],
                    ),
                  );
                  if (confirmed != true || !context.mounted) return;
                  try {
                    final lost = await ref.read(
                        systemKeyboardLostCustodyActionProvider)(reset: true);
                    if (context.mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                        content: Text(lost
                            ? 'Nuova FS di questo dispositivo avviata.'
                            : 'Nessuna FS irrecuperabile da ripristinare.'),
                      ));
                    }
                  } on SystemKeyboardResetCommittedRecoveryFailed {
                    if (context.mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                        content: Text(
                            'FS riavviata; apertura della tastiera da verificare.'),
                      ));
                    }
                  } catch (error) {
                    if (context.mounted) {
                      final blockedByOtherState = error is StateError &&
                          error.message ==
                              'Unrelated V3 protocol state blocks reset';
                      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                        content: Text(blockedByOtherState
                            ? 'Ripristino bloccato: altro stato FS presente.'
                            : 'Ripristino non riuscito: stato FS da verificare.'),
                      ));
                    }
                  }
                },
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
    final bool italian = code == 'it';
    final _SystemKeyboardStrings base = italian ? _italian : _english;
    if (AppPlatform.isAndroid && systemKeyboardAutonomousEnabled) {
      return _SystemKeyboardStrings(
        title: base.title,
        subtitle: italian
            ? 'Cifra e decifra nelle altre app, con sessione attiva durante l’uso.'
            : 'Encrypt and decrypt in other apps while the session stays active during use.',
        dialogTitle: base.dialogTitle,
        dialogBody:
            italian ? _androidAutonomousItalian : _androidAutonomousEnglish,
        confirm: base.confirm,
        cancel: base.cancel,
        openSettings: base.openSettings,
        openSettingsSubtitle: base.openSettingsSubtitle,
      );
    }
    if (!AppPlatform.isIOS) return base;
    return _SystemKeyboardStrings(
      title: base.title,
      subtitle: systemKeyboardAutonomousEnabled
          ? (italian
              ? 'Richiede iOS 26+. Scrivi senza interrompere la sessione.'
              : 'Requires iOS 26+. Keep writing within the active session.')
          : italian
              ? 'Richiede iOS 26+. Sessioni brevi dopo aver lasciato Layergram.'
              : 'Requires iOS 26+. Short sessions after leaving Layergram.',
      dialogTitle: base.dialogTitle,
      dialogBody: systemKeyboardAutonomousEnabled
          ? (italian ? _autonomousItalian : _autonomousEnglish)
          : '${base.dialogBody}\n\n${italian ? _iosItalian : _iosEnglish}',
      confirm: base.confirm,
      cancel: base.cancel,
      openSettings: italian ? 'Apri impostazioni di iOS' : 'Open iOS settings',
      openSettingsSubtitle: italian
          ? 'Aggiungi Layergram in Generali → Tastiera → Tastiere; consenti Accesso completo.'
          : 'Add Layergram under General → Keyboard → Keyboards; allow Full Access.',
    );
  }

  static const String _autonomousItalian =
      'La tastiera è sperimentale e richiede iOS 26+. Dopo aver sbloccato Layergram, '
      'puoi usarla nelle altre app anche quando iOS sospende Layergram. Ogni tocco '
      'rinnova il tempo di inattività scelto; il blocco immediato dell’app ne impedisce l’uso. '
      'Funziona solo con l’identità ordinaria senza passphrase. In modalità Normale il primo '
      'messaggio è leggibile mentre la FS prosegue; Maximum mantiene i propri vincoli. '
      'Devi scegliere il destinatario: dopo la decifratura puoi toccare il mittente per rispondergli. '
      'Nascondere o cambiare tastiera, cambiare campo o bloccare il dispositivo chiude la sessione. '
      'Per riaprirla torna in Layergram e sbloccalo se richiesto. '
      'Il motore della tastiera riceve temporaneamente lo stato delle sessioni e le prove '
      'necessarie al loro ripristino; queste possono contenere testi di messaggi precedenti. '
      'Una capacità temporanea della chiave identità entra nella tastiera per cifrare e decifrare; '
      'la frase di recupero e la chiave radice dell’archivio restano nell’app. Lo stato operativo è cifrato '
      'su disco e torna all’app alla riapertura. Non è possibile impedire gli screenshot '
      'della tastiera, e le protezioni dall’accessibilità possono essere più deboli. '
      'Accesso completo serve per il collegamento locale cifrato: iOS concede anche '
      'l’accesso alla rete, che la tastiera non usa. Solo testo, senza autodistruzione. '
      'Cifra e inserisci aggiunge il testo cifrato all’app ospite: dovrai inviarlo da lì.';

  static const String _androidAutonomousItalian =
      'Dopo aver sbloccato Layergram, puoi usare la tastiera nelle altre app anche quando '
      'Layergram è sospesa. Ogni tocco rinnova il tempo di inattività scelto. '
      'Sono disponibili l’identità ordinaria senza passphrase e tutti i suoi contatti; '
      'Maximum mantiene i propri vincoli di comunicazione. Scegli e conferma sempre il destinatario. '
      'Il motore isolato della tastiera riceve temporaneamente le operazioni della chiave identità '
      'e lo stato FS, che può contenere testi precedenti. La frase di recupero e la chiave '
      'radice dell’archivio restano nell’app. Lo stato operativo è cifrato in una custodia '
      'locale esclusa dai backup e torna all’app alla riapertura, senza azzerare la FS. '
      'Nascondere la tastiera o bloccare il dispositivo cancella i contenuti temporanei e chiude '
      'la sessione. Se abiliti la riapertura biometrica, una credenziale protetta nel Keystore '
      'permette di riaprirla con biometria forte finché la custodia FS è valida '
      'e il dispositivo non viene riavviato; altrimenti riapri Layergram. '
      'La tastiera protegge la propria finestra dalle catture quando la protezione schermo è attiva '
      'e non usa la rete. Puoi scegliere se salvare gli scambi nelle chat di Layergram. '
      'Solo testo, senza autodistruzione. Cifra e inserisci aggiunge il cifrato nell’app ospite; '
      'il pulsante Invia dell’app ospite lo spedisce.';

  static const String _androidAutonomousEnglish =
      'After unlocking Layergram, use the keyboard in other apps even while Layergram is suspended. '
      'Each touch renews the selected inactivity interval. The ordinary identity without a '
      'passphrase and all its contacts are available; Maximum retains its communication rules. '
      'Always choose and confirm the recipient. The isolated keyboard engine temporarily '
      'receives identity-key operations and FS state, which can include previous message text. '
      'The recovery phrase and archive root key remain in the app. Working state is encrypted '
      'in local custody excluded from backups and reclaimed when the app reopens, without resetting FS. '
      'Hiding the keyboard or locking the device clears temporary content and closes the session. '
      'If biometric reopening is enabled, a Keystore-protected credential permits reopening '
      'with a strong biometric while FS custody is valid and the device has not '
      'rebooted; otherwise reopen Layergram. The keyboard protects '
      'its own window from captures when screen protection is enabled and does not use the network. '
      'Choose whether to save keyboard exchanges in Layergram chats. Text only, without '
      'self-destruction. Encrypt & insert places ciphertext in the host app; its Send button sends it.';

  static const String _autonomousEnglish =
      'The experimental keyboard requires iOS 26+. After unlocking Layergram, '
      'you can use it in other apps even when iOS suspends Layergram. Each touch '
      'restarts the selected inactivity interval; immediate app locking prevents use. '
      'Only the ordinary identity without a passphrase is available. In Normal mode '
      'the first message is readable while FS continues; Maximum keeps its session rules. '
      'Choose the recipient explicitly. After decoding, tap the sender to reply. '
      'Hiding or switching keyboards, changing fields or locking the device closes the session. '
      'Return to Layergram and unlock it if requested to start again. '
      'The keyboard engine temporarily receives session state and the evidence needed '
      'for recovery; this can include previous message text. A temporary identity-key '
      'capability enters the keyboard to encrypt and decrypt; the recovery phrase and '
      'archive root key remain in the app. Working state is encrypted on disk and '
      'reclaimed when the app reopens. '
      'The keyboard cannot prevent screenshots, and accessibility protections may be weaker. '
      'Full Access enables the encrypted local connection; iOS also grants network access, '
      'which this keyboard does not use. Text only, without self-destruction. '
      'Encrypt & insert places ciphertext in the host app; send it from that app.';

  static const String _iosItalian =
      'Richiede iOS 26 o successivo per proteggere anche il collegamento locale '
      'con crittografia post-quantum. Su iOS, dopo essere usciti da Layergram, ogni sessione dura al massimo '
      '20 secondi. Nascondere o cambiare tastiera termina la sessione. '
      'iOS può interromperla prima; il blocco app può abbreviarla. '
      'Per riprendere, torna in Layergram e sbloccalo se richiesto. La tastiera '
      'richiede Accesso completo per comunicare localmente con l’app: iOS '
      'concede anche la possibilità di usare la rete, ma questa estensione '
      'non la utilizza. I contenuti temporanei scambiati sono cifrati; chiavi '
      'di identità e database restano nell’app. La tastiera non può impedire '
      'gli screenshot. L’inserimento del messaggio cifrato non conferma '
      'l’invio da parte dell’app ospite.';

  static const String _iosEnglish =
      'Requires iOS 26 or later to protect the local connection with '
      'post-quantum cryptography. On iOS, each session lasts at most 20 seconds after leaving Layergram. '
      'Hiding or switching keyboards ends the session. iOS may end it earlier; '
      'the app lock can shorten it. To resume, return '
      'to Layergram and unlock it if requested. The keyboard requires Full '
      'Access to communicate locally with the app: iOS also grants network '
      'capability, but this extension does not use it. Temporary exchanged '
      'content is encrypted; identity keys and databases remain in the app. '
      'The keyboard cannot prevent screenshots. Inserting ciphertext does '
      'not confirm that the host app has sent the message.';

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
