import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../utils/app_platform.dart';
import 'system_keyboard_app_service.dart';

/// Available after onboarding and from Settings. iOS can open only the app's
/// Settings page through the public URL; the keyboard list is reached manually.
class SystemKeyboardSetupGuide extends ConsumerWidget {
  const SystemKeyboardSetupGuide({super.key, this.iosOverride});

  /// Allows a widget test to exercise the iOS instructions on a macOS runner.
  @visibleForTesting
  final bool? iosOverride;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final language = Localizations.localeOf(context).languageCode;
    String copy(String it, String es, String en) => language == 'it'
        ? it
        : language == 'es'
            ? es
            : en;
    final ios = iosOverride ?? AppPlatform.isIOS;
    final steps = ios
        ? <String>[
            copy(
                'In Layergram, attiva Tastiera di sistema nelle Impostazioni di sicurezza.',
                'En Layergram, activa Teclado del sistema en Ajustes de seguridad.',
                'In Layergram, enable System keyboard in Security settings.'),
            copy(
                'Su iPhone apri Impostazioni → Generali → Tastiera → Tastiere → Aggiungi nuova tastiera → Layergram.',
                'En el iPhone, abre Ajustes → General → Teclado → Teclados → Añadir nuevo teclado → Layergram.',
                'On iPhone, open Settings → General → Keyboard → Keyboards → Add New Keyboard → Layergram.'),
            copy(
                'Tocca Layergram nell’elenco e abilita Accesso completo. Serve per condividere in sicurezza lo stato cifrato con l’app.',
                'Toca Layergram en la lista y activa Permitir acceso total. Es necesario para compartir el estado cifrado con la app.',
                'Tap Layergram in the list and enable Allow Full Access. This lets the keyboard share encrypted state with the app.'),
            copy(
                'Torna in Layergram e sbloccalo. Nell’app di messaggistica usa il globo per scegliere la tastiera Layergram.',
                'Vuelve a Layergram y desbloquéalo. En la app de mensajería, usa el globo para elegir el teclado Layergram.',
                'Return to Layergram and unlock it. In a messaging app, use the globe to select the Layergram keyboard.'),
          ]
        : <String>[
            copy(
                'In Layergram, attiva Tastiera di sistema nelle Impostazioni di sicurezza.',
                'En Layergram, activa Teclado del sistema en Ajustes de seguridad.',
                'In Layergram, enable System keyboard in Security settings.'),
            copy(
                'Apri le impostazioni delle tastiere Android e abilita Layergram.',
                'Abre los ajustes de teclados de Android y habilita Layergram.',
                'Open Android keyboard settings and enable Layergram.'),
            copy(
                'Scegli Layergram come tastiera mentre scrivi in un’altra app.',
                'Elige Layergram como teclado al escribir en otra app.',
                'Choose Layergram as the keyboard while typing in another app.'),
          ];
    return Scaffold(
      appBar: AppBar(
          title: Text(copy('Tastiera Layergram', 'Teclado Layergram',
              'Layergram keyboard'))),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          Text(
              copy(
                  'Scrivi messaggi cifrati nelle altre app',
                  'Escribe mensajes cifrados en otras apps',
                  'Write encrypted messages in other apps'),
              style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 12),
          Text(copy(
              'La tastiera di sistema è disponibile anche nella versione open source. Prima di usarla devi aggiungerla e autorizzarla sul dispositivo.',
              'El teclado del sistema también está disponible en la versión de código abierto. Primero debes añadirlo y autorizarlo en el dispositivo.',
              'The system keyboard is available in the open-source edition too. First add and authorize it on your device.')),
          const SizedBox(height: 20),
          for (var i = 0; i < steps.length; i++)
            ListTile(
              leading: CircleAvatar(child: Text('${i + 1}')),
              title: Text(steps[i]),
            ),
          if (ios)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 12),
              child: Text(copy(
                  'Il pulsante apre le impostazioni dell’app. iOS non offre un collegamento pubblico diretto alla lista delle tastiere: segui il percorso indicato sopra.',
                  'El botón abre los ajustes de la app. iOS no ofrece un enlace público directo a la lista de teclados: sigue la ruta indicada arriba.',
                  'The button opens this app’s Settings page. iOS offers no public direct link to the keyboard list: follow the path above.')),
            ),
          FilledButton.icon(
            key: const ValueKey('system-keyboard-guide-open-settings'),
            onPressed: () async {
              final opened = await ref
                  .read(systemKeyboardAppServiceProvider)
                  .openInputMethodSettings();
              if (!opened && context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                  content: Text(copy(
                      'Apri manualmente le impostazioni del dispositivo.',
                      'Abre manualmente los ajustes del dispositivo.',
                      'Open device settings manually.')),
                ));
              }
            },
            icon: const Icon(Icons.settings_outlined),
            label: Text(ios
                ? copy('Apri impostazioni dell’app', 'Abrir ajustes de la app',
                    'Open app settings')
                : copy('Apri impostazioni tastiera', 'Abrir ajustes de teclado',
                    'Open keyboard settings')),
          ),
        ],
      ),
    );
  }
}
