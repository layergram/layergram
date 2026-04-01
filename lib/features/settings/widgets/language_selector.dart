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
import 'package:easy_localization/easy_localization.dart';
import '../../../l10n/app_strings.dart';

class LanguageSelector extends ConsumerWidget {
  const LanguageSelector({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;
    final currentLocale = Localizations.maybeLocaleOf(context) ?? const Locale('en');
    
    String languageLabel() {
      final code = currentLocale.languageCode;
      if (code == 'en') return 'English';
      if (code == 'it') return 'Italiano';
      if (code == 'es') return 'Español';
      if (code == 'pt' && currentLocale.countryCode == 'PT') return 'Português (PT)';
      if (code == 'pt') return 'Português (Brasil)';
      if (code == 'ru') return 'Русский';
      if (code == 'id') return 'Bahasa Indonesia';
      if (code == 'ar') return 'العربية';
      if (code == 'fr') return 'Français';
      if (code == 'de') return 'Deutsch';
      if (code == 'hi') return 'हिन्दी';
      if (code == 'nl') return 'Nederlands';
      if (code == 'fa') return 'فارسی';
      if (code == 'ro') return 'Română';
      if (code == 'pl') return 'Polski';
      if (code == 'zh') return '中文（繁體）';
      if (code == 'tr') return 'Türkçe';
      if (code == 'ja') return '日本語';
      if (code == 'ko') return '한국어';
      if (code == 'vi') return 'Tiếng Việt';
      if (code == 'th') return 'ภาษาไทย';
      if (code == 'el') return 'Ελληνικά';
      if (code == 'bn') return 'বাংলা';
      if (code == 'mr') return 'मराठी';
      if (code == 'ur') return 'اردو';
      if (code == 'fi') return 'Suomi';
      if (code == 'no') return 'Norsk';
      if (code == 'sv') return 'Svenska';
      if (code == 'uk') return 'Українська';
      if (code == 'sq') return 'Shqip';
      if (code == 'ca') return 'Català';
      if (code == 'sw') return 'Kiswahili';
      if (code == 'ha') return 'Hausa';
      if (code == 'tl') return 'Filipino';
      if (code == 'ms') return 'Bahasa Melayu';
      if (code == 'ta') return 'தமிழ்';
      if (code == 'te') return 'తెలుగు';
      if (code == 'gu') return 'ગુજરાતી';
      if (code == 'kn') return 'ಕನ್ನಡ';
      if (code == 'pa') return 'ਪੰਜਾਬੀ';
      if (code == 'am') return 'አማርኛ';
      if (code == 'yo') return 'Yorùbá';
      return t(context, 'useSystem');
    }

    return ListTile(
      title: Text(t(context, 'language')),
      subtitle: Text(languageLabel()),
      leading: const Icon(Icons.language_outlined),
      onTap: () async {
        // Return a bool flag for 'useSystem' to distinguish from dialog dismissal
        final selected = await showModalBottomSheet<(bool, Locale?)?>(
          context: context,
          builder: (context) => SafeArea(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 16.0, horizontal: 24.0),
                  child: Text(
                    t(context, 'chooseLanguage'),
                    style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold),
                    textAlign: TextAlign.center,
                  ),
                ),
                const Divider(height: 1),
                Flexible(
                  child: SingleChildScrollView(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        ListTile(
                          title: Text(t(context, 'useSystem')),
                          // If currentLocale matches device locale (or if we have a way to track "system" preference)
                          // EasyLocalization doesn't have a built-in "system" vs "explicit" flag easily accessible,
                          // but we can assume if no locale is saved it's system. For now we just show it.
                          leading: const SizedBox(width: 24),
                          onTap: () => Navigator.of(context).pop((true, null)),
                        ),
                        ...(() {
                          final langs = [
                            (name: 'English', locale: const Locale('en')),
                            (name: 'Italiano', locale: const Locale('it')),
                            (name: 'Español', locale: const Locale('es')),
                            (name: 'Português (Brasil)', locale: const Locale('pt')),
                            (name: 'Português (PT)', locale: const Locale('pt', 'PT')),
                            (name: 'Русский', locale: const Locale('ru')),
                            (name: 'Bahasa Indonesia', locale: const Locale('id')),
                            (name: 'العربية', locale: const Locale('ar')),
                            (name: 'Français', locale: const Locale('fr')),
                            (name: 'Deutsch', locale: const Locale('de')),
                            (name: 'हिन्दी', locale: const Locale('hi')),
                            (name: 'Nederlands', locale: const Locale('nl')),
                            (name: 'فارسی', locale: const Locale('fa')),
                            (name: 'Română', locale: const Locale('ro')),
                            (name: 'Polski', locale: const Locale('pl')),
                            (name: '中文（繁體）', locale: const Locale('zh')),
                            (name: 'Türkçe', locale: const Locale('tr')),
                            (name: '日本語', locale: const Locale('ja')),
                            (name: '한국어', locale: const Locale('ko')),
                            (name: 'Tiếng Việt', locale: const Locale('vi')),
                            (name: 'ภาษาไทย', locale: const Locale('th')),
                            (name: 'Ελληνικά', locale: const Locale('el')),
                            (name: 'বাংলা', locale: const Locale('bn')),
                            (name: 'मराठी', locale: const Locale('mr')),
                            (name: 'اردو', locale: const Locale('ur')),
                            (name: 'Suomi', locale: const Locale('fi')),
                            (name: 'Norsk', locale: const Locale('no')),
                            (name: 'Svenska', locale: const Locale('sv')),
                            (name: 'Українська', locale: const Locale('uk')),
                            (name: 'Shqip', locale: const Locale('sq')),
                            (name: 'Català', locale: const Locale('ca')),
                            (name: 'Kiswahili', locale: const Locale('sw')),
                            (name: 'Hausa', locale: const Locale('ha')),
                            (name: 'Filipino', locale: const Locale('tl')),
                            (name: 'Bahasa Melayu', locale: const Locale('ms')),
                            (name: 'தமிழ்', locale: const Locale('ta')),
                            (name: 'తెలుగు', locale: const Locale('te')),
                            (name: 'ગુજરાતી', locale: const Locale('gu')),
                            (name: 'ಕನ್ನಡ', locale: const Locale('kn')),
                            (name: 'ਪੰਜਾਬੀ', locale: const Locale('pa')),
                            (name: 'አማርኛ', locale: const Locale('am')),
                            (name: 'Yorùbá', locale: const Locale('yo')),
                          ];
                          langs.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
                          return langs.map((lang) {
                            final isSelected = currentLocale.languageCode == lang.locale.languageCode &&
                                currentLocale.countryCode == lang.locale.countryCode;
                            return ListTile(
                              title: Text(lang.name),
                              leading: isSelected ? const Icon(Icons.check, color: Colors.green) : const SizedBox(width: 24),
                              onTap: () => Navigator.of(context).pop((false, lang.locale)),
                            );
                          });
                        })(),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        );
        if (selected != null) {
          if (context.mounted) {
            if (selected.$1) {
              // useSystem is true
              context.resetLocale();
            } else if (selected.$2 != null) {
              context.setLocale(selected.$2!);
            }
          }
        }
      },
    );
  }
}
