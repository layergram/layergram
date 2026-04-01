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

import 'package:easy_localization/easy_localization.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

// Legacy provider, keeping it so imports don't break immediately
final localeProvider = StateProvider<Locale?>((_) => null);

class AppStrings {
  static final Map<String, Map<String, String>> _registeredStrings =
      <String, Map<String, String>>{};

  static const supportedLocales = [
    Locale('en'),
    Locale('it'),
    Locale('es'),
    Locale('pt'),
    Locale('ru'),
    Locale('id'),
    Locale('ar'),
    Locale('fr'),
    Locale('de'),
    Locale('hi'),
    Locale('nl'),
    Locale('fa'),
    Locale('ro'),
    Locale('pl'),
    Locale('zh'),
    Locale('tr'),
    Locale('ja'),
    Locale('ko'),
    Locale('vi'),
    Locale('th'),
    Locale('el'),
    Locale('bn'),
    Locale('mr'),
    Locale('ur'),
    Locale('fi'),
    Locale('no'),
    Locale('sv'),
    Locale('uk'),
    Locale('pt', 'PT'),
    Locale('sq'),
    Locale('ca'),
    Locale('sw'),
    Locale('ha'),
    Locale('tl'),
    Locale('ms'),
    Locale('ta'),
    Locale('te'),
    Locale('gu'),
    Locale('kn'),
    Locale('pa'),
    Locale('am'),
    Locale('yo')
  ];

  static void registerStrings(Map<String, Map<String, String>> bundle) {
    final enBundle = bundle['en'] ?? const <String, String>{};
    final existingEn = _registeredStrings['en'] ?? const <String, String>{};

    for (final entry in bundle.entries) {
      if (entry.key == 'en') continue;
      for (final key in entry.value.keys) {
        if (!enBundle.containsKey(key) && !existingEn.containsKey(key)) {
          throw ArgumentError('Missing en fallback for key: $key');
        }
      }
    }

    for (final entry in bundle.entries) {
      final normalized = _normalizeLocaleKey(entry.key);
      final target =
          _registeredStrings.putIfAbsent(normalized, () => <String, String>{});
      target.addAll(entry.value);
    }
  }

  static String t(BuildContext context, String key,
      {Map<String, String>? namedArgs}) {
    final locale = Localizations.maybeLocaleOf(context);
    final registered = _registeredValue(locale, key);
    if (registered != null) {
      return _applyNamedArgs(registered, namedArgs);
    }

    try {
      return key.tr(context: context, namedArgs: namedArgs);
    } catch (_) {
      final fallback = (_registeredStrings['en'] ?? const <String, String>{})[key];
      return _applyNamedArgs(fallback ?? key, namedArgs);
    }
  }

  static String? _registeredValue(Locale? locale, String key) {
    if (locale == null) {
      return (_registeredStrings['en'] ?? const <String, String>{})[key];
    }

    final language = locale.languageCode;
    final country = locale.countryCode;
    if (country != null && country.isNotEmpty) {
      final full = '${language}_$country';
      final value = (_registeredStrings[full] ?? const <String, String>{})[key];
      if (value != null) return value;
    }

    final languageValue =
        (_registeredStrings[language] ?? const <String, String>{})[key];
    if (languageValue != null) return languageValue;

    return (_registeredStrings['en'] ?? const <String, String>{})[key];
  }

  static String _normalizeLocaleKey(String value) {
    return value.replaceAll('-', '_');
  }

  static String _applyNamedArgs(
    String value,
    Map<String, String>? namedArgs,
  ) {
    if (namedArgs == null || namedArgs.isEmpty) return value;
    var out = value;
    for (final entry in namedArgs.entries) {
      out = out.replaceAll('{${entry.key}}', entry.value);
    }
    return out;
  }
}
