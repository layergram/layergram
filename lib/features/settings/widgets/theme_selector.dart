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
import '../../../l10n/app_strings.dart';

class ThemeSelector extends ConsumerWidget {
  const ThemeSelector({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;
    final themeMode = ref.watch(themeModeProvider);
    
    String themeLabel() {
      switch (themeMode) {
        case ThemeMode.light:
          return t(context, 'light');
        case ThemeMode.dark:
          return t(context, 'dark');
        case ThemeMode.system:
          return t(context, 'system');
      }
    }

    return ListTile(
      title: Text(t(context, 'theme')),
      subtitle: Text(themeLabel()),
      leading: const Icon(Icons.palette_outlined),
      onTap: () async {
        final selected = await showModalBottomSheet<ThemeMode>(
          context: context,
          builder: (context) => SafeArea(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                ListTile(title: Text(t(context, 'chooseTheme'))),
                ListTile(
                  title: Text(t(context, 'system')),
                  onTap: () => Navigator.of(context).pop(ThemeMode.system),
                ),
                ListTile(
                  title: Text(t(context, 'light')),
                  onTap: () => Navigator.of(context).pop(ThemeMode.light),
                ),
                ListTile(
                  title: Text(t(context, 'dark')),
                  onTap: () => Navigator.of(context).pop(ThemeMode.dark),
                ),
              ],
            ),
          ),
        );
        if (selected != null) {
          ref.read(themeModeProvider.notifier).state = selected;
        }
      },
    );
  }
}
