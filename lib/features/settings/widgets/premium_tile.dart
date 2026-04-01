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
import '../../../l10n/app_strings.dart';

class PremiumTile extends ConsumerWidget {
  const PremiumTile({
    super.key,
    required this.isAvailable,
    required this.icon,
    required this.titleKey,
    required this.subtitleKey,
    required this.onTap,
  });

  final bool isAvailable;
  final IconData icon;
  final String titleKey;
  final String subtitleKey;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;
    
    return ListTile(
      enabled: isAvailable,
      leading: Icon(icon),
      title: Text(t(context, titleKey)),
      subtitle: Text(
        isAvailable ? t(context, subtitleKey) : t(context, 'premiumTag'),
      ),
      trailing: Icon(isAvailable ? Icons.chevron_right : Icons.lock_outline),
      onTap: isAvailable ? onTap : null,
    );
  }
}
