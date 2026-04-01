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

import '../../core/capabilities/identity_capability.dart';
import '../../core/providers.dart';
import '../../l10n/app_strings.dart';

class MultiIdentityView extends ConsumerWidget {
  const MultiIdentityView({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = AppStrings.t;
    final caps = ref.watch(layergramCapabilitiesProvider);
    final identity = caps.identity;

    if (!identity.isAvailable) {
      return Scaffold(
        backgroundColor: Colors.transparent,
        appBar: AppBar(title: Text(t(context, 'premiumMultiIdentityTitle'))),
        body: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.lock_outline, size: 44),
              const SizedBox(height: 12),
              Text(
                t(context, 'premiumTag'),
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              Text(
                t(context, 'premiumNotAvailable'),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      );
    }

    return Scaffold(
      backgroundColor: Colors.transparent,
      appBar: AppBar(title: Text(t(context, 'premiumMultiIdentityTitle'))),
      body: StreamBuilder<List<IdentityProfile>>(
        stream: identity.watchLocalIdentities(),
        builder: (context, snapshot) {
          final items = snapshot.data ?? const <IdentityProfile>[];
          if (snapshot.connectionState != ConnectionState.active &&
              snapshot.connectionState != ConnectionState.done &&
              items.isEmpty) {
            return const Center(child: CircularProgressIndicator());
          }

          if (items.isEmpty) {
            return Center(child: Text(t(context, 'premiumNoLocalIdentities')));
          }

          return StreamBuilder<String?>(
            stream: identity.watchActiveIdentityId(),
            builder: (context, activeSnapshot) {
              final activeId = activeSnapshot.data;
              return ListView.separated(
                padding: const EdgeInsets.symmetric(vertical: 8),
                itemCount: items.length,
                separatorBuilder: (_, __) =>
                    const Divider(height: 1, thickness: 0.2),
                itemBuilder: (context, index) {
                  final it = items[index];
                  final isActive = activeId != null && it.identityId == activeId;
                  return ListTile(
                    leading: Icon(
                      isActive ? Icons.check_circle : Icons.person_outline,
                      color: isActive ? Colors.green : null,
                    ),
                    title: Text(it.displayName),
                    subtitle: it.fingerprint == null
                        ? null
                        : Text(it.fingerprint!, maxLines: 1),
                    trailing: isActive
                        ? Text(
                            t(context, 'active'),
                            style: Theme.of(context)
                                .textTheme
                                .labelMedium
                                ?.copyWith(color: Colors.green),
                          )
                        : const Icon(Icons.chevron_right),
                    onTap: isActive
                        ? null
                        : () async {
                            try {
                              await identity.setActiveIdentityId(it.identityId);
                              ref
                                  .read(activeIdentityIdProvider.notifier)
                                  .state = it.identityId;

                              if (context.mounted) {
                                ScaffoldMessenger.of(context).showSnackBar(
                                  SnackBar(
                                    content: Text(
                                      '${t(context, 'save')}: ${it.displayName}',
                                    ),
                                  ),
                                );
                              }
                            } catch (e) {
                              if (!context.mounted) return;
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(content: Text(e.toString())),
                              );
                            }
                          },
                  );
                },
              );
            },
          );
        },
      ),
    );
  }
}
