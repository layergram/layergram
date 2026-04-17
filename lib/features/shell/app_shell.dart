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

import '../../core/capabilities/chat_folders_capability.dart';
import '../../core/providers.dart';
import '../../l10n/app_strings.dart';
import '../home/home_view.dart';
import '../identities/identities_list_view.dart';
import '../my_identity/my_identity_view.dart';
import '../settings/settings_view.dart';

class AppShell extends ConsumerStatefulWidget {
  const AppShell({super.key});

  @override
  ConsumerState<AppShell> createState() => _AppShellState();
}

class _AppShellState extends ConsumerState<AppShell> {
  int _index = 0;
  final GlobalKey _switcherKey = GlobalKey(debugLabel: 'app_shell_switcher');

  @override
  void initState() {
    super.initState();
    // Check if there's an initial index set from onboarding
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final initialIndex = ref.read(appShellInitialIndexProvider);
      if (initialIndex != null) {
        setState(() => _index = initialIndex);
        // Clear the provider after using it
        ref.read(appShellInitialIndexProvider.notifier).state = null;
      }
    });
  }

  void _selectIndex(int index, List<_ShellItem> items) {
    final target = items[index];
    if (target.chatFolderId != null) {
      ref.read(selectedChatFolderIdProvider.notifier).state =
          target.chatFolderId!;
    }
    setState(() => _index = index);
  }

  Widget _activeView(List<_ShellItem> items) {
    final effectiveIndex =
        _index.clamp(0, items.isEmpty ? 0 : (items.length - 1));
    return AnimatedSwitcher(
      key: _switcherKey,
      duration: const Duration(milliseconds: 280),
      switchInCurve: Curves.easeOutCubic,
      switchOutCurve: Curves.easeInCubic,
      transitionBuilder: (child, animation) {
        return FadeTransition(opacity: animation, child: child);
      },
      // Use viewKey so switching between folders keeps the same HomeView state.
      child: KeyedSubtree(
        key: ValueKey(items[effectiveIndex].viewKey),
        child: items[effectiveIndex].view,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    // Aggiungi context.locale per forzare il rebuild della navigation bar quando cambia la lingua
    Localizations.maybeLocaleOf(context);
    final caps = ref.watch(layergramCapabilitiesProvider);
    final extraFolders = caps.chatFolders.isAvailable
        ? (ref.watch(chatFoldersProvider).valueOrNull ?? const [])
        : const <ChatFolder>[];

    final items = [
      _ShellItem(
        AppStrings.t(context, 'home'),
        const Icon(Icons.chat_bubble_outline),
        const HomeView(),
        viewKey: 'home',
        chatFolderId: kAllChatsFolderId,
      ),
      for (final folder in extraFolders)
        _ShellItem(
          folder.label,
          const Icon(Icons.folder_outlined),
          const HomeView(),
          viewKey: 'home',
          chatFolderId: folder.id,
        ),
      _ShellItem(AppStrings.t(context, 'identities'),
          const Icon(Icons.people_alt_outlined), const IdentitiesListView(),
          viewKey: 'identities'),
      _ShellItem(AppStrings.t(context, 'myIdentity'),
          const Icon(Icons.qr_code_2_outlined), const MyIdentityView(),
          viewKey: 'myIdentity'),
      _ShellItem(AppStrings.t(context, 'settings'),
          const Icon(Icons.settings_outlined), const SettingsView(),
          viewKey: 'settings'),
    ];

    if (_index >= items.length) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) return;
        setState(() => _index = 0);
      });
    }

    final desktop = MediaQuery.of(context).size.width >= 900;
    if (desktop) {
      final topItems = [
        items[0], // Home (Messages)
        ...items.where((i) => i.chatFolderId != null && i.chatFolderId != kAllChatsFolderId) // Premium folders
      ];
      final bottomItems = items.where((i) => i.chatFolderId == null).toList(); // Identities, MyIdentity, Settings

      final railSelectedIndex = _index < topItems.length ? _index : -1;
      final railTheme = NavigationRailTheme.of(context);
      final unselectedLabelStyle = railTheme.unselectedLabelTextStyle ??
          Theme.of(context).textTheme.labelMedium;

      return Scaffold(
        body: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              width: 120,
              color: Colors.transparent,
              child: SafeArea(
                minimum: const EdgeInsets.fromLTRB(0, 28, 0, 8),
                child: Column(
                  children: [
                    Expanded(
                      child: LayoutBuilder(
                        builder: (context, constraints) {
                          return SingleChildScrollView(
                            child: ConstrainedBox(
                              constraints: BoxConstraints(
                                minHeight: constraints.maxHeight,
                              ),
                              child: IntrinsicHeight(
                                child: NavigationRailTheme(
                                  data: railTheme.copyWith(
                                    indicatorColor: railSelectedIndex == -1
                                        ? Colors.transparent
                                        : railTheme.indicatorColor,
                                  ),
                                  child: NavigationRail(
                                    backgroundColor: Colors.transparent,
                                    selectedIndex: railSelectedIndex == -1 ? null : railSelectedIndex,
                                    labelType: NavigationRailLabelType.all,
                                    onDestinationSelected: (i) => _selectIndex(items.indexOf(topItems[i]), items),
                                    destinations: [
                                      for (final item in topItems)
                                        NavigationRailDestination(
                                          icon: item.icon,
                                          label: Text(
                                            item.label,
                                            textAlign: TextAlign.center,
                                            softWrap: true,
                                            maxLines: 2,
                                            overflow: TextOverflow.ellipsis,
                                          ),
                                        ),
                                    ],
                                  ),
                                ),
                              ),
                            ),
                          );
                        }
                      ),
                    ),
                    Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        for (final item in bottomItems)
                          Padding(
                            padding: const EdgeInsets.only(bottom: 12),
                            child: InkWell(
                              borderRadius: BorderRadius.circular(28),
                              splashColor: Colors.transparent,
                              hoverColor: Colors.transparent,
                              highlightColor: Colors.transparent,
                              onTap: () => setState(() => _index = items.indexOf(item)),
                              child: Padding(
                                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                                child: Column(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                                      decoration: ShapeDecoration(
                                        color: _index == items.indexOf(item)
                                            ? (railTheme.indicatorColor ??
                                                Theme.of(context).colorScheme.primary.withAlpha(0x1F))
                                            : Colors.transparent,
                                        shape: railTheme.indicatorShape ?? const StadiumBorder(),
                                      ),
                                      child: Icon(
                                        item.icon.icon,
                                        color: _index == items.indexOf(item)
                                            ? (railTheme.selectedIconTheme?.color ??
                                                Theme.of(context).colorScheme.onSecondaryContainer)
                                            : (railTheme.unselectedIconTheme?.color ??
                                                Theme.of(context).iconTheme.color),
                                      ),
                                    ),
                                    const SizedBox(height: 4),
                                    Text(
                                      item.label,
                                      style: _index == items.indexOf(item)
                                          ? (railTheme.selectedLabelTextStyle ?? Theme.of(context).textTheme.labelMedium)
                                          : unselectedLabelStyle,
                                      textAlign: TextAlign.center,
                                      maxLines: 1,
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
            const VerticalDivider(
                width: 1, thickness: 1, color: Colors.white24),
            Expanded(
              child: Material(
                color: Colors.white.withValues(alpha: 0.04),
                child: _activeView(items),
              ),
            ),
          ],
        ),
      );
    }

    return Scaffold(
      body: SafeArea(
        minimum: const EdgeInsets.only(top: 28),
        child: _activeView(items),
      ),
      bottomNavigationBar: Padding(
        padding: const EdgeInsets.fromLTRB(10, 0, 10, 10),
        child: ClipPath(
          clipper: ShapeBorderClipper(
            shape: ContinuousRectangleBorder(borderRadius: BorderRadius.circular(56)),
          ),
          child: TooltipVisibility(
            visible: false,
            child: NavigationBar(
              selectedIndex: _index,
              onDestinationSelected: (i) => _selectIndex(i, items),
              destinations: [
                for (final item in items)
                  NavigationDestination(
                    icon: item.icon,
                    label: item.label,
                    tooltip: null,
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _ShellItem {
  const _ShellItem(
    this.label,
    this.icon,
    this.view, {
    required this.viewKey,
    this.chatFolderId,
  });

  final String label;
  final Icon icon;
  final Widget view;

  /// Which logical section this destination belongs to.
  ///
  /// Multiple destinations can share the same [viewKey] (e.g. chat folders).
  final String viewKey;

  /// If set, selecting this destination updates the selected chat folder.
  final String? chatFolderId;
}
