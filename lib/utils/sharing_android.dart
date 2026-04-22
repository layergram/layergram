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
import 'package:android_intent_plus/android_intent.dart';
import 'package:share_plus/share_plus.dart';

import '../l10n/app_strings.dart';
import 'app_platform.dart';

/// Represents an Android app that can receive text shares.
class AndroidShareApp {
  final String name;
  final String packageName;
  final IconData icon;
  final bool isWhatsApp;
  final bool isStandardShare;

  const AndroidShareApp({
    required this.name,
    required this.packageName,
    required this.icon,
    this.isWhatsApp = false,
    this.isStandardShare = false,
  });

  Future<ShareResult> share(String text) async {
    final result = await SharePlus.instance.share(
      ShareParams(
        text: text,
      ),
    );
    return result;
  }
}

/// Common Android messaging apps for text sharing.
/// This is a curated list of popular apps that users typically share to.
const List<AndroidShareApp> _kCommonShareApps = [
  AndroidShareApp(
    name: 'WhatsApp',
    packageName: 'com.whatsapp',
    icon: Icons.message,
    isWhatsApp: true,
  ),
  AndroidShareApp(
    name: 'Telegram',
    packageName: 'org.telegram.messenger',
    icon: Icons.send,
  ),
  AndroidShareApp(
    name: 'Signal',
    packageName: 'org.thoughtcrime.securesms',
    icon: Icons.security,
  ),
  AndroidShareApp(
    name: 'Gmail',
    packageName: 'com.google.android.gm',
    icon: Icons.email,
  ),
  AndroidShareApp(
    name: 'Messages',
    packageName: 'com.google.android.apps.messaging',
    icon: Icons.sms,
  ),
  AndroidShareApp(
    name: 'Copy to clipboard',
    packageName: 'clipboard',
    icon: Icons.content_copy,
  ),
  AndroidShareApp(
    name: 'Other apps',
    packageName: 'standard',
    icon: Icons.share,
    isStandardShare: true,
  ),
];

/// A dialog that shows a list of apps to share to on Android.
/// This replaces the system share sheet to allow us to intercept
/// WhatsApp sharing and show a warning instead.
class AndroidAppSelectorDialog extends StatefulWidget {
  final String text;

  const AndroidAppSelectorDialog({required this.text});

  @override
  State<AndroidAppSelectorDialog> createState() => _AndroidAppSelectorDialogState();
}

class _AndroidAppSelectorDialogState extends State<AndroidAppSelectorDialog> {
  late Future<List<AndroidShareApp>> _installedAppsFuture;

  @override
  void initState() {
    super.initState();
    _installedAppsFuture = _getInstalledApps();
  }

  Future<List<AndroidShareApp>> _getInstalledApps() async {
    if (!AppPlatform.isAndroid) {
      // On non-Android platforms, return all apps (for testing)
      return _kCommonShareApps.toList();
    }

    final List<AndroidShareApp> installedApps = [];

    for (final app in _kCommonShareApps) {
      if (app.packageName == 'clipboard' || app.packageName == 'standard') {
        // Always show clipboard and "Other apps" options
        installedApps.add(app);
      } else {
        // Check if the app is installed using action_view with the app's main activity
        // This is more reliable than action_send for checking package availability
        final canResolve = await _checkAppInstalled(app.packageName);
        if (canResolve) {
          installedApps.add(app);
        }
      }
    }

    // If no messaging apps detected (only clipboard + other apps), show all common apps
    // as fallback - better to show apps that might not be installed than to hide installed ones
    if (installedApps.length <= 2) {
      // Add all messaging apps as fallback (user will get "app not installed" if they tap)
      final installedPackageNames = installedApps.map((a) => a.packageName).toSet();
      for (final app in _kCommonShareApps) {
        if (app.packageName != 'clipboard' &&
            app.packageName != 'standard' &&
            !installedPackageNames.contains(app.packageName)) {
          installedApps.insert(installedApps.length - 2, app);
        }
      }
    }

    return installedApps;
  }

  /// Checks if an app is installed by attempting to resolve its main activity.
  /// Uses multiple strategies for better reliability across different Android versions.
  Future<bool> _checkAppInstalled(String packageName) async {
    try {
      // Strategy 1: Try to resolve the app's main launcher activity
      final launchIntent = AndroidIntent(
        action: 'action_main',
        package: packageName,
        category: 'category_launcher',
      );
      final canResolveLaunch = await launchIntent.canResolveActivity();
      if (canResolveLaunch ?? false) {
        return true;
      }
    } catch (e) {
      // Ignore and try next strategy
    }

    try {
      // Strategy 2: Try action_view with a generic URI
      final viewIntent = AndroidIntent(
        action: 'action_view',
        package: packageName,
        data: 'https://example.com',
      );
      final canResolveView = await viewIntent.canResolveActivity();
      if (canResolveView ?? false) {
        return true;
      }
    } catch (e) {
      // Ignore and try next strategy
    }

    try {
      // Strategy 3: Try action_send (original method as fallback)
      final sendIntent = AndroidIntent(
        action: 'action_send',
        package: packageName,
        type: 'text/plain',
      );
      final canResolveSend = await sendIntent.canResolveActivity();
      if (canResolveSend ?? false) {
        return true;
      }
    } catch (e) {
      // Ignore
    }

    return false;
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(AppStrings.t(context, 'shareAndroidDialogTitle')),
      content: SizedBox(
        width: double.maxFinite,
        child: FutureBuilder<List<AndroidShareApp>>(
          future: _installedAppsFuture,
          builder: (context, snapshot) {
            if (snapshot.connectionState == ConnectionState.waiting) {
              return const SizedBox(
                height: 100,
                child: Center(child: CircularProgressIndicator()),
              );
            }

            final apps = snapshot.data ?? [];
            if (apps.isEmpty) {
              // Fallback: show at least clipboard and other apps
              return ListView(
                shrinkWrap: true,
                children: [
                  ListTile(
                    leading: const Icon(Icons.content_copy),
                    title: Text(AppStrings.t(context, 'shareAppCopyToClipboard')),
                    onTap: () {
                      Navigator.of(context).pop(
                        const AndroidShareApp(
                          name: 'Copy to clipboard',
                          packageName: 'clipboard',
                          icon: Icons.content_copy,
                        ),
                      );
                    },
                  ),
                  ListTile(
                    leading: const Icon(Icons.share),
                    title: Text(AppStrings.t(context, 'shareAppOtherApps')),
                    onTap: () {
                      Navigator.of(context).pop(
                        const AndroidShareApp(
                          name: 'Other apps',
                          packageName: 'standard',
                          icon: Icons.share,
                          isStandardShare: true,
                        ),
                      );
                    },
                  ),
                ],
              );
            }

            return ListView.builder(
              shrinkWrap: true,
              itemCount: apps.length,
              itemBuilder: (context, index) {
                final app = apps[index];
                return ListTile(
                  leading: Icon(app.icon),
                  title: Text(AppStrings.t(context, _getTranslationKey(app.packageName))),
                  onTap: () {
                    Navigator.of(context).pop(app);
                  },
                );
              },
            );
          },
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(AppStrings.t(context, 'shareAndroidDialogCancel')),
        ),
      ],
    );
  }
}

/// Returns the translation key for a given app package name.
String _getTranslationKey(String packageName) {
  switch (packageName) {
    case 'com.whatsapp':
      return 'shareAppWhatsApp';
    case 'org.telegram.messenger':
      return 'shareAppTelegram';
    case 'org.thoughtcrime.securesms':
      return 'shareAppSignal';
    case 'com.google.android.gm':
      return 'shareAppGmail';
    case 'com.google.android.apps.messaging':
      return 'shareAppMessages';
    case 'clipboard':
      return 'shareAppCopyToClipboard';
    case 'standard':
      return 'shareAppOtherApps';
    default:
      return 'shareAppOtherApps';
  }
}
