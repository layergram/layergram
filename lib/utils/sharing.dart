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
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:share_plus/share_plus.dart';
import 'package:url_launcher/url_launcher.dart';

import '../core/crypto/stego_alphabet_v2.dart';
import '../core/providers.dart';
import '../l10n/app_strings.dart';
import 'app_platform.dart';
import 'sharing_android.dart' show AndroidShareApp, AndroidAppSelectorDialog;

export 'sharing_io.dart' if (dart.library.html) 'sharing_stub.dart';

/// Returns true if the text contains zero-width characters used for
/// Layergram steganographic encoding.
bool _containsSteganography(String text) {
  final runes = text.runes;
  // Check for both v1 and v2 payload alphabets
  for (final rune in runes) {
    if (StegoAlphabetV2.payloadRuneToValue.containsKey(rune) ||
        StegoAlphabetV2.noiseRunesSet.contains(rune) ||
        _isV1PayloadRune(rune)) {
      return true;
    }
  }
  return false;
}

/// Checks if a rune is from LMF v1 payload alphabet.
bool _isV1PayloadRune(int rune) {
  // LMF v1 payload alphabet: U+200B, U+200C, U+200D, U+2060
  return rune == 0x200B || rune == 0x200C || rune == 0x200D || rune == 0x2060;
}

Rect? sharePositionOriginForContext(BuildContext context) {
  final renderObject = context.findRenderObject();
  if (renderObject is! RenderBox || !renderObject.hasSize) {
    return null;
  }
  return renderObject.localToGlobal(Offset.zero) & renderObject.size;
}

bool isWhatsAppShareActivityType(String rawActivityType) {
  final normalized = rawActivityType.trim().toLowerCase();
  return normalized.isNotEmpty && normalized.contains('whatsapp');
}

/// Shares text externally.
///
/// When [forceStegoCover] is explicitly set to true, or when the text
/// contains steganographic zero-width characters, on Android a custom app
/// selector is shown that blocks direct WhatsApp sharing to prevent
/// message truncation.
///
/// For deeplinks or plain text without steganography, the standard Android
/// share sheet is used directly.
Future<ShareResult> shareTextExternally(
  BuildContext context,
  String text, {
  bool forceStegoCover = false,
}) async {
  final container = ProviderScope.containerOf(context);
  container.read(isSharingProvider.notifier).state = true;

  // Auto-detect if text contains steganography
  final hasSteganography = _containsSteganography(text);
  // Deeplinks should always use standard share even if they contain zero-width chars
  // (they shouldn't, but if there's a bug we don't want to block link sharing)
  final isDeeplink = text.startsWith('layergram://');
  final shouldUseCustomSelector =
      !isDeeplink && (forceStegoCover || hasSteganography);

  // On Android, use custom share flow only for steganographic messages.
  // For deeplinks, use the standard share sheet.
  if (AppPlatform.isAndroid && context.mounted && shouldUseCustomSelector) {
    final result = await _shareTextAndroid(context, text);
    container.read(isSharingProvider.notifier).state = false;
    return result;
  }

  final result = await SharePlus.instance.share(
    ShareParams(
      text: text,
      sharePositionOrigin: sharePositionOriginForContext(context),
    ),
  );

  container.read(isSharingProvider.notifier).state = false;

  if (AppPlatform.isIOS &&
      result.status == ShareResultStatus.success &&
      isWhatsAppShareActivityType(result.raw)) {
    // On iOS, WhatsApp pre-fills the compose field correctly but we still
    // deep-link to bring the app to foreground after the share sheet closes.
    final whatsappUri = Uri.parse('whatsapp://');
    if (await canLaunchUrl(whatsappUri)) {
      await Future<void>.delayed(const Duration(milliseconds: 250));
      await launchUrl(
        whatsappUri,
        mode: LaunchMode.externalApplication,
      );
    }
  }

  return result;
}

Future<ShareResult> _shareTextAndroid(BuildContext context, String text) async {
  // Copy text to clipboard in case user wants to paste it
  await Clipboard.setData(ClipboardData(text: text));
  if (!context.mounted) {
    return const ShareResult('', ShareResultStatus.unavailable);
  }

  // Show app selector dialog
  final selectedApp = await showDialog<AndroidShareApp>(
    context: context,
    builder: (context) => AndroidAppSelectorDialog(text: text),
  );

  if (selectedApp == null) {
    // User cancelled
    return const ShareResult('', ShareResultStatus.dismissed);
  }

  if (selectedApp.isWhatsApp) {
    // For WhatsApp, show warning dialog instead of sharing directly
    if (context.mounted) {
      await _showWhatsAppAndroidDialog(context);
    }
    return const ShareResult('whatsapp', ShareResultStatus.success);
  }

  if (selectedApp.isStandardShare) {
    // For "Other apps", launch the standard Android share sheet
    return SharePlus.instance.share(
      ShareParams(
        text: text,
      ),
    );
  }

  // For other apps, share directly
  return selectedApp.share(text);
}

Future<void> _showWhatsAppAndroidDialog(BuildContext context) async {
  if (!context.mounted) return;

  final openWhatsApp = await showDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (dialogContext) => AlertDialog(
      title:
          Text(AppStrings.t(dialogContext, 'shareAndroidWhatsAppDialogTitle')),
      content: Text(
          AppStrings.t(dialogContext, 'shareAndroidWhatsAppDialogContent')),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(dialogContext).pop(false),
          child: Text(
              AppStrings.t(dialogContext, 'shareAndroidWhatsAppDialogCancel')),
        ),
        TextButton(
          onPressed: () => Navigator.of(dialogContext).pop(true),
          child: Text(
              AppStrings.t(dialogContext, 'shareAndroidWhatsAppDialogOpen')),
        ),
      ],
    ),
  );

  if (openWhatsApp == true) {
    final whatsappUri = Uri.parse('whatsapp://send');
    if (await canLaunchUrl(whatsappUri)) {
      await launchUrl(
        whatsappUri,
        mode: LaunchMode.externalApplication,
      );
    }
  }
}
