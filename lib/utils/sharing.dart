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

import 'package:flutter/widgets.dart';
import 'package:share_plus/share_plus.dart';
import 'package:url_launcher/url_launcher.dart';

import 'app_platform.dart';

export 'sharing_io.dart' if (dart.library.html) 'sharing_stub.dart';

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

Future<ShareResult> shareTextExternally(
  BuildContext context,
  String text,
) async {
  final result = await SharePlus.instance.share(
    ShareParams(
      text: text,
      sharePositionOrigin: sharePositionOriginForContext(context),
    ),
  );

  if (AppPlatform.isIOS &&
      result.status == ShareResultStatus.success &&
      isWhatsAppShareActivityType(result.raw)) {
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
