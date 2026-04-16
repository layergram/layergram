import 'package:flutter/material.dart';

import '../../l10n/app_strings.dart';

enum IdentityMigrationNoticeAction {
  remindLater,
  understand,
}

Future<IdentityMigrationNoticeAction?> showIdentityMigrationNoticeDialog(
  BuildContext context,
) {
  final t = AppStrings.t;
  return showDialog<IdentityMigrationNoticeAction>(
    context: context,
    barrierDismissible: false,
    builder: (dialogContext) {
      return PopScope(
        canPop: false,
        child: AlertDialog(
          title: Text(t(dialogContext, 'legacyIdentityNoticeTitle')),
          content: Text(t(dialogContext, 'legacyIdentityNoticeBody')),
          actions: [
            TextButton(
              onPressed: () {
                Navigator.of(dialogContext).pop(
                  IdentityMigrationNoticeAction.remindLater,
                );
              },
              child: Text(t(dialogContext, 'legacyIdentityNoticeRemindLater')),
            ),
            FilledButton(
              onPressed: () {
                Navigator.of(dialogContext).pop(
                  IdentityMigrationNoticeAction.understand,
                );
              },
              child: Text(t(dialogContext, 'legacyIdentityNoticeUnderstand')),
            ),
          ],
        ),
      );
    },
  );
}
