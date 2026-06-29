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

import '../l10n/app_strings.dart';

Future<bool> showMaximumFsSetupDialog(
  BuildContext context, {
  required bool incoming,
}) async {
  final result = await showDialog<bool>(
    context: context,
    barrierDismissible: incoming,
    builder: (context) {
      final t = AppStrings.t;
      return AlertDialog(
        title: Text(t(context, 'security.fs.maximum.setup_title')),
        content: Text(
          t(
            context,
            incoming
                ? 'security.fs.maximum.setup_incoming_body'
                : 'security.fs.maximum.setup_outgoing_body',
          ),
        ),
        actions: [
          if (!incoming)
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: Text(t(context, 'security.fs.maximum.cancel_button')),
            ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(
              t(
                context,
                incoming
                    ? 'security.fs.maximum.setup_ack_button'
                    : 'security.fs.maximum.setup_send_button',
              ),
            ),
          ),
        ],
      );
    },
  );

  return result ?? false;
}
