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
import '../../../l10n/app_strings.dart';

class ChangePinDialog {
  const ChangePinDialog({required this.currentPin});

  final String currentPin;

  Future<String?> show(BuildContext context) async {
    return _changePinDialog(context, currentPin);
  }

  Future<String?> _changePinDialog(BuildContext context, String currentPin) async {
    final t = AppStrings.t;
    // Step 1: Verify current PIN
    final currentPinController = TextEditingController();
    
    final verifyCurrentPin = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        void submitStep1() {
          if (currentPinController.text == currentPin) {
            Navigator.of(context).pop(true);
          } else {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text(t(context, 'pinMismatch'))),
            );
          }
        }

        return CallbackShortcuts(
          bindings: {
            const SingleActivator(LogicalKeyboardKey.escape): () => Navigator.of(context).pop(false),
          },
          child: AlertDialog(
            title: Text(t(context, 'changePin')),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: currentPinController,
                  obscureText: true,
                  keyboardType: TextInputType.number,
                  autofocus: true,
                  textInputAction: TextInputAction.done,
                  onSubmitted: (_) => submitStep1(),
                  decoration: InputDecoration(
                    labelText: t(context, 'enterCurrentPin'),
                  ),
                ),
              ],
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(context).pop(false),
                child: Text(t(context, 'cancel')),
              ),
              TextButton(
                onPressed: submitStep1,
                child: Text(t(context, 'confirm')),
              ),
            ],
          ),
        );
      },
    );
    
    if (verifyCurrentPin != true) return null;
    
    // Step 2: Enter new PIN
    if (!context.mounted) return null;
    
    String pin = '';
    String confirm = '';
    
    final newPin = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) => StatefulBuilder(
        builder: (context, setState) {
          void submitStep2() {
            if (pin.isEmpty || pin != confirm) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text(t(context, 'pinMismatch'))),
              );
              return;
            }
            Navigator.of(context).pop(pin);
          }

          return CallbackShortcuts(
            bindings: {
              const SingleActivator(LogicalKeyboardKey.escape): () => Navigator.of(context).pop(),
            },
            child: AlertDialog(
              title: Text(t(context, 'enterNewPin')),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextField(
                    autofocus: true,
                    obscureText: true,
                    keyboardType: TextInputType.number,
                    textInputAction: TextInputAction.next,
                    decoration: InputDecoration(labelText: t(context, 'newPin')),
                    onChanged: (v) => pin = v,
                    onSubmitted: (_) => FocusScope.of(context).nextFocus(),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    obscureText: true,
                    keyboardType: TextInputType.number,
                    textInputAction: TextInputAction.done,
                    decoration: InputDecoration(labelText: t(context, 'confirmPin')),
                    onChanged: (v) => confirm = v,
                    onSubmitted: (_) => submitStep2(),
                  ),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: Text(t(context, 'cancel')),
                ),
                TextButton(
                  onPressed: submitStep2,
                  child: Text(t(context, 'confirm')),
                ),
              ],
            ),
          );
        }
      ),
    );
    
    return newPin;
  }
}
