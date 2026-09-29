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
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/theme/app_theme.dart';

void main() {
  test('snackbar feedback stays legible in both app themes', () {
    for (final theme in [AppTheme.light(), AppTheme.dark()]) {
      final snackBar = theme.snackBarTheme;
      expect(snackBar.contentTextStyle?.color, Colors.white);
      expect(snackBar.backgroundColor, isNotNull);
    }
  });

  test('iOS keyboard dark controls match the app filled button palette', () {
    // The native keyboard test pins the same two colors. If the app palette
    // changes, update its native counterpart at the same time.
    final style = AppTheme.dark().filledButtonTheme.style!;
    expect(style.backgroundColor!.resolve(<WidgetState>{}),
        const Color(0xFF9ACBFA));
    expect(style.foregroundColor!.resolve(<WidgetState>{}),
        const Color(0xFF003352));
  });
}
