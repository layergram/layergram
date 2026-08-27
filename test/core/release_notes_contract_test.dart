// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('2.0.1 release metadata states the cross-platform export scope', () {
    final notes = File('.github/releases/v2.0.1+28.md').readAsStringSync();
    final changelog = File('CHANGELOG.md').readAsStringSync();

    expect(
      notes,
      startsWith(
        '# Layergram 2.0.1 — Copy and Share reliability across platforms',
      ),
    );
    expect(
      notes,
      contains(
        'shared export path used by macOS, Windows, Linux, Android, and iOS',
      ),
    );
    expect(notes, contains('production incident was reproduced on macOS'));
    expect(notes, contains('the correction itself is not\nmacOS-only'));

    final releaseSection = changelog.split('## [2.0.0+27]').first;
    expect(
      releaseSection,
      contains('copying and sharing across all supported platforms'),
    );
    expect(
      releaseSection,
      contains(
          'shared export path used by macOS, Windows, Linux, Android, and iOS'),
    );
    expect(
      releaseSection,
      isNot(contains('copying and sharing on macOS')),
    );
  });
}
