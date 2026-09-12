// Copyright 2026 Layergram
// SPDX-License-Identifier: Apache-2.0

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('documented Android source build matches the pinned CI build', () {
    final readme = File('README.md').readAsStringSync();
    final workflow = File(
      '.github/workflows/android-release-preflight.yml',
    ).readAsStringSync();
    final lockfile = File('pubspec.lock').readAsStringSync();

    expect(readme, contains('Flutter SDK 3.41.1'));
    expect(readme, contains('Dart SDK 3.11.0'));
    expect(readme, contains('Rust 1.87.0'));
    expect(
      readme,
      contains('tool/pq/prepare_scka_packaged_android.sh'),
    );
    expect(
      readme,
      contains('ORG_GRADLE_PROJECT_layergramSckaCandidatePackage=true'),
    );

    expect(lockfile, contains('dart: ">=3.11.0 <4.0.0"'));
    expect(lockfile, contains('flutter: ">=3.38.4"'));

    expect(workflow, contains('flutter-version: 3.41.1'));
    expect(workflow, contains('rustup toolchain install 1.87.0'));
    expect(
      workflow,
      contains('tool/pq/prepare_scka_packaged_android.sh'),
    );
    expect(
      workflow,
      contains('ORG_GRADLE_PROJECT_layergramSckaCandidatePackage: "true"'),
    );
    for (final abi in ['arm64-v8a', 'armeabi-v7a', 'x86_64']) {
      expect(workflow, contains(abi));
    }
  });
}
