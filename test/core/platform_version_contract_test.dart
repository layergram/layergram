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

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Layergram 2.0 version and iOS share extension stay synchronized', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    expect(pubspec, contains('version: 2.0.0+27'));

    final project = File(
      'ios/Runner.xcodeproj/project.pbxproj',
    ).readAsStringSync();
    expect(
      'CURRENT_PROJECT_VERSION = "\$(FLUTTER_BUILD_NUMBER)";'
          .allMatches(project),
      hasLength(7),
    );
    expect(
      'MARKETING_VERSION = "\$(FLUTTER_BUILD_NAME)";'.allMatches(project),
      hasLength(3),
    );
    expect(project, isNot(contains('MARKETING_VERSION = 1.0.4;')));

    final extensionInfo = File(
      'ios/Share Extension/Info.plist',
    ).readAsStringSync();
    expect(extensionInfo, contains('<string>\$(FLUTTER_BUILD_NAME)</string>'));
    expect(
      extensionInfo,
      contains('<string>\$(FLUTTER_BUILD_NUMBER)</string>'),
    );
  });
}
