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
  test('public tree excludes private release and local operational markers',
      () async {
    final listed = await Process.run(
      'git',
      const ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
      runInShell: false,
    );
    expect(listed.exitCode, 0, reason: listed.stderr.toString());

    final paths = listed.stdout
        .toString()
        .split('\u0000')
        .where((path) => path.isNotEmpty && _isAuditedText(path));
    final findings = <String>[];
    for (final path in paths) {
      final file = File(path);
      if (!file.existsSync()) continue;
      final text = file.readAsStringSync();
      for (final marker in _forbiddenMarkers) {
        if (path.contains(marker) || text.contains(marker)) {
          findings.add('$path: ${_redactedLabel(marker)}');
        }
      }
    }

    expect(
      findings,
      isEmpty,
      reason: 'Public release disclosure audit failed:\n${findings.join('\n')}',
    );
  });
}

final _forbiddenMarkers = <String>[
  'layergram-' 'premium',
  'lib/' 'private/' 'main_' 'private.dart',
  'FORCE_' 'PREMIUM_' 'UNLOCK_ON_STARTUP',
  'Rei' 'Phone',
  '/Users/' 'simone',
  r'C:\Users\' 'simone',
  'Premium ' 'validation build',
  'smoke test has ' 'passed as described above',
];

String _redactedLabel(String marker) =>
    'forbidden marker ${marker.codeUnits.fold<int>(0, (sum, unit) => sum + unit)}';

bool _isAuditedText(String path) {
  const extensions = <String>{
    '.cmd',
    '.dart',
    '.entitlements',
    '.gradle',
    '.java',
    '.json',
    '.kt',
    '.kts',
    '.lock',
    '.md',
    '.pbxproj',
    '.plist',
    '.properties',
    '.ps1',
    '.py',
    '.sh',
    '.swift',
    '.toml',
    '.txt',
    '.xcconfig',
    '.xml',
    '.yaml',
    '.yml',
  };
  final dot = path.lastIndexOf('.');
  return dot >= 0 && extensions.contains(path.substring(dot));
}
