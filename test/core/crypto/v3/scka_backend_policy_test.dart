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

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('SCKA candidate receipt excludes AGPL code from the Premium base', () {
    final receipt = jsonDecode(
      File('tool/pq/scka_native_candidate.json').readAsStringSync(),
    ) as Map<String, dynamic>;

    expect(
      receipt['status'],
      'implementation-path-selected-not-production-approved',
    );

    final reference =
        receipt['referenceImplementation'] as Map<String, dynamic>;
    expect(reference['license'], 'AGPL-3.0-only');
    expect(reference['decision'], 'rejected-for-linking-or-embedding');

    final selected =
        receipt['selectedImplementationPath'] as Map<String, dynamic>;
    expect(selected['license'], 'Apache-2.0');
    expect(selected['productionRegistered'], isFalse);

    final primitive =
        receipt['incrementalMlKemPrimitiveCandidate'] as Map<String, dynamic>;
    expect(primitive['crate'], 'libcrux-ml-kem');
    expect(primitive['version'], '0.0.10');
    expect(primitive['license'], 'Apache-2.0');
    expect(primitive['engineeringLicenseGate'], 'pass-candidate-only');
    final dependencyLicenses =
        primitive['runtimeOrBuildDependencyLicenses'] as List<dynamic>;
    for (final license in dependencyLicenses.cast<String>()) {
      expect(license, isNot(contains('AGPL')));
      expect(license, isNot(contains('LGPL')));
      expect(license, isNot(matches(RegExp(r'(^|[^A])GPL'))));
    }

    final effects = receipt['checkpointEffects'] as Map<String, dynamic>;
    expect(effects['thirdPartyCodeImported'], isFalse);
    expect(effects['runtimeDependencyAdded'], isFalse);
    expect(effects['pubspecChanged'], isFalse);
    expect(effects['protocolV3Activated'], isFalse);
  });
}
