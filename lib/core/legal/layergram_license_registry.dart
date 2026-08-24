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

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Adds licenses for code that is compiled outside Dart's package graph.
///
/// Flutter automatically exposes licenses for Dart and Flutter packages. The
/// application and its vendored native ML-KEM implementation need explicit
/// entries so their notices remain available in every binary distribution.
abstract final class LayergramLicenseRegistry {
  static bool _registered = false;

  static void register() {
    if (_registered) return;
    _registered = true;
    LicenseRegistry.addLicense(loadEntries);
  }

  @visibleForTesting
  static Stream<LicenseEntry> loadEntries({AssetBundle? bundle}) async* {
    final assetBundle = bundle ?? rootBundle;
    final layergramLicense = await assetBundle.loadString('LICENSE');
    final mlKemLicense =
        await assetBundle.loadString('third_party/mlkem-native/LICENSE');

    yield LicenseEntryWithLineBreaks(
      const <String>['Layergram'],
      layergramLicense,
    );
    yield LicenseEntryWithLineBreaks(
      const <String>['mlkem-native'],
      mlKemLicense,
    );
  }
}
