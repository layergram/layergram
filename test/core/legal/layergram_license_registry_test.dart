import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/legal/layergram_license_registry.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('native and application license assets are complete and loadable',
      () async {
    final entries = await LayergramLicenseRegistry.loadEntries().toList();

    expect(entries, hasLength(2));
    expect(entries[0].packages, orderedEquals(const <String>['Layergram']));
    expect(entries[1].packages, orderedEquals(const <String>['mlkem-native']));

    final layergramText =
        entries[0].paragraphs.map((paragraph) => paragraph.text).join('\n');
    final mlKemText =
        entries[1].paragraphs.map((paragraph) => paragraph.text).join('\n');
    expect(
      layergramText,
      contains('Apache License'),
    );
    expect(
      mlKemText,
      contains('mlkem-native is a fork'),
    );
  });

  test('application startup registers the additional license source', () {
    final mainSource = File('lib/main.dart').readAsStringSync();
    expect(
      mainSource,
      contains('LayergramLicenseRegistry.register();'),
    );
  });

  test('registration exposes both entries through the Flutter registry',
      () async {
    LayergramLicenseRegistry.register();
    final entries = await LicenseRegistry.licenses.toList();
    final packages = entries.expand((entry) => entry.packages).toSet();

    expect(packages, containsAll(const <String>['Layergram', 'mlkem-native']));
  });
}
