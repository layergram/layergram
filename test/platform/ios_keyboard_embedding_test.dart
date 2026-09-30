import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  late Directory fixture;
  late Directory products;
  late Directory app;
  late Directory source;
  late Directory embedded;

  setUp(() {
    fixture = Directory.systemTemp.createTempSync('keyboard-archive-');
    products = Directory('${fixture.path}/empty archive products')
      ..createSync();
    app = Directory('${fixture.path}/target app')..createSync();
    source = Directory('${fixture.path}/separate build/LayergramKeyboard.appex')
      ..createSync(recursive: true);
    File('${source.path}/Info.plist').writeAsStringSync('<plist/>');
    File('${source.path}/LayergramKeyboard')
        .writeAsStringSync('built-extension');
    embedded = Directory('${app.path}/PlugIns/LayergramKeyboard.appex');
  });
  tearDown(() => fixture.deleteSync(recursive: true));

  ProcessResult embed({String? path, bool enabled = true}) => Process.runSync(
        '/bin/sh',
        ['ios/Runner/embed_system_keyboard.sh'],
        environment: {
          'TARGET_BUILD_DIR': app.path,
          'PLUGINS_FOLDER_PATH': 'PlugIns',
          'BUILT_PRODUCTS_DIR': products.path,
          'LAYERGRAM_KEYBOARD_EMBED': enabled ? 'YES' : 'NO',
          'LAYERGRAM_KEYBOARD_PRODUCT_PATH': path ?? '',
        },
      );

  test('archive embeds a separately built keyboard outside archive products',
      () {
    final result = embed(path: source.path);
    expect(result.exitCode, 0, reason: '${result.stderr}');
    expect(File('${embedded.path}/LayergramKeyboard').readAsStringSync(),
        'built-extension');
    expect(File('${source.path}/LayergramKeyboard').readAsStringSync(),
        'built-extension');
    expect(products.listSync(), isEmpty);
  }, skip: !Platform.isMacOS);

  test('ordinary keyboard build still uses its products directory', () {
    source.renameSync('${products.path}/LayergramKeyboard.appex');
    final result = embed();
    expect(result.exitCode, 0, reason: '${result.stderr}');
    expect(File('${embedded.path}/LayergramKeyboard').readAsStringSync(),
        'built-extension');
  }, skip: !Platform.isMacOS);

  test('disabled embedding removes an old keyboard and missing source fails',
      () {
    expect(embed(path: source.path).exitCode, 0);
    final missing = embed(path: '${fixture.path}/not-built.appex');
    expect(missing.exitCode, isNot(0));
    expect(missing.stderr, contains('Build the LayergramKeyboard scheme'));
    expect(embedded.existsSync(), isTrue);
    final disabled = embed(enabled: false);
    expect(disabled.exitCode, 0, reason: '${disabled.stderr}');
    expect(embedded.existsSync(), isFalse);
  }, skip: !Platform.isMacOS);
}
