import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/providers.dart';
import 'package:layergram/core/storage/local_database.dart';

void main() {
  late Directory temporaryDirectory;

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    temporaryDirectory =
        await Directory.systemTemp.createTemp('layergram_provider_scope_');
    Hive.init(temporaryDirectory.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
  });

  tearDownAll(() async {
    await Hive.close();
    await temporaryDirectory.delete(recursive: true);
  });

  test('active identity changes immediately replace the message repository',
      () async {
    final container = ProviderContainer();
    addTearDown(container.dispose);

    container.read(activeIdentityIdProvider.notifier).state = 'identity-a';
    final identityARepository = container.read(messagesRepositoryProvider);

    container.read(activeIdentityIdProvider.notifier).state = 'identity-b';
    final identityBRepository = container.read(messagesRepositoryProvider);

    expect(identityBRepository, isNot(same(identityARepository)));
  });
}
