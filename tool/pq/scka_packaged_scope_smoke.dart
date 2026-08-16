import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:hive/hive.dart';
import 'package:layergram/core/crypto/v3/session_persistence_scope_v3.dart';
import 'package:layergram/core/storage/local_database.dart';

Future<void> main() async {
  Directory? temporaryDirectory;
  SecretKeyData? auxiliaryKey;
  V3SessionPersistenceScope? scope;
  try {
    temporaryDirectory =
        await Directory.systemTemp.createTemp('layergram_scka_packaged_');
    Hive.init(temporaryDirectory.path);
    await Hive.openBox<Map>(LocalDatabase.messagesBoxName);
    auxiliaryKey = SecretKeyData(
      Uint8List.fromList(List<int>.generate(32, (index) => index + 1)),
    );
    scope = await V3SessionPersistenceScope.openPackagedScka(
      scopeToken: 'packaged-scka-01',
      auxStorageKey: auxiliaryKey,
    );
    final restored = await scope.restore(checkpoints: const []);
    if (restored.inbox.deferredFrames != 0 ||
        restored.sessions.sessionRevisions.isNotEmpty ||
        scope.requiresRecovery) {
      throw StateError('Packaged SCKA scope did not restore empty state');
    }
    const marker = 'LAYERGRAM_SCKA_PACKAGED_SCOPE_OK';
    final markerPath = Platform.environment['LAYERGRAM_SCKA_PACKAGED_MARKER'];
    if (markerPath != null && markerPath.isNotEmpty) {
      await File(markerPath).writeAsString('$marker\n', flush: true);
    }
    // Flutter routes print through the Android engine log. Direct stdout is
    // retained by desktop runners but is not observable through Android ADB.
    // ignore: avoid_print
    print(marker);
  } catch (error, stackTrace) {
    stderr.writeln(error);
    stderr.writeln(stackTrace);
    exitCode = 1;
  } finally {
    await scope?.close();
    auxiliaryKey?.destroy();
    await Hive.close();
    if (temporaryDirectory != null && temporaryDirectory.existsSync()) {
      await temporaryDirectory.delete(recursive: true);
    }
  }
  exit(exitCode);
}
