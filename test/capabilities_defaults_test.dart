import 'package:flutter_test/flutter_test.dart';

import 'package:layergram/core/capabilities/backup_capability.dart';
import 'package:layergram/core/capabilities/chat_folders_capability.dart';
import 'package:layergram/core/capabilities/cover_message_generator_capability.dart';
import 'package:layergram/core/capabilities/identity_capability.dart';
import 'package:layergram/core/capabilities/layergram_capabilities.dart';
import 'package:layergram/core/capabilities/media_light_capability.dart';

void main() {
  test('LayergramCapabilities defaults to OSS stubs', () {
    const caps = LayergramCapabilities();

    expect(caps.identity, isA<NoIdentityCapability>());
    expect(caps.identity.isAvailable, isFalse);

    expect(caps.backup, isA<NoBackupCapability>());
    expect(caps.backup.isAvailable, isFalse);

    expect(caps.coverGenerator, isA<NoCoverMessageGeneratorCapability>());
    expect(caps.coverGenerator.isAvailable, isFalse);

    expect(caps.chatFolders, isA<NoChatFoldersCapability>());
    expect(caps.chatFolders.isAvailable, isFalse);

    expect(caps.mediaLight, isA<NoMediaLightCapability>());
    expect(caps.mediaLight.isAvailable, isFalse);
  });
}
