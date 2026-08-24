// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/models.dart';
import 'package:layergram/features/home/home_controller.dart';

void main() {
  test('an already-read incoming read-once message cannot be displayed again',
      () async {
    final container = ProviderContainer();
    addTearDown(container.dispose);

    const contact = RemoteIdentity(
      identityId: 'contact',
      publicKeyBase64: '',
      fingerprint: '',
      displayName: 'Contact',
    );
    const message = MessageRecord(
      id: 'read-once',
      senderId: 'contact',
      recipientId: 'local',
      direction: 'incoming',
      timestamp: 1,
      text: 'must remain unavailable',
      deleteAfterRead: true,
      readAt: 2,
    );

    final plaintext = await container
        .read(homeControllerProvider)
        .decryptForDisplay(message: message, contact: contact);

    expect(plaintext, isNull);
  });
}
