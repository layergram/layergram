// Tests for FS control messages (FS Spec §9.2).
//
// Acceptance criteria:
//
//  T_CM_1  FsAckMessage serializes and deserializes correctly.
//  T_CM_2  FsAckMessage.computeAckTag produces correct HMAC.
//  T_CM_3  FsSimultaneousNoticeMessage serializes and deserializes correctly.
//  T_CM_4  FsSuspendMessage serializes and deserializes correctly.
//  T_CM_5  FsResetMessage serializes and deserializes correctly.
//  T_CM_6  FsDowngradeNoticeMessage serializes and deserializes correctly.
//  T_CM_7  All extension types are registered in FsExtensionType.all.
//  T_CM_8  Each message type has the correct 'type' field in JSON.
//  T_CM_9  FsAckMessage ackTag verification: valid tag matches.
//  T_CM_10 FsAckMessage ackTag verification: invalid tag does not match.

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_control_messages.dart';

void main() {
  // T_CM_1
  test('T_CM_1: FsAckMessage serializes and deserializes correctly', () {
    const msg = FsAckMessage(
      initId: 'init-AAA',
      replyId: 'reply-BBB',
      ackTag: 'ack-tag-base64url',
    );

    final json = msg.toJson();
    expect(json['v'], equals(1));
    expect(json['type'], equals('fs_ack'));
    expect(json['initId'], equals('init-AAA'));
    expect(json['replyId'], equals('reply-BBB'));
    expect(json['ackTag'], equals('ack-tag-base64url'));

    final restored = FsAckMessage.fromJson(json);
    expect(restored.initId, equals(msg.initId));
    expect(restored.replyId, equals(msg.replyId));
    expect(restored.ackTag, equals(msg.ackTag));
  });

  // T_CM_2
  test('T_CM_2: FsAckMessage.computeAckTag produces deterministic HMAC', () async {
    final confirmKey = Uint8List(32)..fillRange(0, 32, 0xAA);
    final th = Uint8List(32)..fillRange(0, 32, 0xBB);

    final tag1 = await FsAckMessage.computeAckTag(confirmKey, th);
    final tag2 = await FsAckMessage.computeAckTag(confirmKey, th);

    expect(tag1.length, equals(32));
    expect(tag1, equals(tag2));

    // Different key produces different tag.
    final otherKey = Uint8List(32)..fillRange(0, 32, 0xCC);
    final tag3 = await FsAckMessage.computeAckTag(otherKey, th);
    expect(tag3, isNot(equals(tag1)));
  });

  // T_CM_3
  test('T_CM_3: FsSimultaneousNoticeMessage serializes and deserializes correctly', () {
    const msg = FsSimultaneousNoticeMessage(
      winningInitId: 'aaaa',
      losingInitId: 'zzzz',
    );

    final json = msg.toJson();
    expect(json['type'], equals('fs_simultaneous_notice'));
    expect(json['winningInitId'], equals('aaaa'));
    expect(json['losingInitId'], equals('zzzz'));

    final restored = FsSimultaneousNoticeMessage.fromJson(json);
    expect(restored.winningInitId, equals(msg.winningInitId));
    expect(restored.losingInitId, equals(msg.losingInitId));
  });

  // T_CM_4
  test('T_CM_4: FsSuspendMessage serializes and deserializes correctly', () {
    const msg = FsSuspendMessage(
      sessionId: 'sess-123',
      reason: 'device_key_changed',
    );

    final json = msg.toJson();
    expect(json['type'], equals('fs_suspend'));
    expect(json['sessionId'], equals('sess-123'));
    expect(json['reason'], equals('device_key_changed'));

    final restored = FsSuspendMessage.fromJson(json);
    expect(restored.sessionId, equals(msg.sessionId));
    expect(restored.reason, equals(msg.reason));
  });

  // T_CM_5
  test('T_CM_5: FsResetMessage serializes and deserializes correctly', () {
    const msg = FsResetMessage(
      previousSessionId: 'old-sess-456',
      reason: 'identity_reset',
    );

    final json = msg.toJson();
    expect(json['type'], equals('fs_reset'));
    expect(json['previousSessionId'], equals('old-sess-456'));
    expect(json['reason'], equals('identity_reset'));

    final restored = FsResetMessage.fromJson(json);
    expect(restored.previousSessionId, equals(msg.previousSessionId));
    expect(restored.reason, equals(msg.reason));
  });

  // T_CM_6
  test('T_CM_6: FsDowngradeNoticeMessage serializes and deserializes correctly', () {
    const msg = FsDowngradeNoticeMessage(
      previousSessionId: 'sess-789',
      previousLevel: 'fs_only',
    );

    final json = msg.toJson();
    expect(json['type'], equals('fs_downgrade_notice'));
    expect(json['previousSessionId'], equals('sess-789'));
    expect(json['previousLevel'], equals('fs_only'));

    final restored = FsDowngradeNoticeMessage.fromJson(json);
    expect(restored.previousSessionId, equals(msg.previousSessionId));
    expect(restored.previousLevel, equals(msg.previousLevel));
  });

  // T_CM_7
  test('T_CM_7: all extension types are registered in FsExtensionType.all', () {
    expect(FsExtensionType.all, contains('fs_init'));
    expect(FsExtensionType.all, contains('fs_reply'));
    expect(FsExtensionType.all, contains('fs_confirm'));
    expect(FsExtensionType.all, contains('fs_ack'));
    expect(FsExtensionType.all, contains('fs_simultaneous_notice'));
    expect(FsExtensionType.all, contains('fs_suspend'));
    expect(FsExtensionType.all, contains('fs_reset'));
    expect(FsExtensionType.all, contains('fs_downgrade_notice'));
    expect(FsExtensionType.all.length, equals(8));
  });

  // T_CM_8
  test('T_CM_8: each message type has the correct type field in JSON', () {
    expect(
      const FsAckMessage(initId: '', replyId: '', ackTag: '').toJson()['type'],
      equals('fs_ack'),
    );
    expect(
      const FsSimultaneousNoticeMessage(winningInitId: '', losingInitId: '')
          .toJson()['type'],
      equals('fs_simultaneous_notice'),
    );
    expect(
      const FsSuspendMessage(sessionId: '', reason: '').toJson()['type'],
      equals('fs_suspend'),
    );
    expect(
      const FsResetMessage(previousSessionId: '', reason: '').toJson()['type'],
      equals('fs_reset'),
    );
    expect(
      const FsDowngradeNoticeMessage(previousSessionId: '', previousLevel: '')
          .toJson()['type'],
      equals('fs_downgrade_notice'),
    );
  });

  // T_CM_9
  test('T_CM_9: FsAckMessage ackTag verification — valid tag matches', () async {
    final confirmKey = Uint8List(32)..fillRange(0, 32, 0x42);
    final th = Uint8List(32)..fillRange(0, 32, 0x43);

    final expectedTag = await FsAckMessage.computeAckTag(confirmKey, th);

    // Verify manually using the same HMAC.
    final hmac = Hmac.sha256();
    final data = Uint8List.fromList([
      ...th,
      ...'B acknowledges'.codeUnits,
    ]);
    final mac = await hmac.calculateMac(
      data,
      secretKey: SecretKey(confirmKey),
    );
    expect(expectedTag, equals(Uint8List.fromList(mac.bytes)));
  });

  // T_CM_10
  test('T_CM_10: FsAckMessage ackTag verification — invalid tag does not match', () async {
    final confirmKey = Uint8List(32)..fillRange(0, 32, 0x42);
    final th = Uint8List(32)..fillRange(0, 32, 0x43);

    final validTag = await FsAckMessage.computeAckTag(confirmKey, th);

    // Compute with different key — should not match.
    final wrongKey = Uint8List(32)..fillRange(0, 32, 0xFF);
    final wrongTag = await FsAckMessage.computeAckTag(wrongKey, th);

    expect(wrongTag, isNot(equals(validTag)));
  });
}
