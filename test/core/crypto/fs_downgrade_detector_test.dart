// Tests for FsDowngradeDetector (FS Spec §7.6).
//
// Acceptance criteria:
//
//  T_DD_1  Initial highest level for unknown contact is legacy.
//  T_DD_2  recordSecurityLevel advances the highest level.
//  T_DD_3  recordSecurityLevel never regresses the highest level.
//  T_DD_4  evaluate detects downgrade from fsOnly to legacy.
//  T_DD_5  evaluate detects downgrade from fsWithFallback to legacy.
//  T_DD_6  evaluate returns no downgrade when level is equal or higher.
//  T_DD_7  Opportunistic mode → acceptWithWarning on downgrade.
//  T_DD_8  Strict mode → reject on downgrade.
//  T_DD_9  clearContact removes tracking for a specific contact.
//  T_DD_10 clearAll removes all tracking.
//  T_DD_11 Serialization round-trip preserves state.
//  T_DD_12 Different contacts have independent tracking.
//  T_DD_13 Different identity contexts have independent tracking.

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_downgrade_detector.dart';
import 'package:layergram/core/crypto/fs_message_classification.dart';
import 'package:layergram/core/crypto/fs_session_manager.dart';

void main() {
  // T_DD_1
  test('T_DD_1: initial highest level for unknown contact is legacy', () {
    final detector = FsDowngradeDetector();
    expect(
      detector.highestLevel(contactId: 'alice', identityContext: 'primary'),
      equals(FsMessageSecurity.legacy),
    );
  });

  // T_DD_2
  test('T_DD_2: recordSecurityLevel advances highest level', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsWithFallback,
    );
    expect(
      detector.highestLevel(contactId: 'alice', identityContext: 'primary'),
      equals(FsMessageSecurity.fsWithFallback),
    );

    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsOnly,
    );
    expect(
      detector.highestLevel(contactId: 'alice', identityContext: 'primary'),
      equals(FsMessageSecurity.fsOnly),
    );
  });

  // T_DD_3
  test('T_DD_3: recordSecurityLevel never regresses highest level', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsOnly,
    );
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.legacy,
    );
    expect(
      detector.highestLevel(contactId: 'alice', identityContext: 'primary'),
      equals(FsMessageSecurity.fsOnly),
    );
  });

  // T_DD_4
  test('T_DD_4: evaluate detects downgrade from fsOnly to legacy', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsOnly,
    );

    final result = detector.evaluate(
      contactId: 'alice',
      identityContext: 'primary',
      incomingLevel: FsMessageSecurity.legacy,
      sessionState: FsSessionState.fsActive,
    );
    expect(result.isDowngrade, isTrue);
    expect(result.previousLevel, equals(FsMessageSecurity.fsOnly));
    expect(result.currentLevel, equals(FsMessageSecurity.legacy));
  });

  // T_DD_5
  test('T_DD_5: evaluate detects downgrade from fsWithFallback to legacy', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsWithFallback,
    );

    final result = detector.evaluate(
      contactId: 'alice',
      identityContext: 'primary',
      incomingLevel: FsMessageSecurity.legacy,
      sessionState: FsSessionState.fsActive,
    );
    expect(result.isDowngrade, isTrue);
  });

  // T_DD_6
  test('T_DD_6: evaluate returns no downgrade when level is equal or higher', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsWithFallback,
    );

    final same = detector.evaluate(
      contactId: 'alice',
      identityContext: 'primary',
      incomingLevel: FsMessageSecurity.fsWithFallback,
      sessionState: FsSessionState.fsActive,
    );
    expect(same.isDowngrade, isFalse);
    expect(same.action, equals(FsDowngradeAction.accept));

    final higher = detector.evaluate(
      contactId: 'alice',
      identityContext: 'primary',
      incomingLevel: FsMessageSecurity.fsOnly,
      sessionState: FsSessionState.fsActive,
    );
    expect(higher.isDowngrade, isFalse);
    expect(higher.action, equals(FsDowngradeAction.accept));
  });

  // T_DD_7
  test('T_DD_7: opportunistic mode → acceptWithWarning on downgrade', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsOnly,
    );

    final result = detector.evaluate(
      contactId: 'alice',
      identityContext: 'primary',
      incomingLevel: FsMessageSecurity.legacy,
      sessionState: FsSessionState.fsActive,
    );
    expect(result.action, equals(FsDowngradeAction.acceptWithWarning));
  });

  // T_DD_8
  test('T_DD_8: strict mode → reject on downgrade', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsOnly,
    );

    final result = detector.evaluate(
      contactId: 'alice',
      identityContext: 'primary',
      incomingLevel: FsMessageSecurity.legacy,
      sessionState: FsSessionState.strictFsActive,
    );
    expect(result.action, equals(FsDowngradeAction.reject));
  });

  // T_DD_9
  test('T_DD_9: clearContact removes tracking for specific contact', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsOnly,
    );
    detector.recordSecurityLevel(
      contactId: 'bob',
      identityContext: 'primary',
      level: FsMessageSecurity.fsWithFallback,
    );

    detector.clearContact(contactId: 'alice', identityContext: 'primary');

    expect(
      detector.highestLevel(contactId: 'alice', identityContext: 'primary'),
      equals(FsMessageSecurity.legacy),
    );
    expect(
      detector.highestLevel(contactId: 'bob', identityContext: 'primary'),
      equals(FsMessageSecurity.fsWithFallback),
    );
  });

  // T_DD_10
  test('T_DD_10: clearAll removes all tracking', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsOnly,
    );
    detector.recordSecurityLevel(
      contactId: 'bob',
      identityContext: 'primary',
      level: FsMessageSecurity.fsWithFallback,
    );

    detector.clearAll();

    expect(
      detector.highestLevel(contactId: 'alice', identityContext: 'primary'),
      equals(FsMessageSecurity.legacy),
    );
    expect(
      detector.highestLevel(contactId: 'bob', identityContext: 'primary'),
      equals(FsMessageSecurity.legacy),
    );
  });

  // T_DD_11
  test('T_DD_11: serialization round-trip preserves state', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsOnly,
    );
    detector.recordSecurityLevel(
      contactId: 'bob',
      identityContext: 'passphrase-ctx',
      level: FsMessageSecurity.fsWithFallback,
    );

    final json = detector.toJson();
    final restored = FsDowngradeDetector.fromJson(json);

    expect(
      restored.highestLevel(contactId: 'alice', identityContext: 'primary'),
      equals(FsMessageSecurity.fsOnly),
    );
    expect(
      restored.highestLevel(
          contactId: 'bob', identityContext: 'passphrase-ctx'),
      equals(FsMessageSecurity.fsWithFallback),
    );
    expect(
      restored.highestLevel(contactId: 'unknown', identityContext: 'primary'),
      equals(FsMessageSecurity.legacy),
    );
  });

  // T_DD_12
  test('T_DD_12: different contacts have independent tracking', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsOnly,
    );
    expect(
      detector.highestLevel(contactId: 'bob', identityContext: 'primary'),
      equals(FsMessageSecurity.legacy),
    );
  });

  // T_DD_13
  test('T_DD_13: different identity contexts have independent tracking', () {
    final detector = FsDowngradeDetector();
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'primary',
      level: FsMessageSecurity.fsOnly,
    );
    detector.recordSecurityLevel(
      contactId: 'alice',
      identityContext: 'passphrase-ctx',
      level: FsMessageSecurity.fsWithFallback,
    );

    expect(
      detector.highestLevel(contactId: 'alice', identityContext: 'primary'),
      equals(FsMessageSecurity.fsOnly),
    );
    expect(
      detector.highestLevel(
          contactId: 'alice', identityContext: 'passphrase-ctx'),
      equals(FsMessageSecurity.fsWithFallback),
    );
  });
}
