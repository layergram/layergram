import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/passphrase_service.dart';
import 'package:layergram/core/crypto/seed_service.dart';

void main() {
  group('PassphraseNotifier', () {
    final validMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    late SeedService seedService;
    late PassphraseNotifier notifier;

    setUp(() {
      seedService = SeedService();
      notifier = PassphraseNotifier(seedService: seedService);
    });

    test('initial state is inactive', () {
      expect(notifier.state.isActive, isFalse);
      expect(notifier.state.privateKeyBase64, isNull);
      expect(notifier.state.publicKeyBase64, isNull);
      expect(notifier.state.keyTag, isNull);
    });

    test('activate derives deterministic keys from passphrase', () async {
      await notifier.activate(validMnemonic, 'test-passphrase');
      
      final state1 = notifier.state;
      expect(state1.isActive, isTrue);
      expect(state1.privateKeyBase64, isNotNull);
      expect(state1.publicKeyBase64, isNotNull);
      expect(state1.keyTag, isNotNull);
      
      // Activating again with same inputs yields same outputs
      await notifier.activate(validMnemonic, 'test-passphrase');
      final state2 = notifier.state;
      expect(state2.privateKeyBase64, equals(state1.privateKeyBase64));
      expect(state2.publicKeyBase64, equals(state1.publicKeyBase64));
    });

    test('activate derives different keys for different passphrases', () async {
      await notifier.activate(validMnemonic, 'passphrase-A');
      final stateA = notifier.state;
      
      await notifier.activate(validMnemonic, 'passphrase-B');
      final stateB = notifier.state;
      
      expect(stateA.privateKeyBase64, isNot(equals(stateB.privateKeyBase64)));
      expect(stateA.publicKeyBase64, isNot(equals(stateB.publicKeyBase64)));
    });

    test('deactivate clears all keys', () async {
      await notifier.activate(validMnemonic, 'test-passphrase');
      expect(notifier.state.isActive, isTrue);
      
      notifier.deactivate();
      
      expect(notifier.state.isActive, isFalse);
      expect(notifier.state.privateKeyBase64, isNull);
      expect(notifier.state.publicKeyBase64, isNull);
      expect(notifier.state.keyTag, isNull);
    });

    test('computeKeyTag produces consistent length 8 strings without padding', () {
      final pubKeyBytes = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final tag = PassphraseNotifier.computeKeyTag(pubKeyBytes);
      
      expect(tag.length, equals(8)); // 6 bytes base64url encoded
      expect(tag.contains('='), isFalse);
      
      // Test the base64 helper
      final base64Key = base64Encode(pubKeyBytes);
      final tagFromHelper = PassphraseNotifier.computeKeyTagFromBase64(base64Key);
      
      expect(tagFromHelper, equals(tag));
    });
  });
}
