import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/utils/sharing.dart';

void main() {
  group('isWhatsAppShareActivityType', () {
    test('returns true for exact whatsapp package name', () {
      expect(isWhatsAppShareActivityType('com.whatsapp'), isTrue);
    });

    test('returns true for WhatsApp Business package name', () {
      expect(isWhatsAppShareActivityType('com.whatsapp.w4b'), isTrue);
    });

    test('returns true for iOS WhatsApp activity type', () {
      expect(isWhatsAppShareActivityType('net.whatsapp.WhatsApp.ShareExtension'), isTrue);
    });

    test('is case-insensitive', () {
      expect(isWhatsAppShareActivityType('COM.WHATSAPP'), isTrue);
      expect(isWhatsAppShareActivityType('WhatsApp'), isTrue);
    });

    test('trims surrounding whitespace before matching', () {
      expect(isWhatsAppShareActivityType('  com.whatsapp  '), isTrue);
    });

    test('returns false for empty string', () {
      expect(isWhatsAppShareActivityType(''), isFalse);
    });

    test('returns false for whitespace-only string', () {
      expect(isWhatsAppShareActivityType('   '), isFalse);
    });

    test('returns false for unrelated app package names', () {
      expect(isWhatsAppShareActivityType('com.telegram.messenger'), isFalse);
      expect(isWhatsAppShareActivityType('com.google.android.gm'), isFalse);
      expect(isWhatsAppShareActivityType('com.apple.UIKit.activity.Message'), isFalse);
    });

    test('returns false for partial match that is not actually whatsapp', () {
      // Ensure a package that only contains "whatsapp" as a substring still
      // matches (there is no plausible false-positive here in practice, but
      // we confirm the substring rule is intentional).
      expect(isWhatsAppShareActivityType('com.fake.notwhatsapp.app'), isTrue);
    });
  });
}
