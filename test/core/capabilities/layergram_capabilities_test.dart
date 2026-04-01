import 'package:flutter_test/flutter_test.dart';

import 'package:layergram/core/capabilities/layergram_capabilities.dart';

void main() {
  group('LayergramCapabilities', () {
    test('should initialize with default OSS capabilities', () {
      // Act
      final capabilities = const LayergramCapabilities();

      // Assert
      expect(capabilities.identity, isNotNull);
      expect(capabilities.backup, isNotNull);
      expect(capabilities.coverGenerator, isNotNull);
      expect(capabilities.chatFolders, isNotNull);
      expect(capabilities.mediaLight, isNotNull);
    });

    test('should report all capabilities as unavailable in OSS', () {
      // Arrange
      final capabilities = const LayergramCapabilities();

      // Act & Assert
      expect(capabilities.identity.isAvailable, isFalse);
      expect(capabilities.backup.isAvailable, isFalse);
      expect(capabilities.coverGenerator.isAvailable, isFalse);
      expect(capabilities.chatFolders.isAvailable, isFalse);
      expect(capabilities.mediaLight.isAvailable, isFalse);
    });

    test('should maintain capability immutability', () {
      // Arrange
      final capabilities = const LayergramCapabilities();

      // Act & Assert - These should throw at runtime if attempted
      expect(capabilities.identity.isAvailable, isFalse);
      expect(capabilities.backup.isAvailable, isFalse);
    });

    test('should provide clear capability identification', () {
      final capabilities = const LayergramCapabilities();

      // Test that capabilities are properly typed and identifiable
      expect(capabilities.identity.toString(), isA<String>());
      expect(capabilities.backup.toString(), isA<String>());
      expect(capabilities.coverGenerator.toString(), isA<String>());
      expect(capabilities.chatFolders.toString(), isA<String>());
      expect(capabilities.mediaLight.toString(), isA<String>());
    });
  });

  group('Capability Contracts', () {
    test('should maintain consistent interface across all capabilities', () {
      final capabilities = const LayergramCapabilities();

      // All capabilities should have the isAvailable property
      expect(capabilities.identity.isAvailable, isA<bool>());
      expect(capabilities.backup.isAvailable, isA<bool>());
      expect(capabilities.coverGenerator.isAvailable, isA<bool>());
      expect(capabilities.chatFolders.isAvailable, isA<bool>());
      expect(capabilities.mediaLight.isAvailable, isA<bool>());

      // All should be false in OSS
      expect(capabilities.identity.isAvailable, isFalse);
      expect(capabilities.backup.isAvailable, isFalse);
      expect(capabilities.coverGenerator.isAvailable, isFalse);
      expect(capabilities.chatFolders.isAvailable, isFalse);
      expect(capabilities.mediaLight.isAvailable, isFalse);
    });

    test('should handle capability operations gracefully', () {
      final capabilities = const LayergramCapabilities();

      // Test that capability operations don't crash (they should throw UnsupportedError)
      expect(() => capabilities.identity.toString(), returnsNormally);
      expect(() => capabilities.backup.toString(), returnsNormally);
      expect(() => capabilities.coverGenerator.toString(), returnsNormally);
      expect(() => capabilities.chatFolders.toString(), returnsNormally);
      expect(() => capabilities.mediaLight.toString(), returnsNormally);
    });
  });
}
