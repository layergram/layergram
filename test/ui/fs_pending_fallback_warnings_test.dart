/// Tests for §14.6.3 (pending activation indicator) and §14.6.4
/// (fallback warning) — Gap #7.
///
/// Verifies:
///  1. strictRequested maps to a distinct "strict_pending" status key,
///     not the generic "upgrading" key (FsInfoSheet.statusKeyFor).
///  2. All other session states keep their existing status keys.
///  3. Localization coverage: the new keys
///     `security.fs.status.strict_pending` and
///     `security.fs.warning.fallback_body` exist and are non-empty in all
///     6 supported languages.
///  4. The pending status text is distinct from the upgrading text per
///     language (so the icon clearly communicates pending vs negotiating).

import 'package:flutter_test/flutter_test.dart';

import 'package:layergram/core/crypto/fs_session_manager.dart';
import 'package:layergram/l10n/fs_strings_bundle.dart';
import 'package:layergram/ui/fs_info_sheet.dart';

void main() {
  group('§14.6.3 — pending activation status key', () {
    test('strictRequested maps to strict_pending, not upgrading', () {
      expect(
        FsInfoSheet.statusKeyFor(FsSessionState.strictRequested),
        'security.fs.status.strict_pending',
      );
    });

    test('negotiation states still map to upgrading', () {
      const upgradingStates = [
        FsSessionState.fsInitSent,
        FsSessionState.fsInitSeen,
        FsSessionState.fsReplySent,
        FsSessionState.fsReplySeen,
        FsSessionState.fsConfirmSent,
        FsSessionState.fsConfirmed,
      ];
      for (final s in upgradingStates) {
        expect(FsInfoSheet.statusKeyFor(s), 'security.fs.status.upgrading',
            reason: '$s should map to upgrading');
      }
    });

    test('active and strict-active states unchanged', () {
      expect(FsInfoSheet.statusKeyFor(FsSessionState.fsActive),
          'security.fs.status.active');
      expect(FsInfoSheet.statusKeyFor(FsSessionState.strictFsActive),
          'security.fs.status.strict');
    });

    test('legacy/suspended/broken states unchanged', () {
      expect(FsInfoSheet.statusKeyFor(FsSessionState.legacyOnly),
          'security.fs.status.legacy');
      expect(FsInfoSheet.statusKeyFor(FsSessionState.fsSuspended),
          'security.fs.status.suspended');
      expect(FsInfoSheet.statusKeyFor(FsSessionState.fsBroken),
          'security.fs.status.broken');
    });

    test('every session state resolves to a non-empty key', () {
      for (final s in FsSessionState.values) {
        final key = FsInfoSheet.statusKeyFor(s);
        expect(key.isNotEmpty, isTrue, reason: '$s produced empty key');
      }
    });
  });

  group('Localization coverage (§14.6.3 + §14.6.4)', () {
    final requiredKeys = [
      'security.fs.status.strict_pending',
      'security.fs.warning.fallback_body',
    ];

    for (final lang in ['en', 'it', 'es', 'de', 'fr', 'pt']) {
      test('$lang has all new pending/fallback keys', () {
        final bundle = FsStringsBundle.bundle[lang]!;
        for (final key in requiredKeys) {
          expect(bundle.containsKey(key), isTrue,
              reason: '$lang missing key: $key');
          expect(bundle[key]!.isNotEmpty, isTrue,
              reason: '$lang has empty value for key: $key');
        }
      });

      test('$lang pending text differs from upgrading text', () {
        final bundle = FsStringsBundle.bundle[lang]!;
        final pending = bundle['security.fs.status.strict_pending'];
        final upgrading = bundle['security.fs.status.upgrading'];
        expect(pending, isNotNull);
        expect(upgrading, isNotNull);
        expect(pending, isNot(equals(upgrading)),
            reason: '$lang pending should differ from upgrading');
      });
    }

    test('all 6 languages have the strict_pending key', () {
      for (final lang in ['en', 'it', 'es', 'de', 'fr', 'pt']) {
        expect(
          FsStringsBundle.bundle[lang]!
              .containsKey('security.fs.status.strict_pending'),
          isTrue,
          reason: '$lang missing strict_pending',
        );
      }
    });
  });
}
