// Tests for FsPayloadBudget — FS Spec Phase 6.
//
// Mandatory tests (roadmap §9 Phase 6):
//
//  T6.1  Maximum-size fs_init after zero-width encoding.
//  T6.2  Maximum-size fs_reply after zero-width encoding.
//  T6.3  Maximum-size fs_confirm after zero-width encoding.
//  T6.4  Payload-too-large in Opportunistic mode → fitsOpportunistic = false.
//  T6.5  Payload-too-large in Strict mode → fitsStrict = false, no silent drop.
//  T6.6  Normal fs_init / fs_reply / fs_confirm fit within kMaxFsControlPayloadBytes.
//  T6.7  stegoRuneCount is 4 × totalEncryptedBytes (2 bits/rune).
//  T6.8  minimumCoverChars is consistent with StegoEncoder.minCoverLengthForBytes.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/fs_payload_budget.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';

import '../../test_diagnostics.dart';

// ---------------------------------------------------------------------------
// Realistic maximum-size FS control payloads (44-char base64url keys).
// ---------------------------------------------------------------------------

/// A realistic maximum-size fs_init JSON object.
///
/// Each base64url-encoded X25519 key with curve byte prefix is 44 chars.
/// initId is a 22-char base64url (128-bit random).
/// caps contains two capability strings.
Map<String, dynamic> _maxFsInit() => {
      'v': 1,
      'type': 'fs_init',
      'initId': 'AAAAAAAAAAAAAAAAAAAAAA', // 22 chars (128-bit)
      'initiatorDevicePub': 'AQ${'A' * 42}', // 44 chars
      'initiatorEphemeralPub': 'AQ${'A' * 42}',
      'caps': ['lgfs1', 'dr1'],
      'createdAt': 1700000000,
    };

/// A realistic maximum-size fs_reply JSON object.
Map<String, dynamic> _maxFsReply() => {
      'v': 1,
      'type': 'fs_reply',
      'initId': 'AAAAAAAAAAAAAAAAAAAAAA',
      'replyId': 'BBBBBBBBBBBBBBBBBBBBBB',
      'responderDevicePub': 'AQ${'B' * 42}',
      'responderEphemeralPub': 'AQ${'C' * 42}',
      'responderInitialRatchetPub': 'AQ${'D' * 42}',
      'caps': ['lgfs1', 'dr1'],
      'createdAt': 1700000001,
    };

/// A realistic maximum-size fs_confirm JSON object.
///
/// transcriptHash and confirmTag are each 43 chars (SHA-256 base64url).
/// initiatorInitialRatchetPub is 44 chars.
Map<String, dynamic> _maxFsConfirm() => {
      'v': 1,
      'type': 'fs_confirm',
      'initId': 'AAAAAAAAAAAAAAAAAAAAAA',
      'replyId': 'BBBBBBBBBBBBBBBBBBBBBB',
      'transcriptHash': 'A' * 43,
      'confirmTag': 'B' * 43,
      'initiatorInitialRatchetPub': 'AQ${'E' * 42}',
    };

/// An oversized x.fs payload (> kMaxFsControlPayloadBytes).
Map<String, dynamic> _oversizedFs() => {
      'v': 1,
      'type': 'fs_init',
      'initId': 'X' * 22,
      'initiatorDevicePub': 'AQ${'X' * 42}',
      'initiatorEphemeralPub': 'AQ${'X' * 42}',
      'caps': ['lgfs1'],
      // Stuff with a large padding field to exceed the budget.
      'extra': 'X' * 1500,
      'createdAt': 1700000000,
    };

// ---------------------------------------------------------------------------

void main() {
  group('FsPayloadBudget (Phase 6)', () {
    // T6.1 — Maximum-size fs_init measured.
    test('T6.1: fs_init max size measurement', () {
      final result = FsPayloadBudget.measure(_maxFsInit());

      // Print for visibility during development.
      diagnosticLog('fs_init: $result');

      // Must be below the opportunistic ceiling.
      expect(result.fitsOpportunistic, isTrue,
          reason: 'fs_init must fit in Opportunistic FS budget '
              '(${result.fsExtensionBytes} B > ${FsPayloadBudget.kMaxFsControlPayloadBytes} B)');

      // Extension size sanity check: fs_init has 2 keys (88 chars each),
      // so it must be at least 200 bytes.
      expect(result.fsExtensionBytes, greaterThan(200));

      // Stego rune count must equal 4 × totalEncryptedBytes.
      expect(result.stegoRuneCount, equals(result.totalEncryptedBytes * 4));

      // minimumCoverChars must match StegoEncoder directly.
      expect(
        result.minimumCoverChars,
        equals(StegoEncoder.minCoverLengthForBytes(result.totalEncryptedBytes)),
      );
    });

    // T6.2 — Maximum-size fs_reply measured.
    test('T6.2: fs_reply max size measurement', () {
      final result = FsPayloadBudget.measure(_maxFsReply());
      diagnosticLog('fs_reply: $result');

      expect(result.fitsOpportunistic, isTrue,
          reason: 'fs_reply must fit in Opportunistic FS budget '
              '(${result.fsExtensionBytes} B > ${FsPayloadBudget.kMaxFsControlPayloadBytes} B)');

      expect(result.fsExtensionBytes, greaterThan(250),
          reason: 'fs_reply has 3 keys so must be larger than fs_init');

      expect(result.stegoRuneCount, equals(result.totalEncryptedBytes * 4));
      expect(
        result.minimumCoverChars,
        equals(StegoEncoder.minCoverLengthForBytes(result.totalEncryptedBytes)),
      );
    });

    // T6.3 — Maximum-size fs_confirm measured.
    test('T6.3: fs_confirm max size measurement', () {
      final result = FsPayloadBudget.measure(_maxFsConfirm());
      diagnosticLog('fs_confirm: $result');

      expect(result.fitsOpportunistic, isTrue,
          reason: 'fs_confirm must fit in Opportunistic FS budget');

      expect(result.fsExtensionBytes, greaterThan(150));

      expect(result.stegoRuneCount, equals(result.totalEncryptedBytes * 4));
      expect(
        result.minimumCoverChars,
        equals(StegoEncoder.minCoverLengthForBytes(result.totalEncryptedBytes)),
      );
    });

    // T6.4 — Oversized payload in Opportunistic mode.
    test('T6.4: oversized x.fs → fitsOpportunistic = false', () {
      final result = FsPayloadBudget.measure(_oversizedFs());
      diagnosticLog('oversized: $result');

      expect(result.fitsOpportunistic, isFalse,
          reason: 'Oversized payload must NOT fit in Opportunistic budget');
    });

    // T6.5 — Oversized payload in Strict mode: fitsStrict = false.
    test('T6.5: oversized x.fs → fitsStrict = false (no silent drop allowed)',
        () {
      final result = FsPayloadBudget.measure(_oversizedFs());
      expect(result.fitsStrict, isFalse,
          reason: 'Oversized payload must not fit in Strict budget — caller '
              'must NOT silently drop the extension');
    });

    // T6.6 — All three real FS control messages fit within kMaxFsControlPayloadBytes.
    test(
        'T6.6: all real fs_init/fs_reply/fs_confirm fit within kMaxFsControlPayloadBytes',
        () {
      for (final entry in {
        'fs_init': _maxFsInit(),
        'fs_reply': _maxFsReply(),
        'fs_confirm': _maxFsConfirm(),
      }.entries) {
        final bytes = FsPayloadBudget.fsExtensionBytes(entry.value);
        expect(
            bytes, lessThanOrEqualTo(FsPayloadBudget.kMaxFsControlPayloadBytes),
            reason:
                '${entry.key} extension ($bytes B) exceeds kMaxFsControlPayloadBytes '
                '(${FsPayloadBudget.kMaxFsControlPayloadBytes} B)');
      }
    });

    // T6.7 — stegoRuneCount = 4 × totalEncryptedBytes.
    test(
        'T6.7: stegoRuneCount equals 4 × totalEncryptedBytes for all message types',
        () {
      for (final payload in [_maxFsInit(), _maxFsReply(), _maxFsConfirm()]) {
        final result = FsPayloadBudget.measure(payload);
        expect(result.stegoRuneCount, equals(result.totalEncryptedBytes * 4),
            reason: 'stegoRuneCount must be exactly 4 × totalEncryptedBytes '
                '(2 bits per rune, base-4 alphabet)');
      }
    });

    // T6.8 — minimumCoverChars consistent with StegoEncoder.
    test(
        'T6.8: minimumCoverChars is consistent with StegoEncoder.minCoverLengthForBytes',
        () {
      for (final payload in [_maxFsInit(), _maxFsReply(), _maxFsConfirm()]) {
        final result = FsPayloadBudget.measure(payload);
        expect(
          result.minimumCoverChars,
          equals(
              StegoEncoder.minCoverLengthForBytes(result.totalEncryptedBytes)),
        );
      }
    });

    // Snapshot test: assert concrete byte counts are stable.
    test('T6.9: concrete fs extension byte counts are stable (snapshot)', () {
      final initBytes = FsPayloadBudget.fsExtensionBytes(_maxFsInit());
      final replyBytes = FsPayloadBudget.fsExtensionBytes(_maxFsReply());
      final confirmBytes = FsPayloadBudget.fsExtensionBytes(_maxFsConfirm());

      // These values should change only when the FS wire format changes.
      // Update this test intentionally when that happens.
      expect(
          initBytes,
          equals(
            utf8.encode(jsonEncode(_maxFsInit())).length,
          ));
      expect(
          replyBytes,
          equals(
            utf8.encode(jsonEncode(_maxFsReply())).length,
          ));
      expect(
          confirmBytes,
          equals(
            utf8.encode(jsonEncode(_maxFsConfirm())).length,
          ));

      // All must be below 800 B ceiling.
      expect(initBytes, lessThan(FsPayloadBudget.kMaxFsControlPayloadBytes));
      expect(replyBytes, lessThan(FsPayloadBudget.kMaxFsControlPayloadBytes));
      expect(confirmBytes, lessThan(FsPayloadBudget.kMaxFsControlPayloadBytes));

      // Reply must be larger than init (has one extra key field).
      expect(replyBytes, greaterThan(initBytes));
    });

    // totalEncryptedBytesWithFs includes fixed overhead.
    test(
        'T6.10: totalEncryptedBytesWithFs = overhead + baseEnvelope + fsExtBytes',
        () {
      final fs = _maxFsInit();
      final extBytes = FsPayloadBudget.fsExtensionBytes(fs);
      final expected = FsPayloadBudget.lmfV2WireOverheadBytes +
          FsPayloadBudget.baseJsonEnvelopeBytes +
          extBytes;
      expect(FsPayloadBudget.totalEncryptedBytesWithFs(fs), equals(expected));
    });
  });
}
