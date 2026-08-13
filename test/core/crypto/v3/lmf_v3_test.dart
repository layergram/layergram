import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';

void main() {
  final key = SecretKeyData(
    Uint8List.fromList(List<int>.generate(32, (index) => index)),
  );

  group('LMF v3 canonical codec', () {
    test('publishes fixed, bounded wire limits', () {
      expect(V3LmfFrameCodec.headerBytes, 142);
      expect(V3LmfFrameCodec.fragmentPlaintextBytes, 256);
      expect(V3LmfFrameCodec.maxFragments, 64);
      expect(V3LmfFrameCodec.maxAssembledPlaintextBytes, 16384);
      expect(V3LmfFrameCodec.minBinaryFrameBytes, 159);
      expect(V3LmfFrameCodec.maxBinaryFrameBytes, 16542);
    });

    test('single-frame golden vector freezes binary and text armor', () async {
      final frame = await V3LmfAead.sealSingle(
        metadata: _metadata(),
        plaintext: Uint8List.fromList(utf8.encode('Layergram v3 golden frame')),
        secretKey: key,
        nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0xa0),
      );

      final binary = V3LmfFrameCodec.encodeBinary(frame);
      final token = V3LmfFrameCodec.encodeToken(frame);

      expect(
        _hex(binary),
        '4c4d33030101008e00190102030405060708090a0b0c0d0e0f10111213141516'
        '1718191a1b1c1d1e1f204142434445464748494a4b4c4d4e4f50515253545556'
        '5758595a5b5c5d5e5f608182838485868788898a8b8c8d8e8f90a1a2a3a4a5'
        'a6a7a8a9aaabacadaeafb0000000070000000000000009773594000000000100'
        '000019a0a1a2a3a4a5a6a7a8a9aaabaa79054837ac70de0f45f1e0271dafb21'
        '4c93730f4c52301f987ccf30812a75a51aea46274d3f1ac72',
      );
      expect(
        token,
        'm3.TE0zAwEBAI4AGQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g'
        'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2CBgoOEhYaHiImKi4yN'
        'jo-QoaKjpKWmp6ipqqusra6vsAAAAAcAAAAAAAAACXc1lAAAAAABAAAAGaChoq'
        'OkpaanqKmqq6p5BUg3rHDeD0Xx4Ccdr7IUyTcw9MUjAfmHzPMIEqdaUa6kYn'
        'TT8axy',
      );
      expect(
        V3LmfFrameCodec.encodeBinary(
          V3LmfFrameCodec.decodeBinary(binary),
        ),
        orderedEquals(binary),
      );
      expect(
        await V3LmfAead.openSingle(frame: frame, secretKey: key),
        orderedEquals(utf8.encode('Layergram v3 golden frame')),
      );
    });

    test('binary semantics are identical through text, link, and stego',
        () async {
      final frame = await V3LmfAead.sealSingle(
        metadata: _metadata(kind: V3LmfFrameKind.application),
        plaintext: Uint8List.fromList(utf8.encode('three transports')),
        secretKey: key,
        nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0xb0),
      );
      final binary = V3LmfFrameCodec.encodeBinary(frame);
      final token = V3LmfFrameCodec.encodeToken(frame);
      final link = V3LmfFrameCodec.encodeLink(frame);
      final minimumCover = StegoEncoder.minCoverLengthForBytes(binary.length);
      final cover = 'A' * minimumCover;
      final stego = V3LmfFrameCodec.encodeStego(
        frame: frame,
        coverText: cover,
        maxTotalCharacters: V3LmfFrameCodec.portableShareCharacterLimit,
      );

      expect(token, startsWith('m3.'));
      expect(link, startsWith('layergram://m/m3.'));
      expect(V3LmfFrameCodec.fitsPortableText(frame), isTrue);
      expect(V3LmfFrameCodec.fitsPortableLink(frame), isTrue);
      expect(
        V3LmfFrameCodec.fitsPortableStego(frame: frame, coverText: cover),
        isTrue,
      );
      expect(
        V3LmfFrameCodec.encodeBinary(V3LmfFrameCodec.decodeToken(token)),
        orderedEquals(binary),
      );
      expect(
        V3LmfFrameCodec.encodeBinary(V3LmfFrameCodec.decodeLink(link)),
        orderedEquals(binary),
      );
      expect(
        V3LmfFrameCodec.encodeBinary(V3LmfFrameCodec.decodeStego(stego)),
        orderedEquals(binary),
      );
    });

    test('rejects malformed fields before accepting a frame', () async {
      final frame = await V3LmfAead.sealSingle(
        metadata: _metadata(),
        plaintext: Uint8List.fromList(<int>[1, 2, 3]),
        secretKey: key,
        nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0xc0),
      );
      final encoded = V3LmfFrameCodec.encodeBinary(frame);

      expect(
        () => V3LmfFrameCodec.decodeBinary(
          Uint8List(V3LmfFrameCodec.minBinaryFrameBytes - 1),
        ),
        throwsFormatException,
      );
      expect(
        () => V3LmfFrameCodec.decodeBinary(
          Uint8List(V3LmfFrameCodec.maxBinaryFrameBytes + 1),
        ),
        throwsFormatException,
      );

      for (final mutation in <(int, int)>[
        (0, 0),
        (3, 2),
        (4, 0xff),
        (5, 0xff),
        (6, 1),
        (7, V3LmfFrameCodec.headerBytes - 1),
      ]) {
        final changed = Uint8List.fromList(encoded)
          ..[mutation.$1] = mutation.$2;
        expect(
          () => V3LmfFrameCodec.decodeBinary(changed),
          throwsFormatException,
          reason: 'offset ${mutation.$1} must fail closed',
        );
      }

      final zeroSender = Uint8List.fromList(encoded)
        ..fillRange(10, 10 + V3LmfFrameCodec.routingBindingBytes, 0);
      expect(
        () => V3LmfFrameCodec.decodeBinary(zeroSender),
        throwsFormatException,
      );

      final wrongPayloadLength = Uint8List.fromList(encoded)..[9] += 1;
      expect(
        () => V3LmfFrameCodec.decodeBinary(wrongPayloadLength),
        throwsFormatException,
      );
      expect(
        () => V3LmfFrameCodec.decodeBinary(
          Uint8List.fromList(encoded.sublist(0, encoded.length - 1)),
        ),
        throwsFormatException,
      );
      expect(
        () => V3LmfFrameCodec.decodeBinary(
          Uint8List.fromList(<int>[...encoded, 0]),
        ),
        throwsFormatException,
      );

      final wrongAssembledLength = Uint8List.fromList(encoded)
        ..[129] = encoded[129] + 1;
      expect(
        () => V3LmfFrameCodec.decodeBinary(wrongAssembledLength),
        throwsFormatException,
      );
    });

    test('rejects non-canonical token, link, and stego input', () async {
      final frame = await V3LmfAead.sealSingle(
        metadata: _metadata(),
        plaintext: Uint8List.fromList(<int>[7, 8, 9]),
        secretKey: key,
        nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0xd0),
      );
      final token = V3LmfFrameCodec.encodeToken(frame);
      final link = V3LmfFrameCodec.encodeLink(frame);

      for (final invalid in <String>[
        '$token=',
        ' $token',
        '$token\n',
        token.replaceFirst('m3.', 'M3.'),
        '${token.substring(0, token.length - 1)}+',
      ]) {
        expect(
          () => V3LmfFrameCodec.decodeToken(invalid),
          throwsFormatException,
        );
      }
      expect(
        () => V3LmfFrameCodec.decodeToken(
          'm3.${'A' * V3LmfFrameCodec.maxTokenCharacters}',
        ),
        throwsFormatException,
      );

      for (final invalid in <String>[
        '$link?source=test',
        '$link#fragment',
        '$link/extra',
        link.replaceFirst('layergram://', 'layergram://user@'),
        link.replaceFirst('layergram://m/', 'layergram://m:123/'),
      ]) {
        expect(
          () => V3LmfFrameCodec.decodeLink(invalid),
          throwsFormatException,
        );
      }

      expect(
        () => V3LmfFrameCodec.decodeStego(
            'A' * (V3LmfFrameCodec.maxStegoInputCodeUnits + 1)),
        throwsFormatException,
      );
      expect(
        () => V3LmfFrameCodec.decodeStego('cover\u200Etext'),
        throwsFormatException,
      );
      expect(
        () => V3LmfFrameCodec.decodeStego('cover\u200Btext'),
        throwsFormatException,
      );
      expect(
        () => V3LmfFrameCodec.encodeStego(
          frame: frame,
          coverText: 'A' * (V3LmfFrameCodec.maxStegoInputCodeUnits + 1),
        ),
        throwsArgumentError,
      );
    });

    test('bounded random hostile binary input never escapes parser errors', () {
      final random = Random(20260813);
      for (var sample = 0; sample < 1000; sample++) {
        final length = random.nextInt(768);
        final hostile = Uint8List.fromList(
          List<int>.generate(length, (_) => random.nextInt(256)),
        );
        try {
          final decoded = V3LmfFrameCodec.decodeBinary(hostile);
          expect(
            V3LmfFrameCodec.decodeBinary(
              V3LmfFrameCodec.encodeBinary(decoded),
            ),
            isA<V3LmfFrame>(),
          );
        } on FormatException {
          // Expected for hostile input. Any other exception fails the test.
        }
      }
    });
  });

  group('LMF v3 authentication boundary', () {
    test('binds routing, IDs, counters, policy, suite, kind, and nonce',
        () async {
      final original = await V3LmfAead.sealSingle(
        metadata: _metadata(),
        plaintext: Uint8List.fromList(utf8.encode('authenticated header')),
        secretKey: key,
        nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0xe0),
      );

      final variants = <V3LmfFrame>[
        _copyFrame(
          original,
          metadata: _metadata(senderStart: 2),
        ),
        _copyFrame(
          original,
          metadata: _metadata(recipientStart: 0x42),
        ),
        _copyFrame(
          original,
          metadata: _metadata(messageStart: 0x82),
        ),
        _copyFrame(
          original,
          metadata: _metadata(sessionStart: 0xa2),
        ),
        _copyFrame(original, metadata: _metadata(epoch: 8)),
        _copyFrame(original, metadata: _metadata(messageCounter: 10)),
        _copyFrame(
          original,
          metadata: _metadata(expiresAtUnixSeconds: 2000000001),
        ),
        _copyFrame(
          original,
          metadata: _metadata(kind: V3LmfFrameKind.application),
        ),
        _copyFrame(
          original,
          nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0xe1),
        ),
      ];

      for (final changed in variants) {
        await expectLater(
          V3LmfAead.openSingle(frame: changed, secretKey: key),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
      }
    });

    test('binds fragment index, count, and final assembled length', () async {
      final metadata = _metadata();
      final frames = await V3LmfAead.sealFragmented(
        metadata: metadata,
        plaintext: _bytes(512, 1),
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x10 + index),
      );
      final first = frames.first;
      final validButUnauthenticatedVariants = <V3LmfFrame>[
        _copyFrame(first, fragmentIndex: 1),
        _copyFrame(first, assembledPlaintextLength: 511),
        _copyFrame(
          first,
          fragmentCount: 3,
          assembledPlaintextLength: 768,
        ),
      ];

      for (final changed in validButUnauthenticatedVariants) {
        final reassembler = V3LmfReassembler();
        await expectLater(
          reassembler.accept(frame: changed, secretKey: key),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
        expect(reassembler.pendingAssemblyCount, 0);
        reassembler.close();
      }
    });

    test('ciphertext and tag tampering fail without pending state', () async {
      final frame = await V3LmfAead.sealSingle(
        metadata: _metadata(),
        plaintext: Uint8List.fromList(<int>[1, 2, 3, 4]),
        secretKey: key,
        nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0xf0),
      );
      final encoded = V3LmfFrameCodec.encodeBinary(frame);
      final changedCiphertext = Uint8List.fromList(encoded)
        ..[V3LmfFrameCodec.headerBytes] ^= 1;
      final changedTag = Uint8List.fromList(encoded)..[encoded.length - 1] ^= 1;

      for (final tampered in <Uint8List>[changedCiphertext, changedTag]) {
        final decoded = V3LmfFrameCodec.decodeBinary(tampered);
        final reassembler = V3LmfReassembler();
        await expectLater(
          reassembler.accept(frame: decoded, secretKey: key),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
        expect(reassembler.pendingAssemblyCount, 0);
        reassembler.close();
      }
    });

    test('wrong key and fragmented openSingle fail closed', () async {
      final frames = await V3LmfAead.sealFragmented(
        metadata: _metadata(),
        plaintext: _bytes(300, 3),
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x20 + index),
      );
      final wrongKey = SecretKeyData(Uint8List(32));
      final reassembler = V3LmfReassembler();

      await expectLater(
        reassembler.accept(frame: frames.first, secretKey: wrongKey),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(reassembler.pendingAssemblyCount, 0);
      await expectLater(
        V3LmfAead.openSingle(frame: frames.first, secretKey: key),
        throwsStateError,
      );
      reassembler.close();
    });
  });

  group('LMF v3 fragmentation and reassembly', () {
    test('ML-KEM-sized payload is five bounded, portable frames', () async {
      final plaintext = _bytes(1088, 0x31);
      final frames = await V3LmfAead.sealFragmented(
        metadata: _metadata(kind: V3LmfFrameKind.handshake),
        plaintext: plaintext,
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x30 + index),
      );

      expect(frames, hasLength(5));
      expect(
        frames.map((frame) => frame.ciphertext.length),
        <int>[256, 256, 256, 256, 64],
      );
      expect(
        frames.map((frame) => V3LmfFrameCodec.encodeBinary(frame).length),
        <int>[414, 414, 414, 414, 222],
      );
      for (final frame in frames) {
        expect(V3LmfFrameCodec.fitsPortableText(frame), isTrue);
        expect(V3LmfFrameCodec.fitsPortableLink(frame), isTrue);
        final binaryLength = V3LmfFrameCodec.encodeBinary(frame).length;
        final cover = 'A' * StegoEncoder.minCoverLengthForBytes(binaryLength);
        expect(
          V3LmfFrameCodec.fitsPortableStego(
            frame: frame,
            coverText: cover,
          ),
          isTrue,
        );
      }
    });

    test('maximum single frame and 64-fragment assembly stay bounded',
        () async {
      final maximum = _bytes(
        V3LmfFrameCodec.maxAssembledPlaintextBytes,
        0x19,
      );
      final single = await V3LmfAead.sealSingle(
        metadata: _metadata(kind: V3LmfFrameKind.application),
        plaintext: maximum,
        secretKey: key,
        nonce: _bytes(V3LmfFrameCodec.nonceBytes, 0x55),
      );
      final binary = V3LmfFrameCodec.encodeBinary(single);
      expect(binary, hasLength(V3LmfFrameCodec.maxBinaryFrameBytes));
      expect(
        V3LmfFrameCodec.encodeToken(single),
        hasLength(V3LmfFrameCodec.maxTokenCharacters),
      );
      expect(
        await V3LmfAead.openSingle(
          frame: V3LmfFrameCodec.decodeBinary(binary),
          secretKey: key,
        ),
        orderedEquals(maximum),
      );

      final fragments = await V3LmfAead.sealFragmented(
        metadata: _metadata(),
        plaintext: maximum,
        secretKey: key,
        nonceForFragment: (index) => Uint8List.fromList(<int>[
          ..._bytes(V3LmfFrameCodec.nonceBytes - 1, 0x70),
          index,
        ]),
      );
      expect(fragments, hasLength(V3LmfFrameCodec.maxFragments));
      final reassembler = V3LmfReassembler();
      V3LmfReassemblyOutcome? completed;
      for (var index = fragments.length - 1; index >= 0; index--) {
        final outcome = await reassembler.accept(
          frame: fragments[index],
          secretKey: key,
        );
        if (outcome.isComplete) completed = outcome;
      }
      expect(completed?.plaintext, orderedEquals(maximum));
      expect(reassembler.pendingAssemblyCount, 0);
      reassembler.close();

      await expectLater(
        V3LmfAead.sealSingle(
          metadata: _metadata(),
          plaintext: Uint8List(
            V3LmfFrameCodec.maxAssembledPlaintextBytes + 1,
          ),
          secretKey: key,
          nonce: Uint8List(V3LmfFrameCodec.nonceBytes),
        ),
        throwsArgumentError,
      );
    });

    test('reorders, deduplicates, and exposes only the complete payload',
        () async {
      final plaintext = _bytes(1088, 0x41);
      final frames = await V3LmfAead.sealFragmented(
        metadata: _metadata(),
        plaintext: plaintext,
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x40 + index),
      );
      final reassembler = V3LmfReassembler();

      for (final index in <int>[4, 1]) {
        final outcome = await reassembler.accept(
          frame: frames[index],
          secretKey: key,
        );
        expect(outcome.status, V3LmfReassemblyStatus.accepted);
        expect(outcome.plaintext, isNull);
      }
      final duplicate = await reassembler.accept(
        frame: frames[1],
        secretKey: key,
      );
      expect(duplicate.status, V3LmfReassemblyStatus.duplicate);
      expect(duplicate.plaintext, isNull);

      for (final index in <int>[3, 0]) {
        final outcome = await reassembler.accept(
          frame: frames[index],
          secretKey: key,
        );
        expect(outcome.status, V3LmfReassemblyStatus.accepted);
        expect(outcome.plaintext, isNull);
      }
      final completed = await reassembler.accept(
        frame: frames[2],
        secretKey: key,
      );

      expect(completed.status, V3LmfReassemblyStatus.complete);
      expect(completed.plaintext, orderedEquals(plaintext));
      expect(reassembler.pendingAssemblyCount, 0);
      expect(reassembler.bufferedPlaintextBytes, 0);

      final mutableCopy = completed.plaintext!..[0] ^= 1;
      expect(mutableCopy, isNot(orderedEquals(plaintext)));
      expect(completed.plaintext, orderedEquals(plaintext));
      reassembler.close();
    });

    test('authenticated metadata conflicts poison and remove the assembly',
        () async {
      final metadata = _metadata();
      final firstSet = await V3LmfAead.sealFragmented(
        metadata: metadata,
        plaintext: _bytes(512, 0x51),
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x50 + index),
      );
      final conflictingSet = await V3LmfAead.sealFragmented(
        metadata: metadata,
        plaintext: _bytes(768, 0x61),
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x60 + index),
      );
      final reassembler = V3LmfReassembler();

      await reassembler.accept(frame: firstSet.first, secretKey: key);
      expect(reassembler.pendingAssemblyCount, 1);
      await expectLater(
        reassembler.accept(frame: conflictingSet.first, secretKey: key),
        throwsA(isA<V3LmfReassemblyConflictException>()),
      );
      expect(reassembler.pendingAssemblyCount, 0);
      expect(reassembler.bufferedPlaintextBytes, 0);
      reassembler.close();
    });

    test('only a byte-identical authenticated duplicate is accepted', () async {
      final metadata = _metadata();
      final plaintext = _bytes(512, 0x66);
      final firstSet = await V3LmfAead.sealFragmented(
        metadata: metadata,
        plaintext: plaintext,
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x11 + index),
      );
      final reencryption = await V3LmfAead.sealFragmented(
        metadata: metadata,
        plaintext: plaintext,
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x21 + index),
      );
      final reassembler = V3LmfReassembler();

      await reassembler.accept(frame: firstSet.first, secretKey: key);
      final exactDuplicate = await reassembler.accept(
        frame: firstSet.first,
        secretKey: key,
      );
      expect(exactDuplicate.status, V3LmfReassemblyStatus.duplicate);
      await expectLater(
        reassembler.accept(frame: reencryption.first, secretKey: key),
        throwsA(isA<V3LmfReassemblyConflictException>()),
      );
      expect(reassembler.pendingAssemblyCount, 0);
      expect(reassembler.bufferedPlaintextBytes, 0);
      reassembler.close();
    });

    test('enforces pending and buffered limits without evicting valid state',
        () async {
      final firstSet = await V3LmfAead.sealFragmented(
        metadata: _metadata(messageStart: 0x81),
        plaintext: _bytes(512, 0x71),
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x70 + index),
      );
      final secondSet = await V3LmfAead.sealFragmented(
        metadata: _metadata(messageStart: 0x91),
        plaintext: _bytes(512, 0x81),
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x80 + index),
      );
      final pendingLimited = V3LmfReassembler(maxPendingAssemblies: 1);
      await pendingLimited.accept(frame: firstSet.first, secretKey: key);
      await expectLater(
        pendingLimited.accept(frame: secondSet.first, secretKey: key),
        throwsA(isA<V3LmfReassemblyLimitException>()),
      );
      expect(pendingLimited.pendingAssemblyCount, 1);
      expect(pendingLimited.bufferedPlaintextBytes, 256);
      pendingLimited.close();

      final byteLimited = V3LmfReassembler(maxBufferedPlaintextBytes: 300);
      await byteLimited.accept(frame: firstSet.first, secretKey: key);
      await expectLater(
        byteLimited.accept(frame: firstSet.last, secretKey: key),
        throwsA(isA<V3LmfReassemblyLimitException>()),
      );
      expect(byteLimited.pendingAssemblyCount, 1);
      expect(byteLimited.bufferedPlaintextBytes, 256);
      byteLimited.close();
    });

    test('retention cleanup is explicit and close is idempotent', () async {
      final frames = await V3LmfAead.sealFragmented(
        metadata: _metadata(),
        plaintext: _bytes(512, 0x91),
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x90 + index),
      );
      final reassembler = V3LmfReassembler();
      await reassembler.accept(
        frame: frames.first,
        secretKey: key,
        receivedAt: DateTime.utc(2026, 1, 1),
      );

      expect(reassembler.purgeOlderThan(DateTime.utc(2025, 12, 31)), 0);
      expect(reassembler.pendingAssemblyCount, 1);
      expect(reassembler.purgeOlderThan(DateTime.utc(2026, 1, 1)), 1);
      expect(reassembler.pendingAssemblyCount, 0);
      expect(reassembler.bufferedPlaintextBytes, 0);

      reassembler.close();
      reassembler.close();
      await expectLater(
        reassembler.accept(frame: frames.last, secretKey: key),
        throwsStateError,
      );
    });

    test('close during authentication cannot repopulate pending state',
        () async {
      final frames = await V3LmfAead.sealFragmented(
        metadata: _metadata(),
        plaintext: _bytes(512, 0x44),
        secretKey: key,
        nonceForFragment: (index) =>
            _bytes(V3LmfFrameCodec.nonceBytes, 0x33 + index),
      );
      final reassembler = V3LmfReassembler();

      final pending = reassembler.accept(frame: frames.first, secretKey: key);
      reassembler.close();
      await expectLater(pending, throwsStateError);
      expect(reassembler.pendingAssemblyCount, 0);
      expect(reassembler.bufferedPlaintextBytes, 0);
    });

    test('rejects nonce reuse and non-canonical fragmentation inputs',
        () async {
      await expectLater(
        V3LmfAead.sealFragmented(
          metadata: _metadata(),
          plaintext: _bytes(300, 1),
          secretKey: key,
          nonceForFragment: (_) => Uint8List(V3LmfFrameCodec.nonceBytes),
        ),
        throwsStateError,
      );
      await expectLater(
        V3LmfAead.sealFragmented(
          metadata: _metadata(),
          plaintext: Uint8List(0),
          secretKey: key,
          nonceForFragment: (_) => Uint8List(V3LmfFrameCodec.nonceBytes),
        ),
        throwsArgumentError,
      );
      expect(
        () => V3LmfFrame(
          metadata: _metadata(),
          fragmentIndex: 0,
          fragmentCount: 2,
          assembledPlaintextLength: 300,
          nonce: Uint8List(V3LmfFrameCodec.nonceBytes),
          ciphertext: Uint8List(255),
          authenticationTag: Uint8List(V3LmfFrameCodec.authenticationTagBytes),
        ),
        throwsArgumentError,
      );
    });
  });
}

V3LmfMessageMetadata _metadata({
  V3LmfFrameKind kind = V3LmfFrameKind.handshake,
  int senderStart = 1,
  int recipientStart = 0x41,
  int messageStart = 0x81,
  int sessionStart = 0xa1,
  int epoch = 7,
  int messageCounter = 9,
  int expiresAtUnixSeconds = 2000000000,
}) {
  return V3LmfMessageMetadata(
    kind: kind,
    senderBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, senderStart),
    recipientBinding:
        _bytes(V3LmfFrameCodec.routingBindingBytes, recipientStart),
    messageId: _bytes(V3LmfFrameCodec.messageIdBytes, messageStart),
    sessionId: _bytes(V3LmfFrameCodec.sessionIdBytes, sessionStart),
    epoch: epoch,
    messageCounter: messageCounter,
    expiresAtUnixSeconds: expiresAtUnixSeconds,
  );
}

V3LmfFrame _copyFrame(
  V3LmfFrame frame, {
  V3LmfMessageMetadata? metadata,
  int? fragmentIndex,
  int? fragmentCount,
  int? assembledPlaintextLength,
  Uint8List? nonce,
}) {
  return V3LmfFrame(
    metadata: metadata ?? frame.metadata,
    fragmentIndex: fragmentIndex ?? frame.fragmentIndex,
    fragmentCount: fragmentCount ?? frame.fragmentCount,
    assembledPlaintextLength:
        assembledPlaintextLength ?? frame.assembledPlaintextLength,
    nonce: nonce ?? frame.nonce,
    ciphertext: frame.ciphertext,
    authenticationTag: frame.authenticationTag,
  );
}

Uint8List _bytes(int length, int start) {
  return Uint8List.fromList(
    List<int>.generate(length, (index) => (start + index) & 0xff),
  );
}

String _hex(Uint8List bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
