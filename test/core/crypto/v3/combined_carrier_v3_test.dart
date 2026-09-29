import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/stego_alphabet_v2.dart';
import 'package:layergram/core/crypto/stego_decoder.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';
import 'package:layergram/core/crypto/v3/combined_carrier_v3.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/hybrid_ratchet_header_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';

void main() {
  final frames = <V3LmfFrame>[
    _frame(V3LmfFrameKind.application, 1),
    _frame(V3LmfFrameKind.acknowledgement, 0x41),
  ];
  final innerBytes = frames.map(V3LmfFrameCodec.encodeBinary).toList();

  test('round-trips canonical text and link without changing inner bytes', () {
    final text = V3CombinedCarrierCodec.encodeText(frames);
    final link = V3CombinedCarrierCodec.encodeLink(frames);

    expect(text, startsWith('b3.'));
    expect(link, equals('layergram://m/$text'));
    expect(V3CombinedCarrierCodec.isTextPart(text), isTrue);
    expect(V3CombinedCarrierCodec.isLinkPart(link), isTrue);
    _expectInnerBytes(V3CombinedCarrierCodec.decodeText(text), innerBytes);
    _expectInnerBytes(V3CombinedCarrierCodec.decodeLink(link), innerBytes);

    for (final invalid in <String>[
      '$text=',
      ' $text',
      '$text\n',
      text.replaceFirst('b3.', 'B3.'),
    ]) {
      expect(
        () => V3CombinedCarrierCodec.decodeText(invalid),
        throwsFormatException,
      );
    }
    for (final invalid in <String>[
      '$link?source=test',
      '$link#fragment',
      '$link/extra',
      link.replaceFirst('layergram://', 'layergram://user@'),
    ]) {
      expect(
        () => V3CombinedCarrierCodec.decodeLink(invalid),
        throwsFormatException,
      );
    }
  });

  test('round-trips through the unchanged V2 stego alphabet', () {
    final binary = V3CombinedCarrierCodec.encodeBinary(frames);
    final cover = 'A' * StegoEncoder.minCoverLengthForBytes(binary.length);
    final stego = V3CombinedCarrierCodec.encodeStego(
      frames: frames,
      coverText: cover,
    );

    expect(V3CombinedCarrierCodec.looksLikeStegoPart(stego), isTrue);
    expect(StegoDecoder.visibleCoverText(stego), cover);
    for (final rune in stego.runes.where(StegoAlphabetV2.isPayloadRune)) {
      expect(StegoAlphabetV2.payloadRuneToValue, contains(rune));
    }
    _expectInnerBytes(V3CombinedCarrierCodec.decodeStego(stego), innerBytes);
  });

  test('enforces frame shape and portable character limits without truncation',
      () {
    expect(
      () => V3CombinedCarrierCodec.encodeBinary(<V3LmfFrame>[frames.first]),
      throwsArgumentError,
    );
    expect(
      () => V3CombinedCarrierCodec.encodeBinary(<V3LmfFrame>[
        _frame(V3LmfFrameKind.handshake, 2),
        frames.last,
      ]),
      throwsArgumentError,
    );
    expect(
      () => V3CombinedCarrierCodec.encodeBinary(<V3LmfFrame>[
        _frame(V3LmfFrameKind.pqRatchet, 2),
        frames.last,
      ]),
      throwsArgumentError,
    );
    expect(
      () => V3CombinedCarrierCodec.encodeBinary(<V3LmfFrame>[
        frames.first,
        _frame(V3LmfFrameKind.application, 3),
      ]),
      throwsArgumentError,
    );
    expect(
      () => V3CombinedCarrierCodec.encodeText(
        frames,
        maxTotalCharacters: 10,
      ),
      throwsArgumentError,
    );
    expect(
      V3CombinedCarrierCodec.encodeText(frames, maxTotalCharacters: null),
      startsWith('b3.'),
    );
  });

  test('rejects malformed count, length, trailing bytes, magic and version',
      () {
    final valid = V3CombinedCarrierCodec.encodeBinary(frames);
    final firstLength = ByteData.sublistView(valid).getUint32(5, Endian.big);
    final secondLengthOffset = 5 + 4 + firstLength;

    final malformed = <Uint8List>[
      Uint8List.fromList(valid)..[0] = 0,
      Uint8List.fromList(valid)..[3] = 2,
      Uint8List.fromList(valid)..[4] = 1,
      Uint8List.fromList(valid)..[4] = V3CombinedCarrierCodec.maxFrames + 1,
      Uint8List.fromList(valid)..fillRange(5, 9, 0),
      Uint8List.fromList(valid)..[secondLengthOffset + 3] += 1,
      Uint8List.fromList(<int>[...valid, 0]),
      Uint8List.fromList(valid.sublist(0, valid.length - 1)),
    ];
    for (final value in malformed) {
      expect(
        () => V3CombinedCarrierCodec.decodeBinary(value),
        throwsFormatException,
      );
    }
  });

  test('recognizers are cheap and do not accept unrelated carriers', () {
    expect(
        V3CombinedCarrierCodec.hasMagic(Uint8List.fromList(utf8.encode('L3B'))),
        isTrue);
    expect(
        V3CombinedCarrierCodec.hasMagic(Uint8List.fromList(utf8.encode('LM3'))),
        isFalse);
    expect(V3CombinedCarrierCodec.isTextPart('m3.payload'), isFalse);
    expect(
        V3CombinedCarrierCodec.isLinkPart('layergram://m/m3.payload'), isFalse);
    expect(V3CombinedCarrierCodec.looksLikeStegoPart('ordinary text'), isFalse);
  });
}

V3LmfFrame _frame(V3LmfFrameKind kind, int start) {
  final hybridHeader =
      kind == V3LmfFrameKind.application || kind == V3LmfFrameKind.pqRatchet
          ? V3HybridRatchetHeader(
              ecHeader: V3EcRatchetHeader(
                ratchetPublicKey: Uint8List(32)..[0] = 9,
                previousSendingChainLength: 0,
                messageCounter: start,
              ),
              sckaMessage: V3SckaMessage(
                sendingEpoch: 1,
                messageCounter: start,
                nativePayload: Uint8List(0),
              ),
            )
          : null;
  return V3LmfFrame(
    metadata: V3LmfMessageMetadata(
      kind: kind,
      senderBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, start),
      recipientBinding:
          _bytes(V3LmfFrameCodec.routingBindingBytes, start + 0x10),
      messageId: _bytes(V3LmfFrameCodec.messageIdBytes, start + 0x20),
      sessionId: _bytes(V3LmfFrameCodec.sessionIdBytes, start + 0x30),
      epoch: 1,
      messageCounter: start,
    ),
    fragmentIndex: 0,
    fragmentCount: 1,
    assembledPlaintextLength: 3,
    nonce: _bytes(V3LmfFrameCodec.nonceBytes, start + 0x40),
    ciphertext: _bytes(3, start + 0x50),
    authenticationTag:
        _bytes(V3LmfFrameCodec.authenticationTagBytes, start + 0x60),
    hybridRatchetHeader: hybridHeader,
  );
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
    List<int>.generate(length, (index) => (start + index) & 0xff));

void _expectInnerBytes(List<V3LmfFrame> actual, List<Uint8List> expected) {
  expect(actual, hasLength(expected.length));
  for (var index = 0; index < actual.length; index++) {
    expect(V3LmfFrameCodec.encodeBinary(actual[index]),
        orderedEquals(expected[index]));
  }
}
