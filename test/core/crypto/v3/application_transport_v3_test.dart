import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/application_transport_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';

void main() {
  test('one exact frame round-trips through text, link and steganography',
      () async {
    final frame = await _frame();
    final text = V3ApplicationTransport.encodeText(frame);
    final link = V3ApplicationTransport.encodeLink(frame);
    final stego = V3ApplicationTransport.encodeStego(
      frame: frame,
      coverText: 'Ci vediamo domani alle nove. ' * 6,
    );

    expect(text.length, lessThanOrEqualTo(4000));
    expect(link.length, lessThanOrEqualTo(4000));
    expect(stego.length, lessThanOrEqualTo(4000));
    _expectExact(frame, V3ApplicationTransport.decode(text).frame);
    _expectExact(frame, V3ApplicationTransport.decode(link).frame);
    _expectExact(frame, V3ApplicationTransport.decode(stego).frame);
    expect(
      V3ApplicationTransport.decode(text).kind,
      V3ApplicationCarrierKind.text,
    );
    expect(
      V3ApplicationTransport.decode(link).kind,
      V3ApplicationCarrierKind.link,
    );
    expect(
      V3ApplicationTransport.decode(stego).kind,
      V3ApplicationCarrierKind.steganography,
    );
  });

  test('oversized carrier input fails before parsing', () {
    expect(
      () => V3ApplicationTransport.decodeText('m3.${'a' * 4000}'),
      throwsFormatException,
    );
    expect(
      () => V3ApplicationTransport.decodeLink(
        'layergram://m/m3.${'a' * 4000}',
      ),
      throwsFormatException,
    );
  });
}

Future<V3LmfFrame> _frame() async {
  final key = SecretKeyData(_bytes(32, 0x11));
  try {
    return await V3LmfAead.sealSingle(
      metadata: V3LmfMessageMetadata(
        kind: V3LmfFrameKind.acknowledgement,
        senderBinding: _bytes(32, 0x31),
        recipientBinding: _bytes(32, 0x51),
        messageId: _bytes(16, 0x71),
        sessionId: _bytes(16, 0x91),
        epoch: 1,
        messageCounter: 2,
      ),
      plaintext: _bytes(52, 0xb1),
      secretKey: key,
      nonce: _bytes(12, 0xe1),
    );
  } finally {
    key.destroy();
  }
}

void _expectExact(V3LmfFrame left, V3LmfFrame right) {
  expect(
    V3LmfFrameCodec.encodeBinary(right),
    orderedEquals(V3LmfFrameCodec.encodeBinary(left)),
  );
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );
