import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/application_payload_v3.dart';

void main() {
  test('AP3 round-trips every user-message option canonically', () {
    final payload = V3ApplicationPayload(
      messageId: _bytes(16, 0x11),
      senderIdentityDigest: _bytes(48, 0x31),
      recipientIdentityDigest: _bytes(48, 0x71),
      text: 'Messaggio post-quantum 🔒',
      timestampUnixSeconds: 1770000000,
      senderDisplayName: 'Alice',
      expireAfterUnixSeconds: 1770003600,
      deleteAfterRead: true,
      backupExcluded: true,
    );

    final encoded = V3ApplicationPayloadCodec.encode(payload);
    final decoded = V3ApplicationPayloadCodec.decode(encoded);

    expect(decoded.stableMessageId, payload.stableMessageId);
    expect(decoded.senderIdentityDigest, payload.senderIdentityDigest);
    expect(decoded.recipientIdentityDigest, payload.recipientIdentityDigest);
    expect(decoded.text, payload.text);
    expect(decoded.timestampUnixSeconds, payload.timestampUnixSeconds);
    expect(decoded.senderDisplayName, payload.senderDisplayName);
    expect(decoded.expireAfterUnixSeconds, payload.expireAfterUnixSeconds);
    expect(decoded.deleteAfterRead, isTrue);
    expect(decoded.backupExcluded, isTrue);
    expect(V3ApplicationPayloadCodec.encode(decoded), encoded);
  });

  test('AP3 rejects non-canonical flags, lengths, UTF-8 and empty text', () {
    final valid = V3ApplicationPayloadCodec.encode(
      V3ApplicationPayload(
        messageId: _bytes(16, 0x11),
        senderIdentityDigest: _bytes(48, 0x31),
        recipientIdentityDigest: _bytes(48, 0x71),
        text: 'x',
        timestampUnixSeconds: 1770000000,
      ),
    );

    final flags = Uint8List.fromList(valid)..[4] = 0x80;
    expect(
      () => V3ApplicationPayloadCodec.decode(flags),
      throwsFormatException,
    );

    final totalLength = Uint8List.fromList(valid)..[11] ^= 1;
    expect(
      () => V3ApplicationPayloadCodec.decode(totalLength),
      throwsFormatException,
    );

    final malformedUtf8 = Uint8List.fromList(valid)..[144] = 0xff;
    expect(
      () => V3ApplicationPayloadCodec.decode(malformedUtf8),
      throwsFormatException,
    );

    expect(
      () => V3ApplicationPayload(
        messageId: _bytes(16, 0x11),
        senderIdentityDigest: _bytes(48, 0x31),
        recipientIdentityDigest: _bytes(48, 0x71),
        text: '',
        timestampUnixSeconds: 1770000000,
      ),
      throwsArgumentError,
    );
  });

  test('AP3 accepts the exact maximum encoded payload', () {
    final text = 'a' * V3ApplicationPayloadCodec.maxTextBytes;
    final encoded = V3ApplicationPayloadCodec.encode(
      V3ApplicationPayload(
        messageId: _bytes(16, 0x11),
        senderIdentityDigest: _bytes(48, 0x31),
        recipientIdentityDigest: _bytes(48, 0x71),
        text: text,
        timestampUnixSeconds: 1770000000,
        senderDisplayName: 'n' * V3ApplicationPayloadCodec.maxDisplayNameBytes,
      ),
    );
    expect(encoded, hasLength(V3ApplicationPayloadCodec.maxEncodedBytes));
    expect(V3ApplicationPayloadCodec.decode(encoded).text, text);
  });
}

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );
