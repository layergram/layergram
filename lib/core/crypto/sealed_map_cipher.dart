import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

class SealedMapCipher {
  static final _algo = AesGcm.with256bits();
  static final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  static Future<SecretKey> deriveKey(
    Uint8List keyMaterial, {
    required String scope,
    required String info,
  }) async {
    return _hkdf.deriveKey(
      secretKey: SecretKey(keyMaterial),
      nonce: utf8.encode(scope),
      info: utf8.encode(info),
    );
  }

  static Future<String> encrypt({
    required Map<String, dynamic> record,
    required SecretKey key,
  }) async {
    final nonce = _algo.newNonce();
    final box = await _algo.encrypt(
      utf8.encode(jsonEncode(record)),
      secretKey: key,
      nonce: nonce,
    );
    final blob = Uint8List.fromList([
      ...nonce,
      ...box.cipherText,
      ...box.mac.bytes,
    ]);
    return base64Url.encode(blob).replaceAll('=', '');
  }

  static Future<Map<String, dynamic>?> decrypt({
    required String encryptedRecord,
    required SecretKey key,
  }) async {
    try {
      final blob = Uint8List.fromList(
        base64Url.decode(_padBase64(encryptedRecord)),
      );
      if (blob.length < 28) return null;
      final nonce = blob.sublist(0, 12);
      final mac = Mac(blob.sublist(blob.length - 16));
      final cipher = blob.sublist(12, blob.length - 16);
      final box = SecretBox(cipher, nonce: nonce, mac: mac);
      final clear = await _algo.decrypt(box, secretKey: key);
      final decoded = jsonDecode(utf8.decode(clear));
      if (decoded is! Map) return null;
      return decoded.cast<String, dynamic>();
    } catch (_) {
      return null;
    }
  }

  static String _padBase64(String input) {
    final rem = input.length % 4;
    if (rem == 0) return input;
    return input.padRight(input.length + (4 - rem), '=');
  }
}
