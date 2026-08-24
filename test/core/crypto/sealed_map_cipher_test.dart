import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/sealed_map_cipher.dart';

void main() {
  test('key derivation preserves caller ownership and stays deterministic',
      () async {
    final input = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final originalInput = Uint8List.fromList(input);

    final first = await SealedMapCipher.deriveKey(
      input,
      scope: 'identity-a',
      info: 'storage-a',
    );
    final second = await SealedMapCipher.deriveKey(
      input,
      scope: 'identity-a',
      info: 'storage-a',
    );
    addTearDown(first.destroy);
    addTearDown(second.destroy);

    expect(input, originalInput);
    expect(await first.extractBytes(), await second.extractBytes());
    expect(await first.extractBytes(), hasLength(32));
  });
}
