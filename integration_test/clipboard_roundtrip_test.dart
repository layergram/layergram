import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:layergram/core/crypto/stego_decoder.dart';
import 'package:layergram/core/crypto/stego_encoder.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('system clipboard preserves a generated cover message',
      (tester) async {
    final originalClipboard = await Clipboard.getData(Clipboard.kTextPlain);
    addTearDown(() async {
      await Clipboard.setData(
        ClipboardData(text: originalClipboard?.text ?? ''),
      );
    });

    final payload = Uint8List.fromList(List<int>.generate(44, (i) => i));
    const cover =
        'Sto preparando qualcosa di semplice per cena e poi ti aggiorno. '
        'Preparo qualcosa di semplice. Poi ti aggiorno con calma. Ci sentiamo '
        'dopo cena. Certo, ti scrivo appena riesco a controllare meglio la '
        'situazione.';
    final encoded = StegoEncoder().encodeBytes(cover, payload);

    await Clipboard.setData(ClipboardData(text: encoded));
    final copied = await Clipboard.getData(Clipboard.kTextPlain);

    expect(copied?.text, encoded);
    expect(
      StegoDecoder().decodeByteCandidates(copied!.text!).first,
      payload,
    );
  });
}
