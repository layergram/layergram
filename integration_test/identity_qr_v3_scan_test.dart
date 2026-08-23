import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/features/my_identity/identity_qr_code.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('native scanner decodes the maximum branded v3 identity exactly',
      (tester) async {
    final identity = V3PublicIdentity(
      x25519PublicKey: Uint8List.fromList(
        List<int>.generate(32, (index) => index + 1),
      ),
      mlKem768PublicKey: Uint8List.fromList(
        List<int>.generate(
          MlKem768.publicKeyBytes,
          (index) => (index % 251) + 1,
        ),
      ),
      displayName: 'A' * 32,
    );
    final payload = V3PublicIdentityCodec.encodeBinary(identity);
    expect(payload, hasLength(V3PublicIdentityCodec.maxBinaryBytes));

    final directory = await getTemporaryDirectory();
    await directory.create(recursive: true);
    final controller = MobileScannerController(
      autoStart: false,
      formats: const [BarcodeFormat.qrCode],
    );
    final files = <File>[];
    try {
      for (final pixelSize in const [1024, 768]) {
        final png = await renderIdentityQrPng(payload, pixelSize: pixelSize);
        expect(png, isNotNull, reason: '$pixelSize px render failed');
        expect(png, isNotEmpty, reason: '$pixelSize px render was empty');

        final file = File(
          '${directory.path}/layergram-v3-branded-identity-$pixelSize.png',
        );
        files.add(file);
        await file.writeAsBytes(png!, flush: true);
        final capture = await controller.analyzeImage(
          file.path,
          formats: const [BarcodeFormat.qrCode],
        );
        expect(capture, isNotNull, reason: '$pixelSize px QR was not detected');
        expect(
          capture!.barcodes,
          isNotEmpty,
          reason: '$pixelSize px QR had no decoded barcode',
        );

        final barcode = capture.barcodes.first;
        final decoded = switch (barcode.rawDecodedBytes) {
          DecodedBarcodeBytes(:final bytes) => bytes,
          DecodedVisionBarcodeBytes(:final bytes?) => bytes,
          _ => null,
        };
        expect(
          decoded,
          isNotNull,
          reason: '$pixelSize px QR did not expose binary bytes',
        );
        expect(
          decoded,
          orderedEquals(payload),
          reason: '$pixelSize px QR changed the identity payload',
        );
      }
    } finally {
      await controller.dispose();
      for (final file in files) {
        if (await file.exists()) await file.delete();
      }
    }
  });
}
