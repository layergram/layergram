import 'dart:ui' as ui;
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/features/my_identity/identity_qr_code.dart';
import 'package:qr_flutter/qr_flutter.dart';

void main() {
  testWidgets('complete binary v3 identity renders as one static QR',
      (tester) async {
    final binary = _maximumIdentityBytes();

    await tester.pumpWidget(
      MaterialApp(
        home: IdentityQrCode(
          data: binary,
          size: 320,
          color: Colors.black,
          backgroundColor: Colors.white,
        ),
      ),
    );

    expect(binary, hasLength(V3PublicIdentityCodec.maxBinaryBytes));
    expect(
      find.byWidgetPredicate(
        (widget) => widget is CustomPaint && widget.painter is QrPainter,
      ),
      findsOneWidget,
    );
    final logo = find.byKey(const ValueKey('identity-v3-qr-logo'));
    expect(logo, findsOneWidget);
    final logoSize = tester.getSize(logo);
    expect(logoSize.width, closeTo(23.0, 0.2));
    expect(logoSize.height, closeTo(23.0, 0.2));
    expect(tester.takeException(), isNull);
  });

  testWidgets('maximum binary v3 PNG has logo and a four-module quiet zone',
      (tester) async {
    final result = await tester.runAsync(() async {
      final png = await renderIdentityQrPng(
        _maximumIdentityBytes(),
        pixelSize: 1024,
      );
      if (png == null || png.isEmpty) return null;

      final codec = await ui.instantiateImageCodec(png);
      final frame = await codec.getNextFrame();
      final image = frame.image;
      try {
        final rgba = await image.toByteData(format: ui.ImageByteFormat.rawRgba);
        if (rgba == null) return null;

        var brandedPixelCount = 0;
        var nonWhiteQuietZonePixels = 0;
        for (var y = 0; y < image.height; y++) {
          for (var x = 0; x < image.width; x++) {
            final offset = (y * image.width + x) * 4;
            final red = rgba.getUint8(offset);
            final green = rgba.getUint8(offset + 1);
            final blue = rgba.getUint8(offset + 2);
            if (x >= 450 && x < 574 && y >= 450 && y < 574) {
              final isLayergramCyan =
                  blue > 120 && green > 100 && blue > red * 1.5;
              if (isLayergramCyan) brandedPixelCount++;
            }
            if ((x < 16 || x >= 1008 || y < 16 || y >= 1008) &&
                (red < 250 || green < 250 || blue < 250)) {
              nonWhiteQuietZonePixels++;
            }
          }
        }

        return (
          width: image.width,
          height: image.height,
          brandedPixelCount: brandedPixelCount,
          nonWhiteQuietZonePixels: nonWhiteQuietZonePixels,
        );
      } finally {
        image.dispose();
        codec.dispose();
      }
    });

    expect(result, isNotNull);
    expect(result!.width, 1024);
    expect(result.height, 1024);
    expect(result.brandedPixelCount, greaterThan(200));
    expect(result.nonWhiteQuietZonePixels, 0);
  });
}

Uint8List _maximumIdentityBytes() {
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
  return V3PublicIdentityCodec.encodeBinary(identity);
}
