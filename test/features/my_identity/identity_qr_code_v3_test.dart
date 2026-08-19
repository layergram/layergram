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
    final binary = V3PublicIdentityCodec.encodeBinary(identity);

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
    expect(tester.takeException(), isNull);
  });
}
