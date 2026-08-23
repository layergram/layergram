// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

const identityQrLogoAsset = 'assets/icons/app_icon.png';
const identityQrLogoScale = 0.20;
const identityQrV3LogoScale = 0.075;
const identityQrV3QuietZoneModules = 4;
const identityQrV3MaxPreviewSize = 420.0;
const identityQrErrorCorrectionLevel = QrErrorCorrectLevel.H;

class IdentityQrCode extends StatelessWidget {
  const IdentityQrCode({
    required this.data,
    required this.size,
    required this.color,
    this.backgroundColor = Colors.transparent,
    super.key,
  });

  /// Legacy identities use a text payload. Protocol v3 uses canonical binary
  /// bytes so the complete ML-KEM public key still fits one static QR.
  final Object data;
  final double size;
  final Color color;
  final Color backgroundColor;

  @override
  Widget build(BuildContext context) {
    if (data case final Uint8List binary) {
      final qr = QrCode.fromUint8List(
        data: binary,
        errorCorrectLevel: identityQrErrorCorrectionLevel,
      );
      final quietZone = _quietZoneForSize(size, qr.moduleCount);
      final qrSize = size - (quietZone * 2);
      return SizedBox.square(
        dimension: size,
        child: ColoredBox(
          color: backgroundColor == Colors.transparent
              ? Colors.white
              : backgroundColor,
          child: Padding(
            padding: EdgeInsets.all(quietZone),
            child: Stack(
              fit: StackFit.expand,
              children: [
                CustomPaint(
                  painter: QrPainter.withQr(
                    qr: qr,
                    gapless: true,
                    eyeStyle: QrEyeStyle(
                      eyeShape: QrEyeShape.square,
                      color: color,
                    ),
                    dataModuleStyle: QrDataModuleStyle(
                      dataModuleShape: QrDataModuleShape.square,
                      color: color,
                    ),
                  ),
                ),
                Center(
                  child: SizedBox.square(
                    key: const ValueKey('identity-v3-qr-logo'),
                    dimension: qrSize * identityQrV3LogoScale,
                    child: Image.asset(
                      identityQrLogoAsset,
                      fit: BoxFit.contain,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      );
    }
    return QrImageView(
      data: data as String,
      size: size,
      errorCorrectionLevel: identityQrErrorCorrectionLevel,
      eyeStyle: QrEyeStyle(eyeShape: QrEyeShape.square, color: color),
      dataModuleStyle: QrDataModuleStyle(
        dataModuleShape: QrDataModuleShape.square,
        color: color,
      ),
      backgroundColor: backgroundColor,
      embeddedImage: const AssetImage(identityQrLogoAsset),
      embeddedImageStyle: QrEmbeddedImageStyle(
        size: Size.square(size * identityQrLogoScale),
      ),
    );
  }
}

Future<Uint8List?> renderIdentityQrPng(
  Object data, {
  int pixelSize = 1024,
  AssetBundle? assetBundle,
}) async {
  ui.Codec? codec;
  ui.Image? logoImage;

  try {
    final logoData =
        await (assetBundle ?? rootBundle).load(identityQrLogoAsset);
    final logoBytes = logoData.buffer.asUint8List(
      logoData.offsetInBytes,
      logoData.lengthInBytes,
    );
    codec = await ui.instantiateImageCodec(logoBytes);
    final frame = await codec.getNextFrame();
    logoImage = frame.image;

    late final QrPainter painter;
    var quietZone = 0.0;
    var qrPixelSize = pixelSize.toDouble();
    if (data case final Uint8List binary) {
      final qr = QrCode.fromUint8List(
        data: binary,
        errorCorrectLevel: identityQrErrorCorrectionLevel,
      );
      quietZone = _quietZoneForSize(pixelSize.toDouble(), qr.moduleCount);
      qrPixelSize -= quietZone * 2;
      painter = QrPainter.withQr(
        qr: qr,
        gapless: true,
        eyeStyle: const QrEyeStyle(
          eyeShape: QrEyeShape.square,
          color: Colors.black,
        ),
        dataModuleStyle: const QrDataModuleStyle(
          dataModuleShape: QrDataModuleShape.square,
          color: Colors.black,
        ),
        embeddedImage: logoImage,
        embeddedImageStyle: QrEmbeddedImageStyle(
          size: Size.square(qrPixelSize * identityQrV3LogoScale),
        ),
      );
    } else {
      painter = QrPainter(
        data: data as String,
        version: QrVersions.auto,
        errorCorrectionLevel: identityQrErrorCorrectionLevel,
        gapless: true,
        eyeStyle: const QrEyeStyle(
          eyeShape: QrEyeShape.square,
          color: Colors.black,
        ),
        dataModuleStyle: const QrDataModuleStyle(
          dataModuleShape: QrDataModuleShape.square,
          color: Colors.black,
        ),
        embeddedImage: logoImage,
        embeddedImageStyle: QrEmbeddedImageStyle(
          size: Size.square(pixelSize * identityQrLogoScale),
        ),
      );
    }
    final size = Size.square(pixelSize.toDouble());
    final recorder = ui.PictureRecorder();
    final canvas = Canvas(recorder);
    canvas.drawRect(Offset.zero & size, Paint()..color = Colors.white);
    canvas.save();
    canvas.translate(quietZone, quietZone);
    painter.paint(canvas, Size.square(qrPixelSize));
    canvas.restore();
    final picture = recorder.endRecording();
    final image = await picture.toImage(pixelSize, pixelSize);
    try {
      final byteData = await image.toByteData(format: ui.ImageByteFormat.png);
      return byteData?.buffer.asUint8List();
    } finally {
      image.dispose();
      picture.dispose();
    }
  } finally {
    logoImage?.dispose();
    codec?.dispose();
  }
}

double _quietZoneForSize(double size, int moduleCount) {
  return size *
      identityQrV3QuietZoneModules /
      (moduleCount + (identityQrV3QuietZoneModules * 2));
}
