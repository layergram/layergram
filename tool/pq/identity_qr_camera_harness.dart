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

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/features/my_identity/identity_qr_code.dart';
import 'package:layergram/utils/qr_display_brightness_controller.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // This standalone test target must remain capturable for redacted evidence.
  // Production entry points still default screen protection to enabled.
  try {
    await const MethodChannel(
      'layergram/screen_protection',
    ).invokeMethod<void>('setEnabled', false);
  } on MissingPluginException {
    // The harness is also useful on platforms without the native channel.
  }
  runApp(const _QrCameraHarnessApp());
}

class _QrCameraHarnessApp extends StatelessWidget {
  const _QrCameraHarnessApp();

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      debugShowCheckedModeBanner: false,
      home: _QrCameraHarnessPage(),
    );
  }
}

enum _HarnessMode { display, scan }

class _QrCameraHarnessPage extends StatefulWidget {
  const _QrCameraHarnessPage();

  @override
  State<_QrCameraHarnessPage> createState() => _QrCameraHarnessPageState();
}

class _QrCameraHarnessPageState extends State<_QrCameraHarnessPage> {
  final Uint8List _payload = buildPhysicalQrHarnessPayload();
  final QrDisplayBrightnessController _brightness =
      QrDisplayBrightnessController();
  final MobileScannerController _scanner = MobileScannerController(
    autoStart: false,
    formats: const [BarcodeFormat.qrCode],
  );

  _HarnessMode _mode = _HarnessMode.display;
  Stopwatch? _stopwatch;
  String _result = 'Pronto';
  bool _completed = false;
  bool _handlingCapture = false;
  int _nonExactCaptures = 0;

  @override
  void initState() {
    super.initState();
    unawaited(_brightness.enhance());
  }

  @override
  void dispose() {
    unawaited(_brightness.restore());
    _scanner.dispose();
    super.dispose();
  }

  Future<void> _showQr() async {
    await _scanner.stop();
    await _brightness.enhance();
    if (!mounted) return;
    setState(() {
      _mode = _HarnessMode.display;
      _result = 'QR massimo: ${_payload.length} byte';
      _completed = false;
      _handlingCapture = false;
      _nonExactCaptures = 0;
      _stopwatch = null;
    });
  }

  Future<void> _scanQr() async {
    await _brightness.restore();
    if (!mounted) return;
    setState(() {
      _mode = _HarnessMode.scan;
      _result = 'In attesa del QR…';
      _completed = false;
      _handlingCapture = false;
      _nonExactCaptures = 0;
      _stopwatch = Stopwatch()..start();
    });
    await _scanner.start();
  }

  Future<void> _handleCapture(BarcodeCapture capture) async {
    if (_completed || _handlingCapture || capture.barcodes.isEmpty) return;
    _handlingCapture = true;
    final barcode = capture.barcodes.first;
    final decoded = switch (barcode.rawDecodedBytes) {
      DecodedBarcodeBytes(:final bytes) => bytes,
      DecodedVisionBarcodeBytes(:final bytes?) => bytes,
      _ => null,
    };
    if (decoded == null) {
      _handlingCapture = false;
      return;
    }

    final exactHarnessPayload = _constantTimeEquals(decoded, _payload);
    final validV3Identity = isPhysicalQrHarnessAcceptedPayload(
      decoded,
      expectedHarnessPayload: _payload,
    );
    if (validV3Identity) {
      _stopwatch?.stop();
      _completed = true;
      await _scanner.stop();
      if (!mounted) return;
      setState(() {
        final elapsed = _stopwatch?.elapsedMilliseconds ?? 0;
        final kind = exactHarnessPayload
            ? 'identità massima esatta'
            : 'identità v3 integra';
        _result = 'PASS — $kind — ${decoded.length} byte — $elapsed ms';
      });
      debugPrint(
        'LAYERGRAM_QR_CAMERA_PASS bytes=${decoded.length} '
        'maximum_exact=$exactHarnessPayload '
        'elapsed_ms=${_stopwatch?.elapsedMilliseconds ?? 0} '
        'non_exact=$_nonExactCaptures',
      );
      return;
    }

    _nonExactCaptures += 1;
    final firstDifference = _firstDifference(decoded, _payload);
    debugPrint(
      'LAYERGRAM_QR_CAMERA_RETRY bytes=${decoded.length} '
      'first_difference=$firstDifference attempt=$_nonExactCaptures',
    );
    if (mounted) {
      setState(() {
        _result = 'Lettura non esatta (${decoded.length} byte); '
            'continuo automaticamente…';
      });
    }
    _handlingCapture = false;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Layergram v3 — prova QR fisica')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            children: [
              SegmentedButton<_HarnessMode>(
                segments: const [
                  ButtonSegment(
                    value: _HarnessMode.display,
                    icon: Icon(Icons.qr_code_2),
                    label: Text('Mostra QR'),
                  ),
                  ButtonSegment(
                    value: _HarnessMode.scan,
                    icon: Icon(Icons.qr_code_scanner),
                    label: Text('Scansiona'),
                  ),
                ],
                selected: {_mode},
                onSelectionChanged: (selection) {
                  if (selection.single == _HarnessMode.display) {
                    _showQr();
                  } else {
                    _scanQr();
                  }
                },
              ),
              const SizedBox(height: 12),
              Expanded(
                child: switch (_mode) {
                  _HarnessMode.display => LayoutBuilder(
                      builder: (context, constraints) {
                        final side = constraints.biggest.shortestSide
                            .clamp(160.0, identityQrV3MaxPreviewSize)
                            .toDouble();
                        return Center(
                          child: IdentityQrCode(
                            data: _payload,
                            size: side,
                            color: Colors.black,
                            backgroundColor: Colors.white,
                          ),
                        );
                      },
                    ),
                  _HarnessMode.scan => ClipRRect(
                      borderRadius: BorderRadius.circular(24),
                      child: MobileScanner(
                        controller: _scanner,
                        onDetect: _handleCapture,
                      ),
                    ),
                },
              ),
              const SizedBox(height: 12),
              Semantics(
                liveRegion: true,
                child: Text(
                  _result,
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        color: _result.startsWith('PASS')
                            ? Colors.green.shade800
                            : _result.startsWith('FAIL')
                                ? Colors.red.shade800
                                : null,
                        fontWeight: FontWeight.w700,
                      ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

@visibleForTesting
Uint8List buildPhysicalQrHarnessPayload() {
  return V3PublicIdentityCodec.encodeBinary(
    V3PublicIdentity(
      x25519PublicKey: Uint8List.fromList(
        List<int>.generate(32, (index) => index + 1),
      ),
      mlKem768PublicKey: Uint8List.fromList(
        List<int>.generate(
          MlKem768.publicKeyBytes,
          (index) => (index % 251) + 1,
        ),
      ),
      displayName: 'Physical QR camera gate'.padRight(32, 'X'),
    ),
  );
}

bool _constantTimeEquals(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

int _firstDifference(Uint8List left, Uint8List right) {
  final commonLength = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < commonLength; index++) {
    if (left[index] != right[index]) return index;
  }
  return commonLength;
}

@visibleForTesting
bool isPhysicalQrHarnessAcceptedPayload(
  Uint8List decoded, {
  Uint8List? expectedHarnessPayload,
}) {
  if (expectedHarnessPayload != null &&
      _constantTimeEquals(decoded, expectedHarnessPayload)) {
    return true;
  }
  try {
    V3PublicIdentityCodec.decodeBinary(decoded);
    return true;
  } on FormatException {
    return false;
  } on ArgumentError {
    return false;
  }
}
