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

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/public_identity_v3.dart';
import 'package:layergram/features/my_identity/identity_qr_code.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const _QrPngExporter());
}

class _QrPngExporter extends StatefulWidget {
  const _QrPngExporter();

  @override
  State<_QrPngExporter> createState() => _QrPngExporterState();
}

class _QrPngExporterState extends State<_QrPngExporter> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _export());
  }

  Future<void> _export() async {
    try {
      final png = await renderIdentityQrPng(
        _maximumV3Identity(),
        pixelSize: 1024,
      );
      if (png == null || png.isEmpty) {
        throw StateError('The production QR renderer returned no PNG bytes');
      }
      // The macOS runner is sandboxed, so write into its real temporary
      // directory. The calling print-gate script copies this disposable file
      // into the workspace before composing the PDF.
      final output = File(
        '${Directory.systemTemp.path}/layergram-v3-max-identity-export-1024.png',
      );
      await output.parent.create(recursive: true);
      await output.writeAsBytes(png, flush: true);
      stdout.writeln('created=${output.absolute.path} bytes=${png.length}');
      exit(0);
    } catch (error, stackTrace) {
      stderr.writeln(error);
      stderr.writeln(stackTrace);
      exitCode = 1;
      exit(1);
    }
  }

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        body: Center(child: Text('Exporting Layergram v3 QR PNG...')),
      ),
    );
  }
}

Uint8List _maximumV3Identity() {
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
