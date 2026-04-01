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

import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;
import 'package:crypto/crypto.dart';

class SeedService {
  String generateMnemonic({int words = 24}) {
    final strength = words == 24 ? 256 : 128;
    return bip39.generateMnemonic(strength: strength);
  }

  bool validateMnemonic(String mnemonic) {
    return bip39.validateMnemonic(mnemonic.trim());
  }

  Uint8List mnemonicToSeed(String mnemonic) {
    final seedHex = bip39.mnemonicToSeedHex(mnemonic.trim());
    return Uint8List.fromList(_hexToBytes(seedHex));
  }

  Uint8List derivePrivateKey(Uint8List seed) {
    final digest = sha256.convert(seed).bytes;
    return Uint8List.fromList(digest);
  }

  List<int> _hexToBytes(String hex) {
    final out = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      out.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return out;
  }
}
