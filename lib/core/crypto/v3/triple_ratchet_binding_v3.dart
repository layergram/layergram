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

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'triple_ratchet_state_v3.dart';

final List<int> _bindingDomain = utf8.encode(
  'layergram/v3/triple-ratchet/prior-snapshot\u0000',
);

/// Returns a domain-separated binding for one exact canonical TR3 snapshot.
///
/// The binding is candidate-local metadata, not a persisted authentication
/// mechanism. It prevents independently created EC and PQ transitions from
/// being combined when they originate from different same-revision forks.
Uint8List v3TripleRatchetPriorSnapshotBinding(
  V3TripleRatchetState snapshot,
) {
  final encoded = V3TripleRatchetStateCodec.encode(snapshot);
  final input = Uint8List(_bindingDomain.length + encoded.length)
    ..setRange(0, _bindingDomain.length, _bindingDomain)
    ..setRange(
        _bindingDomain.length, _bindingDomain.length + encoded.length, encoded);
  try {
    return Uint8List.fromList(crypto.sha256.convert(input).bytes);
  } finally {
    _wipe(input);
    _wipe(encoded);
  }
}

void _wipe(Uint8List value) => value.fillRange(0, value.length, 0);
