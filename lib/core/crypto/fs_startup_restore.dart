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

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../providers.dart';
import 'aux_record_cipher.dart';
import 'fs_double_ratchet.dart';

typedef ProviderReader = T Function<T>(ProviderListenable<T> provider);

/// Restores persisted Forward Secrecy runtime state after the local identity
/// has been loaded and the auxiliary storage key can be derived.
Future<void> restorePersistedFsRuntimeState(ProviderReader read) async {
  try {
    final privateKeyB64 =
        await read(identityManagerProvider).getLocalPrivateKeyBase64();
    if (privateKeyB64 == null) {
      return;
    }

    final keyBytes = Uint8List.fromList(base64Decode(privateKeyB64));
    final auxKey = await AuxRecordCipher.deriveAuxStorageKey(keyBytes);

    final auxRepo = read(auxRecordRepositoryProvider);
    auxRepo.setActiveContext(
      scopeToken: 'primary',
      auxStorageKey: auxKey,
    );

    await read(fsStatePersistenceServiceProvider).loadPersistedState();
    await read(fsSecurityModeServiceProvider).rebuildIndex();

    final ratchetStates =
        await read(fsRatchetPersistenceServiceProvider).loadAllRatchetStates();
    final cache = <String, RatchetState>{};
    for (final state in ratchetStates) {
      cache[state.sessionId] = state;
    }
    read(fsRatchetStateCacheProvider.notifier).state = cache;
  } catch (_) {
    // Best-effort restore. If auxiliary records cannot be read with the current
    // identity key, FS will start from the normal non-restored state.
  }
}
