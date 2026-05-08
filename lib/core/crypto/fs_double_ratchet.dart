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

import 'package:cryptography/cryptography.dart';

import 'fs_key_codec.dart';

/// Signal Double Ratchet implementation for Layergram Forward Secrecy.
///
/// This follows the Signal Double Ratchet algorithm as described in
/// https://signal.org/docs/specifications/doubleratchet/ with the
/// key derivation functions adapted to the Layergram FS spec (§8.4–§8.5).
///
/// ### Key derivation functions used:
///
/// **Symmetric-key ratchet step:**
/// ```
/// messageKey    = HKDF(chainKey, salt=0x00, info="Layergram-FS-v1 message key", 32)
/// nextChainKey  = HKDF(chainKey, salt=0x01, info="Layergram-FS-v1 chain key",   32)
/// ```
///
/// **DH ratchet step (new root key + chain key pair from root HKDF):**
/// ```
/// dhOut         = DH(localRatchetPriv, remoteRatchetPub)
/// [newRoot, newChainKey] = HKDF(dhOut, salt=rootKey, info="Layergram-FS-v1 ratchet step", 64)
/// ```
///
/// **AES-GCM nonce per message** (spec §8.5.2 — never random):
/// ```
/// encKey = HKDF(messageKey, salt=0, info="Layergram-FS-v1 message key", 32)
/// nonce  = HKDF(messageKey, salt=0, info="Layergram-FS-v1 nonce",       12)
/// ```
///
/// Spec reference: §8.4, §8.5.
class FsDoubleRatchet {
  FsDoubleRatchet._();

  static final _x25519 = X25519();
  static final _hkdf32 = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  static final _hkdf64 = Hkdf(hmac: Hmac.sha256(), outputLength: 64);
  static final _hkdf12 = Hkdf(hmac: Hmac.sha256(), outputLength: 12);
  static final _aesGcm = AesGcm.with256bits();

  // Security constants.
  static const int kMaxSkippedKeys = 50;
  static const int kSkippedKeyTtlSeconds = 48 * 60 * 60; // 48 h

  // ---------------------------------------------------------------------------
  // Ratchet init
  // ---------------------------------------------------------------------------

  /// Initialises the ratchet state immediately after the FS handshake.
  ///
  /// Both parties start from the symmetric chain keys established by the
  /// handshake ([sendingChainKey0] / [receivingChainKey0]). No DH ratchet step
  /// is performed at init — the first DH ratchet step occurs automatically
  /// in [decrypt] when the first message with a new remote ratchet pub arrives.
  ///
  /// [localRatchetPriv] / [localRatchetPub] is the initial local ratchet key
  /// pair for this session. The first message from each party includes this
  /// pub key in its header so the other side can perform the DH ratchet step.
  ///
  /// [lastRemoteRatchetPub] should be set for the initiator (A) to B's
  /// initial ratchet pub if available, or null for the responder (B).
  static Future<RatchetState> initRatchet({
    required Uint8List rootKey0,
    required Uint8List sendingChainKey0,
    required Uint8List receivingChainKey0,
    required Uint8List localRatchetPriv,
    required Uint8List localRatchetPub,
    Uint8List? lastRemoteRatchetPub,
    required String sessionId,
  }) async {
    return RatchetState(
      sessionId: sessionId,
      rootKey: rootKey0,
      sendingChainKey: sendingChainKey0,
      receivingChainKey: receivingChainKey0,
      localRatchetPriv: localRatchetPriv,
      localRatchetPub: localRatchetPub,
      lastRemoteRatchetPub: lastRemoteRatchetPub,
      sendCounter: 0,
      recvCounter: 0,
      skippedKeys: {},
    );
  }

  // ---------------------------------------------------------------------------
  // Encrypt
  // ---------------------------------------------------------------------------

  /// Encrypts [plaintext] and advances the sending ratchet.
  ///
  /// Returns the [FsEncryptedMessage] (which includes the ratchet header and
  /// the encrypted payload) and the updated [RatchetState].
  ///
  /// The nonce is **always derived** from the message key — never random.
  static Future<({FsEncryptedMessage message, RatchetState newState})> encrypt({
    required RatchetState state,
    required Uint8List plaintext,
    required String sessionId,
  }) async {
    // Advance the symmetric sending chain.
    final (:messageKey, :nextChainKey) =
        await _symmetricRatchetStep(state.sendingChainKey);

    // Derive per-message AES-GCM key and nonce from messageKey.
    final encKey = await _hkdf32.deriveKey(
      secretKey: SecretKey(messageKey),
      nonce: const [0],
      info: utf8.encode('Layergram-FS-v1 message key'),
    );
    final nonceBytes = Uint8List.fromList(
      await (await _hkdf12.deriveKey(
        secretKey: SecretKey(messageKey),
        nonce: const [0],
        info: utf8.encode('Layergram-FS-v1 nonce'),
      )).extractBytes(),
    );

    final box = await _aesGcm.encrypt(
      plaintext,
      secretKey: encKey,
      nonce: nonceBytes,
    );

    final newState = state.copyWith(
      sendingChainKey: nextChainKey,
      sendCounter: state.sendCounter + 1,
    );

    _wipe(messageKey);

    return (
      message: FsEncryptedMessage(
        sessionId: sessionId,
        localRatchetPub: FsKeyCodec.encodeKey(state.localRatchetPub),
        counter: state.sendCounter,
        ciphertext: Uint8List.fromList([...box.cipherText, ...box.mac.bytes]),
        nonce: nonceBytes,
      ),
      newState: newState,
    );
  }

  // ---------------------------------------------------------------------------
  // Decrypt
  // ---------------------------------------------------------------------------

  /// Decrypts a received [FsEncryptedMessage] and advances the receiving ratchet.
  ///
  /// Handles:
  /// - normal in-order messages;
  /// - skipped messages (from the skipped-keys map);
  /// - new remote ratchet key → DH ratchet step.
  ///
  /// Returns the decrypted plaintext and updated [RatchetState].
  /// Throws [FsDecryptException] on failure.
  static Future<({Uint8List plaintext, RatchetState newState})> decrypt({
    required RatchetState state,
    required FsEncryptedMessage message,
  }) async {
    // Prune expired skipped keys first.
    final now = _nowSeconds();
    final prunedSkipped = Map<_SkippedKeyId, _SkippedEntry>.from(state.skippedKeys)
      ..removeWhere((_, v) => v.expiresAt < now);

    // Check if this is a skipped key.
    final skippedKey = _SkippedKeyId(
      ratchetPub: message.localRatchetPub,
      counter: message.counter,
    );
    final skippedEntry = prunedSkipped[skippedKey];
    if (skippedEntry != null) {
      // Decrypt with stored skipped message key.
      prunedSkipped.remove(skippedKey);
      final plain = await _decryptWithMessageKey(skippedEntry.messageKey, message);
      return (plaintext: plain, newState: state.copyWith(skippedKeys: prunedSkipped));
    }

    // Decode the new ratchet pub from the message header.
    final remoteRatchetPubBytes = FsKeyCodec.decodeKey(message.localRatchetPub);
    final isNewRatchetKey = state.lastRemoteRatchetPub == null ||
        !_bytesEqual(remoteRatchetPubBytes, state.lastRemoteRatchetPub!);

    RatchetState workingState = state.copyWith(skippedKeys: prunedSkipped);

    if (isNewRatchetKey) {
      // DH ratchet step: skip any outstanding messages on old ratchet.
      workingState = await _skipMessageKeys(
        workingState,
        remoteRatchetPub: message.localRatchetPub,
        upToCounter: message.counter,
      );

      // Perform DH ratchet step (advance receiving chain).
      final dhOut = await _dhRaw(workingState.localRatchetPriv, remoteRatchetPubBytes);
      FsKeyCodec.validateDhOutput(dhOut);

      final derived = await _rootKdf(dhOut, workingState.rootKey);
      final newRootKey = Uint8List.fromList(derived.sublist(0, 32));
      final newRecvChainKey = Uint8List.fromList(derived.sublist(32));
      _wipe(dhOut);

      // Generate a new local ratchet key pair.
      final newLocalPair = await _generateRatchetKeyPair();
      final newLocalPriv = Uint8List.fromList(await newLocalPair.extractPrivateKeyBytes());
      final newLocalPubKey = await newLocalPair.extractPublicKey() as SimplePublicKey;
      final newLocalPub = Uint8List.fromList(newLocalPubKey.bytes);

      // DH ratchet step again with the new local key → advance sending chain.
      final dhOut2 = await _dhRaw(newLocalPriv, remoteRatchetPubBytes);
      FsKeyCodec.validateDhOutput(dhOut2);
      final derived2 = await _rootKdf(dhOut2, newRootKey);
      final newRootKey2 = Uint8List.fromList(derived2.sublist(0, 32));
      final newSendChainKey = Uint8List.fromList(derived2.sublist(32));
      _wipe(dhOut2);

      workingState = workingState.copyWith(
        rootKey: newRootKey2,
        sendingChainKey: newSendChainKey,
        receivingChainKey: newRecvChainKey,
        localRatchetPriv: newLocalPriv,
        localRatchetPub: newLocalPub,
        lastRemoteRatchetPub: remoteRatchetPubBytes,
        recvCounter: 0,
      );
    } else {
      // Same ratchet key: skip intermediate messages if counter jumped.
      if (message.counter > workingState.recvCounter) {
        workingState = await _skipMessageKeys(
          workingState,
          remoteRatchetPub: message.localRatchetPub,
          upToCounter: message.counter,
        );
      }
    }

    // Advance the receiving symmetric ratchet one step.
    final (:messageKey, :nextChainKey) =
        await _symmetricRatchetStep(workingState.receivingChainKey);
    final plain = await _decryptWithMessageKey(messageKey, message);
    _wipe(messageKey);

    final finalState = workingState.copyWith(
      receivingChainKey: nextChainKey,
      recvCounter: message.counter + 1,
    );

    return (plaintext: plain, newState: finalState);
  }

  // ---------------------------------------------------------------------------
  // Internal ratchet helpers
  // ---------------------------------------------------------------------------

  static Future<RatchetState> _skipMessageKeys(
    RatchetState state, {
    required String remoteRatchetPub,
    required int upToCounter,
  }) async {
    if (upToCounter <= state.recvCounter) return state;
    if (upToCounter - state.recvCounter > kMaxSkippedKeys) {
      throw FsDecryptException(
        'Too many skipped messages: ${upToCounter - state.recvCounter} > $kMaxSkippedKeys',
      );
    }

    final skipped = Map<_SkippedKeyId, _SkippedEntry>.from(state.skippedKeys);
    var chainKey = state.receivingChainKey;
    var counter = state.recvCounter;
    final expiresAt = _nowSeconds() + kSkippedKeyTtlSeconds;

    while (counter < upToCounter) {
      final (:messageKey, :nextChainKey) = await _symmetricRatchetStep(chainKey);
      skipped[_SkippedKeyId(ratchetPub: remoteRatchetPub, counter: counter)] =
          _SkippedEntry(messageKey: messageKey, expiresAt: expiresAt);
      chainKey = nextChainKey;
      counter++;
    }

    return state.copyWith(
      receivingChainKey: chainKey,
      recvCounter: counter,
      skippedKeys: skipped,
    );
  }

  /// One symmetric ratchet step: derive message key and next chain key.
  static Future<({Uint8List messageKey, Uint8List nextChainKey})>
      _symmetricRatchetStep(Uint8List chainKey) async {
    final msgKey = Uint8List.fromList(await (await _hkdf32.deriveKey(
      secretKey: SecretKey(chainKey),
      nonce: const [0x00],
      info: utf8.encode('Layergram-FS-v1 message key'),
    )).extractBytes());

    final nextKey = Uint8List.fromList(await (await _hkdf32.deriveKey(
      secretKey: SecretKey(chainKey),
      nonce: const [0x01],
      info: utf8.encode('Layergram-FS-v1 chain key'),
    )).extractBytes());

    return (messageKey: msgKey, nextChainKey: nextKey);
  }

  /// DH ratchet KDF: derives [newRootKey || newChainKey] (64 bytes).
  static Future<Uint8List> _rootKdf(
    Uint8List dhOutput,
    Uint8List rootKey,
  ) async {
    final derived = await _hkdf64.deriveKey(
      secretKey: SecretKey(dhOutput),
      nonce: rootKey,
      info: utf8.encode('Layergram-FS-v1 ratchet step'),
    );
    return Uint8List.fromList(await derived.extractBytes());
  }

  static Future<Uint8List> _decryptWithMessageKey(
    Uint8List messageKey,
    FsEncryptedMessage message,
  ) async {
    final encKey = await _hkdf32.deriveKey(
      secretKey: SecretKey(messageKey),
      nonce: const [0],
      info: utf8.encode('Layergram-FS-v1 message key'),
    );
    final nonceBytes = message.nonce;
    final ciphertext = message.ciphertext.sublist(0, message.ciphertext.length - 16);
    final mac = Mac(message.ciphertext.sublist(message.ciphertext.length - 16));
    final box = SecretBox(ciphertext, nonce: nonceBytes, mac: mac);
    try {
      final plain = await _aesGcm.decrypt(box, secretKey: encKey);
      return Uint8List.fromList(plain);
    } catch (_) {
      throw const FsDecryptException('AES-GCM authentication failed');
    }
  }

  static Future<Uint8List> _dhRaw(Uint8List localPriv, Uint8List remotePub) async {
    final localPublic = await _x25519
        .newKeyPairFromSeed(localPriv)
        .then((p) => p.extractPublicKey());
    final localPair = SimpleKeyPairData(
      localPriv,
      type: KeyPairType.x25519,
      publicKey: localPublic,
    );
    final remote = SimplePublicKey(remotePub, type: KeyPairType.x25519);
    final shared = await _x25519.sharedSecretKey(
      keyPair: localPair,
      remotePublicKey: remote,
    );
    return Uint8List.fromList(await shared.extractBytes());
  }

  static Future<SimpleKeyPair> _generateRatchetKeyPair() => _x25519.newKeyPair();

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static void _wipe(List<int> bytes) {
    if (bytes is Uint8List) {
      for (var i = 0; i < bytes.length; i++) bytes[i] = 0;
    }
  }

  static int _nowSeconds() =>
      DateTime.now().millisecondsSinceEpoch ~/ 1000;
}

// ---------------------------------------------------------------------------
// Ratchet state
// ---------------------------------------------------------------------------

/// Immutable snapshot of the Double Ratchet state for one FS session.
///
/// Persisted as an aux record between messages.
class RatchetState {
  const RatchetState({
    required this.sessionId,
    required this.rootKey,
    required this.sendingChainKey,
    required this.receivingChainKey,
    required this.localRatchetPriv,
    required this.localRatchetPub,
    required this.lastRemoteRatchetPub,
    required this.sendCounter,
    required this.recvCounter,
    required this.skippedKeys,
  });

  final String sessionId;
  final Uint8List rootKey;
  final Uint8List sendingChainKey;
  final Uint8List receivingChainKey;
  final Uint8List localRatchetPriv;
  final Uint8List localRatchetPub;
  final Uint8List? lastRemoteRatchetPub;
  final int sendCounter;
  final int recvCounter;
  final Map<_SkippedKeyId, _SkippedEntry> skippedKeys;

  RatchetState copyWith({
    Uint8List? rootKey,
    Uint8List? sendingChainKey,
    Uint8List? receivingChainKey,
    Uint8List? localRatchetPriv,
    Uint8List? localRatchetPub,
    Uint8List? lastRemoteRatchetPub,
    int? sendCounter,
    int? recvCounter,
    Map<_SkippedKeyId, _SkippedEntry>? skippedKeys,
  }) =>
      RatchetState(
        sessionId: sessionId,
        rootKey: rootKey ?? this.rootKey,
        sendingChainKey: sendingChainKey ?? this.sendingChainKey,
        receivingChainKey: receivingChainKey ?? this.receivingChainKey,
        localRatchetPriv: localRatchetPriv ?? this.localRatchetPriv,
        localRatchetPub: localRatchetPub ?? this.localRatchetPub,
        lastRemoteRatchetPub: lastRemoteRatchetPub ?? this.lastRemoteRatchetPub,
        sendCounter: sendCounter ?? this.sendCounter,
        recvCounter: recvCounter ?? this.recvCounter,
        skippedKeys: skippedKeys ?? this.skippedKeys,
      );
}

// ---------------------------------------------------------------------------
// Message header
// ---------------------------------------------------------------------------

/// The FS-encrypted message including ratchet header and ciphertext.
class FsEncryptedMessage {
  const FsEncryptedMessage({
    required this.sessionId,
    required this.localRatchetPub,
    required this.counter,
    required this.ciphertext,
    required this.nonce,
  });

  final String sessionId;
  final String localRatchetPub;
  final int counter;
  final Uint8List ciphertext;
  final Uint8List nonce;
}

// ---------------------------------------------------------------------------
// Skipped key storage
// ---------------------------------------------------------------------------

class _SkippedKeyId {
  const _SkippedKeyId({required this.ratchetPub, required this.counter});
  final String ratchetPub;
  final int counter;

  @override
  bool operator ==(Object other) =>
      other is _SkippedKeyId &&
      other.ratchetPub == ratchetPub &&
      other.counter == counter;

  @override
  int get hashCode => Object.hash(ratchetPub, counter);
}

class _SkippedEntry {
  const _SkippedEntry({required this.messageKey, required this.expiresAt});
  final Uint8List messageKey;
  final int expiresAt;
}

// ---------------------------------------------------------------------------
// Exception
// ---------------------------------------------------------------------------

class FsDecryptException implements Exception {
  const FsDecryptException(this.message);
  final String message;

  @override
  String toString() => 'FsDecryptException: $message';
}
