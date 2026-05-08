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
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'fs_key_codec.dart';

/// Layergram Interactive Authenticated DH Handshake v1.
///
/// Protocol overview (spec §8.3):
///
/// 1. Initiator A sends FS_INIT: publishes DK_A_pub, EK_A_pub, initId, caps.
/// 2. Responder B processes FS_INIT, generates EK_B, sends FS_REPLY: replyId,
///    DK_B_pub, EK_B_pub, caps.
/// 3. Both sides compute 5 DH operations and derive initialRootSecret (64 b).
/// 4. Initiator A sends FS_CONFIRM: transcriptHash + confirmTag.
/// 5. B verifies confirmTag → session active.
///
/// Intentional design note (spec §8.3.7):
///   DH(IK_A, IK_B) is NOT included. Identity authentication is provided by
///   DH1 = DH(IK_A_priv, DK_B_pub) and DH2 = DH(DK_A_priv, IK_B_pub), which
///   cross-bind identity keys to device keys on both sides.
///   This divergence from a pure X3DH must be preserved as documented.
///
/// Spec reference: §8.3, §8.4, §8.5.
class FsHandshake {
  FsHandshake._();

  static final _x25519 = X25519();
  static final _hkdf64 = Hkdf(hmac: Hmac.sha256(), outputLength: 64);
  static final _hkdf32 = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  static final _hmac = Hmac.sha256();
  static final Random _rng = Random.secure();

  // ---------------------------------------------------------------------------
  // Public entry points
  // ---------------------------------------------------------------------------

  /// Generates the FS_INIT handshake message.
  ///
  /// [ikAPriv] = identity private key of the initiator (A).
  /// [dkAPriv] = device private key of the initiator (A).
  ///
  /// Returns [FsInitPayload] which includes the fields to embed in `x.fs`
  /// and the ephemeral private key [ekAPriv] that must be stored securely
  /// until [completeHandshakeAsInitiator] is called.
  static Future<FsInitPayload> generateFsInit({
    required Uint8List ikAPriv,
    required Uint8List dkAPriv,
    List<String> caps = const ['lgfs1', 'dr1'],
  }) async {
    final ekAPair = await _x25519.newKeyPair();
    final ekAPrivBytes = Uint8List.fromList(
      await (await ekAPair.extractPrivateKeyBytes()),
    );
    final ekAPub = await ekAPair.extractPublicKey();
    final ekAPubBytes = Uint8List.fromList(ekAPub.bytes);

    final dkAPub = await _publicKeyFromPriv(dkAPriv);
    final initId = _randomBase64Url(16);

    return FsInitPayload(
      initId: initId,
      initiatorDevicePub: FsKeyCodec.encodeKey(dkAPub),
      initiatorEphemeralPub: FsKeyCodec.encodeKey(ekAPubBytes),
      caps: List.unmodifiable(caps),
      createdAt: _nowSeconds(),
      ekAPrivBytes: ekAPrivBytes,
    );
  }

  /// Processes a received FS_INIT as the responder (B) and generates FS_REPLY.
  ///
  /// [ikBPriv] = identity private key of the responder.
  /// [dkBPriv] = device private key of the responder.
  /// [init] = the validated [FsInitMessage] received from A.
  ///
  /// Returns [FsReplyPayload] with the fields for `x.fs` and the intermediate
  /// state [FsHandshakePartialState] needed to derive the session after A's
  /// FS_CONFIRM arrives.
  static Future<FsReplyPayload> processFsInitAsResponder({
    required Uint8List ikBPriv,
    required Uint8List dkBPriv,
    required Uint8List ikAPub,
    required FsInitMessage init,
    List<String> caps = const ['lgfs1', 'dr1'],
  }) async {
    // Decode and validate initiator's public keys.
    final dkAPubBytes = FsKeyCodec.decodeKey(init.initiatorDevicePub);
    final ekAPubBytes = FsKeyCodec.decodeKey(init.initiatorEphemeralPub);

    // Generate responder's ephemeral key pair.
    final ekBPair = await _x25519.newKeyPair();
    final ekBPrivBytes = Uint8List.fromList(
      await (await ekBPair.extractPrivateKeyBytes()),
    );
    final ekBPub = await ekBPair.extractPublicKey();
    final ekBPubBytes = Uint8List.fromList(ekBPub.bytes);

    final dkBPub = await _publicKeyFromPriv(dkBPriv);
    final replyId = _randomBase64Url(16);

    // Compute transcript hash.
    final ikBPub = await _publicKeyFromPriv(ikBPriv);
    final th = await _computeTranscriptHash(
      ikAPub: ikAPub,
      ikBPub: ikBPub,
      dkAPub: dkAPubBytes,
      dkBPub: dkBPub,
      ekAPub: ekAPubBytes,
      ekBPub: ekBPubBytes,
      initId: init.initId,
      replyId: replyId,
      capsA: init.caps,
      capsB: caps,
    );

    // Compute 5 DH values (B-side formulas, spec §8.3.7).
    final dh1 = await _dh(dkBPriv, ikAPub);      // DH(DK_B_priv, IK_A_pub)
    final dh2 = await _dh(ikBPriv, dkAPubBytes);  // DH(IK_B_priv, DK_A_pub)
    final dh3 = await _dh(dkBPriv, ekAPubBytes);  // DH(DK_B_priv, EK_A_pub)
    final dh4 = await _dh(ekBPrivBytes, dkAPubBytes); // DH(EK_B_priv, DK_A_pub)
    final dh5 = await _dh(ekBPrivBytes, ekAPubBytes); // DH(EK_B_priv, EK_A_pub)

    final initialRootSecret = await _deriveRootSecret(
      dh1: dh1, dh2: dh2, dh3: dh3, dh4: dh4, dh5: dh5,
      transcriptHash: th,
    );

    // Wipe intermediate DH outputs immediately.
    _wipeList(dh1); _wipeList(dh2); _wipeList(dh3); _wipeList(dh4); _wipeList(dh5);

    // Keep a copy of the root secret for B so it can verify FS_CONFIRM.
    // It is wiped by the caller after [verifyFsConfirmAsResponder] succeeds.
    final rawRootSecretForB = Uint8List.fromList(initialRootSecret);

    final chainSeed0 = Uint8List.fromList(initialRootSecret.sublist(32));
    final rootKey0 = Uint8List.fromList(initialRootSecret.sublist(0, 32));
    _wipeList(initialRootSecret);

    // Derive chain keys (B = responder, so A→B is receiving chain).
    final receivingChainKey0 = await _deriveChainKey(chainSeed0, th, 'Layergram-FS-v1 A->B initial chain');
    final sendingChainKey0 = await _deriveChainKey(chainSeed0, th, 'Layergram-FS-v1 B->A initial chain');
    _wipeList(chainSeed0);

    // Wipe responder ephemeral private key — no longer needed after chain derivation.
    _wipeList(ekBPrivBytes);

    // Generate B's initial ratchet key pair.
    // The public key is published in FS_REPLY so A can set lastRemoteRatchetPub
    // correctly, avoiding a spurious DH ratchet step on first message delivery.
    final ratchetBPair = await _x25519.newKeyPair();
    final ratchetBPriv = Uint8List.fromList(await ratchetBPair.extractPrivateKeyBytes());
    final ratchetBPubKey = await ratchetBPair.extractPublicKey() as SimplePublicKey;
    final ratchetBPub = Uint8List.fromList(ratchetBPubKey.bytes);

    return FsReplyPayload(
      initId: init.initId,
      replyId: replyId,
      responderDevicePub: FsKeyCodec.encodeKey(dkBPub),
      responderEphemeralPub: FsKeyCodec.encodeKey(ekBPubBytes),
      responderInitialRatchetPub: FsKeyCodec.encodeKey(ratchetBPub),
      responderInitialRatchetPriv: ratchetBPriv,
      caps: List.unmodifiable(caps),
      createdAt: _nowSeconds(),
      partialState: FsHandshakePartialState(
        transcriptHash: th,
        rootKey0: rootKey0,
        sendingChainKey0: sendingChainKey0,
        receivingChainKey0: receivingChainKey0,
        isInitiator: false,
        rawRootSecret: rawRootSecretForB,
      ),
    );
  }

  /// Processes FS_REPLY as the initiator (A) and generates FS_CONFIRM.
  ///
  /// Also derives the initial ratchet state for A.
  /// [ikAPriv] / [dkAPriv] = A's long-term identity and device private keys.
  /// [ekAPrivBytes] = A's ephemeral private key stored from [generateFsInit].
  /// [ikBPub] / [dkBPub] = B's long-term identity and device public keys
  ///                       (dkBPub comes from [FsReplyMessage.responderDevicePub]).
  static Future<FsConfirmPayload> processFsReplyAsInitiator({
    required Uint8List ikAPriv,
    required Uint8List dkAPriv,
    required Uint8List ekAPrivBytes,
    required Uint8List ikBPub,
    required FsInitMessage sentInit,
    required FsReplyMessage reply,
    List<String> capsA = const ['lgfs1', 'dr1'],
  }) async {
    // Decode and validate responder's public keys.
    final dkBPubBytes = FsKeyCodec.decodeKey(reply.responderDevicePub);
    final ekBPubBytes = FsKeyCodec.decodeKey(reply.responderEphemeralPub);
    final dkAPub = await _publicKeyFromPriv(dkAPriv);
    final ekAPub = await _publicKeyFromPriv(ekAPrivBytes);

    // Compute transcript hash (must match what B computed).
    final th = await _computeTranscriptHash(
      ikAPub: await _publicKeyFromPriv(ikAPriv),
      ikBPub: ikBPub,
      dkAPub: dkAPub,
      dkBPub: dkBPubBytes,
      ekAPub: ekAPub,
      ekBPub: ekBPubBytes,
      initId: sentInit.initId,
      replyId: reply.replyId,
      capsA: capsA,
      capsB: reply.caps,
    );

    // 5 DH values (A-side formulas, spec §8.3.7).
    final dh1 = await _dh(ikAPriv, dkBPubBytes);      // DH(IK_A_priv, DK_B_pub)
    final dh2 = await _dh(dkAPriv, ikBPub);           // DH(DK_A_priv, IK_B_pub)
    final dh3 = await _dh(ekAPrivBytes, dkBPubBytes); // DH(EK_A_priv, DK_B_pub)
    final dh4 = await _dh(dkAPriv, ekBPubBytes);      // DH(DK_A_priv, EK_B_pub)
    final dh5 = await _dh(ekAPrivBytes, ekBPubBytes); // DH(EK_A_priv, EK_B_pub)

    final initialRootSecret = await _deriveRootSecret(
      dh1: dh1, dh2: dh2, dh3: dh3, dh4: dh4, dh5: dh5,
      transcriptHash: th,
    );
    _wipeList(dh1); _wipeList(dh2); _wipeList(dh3); _wipeList(dh4); _wipeList(dh5);

    // Derive confirmKey and compute confirmTag (spec §8.3.8).
    final confirmKey = await _deriveConfirmKey(initialRootSecret, th);
    final confirmTag = await _computeConfirmTag(confirmKey, th, 'A confirms');
    _wipeList(confirmKey);

    final chainSeed0 = Uint8List.fromList(initialRootSecret.sublist(32));
    final rootKey0 = Uint8List.fromList(initialRootSecret.sublist(0, 32));
    _wipeList(initialRootSecret);

    // Derive chain keys (A = initiator: A→B is sending chain).
    final sendingChainKey0 = await _deriveChainKey(chainSeed0, th, 'Layergram-FS-v1 A->B initial chain');
    final receivingChainKey0 = await _deriveChainKey(chainSeed0, th, 'Layergram-FS-v1 B->A initial chain');
    _wipeList(chainSeed0);

    // Wipe A's ephemeral private key — no longer needed.
    _wipeList(ekAPrivBytes);

    // Generate A's initial ratchet key pair.
    // The public key is published in FS_CONFIRM so B can set lastRemoteRatchetPub
    // correctly, avoiding a spurious DH ratchet step on first message delivery.
    final ratchetAPair = await _x25519.newKeyPair();
    final ratchetAPriv = Uint8List.fromList(await ratchetAPair.extractPrivateKeyBytes());
    final ratchetAPubKey = await ratchetAPair.extractPublicKey() as SimplePublicKey;
    final ratchetAPub = Uint8List.fromList(ratchetAPubKey.bytes);

    return FsConfirmPayload(
      initId: sentInit.initId,
      replyId: reply.replyId,
      transcriptHash: base64Url.encode(th).replaceAll('=', ''),
      confirmTag: base64Url.encode(confirmTag).replaceAll('=', ''),
      initiatorInitialRatchetPub: FsKeyCodec.encodeKey(ratchetAPub),
      initiatorInitialRatchetPriv: ratchetAPriv,
      partialState: FsHandshakePartialState(
        transcriptHash: th,
        rootKey0: rootKey0,
        sendingChainKey0: sendingChainKey0,
        receivingChainKey0: receivingChainKey0,
        isInitiator: true,
      ),
    );
  }

  /// Verifies a received FS_CONFIRM as the responder (B).
  ///
  /// [bState] = the [FsHandshakePartialState] stored from [processFsInitAsResponder].
  /// [ikAPub] = A's identity public key (retrieved from the identity store).
  ///
  /// Returns `true` if the confirm tag is valid.
  static Future<bool> verifyFsConfirmAsResponder({
    required FsConfirmMessage confirm,
    required FsHandshakePartialState bState,
    required Uint8List ikAPub,
  }) async {
    // Re-derive the root secret from stored partial state to produce confirmKey.
    // In practice B already has rootKey0 etc., so we reconstruct confirmKey
    // from the stored transcript hash.
    final th = bState.transcriptHash;

    // Reconstruct initialRootSecret from partial state is not possible without
    // re-running DH. Instead we derive confirmKey directly from rootKey0 +
    // chainSeed — but we only stored the derived keys, not the raw secret.
    // Therefore we carry the confirmVerifyKey separately in partial state.
    //
    // For the first implementation we take the simpler path: the responder
    // stores the rawRootSecret in partial state alongside the derived keys,
    // and wipes it after verification. This is already the approach taken by
    // the Signal reference.
    //
    // FsHandshakePartialState.rawRootSecret is set only for B until FS_CONFIRM
    // is verified, then wiped.
    if (bState.rawRootSecret == null) return false;

    final confirmKey = await _deriveConfirmKey(
      Uint8List.fromList(bState.rawRootSecret!),
      th,
    );
    final expectedTag = await _computeConfirmTag(confirmKey, th, 'A confirms');
    _wipeList(confirmKey);

    // Decode received confirm tag.
    final Uint8List receivedTag;
    try {
      receivedTag = Uint8List.fromList(
        base64Url.decode(_padBase64Url(confirm.confirmTag)),
      );
    } catch (_) {
      return false;
    }

    // Constant-time comparison.
    return _constantTimeEqual(expectedTag, receivedTag);
  }

  // ---------------------------------------------------------------------------
  // Transcript hash (spec §8.3.6)
  // ---------------------------------------------------------------------------

  static Future<Uint8List> _computeTranscriptHash({
    required Uint8List ikAPub,
    required Uint8List ikBPub,
    required Uint8List dkAPub,
    required Uint8List dkBPub,
    required Uint8List ekAPub,
    required Uint8List ekBPub,
    required String initId,
    required String replyId,
    required List<String> capsA,
    required List<String> capsB,
  }) async {
    final prefix = utf8.encode('Layergram-FS-Handshake-v1');
    final initIdBytes = base64Url.decode(_padBase64Url(initId));
    final replyIdBytes = base64Url.decode(_padBase64Url(replyId));
    final capsABytes = _canonicalCaps(capsA);
    final capsBBytes = _canonicalCaps(capsB);

    final payload = Uint8List.fromList([
      ...prefix,
      ...FsKeyCodec.encodeKey(ikAPub).codeUnits,
      ...FsKeyCodec.encodeKey(ikBPub).codeUnits,
      ...FsKeyCodec.encodeKey(dkAPub).codeUnits,
      ...FsKeyCodec.encodeKey(dkBPub).codeUnits,
      ...FsKeyCodec.encodeKey(ekAPub).codeUnits,
      ...FsKeyCodec.encodeKey(ekBPub).codeUnits,
      ...initIdBytes,
      ...replyIdBytes,
      ...capsABytes,
      ...capsBBytes,
    ]);

    final hash = await Sha256().hash(payload);
    return Uint8List.fromList(hash.bytes);
  }

  // ---------------------------------------------------------------------------
  // DH and HKDF helpers
  // ---------------------------------------------------------------------------

  static Future<Uint8List> _dh(
    Uint8List localPriv,
    Uint8List remotePub,
  ) async {
    final localPublic = await _x25519
        .newKeyPairFromSeed(localPriv)
        .then((pair) => pair.extractPublicKey());
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
    final bytes = Uint8List.fromList(await shared.extractBytes());

    // Validate DH output — all-zero means degenerate/low-order input.
    FsKeyCodec.validateDhOutput(bytes);
    return bytes;
  }

  static Future<Uint8List> _deriveRootSecret({
    required Uint8List dh1,
    required Uint8List dh2,
    required Uint8List dh3,
    required Uint8List dh4,
    required Uint8List dh5,
    required Uint8List transcriptHash,
  }) async {
    final ikm = Uint8List.fromList([...dh1, ...dh2, ...dh3, ...dh4, ...dh5]);
    final saltInput = Uint8List.fromList([
      ...utf8.encode('Layergram-FS-v1 salt'),
      ...transcriptHash,
    ]);
    final saltHash = await Sha256().hash(saltInput);
    final infoInput = Uint8List.fromList([
      ...utf8.encode('Layergram-FS-v1 initial root'),
      ...transcriptHash,
    ]);

    final derived = await _hkdf64.deriveKey(
      secretKey: SecretKey(ikm),
      nonce: saltHash.bytes,
      info: infoInput,
    );
    _wipeList(ikm);
    return Uint8List.fromList(await derived.extractBytes());
  }

  static Future<Uint8List> _deriveChainKey(
    Uint8List chainSeed0,
    Uint8List transcriptHash,
    String infoString,
  ) async {
    final derived = await _hkdf32.deriveKey(
      secretKey: SecretKey(chainSeed0),
      nonce: transcriptHash,
      info: utf8.encode(infoString),
    );
    return Uint8List.fromList(await derived.extractBytes());
  }

  static Future<Uint8List> _deriveConfirmKey(
    Uint8List rawRootSecret,
    Uint8List transcriptHash,
  ) async {
    final saltInput = Uint8List.fromList([
      ...utf8.encode('Layergram-FS-v1 confirm'),
      ...transcriptHash,
    ]);
    final saltHash = await Sha256().hash(saltInput);

    final derived = await _hkdf32.deriveKey(
      secretKey: SecretKey(rawRootSecret),
      nonce: saltHash.bytes,
      info: utf8.encode('confirm'),
    );
    return Uint8List.fromList(await derived.extractBytes());
  }

  static Future<Uint8List> _computeConfirmTag(
    Uint8List confirmKey,
    Uint8List transcriptHash,
    String role,
  ) async {
    final data = Uint8List.fromList([
      ...transcriptHash,
      ...utf8.encode(role),
    ]);
    final mac = await _hmac.calculateMac(
      data,
      secretKey: SecretKey(confirmKey),
    );
    return Uint8List.fromList(mac.bytes);
  }

  // ---------------------------------------------------------------------------
  // Misc helpers
  // ---------------------------------------------------------------------------

  static Future<Uint8List> _publicKeyFromPriv(Uint8List priv) async {
    final pair = await _x25519.newKeyPairFromSeed(priv);
    final pub = await pair.extractPublicKey();
    return Uint8List.fromList(pub.bytes);
  }

  static Uint8List _canonicalCaps(List<String> caps) {
    final sorted = List<String>.from(caps)..sort();
    final buf = BytesBuilder();
    for (final cap in sorted) {
      final bytes = utf8.encode(cap);
      // Length-prefixed UTF-8 (4 bytes big-endian length, spec §8.3.6).
      buf.addByte((bytes.length >> 24) & 0xff);
      buf.addByte((bytes.length >> 16) & 0xff);
      buf.addByte((bytes.length >> 8) & 0xff);
      buf.addByte(bytes.length & 0xff);
      buf.add(bytes);
    }
    return buf.toBytes();
  }

  static String _randomBase64Url(int byteCount) {
    final bytes = Uint8List(byteCount);
    for (var i = 0; i < byteCount; i++) {
      bytes[i] = _rng.nextInt(256);
    }
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  static int _nowSeconds() =>
      DateTime.now().millisecondsSinceEpoch ~/ 1000;

  static String _padBase64Url(String s) {
    final rem = s.length % 4;
    if (rem == 0) return s;
    return s.padRight(s.length + (4 - rem), '=');
  }

  /// Best-effort in-place zeroing of a mutable [Uint8List].
  ///
  /// Note: Dart's GC may create copies internally. This minimizes lifetime of
  /// key material in memory within platform constraints (spec §20.2).
  static void _wipeList(List<int> bytes) {
    if (bytes is Uint8List) {
      for (var i = 0; i < bytes.length; i++) {
        bytes[i] = 0;
      }
    }
  }

  static bool _constantTimeEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}

// ---------------------------------------------------------------------------
// Data transfer objects
// ---------------------------------------------------------------------------

/// The public fields sent in an FS_INIT message (`x.fs`).
class FsInitMessage {
  const FsInitMessage({
    required this.initId,
    required this.initiatorDevicePub,
    required this.initiatorEphemeralPub,
    required this.caps,
    required this.createdAt,
  });

  final String initId;
  final String initiatorDevicePub;
  final String initiatorEphemeralPub;
  final List<String> caps;
  final int createdAt;

  Map<String, dynamic> toJson() => {
    'v': 1,
    'type': 'fs_init',
    'initId': initId,
    'initiatorDevicePub': initiatorDevicePub,
    'initiatorEphemeralPub': initiatorEphemeralPub,
    'caps': caps,
    'createdAt': createdAt,
  };

  factory FsInitMessage.fromJson(Map<String, dynamic> j) => FsInitMessage(
    initId: j['initId'] as String,
    initiatorDevicePub: j['initiatorDevicePub'] as String,
    initiatorEphemeralPub: j['initiatorEphemeralPub'] as String,
    caps: (j['caps'] as List).cast<String>(),
    createdAt: j['createdAt'] as int,
  );
}

/// Return value of [FsHandshake.generateFsInit].
class FsInitPayload {
  FsInitPayload({
    required this.initId,
    required this.initiatorDevicePub,
    required this.initiatorEphemeralPub,
    required this.caps,
    required this.createdAt,
    required this.ekAPrivBytes,
  });

  final String initId;
  final String initiatorDevicePub;
  final String initiatorEphemeralPub;
  final List<String> caps;
  final int createdAt;

  /// Must be stored securely until FS_REPLY is processed; wipe afterwards.
  final Uint8List ekAPrivBytes;

  FsInitMessage toMessage() => FsInitMessage(
    initId: initId,
    initiatorDevicePub: initiatorDevicePub,
    initiatorEphemeralPub: initiatorEphemeralPub,
    caps: caps,
    createdAt: createdAt,
  );
}

/// The public fields sent in an FS_REPLY message (`x.fs`).
class FsReplyMessage {
  const FsReplyMessage({
    required this.initId,
    required this.replyId,
    required this.responderDevicePub,
    required this.responderEphemeralPub,
    required this.responderInitialRatchetPub,
    required this.caps,
    required this.createdAt,
  });

  final String initId;
  final String replyId;
  final String responderDevicePub;
  final String responderEphemeralPub;

  /// B's initial ratchet public key. The initiator (A) uses this as
  /// [lastRemoteRatchetPub] when initialising the Double Ratchet, so that
  /// no spurious DH step fires on first message delivery.
  final String responderInitialRatchetPub;
  final List<String> caps;
  final int createdAt;

  Map<String, dynamic> toJson() => {
    'v': 1,
    'type': 'fs_reply',
    'initId': initId,
    'replyId': replyId,
    'responderDevicePub': responderDevicePub,
    'responderEphemeralPub': responderEphemeralPub,
    'responderInitialRatchetPub': responderInitialRatchetPub,
    'caps': caps,
    'createdAt': createdAt,
  };

  factory FsReplyMessage.fromJson(Map<String, dynamic> j) => FsReplyMessage(
    initId: j['initId'] as String,
    replyId: j['replyId'] as String,
    responderDevicePub: j['responderDevicePub'] as String,
    responderEphemeralPub: j['responderEphemeralPub'] as String,
    responderInitialRatchetPub: j['responderInitialRatchetPub'] as String,
    caps: (j['caps'] as List).cast<String>(),
    createdAt: j['createdAt'] as int,
  );
}

/// Return value of [FsHandshake.processFsInitAsResponder].
class FsReplyPayload {
  FsReplyPayload({
    required this.initId,
    required this.replyId,
    required this.responderDevicePub,
    required this.responderEphemeralPub,
    required this.responderInitialRatchetPub,
    required this.responderInitialRatchetPriv,
    required this.caps,
    required this.createdAt,
    required this.partialState,
  });

  final String initId;
  final String replyId;
  final String responderDevicePub;
  final String responderEphemeralPub;

  /// B's initial ratchet public key (included in FS_REPLY wire message).
  final String responderInitialRatchetPub;

  /// B's initial ratchet private key — kept locally, never sent.
  final Uint8List responderInitialRatchetPriv;

  final List<String> caps;
  final int createdAt;
  final FsHandshakePartialState partialState;

  FsReplyMessage toMessage() => FsReplyMessage(
    initId: initId,
    replyId: replyId,
    responderDevicePub: responderDevicePub,
    responderEphemeralPub: responderEphemeralPub,
    responderInitialRatchetPub: responderInitialRatchetPub,
    caps: caps,
    createdAt: createdAt,
  );
}

/// The public fields sent in an FS_CONFIRM message (`x.fs`).
class FsConfirmMessage {
  const FsConfirmMessage({
    required this.initId,
    required this.replyId,
    required this.transcriptHash,
    required this.confirmTag,
    required this.initiatorInitialRatchetPub,
  });

  final String initId;
  final String replyId;
  final String transcriptHash;
  final String confirmTag;

  /// A's initial ratchet public key. Bob sets [lastRemoteRatchetPub] to this
  /// when initialising the Double Ratchet, so no spurious DH step fires on
  /// the first incoming message from A.
  final String initiatorInitialRatchetPub;

  Map<String, dynamic> toJson() => {
    'v': 1,
    'type': 'fs_confirm',
    'initId': initId,
    'replyId': replyId,
    'transcriptHash': transcriptHash,
    'confirmTag': confirmTag,
    'initiatorInitialRatchetPub': initiatorInitialRatchetPub,
  };

  factory FsConfirmMessage.fromJson(Map<String, dynamic> j) => FsConfirmMessage(
    initId: j['initId'] as String,
    replyId: j['replyId'] as String,
    transcriptHash: j['transcriptHash'] as String,
    confirmTag: j['confirmTag'] as String,
    initiatorInitialRatchetPub: j['initiatorInitialRatchetPub'] as String,
  );
}

/// Return value of [FsHandshake.processFsReplyAsInitiator].
class FsConfirmPayload {
  FsConfirmPayload({
    required this.initId,
    required this.replyId,
    required this.transcriptHash,
    required this.confirmTag,
    required this.initiatorInitialRatchetPub,
    required this.initiatorInitialRatchetPriv,
    required this.partialState,
  });

  final String initId;
  final String replyId;
  final String transcriptHash;
  final String confirmTag;

  /// A's initial ratchet public key (included in FS_CONFIRM wire message).
  final String initiatorInitialRatchetPub;

  /// A's initial ratchet private key — kept locally, never sent.
  final Uint8List initiatorInitialRatchetPriv;

  final FsHandshakePartialState partialState;

  FsConfirmMessage toMessage() => FsConfirmMessage(
    initId: initId,
    replyId: replyId,
    transcriptHash: transcriptHash,
    confirmTag: confirmTag,
    initiatorInitialRatchetPub: initiatorInitialRatchetPub,
  );
}

/// Intermediate FS handshake state held by each party between messages.
///
/// For the responder (B), [rawRootSecret] is kept until FS_CONFIRM is verified
/// and then wiped. For the initiator (A), [rawRootSecret] is null (A wipes it
/// immediately after deriving the confirm tag and chain keys).
class FsHandshakePartialState {
  FsHandshakePartialState({
    required this.transcriptHash,
    required this.rootKey0,
    required this.sendingChainKey0,
    required this.receivingChainKey0,
    required this.isInitiator,
    this.rawRootSecret,
  });

  final Uint8List transcriptHash;
  final Uint8List rootKey0;
  final Uint8List sendingChainKey0;
  final Uint8List receivingChainKey0;
  final bool isInitiator;

  /// Kept by responder only until FS_CONFIRM verified.  Null for initiator.
  final Uint8List? rawRootSecret;

  void wipeRawRootSecret() {
    if (rawRootSecret != null) {
      for (var i = 0; i < rawRootSecret!.length; i++) {
        rawRootSecret![i] = 0;
      }
    }
  }
}
