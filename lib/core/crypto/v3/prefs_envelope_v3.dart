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

import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

import 'local_identity_v3.dart';
import 'public_identity_v3.dart';

/// Semantic class of one authenticated pre-session (`preFs`) envelope.
///
/// `preFs` is a **classical identity-only** bootstrap. It is deliberately not a
/// v3 session: it has no forward secrecy and no post-quantum component, and it
/// is never reported as an established v3 session.
enum V3PreFsEnvelopeKind {
  /// One fragment of user text, sealed with the identity X25519 key.
  data(1),

  /// One opaque control fragment (a canonical LMF v3 handshake frame).
  control(2),

  /// Acknowledges one previously delivered `data` message.
  acknowledgement(3);

  const V3PreFsEnvelopeKind(this.wireId);

  final int wireId;

  static V3PreFsEnvelopeKind fromWireId(int wireId) {
    for (final kind in values) {
      if (kind.wireId == wireId) return kind;
    }
    throw const FormatException('Unsupported Layergram preFs envelope kind');
  }
}

/// One opaque, fully authenticated preFs envelope.
///
/// Every field except the ciphertext is authenticated as additional data, so a
/// caller may rely on [senderIdentityDigest], [recipientIdentityDigest],
/// [messageId], [contextId], [nonce] and the control-fragment binding exactly
/// as received once [V3PreFsEnvelopeCodec.open] returns successfully.
final class V3PreFsEnvelope {
  V3PreFsEnvelope._({
    required this.formatVersion,
    required this.kind,
    required Uint8List senderIdentityDigest,
    required Uint8List recipientIdentityDigest,
    required Uint8List messageId,
    required Uint8List contextId,
    required Uint8List nonce,
    required Uint8List? senderDeviceId,
    required Uint8List? recipientDeviceId,
    required this.identityWideNormalFallback,
    required this.fragmentIndex,
    required this.fragmentCount,
    required this.controlFragmentCount,
    required Uint8List controlFragmentDigest,
    required this.timestampUnixSeconds,
    required Uint8List plaintext,
  })  : _senderIdentityDigest = senderIdentityDigest,
        _recipientIdentityDigest = recipientIdentityDigest,
        _messageId = messageId,
        _contextId = contextId,
        _nonce = nonce,
        _senderDeviceId = senderDeviceId,
        _recipientDeviceId = recipientDeviceId,
        _controlFragmentDigest = controlFragmentDigest,
        _plaintext = plaintext;

  final int formatVersion;

  /// Explicitly authenticated Normal-mode delivery to every installation of
  /// an identity while their device sessions are not all usable in one carrier.
  /// Each recipient must show this particular message as lacking FS.
  final bool identityWideNormalFallback;
  final V3PreFsEnvelopeKind kind;
  final int fragmentIndex;
  final int fragmentCount;

  /// Total number of `control` envelopes the sender attached to this bootstrap
  /// message, or zero when the sender attached none / did not know yet.
  final int controlFragmentCount;

  final int timestampUnixSeconds;
  final Uint8List _senderIdentityDigest;
  final Uint8List _recipientIdentityDigest;
  final Uint8List _messageId;
  final Uint8List _contextId;
  final Uint8List _nonce;
  final Uint8List? _senderDeviceId;
  final Uint8List? _recipientDeviceId;
  final Uint8List _controlFragmentDigest;
  final Uint8List _plaintext;

  Uint8List get senderIdentityDigest =>
      Uint8List.fromList(_senderIdentityDigest);

  Uint8List get recipientIdentityDigest =>
      Uint8List.fromList(_recipientIdentityDigest);

  Uint8List get messageId => Uint8List.fromList(_messageId);

  Uint8List get contextId => Uint8List.fromList(_contextId);

  Uint8List get nonce => Uint8List.fromList(_nonce);

  /// Present in v2 envelopes. Legacy v1 traffic has no device binding.
  Uint8List? get senderDeviceId =>
      _senderDeviceId == null ? null : Uint8List.fromList(_senderDeviceId);

  /// Present in targeted v3 envelopes. Other installations sharing the
  /// identity must ignore this message before committing its plaintext.
  Uint8List? get recipientDeviceId => _recipientDeviceId == null
      ? null
      : Uint8List.fromList(_recipientDeviceId);

  /// Digest of the control fragment carried by this envelope, or 32 zero bytes
  /// when this envelope carries no control fragment.
  Uint8List get controlFragmentDigest =>
      Uint8List.fromList(_controlFragmentDigest);

  /// Authenticated plaintext. Callers must not log or persist this raw value
  /// outside an encrypted store.
  Uint8List get plaintext => Uint8List.fromList(_plaintext);

  bool get carriesControl => kind == V3PreFsEnvelopeKind.control;
}

/// Strict, version/suite/domain-separated codec for the preFs bootstrap.
///
/// Wire shape: `LP1` magic, format version, a reserved classical suite id, an
/// envelope kind, ordered identity digests, the logical message and context
/// ids, a random nonce, the fragment shape, a SHA-256 control-fragment binding
/// and then an AES-256-GCM ciphertext and tag. The whole fixed header is the
/// AEAD associated data. Version 2 appends the sender installation's device ID
/// to that authenticated header, so a second device with the same identity can
/// begin its own Normal-mode bootstrap without crossing the first device's
/// post-FS fence. Version 1 remains readable for in-flight messages.
/// Version 3 also appends the intended recipient device ID. It is an
/// authenticated routing restriction for shared-identity installations, not
/// a device-specific encryption key: the key remains classical identity DH.
abstract final class V3PreFsEnvelopeCodec {
  static const List<int> magic = <int>[0x4c, 0x50, 0x31]; // "LP1"
  static const int formatVersion = 2;
  static const int targetedFormatVersion = 3;
  static const int identityWideNormalFallbackFlag = 1;
  static const int legacyFormatVersion = 1;

  /// The single reviewed preFs suite: identity X25519 + HKDF-SHA256 +
  /// AES-256-GCM. It is intentionally not a v3 hybrid suite id.
  static const int classicalIdentitySuite = 1;

  static const int identityDigestBytes = 48;
  static const int messageIdBytes = 16;
  static const int contextIdBytes = 16;
  static const int deviceIdBytes = 16;
  static const int nonceBytes = 12;
  static const int authenticationTagBytes = 16;
  static const int controlFragmentDigestBytes = 32;
  static const int legacyHeaderBytes = 197;
  static const int headerBytes = legacyHeaderBytes + deviceIdBytes;
  static const int targetedHeaderBytes = headerBytes + deviceIdBytes;
  static const int maxFragmentCount = 64;

  /// Hard cap applied before any allocation. Carrier adapters enforce a much
  /// smaller per-carrier budget.
  static const int maxEncodedBytes = 4096;

  static const int maxPlaintextBytes =
      maxEncodedBytes - headerBytes - authenticationTagBytes;

  /// Stable security label surfaced to callers and UI. Never "pq" or "fs".
  static const String securityLabel = 'preFs';

  static final AesGcm _algorithm = AesGcm.with256bits();

  static final Uint8List _saltLabel = Uint8List.fromList(
    'layergram/prefs/v1/x25519-identity-aes256gcm/salt\x00'.codeUnits,
  );
  static final Uint8List _infoLabel = Uint8List.fromList(
    'layergram/prefs/v1/x25519-identity-aes256gcm/key\x00'.codeUnits,
  );
  static final Uint8List _contextLabel = Uint8List.fromList(
    'layergram/prefs/v1/context\x00'.codeUnits,
  );

  /// Digest that binds one full v3 identity, identical to the digest used by
  /// the established v3 handshake and application payloads.
  static Uint8List identityDigest(V3PublicIdentity identity) =>
      Uint8List.fromList(
        crypto.sha384.convert(identity.identityBindingBytes).bytes,
      );

  /// Order-independent conversation context for one identity pair.
  static Uint8List deriveContextId({
    required V3PublicIdentity localIdentity,
    required V3PublicIdentity remoteIdentity,
  }) {
    final local = identityDigest(localIdentity);
    final remote = identityDigest(remoteIdentity);
    try {
      final ordered = _orderPair(local, remote);
      try {
        return Uint8List.fromList(
          crypto.sha256
              .convert(<int>[..._contextLabel, ...ordered])
              .bytes
              .take(contextIdBytes)
              .toList(growable: false),
        );
      } finally {
        ordered.fillRange(0, ordered.length, 0);
      }
    } finally {
      local.fillRange(0, local.length, 0);
      remote.fillRange(0, remote.length, 0);
    }
  }

  /// Seals one fragment with a fresh 96-bit nonce.
  ///
  /// [random] is injectable for deterministic tests only.
  static Future<Uint8List> seal({
    required V3LocalIdentityHandle localIdentity,
    required V3PublicIdentity remoteIdentity,
    Uint8List? senderDeviceId,
    Uint8List? recipientDeviceId,
    bool identityWideNormalFallback = false,
    required V3PreFsEnvelopeKind kind,
    required Uint8List messageId,
    required Uint8List contextId,
    required int fragmentIndex,
    required int fragmentCount,
    int controlFragmentCount = 0,
    Uint8List? controlFragmentDigest,
    required Uint8List plaintext,
    required int timestampUnixSeconds,
    Random? random,
  }) async {
    _validateFragmentShape(
      fragmentIndex: fragmentIndex,
      fragmentCount: fragmentCount,
    );
    if (recipientDeviceId != null && senderDeviceId == null) {
      throw ArgumentError('Targeted preFs requires a sender device ID');
    }
    if (identityWideNormalFallback &&
        (senderDeviceId == null ||
            recipientDeviceId != null ||
            kind != V3PreFsEnvelopeKind.data)) {
      throw ArgumentError('Identity-wide fallback requires untargeted v2 data');
    }
    final version = recipientDeviceId != null
        ? targetedFormatVersion
        : senderDeviceId == null
            ? legacyFormatVersion
            : formatVersion;
    final checkedDeviceId = senderDeviceId == null
        ? null
        : _requireNonZero(senderDeviceId, deviceIdBytes);
    final checkedRecipientDeviceId = recipientDeviceId == null
        ? null
        : _requireNonZero(recipientDeviceId, deviceIdBytes);
    final checkedMessageId = _requireNonZero(messageId, messageIdBytes);
    final checkedContextId = _requireNonZero(contextId, contextIdBytes);
    final binding = _controlBindingFor(
      kind: kind,
      plaintext: plaintext,
      controlFragmentCount: controlFragmentCount,
      controlFragmentDigest: controlFragmentDigest,
    );
    final effectiveMaxPlaintextBytes = maxEncodedBytes -
        (version == targetedFormatVersion
            ? targetedHeaderBytes
            : version == formatVersion
                ? headerBytes
                : legacyHeaderBytes) -
        authenticationTagBytes;
    if (plaintext.isEmpty || plaintext.length > effectiveMaxPlaintextBytes) {
      throw ArgumentError.value(
        plaintext.length,
        'plaintext',
        'preFs plaintext must be between 1 and $maxPlaintextBytes bytes',
      );
    }
    if (timestampUnixSeconds < 0) {
      throw ArgumentError.value(timestampUnixSeconds, 'timestampUnixSeconds');
    }
    final sender = identityDigest(localIdentity.publicIdentity);
    final recipient = identityDigest(remoteIdentity);
    final nonce = Uint8List(nonceBytes);
    final source = random ?? Random.secure();
    for (var index = 0; index < nonceBytes; index++) {
      nonce[index] = source.nextInt(256);
    }
    Uint8List? header;
    final localPlaintext = Uint8List.fromList(plaintext);
    try {
      header = _encodeHeader(
        version: version,
        kind: kind,
        senderIdentityDigest: sender,
        recipientIdentityDigest: recipient,
        messageId: checkedMessageId,
        contextId: checkedContextId,
        nonce: nonce,
        senderDeviceId: checkedDeviceId,
        recipientDeviceId: checkedRecipientDeviceId,
        identityWideNormalFallback: identityWideNormalFallback,
        fragmentIndex: fragmentIndex,
        fragmentCount: fragmentCount,
        controlFragmentCount: binding.controlFragmentCount,
        controlFragmentDigest: binding.digest,
        assembledPlaintextLength: localPlaintext.length,
        timestampUnixSeconds: timestampUnixSeconds,
      );
      final key = await _deriveKey(
        localIdentity: localIdentity,
        remoteIdentity: remoteIdentity,
        kind: kind,
        version: version,
        senderDeviceId: checkedDeviceId,
        recipientDeviceId: checkedRecipientDeviceId,
        senderIdentityDigest: sender,
        recipientIdentityDigest: recipient,
        contextId: checkedContextId,
      );
      try {
        final box = await _algorithm.encrypt(
          localPlaintext,
          secretKey: key,
          nonce: nonce,
          aad: header,
        );
        final encoded = Uint8List(
          header.length + box.cipherText.length + box.mac.bytes.length,
        );
        var offset = 0;
        encoded.setRange(offset, offset + header.length, header);
        offset += header.length;
        encoded.setRange(
            offset, offset + box.cipherText.length, box.cipherText);
        offset += box.cipherText.length;
        encoded.setRange(offset, offset + box.mac.bytes.length, box.mac.bytes);
        return encoded;
      } finally {
        key.destroy();
      }
    } finally {
      if (header != null) header.fillRange(0, header.length, 0);
      localPlaintext.fillRange(0, localPlaintext.length, 0);
      sender.fillRange(0, sender.length, 0);
      recipient.fillRange(0, recipient.length, 0);
      nonce.fillRange(0, nonce.length, 0);
    }
  }

  /// Splits [plaintext] into the smallest number of envelopes that fit
  /// [maxPlaintextPerFragment], sealing each independently.
  static Future<List<Uint8List>> sealFragments({
    required V3LocalIdentityHandle localIdentity,
    required V3PublicIdentity remoteIdentity,
    Uint8List? senderDeviceId,
    Uint8List? recipientDeviceId,
    required V3PreFsEnvelopeKind kind,
    required Uint8List messageId,
    required Uint8List contextId,
    required Uint8List plaintext,
    required int maxPlaintextPerFragment,
    required int timestampUnixSeconds,
    int controlFragmentCount = 0,
    Random? random,
  }) async {
    if (maxPlaintextPerFragment < 1 ||
        maxPlaintextPerFragment > maxPlaintextBytes) {
      throw ArgumentError.value(
        maxPlaintextPerFragment,
        'maxPlaintextPerFragment',
      );
    }
    if (plaintext.isEmpty) {
      throw ArgumentError.value(plaintext.length, 'plaintext');
    }
    final fragmentCount = (plaintext.length + maxPlaintextPerFragment - 1) ~/
        maxPlaintextPerFragment;
    if (fragmentCount > maxFragmentCount) {
      throw StateError('Layergram preFs message needs too many fragments');
    }
    final result = <Uint8List>[];
    for (var index = 0; index < fragmentCount; index++) {
      final start = index * maxPlaintextPerFragment;
      final end = (start + maxPlaintextPerFragment).clamp(0, plaintext.length);
      final fragment = Uint8List.fromList(plaintext.sublist(start, end));
      try {
        result.add(
          await seal(
            localIdentity: localIdentity,
            remoteIdentity: remoteIdentity,
            senderDeviceId: senderDeviceId,
            recipientDeviceId: recipientDeviceId,
            kind: kind,
            messageId: messageId,
            contextId: contextId,
            fragmentIndex: index,
            fragmentCount: fragmentCount,
            controlFragmentCount: controlFragmentCount,
            plaintext: fragment,
            timestampUnixSeconds: timestampUnixSeconds,
            random: random,
          ),
        );
      } finally {
        fragment.fillRange(0, fragment.length, 0);
      }
    }
    return List<Uint8List>.unmodifiable(result);
  }

  /// Authenticates and opens one envelope.
  ///
  /// This performs no replay bookkeeping and never returns partial content: a
  /// failure throws before any plaintext is exposed. The claimed identities are
  /// checked against the caller's resolved pair, so a valid envelope for a
  /// different identity pair is rejected even if it decrypts.
  static Future<V3PreFsEnvelope> open({
    required V3LocalIdentityHandle localIdentity,
    required V3PublicIdentity remoteIdentity,
    required Uint8List encoded,
  }) async {
    if (encoded.length <= legacyHeaderBytes ||
        encoded.length > maxEncodedBytes) {
      throw const FormatException('Invalid Layergram preFs envelope length');
    }
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) {
        throw const FormatException('Invalid Layergram preFs envelope magic');
      }
    }
    final version = encoded[3];
    if ((version != targetedFormatVersion &&
            version != formatVersion &&
            version != legacyFormatVersion) ||
        encoded[4] != classicalIdentitySuite ||
        (encoded[6] != 0 &&
            !(version == formatVersion &&
                encoded[6] == identityWideNormalFallbackFlag &&
                encoded[5] == V3PreFsEnvelopeKind.data.wireId))) {
      throw const FormatException(
        'Unsupported Layergram preFs envelope version, suite or flags',
      );
    }
    final effectiveHeaderBytes = version == targetedFormatVersion
        ? targetedHeaderBytes
        : version == formatVersion
            ? headerBytes
            : legacyHeaderBytes;
    if (encoded.length <= effectiveHeaderBytes + authenticationTagBytes) {
      throw const FormatException('Invalid Layergram preFs envelope length');
    }
    final kind = V3PreFsEnvelopeKind.fromWireId(encoded[5]);
    final data = ByteData.sublistView(encoded);
    final fragmentIndex = data.getUint16(7, Endian.big);
    final fragmentCount = data.getUint16(9, Endian.big);
    final controlFragmentCount = data.getUint16(11, Endian.big);
    final assembledPlaintextLength = data.getUint32(13, Endian.big);
    final timestamp = data.getUint64(17, Endian.big);
    _validateFragmentShape(
      fragmentIndex: fragmentIndex,
      fragmentCount: fragmentCount,
    );
    final ciphertextLength =
        encoded.length - effectiveHeaderBytes - authenticationTagBytes;
    if (ciphertextLength < 1 ||
        ciphertextLength >
            maxEncodedBytes - effectiveHeaderBytes - authenticationTagBytes ||
        assembledPlaintextLength != ciphertextLength ||
        timestamp > _maxCounter ||
        controlFragmentCount > maxFragmentCount) {
      throw const FormatException('Invalid Layergram preFs envelope fields');
    }
    final header = Uint8List.fromList(encoded.sublist(0, effectiveHeaderBytes));
    final sender = Uint8List.fromList(
      encoded.sublist(25, 25 + identityDigestBytes),
    );
    final recipient = Uint8List.fromList(
      encoded.sublist(73, 73 + identityDigestBytes),
    );
    final messageId = Uint8List.fromList(
      encoded.sublist(121, 121 + messageIdBytes),
    );
    final contextId = Uint8List.fromList(
      encoded.sublist(137, 137 + contextIdBytes),
    );
    final nonce = Uint8List.fromList(
      encoded.sublist(153, 153 + nonceBytes),
    );
    final controlDigest = Uint8List.fromList(
      encoded.sublist(165, 165 + controlFragmentDigestBytes),
    );
    final senderDeviceId = version >= formatVersion
        ? Uint8List.fromList(encoded.sublist(
            legacyHeaderBytes,
            headerBytes,
          ))
        : null;
    final recipientDeviceId = version == targetedFormatVersion
        ? Uint8List.fromList(encoded.sublist(headerBytes, targetedHeaderBytes))
        : null;
    var transferred = false;
    try {
      if (_isAllZero(messageId) ||
          _isAllZero(contextId) ||
          _isAllZero(sender) ||
          _isAllZero(recipient) ||
          (senderDeviceId != null && _isAllZero(senderDeviceId)) ||
          (recipientDeviceId != null && _isAllZero(recipientDeviceId))) {
        throw const FormatException('Invalid Layergram preFs envelope binding');
      }
      final expectedSender = identityDigest(remoteIdentity);
      final expectedRecipient = identityDigest(localIdentity.publicIdentity);
      final expectedContext = deriveContextId(
        localIdentity: localIdentity.publicIdentity,
        remoteIdentity: remoteIdentity,
      );
      try {
        if (!_constantTimeEquals(expectedSender, sender) ||
            !_constantTimeEquals(expectedRecipient, recipient) ||
            !_constantTimeEquals(expectedContext, contextId)) {
          throw const FormatException(
            'Layergram preFs envelope identity binding mismatch',
          );
        }
      } finally {
        expectedSender.fillRange(0, expectedSender.length, 0);
        expectedRecipient.fillRange(0, expectedRecipient.length, 0);
        expectedContext.fillRange(0, expectedContext.length, 0);
      }
      final key = await _deriveKey(
        localIdentity: localIdentity,
        remoteIdentity: remoteIdentity,
        kind: kind,
        version: version,
        senderDeviceId: senderDeviceId,
        recipientDeviceId: recipientDeviceId,
        senderIdentityDigest: sender,
        recipientIdentityDigest: recipient,
        contextId: contextId,
      );
      late final Uint8List cleartext;
      try {
        final box = SecretBox(
          Uint8List.fromList(
            encoded.sublist(
                effectiveHeaderBytes, effectiveHeaderBytes + ciphertextLength),
          ),
          nonce: nonce,
          mac: Mac(
            Uint8List.fromList(
              encoded.sublist(effectiveHeaderBytes + ciphertextLength),
            ),
          ),
        );
        try {
          cleartext = Uint8List.fromList(
            await _algorithm.decrypt(box, secretKey: key, aad: header),
          );
        } on SecretBoxAuthenticationError {
          throw const FormatException(
            'Layergram preFs envelope authentication failed',
          );
        }
      } finally {
        key.destroy();
      }
      try {
        _verifyControlBinding(
          kind: kind,
          cleartext: cleartext,
          controlFragmentCount: controlFragmentCount,
          controlDigest: controlDigest,
        );
        final envelope = V3PreFsEnvelope._(
          formatVersion: version,
          kind: kind,
          senderIdentityDigest: sender,
          recipientIdentityDigest: recipient,
          messageId: messageId,
          contextId: contextId,
          nonce: nonce,
          senderDeviceId: senderDeviceId,
          recipientDeviceId: recipientDeviceId,
          identityWideNormalFallback:
              encoded[6] == identityWideNormalFallbackFlag,
          fragmentIndex: fragmentIndex,
          fragmentCount: fragmentCount,
          controlFragmentCount: controlFragmentCount,
          controlFragmentDigest: controlDigest,
          timestampUnixSeconds: timestamp,
          plaintext: cleartext,
        );
        // Ownership of every bound buffer transfers to the returned envelope.
        transferred = true;
        return envelope;
      } catch (_) {
        cleartext.fillRange(0, cleartext.length, 0);
        rethrow;
      }
    } finally {
      if (!transferred) {
        sender.fillRange(0, sender.length, 0);
        recipient.fillRange(0, recipient.length, 0);
        messageId.fillRange(0, messageId.length, 0);
        contextId.fillRange(0, contextId.length, 0);
        nonce.fillRange(0, nonce.length, 0);
        controlDigest.fillRange(0, controlDigest.length, 0);
        senderDeviceId?.fillRange(0, senderDeviceId.length, 0);
        recipientDeviceId?.fillRange(0, recipientDeviceId.length, 0);
      }
      header.fillRange(0, header.length, 0);
    }
  }

  /// Unauthenticated sender identity digest for inbound routing only.
  ///
  /// The value is verified against the identity used to derive the AEAD key by
  /// [open]; callers must never treat a peeked digest as authenticated.
  static Uint8List peekSenderIdentityDigest(Uint8List encoded) {
    if (encoded.length < legacyHeaderBytes) {
      throw const FormatException('Invalid Layergram preFs envelope length');
    }
    return Uint8List.fromList(
      encoded.sublist(25, 25 + identityDigestBytes),
    );
  }

  /// Unauthenticated recipient identity digest for inbound routing only.
  static Uint8List peekRecipientIdentityDigest(Uint8List encoded) {
    if (encoded.length < legacyHeaderBytes) {
      throw const FormatException('Invalid Layergram preFs envelope length');
    }
    return Uint8List.fromList(
      encoded.sublist(73, 73 + identityDigestBytes),
    );
  }

  /// Cheap structural peek used by carrier adapters before committing to a
  /// decode path. It authenticates nothing.
  static bool hasMagic(Uint8List encoded) {
    if (encoded.length < magic.length) return false;
    for (var index = 0; index < magic.length; index++) {
      if (encoded[index] != magic[index]) return false;
    }
    return true;
  }

  static Future<SecretKey> _deriveKey({
    required V3LocalIdentityHandle localIdentity,
    required V3PublicIdentity remoteIdentity,
    required V3PreFsEnvelopeKind kind,
    required int version,
    required Uint8List? senderDeviceId,
    required Uint8List? recipientDeviceId,
    required Uint8List senderIdentityDigest,
    required Uint8List recipientIdentityDigest,
    required Uint8List contextId,
  }) async {
    final salt = Uint8List.fromList(
      crypto.sha256.convert(<int>[
        ..._saltLabel,
        version,
        classicalIdentitySuite,
        kind.wireId,
        ...senderIdentityDigest,
        ...recipientIdentityDigest,
        ...contextId,
        if (version >= formatVersion) ...senderDeviceId!,
        if (version == targetedFormatVersion) ...recipientDeviceId!,
      ]).bytes,
    );
    try {
      return await localIdentity.derivePreFsBootstrapKey(
        remoteIdentity: remoteIdentity,
        salt: salt,
        info: _infoLabel,
      );
    } finally {
      salt.fillRange(0, salt.length, 0);
    }
  }

  static Uint8List _encodeHeader({
    required int version,
    required V3PreFsEnvelopeKind kind,
    required Uint8List senderIdentityDigest,
    required Uint8List recipientIdentityDigest,
    required Uint8List messageId,
    required Uint8List contextId,
    required Uint8List nonce,
    required Uint8List? senderDeviceId,
    required Uint8List? recipientDeviceId,
    required bool identityWideNormalFallback,
    required int fragmentIndex,
    required int fragmentCount,
    required int controlFragmentCount,
    required Uint8List controlFragmentDigest,
    required int assembledPlaintextLength,
    required int timestampUnixSeconds,
  }) {
    final header = Uint8List(version == targetedFormatVersion
        ? targetedHeaderBytes
        : version == formatVersion
            ? headerBytes
            : legacyHeaderBytes);
    final data = ByteData.sublistView(header);
    var offset = 0;
    header.setRange(offset, offset + magic.length, magic);
    offset += magic.length;
    header[offset++] = version;
    header[offset++] = classicalIdentitySuite;
    header[offset++] = kind.wireId;
    header[offset++] =
        identityWideNormalFallback ? identityWideNormalFallbackFlag : 0;
    data.setUint16(offset, fragmentIndex, Endian.big);
    offset += 2;
    data.setUint16(offset, fragmentCount, Endian.big);
    offset += 2;
    data.setUint16(offset, controlFragmentCount, Endian.big);
    offset += 2;
    data.setUint32(offset, assembledPlaintextLength, Endian.big);
    offset += 4;
    data.setUint64(offset, timestampUnixSeconds, Endian.big);
    offset += 8;
    header.setRange(
      offset,
      offset + identityDigestBytes,
      senderIdentityDigest,
    );
    offset += identityDigestBytes;
    header.setRange(
      offset,
      offset + identityDigestBytes,
      recipientIdentityDigest,
    );
    offset += identityDigestBytes;
    header.setRange(offset, offset + messageIdBytes, messageId);
    offset += messageIdBytes;
    header.setRange(offset, offset + contextIdBytes, contextId);
    offset += contextIdBytes;
    header.setRange(offset, offset + nonceBytes, nonce);
    offset += nonceBytes;
    header.setRange(
      offset,
      offset + controlFragmentDigestBytes,
      controlFragmentDigest,
    );
    offset += controlFragmentDigestBytes;
    if (version >= formatVersion) {
      header.setRange(offset, offset + deviceIdBytes, senderDeviceId!);
      offset += deviceIdBytes;
    }
    if (version == targetedFormatVersion) {
      header.setRange(offset, offset + deviceIdBytes, recipientDeviceId!);
      offset += deviceIdBytes;
    }
    if (offset != header.length) {
      throw StateError('Layergram preFs envelope header drift');
    }
    return header;
  }

  static ({
    int controlFragmentCount,
    Uint8List digest,
  }) _controlBindingFor({
    required V3PreFsEnvelopeKind kind,
    required Uint8List plaintext,
    required int controlFragmentCount,
    required Uint8List? controlFragmentDigest,
  }) {
    if (kind != V3PreFsEnvelopeKind.control) {
      if (controlFragmentDigest != null && !_isAllZero(controlFragmentDigest)) {
        throw ArgumentError(
          'only a control envelope may bind a control fragment digest',
        );
      }
      return (
        controlFragmentCount: 0,
        digest: Uint8List(controlFragmentDigestBytes),
      );
    }
    if (controlFragmentCount < 1 || controlFragmentCount > maxFragmentCount) {
      throw ArgumentError.value(
        controlFragmentCount,
        'controlFragmentCount',
      );
    }
    final derived = controlFragmentDigest == null
        ? _digestBytes(plaintext)
        : _requireNonZero(
            controlFragmentDigest,
            controlFragmentDigestBytes,
          );
    return (controlFragmentCount: controlFragmentCount, digest: derived);
  }

  static void _verifyControlBinding({
    required V3PreFsEnvelopeKind kind,
    required Uint8List cleartext,
    required int controlFragmentCount,
    required Uint8List controlDigest,
  }) {
    if (kind != V3PreFsEnvelopeKind.control) {
      if (controlFragmentCount != 0 || !_isAllZero(controlDigest)) {
        throw const FormatException(
          'Layergram preFs data envelope must not bind control fragments',
        );
      }
      return;
    }
    final expected = _digestBytes(cleartext);
    try {
      if (controlFragmentCount < 1 ||
          !_constantTimeEquals(expected, controlDigest)) {
        throw const FormatException(
          'Layergram preFs control fragment binding mismatch',
        );
      }
    } finally {
      expected.fillRange(0, expected.length, 0);
    }
  }

  static void _validateFragmentShape({
    required int fragmentIndex,
    required int fragmentCount,
  }) {
    if (fragmentCount < 1 ||
        fragmentCount > maxFragmentCount ||
        fragmentIndex < 0 ||
        fragmentIndex >= fragmentCount) {
      throw ArgumentError('invalid Layergram preFs fragment shape');
    }
  }
}

const int _maxCounter = 0x7fffffffffffffff;

Uint8List _digestBytes(Uint8List value) =>
    Uint8List.fromList(crypto.sha256.convert(value).bytes);

Uint8List _requireNonZero(Uint8List value, int expectedLength) {
  if (value.length != expectedLength || _isAllZero(value)) {
    throw ArgumentError.value(value.length, 'expectedLength');
  }
  return Uint8List.fromList(value);
}

Uint8List _orderPair(Uint8List left, Uint8List right) {
  var comparison = 0;
  for (var index = 0; index < left.length && comparison == 0; index++) {
    comparison = left[index] - right[index];
  }
  return Uint8List.fromList(
    comparison <= 0 ? <int>[...left, ...right] : <int>[...right, ...left],
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

bool _isAllZero(List<int> value) {
  var accumulator = 0;
  for (final byte in value) {
    accumulator |= byte;
  }
  return accumulator == 0;
}
