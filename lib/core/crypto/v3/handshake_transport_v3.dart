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

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';

import 'lmf_v3.dart';
import 'local_identity_v3.dart';
import 'public_identity_v3.dart';

/// Canonical, deterministic LMF wrapping for public handshake records.
///
/// The outer key is intentionally derived from public identity material. It
/// provides canonical framing and corruption detection, not sender
/// authentication or confidentiality. Authentication is supplied only by the
/// hybrid handshake proofs and the subsequent atomic TR3 handoff. A carrier
/// can still drop, replace, reorder, or duplicate entire exports.
abstract final class V3HandshakeTransport {
  static const List<int> _keyLabel = <int>[
    0x6c,
    0x61,
    0x79,
    0x65,
    0x72,
    0x67,
    0x72,
    0x61,
    0x6d,
    0x2f,
    0x76,
    0x33,
    0x2f,
    0x68,
    0x61,
    0x6e,
    0x64,
    0x73,
    0x68,
    0x61,
    0x6b,
    0x65,
    0x2f,
    0x66,
    0x72,
    0x61,
    0x6d,
    0x69,
    0x6e,
    0x67,
    0x2d,
    0x6b,
    0x65,
    0x79,
    0x00,
  ];
  static const List<int> _nonceLabel = <int>[
    0x6c,
    0x61,
    0x79,
    0x65,
    0x72,
    0x67,
    0x72,
    0x61,
    0x6d,
    0x2f,
    0x76,
    0x33,
    0x2f,
    0x68,
    0x61,
    0x6e,
    0x64,
    0x73,
    0x68,
    0x61,
    0x6b,
    0x65,
    0x2f,
    0x66,
    0x72,
    0x61,
    0x6d,
    0x65,
    0x2f,
    0x6e,
    0x6f,
    0x6e,
    0x63,
    0x65,
    0x00,
  ];

  static Future<List<V3LmfFrame>> seal({
    required Uint8List record,
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
  }) async {
    final descriptor = _decodeRecord(record);
    _validateIdentityBinding(
      descriptor,
      initiatorIdentity,
      responderIdentity,
    );
    final key = _framingKey(initiatorIdentity, responderIdentity);
    try {
      final sender = descriptor.kind == V3HandshakeRecordKind.reply
          ? responderIdentity
          : initiatorIdentity;
      final recipient = descriptor.kind == V3HandshakeRecordKind.reply
          ? initiatorIdentity
          : responderIdentity;
      final metadata = V3LmfMessageMetadata(
        kind: V3LmfFrameKind.handshake,
        senderBinding: _routingBinding(sender),
        recipientBinding: _routingBinding(recipient),
        messageId: descriptor.messageId,
        sessionId: descriptor.handshakeId,
        epoch: 0,
        messageCounter: descriptor.kind.wireId - 1,
      );
      return await V3LmfAead.sealFragmented(
        metadata: metadata,
        plaintext: record,
        secretKey: key,
        nonceForFragment: (index) => _nonce(
          handshakeId: descriptor.handshakeId,
          messageId: descriptor.messageId,
          fragmentIndex: index,
        ),
      );
    } finally {
      key.destroy();
      descriptor.wipe();
    }
  }

  static Future<V3HandshakeTransportRecord> open({
    required Iterable<V3LmfFrame> frames,
    required V3PublicIdentity initiatorIdentity,
    required V3PublicIdentity responderIdentity,
  }) async {
    final candidates = frames.toList(growable: false);
    if (candidates.isEmpty ||
        candidates.length > V3LmfFrameCodec.maxFragments) {
      throw const FormatException('Invalid Layergram v3 handshake export');
    }
    final expectedCounter = candidates.first.metadata.messageCounter;
    final kind = _kindForCounter(expectedCounter);
    final sender = kind == V3HandshakeRecordKind.reply
        ? responderIdentity
        : initiatorIdentity;
    final recipient = kind == V3HandshakeRecordKind.reply
        ? initiatorIdentity
        : responderIdentity;
    final senderBinding = _routingBinding(sender);
    final recipientBinding = _routingBinding(recipient);
    final key = _framingKey(initiatorIdentity, responderIdentity);
    final reassembler = V3LmfReassembler();
    Uint8List? plaintext;
    try {
      for (final frame in candidates) {
        _validateFrameMetadata(
          frame,
          kind: kind,
          senderBinding: senderBinding,
          recipientBinding: recipientBinding,
        );
        final outcome = await reassembler.accept(
          frame: frame,
          secretKey: key,
        );
        if (outcome.isComplete) {
          plaintext = Uint8List.fromList(outcome.plaintext!);
          outcome.wipePlaintext();
        }
      }
      if (plaintext == null) {
        throw const FormatException('Incomplete Layergram v3 handshake export');
      }
      final descriptor = _decodeRecord(plaintext);
      try {
        _validateIdentityBinding(
          descriptor,
          initiatorIdentity,
          responderIdentity,
        );
        if (descriptor.kind != kind ||
            !_bytesEqual(
              descriptor.handshakeId,
              candidates.first.metadata.sessionId,
            ) ||
            !_bytesEqual(
              descriptor.messageId,
              candidates.first.metadata.messageId,
            )) {
          throw const FormatException(
            'Layergram v3 handshake transport binding mismatch',
          );
        }
        return V3HandshakeTransportRecord(
          kind: descriptor.kind,
          record: plaintext,
        );
      } finally {
        descriptor.wipe();
      }
    } finally {
      plaintext?.fillRange(0, plaintext.length, 0);
      reassembler.close();
      key.destroy();
      senderBinding.fillRange(0, senderBinding.length, 0);
      recipientBinding.fillRange(0, recipientBinding.length, 0);
    }
  }

  static String encodeText(Iterable<V3LmfFrame> frames) {
    return frames.map(V3LmfFrameCodec.encodeToken).join('\n');
  }

  static String encodeLinks(Iterable<V3LmfFrame> frames) {
    return frames.map(V3LmfFrameCodec.encodeLink).join('\n');
  }

  static List<String> encodeStego({
    required List<V3LmfFrame> frames,
    required List<String> coverTexts,
  }) {
    if (frames.length != coverTexts.length) {
      throw ArgumentError(
          'one cover text is required for each handshake frame');
    }
    return List<String>.generate(
      frames.length,
      (index) => V3LmfFrameCodec.encodeStego(
        frame: frames[index],
        coverText: coverTexts[index],
        maxTotalCharacters: V3LmfFrameCodec.portableShareCharacterLimit,
      ),
      growable: false,
    );
  }

  static List<V3LmfFrame> decodeText(String value) {
    return _decodeLines(value, V3LmfFrameCodec.decodeToken);
  }

  static List<V3LmfFrame> decodeLinks(String value) {
    return _decodeLines(value, V3LmfFrameCodec.decodeLink);
  }

  static List<V3LmfFrame> decodeStego(Iterable<String> values) {
    final frames = <V3LmfFrame>[];
    for (final value in values) {
      if (frames.length >= V3LmfFrameCodec.maxFragments) {
        throw const FormatException('Too many Layergram v3 handshake frames');
      }
      frames.add(V3LmfFrameCodec.decodeStego(value));
    }
    if (frames.isEmpty) {
      throw const FormatException('Empty Layergram v3 handshake export');
    }
    return List<V3LmfFrame>.unmodifiable(frames);
  }

  static List<V3LmfFrame> _decodeLines(
    String value,
    V3LmfFrame Function(String) decoder,
  ) {
    if (value.length >
        V3LmfFrameCodec.portableShareCharacterLimit *
            V3LmfFrameCodec.maxFragments) {
      throw const FormatException('Layergram v3 handshake export is too large');
    }
    final lines = const LineSplitter()
        .convert(value.trim())
        .map((line) => line.trim())
        .where((line) => line.isNotEmpty)
        .toList(growable: false);
    if (lines.isEmpty || lines.length > V3LmfFrameCodec.maxFragments) {
      throw const FormatException('Invalid Layergram v3 handshake export');
    }
    return List<V3LmfFrame>.unmodifiable(lines.map(decoder));
  }

  static _HandshakeDescriptor _decodeRecord(Uint8List record) {
    if (record.length < V3HandshakeCodec.commonHeaderBytes) {
      throw const FormatException('Invalid Layergram v3 handshake record');
    }
    final kind = V3HandshakeRecordKind.fromWireId(record[6]);
    return switch (kind) {
      V3HandshakeRecordKind.offer => _fromOffer(
          V3HandshakeCodec.decodeOffer(record),
        ),
      V3HandshakeRecordKind.reply => _fromReply(
          V3HandshakeCodec.decodeReply(record),
        ),
      V3HandshakeRecordKind.confirmation => _fromConfirmation(
          V3HandshakeCodec.decodeConfirmation(record),
        ),
    };
  }

  static _HandshakeDescriptor _fromOffer(V3HandshakeOffer offer) {
    return _HandshakeDescriptor(
      kind: V3HandshakeRecordKind.offer,
      handshakeId: offer.handshakeId,
      messageId: offer.messageId,
      initiatorIdentityDigest: offer.initiatorIdentityDigest,
      responderIdentityDigest: offer.responderIdentityDigest,
    );
  }

  static _HandshakeDescriptor _fromReply(V3HandshakeReply reply) {
    return _HandshakeDescriptor(
      kind: V3HandshakeRecordKind.reply,
      handshakeId: reply.handshakeId,
      messageId: reply.messageId,
      initiatorIdentityDigest: reply.initiatorIdentityDigest,
      responderIdentityDigest: reply.responderIdentityDigest,
    );
  }

  static _HandshakeDescriptor _fromConfirmation(
    V3HandshakeConfirmation confirmation,
  ) {
    return _HandshakeDescriptor(
      kind: V3HandshakeRecordKind.confirmation,
      handshakeId: confirmation.handshakeId,
      messageId: confirmation.messageId,
      initiatorIdentityDigest: confirmation.initiatorIdentityDigest,
      responderIdentityDigest: confirmation.responderIdentityDigest,
    );
  }

  static void _validateIdentityBinding(
    _HandshakeDescriptor descriptor,
    V3PublicIdentity initiator,
    V3PublicIdentity responder,
  ) {
    final initiatorDigest = _identityDigest(initiator);
    final responderDigest = _identityDigest(responder);
    try {
      if (!_bytesEqual(descriptor.initiatorIdentityDigest, initiatorDigest) ||
          !_bytesEqual(descriptor.responderIdentityDigest, responderDigest)) {
        throw const FormatException(
          'Layergram v3 handshake identity binding mismatch',
        );
      }
    } finally {
      initiatorDigest.fillRange(0, initiatorDigest.length, 0);
      responderDigest.fillRange(0, responderDigest.length, 0);
    }
  }

  static void _validateFrameMetadata(
    V3LmfFrame frame, {
    required V3HandshakeRecordKind kind,
    required Uint8List senderBinding,
    required Uint8List recipientBinding,
  }) {
    final metadata = frame.metadata;
    final frameSender = metadata.senderBinding;
    final frameRecipient = metadata.recipientBinding;
    try {
      if (metadata.kind != V3LmfFrameKind.handshake ||
          metadata.epoch != 0 ||
          metadata.messageCounter != kind.wireId - 1 ||
          metadata.expiresAtUnixSeconds != 0 ||
          !_bytesEqual(frameSender, senderBinding) ||
          !_bytesEqual(frameRecipient, recipientBinding)) {
        throw const FormatException(
          'Invalid Layergram v3 handshake frame metadata',
        );
      }
      final expectedNonce = _nonce(
        handshakeId: metadata.sessionId,
        messageId: metadata.messageId,
        fragmentIndex: frame.fragmentIndex,
      );
      final frameNonce = frame.nonce;
      try {
        if (!_bytesEqual(frameNonce, expectedNonce)) {
          throw const FormatException(
            'Invalid Layergram v3 handshake frame nonce',
          );
        }
      } finally {
        expectedNonce.fillRange(0, expectedNonce.length, 0);
        frameNonce.fillRange(0, frameNonce.length, 0);
      }
    } finally {
      frameSender.fillRange(0, frameSender.length, 0);
      frameRecipient.fillRange(0, frameRecipient.length, 0);
    }
  }

  static V3HandshakeRecordKind _kindForCounter(int counter) {
    return switch (counter) {
      0 => V3HandshakeRecordKind.offer,
      1 => V3HandshakeRecordKind.reply,
      2 => V3HandshakeRecordKind.confirmation,
      _ => throw const FormatException(
          'Invalid Layergram v3 handshake frame counter',
        ),
    };
  }

  static SecretKeyData _framingKey(
    V3PublicIdentity initiator,
    V3PublicIdentity responder,
  ) {
    final digest = sha256.convert(<int>[
      ..._keyLabel,
      ...initiator.identityBindingBytes,
      ...responder.identityBindingBytes,
    ]).bytes;
    return SecretKeyData(digest);
  }

  static Uint8List _routingBinding(V3PublicIdentity identity) {
    return Uint8List.fromList(
      sha256.convert(identity.identityBindingBytes).bytes,
    );
  }

  static Uint8List _identityDigest(V3PublicIdentity identity) {
    return Uint8List.fromList(
      sha384.convert(identity.identityBindingBytes).bytes,
    );
  }

  static Uint8List _nonce({
    required Uint8List handshakeId,
    required Uint8List messageId,
    required int fragmentIndex,
  }) {
    if (fragmentIndex < 0 || fragmentIndex > 0xffff) {
      throw ArgumentError.value(fragmentIndex, 'fragmentIndex');
    }
    final index = ByteData(2)..setUint16(0, fragmentIndex);
    return Uint8List.fromList(
      sha256
          .convert(<int>[
            ..._nonceLabel,
            ...handshakeId,
            ...messageId,
            ...index.buffer.asUint8List(),
          ])
          .bytes
          .take(V3LmfFrameCodec.nonceBytes)
          .toList(growable: false),
    );
  }

  static bool _bytesEqual(Uint8List left, Uint8List right) {
    if (left.length != right.length) return false;
    var difference = 0;
    for (var index = 0; index < left.length; index++) {
      difference |= left[index] ^ right[index];
    }
    return difference == 0;
  }
}

final class V3HandshakeTransportRecord {
  V3HandshakeTransportRecord({
    required this.kind,
    required Uint8List record,
  }) : _record = Uint8List.fromList(record);

  final V3HandshakeRecordKind kind;
  final Uint8List _record;
  bool _closed = false;

  Uint8List get record {
    if (_closed) {
      throw StateError('Layergram v3 handshake transport record is closed');
    }
    return Uint8List.fromList(_record);
  }

  V3HandshakeOffer decodeOffer() {
    if (kind != V3HandshakeRecordKind.offer) {
      throw StateError('Layergram v3 transport record is not an offer');
    }
    return V3HandshakeCodec.decodeOffer(record);
  }

  V3HandshakeReply decodeReply() {
    if (kind != V3HandshakeRecordKind.reply) {
      throw StateError('Layergram v3 transport record is not a reply');
    }
    return V3HandshakeCodec.decodeReply(record);
  }

  V3HandshakeConfirmation decodeConfirmation() {
    if (kind != V3HandshakeRecordKind.confirmation) {
      throw StateError('Layergram v3 transport record is not a confirmation');
    }
    return V3HandshakeCodec.decodeConfirmation(record);
  }

  void close() {
    if (_closed) return;
    _record.fillRange(0, _record.length, 0);
    _closed = true;
  }
}

final class _HandshakeDescriptor {
  _HandshakeDescriptor({
    required this.kind,
    required this.handshakeId,
    required this.messageId,
    required this.initiatorIdentityDigest,
    required this.responderIdentityDigest,
  });

  final V3HandshakeRecordKind kind;
  final Uint8List handshakeId;
  final Uint8List messageId;
  final Uint8List initiatorIdentityDigest;
  final Uint8List responderIdentityDigest;

  void wipe() {
    handshakeId.fillRange(0, handshakeId.length, 0);
    messageId.fillRange(0, messageId.length, 0);
    initiatorIdentityDigest.fillRange(0, initiatorIdentityDigest.length, 0);
    responderIdentityDigest.fillRange(0, responderIdentityDigest.length, 0);
  }
}
