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
import 'dart:convert';
import 'dart:typed_data';

import '../stego_alphabet_v2.dart';
import '../stego_decoder.dart';
import '../stego_encoder.dart';
import 'lmf_v3.dart';
import 'lmf_v3_persistence.dart';
import 'prefs_envelope_v3.dart';

/// Per-carrier budget for one preFs envelope.
///
/// These reuse the existing v3 carrier limits unchanged: the four-symbol v2
/// payload alphabet, its noise runes, the reserved preview-safe prefix, and the
/// 16-payload / 22-total rune-per-slot caps are all still owned by
/// `StegoEncoder`. Nothing here introduces a new alphabet.
abstract final class V3PreFsCarrierBudget {
  static const String tokenPrefix = 'p1.';
  static const String scheme = 'layergram';
  static const String messageHost = 'p';
  static const int portableShareCharacterLimit =
      V3LmfFrameCodec.portableShareCharacterLimit;
  static const int maxStegoEnvelopeBytes =
      V3LmfFrameCodec.maxPortableStegoFrameBytes;
  static const int maxStegoInputCodeUnits =
      V3LmfFrameCodec.maxStegoInputCodeUnits;

  static const int _linkPrefixLength = 13; // "layergram://p/"

  /// Largest envelope that still fits one text token.
  static final int maxTextEnvelopeBytes = _largestEnvelopeForOverhead(
    tokenPrefix.length,
  );

  /// Largest envelope that still fits one `layergram://p/` link.
  static final int maxLinkEnvelopeBytes = _largestEnvelopeForOverhead(
    _linkPrefixLength + tokenPrefix.length,
  );

  static int _largestEnvelopeForOverhead(int overheadCharacters) {
    var candidate = 1;
    while (candidate < V3PreFsEnvelopeCodec.maxEncodedBytes) {
      final next = candidate + 1;
      if (overheadCharacters + _armorLength(next) >
          portableShareCharacterLimit) {
        break;
      }
      candidate = next;
    }
    return candidate;
  }

  /// Un-padded base64url length for [byteCount] raw bytes.
  static int _armorLength(int byteCount) =>
      4 * ((byteCount + 2) ~/ 3) - ((3 - byteCount % 3) % 3);

  static int oversizedUserTextLimitFor(int envelopeBytes) {
    if (envelopeBytes <=
        V3PreFsEnvelopeCodec.headerBytes +
            V3PreFsEnvelopeCodec.authenticationTagBytes +
            1) {
      throw ArgumentError.value(envelopeBytes, 'envelopeBytes');
    }
    return envelopeBytes -
        V3PreFsEnvelopeCodec.headerBytes -
        V3PreFsEnvelopeCodec.authenticationTagBytes;
  }
}

/// Carrier adapter for preFs envelopes.
///
/// The same carrier shapes as the established v3 application wire are reused,
/// but with an unambiguous `p1.` / `layergram://p/` namespace so a preFs
/// envelope can never be confused with an established LMF v3 frame.
abstract final class V3PreFsTransport {
  static const int maxArmoredCarrierCharacters = 6000;
  static String encodeText(Uint8List envelope) {
    final value = '${V3PreFsCarrierBudget.tokenPrefix}'
        '${base64UrlEncode(envelope).replaceAll('=', '')}';
    if (value.length > maxArmoredCarrierCharacters) {
      throw StateError('Layergram preFs text part exceeds the carrier budget');
    }
    return value;
  }

  static String encodeLink(Uint8List envelope) {
    final value =
        '${V3PreFsCarrierBudget.scheme}://${V3PreFsCarrierBudget.messageHost}/'
        '${base64UrlEncode(envelope).replaceAll('=', '')}';
    if (value.length > maxArmoredCarrierCharacters) {
      throw StateError('Layergram preFs link part exceeds the carrier budget');
    }
    return value;
  }

  static String encodeStego({
    required Uint8List envelope,
    required String coverText,
    int maxTotalCharacters = V3PreFsCarrierBudget.portableShareCharacterLimit,
  }) {
    if (envelope.length > V3PreFsCarrierBudget.maxStegoEnvelopeBytes) {
      throw StateError(
        'Layergram preFs envelope exceeds the stego carrier budget',
      );
    }
    if (coverText.length > V3PreFsCarrierBudget.maxStegoInputCodeUnits) {
      throw ArgumentError.value(coverText.length, 'coverText');
    }
    final encoded = StegoEncoder().encodeBytes(
      coverText,
      envelope,
      maxTotalCharacters: maxTotalCharacters,
    );
    if (encoded.length > V3PreFsCarrierBudget.maxStegoInputCodeUnits) {
      throw StateError('Layergram preFs stego output exceeds its limit');
    }
    return encoded;
  }

  static Uint8List decodeText(String value) {
    final normalized = value.trim();
    if (!normalized.startsWith(V3PreFsCarrierBudget.tokenPrefix) ||
        normalized.length > maxArmoredCarrierCharacters) {
      throw const FormatException('Invalid Layergram preFs text part');
    }
    return _decodeArmored(
      normalized.substring(V3PreFsCarrierBudget.tokenPrefix.length),
    );
  }

  static Uint8List decodeLink(String value) {
    final normalized = value.trim();
    final prefix = '${V3PreFsCarrierBudget.scheme}://'
        '${V3PreFsCarrierBudget.messageHost}/';
    if (!normalized.startsWith(prefix) ||
        normalized.length > maxArmoredCarrierCharacters) {
      throw const FormatException('Invalid Layergram preFs link part');
    }
    final uri = Uri.tryParse(normalized);
    if (uri == null ||
        uri.scheme != V3PreFsCarrierBudget.scheme ||
        uri.host != V3PreFsCarrierBudget.messageHost ||
        uri.pathSegments.length != 1 ||
        uri.query.isNotEmpty ||
        uri.fragment.isNotEmpty) {
      throw const FormatException('Invalid Layergram preFs link part');
    }
    final envelope = _decodeArmored(uri.pathSegments.single);
    if (encodeLink(envelope) != normalized) {
      throw const FormatException('Non-canonical Layergram preFs link part');
    }
    return envelope;
  }

  static Uint8List decodeStego(String value) {
    if (value.length > V3PreFsCarrierBudget.maxStegoInputCodeUnits) {
      throw const FormatException('Layergram preFs stego input exceeds limit');
    }
    final runes = StegoDecoder().extractPayloadRunes(value);
    final bytes = StegoAlphabetV2.payloadRunesToBytes(runes);
    if (bytes == null || bytes.isEmpty) {
      throw const FormatException('Invalid Layergram preFs stego payload');
    }
    if (!V3PreFsEnvelopeCodec.hasMagic(bytes)) {
      throw const FormatException('Invalid Layergram preFs stego magic');
    }
    return bytes;
  }

  static bool isTextPart(String value) =>
      value.trim().startsWith(V3PreFsCarrierBudget.tokenPrefix);

  static bool isLinkPart(String value) => value.trim().startsWith(
        '${V3PreFsCarrierBudget.scheme}://'
        '${V3PreFsCarrierBudget.messageHost}/',
      );

  /// True when [value] is a stego carrier whose hidden bytes start with the
  /// preFs magic. Cheap structural probe; it authenticates nothing.
  static bool looksLikeStegoPart(String value) {
    try {
      final runes = StegoDecoder().extractPayloadRunes(value);
      final bytes = StegoAlphabetV2.payloadRunesToBytes(runes);
      if (bytes == null || bytes.isEmpty) return false;
      return V3PreFsEnvelopeCodec.hasMagic(bytes);
    } on FormatException {
      return false;
    }
  }

  static Uint8List _decodeArmored(String armored) {
    if (armored.isEmpty || armored.length > maxArmoredCarrierCharacters) {
      throw const FormatException('Invalid Layergram preFs part');
    }
    late final Uint8List bytes;
    try {
      bytes = Uint8List.fromList(
        base64Url.decode(base64Url.normalize(armored)),
      );
    } on FormatException {
      throw const FormatException('Invalid Layergram preFs part');
    }
    if (bytes.isEmpty ||
        bytes.length > V3PreFsEnvelopeCodec.maxEncodedBytes ||
        !V3PreFsEnvelopeCodec.hasMagic(bytes)) {
      throw const FormatException('Invalid Layergram preFs envelope');
    }
    return bytes;
  }
}

/// Non-secret security facts for the preFs bootstrap.
///
/// This is the exact label the UI must render. It must never be presented as
/// forward secret, post-quantum, or an established v3 session.
final class V3PreFsSecurityFacts {
  const V3PreFsSecurityFacts._();

  static const V3PreFsSecurityFacts instance = V3PreFsSecurityFacts._();

  static const String label = V3PreFsEnvelopeCodec.securityLabel;
  static const String description = 'preFs identity-encrypted bootstrap';

  final bool classicalIdentityOnly = true;
  final bool forwardSecrecy = false;
  final bool postQuantum = false;
  final bool keyCompromiseImpersonationResistant = false;
  final bool isEstablishedV3Session = false;
}

enum V3PreFsPendingPurpose {
  data('data'),
  control('control'),
  acknowledgement('acknowledgement');

  const V3PreFsPendingPurpose(this.wireName);

  final String wireName;

  static V3PreFsPendingPurpose fromWireName(String value) {
    for (final purpose in values) {
      if (purpose.wireName == value) return purpose;
    }
    throw const FormatException('Unsupported Layergram preFs pending purpose');
  }
}

/// One durable, exactly retransmittable preFs carrier part.
final class V3PreFsPendingEntry {
  V3PreFsPendingEntry({
    required this.entryId,
    required this.contactDigest,
    required this.messageId,
    required this.contextId,
    required this.purpose,
    required this.partIndex,
    required this.partCount,
    required this.carrierMode,
    required Uint8List envelopeBytes,
    Iterable<Uint8List> bundledControlFrames = const <Uint8List>[],
    required this.createdAtUnixSeconds,
    required this.exported,
  })  : _envelopeBytes = Uint8List.fromList(envelopeBytes),
        _bundledControlFrames = List<Uint8List>.unmodifiable(
          bundledControlFrames.map(Uint8List.fromList),
        ) {
    if (partIndex < 0 || partCount < 1 || partIndex >= partCount) {
      throw ArgumentError('invalid Layergram preFs pending part shape');
    }
    if (_bundledControlFrames.length >= V3LmfFrameCodec.maxFragments ||
        _bundledControlFrames.any((frame) =>
            frame.length < V3LmfFrameCodec.minBinaryFrameBytes ||
            frame.length > V3LmfFrameCodec.maxBinaryFrameBytes)) {
      throw ArgumentError('invalid Layergram preFs bundled control frames');
    }
  }

  final String entryId;
  final String contactDigest;
  final String messageId;
  final String contextId;
  final V3PreFsPendingPurpose purpose;
  final int partIndex;
  final int partCount;

  /// Carrier mode the exact bytes were sealed for. Retransmission in a
  /// different mode is only possible when the envelope still fits that mode's
  /// budget; otherwise the part stays pending untouched.
  final String carrierMode;

  final int createdAtUnixSeconds;
  final bool exported;
  final Uint8List _envelopeBytes;
  final List<Uint8List> _bundledControlFrames;

  Uint8List get envelopeBytes => Uint8List.fromList(_envelopeBytes);
  List<Uint8List> get bundledControlFrames => List<Uint8List>.unmodifiable(
        _bundledControlFrames.map(Uint8List.fromList),
      );
  int get bundledControlFrameCount => _bundledControlFrames.length;

  int get envelopeByteLength =>
      _envelopeBytes.length +
      _bundledControlFrames.fold<int>(
          0, (total, frame) => total + frame.length);

  V3PreFsPendingEntry copyWith({bool? exported}) => V3PreFsPendingEntry(
        entryId: entryId,
        contactDigest: contactDigest,
        messageId: messageId,
        contextId: contextId,
        purpose: purpose,
        partIndex: partIndex,
        partCount: partCount,
        carrierMode: carrierMode,
        envelopeBytes: _envelopeBytes,
        bundledControlFrames: _bundledControlFrames,
        createdAtUnixSeconds: createdAtUnixSeconds,
        exported: exported ?? this.exported,
      );

  Map<String, dynamic> toJson() => <String, dynamic>{
        'entryId': entryId,
        'contactDigest': contactDigest,
        'messageId': messageId,
        'contextId': contextId,
        'purpose': purpose.wireName,
        'partIndex': partIndex,
        'partCount': partCount,
        'carrierMode': carrierMode,
        'envelope': base64UrlEncode(_envelopeBytes),
        if (_bundledControlFrames.isNotEmpty)
          'bundledControlFrames': _bundledControlFrames
              .map(base64UrlEncode)
              .toList(growable: false),
        'createdAt': createdAtUnixSeconds,
        'exported': exported,
      };

  static V3PreFsPendingEntry fromJson(Map<String, dynamic> json) {
    return V3PreFsPendingEntry(
      entryId: json['entryId'] as String,
      contactDigest: json['contactDigest'] as String,
      messageId: json['messageId'] as String,
      contextId: json['contextId'] as String,
      purpose: V3PreFsPendingPurpose.fromWireName(json['purpose'] as String),
      partIndex: json['partIndex'] as int,
      partCount: json['partCount'] as int,
      carrierMode: json['carrierMode'] as String,
      envelopeBytes: Uint8List.fromList(
        base64Url.decode(json['envelope'] as String),
      ),
      bundledControlFrames:
          (json['bundledControlFrames'] as List<dynamic>? ?? const <dynamic>[])
              .map((encoded) =>
                  Uint8List.fromList(base64Url.decode(encoded as String))),
      createdAtUnixSeconds: json['createdAt'] as int,
      exported: json['exported'] as bool,
    );
  }
}

/// Raised when the bounded durable preFs journal cannot accept more state.
final class V3PreFsPendingCapacityException implements Exception {
  const V3PreFsPendingCapacityException();
}

/// Inbound reassembly progress for one preFs logical message.
final class V3PreFsInboundAssembly {
  V3PreFsInboundAssembly({
    required this.contactDigest,
    required this.messageId,
    required this.contextId,
    required this.dataFragmentCount,
  });

  final String contactDigest;
  final String messageId;
  final String contextId;
  int dataFragmentCount;
  final Map<int, Uint8List> dataFragments = <int, Uint8List>{};
  final Set<int> controlFragments = <int>{};
  int controlFragmentCount = 0;
  int updatedAtUnixSeconds = 0;

  bool get dataComplete =>
      dataFragmentCount > 0 && dataFragments.length == dataFragmentCount;

  int get receivedDataFragments => dataFragments.length;

  bool get controlComplete =>
      controlFragmentCount > 0 &&
      controlFragments.length == controlFragmentCount;

  Uint8List? assembleData() {
    if (!dataComplete) return null;
    final ordered = <int>[];
    for (var index = 0; index < dataFragmentCount; index++) {
      final fragment = dataFragments[index];
      if (fragment == null) return null;
      ordered.addAll(fragment);
    }
    return Uint8List.fromList(ordered);
  }
}

/// Bounded durable outbound journal, replay window and inbound reassembly.
///
/// Production must pass an encrypting record store (the runtime uses the
/// identity-scoped Aux repository). Every mutation writes a complete new
/// manifest before deleting the previous one, so a restart observes either the
/// previous or the next complete state, never a partial one.
final class V3PreFsPendingStore {
  V3PreFsPendingStore({
    required V3LmfRecordStore store,
    this.maxEntries = 1024,
    this.maxTotalEnvelopeBytes = 4 * 1024 * 1024,
    this.maxReplayEntries = 4096,
    this.maxInboundAssemblies = 64,
    this.maxInboundAssemblyBytes = 512 * 1024,
    this.maxPeerReadySessions = 256,
  }) : _store = store;

  static const String manifestKind = 'v3.prefs.pending.manifest';
  static const int manifestVersion = 1;

  final V3LmfRecordStore _store;
  final int maxEntries;
  final int maxTotalEnvelopeBytes;
  final int maxReplayEntries;
  final int maxInboundAssemblies;
  final int maxInboundAssemblyBytes;
  final int maxPeerReadySessions;

  final Map<String, V3PreFsPendingEntry> _entries =
      <String, V3PreFsPendingEntry>{};
  final Map<String, V3PreFsInboundAssembly> _assemblies =
      <String, V3PreFsInboundAssembly>{};
  final List<String> _replayOrder = <String>[];
  final Set<String> _replayKeys = <String>{};
  final Map<String, int> _peerReadyFences = <String, int>{};
  final Set<String> _bootstrapSessions = <String>{};

  String? _storageId;
  int _revision = 0;
  int _inboundAssemblyBytes = 0;
  bool _restored = false;
  bool _writeRecoveryRequired = false;
  Future<void> _tail = Future<void>.value();

  int get revision => _revision;

  int get entryCount => _entries.length;

  int get totalEnvelopeBytes {
    var total = 0;
    for (final entry in _entries.values) {
      total += entry.envelopeByteLength;
    }
    return total;
  }

  List<V3PreFsPendingEntry> get entries =>
      List<V3PreFsPendingEntry>.unmodifiable(_entries.values);

  /// Loads the durable manifest. Missing or foreign records are ignored; an
  /// undecryptable manifest is treated as absent so the caller rebuilds.
  Future<void> restore() {
    return _serialized(() async {
      if (_restored) return;
      final records = await _store.readAll();
      for (final record in records) {
        if (record.payload['kind'] != manifestKind) continue;
        _adopt(record.storageId, record.payload);
        break;
      }
      _restored = true;
    });
  }

  Future<void> close() {
    _writeRecoveryRequired = false;
    return _serialized(() async {
      _entries.clear();
      _assemblies.clear();
      _replayKeys.clear();
      _replayOrder.clear();
      _peerReadyFences.clear();
      _bootstrapSessions.clear();
      _inboundAssemblyBytes = 0;
      _restored = false;
      _storageId = null;
    });
  }

  Future<List<V3PreFsPendingEntry>> pendingForContact(
    String contactDigest,
  ) {
    return _serialized(() async {
      final result = _entries.values
          .where((entry) => entry.contactDigest == contactDigest)
          .toList(growable: false)
        ..sort((left, right) {
          final byMessage = left.messageId.compareTo(right.messageId);
          if (byMessage != 0) return byMessage;
          final byPurpose = left.purpose.index.compareTo(right.purpose.index);
          if (byPurpose != 0) return byPurpose;
          return left.partIndex.compareTo(right.partIndex);
        });
      return List<V3PreFsPendingEntry>.unmodifiable(result);
    });
  }

  /// Appends freshly sealed parts. Rejects before mutating when the bounded
  /// journal would overflow, preserving the caller's draft.
  Future<void> record(List<V3PreFsPendingEntry> additions) {
    return _serialized(() async {
      if (additions.isEmpty) return;
      final extraBytes = additions.fold<int>(
        0,
        (total, entry) => total + entry.envelopeByteLength,
      );
      if (_entries.length + additions.length > maxEntries ||
          totalEnvelopeBytes + extraBytes > maxTotalEnvelopeBytes) {
        _evictExportedFor(extraBytes);
      }
      if (_entries.length + additions.length > maxEntries ||
          totalEnvelopeBytes + extraBytes > maxTotalEnvelopeBytes) {
        throw const V3PreFsPendingCapacityException();
      }
      for (final entry in additions) {
        _entries[entry.entryId] = entry;
      }
      await _persist();
    });
  }

  Future<void> markExported(String entryId) {
    return _serialized(() async {
      final existing = _entries[entryId];
      if (existing == null || existing.exported) return;
      _entries[entryId] = existing.copyWith(exported: true);
      await _persist();
    });
  }

  /// Removes acknowledged data parts while keeping pending control transport.
  Future<void> acknowledgeData(
    String contactDigest,
    String messageId,
  ) {
    return _serialized(() async {
      final removed = _entries.keys
          .where(
            (key) =>
                _entries[key]!.contactDigest == contactDigest &&
                _entries[key]!.messageId == messageId &&
                _entries[key]!.purpose == V3PreFsPendingPurpose.data,
          )
          .toList(growable: false);
      if (removed.isEmpty) return;
      for (final key in removed) {
        _entries.remove(key);
      }
      await _persist();
    });
  }

  /// Records an inbound data message. Returns false for a replayed message id.
  Future<bool> noteInboundData(
    String contactDigest,
    String messageId,
  ) {
    return _serialized(() async {
      final key = 'd|$contactDigest|$messageId';
      if (_replayKeys.contains(key)) return false;
      await _noteReplayKey(key);
      return true;
    });
  }

  /// Bound-observing inbound fragment acceptance.
  Future<({bool duplicate, bool dataComplete, bool controlComplete})>
      acceptDataFragment({
    required String contactDigest,
    required String messageId,
    required String contextId,
    required int fragmentIndex,
    required int fragmentCount,
    required Uint8List plaintext,
    required int nowUnixSeconds,
  }) {
    return _serialized(() async {
      final assembly = await _assemblyFor(
        contactDigest: contactDigest,
        messageId: messageId,
        contextId: contextId,
        nowUnixSeconds: nowUnixSeconds,
      );
      if (assembly.dataFragmentCount != 0 &&
          assembly.dataFragmentCount != fragmentCount) {
        throw const FormatException(
          'Layergram preFs data fragment count conflict',
        );
      }
      assembly.dataFragmentCount = fragmentCount;
      assembly.updatedAtUnixSeconds = nowUnixSeconds;
      if (assembly.dataFragments.containsKey(fragmentIndex)) {
        return (
          duplicate: true,
          dataComplete: assembly.dataComplete,
          controlComplete: assembly.controlComplete,
        );
      }
      if (_inboundAssemblyBytes + plaintext.length > maxInboundAssemblyBytes) {
        throw const V3PreFsPendingCapacityException();
      }
      _inboundAssemblyBytes += plaintext.length;
      assembly.dataFragments[fragmentIndex] = Uint8List.fromList(plaintext);
      await _trimAssemblies();
      await _persist();
      return (
        duplicate: false,
        dataComplete: assembly.dataComplete,
        controlComplete: assembly.controlComplete,
      );
    });
  }

  Future<({bool duplicate, bool dataComplete, bool controlComplete})>
      acceptControlFragment({
    required String contactDigest,
    required String messageId,
    required String contextId,
    required int controlFragmentIndex,
    required int controlFragmentCount,
    required int nowUnixSeconds,
  }) {
    return _serialized(() async {
      final assembly = await _assemblyFor(
        contactDigest: contactDigest,
        messageId: messageId,
        contextId: contextId,
        nowUnixSeconds: nowUnixSeconds,
      );
      if (assembly.controlFragmentCount != 0 &&
          assembly.controlFragmentCount != controlFragmentCount) {
        throw const FormatException(
          'Layergram preFs control fragment count conflict',
        );
      }
      assembly.controlFragmentCount = controlFragmentCount;
      assembly.updatedAtUnixSeconds = nowUnixSeconds;
      final duplicate = !assembly.controlFragments.add(controlFragmentIndex);
      await _persist();
      return (
        duplicate: duplicate,
        dataComplete: assembly.dataComplete,
        controlComplete: assembly.controlComplete,
      );
    });
  }

  /// Releases one completed inbound assembly. The replay key must already have
  /// been recorded for the logical message.
  Future<void> completeInboundAssembly(
    String contactDigest,
    String messageId,
  ) {
    return _serialized(() async {
      final key = _assemblyKey(contactDigest, messageId);
      final assembly = _assemblies.remove(key);
      if (assembly != null) {
        for (final fragment in assembly.dataFragments.values) {
          _inboundAssemblyBytes -= fragment.length;
        }
      }
      await _persist();
    });
  }

  Future<V3PreFsInboundAssembly?> inboundAssembly(
    String contactDigest,
    String messageId,
  ) {
    return _serialized(() async {
      return _assemblies[_assemblyKey(contactDigest, messageId)];
    });
  }

  Future<bool> hasReplayKeyFor(
    String contactDigest,
    String messageId,
  ) {
    return _serialized(() async {
      return _replayKeys.contains('d|$contactDigest|$messageId');
    });
  }

  Future<bool> isPeerFsReady(String contactDigest, String handshakeId) {
    return _serialized(() async {
      return _peerReadyFences.containsKey('$contactDigest|$handshakeId');
    });
  }

  Future<int?> preFsFenceFor(String contactDigest, String handshakeId) {
    return _serialized(
      () async => _peerReadyFences['$contactDigest|$handshakeId'],
    );
  }

  /// Records the first authenticated peer-FS boundary. It is sticky and lives
  /// outside the evictable application replay window.
  Future<void> markPeerFsReady({
    required String contactDigest,
    required String handshakeId,
    required int preFsFenceUnixSeconds,
  }) {
    return _serialized(() async {
      final key = '$contactDigest|$handshakeId';
      if (_peerReadyFences.containsKey(key)) return;
      if (_peerReadyFences.length >= maxPeerReadySessions) {
        throw const V3PreFsPendingCapacityException();
      }
      _peerReadyFences[key] = preFsFenceUnixSeconds;
      await _persist();
    });
  }

  Future<bool> isBootstrapHandshake(
    String contactDigest,
    String handshakeId,
  ) {
    return _serialized(
      () async => _bootstrapSessions.contains('$contactDigest|$handshakeId'),
    );
  }

  Future<void> markBootstrapHandshake({
    required String contactDigest,
    required String handshakeId,
  }) {
    return _serialized(() async {
      final key = '$contactDigest|$handshakeId';
      if (_bootstrapSessions.contains(key)) return;
      if (_bootstrapSessions.length >= maxPeerReadySessions) {
        throw const V3PreFsPendingCapacityException();
      }
      _bootstrapSessions.add(key);
      await _persist();
    });
  }

  Future<V3PreFsInboundAssembly> _assemblyFor({
    required String contactDigest,
    required String messageId,
    required String contextId,
    required int nowUnixSeconds,
  }) async {
    final key = _assemblyKey(contactDigest, messageId);
    final existing = _assemblies[key];
    if (existing != null) {
      if (existing.contextId != contextId) {
        throw const FormatException(
          'Layergram preFs assembly context conflict',
        );
      }
      return existing;
    }
    if (_assemblies.length >= maxInboundAssemblies) {
      throw const V3PreFsPendingCapacityException();
    }
    final created = V3PreFsInboundAssembly(
      contactDigest: contactDigest,
      messageId: messageId,
      contextId: contextId,
      dataFragmentCount: 0,
    )..updatedAtUnixSeconds = nowUnixSeconds;
    _assemblies[key] = created;
    return created;
  }

  Future<void> _trimAssemblies() async {
    if (_assemblies.length <= maxInboundAssemblies) return;
    final ordered = _assemblies.entries.toList(growable: false)
      ..sort(
        (left, right) => left.value.updatedAtUnixSeconds.compareTo(
          right.value.updatedAtUnixSeconds,
        ),
      );
    while (_assemblies.length > maxInboundAssemblies) {
      final victim = ordered.removeAt(0);
      for (final fragment in victim.value.dataFragments.values) {
        _inboundAssemblyBytes -= fragment.length;
      }
      _assemblies.remove(victim.key);
    }
  }

  Future<void> _noteReplayKey(String key) async {
    _replayKeys.add(key);
    _replayOrder.add(key);
    while (_replayOrder.length > maxReplayEntries) {
      final evicted = _replayOrder.removeAt(0);
      _replayKeys.remove(evicted);
    }
    await _persist();
  }

  void _evictExportedFor(int neededBytes) {
    final ordered = _entries.values.where((entry) => entry.exported).toList()
      ..sort(
        (left, right) =>
            left.createdAtUnixSeconds.compareTo(right.createdAtUnixSeconds),
      );
    for (final entry in ordered) {
      if (_entries.length < maxEntries &&
          totalEnvelopeBytes + neededBytes <= maxTotalEnvelopeBytes) {
        return;
      }
      _entries.remove(entry.entryId);
    }
  }

  void _adopt(String storageId, Map<String, dynamic> payload) {
    _entries.clear();
    _assemblies.clear();
    _replayKeys.clear();
    _replayOrder.clear();
    _peerReadyFences.clear();
    _bootstrapSessions.clear();
    _inboundAssemblyBytes = 0;
    _storageId = storageId;
    _revision = (payload['revision'] as int?) ?? 0;
    for (final raw in (payload['entries'] as List<dynamic>? ?? const [])) {
      final entry = V3PreFsPendingEntry.fromJson(
        Map<String, dynamic>.from(raw as Map),
      );
      _entries[entry.entryId] = entry;
    }
    for (final raw in (payload['assemblies'] as List<dynamic>? ?? const [])) {
      final map = Map<String, dynamic>.from(raw as Map);
      final assembly = V3PreFsInboundAssembly(
        contactDigest: map['contactDigest'] as String,
        messageId: map['messageId'] as String,
        contextId: map['contextId'] as String,
        dataFragmentCount: map['dataFragmentCount'] as int,
      )
        ..controlFragmentCount = map['controlFragmentCount'] as int
        ..updatedAtUnixSeconds = map['updatedAt'] as int;
      for (final fragment in (map['data'] as List<dynamic>? ?? const [])) {
        final entry = Map<String, dynamic>.from(fragment as Map);
        final bytes = Uint8List.fromList(
          base64Url.decode(entry['bytes'] as String),
        );
        assembly.dataFragments[entry['index'] as int] = bytes;
        _inboundAssemblyBytes += bytes.length;
      }
      for (final index in (map['control'] as List<dynamic>? ?? const [])) {
        assembly.controlFragments.add(index as int);
      }
      _assemblies[_assemblyKey(assembly.contactDigest, assembly.messageId)] =
          assembly;
    }
    for (final raw in (payload['replay'] as List<dynamic>? ?? const [])) {
      final key = raw as String;
      if (_replayKeys.add(key)) _replayOrder.add(key);
    }
    final ready = payload['peerReady'];
    if (ready is Map) {
      for (final entry in ready.entries) {
        if (entry.key is String && entry.value is int) {
          _peerReadyFences[entry.key as String] = entry.value as int;
        }
      }
    }
    for (final raw
        in (payload['bootstrapSessions'] as List<dynamic>? ?? const [])) {
      if (raw is String) _bootstrapSessions.add(raw);
    }
  }

  Map<String, dynamic> _toJson() => <String, dynamic>{
        'kind': manifestKind,
        'version': manifestVersion,
        'revision': _revision,
        'entries': _entries.values
            .map((entry) => entry.toJson())
            .toList(growable: false),
        'assemblies': _assemblies.values
            .map(
              (assembly) => <String, dynamic>{
                'contactDigest': assembly.contactDigest,
                'messageId': assembly.messageId,
                'contextId': assembly.contextId,
                'dataFragmentCount': assembly.dataFragmentCount,
                'controlFragmentCount': assembly.controlFragmentCount,
                'updatedAt': assembly.updatedAtUnixSeconds,
                'data': assembly.dataFragments.entries
                    .map(
                      (fragment) => <String, dynamic>{
                        'index': fragment.key,
                        'bytes': base64UrlEncode(fragment.value),
                      },
                    )
                    .toList(growable: false),
                'control': assembly.controlFragments.toList(growable: false)
                  ..sort(),
              },
            )
            .toList(growable: false),
        'replay': List<String>.from(_replayOrder),
        'peerReady': Map<String, int>.from(_peerReadyFences),
        'bootstrapSessions': List<String>.from(_bootstrapSessions),
      };

  Future<void> _persist() async {
    _revision++;
    final payload = _toJson();
    final previous = _storageId;
    late final String written;
    try {
      written = await _store.write(payload);
    } catch (_) {
      _writeRecoveryRequired = true;
      rethrow;
    }
    _storageId = written;
    if (previous != null && previous != written) {
      await _store.delete(previous);
    }
  }

  String _assemblyKey(String contactDigest, String messageId) =>
      '$contactDigest|$messageId';

  Future<T> _serialized<T>(Future<T> Function() operation) {
    final completer = Completer<T>();
    final previous = _tail;
    _tail = previous.catchError((_) {}).then((_) async {
      try {
        if (_writeRecoveryRequired) {
          throw StateError(
            'Layergram preFs state requires reopen after a failed write',
          );
        }
        completer.complete(await operation());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }
}
