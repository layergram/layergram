import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/handshake_frame_inbox_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';

void main() {
  late _MemoryStore store;
  late List<V3LmfFrame> frames;

  setUp(() async {
    store = _MemoryStore();
    frames = await _frames();
  });

  test(
      'persists out-of-order fragments, restores, commits and suppresses replay',
      () async {
    final first = V3HandshakeFrameInbox(store: store);
    await first.restore();
    expect(
      (await first.receive(frame: frames.last)).status,
      V3HandshakeFrameInboxStatus.accepted,
    );
    await first.close();

    final restored = V3HandshakeFrameInbox(store: store);
    final restoredState = await restored.restore();
    expect(restoredState.deferredFrames, 1);
    expect(restoredState.completeAssemblies, isEmpty);
    V3HandshakeFrameAssembly? assembly;
    for (final frame in frames.take(frames.length - 1).toList().reversed) {
      assembly = (await restored.receive(frame: frame)).assembly ?? assembly;
    }
    expect(assembly, isNotNull);
    expect(assembly!.frames, hasLength(frames.length));
    await restored.commit(assembly.assemblyId);
    expect(
      (await restored.receive(frame: frames.first)).status,
      V3HandshakeFrameInboxStatus.committedReplay,
    );
    await restored.close();

    final afterRestart = V3HandshakeFrameInbox(store: store);
    final afterState = await afterRestart.restore();
    expect(afterState.deferredFrames, 0);
    expect(afterState.committedAssemblies, 1);
    expect(
      (await afterRestart.receive(frame: frames.last)).status,
      V3HandshakeFrameInboxStatus.committedReplay,
    );
    await afterRestart.close();
  });

  test('conflicting same-index ciphertext fails closed', () async {
    final inbox = V3HandshakeFrameInbox(store: store);
    await inbox.restore();
    await inbox.receive(frame: frames.first);
    final modifiedBytes = V3LmfFrameCodec.encodeBinary(frames.first);
    modifiedBytes[modifiedBytes.length - 1] ^= 1;
    final modified = V3LmfFrameCodec.decodeBinary(modifiedBytes);
    expect(
      V3LmfFrameCodec.assemblyId(modified),
      V3LmfFrameCodec.assemblyId(frames.first),
    );
    await expectLater(
      inbox.receive(frame: modified),
      throwsA(isA<V3LmfPersistenceConflictException>()),
    );
    await inbox.close();
  });

  test('old incomplete public assemblies cannot permanently exhaust intake',
      () async {
    final inbox = V3HandshakeFrameInbox(
      store: store,
      maxPendingAssemblies: 2,
      maxPendingFrames: 64,
    );
    await inbox.restore();
    final first = _withMessageId(frames, 0x31);
    final second = _withMessageId(frames, 0x51);
    final current = _withMessageId(frames, 0x71);
    await inbox.receive(
      frame: first.first,
      receivedAt: DateTime.fromMillisecondsSinceEpoch(1, isUtc: true),
    );
    await inbox.receive(
      frame: second.first,
      receivedAt: DateTime.fromMillisecondsSinceEpoch(2, isUtc: true),
    );
    expect(
      (await inbox.receive(
        frame: current.first,
        receivedAt: DateTime.fromMillisecondsSinceEpoch(3, isUtc: true),
      ))
          .status,
      V3HandshakeFrameInboxStatus.accepted,
    );

    V3HandshakeFrameAssembly? completed;
    for (final frame in current.skip(1)) {
      completed = (await inbox.receive(frame: frame)).assembly ?? completed;
    }
    expect(completed, isNotNull);
    expect(completed!.frames, hasLength(current.length));
    expect(store.deletedRecords, 1);
    await inbox.close();
  });
}

Future<List<V3LmfFrame>> _frames() async {
  final metadata = V3LmfMessageMetadata(
    kind: V3LmfFrameKind.handshake,
    senderBinding: _bytes(32, 1),
    recipientBinding: _bytes(32, 33),
    messageId: _bytes(16, 65),
    sessionId: _bytes(16, 97),
    epoch: 0,
    messageCounter: 0,
  );
  return V3LmfAead.sealFragmented(
    metadata: metadata,
    plaintext: _bytes(600, 17),
    secretKey: SecretKeyData(_bytes(32, 113)),
    nonceForFragment: (index) => _bytes(12, 145 + index),
  );
}

List<V3LmfFrame> _withMessageId(List<V3LmfFrame> source, int seed) => source
    .map(
      (frame) => V3LmfFrame(
        metadata: V3LmfMessageMetadata(
          kind: frame.metadata.kind,
          senderBinding: frame.metadata.senderBinding,
          recipientBinding: frame.metadata.recipientBinding,
          messageId: _bytes(16, seed),
          sessionId: frame.metadata.sessionId,
          epoch: frame.metadata.epoch,
          messageCounter: frame.metadata.messageCounter,
          expiresAtUnixSeconds: frame.metadata.expiresAtUnixSeconds,
          suite: frame.metadata.suite,
          flags: frame.metadata.flags,
        ),
        fragmentIndex: frame.fragmentIndex,
        fragmentCount: frame.fragmentCount,
        assembledPlaintextLength: frame.assembledPlaintextLength,
        nonce: frame.nonce,
        ciphertext: frame.ciphertext,
        authenticationTag: frame.authenticationTag,
      ),
    )
    .toList(growable: false);

Uint8List _bytes(int length, int seed) => Uint8List.fromList(
      List<int>.generate(length, (index) => (seed + index) & 0xff),
    );

final class _MemoryStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records = {};
  int _nextId = 0;
  int deletedRecords = 0;

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    final id = 'record-${_nextId++}';
    records[id] = Map<String, dynamic>.from(payload);
    return id;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async => records.entries
      .map(
        (entry) => V3LmfStoredRecord(
          storageId: entry.key,
          payload: Map<String, dynamic>.from(entry.value),
        ),
      )
      .toList(growable: false);

  @override
  Future<void> delete(String storageId) async {
    if (records.remove(storageId) != null) deletedRecords++;
  }
}
