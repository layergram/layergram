import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/ec_double_ratchet_v3.dart';
import 'package:layergram/core/crypto/v3/hybrid_ratchet_header_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3.dart';
import 'package:layergram/core/crypto/v3/lmf_v3_persistence.dart';

void main() {
  final key = SecretKeyData(_bytes(32, 0x11));
  final wrongKey = SecretKeyData(_bytes(32, 0x91));

  group('LMF v3 durable inbox', () {
    test('restores out of order fragments without partial plaintext', () async {
      final store = _FaultStore();
      final plaintext = _bytes(600, 0x30);
      final frames = await _frames(plaintext: plaintext, key: key);
      final first = V3LmfDurableInbox(store: store);
      await first.restore(keyResolver: (_) => key);

      final last = await first.receive(frame: frames[2], secretKey: key);
      expect(last.status, V3LmfInboxStatus.accepted);
      expect(last.delivery, isNull);
      expect(last.acknowledgement.receivedFragmentIndexes, {2});

      final leading = await first.receive(frame: frames[0], secretKey: key);
      expect(leading.delivery, isNull);
      expect(leading.acknowledgement.receivedFragmentIndexes, {0, 2});
      final recordCount = store.records.length;
      expect(
        (await first.receive(frame: frames[0], secretKey: key)).status,
        V3LmfInboxStatus.duplicate,
      );
      expect(store.records, hasLength(recordCount));
      expect(first.readyDeliveryCount, 0);
      await first.close();

      final restored = V3LmfDurableInbox(store: store);
      final restoreResult =
          await restored.restore(keyResolver: (_) async => key);
      expect(restoreResult.deliveries, isEmpty);
      expect(restored.readyDeliveryCount, 0);

      final complete = await restored.receive(
        frame: frames[1],
        secretKey: key,
      );
      expect(complete.status, V3LmfInboxStatus.complete);
      expect(complete.delivery!.plaintext, orderedEquals(plaintext));
      expect(
        complete.acknowledgement.receivedFragmentIndexes,
        {0, 1, 2},
      );
      await restored.close();

      // A crash before the higher-level commit intentionally redelivers.
      final redelivering = V3LmfDurableInbox(store: store);
      final redeliveryResult =
          await redelivering.restore(keyResolver: (_) => key);
      expect(redeliveryResult.deliveries, hasLength(1));
      final delivery = redeliveryResult.deliveries.single;
      expect(delivery.plaintext, orderedEquals(plaintext));

      await redelivering.commit(
        delivery,
        committedAt: DateTime.utc(2026, 8, 13),
      );
      await redelivering.commit(delivery);
      expect(delivery.plaintext, everyElement(0));
      expect(store.records.values.single['kind'],
          V3LmfDurableInbox.committedRecordKind);

      final replay = await redelivering.receive(
        frame: frames.first,
        secretKey: key,
      );
      expect(replay.status, V3LmfInboxStatus.committedReplay);
      expect(replay.delivery, isNull);
      expect(replay.acknowledgement.isComplete, isTrue);
    });

    test('tombstone survives cleanup failure and suppresses restart replay',
        () async {
      final store = _FaultStore();
      final frames = await _frames(plaintext: _bytes(520, 0x20), key: key);
      final inbox = V3LmfDurableInbox(store: store);
      await inbox.restore(keyResolver: (_) => key);
      V3LmfDurableDelivery? delivery;
      for (final frame in frames) {
        delivery =
            (await inbox.receive(frame: frame, secretKey: key)).delivery ??
                delivery;
      }
      expect(delivery, isNotNull);

      store.deleteFailuresRemaining = frames.length;
      await inbox.commit(delivery!);
      expect(store.records, hasLength(frames.length + 1));
      await inbox.close();

      final restored = V3LmfDurableInbox(store: store);
      final result = await restored.restore(keyResolver: (_) => key);
      expect(result.deliveries, isEmpty);
      expect(result.suppressedCommittedFrames, frames.length);
      expect(store.records, hasLength(1));
      expect(restored.committedTombstoneCount, 1);
    });

    test('failed tombstone write leaves frames eligible for redelivery',
        () async {
      final store = _FaultStore();
      final frames = await _frames(plaintext: _bytes(300, 0x44), key: key);
      final inbox = V3LmfDurableInbox(store: store);
      await inbox.restore(keyResolver: (_) => key);
      V3LmfDurableDelivery? delivery;
      for (final frame in frames) {
        delivery =
            (await inbox.receive(frame: frame, secretKey: key)).delivery ??
                delivery;
      }
      final frameRecordCount = store.records.length;
      store.failNextWrite = true;
      await expectLater(inbox.commit(delivery!), throwsStateError);
      expect(store.records, hasLength(frameRecordCount));
      expect(inbox.readyDeliveryCount, 1);
      await inbox.close();

      final restored = V3LmfDurableInbox(store: store);
      final result = await restored.restore(keyResolver: (_) => key);
      expect(result.deliveries, hasLength(1));
    });

    test('defers sealed frames until their session key becomes available',
        () async {
      final store = _FaultStore();
      final plaintext = _bytes(300, 0x72);
      final frames = await _frames(plaintext: plaintext, key: key);
      final writer = V3LmfDurableInbox(store: store);
      await writer.restore(keyResolver: (_) => key);
      await writer.receive(frame: frames.first, secretKey: key);
      await writer.close();

      final restored = V3LmfDurableInbox(store: store);
      final deferred = await restored.restore(keyResolver: (_) => null);
      expect(deferred.deferredFrames, 1);
      expect(deferred.deliveries, isEmpty);
      expect(store.records, hasLength(1));

      final resumed = await restored.resumeDeferred(keyResolver: (_) => key);
      expect(resumed.deferredFrames, 0);
      expect(resumed.deliveries, isEmpty);
      final completed =
          await restored.receive(frame: frames.last, secretKey: key);
      expect(completed.delivery!.plaintext, orderedEquals(plaintext));
    });

    test(
        'unauthenticated competing frame is removed without poisoning valid set',
        () async {
      final store = _FaultStore();
      final frames = await _frames(plaintext: _bytes(300, 0x21), key: key);
      final impostors = await _frames(
        plaintext: _bytes(300, 0xe1),
        key: wrongKey,
        nonceStart: 0xd0,
      );
      final inbox = V3LmfDurableInbox(store: store);
      await inbox.restore(keyResolver: (_) => key);
      await inbox.receive(frame: frames.first, secretKey: key);

      await expectLater(
        inbox.receive(frame: impostors.first, secretKey: key),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(inbox.persistedFrameCount, 1);
      final complete = await inbox.receive(frame: frames.last, secretKey: key);
      expect(complete.status, V3LmfInboxStatus.complete);
    });

    test('authenticated competing frame fails closed and wipes the assembly',
        () async {
      final store = _FaultStore();
      final frames = await _frames(plaintext: _bytes(300, 0x21), key: key);
      final competitors = await _frames(
        plaintext: _bytes(300, 0xe1),
        key: key,
        nonceStart: 0xd0,
      );
      final inbox = V3LmfDurableInbox(store: store);
      await inbox.restore(keyResolver: (_) => key);
      await inbox.receive(frame: frames.first, secretKey: key);

      await expectLater(
        inbox.receive(frame: competitors.first, secretKey: key),
        throwsA(isA<V3LmfPersistenceConflictException>()),
      );
      expect(inbox.persistedFrameCount, 0);
      expect(inbox.readyDeliveryCount, 0);
      expect(store.records, isEmpty);
    });

    test('authenticated metadata contradiction wipes persistent indexes too',
        () async {
      final store = _FaultStore();
      final frames = await _frames(plaintext: _bytes(300, 0x21), key: key);
      final contradictory = await _frames(
        plaintext: _bytes(300, 0x21),
        key: key,
        nonceStart: 0xd0,
        epoch: 8,
      );
      final inbox = V3LmfDurableInbox(store: store);
      await inbox.restore(keyResolver: (_) => key);
      await inbox.receive(frame: frames.first, secretKey: key);

      await expectLater(
        inbox.receive(frame: contradictory.last, secretKey: key),
        throwsA(isA<V3LmfReassemblyConflictException>()),
      );
      expect(inbox.persistedFrameCount, 0);
      expect(inbox.readyDeliveryCount, 0);
      expect(store.records, isEmpty);
    });

    test('wrong key never retains an unauthenticated candidate in memory',
        () async {
      final store = _FaultStore();
      final frame =
          (await _frames(plaintext: _bytes(24, 0x41), key: key)).single;
      final inbox = V3LmfDurableInbox(store: store);
      await inbox.restore(keyResolver: (_) => key);

      await expectLater(
        inbox.receive(frame: frame, secretKey: wrongKey),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(inbox.persistedFrameCount, 0);
      expect(store.records, isEmpty);
    });

    test('corrupt records are discarded and unrelated aux records survive',
        () async {
      final store = _FaultStore();
      await store.write(<String, dynamic>{
        'kind': V3LmfDurableInbox.inboxRecordKind,
        'v': 1,
        'frame': 'not_valid!',
        'receivedAt': 1,
      });
      await store.write(<String, dynamic>{
        'kind': V3LmfDurableInbox.inboxRecordKind,
        'v': 1,
        'frame': 'AA',
        'receivedAt': 8640000000000001,
      });
      await store.write(<String, dynamic>{'kind': 'fs_state_v1', 'v': 1});

      final inbox = V3LmfDurableInbox(store: store);
      final result = await inbox.restore(keyResolver: (_) => key);
      expect(result.discardedCorruptRecords, 2);
      expect(store.records.values, hasLength(1));
      expect(store.records.values.single['kind'], 'fs_state_v1');
    });

    test('physical record and byte caps fail before authentication work',
        () async {
      final store = _FaultStore();
      final frame =
          (await _frames(plaintext: _bytes(24, 0x52), key: key)).single;
      final writer = V3LmfDurableInbox(store: store);
      await writer.restore(keyResolver: (_) => key);
      await writer.receive(frame: frame, secretKey: key);
      final payload = _deepCopy(store.records.values.single);
      await writer.close();
      await store.write(payload);

      final physicalLimited = V3LmfDurableInbox(
        store: store,
        maxStoredRecords: 1,
      );
      await expectLater(
        physicalLimited.restore(keyResolver: (_) => key),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );

      final frameLimited = V3LmfDurableInbox(
        store: store,
        maxPersistedFrames: 1,
      );
      await expectLater(
        frameLimited.restore(keyResolver: (_) => key),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );

      final byteLimited = V3LmfDurableInbox(
        store: store,
        maxPersistedFrameBytes: 1,
      );
      await expectLater(
        byteLimited.restore(keyResolver: (_) => key),
        throwsA(isA<V3LmfPersistenceLimitException>()),
      );
    });

    test(
        'deferred continuations cannot permanently exhaust authenticated intake',
        () async {
      final store = _FaultStore();
      final oldest = await _frames(
        plaintext: _bytes(300, 0x22),
        key: key,
        epoch: 7,
        messageStart: 0x81,
      );
      final newer = await _frames(
        plaintext: _bytes(300, 0x42),
        key: key,
        epoch: 8,
        messageStart: 0x91,
      );
      final current = await _frames(
        plaintext: _bytes(300, 0x62),
        key: key,
        epoch: 9,
        messageStart: 0xb1,
      );
      expect(oldest, hasLength(greaterThan(1)));
      expect(
        {
          V3LmfFrameCodec.assemblyId(oldest.first),
          V3LmfFrameCodec.assemblyId(newer.first),
          V3LmfFrameCodec.assemblyId(current.first),
        },
        hasLength(3),
      );
      final inbox = V3LmfDurableInbox(
        store: store,
        maxPersistedFrames: 2,
      );
      await inbox.restore(keyResolver: (_) => null);
      await inbox.persistDeferred(
        frame: oldest.last,
        receivedAt: DateTime.fromMillisecondsSinceEpoch(1, isUtc: true),
      );
      await inbox.persistDeferred(
        frame: newer.last,
        receivedAt: DateTime.fromMillisecondsSinceEpoch(2, isUtc: true),
      );
      await inbox.persistDeferred(
        frame: current.last,
        receivedAt: DateTime.fromMillisecondsSinceEpoch(3, isUtc: true),
      );
      expect(inbox.persistedFrameCount, 2);

      await inbox.preflightAuthenticatedReceive(current.first);
      final leading = await inbox.receive(
        frame: current.first,
        secretKey: key,
      );
      expect(leading.status, V3LmfInboxStatus.accepted);
      final resumed = await inbox.resumeDeferred(
        onlyAssemblyId: V3LmfFrameCodec.assemblyId(current.first),
        keyResolver: (_) => key,
      );
      expect(resumed.deliveries, hasLength(1));
      expect(
        resumed.deliveries.single.plaintext,
        orderedEquals(_bytes(300, 0x62)),
      );
    });

    test('concurrent receives serialize and close waits for queued persistence',
        () async {
      final store = _FaultStore();
      final frames = await _frames(plaintext: _bytes(300, 0x62), key: key);
      final inbox = V3LmfDurableInbox(store: store);
      await inbox.restore(keyResolver: (_) => key);
      store.pauseNextWrite();

      final first = inbox.receive(frame: frames.first, secretKey: key);
      await store.writeStarted.future;
      final second = inbox.receive(frame: frames.last, secretKey: key);
      final closing = inbox.close();
      store.resumeWrite();

      expect((await first).delivery, isNull);
      expect((await second).delivery, isNotNull);
      await closing;
      expect(inbox.persistedFrameCount, 0);
      await expectLater(
        inbox.receive(frame: frames.first, secretKey: key),
        throwsStateError,
      );
    });
  });
}

Future<List<V3LmfFrame>> _frames({
  required Uint8List plaintext,
  required SecretKey key,
  int nonceStart = 0x50,
  int epoch = 7,
  int messageStart = 0x81,
}) {
  if (plaintext.length <= V3LmfFrameCodec.fragmentPlaintextBytes) {
    return V3LmfAead.sealSingle(
      metadata: _metadata(epoch: epoch, messageStart: messageStart),
      plaintext: plaintext,
      secretKey: key,
      nonce: _bytes(V3LmfFrameCodec.nonceBytes, nonceStart),
      hybridRatchetHeader: _hybridHeader(epoch: epoch),
    ).then((frame) => <V3LmfFrame>[frame]);
  }
  return V3LmfAead.sealFragmented(
    metadata: _metadata(epoch: epoch, messageStart: messageStart),
    plaintext: plaintext,
    secretKey: key,
    nonceForFragment: (index) =>
        _bytes(V3LmfFrameCodec.nonceBytes, nonceStart + index),
    hybridRatchetHeader: _hybridHeader(epoch: epoch),
  );
}

V3LmfMessageMetadata _metadata({
  int epoch = 7,
  int messageStart = 0x81,
}) =>
    V3LmfMessageMetadata(
      kind: V3LmfFrameKind.application,
      senderBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x01),
      recipientBinding: _bytes(V3LmfFrameCodec.routingBindingBytes, 0x41),
      messageId: _bytes(V3LmfFrameCodec.messageIdBytes, messageStart),
      sessionId: _bytes(V3LmfFrameCodec.sessionIdBytes, 0xa1),
      epoch: epoch,
      messageCounter: 9,
    );

V3HybridRatchetHeader _hybridHeader({int epoch = 7}) => V3HybridRatchetHeader(
      ecHeader: V3EcRatchetHeader(
        ratchetPublicKey: _bytes(32, 0x21),
        previousSendingChainLength: 3,
        messageCounter: 5,
      ),
      sckaMessage: V3SckaMessage(
        sendingEpoch: epoch,
        messageCounter: 9,
        nativePayload: Uint8List(0),
      ),
    );

Uint8List _bytes(int length, int start) => Uint8List.fromList(
      List<int>.generate(length, (index) => (start + index) & 0xff),
    );

Map<String, dynamic> _deepCopy(Map<String, dynamic> value) =>
    (jsonDecode(jsonEncode(value)) as Map).cast<String, dynamic>();

class _FaultStore implements V3LmfRecordStore {
  final Map<String, Map<String, dynamic>> records =
      <String, Map<String, dynamic>>{};
  var _nextId = 0;
  bool failNextWrite = false;
  int deleteFailuresRemaining = 0;
  Completer<void>? _writeGate;
  Completer<void> writeStarted = Completer<void>();

  void pauseNextWrite() {
    _writeGate = Completer<void>();
    writeStarted = Completer<void>();
  }

  void resumeWrite() => _writeGate?.complete();

  @override
  Future<String> write(Map<String, dynamic> payload) async {
    if (!writeStarted.isCompleted) writeStarted.complete();
    final gate = _writeGate;
    if (gate != null) {
      await gate.future;
      _writeGate = null;
    }
    if (failNextWrite) {
      failNextWrite = false;
      throw StateError('injected write failure');
    }
    final storageId = 'record-${_nextId++}';
    records[storageId] = _deepCopy(payload);
    return storageId;
  }

  @override
  Future<List<V3LmfStoredRecord>> readAll() async => records.entries
      .map(
        (entry) => V3LmfStoredRecord(
          storageId: entry.key,
          payload: _deepCopy(entry.value),
        ),
      )
      .toList(growable: false);

  @override
  Future<void> delete(String storageId) async {
    if (deleteFailuresRemaining > 0) {
      deleteFailuresRemaining--;
      throw StateError('injected delete failure');
    }
    records.remove(storageId);
  }
}
