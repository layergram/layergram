// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import 'package:flutter/services.dart';

import 'system_keyboard_custody.dart';
import 'system_keyboard_record_store.dart';

/// App-side native custody adapter. This channel never carries identity keys;
/// its per-delegation key is generated and journaled by [SystemKeyboardCustody].
final class MethodChannelSystemKeyboardCustodyNative
    implements SystemKeyboardCustodyNative {
  const MethodChannelSystemKeyboardCustodyNative({
    MethodChannel channel = const MethodChannel('layergram/keyboard_custody'),
  }) : _channel = channel;
  final MethodChannel _channel;

  @override
  Future<bool> hasPending() async {
    final value = await _channel.invokeMethod<Object?>('hasPending');
    if (value is! bool) {
      throw StateError('Native custody status unavailable');
    }
    return value;
  }

  @override
  Future<void> prepare(Uint8List epoch, Uint8List key, Uint8List bytes) =>
      _channel.invokeMethod<void>('prepare', {
        'epoch': epoch,
        'key': key,
        'snapshot': bytes,
      });
  @override
  Future<void> activate(Uint8List epoch, Uint8List key) =>
      _channel.invokeMethod<void>('activate', {'epoch': epoch, 'key': key});
  @override
  Future<SystemKeyboardCustodySnapshot> reclaim(
      Uint8List epoch, Uint8List key) async {
    final Object? value;
    try {
      value = await _channel
          .invokeMethod<Object?>('reclaim', {'epoch': epoch, 'key': key});
    } on PlatformException catch (error) {
      if (error.code == 'custodyMissing') {
        throw const SystemKeyboardCustodyMissing();
      }
      rethrow;
    }
    if (value is! Map ||
        value.length != 2 ||
        value['revision'] is! int ||
        (value['revision'] as int) < 0 ||
        (value['revision'] as int) > SystemKeyboardRecordSnapshot.maxRevision ||
        value['snapshot'] is! Uint8List ||
        (value['snapshot'] as Uint8List).length >
            SystemKeyboardRecordSnapshot.maxBytes) {
      throw StateError('Invalid native custody snapshot');
    }
    // Platform-channel typed data can be an immutable view. Recovery owns and
    // wipes its snapshot after the private import journal is durable.
    return SystemKeyboardCustodySnapshot(value['revision'] as int,
        Uint8List.fromList(value['snapshot'] as Uint8List));
  }

  @override
  Future<void> removeAfterImport(
          Uint8List epoch, Uint8List key, int revision) =>
      _channel.invokeMethod<void>(
          'finish', {'epoch': epoch, 'key': key, 'revision': revision});
}
