// ignore_for_file: implementation_imports
// Copyright 2026 Layergram
// Licensed under the Apache License, Version 2.0.

import 'dart:io';
import 'dart:typed_data';

import 'package:hive/src/binary/binary_reader_impl.dart';
import 'package:hive/src/registry/type_registry_impl.dart';

/// Reads only the last deleted frame for one exact opaque key. The caller
/// authenticates its encrypted payload and validates a whole custody snapshot
/// before using it. A compacted or malformed file simply yields no candidate.
Future<String?> findDeletedEncryptedRecord(String path, String key,
    {void Function(String stage)? diagnosticStage}) async {
  try {
    final file = File(path);
    if (await file.length() > 64 * 1024 * 1024) {
      diagnosticStage?.call('historyFileOversize');
      return null;
    }
    final bytes = await file.readAsBytes();
    final reader =
        BinaryReaderImpl(Uint8List.fromList(bytes), TypeRegistryImpl.nullImpl);
    String? sealed;
    bool deleted = false;
    while (reader.availableBytes > 0) {
      final frame = reader.readFrame(frameOffset: reader.usedBytes);
      if (frame == null) {
        diagnosticStage?.call('historyFrameInvalid');
        return null;
      }
      if (frame.key != key) continue;
      if (frame.deleted) {
        deleted = true;
      } else {
        final value = frame.value;
        sealed = value is Map && value['encryptedRecord'] is String
            ? value['encryptedRecord'] as String
            : null;
        deleted = false;
      }
    }
    diagnosticStage?.call(deleted && sealed != null
        ? 'historyDeletedFrameFound'
        : 'historyDeletedFrameAbsent');
    return deleted ? sealed : null;
  } catch (_) {
    diagnosticStage?.call('historyReadError');
    return null;
  }
}
