// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:async';

enum ExternalIngressKind { deepLink, sharedText }

final class ExternalIngressItem {
  const ExternalIngressItem({required this.kind, required this.text});

  final ExternalIngressKind kind;
  final String text;
}

typedef ExternalIngressHandler = Future<void> Function(
  ExternalIngressItem item,
);

/// Bounded, transport-agnostic staging for untrusted external carriers.
///
/// Values remain opaque until [drain] is called after app unlock. This keeps
/// deep links and OS share intents convenient without letting either carrier
/// parse, decrypt, mutate durable protocol state, or navigate behind the lock.
final class ExternalIngressCoordinator {
  ExternalIngressCoordinator({
    this.maxItems = 4,
    required this.maxTotalCodeUnits,
  }) {
    if (maxItems <= 0 || maxTotalCodeUnits <= 0) {
      throw ArgumentError('External ingress limits must be positive');
    }
  }

  final int maxItems;
  final int maxTotalCodeUnits;

  final List<ExternalIngressItem> _pending = <ExternalIngressItem>[];
  Future<void> _drainTail = Future<void>.value();
  int _totalCodeUnits = 0;
  bool _closed = false;

  int get pendingCount => _pending.length;

  bool enqueue({required ExternalIngressKind kind, required String text}) {
    if (_closed) return false;
    if (text.isEmpty || text.length > maxTotalCodeUnits) {
      return false;
    }
    if (_pending.any(
      (item) => item.kind == kind && item.text == text,
    )) {
      return true;
    }
    if (_pending.length >= maxItems ||
        _totalCodeUnits + text.length > maxTotalCodeUnits) {
      return false;
    }
    _pending.add(ExternalIngressItem(kind: kind, text: text));
    _totalCodeUnits += text.length;
    return true;
  }

  Future<void> drain({
    required bool Function() mayProcess,
    required ExternalIngressHandler handler,
  }) {
    final completer = Completer<void>();
    final previous = _drainTail;
    _drainTail = previous.catchError((_) {}).then((_) async {
      try {
        while (!_closed && mayProcess() && _pending.isNotEmpty) {
          final item = _pending.first;
          await handler(item);
          _pending.removeAt(0);
          _totalCodeUnits -= item.text.length;
        }
        completer.complete();
      } catch (error, stackTrace) {
        // Keep the current item queued. A later unlock/resume can retry it.
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  void close() {
    _closed = true;
    _pending.clear();
    _totalCodeUnits = 0;
  }
}
