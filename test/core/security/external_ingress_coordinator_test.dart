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

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/security/external_ingress_coordinator.dart';

void main() {
  test('locked carriers stay opaque and drain in arrival order after unlock',
      () async {
    final coordinator = ExternalIngressCoordinator(
      maxItems: 4,
      maxTotalCodeUnits: 128,
    );
    final processed = <ExternalIngressItem>[];
    var unlocked = false;

    expect(
      coordinator.enqueue(
        kind: ExternalIngressKind.deepLink,
        text: 'layergram://m/first',
      ),
      isTrue,
    );
    expect(
      coordinator.enqueue(
        kind: ExternalIngressKind.sharedText,
        text: 'whatsapp-response',
      ),
      isTrue,
    );

    await coordinator.drain(
      mayProcess: () => unlocked,
      handler: (item) async => processed.add(item),
    );
    expect(processed, isEmpty);
    expect(coordinator.pendingCount, 2);

    unlocked = true;
    await coordinator.drain(
      mayProcess: () => unlocked,
      handler: (item) async => processed.add(item),
    );
    expect(
      processed.map((item) => item.kind),
      [ExternalIngressKind.deepLink, ExternalIngressKind.sharedText],
    );
    expect(coordinator.pendingCount, 0);
  });

  test('bounds and deduplicates exact opaque carriers without normalization',
      () async {
    final coordinator = ExternalIngressCoordinator(
      maxItems: 2,
      maxTotalCodeUnits: 10,
    );
    expect(
      coordinator.enqueue(
        kind: ExternalIngressKind.sharedText,
        text: ' 1234 ',
      ),
      isTrue,
    );
    expect(
      coordinator.enqueue(
        kind: ExternalIngressKind.sharedText,
        text: ' 1234 ',
      ),
      isTrue,
    );
    expect(coordinator.pendingCount, 1);
    expect(
      coordinator.enqueue(
        kind: ExternalIngressKind.deepLink,
        text: '5678901',
      ),
      isFalse,
    );
    expect(coordinator.pendingCount, 1);
    String? received;
    await coordinator.drain(
      mayProcess: () => true,
      handler: (item) async => received = item.text,
    );
    expect(received, ' 1234 ');
  });

  test('a lock request lets the current handler finish and stops the next item',
      () async {
    final coordinator = ExternalIngressCoordinator(
      maxItems: 2,
      maxTotalCodeUnits: 32,
    );
    var unlocked = true;
    var attempts = 0;
    coordinator.enqueue(
      kind: ExternalIngressKind.sharedText,
      text: 'first-response',
    );
    coordinator.enqueue(
      kind: ExternalIngressKind.sharedText,
      text: 'second-response',
    );

    await coordinator.drain(
      mayProcess: () => unlocked,
      handler: (_) async {
        attempts++;
        unlocked = false;
      },
    );
    expect(attempts, 1);
    expect(coordinator.pendingCount, 1);

    unlocked = true;
    await coordinator.drain(
      mayProcess: () => unlocked,
      handler: (_) async => attempts++,
    );
    expect(attempts, 2);
    expect(coordinator.pendingCount, 0);
  });
}
