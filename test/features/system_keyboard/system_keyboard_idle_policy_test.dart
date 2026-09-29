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

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_idle_policy.dart';

const int _start = 500000;
const int _twentySeconds = 20000;

SystemKeyboardIdleSession _liveSession({
  int start = _start,
  int? duration = _twentySeconds,
}) {
  final SystemKeyboardIdleSession? session = SystemKeyboardIdleSession.start(
    startMonotonicMillis: start,
    authorizedDurationMillis: duration,
  );
  expect(session, isNotNull);
  return session!;
}

void main() {
  group('preference validation', () {
    test('accepts exactly the supported durations', () {
      expect(
        SystemKeyboardIdlePolicy.supportedIdleSeconds,
        <int>[20, 30, 60, 120, 300],
      );
      for (final int seconds in SystemKeyboardIdlePolicy.supportedIdleSeconds) {
        expect(
          SystemKeyboardIdlePolicy.validatedPreferenceSeconds(seconds),
          seconds,
        );
      }
    });

    test('fails safe to the 60 second default', () {
      for (final Object? raw in <Object?>[
        null,
        '20',
        true,
        20.5,
        0,
        -20,
        19,
        45,
        301,
        9007199254740991,
      ]) {
        expect(SystemKeyboardIdlePolicy.validatedPreferenceSeconds(raw), 60);
      }
      expect(SystemKeyboardIdlePolicy.defaultIdleSeconds, 60);
    });
  });

  group('app lock clamp', () {
    test('disabled app lock keeps the validated request', () {
      expect(
        SystemKeyboardIdlePolicy.effectiveIdleSeconds(
          requestedIdleSeconds: 300,
          appLockEnabled: false,
          appLockTimeoutSeconds: 60,
        ),
        300,
      );
      expect(
        SystemKeyboardIdlePolicy.effectiveIdleMillis(
          requestedIdleSeconds: 120,
          appLockEnabled: false,
          appLockTimeoutSeconds: 60,
        ),
        120000,
      );
    });

    test('enabled app lock clamps down and never widens it', () {
      expect(
        SystemKeyboardIdlePolicy.effectiveIdleSeconds(
          requestedIdleSeconds: 300,
          appLockEnabled: true,
          appLockTimeoutSeconds: 120,
        ),
        120,
      );
      expect(
        SystemKeyboardIdlePolicy.effectiveIdleSeconds(
          requestedIdleSeconds: 20,
          appLockEnabled: true,
          appLockTimeoutSeconds: 120,
        ),
        20,
      );
      expect(
        SystemKeyboardIdlePolicy.effectiveIdleMillis(
          requestedIdleSeconds: 60,
          appLockEnabled: true,
          appLockTimeoutSeconds: 5,
        ),
        5000,
      );
    });

    test('immediate app lock denies the keyboard', () {
      for (final int timeout in <int>[0, -1]) {
        expect(
          SystemKeyboardIdlePolicy.effectiveIdleSeconds(
            requestedIdleSeconds: 300,
            appLockEnabled: true,
            appLockTimeoutSeconds: timeout,
          ),
          isNull,
        );
        expect(
          SystemKeyboardIdlePolicy.effectiveIdleMillis(
            requestedIdleSeconds: 300,
            appLockEnabled: true,
            appLockTimeoutSeconds: timeout,
          ),
          isNull,
        );
      }
    });
  });

  group('session start', () {
    test('denies missing, nonpositive, negative and unsafe inputs', () {
      expect(
        SystemKeyboardIdleSession.start(
          startMonotonicMillis: _start,
          authorizedDurationMillis: null,
        ),
        isNull,
      );
      expect(
        SystemKeyboardIdleSession.start(
          startMonotonicMillis: _start,
          authorizedDurationMillis: 0,
        ),
        isNull,
      );
      expect(
        SystemKeyboardIdleSession.start(
          startMonotonicMillis: _start,
          authorizedDurationMillis: -20000,
        ),
        isNull,
      );
      expect(
        SystemKeyboardIdleSession.start(
          startMonotonicMillis: -1,
          authorizedDurationMillis: _twentySeconds,
        ),
        isNull,
      );
      expect(
        SystemKeyboardIdleSession.start(
          startMonotonicMillis: _start,
          authorizedDurationMillis:
              SystemKeyboardIdlePolicy.maxSafeMonotonicMillis,
        ),
        isNull,
      );
    });

    test('exposes only status, deadline and remaining', () {
      final SystemKeyboardIdleSession session = _liveSession();
      expect(session.state, SystemKeyboardIdleState.active);
      expect(session.isTerminal, isFalse);
      expect(session.authorizedDurationMillis, _twentySeconds);
      expect(session.deadlineMonotonicMillis, _start + _twentySeconds);
      expect(session.observe(_start + 5000).remainingMillis, 15000);
    });
  });

  group('idle expiry', () {
    test('the 60 second preference renews only on keyboard activity', () {
      final session = _liveSession(duration: 60000);
      expect(session.observe(_start + 59000).isActive, isTrue);
      expect(
          session.recordUserInteraction(_start + 59000).remainingMillis, 60000);
      expect(session.observe(_start + 118999).isActive, isTrue);
      expect(session.observe(_start + 119000).state,
          SystemKeyboardIdleState.expired);
    });

    test('two minutes of continuous touch never expire', () {
      final SystemKeyboardIdleSession session = _liveSession();
      int now = _start;
      for (int second = 1; second <= 120; second++) {
        now += 1000;
        final SystemKeyboardIdleObservation observation =
            session.recordUserInteraction(now);
        expect(observation.isActive, isTrue);
        expect(observation.remainingMillis, _twentySeconds);
      }
      expect(now - _start, 120000);
      // Quiet polling inside the renewed window stays harmless but never
      // extends it: the deadline is still the last touch plus 20 seconds.
      expect(session.observe(now + 1000).isActive, isTrue);
      expect(session.deadlineMonotonicMillis, now + _twentySeconds);
    });

    test('quiet polling expires exactly at the deadline', () {
      final SystemKeyboardIdleSession session = _liveSession();
      for (int second = 1; second < 20; second++) {
        expect(session.observe(_start + second * 1000).isActive, isTrue);
      }
      final SystemKeyboardIdleObservation expired =
          session.observe(_start + _twentySeconds);
      expect(expired.state, SystemKeyboardIdleState.expired);
      expect(expired.remainingMillis, 0);
      expect(expired.deadlineMonotonicMillis, _start + _twentySeconds);
      expect(session.isTerminal, isTrue);
    });

    test('a touch exactly at the deadline cannot revive the session', () {
      final SystemKeyboardIdleSession session = _liveSession();
      expect(
        session.observe(_start + _twentySeconds).state,
        SystemKeyboardIdleState.expired,
      );
      expect(
        session.recordUserInteraction(_start + _twentySeconds).state,
        SystemKeyboardIdleState.expired,
      );
      expect(
        session.recordUserInteraction(_start + _twentySeconds + 1).state,
        SystemKeyboardIdleState.expired,
      );
      expect(session.deadlineMonotonicMillis, _start + _twentySeconds);
    });

    test('a backwards reading revokes an active session permanently', () {
      final SystemKeyboardIdleSession session = _liveSession();
      expect(session.observe(_start + 1000).isActive, isTrue);
      expect(
        session.observe(_start).state,
        SystemKeyboardIdleState.revoked,
      );
      expect(
        session.recordUserInteraction(_start + 2000).state,
        SystemKeyboardIdleState.revoked,
      );
      expect(session.isTerminal, isTrue);
    });

    test('a backwards reading never clears a prior expiry', () {
      final SystemKeyboardIdleSession session = _liveSession();
      expect(
        session.observe(_start + _twentySeconds).state,
        SystemKeyboardIdleState.expired,
      );
      expect(session.observe(_start).state, SystemKeyboardIdleState.expired);
      session.revoke();
      expect(session.state, SystemKeyboardIdleState.expired);
      expect(session.recordUserInteraction(_start + 1).state,
          SystemKeyboardIdleState.expired);
    });

    test('explicit revoke is terminal and idempotent', () {
      final SystemKeyboardIdleSession session = _liveSession();
      session.revoke();
      session.revoke();
      expect(session.state, SystemKeyboardIdleState.revoked);
      expect(
          session.observe(_start + 1).state, SystemKeyboardIdleState.revoked);
      expect(session.observe(_start + 1).remainingMillis, 0);
      expect(
        session.recordUserInteraction(_start + 1).state,
        SystemKeyboardIdleState.revoked,
      );
    });

    test('an overflowing renewal revokes instead of wrapping', () {
      final SystemKeyboardIdleSession session = _liveSession(
        start: 0,
        duration: SystemKeyboardIdlePolicy.maxSafeMonotonicMillis,
      );
      expect(session.observe(0).isActive, isTrue);
      final SystemKeyboardIdleObservation revoked =
          session.recordUserInteraction(1);
      expect(revoked.state, SystemKeyboardIdleState.revoked);
      expect(revoked.remainingMillis, 0);
      expect(
        session.deadlineMonotonicMillis,
        SystemKeyboardIdlePolicy.maxSafeMonotonicMillis,
      );
      expect(
        session.observe(2).state,
        SystemKeyboardIdleState.revoked,
      );
    });
  });
}
