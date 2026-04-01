import 'package:fake_async/fake_async.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/security/app_lock_idle_controller.dart';

void main() {
  group('AppLockIdleController', () {
    test('locks after the configured foreground inactivity timeout', () {
      fakeAsync((async) {
        var lockCount = 0;
        final controller = AppLockIdleController(
          onLockRequired: () => lockCount++,
        );

        controller.updateLockConfig(enabled: true, timeoutSeconds: 5);
        controller.onUnlocked();

        async.elapse(const Duration(seconds: 4));
        expect(lockCount, 0);

        async.elapse(const Duration(seconds: 1));
        expect(lockCount, 1);

        controller.dispose();
      });
    });

    test('resets the inactivity countdown whenever the user interacts', () {
      fakeAsync((async) {
        var lockCount = 0;
        final controller = AppLockIdleController(
          onLockRequired: () => lockCount++,
        );

        controller.updateLockConfig(enabled: true, timeoutSeconds: 5);
        controller.onUnlocked();

        async.elapse(const Duration(seconds: 4));
        controller.onUserInteraction();
        async.elapse(const Duration(seconds: 4));
        expect(lockCount, 0);

        async.elapse(const Duration(seconds: 1));
        expect(lockCount, 1);

        controller.dispose();
      });
    });

    test('keeps the app unlocked when it resumes before the timeout and rearms inactivity timing', () {
      fakeAsync((async) {
        var lockCount = 0;
        final controller = AppLockIdleController(
          onLockRequired: () => lockCount++,
        );

        controller.updateLockConfig(enabled: true, timeoutSeconds: 5);
        controller.onUnlocked();
        controller.onAppLifecycleChanged(AppLifecycleState.inactive);

        async.elapse(const Duration(seconds: 3));
        controller.onAppLifecycleChanged(AppLifecycleState.resumed);
        expect(lockCount, 0);

        async.elapse(const Duration(seconds: 4));
        controller.onUserInteraction();
        async.elapse(const Duration(seconds: 4));
        expect(lockCount, 0);

        async.elapse(const Duration(seconds: 1));
        expect(lockCount, 1);

        controller.dispose();
      });
    });

    test('locks immediately on resume when timeout is zero', () {
      fakeAsync((async) {
        var lockCount = 0;
        final controller = AppLockIdleController(
          onLockRequired: () => lockCount++,
        );

        controller.updateLockConfig(enabled: true, timeoutSeconds: 0);
        controller.onUnlocked();
        controller.onAppLifecycleChanged(AppLifecycleState.inactive);

        async.elapse(const Duration(seconds: 1));
        controller.onAppLifecycleChanged(AppLifecycleState.resumed);
        expect(lockCount, 1);

        controller.dispose();
      });
    });
  });
}
