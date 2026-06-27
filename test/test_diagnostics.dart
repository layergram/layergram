import 'dart:developer' as developer;

const _diagnosticsEnabled = bool.fromEnvironment(
  'LAYERGRAM_TEST_DIAGNOSTICS',
);

void diagnosticLog(Object? message) {
  if (!_diagnosticsEnabled) return;
  developer.log('$message', name: 'layergram.test');
}
