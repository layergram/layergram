import 'dart:developer' as developer;

const _diagnosticsEnabled = bool.fromEnvironment(
  'LAYERGRAM_TEST_DIAGNOSTICS',
);

void diagnosticLog(Object? message) {
  if (!_diagnosticsEnabled) return;
  developer.log(_redactDiagnosticMessage('$message'), name: 'layergram.test');
}

String _redactDiagnosticMessage(String message) {
  var redacted = message;

  redacted = redacted.replaceAllMapped(
    RegExp(r'layergram://[^\s)\]]+'),
    (_) => 'layergram://<redacted>',
  );
  redacted = redacted.replaceAllMapped(
    RegExp(r'\b(?:[A-Fa-f0-9]{2}-){7}[A-Fa-f0-9]{2}\b'),
    (_) => '<fingerprint:redacted>',
  );
  redacted = redacted.replaceAllMapped(
    RegExp(r'\b[A-Za-z0-9+/]{32,}={0,2}\b'),
    (_) => '<base64:redacted>',
  );
  redacted = redacted.replaceAllMapped(
    RegExp(r'\b[A-Z2-7]{32,}\b'),
    (_) => '<id:redacted>',
  );
  redacted = redacted.replaceAllMapped(
    RegExp(r'(password\s*:\s*)[^\r\n]+', caseSensitive: false),
    (match) => '${match.group(1)}<redacted>',
  );
  redacted = redacted.replaceAllMapped(
    RegExp(r'(decrypted text\s*:\s*)[^\r\n]+', caseSensitive: false),
    (match) => '${match.group(1)}<redacted>',
  );
  redacted = redacted.replaceAllMapped(
    RegExp(r'(digits\s*:\s*)[0-9 -]{4,}', caseSensitive: false),
    (match) => '${match.group(1)}<redacted>',
  );

  return redacted;
}
