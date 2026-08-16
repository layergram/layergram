import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/scka_candidate_ffi.dart';

void main() {
  test('Linux packaged path is executable-relative and absolute', () {
    final path = V3SckaCandidateFfiBackend.packagedLinuxLibraryPath(
      executablePath: '/opt/layergram/layergram',
    );
    expect(path, '/opt/layergram/lib/liblayergram_scka.so');
    expect(File(path).isAbsolute, isTrue);
  });

  test(
    'Windows packaged path is executable-relative and absolute',
    () {
      final path = V3SckaCandidateFfiBackend.packagedWindowsLibraryPath(
        executablePath: r'C:\Program Files\Layergram\layergram.exe',
      );
      expect(
        path,
        r'C:\Program Files\Layergram\layergram_scka.dll',
      );
      expect(File(path).isAbsolute, isTrue);
    },
    skip: !Platform.isWindows,
  );
}
