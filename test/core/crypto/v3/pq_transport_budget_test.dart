import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/core/crypto/v3/ml_kem_768.dart';
import 'package:layergram/core/crypto/v3/pq_transport_budget.dart';

void main() {
  test('full ML-KEM ciphertext exposes current raw stego cover cost', () {
    expect(
      V3PqStegoBudget.requiredCarrierSlotsForRawFragment(
        MlKem768.ciphertextBytes,
      ),
      272,
    );
    expect(
      V3PqStegoBudget.minimumVisibleCoverCharactersForRawFragment(
        MlKem768.ciphertextBytes,
      ),
      336,
    );
  });

  test('candidate 256-byte payload cap produces bounded raw fragments', () {
    final sizes = V3PqStegoBudget.fragmentPayloadSizes(
      totalPayloadBytes: MlKem768.ciphertextBytes,
      maxFragmentPayloadBytes: 256,
    );

    expect(sizes, <int>[256, 256, 256, 256, 64]);
    expect(sizes.reduce((sum, value) => sum + value), 1088);
    expect(
      V3PqStegoBudget.minimumVisibleCoverCharactersForRawFragment(256),
      128,
    );
  });

  test('fragment sizing rejects invalid budgets', () {
    expect(
      () => V3PqStegoBudget.fragmentCount(
        totalPayloadBytes: -1,
        maxFragmentPayloadBytes: 256,
      ),
      throwsArgumentError,
    );
    expect(
      () => V3PqStegoBudget.fragmentCount(
        totalPayloadBytes: 1,
        maxFragmentPayloadBytes: 0,
      ),
      throwsArgumentError,
    );
  });
}
