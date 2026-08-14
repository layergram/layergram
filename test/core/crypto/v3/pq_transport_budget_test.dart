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

  test('canonical 256-byte cap produces five bounded fragments', () {
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
    expect(V3PqStegoBudget.canonicalFragmentFrameBytes(256), 418);
    expect(
      V3PqStegoBudget.minimumVisibleCoverCharactersForCanonicalFragment(256),
      169,
    );
    expect(
      V3PqStegoBudget.minimumEncodedCharactersForCanonicalFragment(256),
      2051,
    );
    expect(V3PqStegoBudget.canonicalFragmentFrameBytes(64), 226);
    expect(
      V3PqStegoBudget.minimumVisibleCoverCharactersForCanonicalFragment(64),
      121,
    );
    expect(
      V3PqStegoBudget.minimumEncodedCharactersForCanonicalFragment(64),
      1139,
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
    expect(
      () => V3PqStegoBudget.canonicalFragmentFrameBytes(0),
      throwsArgumentError,
    );
    expect(
      () => V3PqStegoBudget.canonicalFragmentFrameBytes(257),
      throwsArgumentError,
    );
  });
}
