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
    expect(V3PqStegoBudget.canonicalFragmentFrameBytes(256), 452);
    expect(
      V3PqStegoBudget.minimumVisibleCoverCharactersForCanonicalFragment(256),
      177,
    );
    expect(
      V3PqStegoBudget.minimumEncodedCharactersForCanonicalFragment(256),
      2211,
    );
    expect(V3PqStegoBudget.canonicalFragmentFrameBytes(64), 260);
    expect(
      V3PqStegoBudget.minimumVisibleCoverCharactersForCanonicalFragment(64),
      129,
    );
    expect(
      V3PqStegoBudget.minimumEncodedCharactersForCanonicalFragment(64),
      1299,
    );
  });

  test('maximum HR3 first fragment remains within 4000 stego characters', () {
    expect(
      V3PqStegoBudget.canonicalFragmentFrameBytes(
        24,
        hybridRatchetHeaderBytes: 608,
      ),
      828,
    );
    expect(
      V3PqStegoBudget.minimumVisibleCoverCharactersForCanonicalFragment(
        24,
        hybridRatchetHeaderBytes: 608,
      ),
      271,
    );
    expect(
      V3PqStegoBudget.minimumEncodedCharactersForCanonicalFragment(
        24,
        hybridRatchetHeaderBytes: 608,
      ),
      3997,
    );
    expect(
      V3PqStegoBudget.canonicalFragmentFrameBytes(
        256,
        hybridRatchetHeaderBytes: 96,
      ),
      548,
    );
    expect(
      () => V3PqStegoBudget.canonicalFragmentFrameBytes(
        25,
        hybridRatchetHeaderBytes: 608,
      ),
      throwsArgumentError,
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
