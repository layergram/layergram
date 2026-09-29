package app.layergram

import org.junit.Assert.*
import org.junit.Test

class KeyboardCustodyEnvelopeTest {
  private val epoch = ByteArray(16) { 7 }
  private val key = ByteArray(32) { 9 }
  private val bytes = "private snapshot".toByteArray()
  private fun sealed(phase: Int = 1, revision: Long = 8) = KeyboardCustodyEnvelope.seal(
    KeyboardCustodyEnvelope.State(epoch, revision, phase, bytes), key)
  private fun denied(block: () -> Unit) { try { block(); fail("Expected denial") } catch (_: Exception) {} }

  @Test fun allOwnershipPhasesAndLatestRevisionRoundTrip() {
    for (phase in 0..2) {
      val state = KeyboardCustodyEnvelope.open(sealed(phase), epoch, key)
      assertEquals(8L, state.revision); assertEquals(phase, state.phase); assertArrayEquals(bytes, state.snapshot)
    }
  }
  @Test fun corruptedCiphertextAndEveryAuthenticatedHeaderFieldAreDenied() {
    val original = sealed()
    for (index in listOf(0, 4, 5, 6, 22, 29, 30, original.lastIndex)) {
      val changed = original.copyOf(); changed[index] = (changed[index].toInt() xor 1).toByte()
      denied { KeyboardCustodyEnvelope.open(changed, epoch, key) }
    }
  }
  @Test fun anotherEpochKeyAndTruncatedWritesNeverProduceASnapshot() {
    denied { KeyboardCustodyEnvelope.open(sealed(), ByteArray(16) { 8 }, key) }
    denied { KeyboardCustodyEnvelope.open(sealed(), epoch, ByteArray(32) { 8 }) }
    for (size in listOf(0, 12, 29, 30, 57, sealed().size - 1))
      denied { KeyboardCustodyEnvelope.open(sealed().copyOf(size), epoch, key) }
  }
  @Test fun strictBoundsRejectMalformedKeysEpochsPhasesRevisionsAndOversize() {
    for (revision in listOf(-1L, KeyboardCustodyEnvelope.MAX_REVISION + 1)) denied { sealed(revision = revision) }
    for (phase in listOf(-1, 3)) denied { sealed(phase = phase) }
    denied { KeyboardCustodyEnvelope.seal(KeyboardCustodyEnvelope.State(epoch, 0, 1, ByteArray(KeyboardCustodyEnvelope.MAX_BYTES + 1)), key) }
    denied { KeyboardCustodyEnvelope.open(sealed(), epoch, ByteArray(31)) }
  }
  @Test fun freshEncryptionNonceAndCiphertextDoNotExposeSnapshot() {
    val first = sealed(); val second = sealed()
    assertFalse(first.contentEquals(second))
    assertFalse(String(first).contains("private snapshot"))
  }
}
