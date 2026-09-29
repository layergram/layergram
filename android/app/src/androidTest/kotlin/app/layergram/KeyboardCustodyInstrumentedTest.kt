package app.layergram

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.UUID

/** Real AtomicFile I/O; each case uses disposable state, never a user's FS. */
class KeyboardCustodyInstrumentedTest {
  private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
  private val epoch = ByteArray(16) { 4 }
  private val key = ByteArray(32) { 2 }
  private fun denied(block: () -> Unit) { try { block(); fail("Expected denial") } catch (_: Exception) {} }
  private fun fixture(block: (File, KeyboardCustodyStore) -> Unit) {
    val folder = File(context.cacheDir, "custody-test-${UUID.randomUUID()}")
    try { block(folder, KeyboardCustodyStore(context, folder)) } finally { folder.deleteRecursively() }
  }
  @Test fun preparedStateCannotBeUsedAndAppReclaimsWithoutActivationAfterInterruption() = fixture { _, store ->
    store.prepare(epoch, key, byteArrayOf(1))
    denied { store.load(epoch, key) }
    val recovered = store.reclaim(epoch, key)
    assertEquals(0L, recovered.revision); assertArrayEquals(byteArrayOf(1), recovered.snapshot)
    store.finish(epoch, key, 0); assertFalse(store.hasPending())
    // Private import cleanup can retry after the process dies immediately
    // after deleting the native snapshot; it must not strand its receipt.
    store.finish(epoch, key, 0); assertFalse(store.hasPending())
  }
  @Test fun recreatedStoreContinuesLatestRevisionAndRejectsStaleCompetingWrites() = fixture { folder, store ->
    store.prepare(epoch, key, byteArrayOf(1)); store.activate(epoch, key)
    assertEquals(1L, store.commit(epoch, key, byteArrayOf(2), 0))
    val reopened = KeyboardCustodyStore(context, folder)
    assertArrayEquals(byteArrayOf(2), reopened.load(epoch, key).snapshot)
    denied { reopened.commit(epoch, key, byteArrayOf(3), 0) }
    assertArrayEquals(byteArrayOf(2), reopened.load(epoch, key).snapshot)
    assertEquals(2L, reopened.commit(epoch, key, byteArrayOf(4), 1))
    val recovered = store.reclaim(epoch, key)
    assertEquals(2L, recovered.revision); assertArrayEquals(byteArrayOf(4), recovered.snapshot)
    denied { reopened.commit(epoch, key, byteArrayOf(5), 2) }
    denied { store.finish(epoch, key, 1) }
    store.finish(epoch, key, 2)
  }
  @Test fun uncertainCommitCorruptionAndMissingStateFailClosedWithoutResettingData() = fixture { folder, store ->
    store.prepare(epoch, key, byteArrayOf(1)); store.activate(epoch, key)
    val leaf = File(folder, "state")
    val sealed = leaf.readBytes(); sealed[sealed.lastIndex] = (sealed.last().toInt() xor 1).toByte(); leaf.writeBytes(sealed)
    denied { store.reclaim(epoch, key) }
    assertTrue(store.hasPending())
    denied { store.prepare(epoch, key, byteArrayOf(8)) }
    leaf.delete()
    denied { store.load(epoch, key) }
    assertFalse(store.hasPending())
  }
  @Test fun interruptedAtomicWriteRecoversOnlyPreviousCommittedLeaf() = fixture { folder, store ->
    store.prepare(epoch, key, byteArrayOf(1)); store.activate(epoch, key)
    store.commit(epoch, key, byteArrayOf(2), 0)
    File(folder, "state.new").writeBytes(byteArrayOf(0, 1, 2))
    val reopened = KeyboardCustodyStore(context, folder)
    assertEquals(1L, reopened.load(epoch, key).revision)
    assertArrayEquals(byteArrayOf(2), reopened.load(epoch, key).snapshot)
  }
  @Test fun newInstallationCannotImportOrphanStateWithAnotherEpochOrKey() = fixture { folder, store ->
    store.prepare(epoch, key, byteArrayOf(1)); store.activate(epoch, key)
    val reopened = KeyboardCustodyStore(context, folder)
    denied { reopened.reclaim(ByteArray(16) { 8 }, key) }
    denied { reopened.reclaim(epoch, ByteArray(32) { 8 }) }
    assertArrayEquals(byteArrayOf(1), store.load(epoch, key).snapshot)
  }
}
