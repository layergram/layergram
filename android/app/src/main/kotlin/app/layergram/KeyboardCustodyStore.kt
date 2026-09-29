package app.layergram

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** One authenticated atomic leaf: state and ownership can never diverge. */
internal object KeyboardCustodyEnvelope {
  const val MAX_BYTES = 2 * 1024 * 1024
  const val MAX_REVISION = 9007199254740991L
  const val PREPARED = 0
  const val KEYBOARD = 1
  const val APP = 2
  data class State(val epoch: ByteArray, val revision: Long, val phase: Int, val snapshot: ByteArray)
  private const val HEADER = 30

  fun seal(state: State, key: ByteArray): ByteArray {
    require(key.size == 32 && state.epoch.size == 16 && state.epoch.any { it != 0.toByte() })
    require(state.revision in 0..MAX_REVISION && state.phase in PREPARED..APP && state.snapshot.size <= MAX_BYTES)
    val header = ByteBuffer.allocate(HEADER).putInt(0x4c4b4331).put(1).put(state.phase.toByte())
      .put(state.epoch).putLong(state.revision).array()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
    cipher.updateAAD(header)
    return header + cipher.iv + cipher.doFinal(state.snapshot)
  }

  fun open(bytes: ByteArray, epoch: ByteArray, key: ByteArray): State {
    require(key.size == 32 && epoch.size == 16 && bytes.size in (HEADER + 28)..(HEADER + 28 + MAX_BYTES))
    val header = bytes.copyOfRange(0, HEADER)
    val input = ByteBuffer.wrap(header)
    require(input.int == 0x4c4b4331 && input.get() == 1.toByte())
    val phase = input.get().toInt()
    val actualEpoch = ByteArray(16).also { input.get(it) }
    val revision = input.long
    require(MessageDigest.isEqual(epoch, actualEpoch) && revision in 0..MAX_REVISION && phase in PREPARED..APP)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, bytes.copyOfRange(HEADER, HEADER + 12)))
    cipher.updateAAD(header)
    return State(actualEpoch, revision, phase, cipher.doFinal(bytes.copyOfRange(HEADER + 12, bytes.size)))
  }
}

/** App-private, excluded from backup. App recovery supplies its journaled key. */
internal class KeyboardCustodyStore(context: Context, directory: File = File(context.noBackupFilesDir, "keyboard-custody")) {
  private val file: AtomicFile
  init { require(directory.exists() || directory.mkdirs()); file = AtomicFile(File(directory, "state")) }
  @Synchronized fun hasPending() = file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()

  @Synchronized fun prepare(epoch: ByteArray, key: ByteArray, snapshot: ByteArray) {
    check(!hasPending())
    write(KeyboardCustodyEnvelope.State(epoch, 0, KeyboardCustodyEnvelope.PREPARED, snapshot), key)
  }
  @Synchronized fun activate(epoch: ByteArray, key: ByteArray) = mutate(epoch, key) {
    check(it.phase == KeyboardCustodyEnvelope.PREPARED && it.revision == 0L)
    it.copy(phase = KeyboardCustodyEnvelope.KEYBOARD)
  }
  @Synchronized fun load(epoch: ByteArray, key: ByteArray): KeyboardCustodyEnvelope.State = read(epoch, key).also {
    if (it.phase != KeyboardCustodyEnvelope.KEYBOARD) { it.snapshot.fill(0); error("Custody unavailable") }
  }
  @Synchronized fun commit(epoch: ByteArray, key: ByteArray, snapshot: ByteArray, revision: Long): Long {
    val state = read(epoch, key)
    try {
      check(state.phase == KeyboardCustodyEnvelope.KEYBOARD && state.revision == revision && revision < KeyboardCustodyEnvelope.MAX_REVISION)
      write(state.copy(revision = revision + 1, snapshot = snapshot), key)
      return revision + 1
    } finally { state.snapshot.fill(0) }
  }
  @Synchronized fun reclaim(epoch: ByteArray, key: ByteArray): KeyboardCustodyEnvelope.State {
    val state = read(epoch, key)
    try { write(state.copy(phase = KeyboardCustodyEnvelope.APP), key) }
    catch (error: Throwable) { state.snapshot.fill(0); throw error }
    return state
  }
  @Synchronized fun finish(epoch: ByteArray, key: ByteArray, revision: Long) {
    // The authenticated app-private import receipt authorizes retrying cleanup
    // after a process interruption following AtomicFile.delete().
    if (!hasPending()) return
    val state = read(epoch, key)
    try { check(state.phase == KeyboardCustodyEnvelope.APP && state.revision == revision); file.delete(); check(!hasPending()) }
    finally { state.snapshot.fill(0) }
  }
  private fun read(epoch: ByteArray, key: ByteArray): KeyboardCustodyEnvelope.State {
    check(hasPending())
    val bytes = file.openRead().use { input ->
      check(input.available() <= KeyboardCustodyEnvelope.MAX_BYTES + 128)
      input.readBytes()
    }
    return try { KeyboardCustodyEnvelope.open(bytes, epoch, key) } finally { bytes.fill(0) }
  }
  private fun write(state: KeyboardCustodyEnvelope.State, key: ByteArray) {
    val bytes = KeyboardCustodyEnvelope.seal(state, key)
    val output = file.startWrite()
    try { output.write(bytes); file.finishWrite(output) }
    catch (error: Throwable) { file.failWrite(output); throw error }
    finally { bytes.fill(0) }
  }
  private fun mutate(epoch: ByteArray, key: ByteArray, change: (KeyboardCustodyEnvelope.State) -> KeyboardCustodyEnvelope.State) {
    val state = read(epoch, key)
    try { write(change(state), key) } finally { state.snapshot.fill(0) }
  }
}
