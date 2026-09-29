package app.layergram

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Deliberately run in three separate processes around install -r and uninstall. */
class KeyboardLifecycleInstrumentedTest {
  @Test fun updatePreservesLatestCustodyAndReinstallCannotResumeOldInstallation() {
    val instrumentation = InstrumentationRegistry.getInstrumentation()
    val context = instrumentation.targetContext
    assertEquals("app.layergram.keyboardvalidation", context.packageName)
    val stage = InstrumentationRegistry.getArguments().getString("lifecycleStage")
    val custody = KeyboardCustodyStore(context)
    val epoch = ByteArray(16) { 91 }; val key = ByteArray(32) { 72 }
    val marker = byteArrayOf(6, 7, 8, 9)
    val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "layergram.validation.update.canary"
    val canary = java.io.File(context.noBackupFilesDir, "validation-canary")
    val prefs = context.getSharedPreferences("layergram_prefs", 0)
    when (stage) {
      "seed" -> {
        assertFalse(custody.hasPending())
        custody.prepare(epoch, key, byteArrayOf(0)); custody.activate(epoch, key)
        for (revision in 0L..3L) custody.commit(epoch, key, marker, revision)
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build()
        val secret = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
          .apply { init(spec) }.generateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, secret) }
        canary.writeBytes(cipher.iv + cipher.doFinal(marker))
        assertTrue(prefs.edit().putBoolean("system_keyboard_enabled", true).putBoolean("system_keyboard_autonomous", true).commit())
      }
      "upgrade" -> {
        val latest = custody.load(epoch, key)
        assertEquals(4L, latest.revision); assertArrayEquals(marker, latest.snapshot)
        assertTrue(prefs.getBoolean("system_keyboard_enabled", false))
        val sealed = canary.readBytes()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
          init(Cipher.DECRYPT_MODE, keystore.getKey(alias, null) as SecretKey, GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
        }
        assertArrayEquals(marker, cipher.doFinal(sealed.copyOfRange(12, sealed.size)))
        // The updated installation resumes the latest state and advances it.
        assertEquals(5L, custody.commit(epoch, key, marker, latest.revision))
      }
      "fresh" -> {
        assertFalse(custody.hasPending()); assertFalse(canary.exists())
        assertFalse(keystore.containsAlias(alias))
        assertFalse(prefs.getBoolean("system_keyboard_enabled", false))
        try { custody.load(epoch, key); fail("Old custody cannot be inferred after uninstall") } catch (_: IllegalStateException) { }
        try { KeyboardBiometricTicket(context).decryptCipher(); fail("No old biometric capability may survive reinstall") } catch (_: IllegalStateException) { }
      }
      else -> fail("Explicit lifecycleStage seed/upgrade/fresh required")
    }
  }
}
