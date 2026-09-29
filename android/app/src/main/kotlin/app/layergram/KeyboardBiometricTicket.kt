package app.layergram

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.AtomicFile
import io.flutter.plugin.common.StandardMessageCodec
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/** Revocable capability; private unwrap requires a fresh strong biometric. */
internal class KeyboardBiometricTicket(private val context: Context) {
  private val file = AtomicFile(File(context.noBackupFilesDir, "keyboard-biometric-ticket"))
  private val alias = "layergram.keyboard.resume.v1"
  private val codec = StandardMessageCodec.INSTANCE
  private val oaep = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
  private fun keys() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  private fun boot() = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, -1)

  fun seal(grant: Map<String, Any>) {
    require(Build.VERSION.SDK_INT >= 28 && boot() >= 0)
    val store = keys()
    // A new app-authorized delegation may replace a key invalidated by an
    // enrollment change. A locked keyboard never recreates the credential.
    if (store.containsAlias(alias)) {
      try { decryptCipherForKey(store.getKey(alias, null) as PrivateKey) }
      catch (_: KeyPermanentlyInvalidatedException) { file.delete(); store.deleteEntry(alias) }
    }
    if (!store.containsAlias(alias)) {
      val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
        .setKeySize(2048).setDigests(KeyProperties.DIGEST_SHA256)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        .setUserAuthenticationRequired(true).setInvalidatedByBiometricEnrollment(true)
      if (Build.VERSION.SDK_INT >= 30) spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
      else @Suppress("DEPRECATION") spec.setUserAuthenticationValidityDurationSeconds(-1)
      KeyPairGenerator.getInstance("RSA", "AndroidKeyStore").apply { initialize(spec.build()) }.generateKeyPair()
    }
    val envelope = mapOf("v" to 2, "boot" to boot(),
      "issued" to SystemClock.elapsedRealtime(), "grant" to grant)
    val encoded = codec.encodeMessage(envelope)!!
    val plaintext = ByteArray(encoded.position()).also { encoded.flip(); encoded.get(it) }
    encoded.clear(); while (encoded.hasRemaining()) encoded.put(0)
    val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
    try {
      require(plaintext.size <= 256 * 1024)
      val rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      rsa.init(Cipher.ENCRYPT_MODE, store.getCertificate(alias).publicKey, oaep)
      val wrapped = rsa.doFinal(key)
      val aes = Cipher.getInstance("AES/GCM/NoPadding")
      aes.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES")); aes.updateAAD(wrapped)
      val bytes = wrapped + aes.iv + aes.doFinal(plaintext)
      val output = file.startWrite()
      try { output.write(bytes); file.finishWrite(output) }
      catch (error: Throwable) { file.failWrite(output); throw error }
      finally { bytes.fill(0) }
    } finally { key.fill(0); plaintext.fill(0) }
  }
  fun decryptCipher(): Cipher {
    check(Build.VERSION.SDK_INT >= 28 && file.baseFile.exists())
    return decryptCipherForKey(keys().getKey(alias, null) as PrivateKey)
  }
  private fun decryptCipherForKey(key: PrivateKey): Cipher =
    Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").apply { init(Cipher.DECRYPT_MODE, key, oaep) }
  @Suppress("UNCHECKED_CAST") fun open(authenticatedCipher: Cipher): Map<String, Any> {
    val bytes = file.openRead().use { check(it.available() in 284..(256 * 1024 + 284)); it.readBytes() }
    var key: ByteArray? = null; var plaintext: ByteArray? = null
    try {
      val wrapped = bytes.copyOfRange(0, 256)
      key = authenticatedCipher.doFinal(wrapped)
      check(key.size == 32)
      val aes = Cipher.getInstance("AES/GCM/NoPadding")
      aes.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, bytes.copyOfRange(256, 268)))
      aes.updateAAD(wrapped); plaintext = aes.doFinal(bytes.copyOfRange(268, bytes.size))
      val buffer = ByteBuffer.allocateDirect(plaintext.size).apply { put(plaintext) }
      val envelope = codec.decodeMessage(buffer.apply { flip() }) as? Map<*, *> ?: error("Invalid ticket")
      try {
        val issued = envelope["issued"] as? Long ?: error("Invalid ticket")
        val savedBoot = envelope["boot"] as? Int ?: error("Invalid ticket")
        val version = if (envelope.containsKey("v")) envelope["v"] as? Int ?: error("Invalid ticket") else 1
        check(envelope.size == (if (version == 1) 3 else 4) &&
          KeyboardBiometricPolicy.admits(version, savedBoot, boot(), issued, SystemClock.elapsedRealtime()))
        return envelope["grant"] as? Map<String, Any> ?: error("Invalid ticket")
      } finally { buffer.clear(); while (buffer.hasRemaining()) buffer.put(0) }
    } finally { bytes.fill(0); key?.fill(0); plaintext?.fill(0) }
  }
  fun remove() { file.delete() }
}
