package app.layergram

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import android.widget.TextView
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.lang.ref.WeakReference

/** Read-only QA check: prints booleans, never preferences or keyboard content. */
class KeyboardOptInReadbackInstrumentedTest {
  @Test fun reportNativeKeyboardConfiguration() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    assertEquals("app.layergram.keyboardvalidation", context.packageName)
    val prefs = context.getSharedPreferences("layergram_prefs", Context.MODE_PRIVATE)
    val component = ComponentName(context, LayergramInputMethodService::class.java)
    val componentEnabled = context.packageManager.getComponentEnabledSetting(component) ==
      PackageManager.COMPONENT_ENABLED_STATE_ENABLED
    val id = component.flattenToString()
    val enabledBySystem = Settings.Secure.getString(context.contentResolver,
      Settings.Secure.ENABLED_INPUT_METHODS)?.split(':')?.contains(id) == true
    println("QA_KEYBOARD_NATIVE_OPT_IN=" + prefs.getBoolean("system_keyboard_enabled", false))
    println("QA_KEYBOARD_AUTONOMOUS_OPT_IN=" + prefs.getBoolean("system_keyboard_autonomous", false))
    println("QA_KEYBOARD_COMPONENT_ENABLED=" + componentEnabled)
    println("QA_KEYBOARD_OS_IME_ENABLED=" + enabledBySystem)
    println("QA_KEYBOARD_OS_DEFAULT=" + (Settings.Secure.getString(context.contentResolver,
      Settings.Secure.DEFAULT_INPUT_METHOD) == id))
  }

  /** QA-only repair after installing an app compiled without the keyboard. */
  @Test fun restorePriorNativeConsentWhenExplicitlyRequested() {
    if (InstrumentationRegistry.getArguments().getString("qaRestoreNativeConsent") != "yes") return
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    assertEquals("app.layergram.keyboardvalidation", context.packageName)
    val component = ComponentName(context, LayergramInputMethodService::class.java)
    val id = component.flattenToString()
    val enabledBySystem = Settings.Secure.getString(context.contentResolver,
      Settings.Secure.ENABLED_INPUT_METHODS)?.split(':')?.contains(id) == true
    org.junit.Assert.assertTrue("Require the user's prior Android IME authorization", enabledBySystem)
    val prefs = context.getSharedPreferences("layergram_prefs", Context.MODE_PRIVATE)
    org.junit.Assert.assertTrue(prefs.edit().putBoolean("system_keyboard_enabled", true)
      .putBoolean("system_keyboard_autonomous", true).commit())
    context.packageManager.setComponentEnabledSetting(component,
      PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
    assertEquals(PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
      context.packageManager.getComponentEnabledSetting(component))
  }

  @Test fun reportLiveKeyboardAdmissionWithoutContent() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    assertEquals("app.layergram.keyboardvalidation", context.packageName)
    val serviceReference = SystemKeyboardBroker::class.java.getDeclaredField("serviceRef")
      .apply { isAccessible = true }.get(SystemKeyboardBroker) as? WeakReference<*>
    val service = serviceReference?.get() as? LayergramInputMethodService
    val label = service?.let {
      val status = LayergramInputMethodService::class.java.getDeclaredField("statusView")
        .apply { isAccessible = true }.get(it) as? TextView
      when (status?.text?.toString()) {
        it.getString(R.string.sk_status_ready) -> "ready"
        it.getString(R.string.sk_status_unavailable) -> "unavailable"
        it.getString(R.string.sk_status_touch_to_unlock) -> "touchToUnlock"
        it.getString(R.string.sk_status_unlocking) -> "unlocking"
        it.getString(R.string.sk_status_connecting) -> "connecting"
        else -> "other"
      }
    } ?: "noService"
    println("QA_KEYBOARD_STATUS=" + label)
    println("QA_KEYBOARD_RUNTIME_RUNNING=" + KeyboardAutonomousHost.isRunning)
    println("QA_KEYBOARD_TICKET_PRESENT=" +
      File(context.noBackupFilesDir, "keyboard-biometric-ticket").exists())
    println("QA_KEYBOARD_CUSTODY_PENDING=" + KeyboardCustodyStore(context).hasPending())
  }

  @Test fun reportBiometricCipherInitializationCategory() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    assertEquals("app.layergram.keyboardvalidation", context.packageName)
    val filePresent = File(context.noBackupFilesDir, "keyboard-biometric-ticket").exists()
    val keyPresent = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
      .containsAlias("layergram.keyboard.resume.v1")
    val outcome = try {
      KeyboardBiometricTicket(context).decryptCipher()
      "ready"
    } catch (error: Throwable) {
      when (error) {
        is android.security.keystore.KeyPermanentlyInvalidatedException -> "invalidated"
        is java.lang.IllegalStateException -> "state"
        is java.security.GeneralSecurityException -> "keystore"
        else -> "other"
      }
    }
    println("QA_BIOMETRIC_FILE_PRESENT=" + filePresent)
    println("QA_BIOMETRIC_KEY_PRESENT=" + keyPresent)
    println("QA_BIOMETRIC_CIPHER_INIT=" + outcome)
  }
}
