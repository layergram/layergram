package app.layergram

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.view.WindowManager

/** Foreground owner for a biometric request originating in the system IME. */
class KeyboardBiometricActivity : Activity() {
  private var started = false

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
    if (!KeyboardAutonomousHost.hasBiometricFlow) finish()
  }

  override fun onResume() {
    super.onResume()
    if (started || isFinishing) return
    started = true
    window.decorView.post { if (!isFinishing) SystemKeyboardBroker.authenticateFromBiometricActivity(this) }
  }

  override fun onDestroy() {
    SystemKeyboardBroker.cancelBiometricActivity()
    super.onDestroy()
  }
}
