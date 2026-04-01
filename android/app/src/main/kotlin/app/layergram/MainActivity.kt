package app.layergram

import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
  private val channelName = "layergram/screen_protection"
  private val prefsName = "layergram_prefs"
  private val enabledKey = "screen_protection_enabled"

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val enabled =
      getSharedPreferences(prefsName, MODE_PRIVATE).getBoolean(enabledKey, true)
    applyFlagSecure(enabled)
  }

  override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
    super.configureFlutterEngine(flutterEngine)

    MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
      .setMethodCallHandler { call, result ->
        when (call.method) {
          "setEnabled" -> {
            val enabled = (call.arguments as? Boolean) ?: false
            getSharedPreferences(prefsName, MODE_PRIVATE)
              .edit()
              .putBoolean(enabledKey, enabled)
              .apply()
            applyFlagSecure(enabled)
            result.success(null)
          }
          "isSupported" -> result.success(true)
          else -> result.notImplemented()
        }
      }
  }

  private fun applyFlagSecure(enabled: Boolean) {
    if (enabled) {
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    } else {
      window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
  }
}
