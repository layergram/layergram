package app.layergram

import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
  private val screenProtectionChannelName = "layergram/screen_protection"
  private val qrBrightnessChannelName = "layergram/screen_brightness"
  private val qrBrightnessFloor = 0.60f
  private val prefsName = "layergram_prefs"
  private val enabledKey = "screen_protection_enabled"
  private var qrBrightnessRequested = false
  private var previousScreenBrightness: Float? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val enabled =
      getSharedPreferences(prefsName, MODE_PRIVATE).getBoolean(enabledKey, true)
    applyFlagSecure(enabled)
  }

  override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
    super.configureFlutterEngine(flutterEngine)

    MethodChannel(flutterEngine.dartExecutor.binaryMessenger, screenProtectionChannelName)
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

    MethodChannel(flutterEngine.dartExecutor.binaryMessenger, qrBrightnessChannelName)
      .setMethodCallHandler { call, result ->
        when (call.method) {
          "setQrDisplayActive" -> {
            setQrDisplayActive((call.arguments as? Boolean) ?: false)
            result.success(null)
          }
          else -> result.notImplemented()
        }
      }
  }

  override fun onPause() {
    restorePreviousScreenBrightness(clearRequest = false)
    super.onPause()
  }

  override fun onResume() {
    super.onResume()
    if (qrBrightnessRequested) {
      applyQrScreenBrightness(capturePrevious = false)
    }
  }

  private fun applyFlagSecure(enabled: Boolean) {
    if (enabled) {
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    } else {
      window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
  }

  private fun setQrDisplayActive(active: Boolean) {
    if (active) {
      if (qrBrightnessRequested) return
      qrBrightnessRequested = true
      applyQrScreenBrightness(capturePrevious = true)
    } else {
      restorePreviousScreenBrightness(clearRequest = true)
    }
  }

  private fun applyQrScreenBrightness(capturePrevious: Boolean) {
    val attributes = window.attributes
    if (capturePrevious) {
      previousScreenBrightness = attributes.screenBrightness
    }
    val baseline = previousScreenBrightness
      ?.takeIf { it >= 0.0f }
      ?: (Settings.System.getInt(
        contentResolver,
        Settings.System.SCREEN_BRIGHTNESS,
        128,
      ) / 255.0f)
    attributes.screenBrightness = maxOf(baseline, qrBrightnessFloor)
    window.attributes = attributes
  }

  private fun restorePreviousScreenBrightness(clearRequest: Boolean) {
    if (previousScreenBrightness != null) {
      val attributes = window.attributes
      attributes.screenBrightness = previousScreenBrightness
        ?: WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE
      window.attributes = attributes
    }

    if (clearRequest) {
      qrBrightnessRequested = false
      previousScreenBrightness = null
    }
  }
}
