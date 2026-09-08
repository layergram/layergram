package app.layergram

import android.os.Bundle
import android.provider.Settings
import android.view.MotionEvent
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.android.FlutterView
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
  private val screenProtectionChannelName = "layergram/screen_protection"
  private val qrBrightnessChannelName = "layergram/screen_brightness"
  private val qrBrightnessFloor = 0.60f
  private val prefsName = "layergram_prefs"
  private val enabledKey = "screen_protection_enabled"
  private val screenProtectionTouchGate = ScreenProtectionTouchGate()
  private var qrBrightnessRequested = false
  private var previousScreenBrightness: Float? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    val enabled = initializeScreenProtectionPreference()
    // This runs before FlutterActivity creates and attaches the Flutter content view.
    applyWindowScreenProtection(enabled)
    super.onCreate(savedInstanceState)
    applyAccessibilityDataSensitivity(enabled)
  }

  override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
    super.configureFlutterEngine(flutterEngine)

    MethodChannel(flutterEngine.dartExecutor.binaryMessenger, screenProtectionChannelName)
      .setMethodCallHandler { call, result ->
        when (call.method) {
          "setEnabled" -> {
            val enabled = call.arguments as? Boolean
            if (enabled == null) {
              result.error(
                "invalid_arguments",
                "setEnabled requires a Boolean argument.",
                null,
              )
              return@setMethodCallHandler
            }
            applyScreenProtectionEnabled(enabled)
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
    screenProtectionTouchGate.reset()
    restorePreviousScreenBrightness(clearRequest = false)
    super.onPause()
  }

  override fun onResume() {
    super.onResume()
    applyAccessibilityDataSensitivity(isScreenProtectionEnabled())
    if (qrBrightnessRequested) {
      applyQrScreenBrightness(capturePrevious = false)
    }
  }

  override fun dispatchTouchEvent(event: MotionEvent): Boolean {
    return when (
      screenProtectionTouchGate.onTouchEvent(
        event.actionMasked,
        event.flags,
        isScreenProtectionEnabled(),
        android.os.Build.VERSION.SDK_INT,
      )
    ) {
      TouchDispatchAction.DISPATCH -> super.dispatchTouchEvent(event)
      TouchDispatchAction.REJECT -> false
      TouchDispatchAction.CANCEL_THEN_REJECT -> {
        dispatchCancellationToContent(event)
        false
      }
    }
  }

  private fun initializeScreenProtectionPreference(): Boolean {
    return getSharedPreferences(prefsName, MODE_PRIVATE).getBoolean(enabledKey, true)
  }

  private fun isScreenProtectionEnabled(): Boolean =
    getSharedPreferences(prefsName, MODE_PRIVATE).getBoolean(enabledKey, true)

  internal fun applyScreenProtectionEnabled(enabled: Boolean) {
    getSharedPreferences(prefsName, MODE_PRIVATE)
      .edit()
      .putBoolean(enabledKey, enabled)
      .apply()
    applyScreenProtection(enabled)
  }

  private fun applyScreenProtection(enabled: Boolean) {
    applyWindowScreenProtection(enabled)
    applyAccessibilityDataSensitivity(enabled)
  }

  private fun dispatchCancellationToContent(event: MotionEvent) {
    val pointerProperties = Array(event.pointerCount) { index ->
      MotionEvent.PointerProperties().also { event.getPointerProperties(index, it) }
    }
    val pointerCoordinates = Array(event.pointerCount) { index ->
      MotionEvent.PointerCoords().also { event.getPointerCoords(index, it) }
    }
    val obscuredFlags =
      MotionEvent.FLAG_WINDOW_IS_OBSCURED or MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED
    val cancellation = MotionEvent.obtain(
      event.downTime,
      event.eventTime,
      MotionEvent.ACTION_CANCEL,
      event.pointerCount,
      pointerProperties,
      pointerCoordinates,
      event.metaState,
      event.buttonState,
      event.xPrecision,
      event.yPrecision,
      event.deviceId,
      event.edgeFlags,
      event.source,
      event.flags and obscuredFlags.inv(),
    )
    try {
      super.dispatchTouchEvent(cancellation)
    } finally {
      cancellation.recycle()
    }
  }

  private fun applyWindowScreenProtection(enabled: Boolean) {
    if (enabled) {
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    } else {
      window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
      window.setHideOverlayWindows(enabled)
    }
  }

  private fun applyAccessibilityDataSensitivity(enabled: Boolean) {
    if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      return
    }
    val sensitivity = ScreenProtectionPolicy.accessibilityDataSensitivity(
      enabled,
      android.os.Build.VERSION.SDK_INT,
    ) ?: return

    window.decorView.setAccessibilityDataSensitive(sensitivity)
    findViewById<FlutterView>(FlutterActivity.FLUTTER_VIEW_ID)
      ?.setAccessibilityDataSensitive(sensitivity)
    // Flutter's virtual accessibility nodes are created by the engine. Marking this host view
    // limits some framework paths, but it is not complete virtual-node isolation.
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
