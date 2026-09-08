package app.layergram

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Build
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.ActivityTestRule
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.android.FlutterView
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class ScreenProtectionInstrumentedTest {
  @get:Rule
  val activityRule = ActivityTestRule(MainActivity::class.java, true, false)

  private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

  @After
  fun clearPreference() {
    context.getSharedPreferences(PREFERENCES_NAME, 0).edit().clear().commit()
  }

  @Test
  fun coldDefaultEnablesProtection() {
    context.getSharedPreferences(PREFERENCES_NAME, 0).edit().clear().commit()
    val activity = activityRule.launchActivity(Intent())

    activityRule.runOnUiThread {
      assertTrue(isSecure(activity))
    }
  }

  @Test
  fun channelPathTogglesFlagPreferenceSensitivityAndObscuredDispatch() {
    val activity = activityRule.launchActivity(Intent())
    val target = RecordingTouchView(activity)
    addContentAndAwaitLayout(activity, target)
    val point = centerInWindow(target)
    val obscuredDown = touchEvent(
      100L,
      MotionEvent.ACTION_DOWN,
      MotionEvent.FLAG_WINDOW_IS_OBSCURED,
      point.x,
      point.y,
    )
    val cleanUp = touchEvent(110L, MotionEvent.ACTION_UP, 0, point.x, point.y)

    try {
      activityRule.runOnUiThread {
        val flutterView = activity.findViewById<FlutterView>(FlutterActivity.FLUTTER_VIEW_ID)
        assertNotNull(flutterView)

        activity.applyScreenProtectionEnabled(true)
        assertTrue(isSecure(activity))
        assertTrue(context.getSharedPreferences(PREFERENCES_NAME, 0).getBoolean(ENABLED_KEY, false))
        assertAccessibilitySensitivity(activity, flutterView!!, expectedSensitive = true)

        activity.applyScreenProtectionEnabled(false)
        assertFalse(isSecure(activity))
        assertFalse(context.getSharedPreferences(PREFERENCES_NAME, 0).getBoolean(ENABLED_KEY, true))
        assertAccessibilitySensitivity(activity, flutterView, expectedSensitive = false)
        assertTrue(activity.dispatchTouchEvent(obscuredDown))
        assertEquals(listOf(MotionEvent.ACTION_DOWN), target.actions)
        assertTrue(activity.dispatchTouchEvent(cleanUp))

        activity.applyScreenProtectionEnabled(true)
        assertTrue(isSecure(activity))
        assertTrue(context.getSharedPreferences(PREFERENCES_NAME, 0).getBoolean(ENABLED_KEY, false))
        assertAccessibilitySensitivity(activity, flutterView, expectedSensitive = true)
      }
    } finally {
      obscuredDown.recycle()
      cleanUp.recycle()
    }
  }

  @Test
  fun obscuredMoveCancelsTheForwardedGestureAndBlocksItsLaterUp() {
    val activity = activityRule.launchActivity(Intent())
    val target = RecordingTouchView(activity)
    addContentAndAwaitLayout(activity, target)
    activityRule.runOnUiThread {
      activity.applyScreenProtectionEnabled(true)
    }
    val point = centerInWindow(target)
    val down = touchEvent(100L, MotionEvent.ACTION_DOWN, 0, point.x, point.y)
    val obscuredMove = touchEvent(
      110L,
      MotionEvent.ACTION_MOVE,
      MotionEvent.FLAG_WINDOW_IS_OBSCURED,
      point.x,
      point.y,
    )
    val cleanUp = touchEvent(120L, MotionEvent.ACTION_UP, 0, point.x, point.y)

    try {
      assertTrue(dispatch(activity, down))
      assertFalse(dispatch(activity, obscuredMove))
      assertFalse(dispatch(activity, cleanUp))
      assertEquals(listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_CANCEL), target.actions)
      assertEquals(0, target.clickCount)
    } finally {
      down.recycle()
      obscuredMove.recycle()
      cleanUp.recycle()
    }
  }

  @Test
  fun newDownResetsAnUnfinishedBlockedGesture() {
    val activity = activityRule.launchActivity(Intent())
    val target = RecordingTouchView(activity)
    addContentAndAwaitLayout(activity, target)
    activityRule.runOnUiThread {
      activity.applyScreenProtectionEnabled(true)
    }
    val point = centerInWindow(target)
    val firstDown = touchEvent(100L, MotionEvent.ACTION_DOWN, 0, point.x, point.y)
    val obscuredMove = touchEvent(
      110L,
      MotionEvent.ACTION_MOVE,
      MotionEvent.FLAG_WINDOW_IS_OBSCURED,
      point.x,
      point.y,
    )
    val nextDown = touchEvent(200L, MotionEvent.ACTION_DOWN, 0, point.x, point.y, 200L)
    val nextUp = touchEvent(210L, MotionEvent.ACTION_UP, 0, point.x, point.y, 200L)

    try {
      assertTrue(dispatch(activity, firstDown))
      assertFalse(dispatch(activity, obscuredMove))
      assertTrue(dispatch(activity, nextDown))
      assertTrue(dispatch(activity, nextUp))
      assertEquals(
        listOf(
          MotionEvent.ACTION_DOWN,
          MotionEvent.ACTION_CANCEL,
          MotionEvent.ACTION_DOWN,
          MotionEvent.ACTION_UP,
        ),
        target.actions,
      )
    } finally {
      firstDown.recycle()
      obscuredMove.recycle()
      nextDown.recycle()
      nextUp.recycle()
    }
  }

  @Test
  fun flagSecureRedactsNativeWindowContentInUiAutomationScreenshot() {
    val activity = activityRule.launchActivity(Intent())
    val redContent = View(activity).apply { setBackgroundColor(Color.RED) }
    val location = IntArray(2)
    val size = IntArray(2)

    addContentAndAwaitLayout(activity, redContent)
    activityRule.runOnUiThread {
      activity.applyScreenProtectionEnabled(false)
      redContent.getLocationOnScreen(location)
      size[0] = redContent.width
      size[1] = redContent.height
    }
    awaitDraw(redContent)
    val centerX = location[0] + size[0] / 2
    val centerY = location[1] + size[1] / 2
    val offScreenshot = requireNotNull(
      awaitScreenshotState(activity, enabled = false, centerX, centerY, "OFF baseline"),
    ) {
      "UiAutomation did not capture the unprotected native content."
    }
    try {
      assertRedPixel(offScreenshot, centerX, centerY)
    } finally {
      offScreenshot.recycle()
    }

    val onScreenshot = awaitScreenshotState(activity, enabled = true, centerX, centerY, "ON")
    if (onScreenshot != null) {
      try {
        assertFalse(isRedPixel(onScreenshot.getPixel(centerX, centerY)))
      } finally {
        onScreenshot.recycle()
      }
    }

    val restoredScreenshot = requireNotNull(
      awaitScreenshotState(activity, enabled = false, centerX, centerY, "OFF restored"),
    ) {
      "UiAutomation did not capture the restored unprotected native content."
    }
    try {
      assertRedPixel(restoredScreenshot, centerX, centerY)
    } finally {
      restoredScreenshot.recycle()
    }
  }

  @Test
  fun policyGatesPartialObscurationAndPlatformFeaturesByApiLevel() {
    assertFalse(
      ScreenProtectionPolicy.shouldRejectTouch(
        MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED,
        true,
        Build.VERSION_CODES.P,
      ),
    )
    assertTrue(
      ScreenProtectionPolicy.shouldRejectTouch(
        MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED,
        true,
        Build.VERSION_CODES.Q,
      ),
    )
    assertFalse(ScreenProtectionPolicy.supportsHideOverlayWindows(Build.VERSION_CODES.R))
    assertTrue(ScreenProtectionPolicy.supportsHideOverlayWindows(Build.VERSION_CODES.S))
    assertEquals(
      null,
      ScreenProtectionPolicy.accessibilityDataSensitivity(true, Build.VERSION_CODES.TIRAMISU),
    )
  }

  private fun isSecure(activity: MainActivity): Boolean =
    activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0

  private fun assertAccessibilitySensitivity(
    activity: MainActivity,
    flutterView: FlutterView,
    expectedSensitive: Boolean,
  ) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
    if (expectedSensitive) {
      assertTrue(activity.window.decorView.isAccessibilityDataSensitive)
      assertTrue(flutterView.isAccessibilityDataSensitive)
    } else {
      assertFalse(activity.window.decorView.isAccessibilityDataSensitive)
      assertFalse(flutterView.isAccessibilityDataSensitive)
    }
  }

  private fun dispatch(activity: MainActivity, event: MotionEvent): Boolean {
    val result = BooleanArray(1)
    activityRule.runOnUiThread {
      result[0] = activity.dispatchTouchEvent(event)
    }
    return result[0]
  }

  private fun takeScreenshotOrNull(): Bitmap? =
    InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot()

  private fun assertRedPixel(bitmap: Bitmap, x: Int, y: Int) {
    val pixel = bitmap.getPixel(x, y)
    assertTrue(
      "Expected red pixel at ($x,$y) in ${bitmap.width}x${bitmap.height}, got ${pixelDescription(pixel)}.",
      isRedPixel(pixel),
    )
  }

  private fun pixelDescription(pixel: Int): String =
    "argb(${Color.alpha(pixel)},${Color.red(pixel)},${Color.green(pixel)},${Color.blue(pixel)})"

  private fun awaitScreenshotState(
    activity: MainActivity,
    enabled: Boolean,
    x: Int,
    y: Int,
    label: String,
  ): Bitmap? {
    val instrumentation = InstrumentationRegistry.getInstrumentation()
    val deadline = SystemClock.uptimeMillis() + SCREENSHOT_TRANSITION_TIMEOUT_MS
    var lastObservation = "no screenshot captured"

    do {
      activityRule.runOnUiThread {
        activity.applyScreenProtectionEnabled(enabled)
        assertEquals("$label native FLAG_SECURE state", enabled, isSecure(activity))
      }
      instrumentation.waitForIdleSync()

      val screenshot = takeScreenshotOrNull()
      if (screenshot == null) {
        lastObservation = "screenshot=null, secure=${isSecure(activity)}"
        if (enabled) return null
      } else if (x in 0 until screenshot.width && y in 0 until screenshot.height) {
        val pixel = screenshot.getPixel(x, y)
        lastObservation =
          "screenshot=${screenshot.width}x${screenshot.height}, pixel=${pixelDescription(pixel)}, " +
            "secure=${isSecure(activity)}"
        if (isRedPixel(pixel) != enabled) return screenshot
        screenshot.recycle()
      } else {
        lastObservation =
          "screenshot=${screenshot.width}x${screenshot.height}, point=($x,$y) out of bounds, " +
            "secure=${isSecure(activity)}"
        screenshot.recycle()
      }

      SystemClock.sleep(SCREENSHOT_POLL_INTERVAL_MS)
    } while (SystemClock.uptimeMillis() < deadline)

    throw AssertionError("$label screenshot state did not settle within 5 seconds: $lastObservation")
  }

  private fun isRedPixel(pixel: Int): Boolean =
    Color.red(pixel) > 200 && Color.green(pixel) < 50 && Color.blue(pixel) < 50

  private fun touchEvent(
    eventTime: Long,
    action: Int,
    flags: Int,
    x: Float,
    y: Float,
    downTime: Long = 100L,
  ): MotionEvent {
    val properties = MotionEvent.PointerProperties().apply {
      id = 0
      toolType = MotionEvent.TOOL_TYPE_FINGER
    }
    val coordinates = MotionEvent.PointerCoords().apply {
      this.x = x
      this.y = y
      pressure = 1.0f
      size = 1.0f
    }
    return MotionEvent.obtain(
      downTime,
      eventTime,
      action,
      1,
      arrayOf(properties),
      arrayOf(coordinates),
      0,
      0,
      1.0f,
      1.0f,
      0,
      0,
      InputDevice.SOURCE_TOUCHSCREEN,
      flags,
    )
  }

  private fun addContentAndAwaitLayout(activity: MainActivity, view: View) {
    awaitLayout(view) {
      activity.addContentView(
        view,
        ViewGroup.LayoutParams(
          ViewGroup.LayoutParams.MATCH_PARENT,
          ViewGroup.LayoutParams.MATCH_PARENT,
        ),
      )
    }
  }

  private fun awaitLayout(view: View, attach: () -> Unit) {
    val laidOut = CountDownLatch(1)
    activityRule.runOnUiThread {
      view.addOnLayoutChangeListener { changedView, _, _, _, _, _, _, _, _ ->
        if (changedView.width > 0 && changedView.height > 0) {
          laidOut.countDown()
        }
      }
      attach()
      if (view.width > 0 && view.height > 0) {
        laidOut.countDown()
      }
    }
    assertTrue("Test view did not receive a non-empty layout within 5 seconds.", laidOut.await(5, TimeUnit.SECONDS))
  }

  private fun awaitDraw(view: View) {
    val drawn = CountDownLatch(1)
    lateinit var listener: android.view.ViewTreeObserver.OnDrawListener
    activityRule.runOnUiThread {
      listener = android.view.ViewTreeObserver.OnDrawListener { drawn.countDown() }
      view.viewTreeObserver.addOnDrawListener(listener)
      view.invalidate()
    }
    try {
      assertTrue("Test view did not draw within 5 seconds.", drawn.await(5, TimeUnit.SECONDS))
    } finally {
      activityRule.runOnUiThread {
        if (view.viewTreeObserver.isAlive) {
          view.viewTreeObserver.removeOnDrawListener(listener)
        }
      }
    }
  }

  private fun centerInWindow(view: View): TouchPoint {
    val location = IntArray(2)
    activityRule.runOnUiThread { view.getLocationInWindow(location) }
    return TouchPoint(
      location[0] + view.width / 2.0f,
      location[1] + view.height / 2.0f,
    )
  }

  private class RecordingTouchView(context: android.content.Context) : View(context) {
    val actions = mutableListOf<Int>()
    var clickCount = 0

    init {
      isClickable = true
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
      actions += event.actionMasked
      return super.onTouchEvent(event)
    }

    override fun performClick(): Boolean {
      clickCount += 1
      return super.performClick()
    }
  }

  private data class TouchPoint(val x: Float, val y: Float)

  private companion object {
    const val PREFERENCES_NAME = "layergram_prefs"
    const val ENABLED_KEY = "screen_protection_enabled"
    const val SCREENSHOT_TRANSITION_TIMEOUT_MS = 5_000L
    const val SCREENSHOT_POLL_INTERVAL_MS = 50L
  }
}
