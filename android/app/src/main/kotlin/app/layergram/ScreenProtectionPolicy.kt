package app.layergram

import android.os.Build
import android.view.MotionEvent
import android.view.View

/** Small, side-effect-free policy used by [MainActivity] and instrumentation tests. */
object ScreenProtectionPolicy {
  fun shouldRejectTouch(eventFlags: Int, protectionEnabled: Boolean, sdkInt: Int): Boolean {
    if (!protectionEnabled) return false

    if (eventFlags and MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0) return true

    return sdkInt >= Build.VERSION_CODES.Q &&
      eventFlags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0
  }

  fun supportsHideOverlayWindows(sdkInt: Int): Boolean =
    sdkInt >= Build.VERSION_CODES.S

  fun accessibilityDataSensitivity(protectionEnabled: Boolean, sdkInt: Int): Int? =
    if (sdkInt < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      null
    } else if (protectionEnabled) {
      View.ACCESSIBILITY_DATA_SENSITIVE_YES
    } else {
      View.ACCESSIBILITY_DATA_SENSITIVE_AUTO
    }
}

enum class TouchDispatchAction {
  DISPATCH,
  REJECT,
  CANCEL_THEN_REJECT,
}

/** Tracks a touch sequence so an obscured event cannot resume a gesture after it is blocked. */
class ScreenProtectionTouchGate {
  private var forwardedGesture = false
  private var blockedGesture = false

  fun onTouchEvent(
    actionMasked: Int,
    eventFlags: Int,
    protectionEnabled: Boolean,
    sdkInt: Int,
  ): TouchDispatchAction {
    // Android treats a DOWN as the start of a new sequence, even if the previous UP/CANCEL
    // was never delivered to this activity.
    if (actionMasked == MotionEvent.ACTION_DOWN) reset()

    if (blockedGesture) {
      if (isGestureEnd(actionMasked)) reset()
      return TouchDispatchAction.REJECT
    }

    if (ScreenProtectionPolicy.shouldRejectTouch(eventFlags, protectionEnabled, sdkInt)) {
      val dispatchAction = if (forwardedGesture) {
        TouchDispatchAction.CANCEL_THEN_REJECT
      } else {
        TouchDispatchAction.REJECT
      }
      if (isGestureEnd(actionMasked)) {
        reset()
      } else {
        blockedGesture = true
        forwardedGesture = false
      }
      return dispatchAction
    }

    when (actionMasked) {
      MotionEvent.ACTION_DOWN -> forwardedGesture = true
      MotionEvent.ACTION_UP,
      MotionEvent.ACTION_CANCEL,
      -> reset()
    }
    return TouchDispatchAction.DISPATCH
  }

  fun reset() {
    forwardedGesture = false
    blockedGesture = false
  }

  private fun isGestureEnd(actionMasked: Int): Boolean =
    actionMasked == MotionEvent.ACTION_UP || actionMasked == MotionEvent.ACTION_CANCEL
}
