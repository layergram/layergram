package app.layergram

import android.util.Log

/** Included only in the dedicated Profile QA artifact. */
internal object KeyboardQaProfileTrace {
  @JvmStatic
  fun emit(stage: String) {
    if (stage.startsWith("protocol:")) {
      Log.i("LayergramKeyboardProtocol", stage.removePrefix("protocol:"))
    } else {
      Log.i("LayergramKeyboardQA", stage)
    }
  }
}
