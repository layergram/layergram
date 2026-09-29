package app.layergram

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ComponentName
import android.content.Intent
import android.graphics.Rect
import android.graphics.Bitmap
import android.graphics.Color
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.lang.ref.WeakReference

/** Real IME gestures in the separate offline host, on a disposable QA install. */
class KeyboardTransportInstrumentedTest {
  private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
  private val automation get() = instrumentation.uiAutomation
  private val context get() = instrumentation.targetContext

  private fun nodes(): List<AccessibilityNodeInfo> {
    fun descend(node: AccessibilityNodeInfo): List<AccessibilityNodeInfo> {
      // UiAutomation can retain the previous TextView text after a key tap.
      // Refresh the actual node before asserting a draft or countdown value.
      if (!node.refresh()) return emptyList()
      return listOf(node) + (0 until node.childCount).flatMap {
        node.getChild(it)?.let { child -> descend(child) } ?: emptyList()
      }
    }
    return automation.windows.flatMap { it.root?.let { root -> descend(root) } ?: emptyList() }
  }

  private fun waitNode(timeout: Long = 15_000, match: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo {
    val deadline = SystemClock.uptimeMillis() + timeout
    do {
      nodes().firstOrNull { it.isVisibleToUser && match(it) }?.let { return it }
      SystemClock.sleep(100)
    } while (SystemClock.uptimeMillis() < deadline)
    val current = nodes()
    // Bounded private QA metadata, never plaintext, carrier or identity secret.
    File(context.cacheDir, "qa-transport-visible-node-types.txt").writeText(
      current.filter { it.packageName?.toString() == context.packageName &&
        (it.text?.length ?: 0) <= 100 && (it.contentDescription?.length ?: 0) <= 100 }
        .joinToString("\n") { node ->
          val rect = Rect(); node.getBoundsInScreen(rect)
          val known = listOf("Messaggi", "Mensajes", "Messages", "Impostazioni", "Ajustes", "Settings")
            .firstOrNull { label -> node.contentDescription?.toString()?.startsWith(label) == true } ?: "other"
          node.className.toString() + "|textUnits=" + (node.text?.length ?: 0) +
            "|descriptionUnits=" + (node.contentDescription?.length ?: 0) +
            "|visible=" + node.isVisibleToUser + "|control=" + known + "|bounds=" + rect.toShortString()
        })
    val categories = listOf(R.string.sk_status_ready, R.string.sk_status_connecting,
      R.string.sk_status_unavailable, R.string.sk_status_touch_to_unlock,
      R.string.sk_status_unlocking, R.string.sk_status_rejected_field).filter { id ->
      current.any { it.text?.toString() == string(id) }
    }.map { context.resources.getResourceEntryName(it) }
    throw AssertionError("Expected visible QA control was not available; windows=" +
      automation.windows.map { it.type.toString() + ":" + it.root?.packageName } + "; nativeNodes=" +
      current.count { it.packageName?.toString() == context.packageName } + "; status=" + categories +
      "; textViewTypes=" + current.filter { it.packageName?.toString() == context.packageName &&
        it.className?.toString()?.contains("TextView") == true }.map {
          it.className.toString() + ":units=" + (it.text?.length ?: 0) })
  }

  private fun tap(node: AccessibilityNodeInfo) {
    val bounds = Rect(); node.getBoundsInScreen(bounds)
    assertFalse("Cannot touch an empty control", bounds.isEmpty)
    val time = SystemClock.uptimeMillis()
    for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
      if (action == MotionEvent.ACTION_UP) SystemClock.sleep(35)
      val event = MotionEvent.obtain(time, SystemClock.uptimeMillis(),
        action, bounds.exactCenterX(), bounds.exactCenterY(), 0)
      event.source = InputDevice.SOURCE_TOUCHSCREEN
      try { assertTrue(automation.injectInputEvent(event, true)) } finally { event.recycle() }
    }
    SystemClock.sleep(80)
  }

  private fun byDescription(description: String) = waitNode { it.contentDescription?.toString() == description }
  private fun byText(text: String) = waitNode { it.text?.toString() == text }
  private fun string(id: Int) = context.getString(id)

  @Test fun realKeyboardExportsOrDecodesInOfflineTransport() {
    assertEquals("Never run this against a personal or distributed app", "app.layergram.keyboardvalidation", context.packageName)
    val info = automation.serviceInfo
    info.flags = info.flags or AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS or
      AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
    automation.serviceInfo = info
    val arguments = InstrumentationRegistry.getArguments()
    val mode = arguments.getString("qaAction") ?: "export"
    val traceFile = File(context.cacheDir, "qa-transport-stages.txt")
    traceFile.writeText("")
    val trace: (String) -> Unit = { stage -> synchronized(traceFile) {
      traceFile.appendText(stage + "\n")
    } }
    KeyboardAutonomousHost::class.java.getDeclaredField("traceForTesting").apply {
      isAccessible = true; set(KeyboardAutonomousHost, trace)
    }
    SystemKeyboardBroker::class.java.getDeclaredField("traceForTesting").apply {
      isAccessible = true; set(SystemKeyboardBroker, trace)
    }
    context.startActivity(Intent().setComponent(ComponentName(context.packageName, "app.layergram.MainActivity"))
      .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    // A cold Flutter launch may take longer than a fixed delay on a physical
    // device. Handoff is valid only after the unlocked app has rendered.
    val rootLater = listOf("Più tardi", "Más tarde", "Later")
    val rootMessages = listOf("Messaggi", "Mensajes", "Messages")
    val rootBack = listOf("Indietro", "Atrás", "Back")
    val rootReady: (AccessibilityNodeInfo) -> Boolean = { node ->
      node.packageName?.toString() == context.packageName &&
        listOf(node.text, node.contentDescription).any { value ->
          val label = value?.toString() ?: ""
          label in rootLater || label in rootBack || rootMessages.any { label.startsWith(it) }
        }
    }
    val rootSurface = waitNode(timeout = 90_000, match = rootReady)
    if (listOf(rootSurface.text?.toString(), rootSurface.contentDescription?.toString()).any { it in rootLater }) {
      tap(rootSurface)
      waitNode(timeout = 90_000) { node -> rootReady(node) &&
        listOf(node.text?.toString(), node.contentDescription?.toString()).none { it in rootLater } }
    }
    SystemClock.sleep(4_000)
    if (mode == "privacy") {
      tap(waitNode { it.packageName?.toString() == context.packageName &&
        it.contentDescription?.toString()?.startsWith("Impostazioni") == true })
      val protection = waitNode { it.packageName?.toString() == context.packageName && it.isCheckable &&
        listOf(it.text, it.contentDescription).any { label -> label?.toString()?.startsWith("Protezione screenshot") == true } }
      if (!protection.isChecked) tap(protection)
      waitNode { it.packageName?.toString() == context.packageName && it.isCheckable && it.isChecked &&
        listOf(it.text, it.contentDescription).any { label -> label?.toString()?.startsWith("Protezione screenshot") == true } }
      println("QA_CAPTURE_PREFERENCE=enabled")
    }
    if (mode == "history") {
      val plaintext = arguments.getString("qaPlaintext") ?: ""
      assertTrue("Supply a unique body from a passed keyboard exchange", plaintext.isNotEmpty())
      val later = listOf("Più tardi", "Más tarde", "Later")
      val back = listOf("Indietro", "Atrás", "Back")
      val contact = arguments.getString("qaContact") ?: "prova"
      // Flutter can publish the migration dialog after the activity first
      // resumes. Wait for the actual navigable surface instead of taking a
      // one-off snapshot that could miss it and strand the history assertion.
      repeat(3) {
        val navigation = waitNode(timeout = 45_000) { it.packageName?.toString() == context.packageName &&
          (it.text?.toString() in later || it.contentDescription?.toString() in later ||
            it.contentDescription?.toString() in back ||
            it.contentDescription?.toString()?.startsWith(contact + "\n") == true) }
        if (navigation.text?.toString() in later || navigation.contentDescription?.toString() in later ||
            navigation.contentDescription?.toString() in back) tap(navigation)
      }
      tap(waitNode { it.packageName?.toString() == context.packageName &&
        it.contentDescription?.toString()?.startsWith(contact + "\n") == true })
      waitNode { it.packageName?.toString() == context.packageName && it.contentDescription?.toString() in back }
      waitNode { node -> listOf(node.text, node.contentDescription).any {
        it?.toString()?.lineSequence()?.firstOrNull() == plaintext
      } }
      println("QA_CHAT_ARCHIVE_EXACT_PLAINTEXT=present")
      return
    }
    val probeStartedAt = SystemClock.uptimeMillis()
    context.startActivity(Intent().setComponent(ComponentName("app.layergram.keyboardprobe", "app.layergram.keyboardprobe.TransportActivity"))
      .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
    tap(byDescription("probe.transport.field"))
    byText(string(R.string.sk_status_ready))
    if (mode == "coldHandoff") {
      assertTrue("The autonomous keyboard host must be running after readiness",
        KeyboardAutonomousHost.isRunning)
      val readinessMillis = SystemClock.uptimeMillis() - probeStartedAt
      context.startActivity(Intent().setComponent(ComponentName(context.packageName, "app.layergram.MainActivity"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP))
      waitNode(timeout = 90_000, match = rootReady)
      println("QA_COLD_HANDOFF=ready;bucket=" + when {
        readinessMillis <= 5_000 -> "under5s"
        readinessMillis <= 15_000 -> "under15s"
        else -> "over15s"
      })
      return
    }
    if (mode == "privacy") {
      for (character in "captura") tap(waitNode { it.packageName?.toString() == context.packageName &&
        it.isClickable && it.isEnabled && it.text?.toString() == character.toString() })
      val draft = byText("captura")
      var secureWindow = false
      instrumentation.runOnMainSync {
        val ref = SystemKeyboardBroker::class.java.getDeclaredField("serviceRef").apply { isAccessible = true }
          .get(SystemKeyboardBroker) as WeakReference<*>
        val service = ref.get() as LayergramInputMethodService
        secureWindow = (service.window.window!!.attributes.flags and android.view.WindowManager.LayoutParams.FLAG_SECURE) != 0
      }
      assertTrue("The actual IME window must enforce FLAG_SECURE", secureWindow)
      val screenshot = automation.takeScreenshot()
      if (screenshot == null) {
        println("QA_PHYSICAL_CAPTURE=refusedBySystem")
      } else {
        File(context.cacheDir, "qa-protected-keyboard.png").outputStream().use {
          screenshot.compress(Bitmap.CompressFormat.PNG, 100, it)
        }
        val rect = Rect(); draft.getBoundsInScreen(rect); rect.inset(8, 8)
        assertTrue("The known draft must have an on-screen capture region", rect.width() > 0 && rect.height() > 0 &&
          rect.left >= 0 && rect.top >= 0 && rect.right <= screenshot.width && rect.bottom <= screenshot.height)
        val pixels = IntArray(rect.width() * rect.height())
        screenshot.getPixels(pixels, 0, rect.width(), rect.left, rect.top, rect.width(), rect.height())
        for (channel in listOf<(Int) -> Int>(Color::red, Color::green, Color::blue)) {
          val values = pixels.map(channel)
          assertTrue("The physical secure window capture must hide draft glyphs and cursor",
            values.maxOrNull()!! - values.minOrNull()!! <= 5)
        }
        screenshot.recycle()
        println("QA_PHYSICAL_CAPTURE=uniformProtectedCanvas")
      }
      return
    }
    if (mode == "decode") {
      tap(byDescription(string(R.string.sk_action_paste_decode)))
      byText(string(R.string.sk_status_decoded))
      byText(arguments.getString("qaPlaintext") ?: "prova")
      // The real preview, rather than a success status alone, proves delivery.
      val reply = byText(string(R.string.sk_reply_to))
      if (arguments.getString("qaReplyText").isNullOrEmpty()) return
      tap(reply)
      tap(byText(string(R.string.sk_confirm_yes)))
    } else {
      assertTrue("Choose an explicit supported QA action", mode in listOf("export", "continuity"))
      val contact = arguments.getString("qaContact") ?: "prova"
      tap(byDescription(string(R.string.sk_action_contacts)))
      tap(byText(contact))
      tap(byText(string(R.string.sk_confirm_yes)))
    }
    val contact = arguments.getString("qaContact") ?: "prova"
    val plaintext = arguments.getString("qaReplyText") ?: arguments.getString("qaPlaintext") ?: "risposta"
    var typed = ""
    for (character in plaintext) {
      tap(waitNode { it.packageName?.toString() == context.packageName &&
        it.isClickable && it.isEnabled && it.text?.toString() == character.toString() })
      typed += character
      val prefix = typed
      waitNode(timeout = 3_000) { it.packageName?.toString() == context.packageName &&
        it.text?.toString() == prefix }
    }
    waitNode { it.packageName?.toString() == context.packageName &&
      it.text?.toString() == plaintext }
    tap(byDescription(string(R.string.sk_action_insert_idle)))
    val deadline = SystemClock.uptimeMillis() + 20_000
    var carrier = ""
    do {
      carrier = byDescription("probe.transport.field").text?.toString() ?: ""
      if (carrier.startsWith("p1.") || carrier.startsWith("m3.") || carrier.startsWith("b3.")) break
      SystemClock.sleep(100)
    } while (SystemClock.uptimeMillis() < deadline)
    assertTrue("The host must receive a V3 carrier", carrier.startsWith("p1.") || carrier.startsWith("m3.") || carrier.startsWith("b3."))
    assertTrue(carrier.length <= 4_000)
    assertFalse(Regex("\\b[0-9]+/[0-9]+\\b").containsMatchIn(carrier))
    File(context.cacheDir, "qa-transport-export.txt").writeText(carrier)
    byDescription(string(R.string.sk_action_paste_decode))
    byText(contact)
    val phases = listOf(R.string.sk_fs_active, R.string.sk_fs_pending, R.string.sk_fs_recovery, R.string.sk_fs_unknown)
    val phase = phases.firstOrNull { id -> nodes().any { it.isVisibleToUser && it.contentDescription?.toString() == string(id) } }
    assertNotNull("The selected recipient must expose the real FS shield state", phase)
    assertTrue("A usable exchange cannot report unknown or recovery FS", phase in listOf(R.string.sk_fs_active, R.string.sk_fs_pending))
    arguments.getString("qaExpectedFs")?.let { expected ->
      assertTrue("Expected FS must be active or pending", expected in listOf("active", "pending"))
      assertEquals("The final exchange must reach the requested real FS shield",
        if (expected == "active") R.string.sk_fs_active else R.string.sk_fs_pending, phase)
    }
    println("QA_TRANSPORT_FS=" + context.resources.getResourceEntryName(phase!!))
    // No secret is logged. The disposable carrier is read back by the harness
    // and imported into the other real device for its plaintext assertion.
    println("QA_TRANSPORT_EXPORT_CODE_UNITS=" + carrier.length)
    if (mode == "continuity") {
      var idleBeforeSend = 0L
      instrumentation.runOnMainSync { idleBeforeSend = KeyboardAutonomousHost.remainingIdleMillis() }
      assertTrue("The first export must retain a live idle window", idleBeforeSend > 0)
      tap(byDescription("probe.transport.send"))
      val emptied = byDescription("probe.transport.field").text?.toString() ?: ""
      assertTrue("Host Send must clear its carrier field",
        emptied.isEmpty() || emptied == "Offline carrier")
      byText(contact)
      waitNode { it.packageName?.toString() == context.packageName &&
        Regex("^[1-9][0-9]*s$").matches(it.text?.toString() ?: "") }
      var idleAfterSend = 0L
      instrumentation.runOnMainSync { idleAfterSend = KeyboardAutonomousHost.remainingIdleMillis() }
      assertTrue("Host Send and editor rebind must not renew inactivity",
        idleAfterSend in 1..idleBeforeSend)
      val secondText = arguments.getString("qaSecondPlaintext") ?: "continuita"
      assertTrue(secondText.isNotEmpty())
      var secondTyped = ""
      for (character in secondText) {
        tap(waitNode { it.packageName?.toString() == context.packageName &&
          it.isClickable && it.isEnabled && it.text?.toString() == character.toString() })
        secondTyped += character
        val prefix = secondTyped
        waitNode(timeout = 3_000) { it.packageName?.toString() == context.packageName &&
          it.text?.toString() == prefix }
      }
      waitNode { it.packageName?.toString() == context.packageName &&
        it.text?.toString() == secondText }
      tap(byDescription(string(R.string.sk_action_insert_idle)))
      val nextDeadline = SystemClock.uptimeMillis() + 20_000
      var secondCarrier = ""
      do {
        secondCarrier = byDescription("probe.transport.field").text?.toString() ?: ""
        if (secondCarrier.startsWith("p1.") || secondCarrier.startsWith("m3.") || secondCarrier.startsWith("b3.")) break
        SystemClock.sleep(100)
      } while (SystemClock.uptimeMillis() < nextDeadline)
      assertTrue("A second send must insert another complete V3 carrier",
        secondCarrier.startsWith("p1.") || secondCarrier.startsWith("m3.") || secondCarrier.startsWith("b3."))
      assertTrue(secondCarrier.length <= 4_000)
      assertFalse(Regex("\\b[0-9]+/[0-9]+\\b").containsMatchIn(secondCarrier))
      assertNotEquals(carrier, secondCarrier)
      byText(contact)
      byDescription(string(R.string.sk_fs_active))
      waitNode { it.packageName?.toString() == context.packageName &&
        Regex("^[1-9][0-9]*s$").matches(it.text?.toString() ?: "") }
      File(context.cacheDir, "qa-transport-export.txt").writeText(secondCarrier)
      println("QA_CONSECUTIVE_SENDS=passed;FS=active")
    }
  }
}
