package app.layergram

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.View
import android.view.ViewGroup
import android.view.MotionEvent
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.ActivityTestRule
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import java.util.Locale

/** Runs actual native layout and text scrolling on Android, using no identities. */
class KeyboardSurfaceInstrumentedTest {
  @get:Rule val rule = ActivityTestRule(MainActivity::class.java, true, false)
  private val instrumentation get() = InstrumentationRegistry.getInstrumentation()

  private fun surface(dark: Boolean = false, locale: String = "en"): Pair<LayergramInputMethodService, View> {
    val base = instrumentation.targetContext
    val config = Configuration(base.resources.configuration).apply {
      uiMode = (uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or
        if (dark) Configuration.UI_MODE_NIGHT_YES else Configuration.UI_MODE_NIGHT_NO
      setLocale(Locale.forLanguageTag(locale))
    }
    val service = LayergramInputMethodService()
    ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", Context::class.java)
      .apply { isAccessible = true }.invoke(service, base.createConfigurationContext(config))
    return service to service.onCreateInputView()
  }

  private fun mount(root: View) {
    val activity = rule.launchActivity(Intent())
    // Keep Flutter's attached view alive: replacing it while its accessibility
    // bridge is still emitting semantics crashes the real app test target.
    rule.runOnUiThread { activity.addContentView(root,
      ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)) }
    instrumentation.waitForIdleSync()
  }

  private fun views(root: View): List<View> = listOf(root) +
    if (root is ViewGroup) (0 until root.childCount).flatMap { views(root.getChildAt(it)) } else emptyList()
  private fun tagged(root: View, tag: String): View = views(root).single { it.tag == tag }
  private fun invoke(service: LayergramInputMethodService, method: String, value: Any? = null) {
    val target = service.javaClass.declaredMethods.single { it.name == method }
    target.isAccessible = true
    if (value == null) target.invoke(service) else target.invoke(service, value)
  }

  @Test fun compactComposerHasEqualRoundButtonsAndOneStatusCountdownRow() {
    var pair: Pair<LayergramInputMethodService, View>? = null
    instrumentation.runOnMainSync { pair = surface() }
    val root = pair!!.second; mount(root)
    rule.runOnUiThread {
      val primary = tagged(root, "keyboard.primary")
      val contacts = views(root).filterIsInstance<ImageButton>().single { it.contentDescription == "Contacts" }
      assertEquals(contacts.height, primary.height); assertEquals(contacts.width, primary.width)
      assertEquals(contacts.top, primary.top)
      assertEquals(tagged(root, "keyboard.status").top, tagged(root, "keyboard.countdown").top)
      assertEquals(View.GONE, tagged(root, "keyboard.clear").visibility)
      assertEquals("Paste and decrypt", primary.contentDescription)
      assertFalse(tagged(root, "keyboard.secret").onCheckIsTextEditor())
    }
  }

  @Test fun darkControlsMatchTheAppAndSpanishLayoutContainsEnye() {
    var pair: Pair<LayergramInputMethodService, View>? = null
    instrumentation.runOnMainSync { pair = surface(dark = true, locale = "es") }
    val root = pair!!.second; mount(root)
    rule.runOnUiThread {
      assertEquals(Color.rgb(154, 203, 250), (tagged(root, "keyboard.primary").background as GradientDrawable).color!!.defaultColor)
      assertTrue(views(root).filterIsInstance<TextView>().any { it.text == "ñ" })
      assertTrue(views(root).filterIsInstance<TextView>().any { it.text == "espacio" })
      assertEquals(Color.rgb(33, 33, 33), (root as LinearLayout).let {
        (it.background as android.graphics.drawable.ColorDrawable).color
      })
    }
  }

  @Test fun searchingKeepsKeysBelowAFixedScrollableContactViewport() {
    var pair: Pair<LayergramInputMethodService, View>? = null
    instrumentation.runOnMainSync { pair = surface() }
    val service = pair!!.first; val root = pair!!.second; mount(root)
    rule.runOnUiThread { invoke(service, "renderContacts", (1..40).map { BrokerContact("c$it", "Contact $it", "FP$it") }) }
    instrumentation.waitForIdleSync()
    val before = tagged(root, "keyboard.keys").top
    rule.runOnUiThread { invoke(service, "renderContacts", listOf(BrokerContact("c1", "Alice", "FP1"))) }
    instrumentation.waitForIdleSync()
    rule.runOnUiThread {
      assertEquals(before, tagged(root, "keyboard.keys").top)
      assertTrue(tagged(root, "keyboard.search").height > 0)
      assertTrue(tagged(root, "keyboard.keys").top > tagged(root, "keyboard.contactList").parent.let { (it as View).top })
    }
  }

  @Test fun localCaretScrollsToNewlinesAndReturnsToEarlierLines() {
    var pair: Pair<LayergramInputMethodService, View>? = null
    instrumentation.runOnMainSync { pair = surface() }
    val root = pair!!.second; mount(root)
    val editor = tagged(root, "keyboard.secret") as KeyboardDraftView
    val text = (1..12).joinToString("\n") { "Line $it" }
    rule.runOnUiThread { editor.present(text, text.length) }
    instrumentation.waitForIdleSync()
    rule.runOnUiThread {
      assertTrue(editor.scrollY > 0)
      val line = editor.layout.getLineForOffset(editor.localCursor)
      assertTrue(editor.layout.getLineBottom(line) - editor.scrollY <= editor.height - editor.totalPaddingTop - editor.totalPaddingBottom)
      editor.present(text, 0)
    }
    instrumentation.waitForIdleSync()
    rule.runOnUiThread { assertEquals(0, editor.scrollY) }
  }

  @Test fun explicitPasteTapDoesNotStartAnEarlierOrSecondBiometricWake() {
    var pair: Pair<LayergramInputMethodService, View>? = null
    instrumentation.runOnMainSync { pair = surface() }
    val root = pair!!.second as ProtectedInputRoot; mount(root)
    val events = mutableListOf<String>()
    rule.runOnUiThread {
      val primary = tagged(root, "keyboard.primary")
      primary.setOnClickListener { events.add("paste") }
      root.onWakeTap = { events.add("wake") }
      val rootLocation = IntArray(2); val buttonLocation = IntArray(2)
      root.getLocationOnScreen(rootLocation); primary.getLocationOnScreen(buttonLocation)
      val x = (buttonLocation[0] - rootLocation[0] + primary.width / 2).toFloat()
      val y = (buttonLocation[1] - rootLocation[1] + primary.height / 2).toFloat()
      val now = android.os.SystemClock.uptimeMillis()
      for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
        val event = MotionEvent.obtain(now, now + action, action, x, y, 0)
        try { root.dispatchTouchEvent(event) } finally { event.recycle() }
      }
    }
    instrumentation.waitForIdleSync()
    rule.runOnUiThread { assertEquals(listOf("paste"), events) }
  }

  @Test fun hidingTheSameEditorAllowsANewBeginWithoutKeepingItsDraft() {
    var pair: Pair<LayergramInputMethodService, View>? = null
    instrumentation.runOnMainSync { pair = surface() }
    val service = pair!!.first; val root = pair!!.second; mount(root)
    rule.runOnUiThread {
      fun field(name: String) = service.javaClass.getDeclaredField(name).apply { isAccessible = true }
      field("beginRequested").setBoolean(service, true)
      field("connected").setBoolean(service, true)
      (tagged(root, "keyboard.secret") as KeyboardDraftView).present("secret", 6)
      service.onWindowHidden()
      assertFalse(field("beginRequested").getBoolean(service))
      assertFalse(field("connected").getBoolean(service))
      assertFalse(SystemKeyboardBroker.hasEditorGeneration())
      assertEquals("", (tagged(root, "keyboard.secret") as TextView).text.toString())
    }
  }
}
