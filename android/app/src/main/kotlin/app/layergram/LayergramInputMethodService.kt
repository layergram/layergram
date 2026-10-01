package app.layergram

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.res.Configuration
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.HapticFeedbackConstants
import android.widget.ImageButton
import android.widget.ImageView
import java.util.Locale
import android.os.Build
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowInsets
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.inputmethodservice.InputMethodService
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.security.SecureRandom

/**
 * Optional SYSTEM keyboard surface for the experimental Layergram keyboard.
 *
 * The service is entirely local: it renders a plaintext draft in its own
 * local cursor viewport plus a custom key grid, and it never hands plaintext to the host
 * editor. The single host insert is `InputConnection.commitText(carrier, 1)`
 * with the carrier returned by an explicit `authorize`, followed by an `ack`
 * that reports the *actual* result. No `EditText`, no `setComposingText`, no
 * surrounding-text read, no clipboard observer, no learned dictionary, no
 * logging, no storage, no network and no engine creation live here.
 *
 * It runs in the default app process and only ever talks to the already-bound
 * engine through [SystemKeyboardBroker]; with no app opt-in or no bound engine
 * every operation fails generically and no keyboard state is kept.
 */
class LayergramInputMethodService : InputMethodService() {
  private companion object {
    val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
    val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT
    val LETTER_ROWS = listOf("qwertyuiop", "asdfghjkl", "zxcvbnm")
    val NUMBER_ROWS = listOf("1234567890", "-/:;()\$&@\"", ".,?!'#%")
    val SYMBOL_ROWS = listOf("[]{}#%^*+=", "_\\|~<>€£¥•", "…—°±§¶×")
  }

  private enum class KeyMode { LETTERS, NUMBERS, SYMBOLS }

  private val secureRandom = SecureRandom()
  private val draft = KeyboardComposerState()
  private val search = KeyboardComposerState(128)
  private val uiHandler = Handler(Looper.getMainLooper())
  private var searching = false
  private var emojiVisible = false
  private var operationInFlight = false
  private var loadedContacts = emptyList<BrokerContact>()
  private var countdownView: TextView? = null
  private var recipientRow: LinearLayout? = null
  private var recipientName: TextView? = null
  private var recipientShield: ImageView? = null
  private var composeRow: LinearLayout? = null
  private var clearDraftButton: ImageButton? = null
  private var searchView: KeyboardDraftView? = null
  private var searchRowView: LinearLayout? = null
  private var accentRow: LinearLayout? = null
  private val accentSelection = KeyboardAccentSelection()
  private val currentAccents get() = accentSelection.options
  private val accentIndex get() = accentSelection.index

  private var rootView: ProtectedInputRoot? = null
  private var statusView: TextView? = null
  private var statusDot: TextView? = null
  private var draftView: KeyboardDraftView? = null
  private var keysContainer: LinearLayout? = null
  private var contactsSection: LinearLayout? = null
  private var contactsContainer: LinearLayout? = null
  private var previewSection: LinearLayout? = null
  private var previewTitle: TextView? = null
  private var previewView: TextView? = null
  private var insertButton: ImageButton? = null

  private var keyMode = KeyMode.LETTERS
  private var uppercase = false
  private var scramble = false
  private var activeRows: List<String> = LETTER_ROWS

  private var admitted = false
  private var connected = false
  private var beginRequested = false
  private var selectedContact: BrokerContact? = null
  private var carrierBuffer: String? = null
  private val commitSelection = KeyboardCommitSelection()
  private var editorBinding: KeyboardEditorBinding? = null
  private var committedCarrierInEditor = false
  private var editorEpoch = 0
  private var securityReceiverRegistered = false
  private var biometricInFlight = false
  private var biometricVerified = false
  private var biometricCompleting = false
  private var biometricTarget: KeyboardEditorBinding? = null
  private var afterBiometric: (() -> Unit)? = null

  // --- lifecycle -----------------------------------------------------------

  override fun onCreate() {
    super.onCreate()
    registerSecurityReceiver()
  }

  override fun onCreateInputView(): View {
    val view = buildKeyboardView()
    rootView = view
    applyWindowSecurity()
    applyAccessibilitySensitivity(view)
    rebuildRows()
    renderKeys()
    updateInsertLabel()
    return view
  }

  /**
   * Fullscreen "extract" mode can mirror host editor text into our own UI through
   * the framework, even without an explicit surrounding-text read. It is disabled
   * unconditionally and the extraction UI is never enabled: no ExtractEditText,
   * no automatic host-text extraction and no learning input.
   */
  override fun onEvaluateFullscreenMode(): Boolean = false

  override fun onUpdateExtractingVisibility(info: EditorInfo?) {
    setExtractViewShown(false)
  }

  /**
   * The previous broker session is reset even when the new field is rejected, and
   * a fresh generation is bound only for an admitted field. The `begin` request is
   * sent later, once the input view is actually visible.
   */
  override fun onStartInput(attribute: EditorInfo?, restarting: Boolean) {
    SystemKeyboardBroker.traceImeForTesting("start:restart=$restarting:connected=$connected")
    super.onStartInput(attribute, restarting)
    val binding = currentInputBinding
    val nextBinding = if (attribute?.packageName != null && binding?.connectionToken != null)
      KeyboardEditorBinding(attribute.packageName, attribute.fieldId, attribute.inputType, attribute.imeOptions,
        binding.uid, binding.pid, binding.connectionToken) else null
    val continueEditor = KeyboardEditorRestartPolicy.mayContinue(restarting, editorBinding, nextBinding,
      connected && admitted, isInputViewShown, KeyboardAutonomousHost.isRunning,
      restarting && SystemKeyboardBroker.isEditorUsableNow(), committedCarrierInEditor && draft.text.isEmpty())
    editorBinding = nextBinding
    // A platform biometric dialog may temporarily become the input target.
    // Do not admit it; wait briefly for the exact original binding to return.
    if (KeyboardBiometricEditorPolicy.changed(biometricTarget, nextBinding))
      KeyboardQaTrace.emit(this, "biometricDifferentEditorDeferred")
    if (continueEditor) {
      // Host Send can restart the same visible field. Fence old callbacks and
      // clear draft/exports, but keep exclusive FS custody and its idle deadline.
      val recipient = selectedContact
      editorEpoch += 1; connected = false; beginRequested = true
      clearSensitiveUi()
      // EditorInfo can still contain the pre-Send cursor. The subsequent OS
      // update to (0,0) belongs to clearing this successfully populated field.
      commitSelection.expectRestartSelection(0, 0)
      val epoch = editorEpoch
      showStatus(R.string.sk_status_connecting)
      SystemKeyboardBroker.onHostSelectionChanged { outcome ->
        if (!guardEpoch(epoch)) return@onHostSelectionChanged
        if (outcome is BrokerOutcome.Success) {
          connected = true; scramble = outcome.value
          rebuildRows(); renderKeys(); showStatus(R.string.sk_status_ready)
          if (recipient != null) selectContact(recipient.id, epoch) else updateInsertLabel()
        } else onBrokerUnavailable()
      }
      return
    }
    editorEpoch += 1
    beginRequested = false
    connected = false
    SystemKeyboardBroker.attachService(this)
    SystemKeyboardBroker.resetEditor()
    clearSensitiveUi()
    commitSelection.update(attribute?.initialSelStart ?: -1, attribute?.initialSelEnd ?: -1)
    admitted = KeyboardEditorPolicy.admitsEditor(attribute?.inputType ?: 0) && !isKeyguardLocked()
    if (!admitted) {
      showStatus(R.string.sk_status_rejected_field)
      return
    }
    SystemKeyboardBroker.bindEditor()
    showStatus(R.string.sk_status_connecting)
  }

  override fun onStartInputView(info: EditorInfo?, restarting: Boolean) {
    SystemKeyboardBroker.traceImeForTesting("startView:restart=$restarting:connected=$connected")
    super.onStartInputView(info, restarting)
    applyWindowSecurity()
    applyAccessibilitySensitivity(rootView)
    SystemKeyboardBroker.attachService(this)
    SystemKeyboardBroker.setServiceVisible(true)
    if (!admitted && KeyboardEditorPolicy.admitsEditor(info?.inputType ?: 0) && !isKeyguardLocked()) {
      admitted = true; beginRequested = false
      SystemKeyboardBroker.bindEditor()
    }
    renderKeys()
    updateInsertLabel()
    uiHandler.removeCallbacks(countdownTick); uiHandler.post(countdownTick)
    if (!admitted) {
      showStatus(R.string.sk_status_rejected_field)
      return
    }
    if (!completeBiometricIfReady()) beginEditorSession()
  }

  override fun onWindowShown() {
    SystemKeyboardBroker.traceImeForTesting("shown:connected=$connected")
    super.onWindowShown()
    applyWindowSecurity()
    SystemKeyboardBroker.setServiceVisible(true)
    if (admitted && !completeBiometricIfReady()) beginEditorSession()
  }

  override fun onWindowHidden() {
    KeyboardQaTrace.emit(this, "imeWindowHidden")
    SystemKeyboardBroker.traceImeForTesting("hidden:connected=$connected")
    uiHandler.removeCallbacks(countdownTick)
    // Android may hide and show the same editor without onFinishInputView or
    // onStartInput. The hidden generation is revoked, so its one-shot begin
    // marker must not suppress admission when the window is shown again.
    beginRequested = false
    connected = false
    // A hidden window always clears every sensitive entry; the broker also
    // invalidates the generation so no reply can arrive for a hidden surface.
    clearSensitiveUi()
    SystemKeyboardBroker.setServiceVisible(false)
    super.onWindowHidden()
  }

  override fun onFinishInputView(finishingInput: Boolean) {
    KeyboardQaTrace.emit(this, "imeFinishInputView")
    SystemKeyboardBroker.traceImeForTesting("finishView:finishing=$finishingInput:connected=$connected")
    resetForLifecycleEvent()
    super.onFinishInputView(finishingInput)
  }

  override fun onFinishInput() {
    KeyboardQaTrace.emit(this, "imeFinishInput")
    SystemKeyboardBroker.traceImeForTesting("finish:connected=$connected")
    resetForLifecycleEvent()
    super.onFinishInput()
  }

  override fun onDestroy() {
    KeyboardAutonomousHost.discardBiometric()
    resetForLifecycleEvent()
    unregisterSecurityReceiver()
    super.onDestroy()
  }

  /**
   * Any selection movement the service did not itself cause drops the in-flight
   * commit bookkeeping and the confirmed recipient instead of reusing a stale
   * frame. Our own commit is recognised only by its expected cursor position, consumed
   * once; surrounding text is never read.
   */
  override fun onUpdateSelection(
    oldSelStart: Int,
    oldSelEnd: Int,
    newSelStart: Int,
    newSelEnd: Int,
    candidatesStart: Int,
    candidatesEnd: Int,
  ) {
    super.onUpdateSelection(
      oldSelStart,
      oldSelEnd,
      newSelStart,
      newSelEnd,
      candidatesStart,
      candidatesEnd,
    )
    val ownCommit = commitSelection.update(newSelStart, newSelEnd)
    SystemKeyboardBroker.traceImeForTesting("selection:own=$ownCommit:changed=${oldSelStart != newSelStart || oldSelEnd != newSelEnd}:connected=$connected")
    if (ownCommit || (oldSelStart == newSelStart && oldSelEnd == newSelEnd)) return
    onBrokerUnavailable()
    val epoch = editorEpoch
    SystemKeyboardBroker.onHostSelectionChanged { outcome ->
      if (!guardEpoch(epoch)) return@onHostSelectionChanged
      if (outcome is BrokerOutcome.Success) {
        connected = true; scramble = outcome.value; beginRequested = true
        rebuildRows(); renderKeys(); showStatus(R.string.sk_status_ready)
      }
    }
  }

  /** Called by the broker whenever it clears or invalidates the editor. */
  fun onBrokerUnavailable() {
    afterBiometric = null
    if (!KeyboardAutonomousHost.hasBiometricFlow) {
      biometricInFlight = false; biometricVerified = false; biometricCompleting = false
      biometricTarget = null
    }
    editorEpoch += 1
    connected = false
    clearSensitiveUi()
    showReentryStatus()
  }

  private fun resetForLifecycleEvent() {
    editorBinding = null
    afterBiometric = null
    if (!KeyboardAutonomousHost.hasBiometricFlow) {
      biometricInFlight = false; biometricVerified = false; biometricCompleting = false
      biometricTarget = null
    }
    uiHandler.removeCallbacks(countdownTick)
    editorEpoch += 1
    admitted = false
    connected = false
    beginRequested = false
    SystemKeyboardBroker.setServiceVisible(false)
    SystemKeyboardBroker.resetEditor()
    SystemKeyboardBroker.detachService()
    clearSensitiveUi()
  }

  // --- security ------------------------------------------------------------

  private fun applyWindowSecurity() {
    val dialogWindow = window?.window ?: return
    val protection = getSharedPreferences("layergram_prefs", Context.MODE_PRIVATE)
      .getBoolean("screen_protection_enabled", true)
    if (protection) dialogWindow.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    else dialogWindow.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      dialogWindow.setHideOverlayWindows(true)
    }
  }

  private fun applyAccessibilitySensitivity(view: View?) {
    val target = view ?: return
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
    val sensitivity = ScreenProtectionPolicy.accessibilityDataSensitivity(
      true,
      Build.VERSION.SDK_INT,
    ) ?: return
    target.setAccessibilityDataSensitive(sensitivity)
  }

  private fun isKeyguardLocked(): Boolean {
    val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager ?: return true
    return keyguard.isKeyguardLocked
  }

  private val securityReceiver = object : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
      when (intent?.action) {
        Intent.ACTION_SCREEN_OFF, Intent.ACTION_USER_PRESENT -> {
          // Screen off and any keyguard transition clear local state immediately.
          editorEpoch += 1
          connected = false
          beginRequested = false
          SystemKeyboardBroker.resetEditor()
          clearSensitiveUi()
          showStatus(R.string.sk_status_unavailable)
        }
      }
    }
  }

  private fun registerSecurityReceiver() {
    if (securityReceiverRegistered) return
    val filter = IntentFilter().apply {
      addAction(Intent.ACTION_SCREEN_OFF)
      addAction(Intent.ACTION_USER_PRESENT)
    }
    securityReceiverRegistered = try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        registerReceiver(securityReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
      } else {
        registerReceiver(securityReceiver, filter)
      }
      true
    } catch (error: Throwable) {
      false
    }
  }

  private fun unregisterSecurityReceiver() {
    if (!securityReceiverRegistered) return
    securityReceiverRegistered = false
    try {
      unregisterReceiver(securityReceiver)
    } catch (error: Throwable) {
      // Already unregistered; nothing else to release.
    }
  }

  // --- view construction ---------------------------------------------------

  private val dark: Boolean get() = resources.configuration.uiMode and
    Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
  private val chrome: Int get() = if (dark) Color.rgb(33, 33, 33) else Color.rgb(223, 225, 228)
  private val inkColor: Int get() = if (dark) Color.WHITE else Color.BLACK
  private val muted: Int get() = if (dark) Color.rgb(155, 155, 160) else Color.rgb(115, 115, 120)
  private val functionColor: Int get() = if (dark) Color.rgb(154, 203, 250) else Color.rgb(11, 82, 69)
  private val functionInk: Int get() = if (dark) Color.rgb(0, 51, 82) else Color.WHITE
  private val keyColor: Int get() = if (dark) Color.BLACK else Color.WHITE
  private val specialColor: Int get() = if (dark) Color.rgb(67, 68, 72) else Color.rgb(204, 206, 210)
  private val language: String get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
    resources.configuration.locales[0].language else @Suppress("DEPRECATION") resources.configuration.locale.language

  private fun background(color: Int, radius: Int = 8) = GradientDrawable().apply {
    setColor(color); cornerRadius = dp(radius).toFloat()
  }

  private fun buildKeyboardView(): ProtectedInputRoot {
    val root = ProtectedInputRoot(this)
    root.orientation = LinearLayout.VERTICAL
    root.layoutParams = ViewGroup.LayoutParams(MATCH, WRAP)
    root.setBackgroundColor(chrome)
    root.setPadding(dp(6), dp(2), dp(6), dp(2))
    root.onUserTouch = {
      if (connected) SystemKeyboardBroker.recordUserInteraction()
      updateCountdown()
    }
    // An explicit paste/contact click must queue its action before the prompt
    // can steal focus. A tap on the unused surface may then only unlock.
    root.onWakeTap = { if (!connected && admitted && !biometricInFlight) resumeKeyboard() }
    root.setOnApplyWindowInsetsListener { view, insets ->
      val bottom = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        insets.getInsets(WindowInsets.Type.navigationBars()).bottom
      else @Suppress("DEPRECATION") insets.systemWindowInsetBottom
      view.setPadding(dp(6), dp(2), dp(6), dp(2) + bottom)
      insets
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
      root.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    root.isSaveEnabled = false

    val statusRow = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
    statusDot = TextView(this).apply {
      text = "●"; setTextColor(muted); textSize = 12f; gravity = Gravity.CENTER
    }
    statusRow.addView(statusDot, LinearLayout.LayoutParams(dp(16), dp(22)).apply { marginStart = dp(10); marginEnd = dp(8) })
    statusView = TextView(this).apply {
      setTextColor(muted); textSize = 12f; tag = "keyboard.status"
    }
    countdownView = TextView(this).apply {
      setTextColor(muted); textSize = 12f; gravity = Gravity.END
      setPadding(0, 0, dp(10), 0); tag = "keyboard.countdown"
    }
    statusRow.addView(statusView, LinearLayout.LayoutParams(0, dp(22), 1f))
    statusRow.addView(countdownView, LinearLayout.LayoutParams(dp(50), dp(22)))
    root.addView(statusRow)

    recipientRow = LinearLayout(this).apply {
      gravity = Gravity.CENTER_VERTICAL; visibility = View.GONE
      setPadding(dp(10), dp(3), dp(10), dp(3))
    }
    recipientShield = ImageView(this).apply { tag = "keyboard.shield" }
    recipientName = TextView(this).apply { textSize = 15f; setTextColor(inkColor); tag = "keyboard.recipient" }
    recipientRow!!.addView(recipientShield, LinearLayout.LayoutParams(dp(16), dp(20)).apply { marginEnd = dp(8) })
    recipientRow!!.addView(recipientName, LinearLayout.LayoutParams(0, WRAP, 1f))
    root.addView(recipientRow, LinearLayout.LayoutParams(MATCH, WRAP))

    val compose = LinearLayout(this).apply {
      gravity = Gravity.CENTER_VERTICAL; setPadding(0, dp(4), 0, dp(6))
    }
    composeRow = compose
    compose.addView(iconButton("contacts", getString(R.string.sk_action_contacts)) { requestContacts() },
      LinearLayout.LayoutParams(dp(40), dp(40)))
    val field = FrameLayout(this).apply { background = background(if (dark) Color.rgb(42, 42, 44) else Color.WHITE, 12) }
    draftView = KeyboardDraftView(this).apply {
      hint = getString(R.string.sk_draft_hint); setHintTextColor(muted)
      setTextColor(inkColor); textSize = 18f; gravity = Gravity.TOP
      setPadding(dp(10), dp(5), dp(30), dp(5)); tag = "keyboard.secret"
      onCursorTouch = { offset -> if (requireActiveEditor()) { draft.moveTo(offset); presentDraft() } }
    }
    field.addView(draftView, FrameLayout.LayoutParams(MATCH, dp(60)))
    clearDraftButton = iconButton("close", getString(R.string.sk_action_clear), false) {
      if (requireActiveEditor()) clearDraft()
    }.apply { visibility = View.GONE; tag = "keyboard.clear" }
    field.addView(clearDraftButton, FrameLayout.LayoutParams(dp(26), dp(26), Gravity.CENTER_VERTICAL or Gravity.END))
    compose.addView(field, LinearLayout.LayoutParams(0, dp(60), 1f).apply { marginStart = dp(6); marginEnd = dp(6) })
    insertButton = iconButton("paste", getString(R.string.sk_action_paste_decode)) {
      if (draft.text.isEmpty()) pasteCarrierFromClipboard() else requestInsert()
    }.apply { tag = "keyboard.primary" }
    compose.addView(insertButton, LinearLayout.LayoutParams(dp(40), dp(40)))
    root.addView(compose, LinearLayout.LayoutParams(MATCH, WRAP))

    contactsSection = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE }
    searchView = KeyboardDraftView(this).apply {
      hint = getString(R.string.sk_search_contacts); setHintTextColor(muted)
      setTextColor(inkColor); textSize = 16f; background = background(keyColor)
      setPadding(dp(10), dp(6), dp(10), dp(6)); tag = "keyboard.search"
      onCursorTouch = { offset -> if (requireActiveEditor()) { search.moveTo(offset); presentSearch() } }
    }
    val searchRow = LinearLayout(this)
    searchRowView = searchRow
    searchRow.addView(searchView, LinearLayout.LayoutParams(0, dp(40), 1f))
    searchRow.addView(plainButton(getString(R.string.sk_confirm_no)) { closeContacts() }, LinearLayout.LayoutParams(dp(76), dp(40)))
    contactsSection!!.addView(searchRow)
    val contactsScroll = ScrollView(this)
    contactsContainer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; tag = "keyboard.contactList" }
    contactsScroll.addView(contactsContainer, FrameLayout.LayoutParams(MATCH, WRAP))
    contactsSection!!.addView(contactsScroll, LinearLayout.LayoutParams(MATCH, dp(136)))
    contactsSection!!.setPadding(0, 0, 0, dp(8))
    root.addView(contactsSection)

    previewSection = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE }
    previewTitle = sectionTitle("")
    previewSection!!.addView(previewTitle)
    val previewScroll = ScrollView(this)
    previewView = TextView(this).apply {
      setTextColor(inkColor); textSize = 16f; setPadding(dp(8), dp(8), dp(8), dp(8)); isSaveEnabled = false
    }
    previewScroll.addView(previewView, FrameLayout.LayoutParams(MATCH, WRAP))
    previewSection!!.addView(previewScroll, LinearLayout.LayoutParams(MATCH, dp(145)))
    previewSection!!.addView(plainButton(getString(R.string.sk_reply_to)) {
      val sender = decodedSender ?: return@plainButton
      previewSection?.visibility = View.GONE
      showContactConfirmation(sender)
    })
    previewSection!!.addView(plainButton(getString(R.string.sk_preview_clear)) {
      previewView?.text = ""; previewTitle?.text = ""; decodedSender = null
      previewSection?.visibility = View.GONE; composeRow?.visibility = View.VISIBLE; keysContainer?.visibility = View.VISIBLE
    })
    root.addView(previewSection)

    accentRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; visibility = View.GONE }
    root.addView(accentRow, LinearLayout.LayoutParams(MATCH, dp(42)))
    keysContainer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; tag = "keyboard.keys" }
    root.addView(keysContainer, LinearLayout.LayoutParams(MATCH, WRAP))
    return root
  }

  private var decodedSender: BrokerContact? = null

  private fun sectionTitle(label: String): TextView = TextView(this).apply {
    text = label; setTextColor(muted); textSize = 13f; setPadding(dp(8), dp(4), dp(8), dp(4))
  }

  private fun haptic(view: View) { view.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP) }

  private fun plainButton(label: String, onClick: () -> Unit): Button = Button(this).apply {
    text = label; isAllCaps = false; minWidth = 0; minimumWidth = 0; minHeight = 0; minimumHeight = 0
    textSize = 14f; setTextColor(inkColor); background = background(specialColor)
    setPadding(dp(8), dp(5), dp(8), dp(5)); isSaveEnabled = false
    setOnClickListener { haptic(this); onClick() }
  }

  private fun iconButton(glyph: String, label: String, function: Boolean = true, action: () -> Unit): ImageButton =
    ImageButton(this).apply {
      background = background(if (function) functionColor else Color.TRANSPARENT, if (function) 24 else 8)
      setImageDrawable(KeyboardGlyphDrawable(glyph, if (function) functionInk else muted))
      val inset = if (glyph == "contacts") 11 else 10
      setPadding(dp(inset), dp(inset), dp(inset), dp(inset)); contentDescription = label; isSaveEnabled = false
      setOnClickListener { haptic(this); action() }
    }

  private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt().coerceAtLeast(0)

  // --- local key grid and editor --------------------------------------------

  private fun rebuildRows() {
    val base = when (keyMode) {
      KeyMode.LETTERS -> KeyboardPresentation.letterRows(language)
      KeyMode.NUMBERS -> NUMBER_ROWS
      KeyMode.SYMBOLS -> SYMBOL_ROWS
    }
    activeRows = if (scramble) base.map { shuffleRow(it) } else base
  }

  private fun shuffleRow(row: String): String {
    val characters = row.toCharArray()
    for (index in characters.size - 1 downTo 1) {
      val swapWith = secureRandom.nextInt(index + 1)
      val current = characters[index]; characters[index] = characters[swapWith]; characters[swapWith] = current
    }
    return String(characters)
  }

  private fun keyParams(weight: Float = 1f) = LinearLayout.LayoutParams(0,
    dp(if (resources.configuration.orientation == Configuration.ORIENTATION_LANDSCAPE) 36 else 44), weight).apply {
      marginStart = dp(2); marginEnd = dp(2); topMargin = dp(3); bottomMargin = dp(3)
    }

  private fun renderKeys() {
    val container = keysContainer ?: return
    container.removeAllViews()
    if (emojiVisible) { renderEmojiKeys(container); return }
    for ((index, row) in activeRows.withIndex()) {
      val rowView = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
      if (index == 2) rowView.addView(specialKey("shift", getString(R.string.sk_action_shift)) {
        if (requireActiveEditor()) { uppercase = !uppercase; renderKeys() }
      }, keyParams(1.3f))
      for (character in row) {
        val label = if (uppercase && character.isLetter()) character.uppercaseChar().toString() else character.toString()
        val key = plainButton(label) { appendDraft(label) }.apply {
          textSize = 21f; background = background(keyColor, 6); setPadding(0, 0, 0, 0)
        }
        attachAccents(key, label)
        rowView.addView(key, keyParams())
      }
      if (index == 2) rowView.addView(specialKey("delete", getString(R.string.sk_action_backspace)) { backspace() }, keyParams(1.3f))
      container.addView(rowView, LinearLayout.LayoutParams(MATCH, WRAP))
    }
    renderBottomRow(container)
  }

  private fun specialKey(glyph: String, label: String, action: () -> Unit): ImageButton = iconButton(glyph, label, false, action).apply {
    background = background(specialColor, 6); setImageDrawable(KeyboardGlyphDrawable(glyph, inkColor))
    setPadding(dp(12), dp(10), dp(12), dp(10))
  }

  private fun renderBottomRow(container: LinearLayout) {
    val row = LinearLayout(this)
    row.addView(plainButton(modeLabel()) {
      if (requireActiveEditor()) {
        emojiVisible = false
        keyMode = when (keyMode) { KeyMode.LETTERS -> KeyMode.NUMBERS; KeyMode.NUMBERS -> KeyMode.SYMBOLS; KeyMode.SYMBOLS -> KeyMode.LETTERS }
        rebuildRows(); renderKeys()
      }
    }, keyParams(1.25f))
    row.addView(specialKey("emoji", getString(R.string.sk_action_emoji)) {
      if (requireActiveEditor()) { emojiVisible = !emojiVisible; renderKeys() }
    }, keyParams(1.1f))
    val space = plainButton(getString(R.string.sk_action_space)) { appendDraft(" ") }
    attachTrackpad(space)
    row.addView(space, keyParams(5.5f))
    row.addView(specialKey("return", getString(R.string.sk_action_newline)) {
      if (searching) closeContacts() else appendDraft("\n")
    }, keyParams(1.4f))
    container.addView(row, LinearLayout.LayoutParams(MATCH, WRAP))
  }

  private var emojiCategory = 0
  private fun renderEmojiKeys(container: LinearLayout) {
    val categories = listOf("😀", "❤️", "🐱", "🍎")
    val emojiRows = listOf(
      listOf("😀 😃 😄 😁 😆 😅 😂", "🙂 🙃 😉 😊 😍 🥰 😘", "😎 🤔 😭 😢 😡 👍 🙏"),
      listOf("❤️ 🧡 💛 💚 💙 💜 🖤", "🤍 💕 💞 💓 💗 💖 💘", "✅ ❌ ⭐ ✨ 🔥 🎉 🎁"),
      listOf("🐱 🐶 🐭 🐹 🐰 🦊 🐻", "🐼 🐨 🐯 🦁 🐮 🐷 🐸", "🌸 🌹 🌻 🌷 🌴 🌊 ☀️"),
      listOf("🍎 🍐 🍊 🍋 🍌 🍉 🍇", "🍓 🍒 🍑 🥑 🍕 🍔 🍟", "🍰 🍫 ☕ 🍵 🥂 🍺 🍽️"))
    val tabs = LinearLayout(this)
    categories.forEachIndexed { index, title -> tabs.addView(plainButton(title) {
      if (requireActiveEditor()) { emojiCategory = index; renderKeys() }
    }, keyParams()) }
    tabs.addView(specialKey("delete", getString(R.string.sk_action_backspace)) { backspace() }, keyParams())
    container.addView(tabs)
    for (values in emojiRows[emojiCategory]) {
      val row = LinearLayout(this)
      for (value in values.split(" ")) row.addView(plainButton(value) { appendDraft(value) }.apply {
        textSize = 23f; background = background(keyColor, 6); setPadding(0, 0, 0, 0)
      }, keyParams())
      container.addView(row)
    }
    val bottom = LinearLayout(this)
    bottom.addView(plainButton("ABC") { if (requireActiveEditor()) { emojiVisible = false; renderKeys() } }, keyParams())
    bottom.addView(plainButton(getString(R.string.sk_action_space)) { appendDraft(" ") }, keyParams(4f))
    bottom.addView(specialKey("return", getString(R.string.sk_action_newline)) { appendDraft("\n") }, keyParams())
    container.addView(bottom)
  }

  private fun attachAccents(key: Button, label: String) {
    var choosing = false
    key.setOnLongClickListener {
      val variants = KeyboardPresentation.variants(label)
      if (variants.isEmpty() || !requireActiveEditor()) false else {
        haptic(key); accentSelection.begin(variants); choosing = true
        accentRow?.removeAllViews()
        for (value in variants) accentRow?.addView(plainButton(value) { }, keyParams())
        accentRow?.visibility = View.VISIBLE; true
      }
    }
    key.setOnTouchListener { _, event ->
      if (!choosing) false else {
        // A lock/revoke can clear the popup between a long press and finger-up.
        // Never index stale options or insert a character into a new session.
        if (currentAccents.isEmpty() || !requireActiveEditor()) {
          choosing = false; accentSelection.clear(); accentRow?.visibility = View.GONE
          return@setOnTouchListener true
        }
        if (event.actionMasked == MotionEvent.ACTION_MOVE) {
          val location = IntArray(2); accentRow?.getLocationOnScreen(location)
          val width = accentRow?.width ?: 1
          accentSelection.move((((event.rawX - location[0]) / width) * currentAccents.size).toInt())
          for (i in 0 until (accentRow?.childCount ?: 0)) accentRow?.getChildAt(i)?.alpha = if (i == accentIndex) 1f else .5f
        }
        if (event.actionMasked == MotionEvent.ACTION_UP || event.actionMasked == MotionEvent.ACTION_CANCEL) {
          if (event.actionMasked == MotionEvent.ACTION_UP) accentSelection.finish()?.let { appendDraft(it) }
          choosing = false; accentSelection.clear(); accentRow?.visibility = View.GONE
        }
        true
      }
    }
  }

  private fun attachTrackpad(space: Button) {
    var dragging = false; var x = 0f; var y = 0f
    space.setOnLongClickListener { if (!requireActiveEditor()) false else { dragging = true; haptic(space); true } }
    space.setOnTouchListener { _, event ->
      if (event.actionMasked == MotionEvent.ACTION_DOWN) { x = event.x; y = event.y }
      if (!dragging) false else {
        if (event.actionMasked == MotionEvent.ACTION_MOVE && requireActiveEditor()) {
          val horizontal = ((event.x - x) / dp(12).coerceAtLeast(1)).toInt()
          val vertical = ((event.y - y) / dp(22).coerceAtLeast(1)).toInt()
          val state = if (searching) search else draft
          val view = if (searching) searchView else draftView
          if (horizontal != 0) { state.moveBy(horizontal); x = event.x }
          if (vertical != 0) { state.moveTo(view?.moveVertical(vertical) ?: state.cursor); y = event.y }
          if (searching) presentSearch() else presentDraft()
        }
        if (event.actionMasked == MotionEvent.ACTION_UP || event.actionMasked == MotionEvent.ACTION_CANCEL) dragging = false
        true
      }
    }
  }

  private fun modeLabel(): String = when (keyMode) {
    KeyMode.LETTERS -> "123"; KeyMode.NUMBERS -> "#+="; KeyMode.SYMBOLS -> "ABC"
  }

  private fun appendDraft(text: String) {
    if (!requireActiveEditor()) return
    val state = if (searching) search else draft
    if (!state.insert(text)) { showStatus(R.string.sk_error_oversize); return }
    commitSelection.cancelPending()
    if (searching) { presentSearch(); filterContacts() } else presentDraft()
  }

  private fun backspace() {
    if (!requireActiveEditor()) return
    val state = if (searching) search else draft
    state.deleteBeforeCursor(); commitSelection.cancelPending()
    if (searching) { presentSearch(); filterContacts() } else presentDraft()
  }

  private fun presentDraft() { draftView?.present(draft.text, draft.cursor); updateInsertLabel() }
  private fun presentSearch() { searchView?.present(search.text, search.cursor) }
  private fun clearDraft() { draft.clear(); presentDraft() }

  // --- explicit clipboard paste -------------------------------------------

  /**
   * The only clipboard read in the whole keyboard. Exactly one item, its literal
   * `text` field, no `coerceToText`, no URIs, no listener and no automatic read.
   */
  private fun pasteCarrierFromClipboard() {
    if (!connected) { resumeKeyboard { pasteCarrierFromClipboard() }; return }
    if (!requireActiveEditor()) return
    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    if (clipboard == null) {
      showStatus(R.string.sk_error_unavailable)
      return
    }
    val clip = try {
      clipboard.primaryClip
    } catch (error: Throwable) {
      null
    }
    if (clip == null || clip.itemCount != 1) {
      showStatus(R.string.sk_error_no_message)
      return
    }
    val text = clip.getItemAt(0)?.text?.toString()
    if (text.isNullOrEmpty()) {
      showStatus(R.string.sk_error_no_message)
      return
    }
    if (!KeyboardEditorPolicy.admitsCarrierLength(text.length)) {
      showStatus(R.string.sk_error_oversize)
      return
    }
    if (KeyboardPastePolicy.looksLikePublicIdentity(text)) {
      showStatus(R.string.sk_identity_import)
      return
    }
    carrierBuffer = text
    requestDecode()
  }

  // --- recipient chooser ---------------------------------------------------

  private fun requestContacts() {
    if (!connected) { resumeKeyboard { requestContacts() }; return }
    if (!requireActiveEditor()) return
    val epoch = editorEpoch
    showStatus(R.string.sk_status_loading)
    SystemKeyboardBroker.loadContacts { outcome ->
      if (!guardEpoch(epoch)) return@loadContacts
      when (outcome) {
        is BrokerOutcome.Failure -> showFailure(outcome.status)
        is BrokerOutcome.Success -> renderContacts(outcome.value)
      }
    }
  }

  private fun renderContacts(contacts: List<BrokerContact>) {
    loadedContacts = contacts; search.clear(); searching = true; presentSearch()
    contactsSection?.visibility = View.VISIBLE; composeRow?.visibility = View.GONE
    previewSection?.visibility = View.GONE; keysContainer?.visibility = View.VISIBLE
    searchRowView?.visibility = View.VISIBLE; filterContacts()
    showStatus(R.string.sk_contacts_title)
  }

  private fun filterContacts() {
    val container = contactsContainer ?: return
    container.removeAllViews()
    val matches = loadedContacts.filter { KeyboardPresentation.matches(it.name, search.text) }
    if (matches.isEmpty()) container.addView(sectionTitle(getString(R.string.sk_status_contacts_empty)))
    for (contact in matches) container.addView(plainButton(contact.name) { showContactConfirmation(contact) }.apply {
      gravity = Gravity.START or Gravity.CENTER_VERTICAL; background = background(Color.TRANSPARENT)
    }, LinearLayout.LayoutParams(MATCH, dp(44)))
  }

  private fun closeContacts() {
    searching = false; search.clear(); loadedContacts = emptyList()
    contactsContainer?.removeAllViews(); contactsSection?.visibility = View.GONE
    composeRow?.visibility = View.VISIBLE; keysContainer?.visibility = View.VISIBLE
    showStatus(R.string.sk_status_ready)
  }

  private fun showContactConfirmation(contact: BrokerContact) {
    if (!requireActiveEditor()) return
    val epoch = editorEpoch
    searching = false; search.clear(); loadedContacts = emptyList()
    val container = contactsContainer ?: return
    container.removeAllViews(); searchRowView?.visibility = View.GONE
    contactsSection?.visibility = View.VISIBLE; composeRow?.visibility = View.GONE
    keysContainer?.visibility = View.GONE; recipientRow?.visibility = View.GONE
    val row = LinearLayout(this)
    row.addView(plainButton(getString(R.string.sk_confirm_no)) { closeContacts() }.apply {
      setTextColor(functionInk); background = background(functionColor, 22)
    }, LinearLayout.LayoutParams(0, dp(40), 1f).apply { marginEnd = dp(6) })
    row.addView(plainButton(getString(R.string.sk_confirm_yes)) {
      if (guardEpoch(epoch) && requireActiveEditor()) selectContact(contact.id, epoch)
    }.apply { setTextColor(functionInk); background = background(functionColor, 22) }, LinearLayout.LayoutParams(0, dp(40), 1f))
    container.addView(row)
    container.addView(sectionTitle(getString(R.string.sk_contact_confirm_message, contact.name, contact.fingerprint)))
  }

  private fun selectContact(contactId: String, epoch: Int) {
    SystemKeyboardBroker.selectContact(contactId) { outcome ->
      if (!guardEpoch(epoch)) return@selectContact
      when (outcome) {
        is BrokerOutcome.Failure -> showFailure(outcome.status)
        is BrokerOutcome.Success -> {
          selectedContact = outcome.value; closeContacts(); updateInsertLabel()
        }
      }
    }
  }

  private fun updateInsertLabel() {
    val hasText = draft.text.isNotEmpty()
    insertButton?.setImageDrawable(KeyboardGlyphDrawable(KeyboardPresentation.primaryAction(hasText), functionInk))
    insertButton?.contentDescription = getString(if (hasText) R.string.sk_action_insert_idle else R.string.sk_action_paste_decode)
    insertButton?.isEnabled = !operationInFlight
    clearDraftButton?.visibility = if (hasText) View.VISIBLE else View.GONE
    val contact = selectedContact
    recipientRow?.visibility = if (contact == null || contactsSection?.visibility == View.VISIBLE) View.GONE else View.VISIBLE
    recipientName?.text = contact?.name ?: ""
    val phase = contact?.securityPhase
    val color = when (KeyboardPresentation.shieldState(phase)) {
      "active" -> Color.rgb(48, 209, 88); "pending" -> Color.rgb(255, 159, 10)
      "recovery" -> Color.rgb(255, 69, 58); else -> muted
    }
    recipientShield?.setImageDrawable(KeyboardGlyphDrawable("shield", color, phase?.startsWith("maximum") == true))
    recipientShield?.contentDescription = getString(when (KeyboardPresentation.shieldState(phase)) {
      "active" -> R.string.sk_fs_active; "pending" -> R.string.sk_fs_pending
      "recovery" -> R.string.sk_fs_recovery; else -> R.string.sk_fs_unknown
    })
  }

  // --- compose, insert, acknowledge ---------------------------------------

  private fun requestInsert() {
    if (!requireActiveEditor()) return
    if (selectedContact == null) {
      requestContacts()
      return
    }
    if (draft.text.isEmpty()) {
      showStatus(R.string.sk_status_nothing_to_insert)
      return
    }
    val epoch = editorEpoch
    operationInFlight = true
    updateInsertLabel()
    SystemKeyboardBroker.prepareAndAuthorize(draft.text) { outcome ->
      if (!guardEpoch(epoch)) return@prepareAndAuthorize
      when (outcome) {
        is BrokerOutcome.Failure -> { operationInFlight = false; updateInsertLabel(); showFailure(outcome.status) }
        is BrokerOutcome.Success -> commitCarrier(outcome.value, epoch)
      }
    }
  }

  /**
   * The only host insert in the service: the already-encrypted carrier. The
   * exact editor epoch, the live grant deadline, the current input connection and
   * the outbound 4000-unit carrier bound are all re-checked immediately before the
   * commit. A successful commit clears the plaintext draft at once, so a failing
   * acknowledgement can never lead to a second, unintended insert.
   */
  private fun commitCarrier(export: PreparedExport, epoch: Int) {
    if (!guardEpoch(epoch) || !admitted || !connected) return
    if (!KeyboardEditorPolicy.admitsOutboundCarrierLength(export.carrier.length)) {
      // Never trust an oversized carrier, even if the app core misbehaves.
      SystemKeyboardBroker.acknowledge(export.pendingId, false) { }
      operationInFlight = false; updateInsertLabel()
      showStatus(R.string.sk_error_unsupported_export)
      return
    }
    if (!SystemKeyboardBroker.isEditorUsableNow()) {
      operationInFlight = false; updateInsertLabel()
      showStatus(R.string.sk_status_unavailable)
      return
    }
    val connection = currentInputConnection
    val inserted = if (connection == null) {
      false
    } else {
      try {
        commitSelection.expectInsertion(export.carrier.length)
        connection.commitText(export.carrier, 1)
      } catch (error: Throwable) {
        false
      }
    }
    if (inserted) {
      committedCarrierInEditor = true
      clearDraft()
      // Keep the choice only for our own successful insert in this editor.
      // Lifecycle and arbitrary host selection changes still revoke it.
      updateInsertLabel()
      showStatus(R.string.sk_status_insert_uncertain)
    }
    if (!inserted) commitSelection.cancelPending()
    SystemKeyboardBroker.acknowledge(export.pendingId, inserted) { outcome ->
      if (!guardEpoch(epoch)) return@acknowledge
      if (outcome is BrokerOutcome.Success && outcome.value && inserted) {
        val recipient = selectedContact
        if (recipient != null) {
          // The core consumes selection on export: ask it to reapprove the
          // same user-confirmed contact before enabling another insertion.
          SystemKeyboardBroker.selectContact(recipient.id) { selected ->
            if (!guardEpoch(epoch)) return@selectContact
            operationInFlight = false
            selectedContact = (selected as? BrokerOutcome.Success)?.value
            updateInsertLabel()
            if (selected is BrokerOutcome.Failure) showFailure(selected.status) else showStatus(R.string.sk_status_ready)
          }
        } else { operationInFlight = false; updateInsertLabel() }
      } else {
        operationInFlight = false; selectedContact = null; updateInsertLabel()
        showStatus(if (inserted) R.string.sk_status_insert_open_app else R.string.sk_error_unavailable)
      }
    }
  }

  // --- inbound decode ------------------------------------------------------

  private fun requestDecode() {
    if (!requireActiveEditor()) return
    val carrier = carrierBuffer
    if (carrier.isNullOrEmpty()) {
      showStatus(R.string.sk_error_no_message)
      return
    }
    val epoch = editorEpoch
    carrierBuffer = null
    // A pasted message cannot silently keep a previous outbound recipient.
    selectedContact = null; decodedSender = null; updateInsertLabel()
    SystemKeyboardBroker.decode(carrier) { outcome ->
      if (!guardEpoch(epoch)) return@decode
      when (outcome) {
        is BrokerOutcome.Failure -> showFailure(outcome.status)
        is BrokerOutcome.Success -> renderPreview(outcome.value)
      }
    }
  }

  private fun renderPreview(preview: BrokerDecoded) {
    previewTitle?.text = getString(
      R.string.sk_preview_title,
      preview.contactName,
      preview.fingerprint,
    )
    selectedContact = null; updateInsertLabel()
    decodedSender = if (preview.contactId.isNotEmpty()) BrokerContact(preview.contactId, preview.contactName, preview.fingerprint) else null
    composeRow?.visibility = View.GONE
    previewView?.text = preview.text
    previewSection?.visibility = View.VISIBLE
    keysContainer?.visibility = View.GONE
    // The authenticated sender is never bound to the outbound recipient chooser.
    showStatus(R.string.sk_status_decoded)
  }

  /**
   * Switches to the next input method without launching any app. On API 28+ the
   * service convenience method is used; below that the framework token overload
   * `InputMethodManager.switchToNextInputMethod(token, false)` is required.
   */
  private fun switchToNextKeyboard() {
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        switchToNextInputMethod(false)
        return
      }
      val token = window?.window?.attributes?.token
      val manager = getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
      if (token == null || manager == null || !manager.switchToNextInputMethod(token, false)) {
        showStatus(R.string.sk_error_unavailable)
      }
    } catch (error: Throwable) {
      showStatus(R.string.sk_error_unavailable)
    }
  }

  // --- helpers -------------------------------------------------------------

  /**
   * Binds (when needed) and requests `begin` at most once per editor generation,
   * and only while the input view is actually visible. A heartbeat never
   * re-begins a revoked editor.
   */
  private fun beginEditorSession() {
    if (biometricTarget != null && KeyboardAutonomousHost.hasBiometricFlow) return
    if (!admitted) {
      showStatus(R.string.sk_status_rejected_field)
      return
    }
    if (beginRequested) return
    if (!SystemKeyboardBroker.isEnabled()) {
      // Without the explicit app opt-in the component stays unusable.
      showStatus(R.string.sk_status_unavailable)
      return
    }
    if (!SystemKeyboardBroker.hasEditorGeneration()) {
      SystemKeyboardBroker.bindEditor()
    }
    beginRequested = true
    connected = false
    val epoch = editorEpoch
    showStatus(R.string.sk_status_connecting)
    SystemKeyboardBroker.requestBegin { outcome ->
      if (!guardEpoch(epoch)) return@requestBegin
      when (outcome) {
        is BrokerOutcome.Failure -> {
          // No automatic fallback: a new admitted editor is required after an
          // initial begin failure. An expired active editor uses biometrics.
          connected = false
          showFailure(outcome.status)
        }
        is BrokerOutcome.Success -> {
          connected = true
          scramble = outcome.value
          rebuildRows()
          renderKeys()
          updateInsertLabel()
          showStatus(R.string.sk_status_ready)
        }
      }
    }
  }

  /**
   * Synchronous admission gate for every local operation: field admission, a
   * confirmed editor generation and a live, unexpired grant. The broker re-checks
   * the same deadline again immediately before any host insert.
   */
  private fun requireActiveEditor(): Boolean {
    if (!admitted || !connected || !SystemKeyboardBroker.isEditorUsableNow()) {
      KeyboardQaTrace.emit(
        this, "keyNeedsAdmission:admitted=$admitted:connected=$connected:binding=${editorBinding != null}")
      if (admitted && !connected) resumeKeyboard()
      showReentryStatus()
      return false
    }
    return true
  }

  private fun resumeKeyboard(after: (() -> Unit)? = null) {
    KeyboardQaTrace.emit(
      this, "resumePreflight:admitted=$admitted:enabled=${KeyboardAutonomousHost.enabled()}:binding=${editorBinding != null}:flow=${KeyboardAutonomousHost.hasBiometricFlow}:pending=${biometricInFlight || biometricCompleting || biometricVerified}")
    if (!admitted || !KeyboardAutonomousHost.enabled()) return
    if (biometricTarget != null && !KeyboardAutonomousHost.hasBiometricFlow) cancelBiometricFlow()
    if (biometricInFlight || biometricCompleting || biometricVerified) return
    val target = editorBinding ?: return
    afterBiometric = after
    biometricTarget = target
    biometricInFlight = true
    SystemKeyboardBroker.requestBiometricBegin { authenticated ->
      biometricInFlight = false
      if (!authenticated) { cancelBiometricFlow(); if (isInputViewShown) showReentryStatus(); return@requestBiometricBegin }
      biometricVerified = true
      KeyboardQaTrace.emit(this, "biometricVerifiedWaitingForEditor")
      completeBiometricIfReady()
      // EMUI can finish the IME input while the biometric Activity is closing.
      // One immediate request is too early there. Retry briefly, only while the
      // authenticated handoff still belongs to this exact original editor.
      scheduleBiometricReturn(target)
    }
  }

  private fun scheduleBiometricReturn(target: KeyboardEditorBinding) {
    for (delay in listOf(150L, 500L, 1200L, 2400L)) {
      uiHandler.postDelayed({
        if (biometricTarget != target || !biometricVerified || !KeyboardAutonomousHost.hasBiometricFlow ||
            isKeyguardLocked() || (editorBinding != null && editorBinding != target)) return@postDelayed
        KeyboardQaTrace.emit(this, "biometricShowSelfRequested")
        requestShowSelf(0)
      }, delay)
    }
  }

  private fun cancelBiometricFlow() {
    biometricInFlight = false; biometricVerified = false; biometricCompleting = false
    biometricTarget = null; afterBiometric = null
    if (KeyboardAutonomousHost.hasBiometricFlow) KeyboardAutonomousHost.discardBiometric()
  }

  /** An authenticated ticket can only be used in the exact editor that asked. */
  private fun completeBiometricIfReady(): Boolean {
    val target = biometricTarget ?: return false
    if (biometricCompleting || biometricInFlight) return true
    if (!KeyboardAutonomousHost.hasBiometricFlow) { cancelBiometricFlow(); return false }
    if (!biometricVerified) return true
    if (!KeyboardBiometricEditorPolicy.mayAdmit(target, editorBinding, isInputViewShown, admitted)) return true
    biometricCompleting = true; biometricVerified = false; beginRequested = true
    KeyboardQaTrace.emit(this, "biometricEditorReadmitted")
    val epoch = editorEpoch
    SystemKeyboardBroker.completeBiometricBegin { outcome ->
      biometricCompleting = false
      if (!guardEpoch(epoch) || editorBinding != target || !isInputViewShown) {
        cancelBiometricFlow(); return@completeBiometricBegin
      }
      biometricTarget = null
      val action = afterBiometric; afterBiometric = null
      if (outcome is BrokerOutcome.Success) {
        connected = true; scramble = outcome.value
        rebuildRows(); renderKeys(); showStatus(R.string.sk_status_ready)
        action?.invoke()
      } else { showReentryStatus() }
    }
    return true
  }

  private fun guardEpoch(epoch: Int): Boolean = epoch == editorEpoch

  /**
   * Best-effort local clear of every sensitive entry: draft, carrier buffer,
   * confirmed recipient, chooser list, preview labels and inline confirmation. String content is dropped, not zeroized.
   */
  private fun clearSensitiveUi() {
    committedCarrierInEditor = false
    clearDraft()
    carrierBuffer = null
    selectedContact = null
    decodedSender = null; searching = false; search.clear(); loadedContacts = emptyList(); operationInFlight = false
    searchView?.present("", 0); accentRow?.visibility = View.GONE; accentSelection.clear()
    composeRow?.visibility = View.VISIBLE
    commitSelection.cancelPending()
    contactsContainer?.removeAllViews()
    contactsSection?.visibility = View.GONE
    keysContainer?.visibility = View.VISIBLE
    previewTitle?.text = ""
    previewView?.text = ""
    previewSection?.visibility = View.GONE
    updateInsertLabel()
  }

  private fun showStatus(resId: Int) {
    statusView?.text = getString(resId)
    statusDot?.setTextColor(if (connected) (if (dark) Color.WHITE else functionColor) else muted)
    updateCountdown()
  }

  private fun showReentryStatus() {
    val status = KeyboardReentryStatusPolicy.status(admitted,
      biometricInFlight || biometricVerified || biometricCompleting,
      SystemKeyboardBroker.canOfferBiometricUnlock())
    showStatus(when (status) {
      KeyboardReentryStatusPolicy.Status.REJECTED_FIELD -> R.string.sk_status_rejected_field
      KeyboardReentryStatusPolicy.Status.UNLOCKING -> R.string.sk_status_unlocking
      KeyboardReentryStatusPolicy.Status.TOUCH_TO_UNLOCK -> R.string.sk_status_touch_to_unlock
      KeyboardReentryStatusPolicy.Status.OPEN_APP -> R.string.sk_status_unavailable
    })
  }

  private fun showStatusText(text: CharSequence) {
    statusView?.text = text
    updateCountdown()
  }

  private fun updateCountdown() {
    val remaining = if (connected) SystemKeyboardBroker.remainingIdleMillis() else 0L
    countdownView?.text = if (remaining > 0) "${(remaining + 999) / 1000}s" else ""
  }

  private val countdownTick = object : Runnable {
    override fun run() { updateCountdown(); uiHandler.postDelayed(this, 250) }
  }

  /** Maps every internal failure to one short, identity-free user message. */
  private fun showFailure(status: String) {
    if (status == SystemKeyboardBroker.STATUS_UNAVAILABLE) {
      showReentryStatus()
      return
    }
    val resId = when (status) {
      SystemKeyboardBroker.STATUS_BUSY -> R.string.sk_error_busy
      SystemKeyboardBroker.STATUS_INVALID_SELECTION -> R.string.sk_error_invalid_selection
      SystemKeyboardBroker.STATUS_OVERSIZE -> R.string.sk_error_oversize
      SystemKeyboardBroker.STATUS_UNSUPPORTED_EXPORT -> R.string.sk_error_unsupported_export
      SystemKeyboardBroker.STATUS_INVALID_REQUEST -> R.string.sk_error_invalid_request
      SystemKeyboardBroker.STATUS_NO_PENDING_EXPORT -> R.string.sk_error_no_pending_export
      SystemKeyboardBroker.STATUS_NO_MESSAGE -> R.string.sk_error_no_message
      "openAppRequired" -> R.string.sk_error_open_app_required
      "duplicateRequest" -> R.string.sk_error_duplicate_request
      "backendError" -> R.string.sk_error_backend
      else -> R.string.sk_error_unavailable
    }
    showStatus(resId)
  }
}

/**
 * Input-view root that reuses the existing [ScreenProtectionTouchGate] so an
 * obscured gesture stream is cancelled to children before it is rejected.
 */
internal class ProtectedInputRoot(context: Context) : LinearLayout(context) {
  var onUserTouch: (() -> Unit)? = null
  var onWakeTap: (() -> Unit)? = null
  private val touchGate = ScreenProtectionTouchGate()

  override fun dispatchTouchEvent(event: MotionEvent): Boolean {
    return when (
      touchGate.onTouchEvent(
        event.actionMasked,
        event.flags,
        true,
        Build.VERSION.SDK_INT,
      )
    ) {
      TouchDispatchAction.DISPATCH -> {
        if (event.actionMasked == MotionEvent.ACTION_DOWN)
          KeyboardQaTrace.emit(context, "imeTouchDown")
        if (event.actionMasked == MotionEvent.ACTION_DOWN || event.actionMasked == MotionEvent.ACTION_MOVE) onUserTouch?.invoke()
        val handled = super.dispatchTouchEvent(event)
        if (event.actionMasked == MotionEvent.ACTION_UP && !handled) onWakeTap?.invoke()
        handled
      }
      TouchDispatchAction.REJECT -> false
      TouchDispatchAction.CANCEL_THEN_REJECT -> {
        dispatchCancellationToChildren(event)
        false
      }
    }
  }

  private fun dispatchCancellationToChildren(event: MotionEvent) {
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
}
