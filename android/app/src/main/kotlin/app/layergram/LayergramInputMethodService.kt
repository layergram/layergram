package app.layergram

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.res.Configuration
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
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
 * [TextView] plus a custom key grid, and it never hands plaintext to the host
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
    val NUMBER_ROWS = listOf("1234567890", "-/:;()\$&@\"", ".,?!'")
    val SYMBOL_ROWS = listOf("[]{}#%^*+=", "_\\|~<>€£¥•", ".,?!àèéìòù")
  }

  private enum class KeyMode { LETTERS, NUMBERS, SYMBOLS }

  private val secureRandom = SecureRandom()
  private val draft = StringBuilder()

  private var rootView: ProtectedInputRoot? = null
  private var statusView: TextView? = null
  private var draftView: TextView? = null
  private var keysContainer: LinearLayout? = null
  private var contactsSection: LinearLayout? = null
  private var contactsContainer: LinearLayout? = null
  private var previewSection: LinearLayout? = null
  private var previewTitle: TextView? = null
  private var previewView: TextView? = null
  private var insertButton: Button? = null
  private var reconnectButton: Button? = null

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
  private var editorEpoch = 0
  private var securityReceiverRegistered = false

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
    super.onStartInput(attribute, restarting)
    editorEpoch += 1
    beginRequested = false
    connected = false
    SystemKeyboardBroker.attachService(this)
    SystemKeyboardBroker.resetEditor()
    clearSensitiveUi()
    commitSelection.update(attribute?.initialSelStart ?: -1, attribute?.initialSelEnd ?: -1)
    admitted = KeyboardEditorPolicy.admitsEditor(attribute?.inputType ?: 0) && !isKeyguardLocked()
    if (!admitted) {
      setReconnectVisible(false)
      showStatus(R.string.sk_status_rejected_field)
      return
    }
    SystemKeyboardBroker.bindEditor()
    setReconnectVisible(false)
    showStatus(R.string.sk_status_ready)
  }

  override fun onStartInputView(info: EditorInfo?, restarting: Boolean) {
    super.onStartInputView(info, restarting)
    applyWindowSecurity()
    applyAccessibilitySensitivity(rootView)
    SystemKeyboardBroker.attachService(this)
    SystemKeyboardBroker.setServiceVisible(true)
    renderKeys()
    updateInsertLabel()
    if (!admitted) {
      showStatus(R.string.sk_status_rejected_field)
      return
    }
    beginEditorSession(explicitReconnect = false)
  }

  override fun onWindowShown() {
    super.onWindowShown()
    applyWindowSecurity()
    SystemKeyboardBroker.setServiceVisible(true)
    if (admitted) beginEditorSession(explicitReconnect = false)
  }

  override fun onWindowHidden() {
    // A hidden window always clears every sensitive entry; the broker also
    // invalidates the generation so no reply can arrive for a hidden surface.
    clearSensitiveUi()
    SystemKeyboardBroker.setServiceVisible(false)
    super.onWindowHidden()
  }

  override fun onFinishInputView(finishingInput: Boolean) {
    resetForLifecycleEvent()
    super.onFinishInputView(finishingInput)
  }

  override fun onFinishInput() {
    resetForLifecycleEvent()
    super.onFinishInput()
  }

  override fun onDestroy() {
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
    if (ownCommit || (oldSelStart == newSelStart && oldSelEnd == newSelEnd)) return
    SystemKeyboardBroker.onHostSelectionChanged()
    onBrokerUnavailable()
  }

  /** Called by the broker whenever it clears or invalidates the editor. */
  fun onBrokerUnavailable() {
    editorEpoch += 1
    connected = false
    clearSensitiveUi()
    showStatus(R.string.sk_status_unavailable)
    setReconnectVisible(admitted)
  }

  private fun resetForLifecycleEvent() {
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
    dialogWindow.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
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

  private fun buildKeyboardView(): ProtectedInputRoot {
    val root = ProtectedInputRoot(this)
    root.orientation = LinearLayout.VERTICAL
    // Reserve a real preview/draft viewport; a zero-height weighted child in an
    // unbounded wrap-content IME would otherwise never become visible.
    val landscape = resources.configuration.orientation == Configuration.ORIENTATION_LANDSCAPE
    root.minimumHeight = minOf(
      dp(if (landscape) 352 else 440),
      (resources.displayMetrics.heightPixels * 0.8).toInt(),
    )
    root.setBackgroundColor(Color.BLACK)
    root.setPadding(dp(4), dp(4), dp(4), dp(4))
    root.setOnApplyWindowInsetsListener { view, insets ->
      val bottom = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        insets.getInsets(WindowInsets.Type.navigationBars()).bottom
      } else {
        @Suppress("DEPRECATION")
        insets.systemWindowInsetBottom
      }
      view.setPadding(dp(4), dp(4), dp(4), dp(4) + bottom)
      insets
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      // The plaintext draft and every label stay out of autofill entirely.
      root.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    }

    val status = TextView(this).apply {
      setTextColor(Color.LTGRAY)
      setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
      gravity = Gravity.CENTER_HORIZONTAL
      minHeight = dp(20)
    }
    statusView = status
    root.addView(status, LinearLayout.LayoutParams(MATCH, WRAP))

    val bodyScroll = ScrollView(this)
    val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    bodyScroll.addView(body, FrameLayout.LayoutParams(MATCH, WRAP))
    root.addView(bodyScroll, LinearLayout.LayoutParams(MATCH, 0, 1f))

    val draft = TextView(this).apply {
      setTextColor(Color.WHITE)
      setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
      hint = getString(R.string.sk_draft_hint)
      setHintTextColor(Color.LTGRAY)
      setPadding(dp(6), dp(6), dp(6), dp(6))
    }
    draftView = draft
    body.addView(draft, LinearLayout.LayoutParams(MATCH, WRAP))

    // Contacts chooser: names and fingerprints only, never a pre-selected entry.
    val contacts = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    contactsSection = contacts
    contacts.visibility = View.GONE
    contacts.addView(sectionTitle(getString(R.string.sk_contacts_title)), LinearLayout.LayoutParams(MATCH, WRAP))
    val contactList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    contactsContainer = contactList
    contacts.addView(contactList, LinearLayout.LayoutParams(MATCH, WRAP))
    contacts.addView(
      plainButton(getString(R.string.sk_contacts_clear)) {
        contactList.removeAllViews()
        contacts.visibility = View.GONE
        keysContainer?.visibility = View.VISIBLE
      },
      LinearLayout.LayoutParams(MATCH, WRAP),
    )
    body.addView(contacts, LinearLayout.LayoutParams(MATCH, WRAP))

    // Decoded preview: scrollable, clearable, and never a recipient source.
    val preview = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    previewSection = preview
    preview.visibility = View.GONE
    val title = sectionTitle("")
    previewTitle = title
    preview.addView(title, LinearLayout.LayoutParams(MATCH, WRAP))
    val previewScroll = ScrollView(this)
    val previewText = TextView(this).apply {
      setTextColor(Color.WHITE)
      setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
      setPadding(dp(6), dp(6), dp(6), dp(6))
    }
    previewView = previewText
    previewScroll.addView(previewText, FrameLayout.LayoutParams(MATCH, WRAP))
    preview.addView(previewScroll, LinearLayout.LayoutParams(MATCH, dp(120)))
    preview.addView(
      plainButton(getString(R.string.sk_preview_clear)) {
        previewText.text = ""
        previewTitle?.text = ""
        preview.visibility = View.GONE
        keysContainer?.visibility = View.VISIBLE
      },
      LinearLayout.LayoutParams(MATCH, WRAP),
    )
    body.addView(preview, LinearLayout.LayoutParams(MATCH, WRAP))

    val keys = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    keysContainer = keys
    root.addView(keys, LinearLayout.LayoutParams(MATCH, WRAP))

    val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
    actions.addView(
      actionButton(getString(R.string.sk_action_paste)) { pasteCarrierFromClipboard() },
      weightParams(),
    )
    actions.addView(
      actionButton(getString(R.string.sk_action_contacts)) { requestContacts() },
      weightParams(),
    )
    actions.addView(
      actionButton(getString(R.string.sk_action_decode)) { requestDecode() },
      weightParams(),
    )
    actions.addView(
      actionButton(getString(R.string.sk_action_next_keyboard)) { switchToNextKeyboard() },
      weightParams(),
    )
    root.addView(actions, LinearLayout.LayoutParams(MATCH, WRAP))

    val insertRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
    val insert = actionButton(getString(R.string.sk_action_insert_idle)) { requestInsert() }
    insertButton = insert
    insertRow.addView(insert, weightParams())
    val reconnect = actionButton(getString(R.string.sk_action_reconnect)) {
      beginEditorSession(explicitReconnect = true)
    }
    reconnect.visibility = View.GONE
    reconnectButton = reconnect
    insertRow.addView(reconnect, weightParams())
    root.addView(insertRow, LinearLayout.LayoutParams(MATCH, WRAP))

    return root
  }

  private fun sectionTitle(label: String): TextView = TextView(this).apply {
    text = label
    setTextColor(Color.LTGRAY)
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
  }

  private fun plainButton(label: String, onClick: () -> Unit): Button = Button(this).apply {
    text = label
    isAllCaps = false
    minWidth = 0
    minimumWidth = 0
    minHeight = dp(40)
    minimumHeight = dp(40)
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
    setPadding(dp(4), dp(2), dp(4), dp(2))
    setOnClickListener { onClick() }
  }

  private fun actionButton(label: String, onClick: () -> Unit): Button = plainButton(label, onClick)

  private fun weightParams(): LinearLayout.LayoutParams =
    LinearLayout.LayoutParams(0, WRAP, 1f)

  private fun dp(value: Int): Int =
    (value * resources.displayMetrics.density).toInt().coerceAtLeast(0)

  // --- key grid ------------------------------------------------------------

  private fun rebuildRows() {
    val base = when (keyMode) {
      KeyMode.LETTERS -> LETTER_ROWS
      KeyMode.NUMBERS -> NUMBER_ROWS
      KeyMode.SYMBOLS -> SYMBOL_ROWS
    }
    activeRows = if (scramble) base.map { shuffleRow(it) } else base
  }

  /** Presentation-only shuffle of the local grid; never used for any keying material. */
  private fun shuffleRow(row: String): String {
    val characters = row.toCharArray()
    for (index in characters.size - 1 downTo 1) {
      val swapWith = secureRandom.nextInt(index + 1)
      val current = characters[index]
      characters[index] = characters[swapWith]
      characters[swapWith] = current
    }
    return String(characters)
  }

  private fun renderKeys() {
    val container = keysContainer ?: return
    container.removeAllViews()
    for (row in activeRows) {
      val rowView = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
      for (character in row) {
        val label = if (uppercase && character.isLetter()) {
          character.uppercaseChar().toString()
        } else {
          character.toString()
        }
        val key = plainButton(label) { appendDraft(label) }
        key.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
        val height = if (resources.configuration.orientation == Configuration.ORIENTATION_LANDSCAPE) 30 else 44
        rowView.addView(key, LinearLayout.LayoutParams(0, dp(height), 1f))
      }
      container.addView(rowView, LinearLayout.LayoutParams(MATCH, WRAP))
    }

    val specialRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
    specialRow.addView(
      plainButton(getString(R.string.sk_action_shift)) {
        uppercase = !uppercase
        renderKeys()
      },
      weightParams(),
    )
    specialRow.addView(
      plainButton(modeLabel()) {
        keyMode = when (keyMode) {
          KeyMode.LETTERS -> KeyMode.NUMBERS
          KeyMode.NUMBERS -> KeyMode.SYMBOLS
          KeyMode.SYMBOLS -> KeyMode.LETTERS
        }
        rebuildRows()
        renderKeys()
      },
      weightParams(),
    )
    specialRow.addView(
      plainButton(getString(R.string.sk_action_backspace)) { backspace() },
      weightParams(),
    )
    container.addView(specialRow, LinearLayout.LayoutParams(MATCH, WRAP))

    val editRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
    editRow.addView(
      plainButton(getString(R.string.sk_action_space)) { appendDraft(" ") },
      weightParams(),
    )
    editRow.addView(
      plainButton(getString(R.string.sk_action_newline)) { appendDraft("\n") },
      weightParams(),
    )
    editRow.addView(
      plainButton(getString(R.string.sk_action_clear)) { clearDraft() },
      weightParams(),
    )
    container.addView(editRow, LinearLayout.LayoutParams(MATCH, WRAP))
  }

  private fun modeLabel(): String = when (keyMode) {
    KeyMode.LETTERS -> getString(R.string.sk_mode_numbers)
    KeyMode.NUMBERS -> getString(R.string.sk_mode_symbols)
    KeyMode.SYMBOLS -> getString(R.string.sk_mode_letters)
  }

  // --- local draft ---------------------------------------------------------

  private fun appendDraft(text: CharSequence) {
    if (!requireActiveEditor()) return
    if (!KeyboardEditorPolicy.admitsDraftAppend(draft.length, text.length)) {
      showStatus(R.string.sk_error_oversize)
      return
    }
    commitSelection.cancelPending()
    draft.append(text)
    draftView?.text = draft.toString()
  }

  private fun backspace() {
    if (!requireActiveEditor()) return
    if (draft.isEmpty()) return
    commitSelection.cancelPending()
    draft.setLength(draft.length - 1)
    draftView?.text = draft.toString()
  }

  /** Best-effort local clear of the native draft; String content is not zeroized. */
  private fun clearDraft() {
    draft.setLength(0)
    draftView?.text = ""
  }

  // --- explicit clipboard paste -------------------------------------------

  /**
   * The only clipboard read in the whole keyboard. Exactly one item, its literal
   * `text` field, no `coerceToText`, no URIs, no listener and no automatic read.
   */
  private fun pasteCarrierFromClipboard() {
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
    carrierBuffer = text
    showStatusText(getString(R.string.sk_status_carrier_loaded, text.length))
  }

  // --- recipient chooser ---------------------------------------------------

  private fun requestContacts() {
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
    val section = contactsSection ?: return
    val container = contactsContainer ?: return
    container.removeAllViews()
    section.visibility = View.VISIBLE
    keysContainer?.visibility = View.GONE
    if (contacts.isEmpty()) {
      showStatus(R.string.sk_status_contacts_empty)
      return
    }
    showStatus(R.string.sk_status_ready)
    for (contact in contacts) {
      val entry = plainButton(
        getString(R.string.sk_contact_entry, contact.name, contact.fingerprint),
      ) { confirmContact(contact) }
      container.addView(entry, LinearLayout.LayoutParams(MATCH, WRAP))
    }
  }

  /** Explicit confirmation with the displayed fingerprint; nothing is inferred. */
  private fun confirmContact(contact: BrokerContact) {
    if (!requireActiveEditor()) return
    val epoch = editorEpoch
    val container = contactsContainer ?: return
    container.removeAllViews()
    container.addView(sectionTitle(getString(
      R.string.sk_contact_confirm_message, contact.name, contact.fingerprint,
    )), LinearLayout.LayoutParams(MATCH, WRAP))
    // Keep confirmation inside the protected IME window. A service has no
    // activity token for an application dialog, and a second window could
    // change input focus while a recipient is being confirmed.
    container.addView(plainButton(getString(R.string.sk_confirm_yes)) {
      if (guardEpoch(epoch) && requireActiveEditor()) selectContact(contact.id, epoch)
    }, LinearLayout.LayoutParams(MATCH, WRAP))
    container.addView(plainButton(getString(R.string.sk_confirm_no)) {
      container.removeAllViews()
      contactsSection?.visibility = View.GONE
      keysContainer?.visibility = View.VISIBLE
    }, LinearLayout.LayoutParams(MATCH, WRAP))
  }

  private fun selectContact(contactId: String, epoch: Int) {
    SystemKeyboardBroker.selectContact(contactId) { outcome ->
      if (!guardEpoch(epoch)) return@selectContact
      when (outcome) {
        is BrokerOutcome.Failure -> showFailure(outcome.status)
        is BrokerOutcome.Success -> {
          selectedContact = outcome.value
          contactsContainer?.removeAllViews()
          contactsSection?.visibility = View.GONE
          keysContainer?.visibility = View.VISIBLE
          updateInsertLabel()
          showStatusText(getString(R.string.sk_status_selected, outcome.value.name))
        }
      }
    }
  }

  private fun updateInsertLabel() {
    val button = insertButton ?: return
    val recipient = selectedContact
    if (recipient == null) {
      button.text = getString(R.string.sk_action_insert_idle)
      button.isEnabled = false
    } else {
      button.text = getString(R.string.sk_action_insert_for, recipient.name)
      button.isEnabled = true
    }
  }

  // --- compose, insert, acknowledge ---------------------------------------

  private fun requestInsert() {
    if (!requireActiveEditor()) return
    if (selectedContact == null) {
      showStatus(R.string.sk_status_select_recipient)
      return
    }
    if (draft.isEmpty()) {
      showStatus(R.string.sk_status_nothing_to_insert)
      return
    }
    val epoch = editorEpoch
    SystemKeyboardBroker.prepareAndAuthorize(draft.toString()) { outcome ->
      if (!guardEpoch(epoch)) return@prepareAndAuthorize
      when (outcome) {
        is BrokerOutcome.Failure -> showFailure(outcome.status)
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
      showStatus(R.string.sk_error_unsupported_export)
      return
    }
    if (!SystemKeyboardBroker.isEditorUsableNow()) {
      showStatus(R.string.sk_status_unavailable)
      setReconnectVisible(true)
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
      clearDraft()
      // The host cannot prove which external conversation remains open.
      // Require a new explicit recipient selection for the next message.
      selectedContact = null
      updateInsertLabel()
      showStatus(R.string.sk_status_insert_uncertain)
    }
    if (!inserted) commitSelection.cancelPending()
    SystemKeyboardBroker.acknowledge(export.pendingId, inserted) { outcome ->
      if (!guardEpoch(epoch)) return@acknowledge
      when (outcome) {
        is BrokerOutcome.Failure -> showStatus(
          if (inserted) R.string.sk_status_insert_open_app else R.string.sk_error_unavailable,
        )
        is BrokerOutcome.Success -> showStatus(
          if (inserted && outcome.value) R.string.sk_status_insert_done
          else if (inserted) R.string.sk_status_insert_open_app
          else R.string.sk_error_unavailable,
        )
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
   * and only while the input view is actually visible. Only the explicit reconnect
   * button asks for a retry; a heartbeat never re-begins a revoked editor.
   */
  private fun beginEditorSession(explicitReconnect: Boolean) {
    if (!admitted) {
      setReconnectVisible(false)
      showStatus(R.string.sk_status_rejected_field)
      return
    }
    if (beginRequested && !explicitReconnect) return
    if (!SystemKeyboardBroker.isEnabled()) {
      // Without the explicit app opt-in the component stays unusable.
      showStatus(R.string.sk_status_unavailable)
      setReconnectVisible(true)
      return
    }
    if (explicitReconnect || !SystemKeyboardBroker.hasEditorGeneration()) {
      // A manual retry always starts a brand new generation.
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
          // No automatic fallback: `beginRequested` stays set until the user asks
          // for an explicit reconnect or a new editor starts.
          connected = false
          showFailure(outcome.status)
          setReconnectVisible(true)
        }
        is BrokerOutcome.Success -> {
          connected = true
          scramble = outcome.value
          rebuildRows()
          renderKeys()
          updateInsertLabel()
          setReconnectVisible(false)
          showStatus(R.string.sk_status_ready)
        }
      }
    }
  }

  private fun setReconnectVisible(visible: Boolean) {
    reconnectButton?.visibility = if (visible) View.VISIBLE else View.GONE
  }

  /**
   * Synchronous admission gate for every local operation: field admission, a
   * confirmed editor generation and a live, unexpired grant. The broker re-checks
   * the same deadline again immediately before any host insert.
   */
  private fun requireActiveEditor(): Boolean {
    if (!admitted || !connected || !SystemKeyboardBroker.isEditorUsableNow()) {
      showStatus(R.string.sk_status_unavailable)
      setReconnectVisible(admitted)
      return false
    }
    return true
  }

  private fun guardEpoch(epoch: Int): Boolean = epoch == editorEpoch

  /**
   * Best-effort local clear of every sensitive entry: draft, carrier buffer,
   * confirmed recipient, chooser list, preview labels and inline confirmation. String content is dropped, not zeroized.
   */
  private fun clearSensitiveUi() {
    clearDraft()
    carrierBuffer = null
    selectedContact = null
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
  }

  private fun showStatusText(text: CharSequence) {
    statusView?.text = text
  }

  /** Maps every internal failure to one short, identity-free user message. */
  private fun showFailure(status: String) {
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
private class ProtectedInputRoot(context: Context) : LinearLayout(context) {
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
      TouchDispatchAction.DISPATCH -> super.dispatchTouchEvent(event)
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
