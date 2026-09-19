package app.layergram

import android.app.KeyguardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.lang.ref.WeakReference
import java.security.SecureRandom

/** One contact as displayed by the chooser; never inferred from the host app. */
data class BrokerContact(val id: String, val name: String, val fingerprint: String)

/** Authenticated inbound preview. Ordinary messages only; never a recipient source. */
data class BrokerDecoded(
  val contactId: String,
  val contactName: String,
  val fingerprint: String,
  val text: String,
)

/** A prepared and explicitly authorized outbound carrier plus its one-shot pending id. */
data class PreparedExport(val pendingId: String, val carrier: String)

/**
 * Result of a broker round trip.
 *
 * [BrokerOutcome.Failure.status] is an internal, already-sanitized protocol code.
 * It must be mapped to one short generic user-visible string by the caller; the
 * raw code, the exception, and any identity metadata are never displayed.
 */
sealed class BrokerOutcome<out T> {
  data class Success<out T>(val value: T) : BrokerOutcome<T>()
  data class Failure(val status: String) : BrokerOutcome<Nothing>()
}

/**
 * Singleton bridge between the live Flutter engine (owned by [MainActivity]) and
 * the optional SYSTEM keyboard IME ([LayergramInputMethodService]).
 *
 * The service never creates an engine. It only ever speaks through the channel
 * that [MainActivity.configureFlutterEngine] attached to its own engine; when no
 * engine is attached every request fails generically (`unavailable`) without
 * starting the app, reading storage, keys or the network.
 *
 * Freshness model: every reply must carry strictly parsed `processingMillis`
 * (0..30000) and `leaseMillis` (1..1000). That pair produces one absolute grant
 * deadline (`requestStart + processing + lease`). A watchdog is scheduled at the
 * deadline itself, the deadline is re-checked synchronously before every local
 * operation, and any failure, malformed reply or unanswered heartbeat for the
 * current generation revokes it immediately. Nothing here renews the app lock
 * deadline or the app's own authorization state.
 *
 * The broker deliberately retains no message content: contacts and decoded
 * previews live only in the service view for the duration of one editor
 * generation, and pending export state is a single opaque id.
 */
object SystemKeyboardBroker {
  const val CHANNEL_NAME = "layergram/system_keyboard"

  private const val REQUEST_METHOD = "request"
  private const val PREFS_NAME = "layergram_prefs"
  private const val PREF_KEY_ENABLED = "system_keyboard_enabled"

  const val STATUS_OK = "ok"
  const val STATUS_UNAVAILABLE = "unavailable"
  const val STATUS_BUSY = "busy"
  const val STATUS_NO_MESSAGE = "noMessage"
  const val STATUS_INVALID_SELECTION = "invalidSelection"
  const val STATUS_OVERSIZE = "oversize"
  const val STATUS_UNSUPPORTED_EXPORT = "unsupportedExport"
  const val STATUS_INVALID_REQUEST = "invalidRequest"
  const val STATUS_NO_PENDING_EXPORT = "noPendingExport"

  private const val OPERATION_BEGIN = "begin"
  private const val OPERATION_HEARTBEAT = "heartbeat"
  private const val OPERATION_CONTACTS = "contacts"
  private const val OPERATION_SELECT = "select"
  private const val OPERATION_PREPARE = "prepare"
  private const val OPERATION_AUTHORIZE = "authorize"
  private const val OPERATION_ACK = "ack"
  private const val OPERATION_DECODE = "decode"
  private const val OPERATION_END = "end"

  /** UI-safe protocol codes that may travel back to the service for generic wording. */
  private val knownFailureStatuses = setOf(
    STATUS_UNAVAILABLE,
    STATUS_BUSY,
    STATUS_NO_MESSAGE,
    STATUS_INVALID_SELECTION,
    STATUS_OVERSIZE,
    STATUS_UNSUPPORTED_EXPORT,
    STATUS_INVALID_REQUEST,
    STATUS_NO_PENDING_EXPORT,
    "openAppRequired",
    "duplicateRequest",
    "backendError",
  )

  private val hexDigits = "0123456789abcdef".toCharArray()
  private val secureRandom = SecureRandom()
  private val mainHandler = Handler(Looper.getMainLooper())

  private val editorSession = KeyboardEditorSession()
  private val activeGrant = KeyboardActiveGrant()
  private val pendingRequests = LinkedHashMap<String, PendingCallback>()

  private var engineChannel: MethodChannel? = null
  private var engineOwner: WeakReference<FlutterEngine>? = null
  private var appContext: Context? = null

  private var enabled = false
  private var serviceVisible = false
  private var beginConfirmed = false
  private var serviceRef: WeakReference<LayergramInputMethodService>? = null

  private var requestCounter = 0L
  private var heartbeatInFlight = false
  private var heartbeatScheduled = false
  private var watchdogScheduledAt = 0L
  private var pendingExportId: String? = null

  // --- engine ownership ----------------------------------------------------

  /**
   * Attaches the already-running engine channel. [owner] is the exact ownership
   * token later used by `cleanUpFlutterEngine`.
   */
  fun bindEngine(channel: MethodChannel, owner: FlutterEngine, context: Context) {
    val app = context.applicationContext
    if (engineOwner?.get() !== owner) revokeCurrentEditor()
    engineChannel = channel
    engineOwner = WeakReference(owner)
    appContext = app
    enabled = app
      .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      .getBoolean(PREF_KEY_ENABLED, false)
  }

  /** Unbinds only when [owner] is still the exact bound engine. */
  fun unbindEngine(owner: FlutterEngine) {
    val bound = engineOwner?.get()
    if (bound == null || bound !== owner) return
    engineChannel = null
    engineOwner = null
    appContext = null
    enabled = false
    revokeCurrentEditor()
  }

  fun isEnabled(): Boolean = enabled

  fun hasEditorGeneration(): Boolean = editorSession.generation != null

  // --- Dart -> Native ------------------------------------------------------

  /**
   * Handles the app-driven methods. Called by [MainActivity] on the main
   * thread with the channel's incoming handler.
   */
  fun handleAppCall(call: MethodCall, result: MethodChannel.Result) {
    when (call.method) {
      "configure" -> {
        val requested = readEnabledArgument(call.arguments)
        if (requested == null) {
          result.error("invalid_arguments", "configure requires an enabled boolean.", null)
          return
        }
        result.success(configureInternal(requested))
      }
      "revoke" -> {
        revokeCurrentEditor()
        result.success(null)
      }
      "openSettings" -> result.success(openSettingsInternal())
      "isSupported" -> result.success(true)
      "readEnabled" -> result.success(readConfiguredState())
      else -> result.notImplemented()
    }
  }

  private fun readEnabledArgument(arguments: Any?): Boolean? = when (arguments) {
    is Boolean -> arguments
    is Map<*, *> -> arguments["enabled"] as? Boolean
    else -> null
  }

  /**
   * Clears any active service state first, persists the native opt-in flag, then
   * flips the permission-bound IME component with `DONT_KILL_APP`. The manifest
   * default stays disabled, so a build that never opts in cannot be enabled.
   */
  private fun readConfiguredState(): Boolean {
    val context = appContext ?: return false
    return try {
      enabled && context.packageManager.getComponentEnabledSetting(
        ComponentName(context, LayergramInputMethodService::class.java),
      ) == PackageManager.COMPONENT_ENABLED_STATE_ENABLED
    } catch (_: Throwable) {
      false
    }
  }

  private fun configureInternal(value: Boolean): Boolean {
    revokeCurrentEditor()
    val context = appContext ?: return false
    enabled = false
    return try {
      val persisted = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .edit().putBoolean(PREF_KEY_ENABLED, value).commit()
      val accepted = value && persisted
      context.packageManager.setComponentEnabledSetting(
        ComponentName(context, LayergramInputMethodService::class.java),
        if (accepted) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
        PackageManager.DONT_KILL_APP,
      )
      enabled = accepted
      persisted
    } catch (_: Throwable) {
      false
    }
  }

  private fun openSettingsInternal(): Boolean {
    val context = appContext ?: return false
    return try {
      context.startActivity(
        Intent(Settings.ACTION_INPUT_METHOD_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
      )
      true
    } catch (error: Throwable) {
      false
    }
  }

  // --- service attachment --------------------------------------------------

  fun attachService(service: LayergramInputMethodService) {
    serviceRef = WeakReference(service)
  }

  fun detachService() {
    serviceRef = null
    serviceVisible = false
    stopHeartbeatLoop()
    cancelGrantWatchdog()
  }

  /**
   * Visibility transitions also drive freshness. A hidden window always clears
   * every sensitive local entry and invalidates the generation; a visible window
   * only marks the service as shown (the service decides when to `begin`).
   */
  fun setServiceVisible(visible: Boolean) {
    serviceVisible = visible
    if (!visible && editorSession.generation != null) {
      revokeCurrentEditor()
    }
  }

  // --- editor lifecycle ----------------------------------------------------

  /**
   * Invalidates any previous generation (best-effort `end`), clears all local
   * state and — only when the app opted in — creates a fresh generation.
   *
   * The `begin` request is *not* sent here: the service sends it once the input
   * view is actually visible, so a hidden window can never be mistaken for an
   * admitted editor.
   */
  fun bindEditor() {
    resetEditorInternal(sendEnd = true)
    if (!enabled) return
    editorSession.begin(newNonce())
  }

  /** Lifecycle reset: cancels pending host commits and invalidates every callback. */
  fun resetEditor() {
    resetEditorInternal(sendEnd = true)
  }

  /** Synchronous clear of every sensitive bookkeeping entry, without a round trip. */
  fun clearSensitiveState() {
    clearLocalState()
  }

  /**
   * Called from `onUpdateSelection`. Any selection movement that our own commit
   * did not cause clears the pending export and any in-flight commit callback.
   */
  fun onHostSelectionChanged() {
    resetEditorInternal(sendEnd = true)
  }

  /**
   * Synchronous freshness check used immediately before any local draft,
   * clipboard, contact or commit operation. A lapsed grant, a locked keyguard, a
   * hidden window or a lost generation revokes the editor and returns false.
   */
  fun isEditorUsableNow(): Boolean {
    if (!enabled || !beginConfirmed || editorSession.generation == null) return false
    val now = SystemClock.elapsedRealtime()
    if (isKeyguardLocked() || !serviceVisible || !activeGrant.isActive(now)) {
      revokeCurrentEditor()
      return false
    }
    return true
  }

  /**
   * Sends `begin` for the current generation. Only called while the window is
   * visible, at most once per editor generation.
   */
  fun requestBegin(callback: (BrokerOutcome<Boolean>) -> Unit) {
    val generation = editorSession.generation
    if (!enabled || generation == null) {
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return
    }
    if (!serviceVisible || isKeyguardLocked()) {
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return
    }
    beginConfirmed = false
    activeGrant.bootstrap(SystemClock.elapsedRealtime())
    scheduleGrantWatchdog()
    sendRequest(OPERATION_BEGIN, emptyMap(), ::parseScramble) { outcome ->
      when (outcome) {
        is BrokerOutcome.Success -> {
          beginConfirmed = true
          startHeartbeatLoop()
        }
        is BrokerOutcome.Failure -> revokeCurrentEditor()
      }
      callback(outcome)
    }
  }

  private fun resetEditorInternal(sendEnd: Boolean) {
    val previous = editorSession.generation
    clearLocalState()
    if (sendEnd && previous != null) {
      sendEndOperation(previous)
    }
    editorSession.reset()
  }

  private fun clearLocalState() {
    pendingRequests.clear()
    pendingExportId = null
    beginConfirmed = false
    heartbeatInFlight = false
    activeGrant.clear()
    cancelGrantWatchdog()
    stopHeartbeatLoop()
  }

  /** Clears every sensitive entry and permanently invalidates the generation. */
  private fun revokeCurrentEditor() {
    resetEditorInternal(sendEnd = true)
    serviceRef?.get()?.onBrokerUnavailable()
  }

  // --- operations ----------------------------------------------------------

  fun loadContacts(callback: (BrokerOutcome<List<BrokerContact>>) -> Unit) {
    sendRequest(OPERATION_CONTACTS, emptyMap(), ::parseContacts, callback)
  }

  fun selectContact(contactId: String, callback: (BrokerOutcome<BrokerContact>) -> Unit) {
    if (!KeyboardEditorPolicy.isWellFormedIdentifier(contactId)) {
      callback(BrokerOutcome.Failure(STATUS_INVALID_SELECTION))
      return
    }
    sendRequest(
      OPERATION_SELECT,
      mapOf("contactId" to contactId, "confirm" to true),
      ::parseSelectedContact,
      callback,
    )
  }

  /**
   * Two-step compose path: `prepare` hands the plaintext draft to the app core
   * and returns an opaque pending id; `authorize` returns the already-encrypted
   * carrier. The carrier is bounded again here and again immediately before the
   * host insert; nothing is ever committed without that carrier.
   */
  fun prepareAndAuthorize(text: String, callback: (BrokerOutcome<PreparedExport>) -> Unit) {
    if (!KeyboardEditorPolicy.admitsComposeLength(text.length)) {
      val status = if (text.isEmpty()) STATUS_INVALID_REQUEST else STATUS_OVERSIZE
      callback(BrokerOutcome.Failure(status))
      return
    }
    sendRequest(OPERATION_PREPARE, mapOf("text" to text), ::parsePendingId) { prepareOutcome ->
      when (prepareOutcome) {
        is BrokerOutcome.Failure -> callback(prepareOutcome)
        is BrokerOutcome.Success -> {
          val pendingId = prepareOutcome.value
          pendingExportId = pendingId
          sendRequest(
            OPERATION_AUTHORIZE,
            mapOf("pendingId" to pendingId),
            ::parseOutboundCarrier,
          ) { authorizeOutcome ->
            when (authorizeOutcome) {
              is BrokerOutcome.Failure -> {
                pendingExportId = null
                callback(authorizeOutcome)
              }
              is BrokerOutcome.Success -> {
                val carrier = authorizeOutcome.value
                if (!KeyboardEditorPolicy.admitsOutboundCarrierLength(carrier.length)) {
                  pendingExportId = null
                  callback(BrokerOutcome.Failure(STATUS_UNSUPPORTED_EXPORT))
                } else {
                  callback(BrokerOutcome.Success(PreparedExport(pendingId, carrier)))
                }
              }
            }
          }
        }
      }
    }
  }

  /**
   * Reports the *actual* `InputConnection.commitText` result. The ack is the only
   * place where export success is declared; native never assumes insertion.
   */
  fun acknowledge(
    pendingId: String,
    commitText: Boolean,
    callback: (BrokerOutcome<Boolean>) -> Unit,
  ) {
    if (pendingId.isEmpty() || pendingExportId != pendingId) {
      callback(BrokerOutcome.Failure(STATUS_NO_PENDING_EXPORT))
      return
    }
    pendingExportId = null
    sendRequest(
      OPERATION_ACK,
      mapOf("pendingId" to pendingId, "commitText" to commitText),
      ::parseExported,
      callback,
    )
  }

  fun decode(carrier: String, callback: (BrokerOutcome<BrokerDecoded>) -> Unit) {
    if (carrier.isEmpty()) {
      callback(BrokerOutcome.Failure(STATUS_NO_MESSAGE))
      return
    }
    if (!KeyboardEditorPolicy.admitsCarrierLength(carrier.length)) {
      callback(BrokerOutcome.Failure(STATUS_OVERSIZE))
      return
    }
    sendRequest(OPERATION_DECODE, mapOf("carrier" to carrier), ::parseDecoded, callback)
  }

  // --- request plumbing ----------------------------------------------------

  private fun <T> sendRequest(
    operation: String,
    extra: Map<String, Any>,
    parse: (Map<*, *>?) -> T?,
    callback: (BrokerOutcome<T>) -> Unit,
  ): PendingCallback? {
    if (operation != OPERATION_BEGIN && !isEditorUsableNow()) {
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return null
    }
    val generation = editorSession.generation
    if (!enabled || generation == null) {
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return null
    }
    if (isKeyguardLocked() || !serviceVisible) {
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return null
    }
    val channel = engineChannel
    if (channel == null) {
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return null
    }
    if (pendingRequests.size >= KeyboardEditorPolicy.MAX_PENDING_REQUESTS) {
      callback(BrokerOutcome.Failure(STATUS_BUSY))
      return null
    }

    val requestId = "skq" + (requestCounter++)
    val pending = PendingCallback(
      requestId = requestId,
      generation = generation,
      requestStartElapsedRealtime = SystemClock.elapsedRealtime(),
    )
    pendingRequests[requestId] = pending

    val arguments = HashMap<String, Any>()
    arguments["operation"] = operation
    arguments["editorNonce"] = generation.nonce
    arguments["requestId"] = requestId
    arguments.putAll(extra)

    val resultHandler = object : MethodChannel.Result {
      override fun success(result: Any?) {
        onReply(requestId, result, parse, callback)
      }

      override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) {
        if (pendingRequests.remove(requestId) != null) {
          revokeCurrentEditor()
          callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
        }
      }

      override fun notImplemented() {
        if (pendingRequests.remove(requestId) != null) {
          revokeCurrentEditor()
          callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
        }
      }
    }

    try {
      channel.invokeMethod(REQUEST_METHOD, arguments, resultHandler)
    } catch (error: Throwable) {
      if (pendingRequests.remove(requestId) != null) {
        revokeCurrentEditor()
        callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      }
      return null
    }
    return pending
  }

  private fun <T> onReply(
    requestId: String,
    rawReply: Any?,
    parse: (Map<*, *>?) -> T?,
    callback: (BrokerOutcome<T>) -> Unit,
  ) {
    // A missing entry means the frame was already cancelled by a lifecycle reset,
    // a revoke, a stale selection update or a newer editor generation.
    val pending = pendingRequests.remove(requestId) ?: return
    val current = editorSession.generation
    val now = SystemClock.elapsedRealtime()
    if (current == null || pending.generation != current) {
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return
    }
    if (isKeyguardLocked() || !serviceVisible || !activeGrant.isActive(now)) {
      revokeCurrentEditor()
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return
    }

    val map = rawReply as? Map<*, *>
    if (map == null) {
      revokeCurrentEditor()
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return
    }
    val status = map["status"] as? String
    if (status != STATUS_OK) {
      val safeStatus = sanitizeStatus(status ?: STATUS_UNAVAILABLE)
      if (safeStatus == STATUS_UNAVAILABLE) {
        revokeCurrentEditor()
      }
      callback(BrokerOutcome.Failure(safeStatus))
      return
    }

    val grant = KeyboardEditorPolicy.strictGrant(
      processingMillisRaw = map["processingMillis"],
      leaseMillisRaw = map["leaseMillis"],
      heartbeat = false,
    )
    if (grant == null) {
      revokeCurrentEditor()
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return
    }
    if (!KeyboardCallbackPolicy.admits(pending, current, now, false, false, grant)) {
      // Expired or otherwise stale: the reply is suppressed and never revives
      // an expired generation, even if the watchdog has not run yet.
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return
    }

    val value = try {
      parse(map["data"] as? Map<*, *>)
    } catch (error: Throwable) {
      null
    }
    if (value == null) {
      revokeCurrentEditor()
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return
    }

    if (!activeGrant.tryRenew(pending.requestStartElapsedRealtime, grant, now)) {
      revokeCurrentEditor()
      callback(BrokerOutcome.Failure(STATUS_UNAVAILABLE))
      return
    }
    scheduleGrantWatchdog()
    callback(BrokerOutcome.Success(value))
  }

  private fun sanitizeStatus(status: String): String =
    if (status in knownFailureStatuses) status else STATUS_UNAVAILABLE

  private fun sendEndOperation(generation: EditorGeneration) {
    val channel = engineChannel ?: return
    val arguments = HashMap<String, Any>()
    arguments["operation"] = OPERATION_END
    arguments["editorNonce"] = generation.nonce
    arguments["requestId"] = "ske" + (requestCounter++)
    try {
      channel.invokeMethod(REQUEST_METHOD, arguments)
    } catch (error: Throwable) {
      // Best effort: `end` carries no content and its failure needs no UI.
    }
  }

  // --- grant watchdog, heartbeat and revocation ---------------------------

  /**
   * Scheduled at the *absolute* grant deadline. Revoking here is the last line of
   * defence; every local operation also checks the deadline synchronously so a
   * late watchdog run can never expose a lapsed grant.
   */
  private val grantWatchdogRunnable = object : Runnable {
    override fun run() {
      watchdogScheduledAt = 0L
      if (editorSession.generation == null) return
      val now = SystemClock.elapsedRealtime()
      if (!enabled || isKeyguardLocked() || !serviceVisible || !activeGrant.isActive(now)) {
        revokeCurrentEditor()
        return
      }
      scheduleGrantWatchdog()
    }
  }

  private fun scheduleGrantWatchdog() {
    val deadline = activeGrant.deadline ?: return
    if (watchdogScheduledAt == deadline) return
    mainHandler.removeCallbacks(grantWatchdogRunnable)
    watchdogScheduledAt = deadline
    val delay = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
    mainHandler.postDelayed(grantWatchdogRunnable, delay)
  }

  private fun cancelGrantWatchdog() {
    watchdogScheduledAt = 0L
    mainHandler.removeCallbacks(grantWatchdogRunnable)
  }

  private fun startHeartbeatLoop() {
    if (heartbeatScheduled) return
    heartbeatScheduled = true
    mainHandler.postDelayed(heartbeatRunnable, KeyboardEditorPolicy.HEARTBEAT_INTERVAL_MILLIS)
  }

  private fun stopHeartbeatLoop() {
    heartbeatScheduled = false
    heartbeatInFlight = false
    mainHandler.removeCallbacks(heartbeatRunnable)
  }

  private val heartbeatRunnable = object : Runnable {
    override fun run() {
      heartbeatScheduled = false
      if (!enabled || !beginConfirmed || editorSession.generation == null) {
        stopHeartbeatLoop()
        return
      }
      val now = SystemClock.elapsedRealtime()
      if (isKeyguardLocked() || !serviceVisible) {
        revokeCurrentEditor()
        return
      }
      if (!activeGrant.isActive(now)) {
        // The granted window lapsed before the watchdog ran: clear immediately.
        revokeCurrentEditor()
        return
      }
      if (!heartbeatInFlight) sendHeartbeat()
      startHeartbeatLoop()
    }
  }

  private fun sendHeartbeat() {
    val generation = editorSession.generation ?: return
    if (!enabled || !beginConfirmed || !serviceVisible || isKeyguardLocked()) return
    val channel = engineChannel ?: return
    val requestId = "skh" + (requestCounter++)
    val pending = PendingCallback(
      requestId = requestId,
      generation = generation,
      requestStartElapsedRealtime = SystemClock.elapsedRealtime(),
    )
    heartbeatInFlight = true
    val arguments = HashMap<String, Any>()
    arguments["operation"] = OPERATION_HEARTBEAT
    arguments["editorNonce"] = generation.nonce
    arguments["requestId"] = requestId
    val resultHandler = object : MethodChannel.Result {
      override fun success(result: Any?) {
        if (editorSession.isCurrent(pending.generation)) heartbeatInFlight = false
        onHeartbeatReply(pending, result)
      }

      override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) {
        if (editorSession.isCurrent(pending.generation)) heartbeatInFlight = false
        revokeIfCurrentGeneration(pending.generation)
      }

      override fun notImplemented() {
        if (editorSession.isCurrent(pending.generation)) heartbeatInFlight = false
        revokeIfCurrentGeneration(pending.generation)
      }
    }
    try {
      channel.invokeMethod(REQUEST_METHOD, arguments, resultHandler)
    } catch (error: Throwable) {
      heartbeatInFlight = false
      revokeIfCurrentGeneration(pending.generation)
    }
  }

  /**
   * A heartbeat may advance the active grant only to its own strictly parsed
   * `requestStart + leaseMillis`; `processingMillis` must be exactly 0. Every
   * failure, denial or malformed/unavailable heartbeat for the current
   * generation revokes it immediately. A heartbeat for an older generation is
   * ignored so it cannot touch a newer editor.
   */
  private fun onHeartbeatReply(pending: PendingCallback, rawReply: Any?) {
    val current = editorSession.generation
    if (current == null || pending.generation != current) return
    val now = SystemClock.elapsedRealtime()
    if (isKeyguardLocked() || !serviceVisible || !activeGrant.isActive(now)) {
      revokeCurrentEditor()
      return
    }
    val map = rawReply as? Map<*, *>
    if (map == null || map["status"] != STATUS_OK) {
      revokeCurrentEditor()
      return
    }
    val grant = KeyboardEditorPolicy.strictGrant(
      processingMillisRaw = map["processingMillis"],
      leaseMillisRaw = map["leaseMillis"],
      heartbeat = true,
    )
    if (grant == null) {
      revokeCurrentEditor()
      return
    }
    if (!KeyboardCallbackPolicy.admits(pending, current, now, false, false, grant)) {
      revokeCurrentEditor()
      return
    }
    if (!activeGrant.tryRenew(pending.requestStartElapsedRealtime, grant, now)) {
      revokeCurrentEditor()
      return
    }
    scheduleGrantWatchdog()
  }

  private fun revokeIfCurrentGeneration(generation: EditorGeneration) {
    val current = editorSession.generation ?: return
    if (current != generation) return
    revokeCurrentEditor()
  }

  // --- environment helpers -------------------------------------------------

  private fun isKeyguardLocked(): Boolean {
    val context = appContext ?: return true
    val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager ?: return true
    return keyguard.isKeyguardLocked
  }

  private fun newNonce(): String {
    val bytes = ByteArray(16)
    secureRandom.nextBytes(bytes)
    val builder = StringBuilder(2 + bytes.size * 2)
    builder.append("sk")
    for (current in bytes) {
      val value = current.toInt() and 0xFF
      builder.append(hexDigits[value ushr 4]).append(hexDigits[value and 0x0F])
    }
    return builder.toString()
  }

  // --- reply parsers (fail closed on any malformed payload) ----------------

  private fun parseScramble(data: Map<*, *>?): Boolean? {
    if (data == null) return false
    return when (val raw = data["scramble"]) {
      null -> false
      is Boolean -> raw
      else -> null
    }
  }

  private fun parseContacts(data: Map<*, *>?): List<BrokerContact>? {
    val raw = data?.get("contacts") as? List<*> ?: return null
    val contacts = ArrayList<BrokerContact>(raw.size)
    for (entry in raw) {
      val map = entry as? Map<*, *> ?: return null
      val contact = parseContactMap(map) ?: return null
      contacts.add(contact)
    }
    return contacts
  }

  private fun parseSelectedContact(data: Map<*, *>?): BrokerContact? =
    data?.let { parseContactMap(it) }

  private fun parseContactMap(map: Map<*, *>): BrokerContact? {
    val id = map["id"] as? String ?: return null
    val name = map["name"] as? String ?: return null
    val fingerprint = map["fingerprint"] as? String ?: return null
    if (!KeyboardEditorPolicy.isWellFormedIdentifier(id)) return null
    if (name.isEmpty() || fingerprint.isEmpty()) return null
    return BrokerContact(id, name, fingerprint)
  }

  private fun parsePendingId(data: Map<*, *>?): String? =
    (data?.get("pendingId") as? String)
      ?.takeIf { KeyboardEditorPolicy.isWellFormedIdentifier(it) }

  /** Outbound carriers are capped at the compose ceiling, never the inbound one. */
  private fun parseOutboundCarrier(data: Map<*, *>?): String? =
    (data?.get("carrier") as? String)
      ?.takeIf { KeyboardEditorPolicy.admitsOutboundCarrierLength(it.length) }

  private fun parseExported(data: Map<*, *>?): Boolean? =
    data?.get("exported") as? Boolean

  private fun parseDecoded(data: Map<*, *>?): BrokerDecoded? {
    val contactId = data?.get("contactId") as? String ?: return null
    val contactName = data?.get("contactName") as? String ?: return null
    val fingerprint = data?.get("fingerprint") as? String ?: return null
    val text = data?.get("text") as? String ?: return null
    if (contactId.isNotEmpty() && !KeyboardEditorPolicy.isWellFormedIdentifier(contactId)) return null
    if (text.length > KeyboardEditorPolicy.MAX_CARRIER_CODE_UNITS) return null
    return BrokerDecoded(contactId, contactName, fingerprint, text)
  }
}
