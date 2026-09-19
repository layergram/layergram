package app.layergram

/**
 * Pure, framework-free policy and bookkeeping for the optional SYSTEM keyboard.
 *
 * Nothing in this file imports `android.*` on purpose: every admission, grant and
 * lease decision is deterministic arithmetic plus immutable snapshots, so it can
 * be exercised by ordinary JVM unit tests without Robolectric or an emulator.
 *
 * Security posture:
 * * Every broker callback is bound to the editor generation that was current
 *   when the request started. A new `onStartInput`, a lifecycle reset, a hidden
 *   window, a locked keyguard, an expired grant or a malformed reply makes that
 *   generation unusable and the reply is rejected instead of applied.
 * * Reply bounds are parsed *strictly*: a missing, non-integer, negative or
 *   out-of-range `processingMillis`/`leaseMillis` is denied. There is no default
 *   and no clamping fallback, so a backend cannot grant itself a longer window.
 * * This file never stores or formats message content, identifiers or failures.
 */
object KeyboardEditorPolicy {
  /** Native plaintext draft ceiling handed to `prepare`. */
  const val MAX_COMPOSE_CODE_UNITS = 4000

  /** Outbound ciphertext ceiling: the native layer never trusts a larger carrier. */
  const val MAX_OUTBOUND_CARRIER_CODE_UNITS = 4000

  /** Inbound encoded carrier ceiling (matches the app core). */
  const val MAX_CARRIER_CODE_UNITS = 262144

  /** Bound for every opaque identifier crossing the channel (nonce, requestId, pendingId). */
  const val MAX_IDENTIFIER_CHARS = 128

  /** Strict reply bounds. Both fields are required and must be exact integers. */
  const val MIN_REPLY_PROCESSING_MILLIS = 0
  const val MAX_REPLY_PROCESSING_MILLIS = 30000
  const val MIN_REPLY_LEASE_MILLIS = 1
  const val MAX_REPLY_LEASE_MILLIS = 1000

  /** A `begin` with no valid reply may keep the local surface for at most this long. */
  const val BOOTSTRAP_GRANT_MILLIS = 1000

  /** Heartbeats are cheap: processingMillis must be 0 and the lease stays short. */
  const val HEARTBEAT_INTERVAL_MILLIS = 250L
  const val HEARTBEAT_PROCESSING_MILLIS = 0
  const val HEARTBEAT_LEASE_MILLIS = 250

  /** Upper bound on concurrent non-heartbeat requests; extra calls fail closed. */
  const val MAX_PENDING_REQUESTS = 16

  // `android.text.InputType` values, verified against the real android.jar
  // constants: TYPE_CLASS_TEXT=0x1, TYPE_MASK_CLASS=0xf, TYPE_MASK_VARIATION=0xff0,
  // TYPE_TEXT_VARIATION_URI=0x10, _PASSWORD=0x80, _VISIBLE_PASSWORD=0x90,
  // _WEB_PASSWORD=0xe0. Keep in sync with the framework values used by the IME.
  const val INPUT_TYPE_MASK_CLASS = 0x0000000f
  const val INPUT_TYPE_MASK_VARIATION = 0x00000ff0
  const val INPUT_TYPE_CLASS_TEXT = 0x00000001
  const val INPUT_TYPE_TEXT_VARIATION_URI = 0x00000010
  const val INPUT_TYPE_TEXT_VARIATION_PASSWORD = 0x00000080
  const val INPUT_TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090
  const val INPUT_TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x000000e0

  /**
   * Admits only ordinary text editors. Numbers, phone/date classes, and every
   * password variation (including password with extra flags) are refused before
   * any broker call is made; ordinary and URI text variations stay allowed.
   */
  fun admitsEditor(inputType: Int): Boolean {
    if (inputType and INPUT_TYPE_MASK_CLASS != INPUT_TYPE_CLASS_TEXT) return false
    val variation = inputType and INPUT_TYPE_MASK_VARIATION
    return variation != INPUT_TYPE_TEXT_VARIATION_PASSWORD &&
      variation != INPUT_TYPE_TEXT_VARIATION_VISIBLE_PASSWORD &&
      variation != INPUT_TYPE_TEXT_VARIATION_WEB_PASSWORD
  }

  /**
   * Strict integer decode of a reply field. Accepts only integral values that
   * fit an `Int`; never a string, a fractional number or an out-of-range long.
   */
  fun replyInt(value: Any?): Int? = when (value) {
    is Int -> value
    is Long ->
      if (value >= Int.MIN_VALUE.toLong() && value <= Int.MAX_VALUE.toLong()) {
        value.toInt()
      } else {
        null
      }
    is Short -> value.toInt()
    is Byte -> value.toInt()
    is Double ->
      if (value.isFinite() && value == Math.floor(value) &&
        value >= Int.MIN_VALUE.toDouble() && value <= Int.MAX_VALUE.toDouble()
      ) {
        value.toInt()
      } else {
        null
      }
    is Float ->
      if (value.isFinite() && value.toDouble() == Math.floor(value.toDouble()) &&
        value >= Int.MIN_VALUE.toDouble() && value <= Int.MAX_VALUE.toDouble()
      ) {
        value.toInt()
      } else {
        null
      }
    else -> null
  }

  /**
   * Strictly parses an absolute grant from a reply.
   *
   * Returns `null` — which the caller must treat as a denial — for a missing,
   * non-integer, negative or oversized value. There is deliberately no default
   * and no clamping: a malformed lease never becomes a usable grant.
   */
  fun strictGrant(
    processingMillisRaw: Any?,
    leaseMillisRaw: Any?,
    heartbeat: Boolean,
  ): AbsoluteGrant? {
    val processing = replyInt(processingMillisRaw) ?: return null
    val lease = replyInt(leaseMillisRaw) ?: return null
    if (processing < MIN_REPLY_PROCESSING_MILLIS || processing > MAX_REPLY_PROCESSING_MILLIS) {
      return null
    }
    if (lease < MIN_REPLY_LEASE_MILLIS || lease > MAX_REPLY_LEASE_MILLIS) return null
    if (heartbeat && processing != HEARTBEAT_PROCESSING_MILLIS) return null
    return AbsoluteGrant(processing, lease)
  }

  /** Absolute local deadline: request start + measured processing + granted lease. */
  fun deadline(requestStartElapsedRealtime: Long, grant: AbsoluteGrant): Long =
    requestStartElapsedRealtime +
      grant.processingMillis.toLong() +
      grant.leaseMillis.toLong()

  fun isWellFormedIdentifier(value: String?): Boolean =
    value != null && value.isNotEmpty() && value.length <= MAX_IDENTIFIER_CHARS

  fun admitsComposeLength(codeUnits: Int): Boolean =
    codeUnits in 1..MAX_COMPOSE_CODE_UNITS

  fun admitsOutboundCarrierLength(codeUnits: Int): Boolean =
    codeUnits in 1..MAX_OUTBOUND_CARRIER_CODE_UNITS

  fun admitsCarrierLength(codeUnits: Int): Boolean =
    codeUnits in 1..MAX_CARRIER_CODE_UNITS

  /** Result of an explicit draft append under the compose ceiling. */
  fun admitsDraftAppend(currentCodeUnits: Int, appendCodeUnits: Int): Boolean =
    currentCodeUnits >= 0 &&
      appendCodeUnits >= 0 &&
      currentCodeUnits + appendCodeUnits <= MAX_COMPOSE_CODE_UNITS

  /**
   * A host insert only counts as exported when `InputConnection.commitText`
   * actually returned `true`. `false` or a missing result is never exported.
   */
  fun classifyInsert(commitResult: Boolean?): InsertOutcome =
    if (commitResult == true) InsertOutcome.INSERTED else InsertOutcome.NOT_INSERTED
}

enum class InsertOutcome {
  INSERTED,
  NOT_INSERTED,
}

/** A strictly validated lease granted by one reply. */
data class AbsoluteGrant(val processingMillis: Int, val leaseMillis: Int)

/** Identity of exactly one editor generation. Never reused after a reset. */
data class EditorGeneration(val nonce: String, val epoch: Long)

/**
 * Owns the current editor generation and guarantees monotonic epochs: a frame
 * captured before [reset] can never compare equal to a later generation.
 */
class KeyboardEditorSession {
  private var current: EditorGeneration? = null
  private var epochCounter = 0L

  val generation: EditorGeneration?
    get() = current

  fun begin(nonce: String): EditorGeneration {
    epochCounter += 1
    return EditorGeneration(nonce, epochCounter).also { current = it }
  }

  fun reset() {
    current = null
    epochCounter += 1
  }

  fun isCurrent(candidate: EditorGeneration?): Boolean =
    candidate != null && candidate == current
}

/**
 * Local view of how long the app core has granted the native surface.
 *
 * The deadline is absolute (`elapsedRealtime`), so it keeps counting down even if
 * the watchdog runnable never executes; callers must therefore check [isActive]
 * synchronously before touching any sensitive local state.
 */
class KeyboardActiveGrant {
  private var deadlineElapsedRealtime = 0L
  private var established = false

  val deadline: Long?
    get() = if (established) deadlineElapsedRealtime else null

  val isEstablished: Boolean
    get() = established

  /** Conservative pre-`begin` window: no data may arrive, so it is short. */
  fun bootstrap(requestStartElapsedRealtime: Long): Long {
    deadlineElapsedRealtime =
      requestStartElapsedRealtime + KeyboardEditorPolicy.BOOTSTRAP_GRANT_MILLIS
    established = true
    return deadlineElapsedRealtime
  }

  fun apply(requestStartElapsedRealtime: Long, grant: AbsoluteGrant): Long {
    deadlineElapsedRealtime = KeyboardEditorPolicy.deadline(requestStartElapsedRealtime, grant)
    established = true
    return deadlineElapsedRealtime
  }

  /** A reply cannot revive an expired grant even when the timer is delayed. */
  fun tryRenew(start: Long, grant: AbsoluteGrant, now: Long): Boolean {
    if (!isActive(now) || now >= KeyboardEditorPolicy.deadline(start, grant)) {
      clear()
      return false
    }
    apply(start, grant)
    return true
  }

  fun clear() {
    established = false
    deadlineElapsedRealtime = 0L
  }

  fun isActive(nowElapsedRealtime: Long): Boolean =
    established && nowElapsedRealtime < deadlineElapsedRealtime
}

/**
 * One request that is still allowed to produce a callback.
 *
 * [requestStartElapsedRealtime] is captured when the request is dispatched; the
 * grant deadline is always computed from that instant, so dispatch latency is
 * accounted for conservatively.
 */
data class PendingCallback(
  val requestId: String,
  val generation: EditorGeneration,
  val requestStartElapsedRealtime: Long,
  val processingMillis: Int = KeyboardEditorPolicy.HEARTBEAT_PROCESSING_MILLIS,
  val leaseMillis: Int = KeyboardEditorPolicy.HEARTBEAT_LEASE_MILLIS,
) {
  fun deadline(grant: AbsoluteGrant): Long =
    KeyboardEditorPolicy.deadline(requestStartElapsedRealtime, grant)
}

object KeyboardCallbackPolicy {
  /**
   * A callback is admitted only when the editor generation still matches, the
   * keyguard is off, the input view is visible, a strictly parsed grant exists,
   * and the reply arrived before that grant's absolute deadline.
   */
  fun admits(
    request: PendingCallback?,
    current: EditorGeneration?,
    nowElapsedRealtime: Long,
    keyguardEngaged: Boolean,
    serviceHidden: Boolean,
    grant: AbsoluteGrant?,
  ): Boolean {
    if (request == null || current == null || grant == null) return false
    if (request.generation != current) return false
    if (keyguardEngaged || serviceHidden) return false
    return nowElapsedRealtime < request.deadline(grant)
  }
}

/** Tracks cursor positions supplied by editor callbacks, without reading host text. */
class KeyboardCommitSelection {
  private var start = -1
  private var end = -1
  private var expected: Int? = null

  fun update(newStart: Int, newEnd: Int): Boolean {
    val own = expected != null && newStart == expected && newEnd == expected
    expected = null
    start = newStart
    end = newEnd
    return own
  }

  fun expectInsertion(length: Int) {
    expected = if (start >= 0 && end >= 0 && length > 0) {
      val position = minOf(start, end).toLong() + length
      if (position <= Int.MAX_VALUE) position.toInt() else null
    } else null
  }

  fun cancelPending() { expected = null }
}
