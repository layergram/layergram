package app.layergram

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure JVM tests for the SYSTEM keyboard admission, grant and lease policy.
 *
 * The InputType cases use the *raw* framework values published by `android.jar`
 * (verified with `javap -constants android.text.InputType`), not the mirrored
 * policy constants, so the mirror itself is under test. The grant cases cover a
 * 20 ms lease, strict reply bounds, ignored `processingMillis` on heartbeats,
 * stale heartbeats after a reset, lapse before any timer runs, and a long
 * operation staying valid while independent heartbeats remain fresh.
 */
class KeyboardEditorLeaseTest {
  private val start = 10_000L
  private val generation = EditorGeneration("nonce-a", 1L)

  private fun request(
    generation: EditorGeneration = this.generation,
    requestStart: Long = start,
  ) = PendingCallback(
    requestId = "skq1",
    generation = generation,
    requestStartElapsedRealtime = requestStart,
  )

  private fun admits(
    pending: PendingCallback?,
    current: EditorGeneration?,
    now: Long,
    grant: AbsoluteGrant?,
    keyguardEngaged: Boolean = false,
    serviceHidden: Boolean = false,
  ): Boolean = KeyboardCallbackPolicy.admits(
    request = pending,
    current = current,
    nowElapsedRealtime = now,
    keyguardEngaged = keyguardEngaged,
    serviceHidden = serviceHidden,
    grant = grant,
  )

  // --- editor type admission against raw Android SDK values ----------------

  @Test
  fun mirroredPasswordVariationsEqualTheAndroidSdkValues() {
    // android.text.InputType: PASSWORD=0x80, VISIBLE_PASSWORD=0x90,
    // WEB_PASSWORD=0xe0, URI=0x10 (javap -constants android.jar).
    assertEquals(0x00000001, KeyboardEditorPolicy.INPUT_TYPE_CLASS_TEXT)
    assertEquals(0x00000080, KeyboardEditorPolicy.INPUT_TYPE_TEXT_VARIATION_PASSWORD)
    assertEquals(0x00000090, KeyboardEditorPolicy.INPUT_TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
    assertEquals(0x000000e0, KeyboardEditorPolicy.INPUT_TYPE_TEXT_VARIATION_WEB_PASSWORD)
    assertEquals(0x00000010, KeyboardEditorPolicy.INPUT_TYPE_TEXT_VARIATION_URI)
  }

  @Test
  fun ordinaryAndUriTextEditorsAreAdmitted() {
    assertTrue(KeyboardEditorPolicy.admitsEditor(0x00000001)) // TYPE_CLASS_TEXT
    assertTrue(KeyboardEditorPolicy.admitsEditor(0x00000011)) // text | URI
    assertTrue(KeyboardEditorPolicy.admitsEditor(0x00000021)) // text | email
    assertTrue(KeyboardEditorPolicy.admitsEditor(0x00020001)) // text | multi-line flag
    assertTrue(KeyboardEditorPolicy.admitsEditor(0x000a0001)) // text | flags only
  }

  @Test
  fun passwordVariationsIncludingFlaggedOnesAreRejected() {
    assertFalse(KeyboardEditorPolicy.admitsEditor(0x00000081)) // text | password
    assertFalse(KeyboardEditorPolicy.admitsEditor(0x00000091)) // visible password
    assertFalse(KeyboardEditorPolicy.admitsEditor(0x000000e1)) // web password
    assertFalse(KeyboardEditorPolicy.admitsEditor(0x00008081)) // password + no-suggestions
    assertFalse(KeyboardEditorPolicy.admitsEditor(0x00010081)) // password + auto-correct flag
  }

  @Test
  fun nonTextEditorClassesAreRejected() {
    assertFalse(KeyboardEditorPolicy.admitsEditor(0x00000000)) // TYPE_NULL
    assertFalse(KeyboardEditorPolicy.admitsEditor(0x00000002)) // TYPE_CLASS_NUMBER
    assertFalse(KeyboardEditorPolicy.admitsEditor(0x00000003)) // TYPE_CLASS_PHONE
    assertFalse(KeyboardEditorPolicy.admitsEditor(0x00000004)) // TYPE_CLASS_DATETIME
  }

  // --- strict reply grant parsing ------------------------------------------

  @Test
  fun strictGrantAcceptsExactlyTheDocumentedBounds() {
    assertEquals(AbsoluteGrant(0, 1), KeyboardEditorPolicy.strictGrant(0, 1, heartbeat = false))
    assertEquals(
      AbsoluteGrant(30000, 1000),
      KeyboardEditorPolicy.strictGrant(30000, 1000, heartbeat = false),
    )
    assertEquals(AbsoluteGrant(0, 250), KeyboardEditorPolicy.strictGrant(0L, 250L, heartbeat = false))
    assertEquals(AbsoluteGrant(0, 250), KeyboardEditorPolicy.strictGrant(0.0, 250.0, heartbeat = false))
  }

  @Test
  fun missingZeroNegativeOrOversizedLeaseIsDeniedNotClampedOrDefaulted() {
    assertNull(KeyboardEditorPolicy.strictGrant(0, null, heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(null, 250, heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(0, 0, heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(0, -1, heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(0, -1000, heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(0, 1001, heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(0, 1.5, heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(0, "250", heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(0, 1L shl 40, heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(-1, 250, heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(30001, 250, heartbeat = false))
    assertNull(KeyboardEditorPolicy.strictGrant(1.25, 250, heartbeat = false))
  }

  @Test
  fun heartbeatMustCarryProcessingZeroAndIgnoresAnyProcessingClaim() {
    assertNull(KeyboardEditorPolicy.strictGrant(500, 250, heartbeat = true))
    assertNull(KeyboardEditorPolicy.strictGrant(1, 250, heartbeat = true))
    assertNull(KeyboardEditorPolicy.strictGrant(30000, 250, heartbeat = true))
    assertEquals(
      AbsoluteGrant(0, 250),
      KeyboardEditorPolicy.strictGrant(0, 250, heartbeat = true),
    )
  }

  // --- absolute deadlines --------------------------------------------------

  @Test
  fun twentyMillisecondGrantExpiresExactlyAtItsAbsoluteDeadline() {
    val pending = request()
    val grant = AbsoluteGrant(0, 20)
    assertEquals(start + 20, KeyboardEditorPolicy.deadline(start, grant))

    assertTrue(admits(pending, generation, start + 19, grant))
    assertFalse(admits(pending, generation, start + 20, grant))
    assertFalse(admits(pending, generation, start + 1_000, grant))
  }

  @Test
  fun lapseIsDeniedBeforeAnyWatchdogOrTimerExecutes() {
    val pending = request()
    val grant = AbsoluteGrant(0, 20)

    val active = KeyboardActiveGrant()
    active.apply(start, grant)
    assertTrue(active.isActive(start + 19))
    // The timer has not run, yet the synchronous deadline check already denies.
    assertFalse(active.isActive(start + 20))
    assertFalse(admits(pending, generation, start + 20, grant))
  }

  @Test
  fun bootstrapGrantIsShortAndClearedByReset() {
    val active = KeyboardActiveGrant()
    assertFalse(active.isActive(start))
    assertEquals(start + KeyboardEditorPolicy.BOOTSTRAP_GRANT_MILLIS, active.bootstrap(start))
    assertTrue(active.isActive(start + 999))
    assertFalse(active.isActive(start + 1000))

    active.clear()
    assertNull(active.deadline)
    assertFalse(active.isEstablished)
    assertFalse(active.isActive(start))
  }

  @Test
  fun heartbeatGrantAdvancesOnlyToItsOwnStartPlusLease() {
    val heartbeat = request(requestStart = 20_500L)
    val heartbeatGrant = AbsoluteGrant(0, 250)
    assertTrue(admits(heartbeat, generation, 20_749, heartbeatGrant))
    assertFalse(admits(heartbeat, generation, 20_750, heartbeatGrant))
  }

  @Test
  fun longOperationStaysValidWhileIndependentHeartbeatsRemainFresh() {
    val longRequest = request(requestStart = 1_000L)
    val longGrant = AbsoluteGrant(20_000, 1_000)
    assertTrue(admits(longRequest, generation, 21_999, longGrant))
    assertFalse(admits(longRequest, generation, 22_000, longGrant))

    // A heartbeat started later is admitted against its own short window and
    // cannot shorten or extend the long operation's own reply window.
    val heartbeat = request(requestStart = 21_900L)
    val heartbeatGrant = AbsoluteGrant(0, 250)
    assertTrue(admits(heartbeat, generation, 22_149, heartbeatGrant))
    assertFalse(admits(heartbeat, generation, 22_150, heartbeatGrant))
  }

  // --- staleness -----------------------------------------------------------

  @Test
  fun staleHeartbeatAfterEditorResetIsRejected() {
    val session = KeyboardEditorSession()
    val first = session.begin("nonce-a")
    val heartbeat = request(generation = first)
    assertTrue(admits(heartbeat, session.generation, start, AbsoluteGrant(0, 250)))

    session.reset()
    assertNull(session.generation)
    assertFalse(admits(heartbeat, session.generation, start, AbsoluteGrant(0, 250)))

    val second = session.begin("nonce-b")
    assertNotEquals(first, second)
    assertFalse(admits(heartbeat, session.generation, start, AbsoluteGrant(0, 250)))
    assertTrue(
      admits(request(generation = second), session.generation, start, AbsoluteGrant(0, 250)),
    )
  }

  @Test
  fun sameNonceWithDifferentEpochIsRejected() {
    val live = EditorGeneration("nonce-a", 7L)
    val stale = request(generation = EditorGeneration("nonce-a", 6L))
    assertFalse(admits(stale, live, start, AbsoluteGrant(0, 250)))
  }

  @Test
  fun missingRequestEditorOrGrantIsRejected() {
    assertFalse(admits(null, generation, start, AbsoluteGrant(0, 250)))
    assertFalse(admits(request(), null, start, AbsoluteGrant(0, 250)))
    assertFalse(admits(request(), generation, start, null))
  }

  @Test
  fun keyguardAndHiddenWindowRejectFreshCallbacks() {
    val pending = request()
    val grant = AbsoluteGrant(0, 250)
    assertFalse(admits(pending, generation, start, grant, keyguardEngaged = true))
    assertFalse(admits(pending, generation, start, grant, serviceHidden = true))
  }

  // --- failed insert vs success -------------------------------------------

  @Test
  fun onlyATrueCommitTextResultCountsAsInserted() {
    assertEquals(InsertOutcome.INSERTED, KeyboardEditorPolicy.classifyInsert(true))
    assertEquals(InsertOutcome.NOT_INSERTED, KeyboardEditorPolicy.classifyInsert(false))
    assertEquals(InsertOutcome.NOT_INSERTED, KeyboardEditorPolicy.classifyInsert(null))
  }

  // --- bounds --------------------------------------------------------------

  @Test
  fun identifierBoundIsEnforced() {
    assertFalse(KeyboardEditorPolicy.isWellFormedIdentifier(null))
    assertFalse(KeyboardEditorPolicy.isWellFormedIdentifier(""))
    assertTrue(KeyboardEditorPolicy.isWellFormedIdentifier("a".repeat(128)))
    assertFalse(KeyboardEditorPolicy.isWellFormedIdentifier("a".repeat(129)))
  }

  @Test
  fun inboundAndOutboundCarrierBoundsAreSeparate() {
    assertTrue(KeyboardEditorPolicy.admitsOutboundCarrierLength(4000))
    assertFalse(KeyboardEditorPolicy.admitsOutboundCarrierLength(4001))
    assertFalse(KeyboardEditorPolicy.admitsOutboundCarrierLength(0))

    assertTrue(KeyboardEditorPolicy.admitsCarrierLength(262144))
    assertFalse(KeyboardEditorPolicy.admitsCarrierLength(262145))
    assertFalse(KeyboardEditorPolicy.admitsCarrierLength(0))

    assertFalse(KeyboardEditorPolicy.admitsComposeLength(0))
    assertTrue(KeyboardEditorPolicy.admitsComposeLength(4000))
    assertFalse(KeyboardEditorPolicy.admitsComposeLength(4001))
  }

  @Test
  fun draftAppendStopsExactlyAtTheComposeCeiling() {
    assertTrue(KeyboardEditorPolicy.admitsDraftAppend(3999, 1))
    assertFalse(KeyboardEditorPolicy.admitsDraftAppend(4000, 1))
    assertTrue(KeyboardEditorPolicy.admitsDraftAppend(4000, 0))
    assertFalse(KeyboardEditorPolicy.admitsDraftAppend(-1, 1))
  }
}

class KeyboardGrantRevocationRegressionTest {
  @Test
  fun delayedReplyCannotReviveExpiredGrantBeforeWatchdogRuns() {
    val active = KeyboardActiveGrant()
    active.bootstrap(1000)
    assertTrue(active.tryRenew(1000, AbsoluteGrant(0, 20), 1001))
    assertFalse(active.tryRenew(1010, AbsoluteGrant(200, 1000), 1020))
    assertFalse(active.isEstablished)
    assertFalse(active.tryRenew(1020, AbsoluteGrant(0, 1000), 1021))
  }

  @Test
  fun independentHeartbeatKeepsLongOperationAdmissibleOnlyWhileFresh() {
    val active = KeyboardActiveGrant()
    active.bootstrap(1000)
    for (time in 1100L..3000L step 100) {
      assertTrue(active.tryRenew(time, AbsoluteGrant(0, 250), time + 1))
    }
    assertTrue(active.tryRenew(1000, AbsoluteGrant(2050, 1000), 3050))
    active.clear()
    assertFalse(active.tryRenew(3000, AbsoluteGrant(100, 1000), 3100))
  }

  @Test
  fun ownInsertRequiresExactExpectedCursorAndIsConsumedOnce() {
    val selection = KeyboardCommitSelection()
    assertFalse(selection.update(12, 8))
    selection.expectInsertion(100)
    assertTrue(selection.update(108, 108))
    assertFalse(selection.update(108, 108))
    selection.expectInsertion(40)
    assertFalse(selection.update(0, 0))
    assertFalse(selection.update(148, 148))
  }

  @Test
  fun unknownOrCancelledCursorNeverSuppressesHostChange() {
    val selection = KeyboardCommitSelection()
    selection.expectInsertion(100)
    assertFalse(selection.update(100, 100))
    selection.expectInsertion(20)
    selection.cancelPending()
    assertFalse(selection.update(120, 120))
  }
}
