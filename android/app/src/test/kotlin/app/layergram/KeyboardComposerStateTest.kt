package app.layergram

import org.junit.Assert.*
import org.junit.Test

class KeyboardComposerStateTest {
  @Test fun cursorInsertsAndDeletesAtTheChosenPosition() {
    val state = KeyboardComposerState()
    state.insert("ciao"); state.moveTo(2); state.insert("XX")
    assertEquals("ciXXao", state.text); assertEquals(4, state.cursor)
    state.deleteBeforeCursor(); assertEquals("ciXao", state.text)
    state.moveBy(-100); assertEquals(0, state.cursor)
    state.moveBy(100); assertEquals(state.text.length, state.cursor)
  }

  @Test fun emojiAccentsFlagsAndFamiliesAreNeverSplit() {
    for (value in listOf("😀", "e\u0301", "❤️", "👍🏽", "👨‍👩‍👧‍👦", "🇮🇹")) {
      val state = KeyboardComposerState(); state.insert("a$value")
      state.moveBy(-1); assertEquals(1, state.cursor)
      state.moveBy(1); state.deleteBeforeCursor(); assertEquals("a", state.text)
    }
  }

  @Test fun limitRejectsWithoutChangingCursorOrTextAndClearResetsBoth() {
    val state = KeyboardComposerState(4); assertTrue(state.insert("😀ab"))
    state.moveTo(2); assertFalse(state.insert("c")); assertEquals("😀ab", state.text)
    assertEquals(2, state.cursor); state.clear(); assertEquals("", state.text); assertEquals(0, state.cursor)
  }

  @Test fun cursorCannotEnterASurrogateOrCombiningSequence() {
    val state = KeyboardComposerState(); state.insert("😀e\u0301")
    state.moveTo(1); assertTrue(state.cursor == 0 || state.cursor == 2)
    state.moveTo(3); assertTrue(state.cursor == 2 || state.cursor == 4)
  }

  @Test fun primaryActionChangesWithTheDraft() {
    assertEquals("paste", KeyboardPresentation.primaryAction(false))
    assertEquals("send", KeyboardPresentation.primaryAction(true))
  }

  @Test fun searchIsLiveCaseAndAccentInsensitive() {
    assertTrue(KeyboardPresentation.matches("José", "jose"))
    assertTrue(KeyboardPresentation.matches("Identità A", " TÀ "))
    assertTrue(KeyboardPresentation.matches("Alice", ""))
    assertFalse(KeyboardPresentation.matches("Alice", "Bob"))
  }

  @Test fun localeAndLongPressProvideSpanishAndInternationalLetters() {
    assertTrue(KeyboardPresentation.letterRows("es")[1].contains("ñ"))
    assertTrue(KeyboardPresentation.letterRows("de")[0].contains("ü"))
    assertEquals("azertyuiop", KeyboardPresentation.letterRows("fr")[0])
    assertTrue(KeyboardPresentation.letterRows("pt")[1].contains("ç"))
    assertTrue(KeyboardPresentation.letterRows("sv")[1].contains("ä"))
    assertTrue(KeyboardPresentation.letterRows("da")[1].contains("æ"))
    assertTrue(KeyboardPresentation.variants("n").contains("ñ"))
    assertTrue(KeyboardPresentation.variants("C").contains("Ç"))
    assertTrue(KeyboardPresentation.variants("e").contains("é"))
    assertTrue(KeyboardPresentation.variants("7").isEmpty())
  }

  @Test fun shieldMatchesEveryIosPhaseAndNeverInventsActiveFs() {
    for (phase in listOf("normalActive", "maximumActive")) assertEquals("active", KeyboardPresentation.shieldState(phase))
    for (phase in listOf("setupRequired", "setupPending", "maximumSetupRequired", "maximumSetupPending"))
      assertEquals("pending", KeyboardPresentation.shieldState(phase))
    for (phase in listOf("recoveryRequired", "maximumRecoveryRequired"))
      assertEquals("recovery", KeyboardPresentation.shieldState(phase))
    assertEquals("unknown", KeyboardPresentation.shieldState(null))
    assertEquals("unknown", KeyboardPresentation.shieldState("invalid"))
  }

  @Test fun onlyRealActivityRenewsIdleAndExpiryCannotBeRevivedByTouch() {
    val window = KeyboardInteractionWindow(); assertTrue(window.start(1000, 60000))
    assertEquals(40000, window.remaining(21000)); assertEquals(20000, window.remaining(41000))
    assertTrue(window.touch(41000)); assertEquals(60000, window.remaining(41000))
    assertEquals(1, window.remaining(101000 - 1)); assertFalse(window.touch(101000))
    assertEquals(0, window.remaining(101001))
  }

  @Test fun invalidDurationClockRollbackAndRevocationFailClosed() {
    val window = KeyboardInteractionWindow()
    for (bad in listOf(-1, 0, 300001)) assertFalse(window.start(10, bad))
    window.start(100, 60000); assertEquals(0, window.remaining(99))
    assertFalse(window.touch(101)); window.start(100, 60000); window.clear(); assertEquals(0, window.remaining(100))
  }

  @Test fun revocationDuringAccentGestureDropsLateMovesAndFingerUp() {
    val selection = KeyboardAccentSelection()
    selection.begin(listOf("a", "à", "á")); selection.move(2)
    selection.clear(); selection.move(100)
    assertNull(selection.finish()); assertTrue(selection.options.isEmpty())
    selection.begin(listOf("n", "ñ")); selection.move(1)
    assertEquals("ñ", selection.finish()); assertNull(selection.finish())
  }
}
