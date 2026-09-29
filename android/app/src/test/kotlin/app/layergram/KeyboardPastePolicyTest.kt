package app.layergram

import org.junit.Assert.*
import org.junit.Test

class KeyboardPastePolicyTest {
  @Test fun publicCardsAreRoutedToManualAppReview() {
    assertTrue(KeyboardPastePolicy.looksLikePublicIdentity("\n layergram://i/public \n"))
    assertTrue(KeyboardPastePolicy.looksLikePublicIdentity("LAYERGRAM://I/public"))
    assertTrue(KeyboardPastePolicy.looksLikePublicIdentity("v3.public"))
    assertTrue(KeyboardPastePolicy.looksLikePublicIdentity("[Layergram Identity]\npublic"))
  }
  @Test fun encryptedMessagesAndOrdinaryTextAreNotContactHints() {
    for (text in listOf("m3.encrypted", "p1.data\nm3.negotiation", "hello", ""))
      assertFalse(KeyboardPastePolicy.looksLikePublicIdentity(text))
  }
  @Test fun oversizedUntrustedIdentityTextNeverGetsTheContactShortcut() {
    assertFalse(KeyboardPastePolicy.looksLikePublicIdentity("v3." + "a".repeat(4096)))
  }
}
