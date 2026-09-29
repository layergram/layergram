package app.layergram

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyboardBiometricEditorPolicyTest {
  private val connection = Any()
  private val original = KeyboardEditorBinding("host.example", 7, 1, 0, 12000, 42, connection)

  @Test fun transientNoEditorKeepsPromptButCannotAdmit() {
    assertFalse(KeyboardBiometricEditorPolicy.changed(original, null))
    assertFalse(KeyboardBiometricEditorPolicy.mayAdmit(original, null, true, true))
    assertTrue(KeyboardBiometricEditorPolicy.mayAdmit(original, original.copy(), true, true))
  }

  @Test fun changedHostFieldOrConnectionRejectsAuthenticatedHandoff() {
    for (different in listOf(
      original.copy(packageName = "other.example"),
      original.copy(fieldId = 8),
      original.copy(connectionToken = Any()),
      original.copy(uid = 12001),
    )) {
      assertTrue(KeyboardBiometricEditorPolicy.changed(original, different))
      assertFalse(KeyboardBiometricEditorPolicy.mayAdmit(original, different, true, true))
    }
  }

  @Test fun hiddenOrRejectedFieldCannotConsumeAuthenticatedTicket() {
    assertFalse(KeyboardBiometricEditorPolicy.mayAdmit(original, original, false, true))
    assertFalse(KeyboardBiometricEditorPolicy.mayAdmit(original, original, true, false))
  }

  @Test fun reentryHintOnlyPromisesBiometricsForAnAdmittedEditorWithATicket() {
    val policy = KeyboardReentryStatusPolicy
    assertTrue(policy.status(false, false, true) == KeyboardReentryStatusPolicy.Status.REJECTED_FIELD)
    assertTrue(policy.status(true, false, false) == KeyboardReentryStatusPolicy.Status.OPEN_APP)
    assertTrue(policy.status(true, false, true) == KeyboardReentryStatusPolicy.Status.TOUCH_TO_UNLOCK)
    assertTrue(policy.status(true, true, false) == KeyboardReentryStatusPolicy.Status.UNLOCKING)
  }
}
