package app.layergram

import org.junit.Assert.*
import org.junit.Test

class KeyboardBiometricPolicyTest {
  @Test fun oldTicketsKeepTheirTenMinuteLimit() {
    assertTrue(KeyboardBiometricPolicy.admits(1, 3, 3, 50, 50))
    assertTrue(KeyboardBiometricPolicy.admits(1, 3, 3, 50, 600050))
    assertFalse(KeyboardBiometricPolicy.admits(1, 3, 3, 50, 600051))
  }
  @Test fun newTicketsSurviveLongIdleOnlyUntilRevocationOrReboot() {
    assertTrue(KeyboardBiometricPolicy.admits(2, 3, 3, 50, 50 + 9 * 60 * 60 * 1000L))
    assertFalse(KeyboardBiometricPolicy.admits(2, 3, 4, 50, 50 + 9 * 60 * 60 * 1000L))
    assertFalse(KeyboardBiometricPolicy.admits(2, -1, -1, 50, 60))
    assertFalse(KeyboardBiometricPolicy.admits(3, 3, 3, 50, 60))
  }
  @Test fun rebootAndMissingBootMetadataDenyResumption() {
    assertFalse(KeyboardBiometricPolicy.admits(1, 3, 4, 50, 60))
    assertFalse(KeyboardBiometricPolicy.admits(1, -1, -1, 50, 60))
  }
  @Test fun FutureNegativeAndOverflowTimestampsCannotExtendAccess() {
    assertFalse(KeyboardBiometricPolicy.admits(2, 3, 3, 60, 50))
    assertFalse(KeyboardBiometricPolicy.admits(2, 3, 3, -1, 50))
    assertFalse(KeyboardBiometricPolicy.admits(1, 3, 3, 50, Long.MAX_VALUE))
    assertFalse(KeyboardBiometricPolicy.admits(2, 3, 3, Long.MAX_VALUE, Long.MIN_VALUE))
  }
}
