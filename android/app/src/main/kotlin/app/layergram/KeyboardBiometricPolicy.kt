package app.layergram

/** Metadata is admitted only after the authenticated Keystore unwrap. */
internal object KeyboardBiometricPolicy {
  // Existing v1 tickets keep their original ten-minute bound. New v2 tickets
  // are revocable and reusable only during the original device boot, with a
  // fresh strong biometric required for every session after idle expiry.
  const val MAX_AGE_MILLIS = 600000L
  fun admits(version: Int, savedBoot: Int, currentBoot: Int, issued: Long, now: Long): Boolean =
    (version == 1 || version == 2) &&
      savedBoot >= 0 && savedBoot == currentBoot && issued >= 0 && now >= issued &&
      (version == 2 || now - issued <= MAX_AGE_MILLIS)
}
