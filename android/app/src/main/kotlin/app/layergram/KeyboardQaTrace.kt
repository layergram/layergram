package app.layergram

import android.content.Context

/**
 * Narrow bridge to profile-only, fixed-code diagnostics.
 *
 * The production source set contains no Android logger. The implementation is
 * discovered only in Profile QA builds and only for the dedicated validation
 * package. Unknown or data-bearing values are rejected before reflection.
 */
internal object KeyboardQaTrace {
  private const val validationPackage = "app.layergram.keyboardvalidation"
  private const val profileLogger = "app.layergram.KeyboardQaProfileTrace"

  private val fixedStages = setOf(
    "promptCancelledByRevoke", "promptCancelledByEditorClose",
    "beginDenied", "delegateTimedOutOrHidden", "delegateRejectedOrInvalid",
    "delegateChannelError", "startBiometricEnabled", "startBiometricDisabled",
    "ticketSealed", "ticketSealFailed", "runtimeReady", "runtimeNotReady",
    "biometricAttempt", "biometricSucceeded", "authenticatedGrantPending",
    "biometricCipherUnavailable", "authenticatedGrantStarting",
    "biometricDifferentEditorDeferred", "imeWindowHidden", "imeFinishInputView",
    "imeFinishInput", "biometricVerifiedWaitingForEditor",
    "biometricShowSelfRequested", "biometricEditorReadmitted", "imeTouchDown",
  )
  private val protocolStages = setOf(
    "fragmentAccepted", "fragmentDuplicate", "committedReplay",
    "responsePrepared", "sessionEstablished", "addressedElsewhere",
    "initiatorProofRejected", "responderProofRejected", "transcriptMismatch",
    "deviceMismatch", "resetRejected", "malformed",
  )
  private val delegateStatus = Regex("delegateStatus:(ok|unavailable)")
  private val biometricError = Regex("biometricError:[0-9]{1,5}")
  private val prepareStage = Regex("prepareStage:[A-Za-z][A-Za-z0-9]{0,63}")
  private val admissionState = Regex(
    "keyNeedsAdmission:admitted=(true|false):connected=(true|false):binding=(true|false)",
  )
  private val resumeState = Regex(
    "resumePreflight:admitted=(true|false):enabled=(true|false):binding=(true|false):" +
      "flow=(true|false):pending=(true|false)",
  )

  fun emit(context: Context?, stage: String) {
    if (context?.packageName != validationPackage || !allowed(stage)) return
    invokeProfileLogger(stage)
  }

  fun emitProtocol(context: Context?, stage: String) {
    if (stage !in protocolStages) return
    emit(context, "protocol:$stage")
  }

  private fun allowed(stage: String): Boolean =
    stage in fixedStages ||
      delegateStatus.matches(stage) ||
      biometricError.matches(stage) ||
      prepareStage.matches(stage) ||
      admissionState.matches(stage) ||
      resumeState.matches(stage) ||
      (stage.startsWith("protocol:") && stage.removePrefix("protocol:") in protocolStages)

  private fun invokeProfileLogger(stage: String) {
    try {
      Class.forName(profileLogger)
        .getDeclaredMethod("emit", String::class.java)
        .invoke(null, stage)
    } catch (_: ReflectiveOperationException) {
      // Production builds deliberately have no logger implementation.
    }
  }
}
