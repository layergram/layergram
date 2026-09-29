package app.layergram

import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Base64
import io.flutter.FlutterInjector
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.dart.DartExecutor
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.Executor

/** Exclusive native owner. Creates only the narrow, plugin-free Dart runtime. */
internal object KeyboardAutonomousHost {
  private val handler = Handler(Looper.getMainLooper())
  private var context: Context? = null
  private var store: KeyboardCustodyStore? = null
  private var ticket: KeyboardBiometricTicket? = null
  private var engine: FlutterEngine? = null
  private var channel: MethodChannel? = null
  private var epoch: ByteArray? = null
  private var key: ByteArray? = null
  private var startingMaterial: ByteArray? = null
  private val idle = KeyboardInteractionWindow()
  private var token = 0
  private var prompting: CancellationSignal? = null
  private var biometricLaunchPending = false
  private var authenticatedGrant: Map<String, Any>? = null
  private var authenticatedUntil = 0L
  private var waiting = false
  private var currentNonce: String? = null
  private var ready = false
  private var appForeground = false
  private var authorizedUi: (() -> Boolean)? = null
  // Instrumentation can observe fixed state codes without keys, configuration,
  // plaintext, carriers or identity metadata. Never installed by the app.
  private var traceForTesting: ((String) -> Unit)? = null
  private fun qaStage(stage: String) {
    KeyboardQaTrace.emit(context, stage)
  }
  val isRunning get() = ready && engine != null
  val hasBiometricFlow get() = biometricLaunchPending || prompting != null || authenticatedGrant != null
  fun remainingIdleMillis(): Long = if (isRunning) idle.remaining(SystemClock.elapsedRealtime()) else 0L

  /** New editor-local capability, same exclusive FS owner and original idle deadline. */
  fun rebind(nonce: String, ui: () -> Boolean, callback: (Boolean) -> Unit) {
    if (!ready || !valid(checkUi = false) || nonce == currentNonce || !ui()) { callback(false); return }
    val captured = token
    currentNonce = nonce; authorizedUi = ui
    channel!!.invokeMethod("rebind", mapOf("editorNonce" to nonce), object : MethodChannel.Result {
      override fun success(value: Any?) {
        if (captured != token) return
        val accepted = value == true && valid()
        if (!accepted) closeEditor()
        callback(accepted)
      }
      override fun error(code: String, message: String?, details: Any?) {
        if (captured == token) { closeEditor(); callback(false) }
      }
      override fun notImplemented() = error("unavailable", null, null)
    })
  }

  fun initialize(value: Context) {
    if (context == null) {
      context = value.applicationContext
      store = KeyboardCustodyStore(context!!)
      ticket = KeyboardBiometricTicket(context!!)
    }
  }
  fun enabled(): Boolean = context?.getSharedPreferences("layergram_prefs", Context.MODE_PRIVATE)?.let {
    it.getBoolean("system_keyboard_enabled", false) && it.getBoolean("system_keyboard_autonomous", false)
  } == true

  fun appResumed() { appForeground = true; close(removeTicket = true) }
  fun appDeparted() { appForeground = false }
  fun revoke() = close(removeTicket = true)
  fun closeEditor() = close(removeTicket = false)

  fun discardBiometric() {
    val stale = authenticatedGrant
    authenticatedGrant = null; authenticatedUntil = 0L
    wipeGrant(stale)
    close(removeTicket = false, preserveBiometric = false)
  }

  private fun wipeGrant(grant: Map<String, Any>?) {
    fun wipe(value: Any?) {
      when (value) {
        is ByteArray -> value.fill(0)
        is Map<*, *> -> value.values.forEach(::wipe)
        is Iterable<*> -> value.forEach(::wipe)
      }
    }
    wipe(grant)
  }

  private fun close(removeTicket: Boolean, preserveBiometric: Boolean = true) {
    // The system fingerprint dialog temporarily finishes the IME input view.
    // Keep only the prompt, never the editor session, across that transition.
    if (!removeTicket && preserveBiometric && hasBiometricFlow) return
    traceForTesting?.invoke("close:ready=$ready:ticket=$removeTicket")
    if (prompting != null) qaStage(if (removeTicket) "promptCancelledByRevoke" else "promptCancelledByEditorClose")
    token++; waiting = false; ready = false; prompting?.cancel(); prompting = null; biometricLaunchPending = false
    wipeGrant(authenticatedGrant); authenticatedGrant = null; authenticatedUntil = 0L
    idle.clear(); currentNonce = null; authorizedUi = null
    channel?.setMethodCallHandler(null); channel = null
    val old = engine; engine = null
    old?.destroy()
    epoch?.fill(0); key?.fill(0); epoch = null; key = null
    startingMaterial?.fill(0); startingMaterial = null
    if (removeTicket) ticket?.remove()
  }

  fun handleCustody(call: MethodCall, result: MethodChannel.Result) {
    try {
      val state = store ?: error("Unavailable")
      if (call.method == "hasPending") { result.success(state.hasPending()); return }
      val args = call.arguments as? Map<*, *> ?: error("Invalid arguments")
      val epoch = args["epoch"] as? ByteArray ?: error("Invalid epoch")
      val key = args["key"] as? ByteArray ?: error("Invalid key")
      require(epoch.size == 16 && key.size == 32)
      when (call.method) {
        "prepare" -> { check(enabled() && !appForeground); state.prepare(epoch, key, args["snapshot"] as ByteArray); result.success(null) }
        "activate" -> { check(enabled() && !appForeground); state.activate(epoch, key); result.success(null) }
        "reclaim" -> {
          close(removeTicket = true)
          if (!state.hasPending()) { result.error("custodyMissing", null, null); return }
          val snapshot = state.reclaim(epoch, key)
          result.success(mapOf("revision" to snapshot.revision, "snapshot" to snapshot.snapshot))
          snapshot.snapshot.fill(0)
        }
        "finish" -> { state.finish(epoch, key, (args["revision"] as Number).toLong()); result.success(null) }
        else -> result.notImplemented()
      }
    } catch (_: Throwable) { result.error("custodyUnavailable", null, null) }
  }

  /** App delegation is one-shot. Busy polling never extends the bootstrap. */
  fun begin(nonce: String, ui: () -> Boolean, delegate: (Map<String, Any>, MethodChannel.Result) -> Unit,
            callback: (Boolean) -> Unit) {
    if (!enabled() || appForeground || !ui() || hasBiometricFlow) {
      traceForTesting?.invoke("beginDenied:enabled=${enabled()}:foreground=$appForeground:visible=${ui()}")
      qaStage("beginDenied")
      callback(false); return
    }
    closeEditor()
    val captured = token
    val deadline = SystemClock.elapsedRealtime() + 30000
    waiting = true
    fun poll() {
      if (captured != token) return
      if (!ui() || appForeground || SystemClock.elapsedRealtime() >= deadline) { qaStage("delegateTimedOutOrHidden"); waiting = false; callback(false); return }
      delegate(mapOf("operation" to "delegate", "editorNonce" to nonce, "requestId" to "delegate-$captured"),
        object : MethodChannel.Result {
          override fun success(value: Any?) {
            if (captured != token) return
            val reply = value as? Map<*, *>
            val status = reply?.get("status") as? String
            val stage = reply?.get("diagnosticStage") as? String
            if (stage != null && Regex("[A-Za-z]{1,64}").matches(stage))
              traceForTesting?.invoke("delegateStage:$stage")
            if (status in setOf("ok", "busy", "unavailable")) traceForTesting?.invoke("delegateStatus:$status")
            if (status in setOf("ok", "unavailable")) qaStage("delegateStatus:$status")
            if (reply?.get("status") == "busy") { handler.postDelayed({ poll() }, 100); return }
            waiting = false
            try {
              check(reply?.get("status") == "ok" && reply["mode"] == "autonomous-v1")
              val grant = decodeGrant(reply)
              start(grant, nonce, ui, captured, callback, sealTicket = true)
            } catch (_: Throwable) { qaStage("delegateRejectedOrInvalid"); closeEditor(); callback(false) }
          }
          override fun error(code: String, message: String?, details: Any?) {
            if (captured == token) { qaStage("delegateChannelError"); waiting = false; callback(false) }
          }
          override fun notImplemented() = error("unavailable", null, null)
        })
    }
    poll()
  }

  @Suppress("UNCHECKED_CAST") private fun decodeGrant(reply: Map<*, *>): Map<String, Any> {
    val config = (reply["configuration"] as Map<String, Any>).toMutableMap()
    for (field in listOf("publicIdentity", "identityKeyMaterial", "localDeviceId", "epoch"))
      config[field] = Base64.decode(config[field] as String, Base64.DEFAULT)
    config["contacts"] = (config["contacts"] as List<Map<String, Any>>).map {
      it.toMutableMap().apply { this["identity"] = Base64.decode(this["identity"] as String, Base64.DEFAULT) }
    }
    return mapOf("key" to Base64.decode(reply["key"] as String, Base64.DEFAULT), "configuration" to config)
  }

  @Suppress("UNCHECKED_CAST") private fun start(grant: Map<String, Any>, nonce: String, ui: () -> Boolean,
      captured: Int, callback: (Boolean) -> Unit, sealTicket: Boolean) {
    check(captured == token && enabled() && !appForeground && ui())
    val config = (grant["configuration"] as Map<String, Any>).toMutableMap()
    qaStage(if (config["biometricResume"] == true) "startBiometricEnabled" else "startBiometricDisabled")
    val material = config["identityKeyMaterial"] as ByteArray
    startingMaterial = material
    epoch = (config["epoch"] as ByteArray).copyOf(); key = (grant["key"] as ByteArray).copyOf()
    require(epoch!!.size == 16 && key!!.size == 32)
    val idleMillis = config["idleMillis"] as Int
    require(idleMillis in 1..300000)
    store!!.load(epoch!!, key!!).snapshot.fill(0)
    if (sealTicket && config["biometricResume"] == true && Build.VERSION.SDK_INT >= 28) {
      try { ticket!!.seal(grant); qaStage("ticketSealed") }
      catch (_: Throwable) { qaStage("ticketSealFailed"); ticket!!.remove() }
    }
    (grant["key"] as ByteArray).fill(0)
    config.remove("biometricResume"); config["editorNonce"] = nonce
    currentNonce = nonce; authorizedUi = ui; idle.start(SystemClock.elapsedRealtime(), idleMillis)
    val loader = FlutterInjector.instance().flutterLoader()
    loader.startInitialization(context!!); loader.ensureInitializationComplete(context!!, null)
    val runtimeEngine = FlutterEngine(context!!, null, false)
    engine = runtimeEngine
    val runtime = MethodChannel(runtimeEngine.dartExecutor.binaryMessenger, "layergram/keyboard_runtime")
    channel = runtime
    var completed = false
    fun complete(value: Boolean) { if (completed) return; completed = true; callback(value) }
    runtime.setMethodCallHandler { call, result ->
      if (captured != token || engine !== runtimeEngine) { result.error("unavailable", null, null); return@setMethodCallHandler }
      try {
        when (call.method) {
          "diagnosticStage" -> {
            val allowed = setOf("fragmentAccepted", "fragmentDuplicate", "committedReplay",
              "responsePrepared", "sessionEstablished", "addressedElsewhere", "initiatorProofRejected",
              "responderProofRejected", "transcriptMismatch", "deviceMismatch", "resetRejected", "malformed")
            if (call.arguments is String && allowed.contains(call.arguments as String))
              KeyboardQaTrace.emitProtocol(context, call.arguments as String)
            result.success(null)
          }
          "ready" -> {
            result.success(null)
            runtime.invokeMethod("start", config, object : MethodChannel.Result {
              override fun success(value: Any?) {
                material.fill(0)
                if (captured != token) return
                ready = value == true && valid()
                qaStage(if (ready) "runtimeReady" else "runtimeNotReady")
                if (!ready) closeEditor()
                complete(ready)
              }
              override fun error(code: String, message: String?, details: Any?) {
                material.fill(0)
                if (captured == token) { closeEditor(); complete(false) }
              }
              override fun notImplemented() = error("unavailable", null, null)
            })
          }
          "check" -> result.success(valid())
          "load" -> {
            check(valid()); val snapshot = store!!.load(epoch!!, key!!)
            result.success(mapOf("revision" to snapshot.revision, "snapshot" to snapshot.snapshot)); snapshot.snapshot.fill(0)
          }
          "commit" -> {
            check(valid()); val args = call.arguments as Map<*, *>
            check(args.size == 2 && args["revision"] is Number && args["snapshot"] is ByteArray)
            result.success(store!!.commit(epoch!!, key!!, args["snapshot"] as ByteArray, (args["revision"] as Number).toLong()))
          }
          "closed" -> { result.success(null); handler.post { if (captured == token) closeEditor() } }
          else -> result.notImplemented()
        }
      } catch (_: Throwable) { result.error("unavailable", null, null); handler.post { if (captured == token) { closeEditor(); complete(false) } } }
    }
    runtimeEngine.dartExecutor.executeDartEntrypoint(DartExecutor.DartEntrypoint(loader.findAppBundlePath(), "layergramKeyboardMain"))
    handler.postDelayed({ if (!completed && captured == token) { material.fill(0); closeEditor(); complete(false) } }, 30000)
  }

  private fun valid(checkUi: Boolean = true): Boolean = enabled() && !appForeground && currentNonce != null &&
    (!checkUi || authorizedUi?.invoke() == true) && context?.let { !(it.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isKeyguardLocked } == true &&
    idle.remaining(SystemClock.elapsedRealtime()) > 0

  fun request(args: Map<String, Any>, result: MethodChannel.Result) {
    if (!ready || !valid() || args["editorNonce"] != currentNonce) { result.success(mapOf("status" to "unavailable")); return }
    channel!!.invokeMethod("request", args, result)
  }
  fun touch() {
    if (!ready || !valid() || !idle.touch(SystemClock.elapsedRealtime())) return
    channel?.invokeMethod("activity", null)
  }

  /** Read-only ticket preflight for a truthful unlock hint. */
  fun canOfferBiometric(): Boolean {
    if (Build.VERSION.SDK_INT < 28 || hasBiometricFlow || waiting || !enabled() || appForeground) return false
    return try { ticket?.decryptCipher() != null } catch (_: Throwable) { false }
  }

  /** Reserve only after a deliberate tap in a visible, admitted editor. */
  fun reserveBiometricLaunch(): Boolean {
    if (Build.VERSION.SDK_INT < 28 || hasBiometricFlow || waiting || !enabled() || appForeground) return false
    closeEditor()
    try { ticket!!.decryptCipher() } catch (_: Throwable) { return false }
    biometricLaunchPending = true
    return true
  }

  /** The caller must be the non-exported, foreground biometric activity. */
  fun resumeBiometrically(activity: KeyboardBiometricActivity, callback: (Boolean) -> Unit) {
    if (!biometricLaunchPending || !enabled() || appForeground ||
        (activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isKeyguardLocked) {
      discardBiometric(); callback(false); return
    }
    biometricLaunchPending = false
    qaStage("biometricAttempt")
    val captured = token
    val cancellation = CancellationSignal(); prompting = cancellation
    try {
      val cipher = ticket!!.decryptCipher()
      val executor = Executor { handler.post(it) }
      val builder = BiometricPrompt.Builder(activity).setTitle(activity.getString(R.string.sk_biometric_title))
        .setNegativeButton(activity.getString(android.R.string.cancel), executor) { _, _ ->
          if (captured == token) { prompting = null; callback(false) }
        }
      if (Build.VERSION.SDK_INT >= 30) builder.setAllowedAuthenticators(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG)
      builder.build().authenticate(BiometricPrompt.CryptoObject(cipher), cancellation, executor,
        object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            if (captured != token) return
            qaStage("biometricSucceeded")
            prompting = null
            try {
              check(enabled() && !appForeground &&
                !(activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isKeyguardLocked)
              authenticatedGrant = ticket!!.open(result.cryptoObject!!.cipher!!)
              authenticatedUntil = SystemClock.elapsedRealtime() + 15000
              qaStage("authenticatedGrantPending")
              handler.postDelayed({ if (captured == token && authenticatedGrant != null &&
                  SystemClock.elapsedRealtime() >= authenticatedUntil) discardBiometric() }, 15000)
              callback(true)
            } catch (_: Throwable) { discardBiometric(); callback(false) }
          }
          override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            if (captured == token) { qaStage("biometricError:$errorCode"); prompting = null; callback(false) }
          }
        })
    } catch (_: Throwable) { qaStage("biometricCipherUnavailable"); prompting = null; callback(false) }
  }

  fun startAuthenticated(nonce: String, ui: () -> Boolean, callback: (Boolean) -> Unit) {
    val grant = authenticatedGrant
    if (grant == null || SystemClock.elapsedRealtime() >= authenticatedUntil ||
        !enabled() || appForeground || !ui()) { discardBiometric(); callback(false); return }
    authenticatedGrant = null; authenticatedUntil = 0L
    qaStage("authenticatedGrantStarting")
    try { start(grant, nonce, ui, token, callback, sealTicket = false) }
    catch (_: Throwable) { wipeGrant(grant); closeEditor(); callback(false) }
  }
}
