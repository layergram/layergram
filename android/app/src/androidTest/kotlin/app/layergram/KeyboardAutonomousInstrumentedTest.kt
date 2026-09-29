package app.layergram

import android.content.Context
import android.content.ContextWrapper
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.ActivityTestRule
import io.flutter.FlutterInjector
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.dart.DartExecutor
import io.flutter.plugin.common.MethodChannel
import org.junit.Assert.*
import org.junit.Test
import org.junit.Rule
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Uses the separately installed fixture and real packaged ML-KEM/SCKA. */
class KeyboardAutonomousInstrumentedTest {
  // Keep the disposable fixture visible during instrumentation. OEM process
  // freezers may otherwise suspend a headless test UID before it has an IME
  // binding. Real app-departure/custody transitions are still exercised below.
  @get:Rule val rule = ActivityTestRule(MainActivity::class.java, true, true)
  private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
  private val main = Handler(Looper.getMainLooper())
  private var requestId = 0
  private fun traceBroker(trace: ((String) -> Unit)?) {
    // Reflection also works when this test APK exercises a signed Profile
    // fixture: Kotlin's internal member names otherwise vary by build type.
    SystemKeyboardBroker::class.java.getDeclaredField("traceForTesting")
      .apply { isAccessible = true }.set(SystemKeyboardBroker, trace)
  }
  private fun await(timeoutSeconds: Long = 45, block: ((Any?) -> Unit) -> Unit): Any? {
    val latch = CountDownLatch(1); var value: Any? = null; var failure: Throwable? = null
    main.post { try { block { value = it; latch.countDown() } } catch (error: Throwable) { failure = error; latch.countDown() } }
    assertTrue("Native/Flutter request timed out", latch.await(timeoutSeconds, TimeUnit.SECONDS))
    failure?.let { throw it }; return value
  }
  private fun result(done: (Any?) -> Unit) = object : MethodChannel.Result {
    override fun success(value: Any?) = done(value)
    override fun error(code: String, message: String?, details: Any?) = done(mapOf("status" to "error", "code" to code))
    override fun notImplemented() = done(mapOf("status" to "notImplemented"))
  }
  @Suppress("UNCHECKED_CAST") private fun response(value: Any?): Map<String, Any?> {
    val reply = value as Map<String, Any?>; assertEquals("ok", reply["status"]); return reply
  }
  private fun data(value: Any?) = response(value)["data"] as Map<*, *>

  @Test fun lateDelegationFailureCannotCancelANewerKeyboardAttempt() {
    assertEquals("app.layergram.keyboardvalidation", context.packageName)
    await { done ->
      context.getSharedPreferences("layergram_prefs", 0).edit().putBoolean("system_keyboard_enabled", true)
        .putBoolean("system_keyboard_autonomous", true).commit()
      KeyboardAutonomousHost.initialize(context); KeyboardAutonomousHost.appDeparted()
      var old: MethodChannel.Result? = null; var current: MethodChannel.Result? = null
      var oldCompletions = 0; var currentCompletions = 0
      KeyboardAutonomousHost.begin("attempt-old", { true }, { _, reply -> old = reply }) { oldCompletions++ }
      KeyboardAutonomousHost.begin("attempt-current", { true }, { _, reply -> current = reply }) { currentCompletions++ }
      old!!.error("unavailable", null, null)
      assertEquals(0, oldCompletions); assertEquals(0, currentCompletions)
      val waiting = KeyboardAutonomousHost::class.java.getDeclaredField("waiting").apply { isAccessible = true }
      assertEquals(true, waiting.get(KeyboardAutonomousHost))
      current!!.error("unavailable", null, null)
      assertEquals(1, currentCompletions); assertEquals(false, waiting.get(KeyboardAutonomousHost))
      KeyboardAutonomousHost.revoke(); done(true)
    }
  }

  @Test fun nativeHeadlessEngineDeliversFirstDataReachesGreenAndResumesLatestFsAfterRestart() {
    assertEquals("Use disposable keyboard validation package", "app.layergram.keyboardvalidation", context.packageName)
    var fixtureEngine: FlutterEngine? = null; var fixtureChannel: MethodChannel? = null
    var nativeStore: KeyboardCustodyStore? = null; var init: Map<*, *>? = null
    var custodyPrepared = false
    try {
      await { done ->
        val loader = FlutterInjector.instance().flutterLoader()
        loader.startInitialization(context); loader.ensureInitializationComplete(context, null)
        val engine = FlutterEngine(context, null, false); fixtureEngine = engine
        val channel = MethodChannel(engine.dartExecutor.binaryMessenger, "layergram/keyboard_validation"); fixtureChannel = channel
        channel.setMethodCallHandler { call, reply -> if (call.method == "ready") { reply.success(null); done(true) } else reply.notImplemented() }
        engine.dartExecutor.executeDartEntrypoint(DartExecutor.DartEntrypoint(loader.findAppBundlePath(), "layergramKeyboardValidationMain"))
      }
      // A cold debug VM on older physical hardware can page in its crypto
      // code slowly. This only bounds QA seed setup, not keyboard admission.
      fun fixture(method: String, args: Any? = null) = await(if (method == "initialize") 180 else 45) { done -> fixtureChannel!!.invokeMethod(method, args, result(done)) }
      val setup = fixture("initialize") as Map<*, *>
      init = setup
      val epoch = setup["epoch"] as ByteArray; val key = setup["key"] as ByteArray
      nativeStore = KeyboardCustodyStore(context)
      assertFalse(nativeStore.hasPending())
      await { done ->
        context.getSharedPreferences("layergram_prefs", 0).edit().putBoolean("system_keyboard_enabled", true)
          .putBoolean("system_keyboard_autonomous", true).commit()
        KeyboardAutonomousHost.initialize(context); KeyboardAutonomousHost.appDeparted()
        nativeStore!!.prepare(epoch, key, init!!["snapshot"] as ByteArray); custodyPrepared = true; nativeStore!!.activate(epoch, key)
        done(true)
      }
      var nonce = "native-editor-1"
      var remoteNonce = "remote-editor"
      fun start() {
        val grant = fixture("grant", nonce)
        assertEquals(true, await { done -> KeyboardAutonomousHost.begin(nonce, { true }, { _, reply -> reply.success(grant) }) { done(it) } })
      }
      fun local(operation: String, extra: Map<String, Any> = emptyMap()): Any? = await { done ->
        KeyboardAutonomousHost.touch()
        KeyboardAutonomousHost.request(mapOf("operation" to operation, "editorNonce" to nonce,
          "requestId" to "local-${requestId++}") + extra, result(done))
      }
      fun remote(operation: String, extra: Map<String, Any> = emptyMap()): Any? = fixture("remote",
        mapOf("operation" to operation, "editorNonce" to remoteNonce, "requestId" to "remote-${requestId++}") + extra)
      start(); data(local("begin")); data(remote("begin"))
      val localContact = setup["contactId"] as String; val remoteContact = setup["remoteContactId"] as String
      var green = false
      for (turn in 0..47) {
        fun send(fromLocal: Boolean) {
          val request = if (fromLocal) ::local else ::remote
          val decode = if (fromLocal) ::remote else ::local
          val contact = if (fromLocal) localContact else remoteContact
          data(request("select", mapOf("contactId" to contact, "confirm" to true)))
          val text = "Readable native keyboard message $turn ${if (fromLocal) "A" else "B"}"
          val pending = data(request("prepare", mapOf("text" to text)))["pendingId"] as String
          val carrier = data(request("authorize", mapOf("pendingId" to pending)))["carrier"] as String
          assertTrue(carrier.length <= 4000)
          assertFalse(carrier.contains("1/2") || carrier.contains("2/2"))
          data(request("ack", mapOf("pendingId" to pending, "commitText" to true)))
          assertEquals(text, data(decode("decode", mapOf("carrier" to carrier)))["text"])
        }
        send(true); send(false)
        val localPhase = data(local("select", mapOf("contactId" to localContact, "confirm" to true)))["securityPhase"]
        val remotePhase = data(remote("select", mapOf("contactId" to remoteContact, "confirm" to true)))["securityPhase"]
        if (localPhase == "normalActive" && remotePhase == "normalActive") { green = true; break }
      }
      assertTrue("Both real V3 peers must reach FS green", green)
      Log.i("KeyboardQA", "realPeersGreen")
      val revision = nativeStore.load(epoch, key).revision
      assertTrue(revision > 0)
      await { done -> KeyboardAutonomousHost.closeEditor(); done(true) }
      assertTrue(nativeStore.hasPending())
      nonce = "native-editor-after-restart"
      start(); data(local("begin"))
      assertEquals("normalActive", data(local("select", mapOf("contactId" to localContact, "confirm" to true)))["securityPhase"])
      val text = "FS preserved after native engine restart"
      val pending = data(local("prepare", mapOf("text" to text)))["pendingId"] as String
      val carrier = data(local("authorize", mapOf("pendingId" to pending)))["carrier"] as String
      data(local("ack", mapOf("pendingId" to pending, "commitText" to true)))
      assertEquals(text, data(remote("decode", mapOf("carrier" to carrier)))["text"])
      assertTrue(nativeStore.load(epoch, key).revision > revision)

      // Exercise the actual broker heartbeat/grant path and replay rotation,
      // beyond its 64-request controller limit, without replacing FS custody.
      await { done ->
        SystemKeyboardBroker.bindEngine(fixtureChannel!!, fixtureEngine!!, context)
        traceBroker { Log.i("KeyboardQA", it) }
        val service = LayergramInputMethodService()
        ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", Context::class.java)
          .apply { isAccessible = true }.invoke(service, context)
        service.onCreateInputView()
        SystemKeyboardBroker.attachService(service)
        SystemKeyboardBroker.setServiceVisible(true)
        SystemKeyboardBroker.bindEditor()
        done(true)
      }
      assertTrue(await { done -> SystemKeyboardBroker.requestBegin { done(it is BrokerOutcome.Success) } } as Boolean)
      for (turn in 0..17) {
        if (turn % 4 == 0) {
          remoteNonce = "remote-continued-$turn"
          assertEquals(true, fixture("remoteRebind", remoteNonce)); data(remote("begin"))
        }
        await { done -> SystemKeyboardBroker.recordUserInteraction(); done(true) }
        val chosen = await { done -> SystemKeyboardBroker.selectContact(localContact) { done(it) } }
        assertTrue("Broker select after rotation", chosen is BrokerOutcome.Success<*>)
        assertEquals("normalActive", (chosen as BrokerOutcome.Success<*>).value.let { (it as BrokerContact).securityPhase })
        val message = "Continuous keyboard message $turn"
        val prepared = await { done -> SystemKeyboardBroker.prepareAndAuthorize(message) { done(it) } }
        assertTrue("Broker prepare with live heartbeat", prepared is BrokerOutcome.Success<*>)
        val export = (prepared as BrokerOutcome.Success<*>).value as PreparedExport
        assertTrue(await { done -> SystemKeyboardBroker.acknowledge(export.pendingId, true) { done(it is BrokerOutcome.Success) } } as Boolean)
        assertEquals(message, data(remote("decode", mapOf("carrier" to export.carrier)))["text"])
      }
      val beforeRebind = await { done -> done(KeyboardAutonomousHost.remainingIdleMillis()) } as Long
      assertTrue(await { done -> SystemKeyboardBroker.onHostSelectionChanged { done(it is BrokerOutcome.Success) } } as Boolean)
      val afterRebind = await { done -> done(KeyboardAutonomousHost.remainingIdleMillis()) } as Long
      assertTrue("Host selection change does not renew inactivity", afterRebind <= beforeRebind)
      assertTrue(await { done -> SystemKeyboardBroker.selectContact(localContact) { done(it is BrokerOutcome.Success && it.value.securityPhase == "normalActive") } } as Boolean)
      // Reopening the app must reclaim the latest revision, not the initial one.
      await { done -> SystemKeyboardBroker.resetEditor(); done(true) }
      val latest = nativeStore.reclaim(epoch, key)
      assertTrue(latest.revision > revision)
      nativeStore.finish(epoch, key, latest.revision)
    } finally {
      await { done ->
        KeyboardAutonomousHost.revoke()
        SystemKeyboardBroker.resetEditor(); SystemKeyboardBroker.detachService()
        // A rejected stale fixture must not be reclaimed using this run's
        // unrelated epoch/key, nor hide the original assertion with cleanup.
        if (custodyPrepared && nativeStore?.hasPending() == true && init != null) {
          val state = nativeStore!!.reclaim(init!!["epoch"] as ByteArray, init!!["key"] as ByteArray)
          nativeStore!!.finish(init!!["epoch"] as ByteArray, init!!["key"] as ByteArray, state.revision)
        }
        fixtureChannel?.setMethodCallHandler(null); fixtureEngine?.destroy(); done(true)
        traceBroker(null)
      }
    }
  }
}
