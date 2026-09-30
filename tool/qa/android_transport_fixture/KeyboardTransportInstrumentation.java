// Copyright 2026 Layergram. Licensed under the Apache License, Version 2.0.
package app.layergram.keyboardprobe;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.Instrumentation;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.content.res.Configuration;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.SystemClock;
import android.provider.Settings;
import android.view.InputDevice;
import android.view.MotionEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;

/** Real keyboard UI from the offline host, without instrumenting the IME owner. */
public final class KeyboardTransportInstrumentation extends Instrumentation {
  private static final String TARGET = "app.layergram.keyboardvalidation";
  private static final String HOST = "app.layergram.keyboardprobe";
  private static final ComponentName IME = new ComponentName(TARGET, "app.layergram.LayergramInputMethodService");
  private Bundle arguments;
  private Resources targetResources;
  private static final class QaFailure extends AssertionError {
    private QaFailure(String category) { super(category); }
  }

  @Override public void onCreate(Bundle values) { arguments = values; start(); }

  private void require(boolean condition, String category) {
    if (!condition) throw new QaFailure(category);
  }
  private String value(CharSequence value) { return value == null ? "" : value.toString(); }
  private boolean label(AccessibilityNodeInfo node, String label) {
    return label.equals(value(node.getText())) || label.equals(value(node.getContentDescription()));
  }
  private boolean target(AccessibilityNodeInfo node) {
    return TARGET.equals(value(node.getPackageName()));
  }
  private boolean messagesNavigation(AccessibilityNodeInfo node) {
    for (String text : new String[]{value(node.getText()), value(node.getContentDescription())}) {
      String first = text.split("\\n", 2)[0];
      if (first.equals("Messaggi") || first.equals("Mensajes") || first.equals("Messages")) return true;
    }
    return false;
  }
  private String string(String name) {
    int id = targetResources.getIdentifier(name, "string", "app.layergram");
    if (id == 0) id = targetResources.getIdentifier(name, "string", TARGET);
    require(id != 0, "targetResourceUnavailable");
    return targetResources.getString(id);
  }
  private List<AccessibilityNodeInfo> nodes() {
    List<AccessibilityNodeInfo> result = new ArrayList<>();
    int[] scanned = {0};
    long deadline = SystemClock.uptimeMillis() + 2000;
    for (android.view.accessibility.AccessibilityWindowInfo window : getUiAutomation().getWindows()) {
      if (window.getType() != AccessibilityWindowInfo.TYPE_INPUT_METHOD && !window.isFocused()) continue;
      AccessibilityNodeInfo root = window.getRoot();
      if (root == null || !root.refresh()) continue;
      String owner = value(root.getPackageName());
      if (TARGET.equals(owner) || HOST.equals(owner)) descend(root, result, 0, scanned, deadline);
    }
    return result;
  }
  private void descend(AccessibilityNodeInfo node, List<AccessibilityNodeInfo> result, int depth, int[] scanned, long deadline) {
    // Obtain a new window root on every poll. Refreshing every Flutter node
    // separately can wait on repeated cross-process IPC during a cold launch.
    if (node == null || depth > 24 || scanned[0]++ >= 1000 || SystemClock.uptimeMillis() > deadline) return;
    String owner = value(node.getPackageName());
    if (node.isVisibleToUser() && (TARGET.equals(owner) || HOST.equals(owner))) result.add(node);
    for (int i = 0; i < node.getChildCount(); i++) descend(node.getChild(i), result, depth + 1, scanned, deadline);
  }
  private AccessibilityNodeInfo waitNode(long millis, Predicate<AccessibilityNodeInfo> match, String failure) {
    long deadline = SystemClock.uptimeMillis() + millis;
    do {
      for (AccessibilityNodeInfo node : nodes()) if (match.test(node)) return node;
      SystemClock.sleep(100);
    } while (SystemClock.uptimeMillis() < deadline);
    throw new QaFailure(failure);
  }
  private AccessibilityNodeInfo byTargetLabel(String label, String failure) {
    return waitNode(15000, n -> target(n) && label(n, label), failure);
  }
  private void tap(AccessibilityNodeInfo node) {
    require(getUiAutomation().getWindows().stream().anyMatch(window ->
        window.getId() == node.getWindowId() &&
        (window.getType() == AccessibilityWindowInfo.TYPE_INPUT_METHOD || window.isFocused())),
        "controlWindowNoLongerFocused");
    Rect bounds = new Rect(); node.getBoundsInScreen(bounds);
    require(!bounds.isEmpty() && node.isVisibleToUser(), "controlNotVisible");
    long time = SystemClock.uptimeMillis();
    for (int action : new int[]{MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP}) {
      if (action == MotionEvent.ACTION_UP) SystemClock.sleep(35);
      MotionEvent event = MotionEvent.obtain(time, SystemClock.uptimeMillis(), action,
          bounds.exactCenterX(), bounds.exactCenterY(), 0);
      event.setSource(InputDevice.SOURCE_TOUCHSCREEN);
      // Queue the actual touch, then assert its rendered outcome. Waiting for
      // synchronous dispatch can stall the driver's cross-process IPC.
      try { require(getUiAutomation().injectInputEvent(event, false), "touchInjectionFailed"); }
      finally { event.recycle(); }
    }
    SystemClock.sleep(80);
  }
  private void stage(String code) {
    Bundle progress = new Bundle(); progress.putString("QA_KEYBOARD_STAGE", code); sendStatus(1, progress);
  }
  private void copyDeclaredCarrier(String expectedHash) {
    AccessibilityNodeInfo copy = waitNode(5000, n -> HOST.equals(value(n.getPackageName())) &&
        ("probe.transport.copyIncoming:" + expectedHash).equals(value(n.getContentDescription())),
        "declaredCarrierUnavailable");
    stage("declaredIncomingCarrierControlLocated");
    require(copy.performAction(AccessibilityNodeInfo.ACTION_CLICK), "declaredIncomingCopyFailed");
    stage("declaredIncomingCarrierCopied");
  }
  private String declaredCarrier(String expectedHash) throws Exception {
    File input = new File(getTargetContext().getNoBackupFilesDir(), "qa-transport-incoming.carrier");
    require(input.isFile() && input.length() > 3 && input.length() <= 4000, "declaredCarrierFileUnavailable");
    String carrier = new String(Files.readAllBytes(input.toPath()), StandardCharsets.UTF_8).trim();
    require(carrier.matches("(?:p1|m3|b3)\\.[A-Za-z0-9_-]+(?:\\n(?:p1|m3|b3)\\.[A-Za-z0-9_-]+)*"),
        "declaredCarrierFileInvalid");
    byte[] hash = MessageDigest.getInstance("SHA-256").digest(carrier.getBytes(StandardCharsets.UTF_8));
    StringBuilder actual = new StringBuilder();
    for (byte item : hash) actual.append(String.format("%02x", item & 255));
    require(expectedHash.equals(actual.toString()), "declaredCarrierFileHashMismatch");
    return carrier;
  }
  private boolean imeEnabled() {
    return getTargetContext().getPackageManager().getComponentEnabledSetting(IME) ==
        PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
  }
  private boolean imeSelected() {
    return IME.flattenToString().equals(Settings.Secure.getString(
        getTargetContext().getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD));
  }
  private void prepareOrdinaryHandoff(String carrier, int settleMillis) {
    getTargetContext().startActivity(new Intent().setComponent(new ComponentName(TARGET, "app.layergram.MainActivity"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
    stage("appActivated");
    Predicate<AccessibilityNodeInfo> root = n -> target(n) &&
        (label(n, "Più tardi") || label(n, "Más tarde") || label(n, "Later") ||
         label(n, "Indietro") || label(n, "Atrás") || label(n, "Back") ||
         messagesNavigation(n));
    AccessibilityNodeInfo surface = waitNode(90000, root, "unlockedAppNavigationUnavailable");
    stage("appNavigationControlLocated");
    if (label(surface, "Più tardi") || label(surface, "Más tarde") || label(surface, "Later")) {
      stage("observedNoticeDismissalStarted");
      require(surface.performAction(AccessibilityNodeInfo.ACTION_CLICK), "observedNoticeDismissalFailed");
      stage("observedNoticeDismissalIssued");
      waitNode(90000, n -> root.test(n) && !label(n, "Più tardi") && !label(n, "Más tarde") && !label(n, "Later"),
          "appNoticeStillVisible");
    }
    SystemClock.sleep(settleMillis);
    stage("ordinaryAppNavigationReady");
    Intent host = new Intent().setComponent(new ComponentName(HOST, HOST + ".TransportActivity"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
    if (carrier != null) host.putExtra("qa_carrier", carrier);
    getTargetContext().startActivity(host);
    stage("probeActivated");
    AccessibilityNodeInfo field = waitNode(15000, n -> HOST.equals(value(n.getPackageName())) &&
        "probe.transport.field".equals(value(n.getContentDescription())), "probeFieldUnavailable");
    stage("probeFieldLocated");
    tap(field);
    stage("probeFieldTouched");
    byTargetLabel(string("sk_status_ready"), "visibleActiveSessionUnavailable");
    stage("visibleActiveSession");
  }
  private void verifyReplyFs(String expectedContact) {
    tap(byTargetLabel(string("sk_reply_to"), "authenticatedReplyControlUnavailable"));
    stage("authenticatedReplyTapped");
    tap(byTargetLabel(string("sk_confirm_yes"), "recipientConfirmationUnavailable"));
    byTargetLabel(expectedContact, "authenticatedRecipientUnavailable");
    byTargetLabel(string("sk_fs_active"), "activeFsShieldUnavailable");
    waitNode(5000, n -> target(n) && value(n.getText()).matches("[1-9][0-9]*s"), "activeCountdownUnavailable");
    stage("activeFsAndCountdown");
  }

  @Override public void onStart() {
    Bundle result = new Bundle();
    try {
      require(arguments != null && TARGET.equals(arguments.getString("qaTarget")), "validationTargetRequired");
      require("YES".equals(arguments.getString("disposableDevice")), "disposableConsentRequired");
      require(HOST.equals(getTargetContext().getPackageName()), "offlineHostRequired");
      String expected = arguments.getString("qaExpectedPlaintext");
      require(expected != null && expected.matches("[a-z]{1,128}"), "safeQaPlaintextRequired");
      String locale = arguments.getString("qaLocale", "it");
      require(locale.matches("en|it|es"), "supportedQaLocaleRequired");
      android.content.Context resourceContext = getTargetContext().createPackageContext(TARGET, 0);
      Configuration configuration = new Configuration(resourceContext.getResources().getConfiguration());
      configuration.setLocale(Locale.forLanguageTag(locale));
      targetResources = resourceContext.createConfigurationContext(configuration).getResources();
      AccessibilityServiceInfo info = getUiAutomation().getServiceInfo();
      info.flags |= AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS | AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;
      getUiAutomation().setServiceInfo(info);
      String requested = arguments.getString("qaStage");
      stage("inspectionStarted");
      boolean preview = nodes().stream().anyMatch(n -> target(n) && label(n, expected));
      if ("inspect".equals(requested)) {
        List<AccessibilityNodeInfo> current = nodes();
        String state = "noVisibleKeyboard";
        for (String id : new String[]{"sk_status_ready", "sk_status_decoded", "sk_status_touch_to_unlock", "sk_status_unavailable"}) {
          if (nodes().stream().anyMatch(n -> target(n) && label(n, string(id)))) state = id;
        }
        result.putString("QA_KEYBOARD_VISIBLE_STATE", state);
        result.putString("QA_KEYBOARD_COMPONENT", imeEnabled() ? "enabled" : "disabled");
        result.putString("QA_KEYBOARD_SELECTION", imeSelected() ? "validationIme" : "otherIme");
        result.putString("QA_KEYBOARD_EXACT_PREVIEW", preview ? "present" : "absent");
        result.putInt("QA_TARGET_VISIBLE_NODE_COUNT", (int) current.stream().filter(this::target).count());
        result.putString("QA_APP_MESSAGES_LABEL", current.stream().anyMatch(n -> target(n) && messagesNavigation(n)) ? "present" : "absent");
        String[] known = {"Più tardi", "Más tarde", "Later", "Indietro", "Atrás", "Back", "Sblocca",
            "Crea identità", "Ripristina identità", "La tua nuova identità post-quantum", "Tastiera di sistema"};
        List<String> labels = new ArrayList<>();
        for (String text : known) if (current.stream().anyMatch(n -> target(n) && label(n, text))) labels.add(text);
        result.putString("QA_APP_KNOWN_CONTROLS", labels.toString());
        result.putString("QA_APP_NODE_SHAPES", current.stream().filter(this::target).map(n ->
            value(n.getClassName()) + ":t" + value(n.getText()).length() + ":d" + value(n.getContentDescription()).length())
            .collect(java.util.stream.Collectors.joining(";")));
      } else if ("handoff".equals(requested)) {
        require(imeEnabled(), "validationImeDisabled");
        require(imeSelected(), "validationImeNotSelected");
        // Observe the ordinary handoff as soon as navigation renders. No
        // carrier, Paste, extra warm-up delay or IME-owner instrumentation.
        prepareOrdinaryHandoff(null, 0);
        long until = SystemClock.uptimeMillis() + 20000;
        int observations = 0;
        while (SystemClock.uptimeMillis() < until) {
          byTargetLabel(string("sk_status_ready"), "activeSessionLostDuringObservation");
          waitNode(2000, n -> target(n) && value(n.getText()).matches("[1-9][0-9]*s"),
              "activeCountdownUnavailable");
          observations++;
          SystemClock.sleep(750);
        }
        require(observations >= 10, "insufficientHandoffObservation");
        result.putInt("QA_HANDOFF_OBSERVATIONS", observations);
        result.putString("QA_PHYSICAL_HANDOFF", "visibleActiveSessionAndCountdown20s");
      } else if ("decode".equals(requested)) {
        String contact = arguments.getString("qaExpectedContact");
        require(contact != null && contact.length() > 0 && contact.length() <= 64 &&
            !contact.contains("\r") && !contact.contains("\n"),
            "qaPublicContactRequired");
        require(imeEnabled(), "validationImeDisabled");
        require(imeSelected(), "validationImeNotSelected");
        String expectedHash = arguments.getString("qaCarrierSha256");
        require(expectedHash != null && expectedHash.matches("[a-f0-9]{64}"), "declaredCarrierHashRequired");
        File attempted = new File(getTargetContext().getNoBackupFilesDir(), "qa-paste-attempt-" + expectedHash);
        if (preview) {
          byTargetLabel(string("sk_status_decoded"), "decodedStatusUnavailable");
          stage("existingExactDecodedPreview");
        } else {
          require(!attempted.exists(), "carrierAlreadyAttempted");
          prepareOrdinaryHandoff(declaredCarrier(expectedHash), 4000);
          copyDeclaredCarrier(expectedHash);
          AccessibilityNodeInfo paste = byTargetLabel(string("sk_action_paste_decode"), "pasteControlUnavailable");
          require(attempted.createNewFile(), "carrierAttemptMarkerUnavailable");
          stage("singlePasteIssued");
          tap(paste);
          byTargetLabel(string("sk_status_decoded"), "decodedStatusUnavailable");
          byTargetLabel(expected, "exactDecodedPlaintextUnavailable");
          stage("exactDecodedPlaintext");
        }
        verifyReplyFs(contact);
        result.putString("QA_PHYSICAL_DECODE", "exactPlaintextAndActiveFS");
      } else throw new QaFailure("unsupportedStage");
      finish(-1, result);
    } catch (Throwable failure) {
      // Framework exceptions may contain user text. Export only fixed categories.
      result.putString("QA_KEYBOARD_FAILURE", failure instanceof QaFailure ? value(failure.getMessage()) : failure.getClass().getSimpleName());
      finish(0, result);
    }
  }
}
