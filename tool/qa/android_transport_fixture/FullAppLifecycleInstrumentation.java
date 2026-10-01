// Copyright 2026 Layergram. Licensed under the Apache License, Version 2.0.
package app.layergram.keyboardprobe;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.Instrumentation;
import android.app.UiAutomation;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.accessibility.AccessibilityNodeInfo;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** UI-only gates for the separate complete-app removal copy. Never exports its seed. */
public final class FullAppLifecycleInstrumentation extends Instrumentation {
  private static final String TARGET = "app.layergram.sckasmoke";
  private Bundle arguments;

  @Override public void onCreate(Bundle values) {
    arguments = values;
    start();
  }

  private List<AccessibilityNodeInfo> nodes() {
    List<AccessibilityNodeInfo> result = new ArrayList<>();
    for (android.view.accessibility.AccessibilityWindowInfo window : getUiAutomation().getWindows()) {
      descend(window.getRoot(), result);
    }
    return result;
  }

  private void descend(AccessibilityNodeInfo node, List<AccessibilityNodeInfo> result) {
    if (node == null || !node.refresh()) return;
    if (TARGET.contentEquals(node.getPackageName() == null ? "" : node.getPackageName())) result.add(node);
    for (int i = 0; i < node.getChildCount(); i++) descend(node.getChild(i), result);
  }

  private String value(CharSequence value) { return value == null ? "" : value.toString(); }
  private boolean label(AccessibilityNodeInfo node, String label) {
    return label.equals(value(node.getText())) || label.equals(value(node.getContentDescription()));
  }
  private void require(boolean condition, String category) {
    if (!condition) throw new AssertionError(category);
  }

  @Override public void onStart() {
    Bundle result = new Bundle();
    try {
      require(arguments != null && TARGET.equals(arguments.getString("qaTarget")), "isolatedTargetRequired");
      require("YES".equals(arguments.getString("disposableDevice")), "disposableConsentRequired");
      UiAutomation ui = getUiAutomation();
      AccessibilityServiceInfo service = ui.getServiceInfo();
      service.flags |= AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS;
      ui.setServiceInfo(service);
      String stage = arguments.getString("qaStage");
      List<AccessibilityNodeInfo> current = nodes();
      require(!current.isEmpty(), "isolatedAppNotVisible");
      if ("confirmGeneratedIdentity".equals(stage)) {
        require(current.stream().anyMatch(n -> label(n, "Proteggi la tua chiave privata")), "recoveryDialogRequired");
        String[] words = null;
        AccessibilityNodeInfo field = null;
        int index = -1;
        for (AccessibilityNodeInfo node : current) {
          for (String text : new String[]{value(node.getText()), value(node.getContentDescription())}) {
            String[] candidate = text.trim().split("\\s+");
            if ((candidate.length == 12 || candidate.length == 24) && text.matches("[a-z]+(?:\\s+[a-z]+)+")) {
              require(words == null, "ambiguousTestSeed"); words = candidate;
            }
          }
          if ("android.widget.EditText".contentEquals(node.getClassName())) {
            require(field == null, "ambiguousConfirmationField"); field = node;
            String hint = value(node.getHintText());
            Matcher match = Pattern.compile("Parola #(\\d+)").matcher(hint);
            if (match.find()) index = Integer.parseInt(match.group(1));
          }
        }
        require(words != null && field != null, "testSeedOrFieldUnavailable");
        require(index >= 1 && index <= words.length, "confirmationHintUnavailable");
        Bundle input = new Bundle();
        input.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, words[index - 1]);
        require(field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, input), "confirmationInputFailed");
        java.util.Arrays.fill(words, ""); input.clear();
        AccessibilityNodeInfo confirm = current.stream().filter(n -> label(n, "L'ho trascritta su carta")).findFirst().orElse(null);
        require(confirm != null && confirm.performAction(AccessibilityNodeInfo.ACTION_CLICK), "confirmationActionFailed");
        boolean created = false;
        for (int i = 0; i < 100 && !created; i++) {
          SystemClock.sleep(100);
          created = nodes().stream().anyMatch(n -> label(n, "Identità creata"));
        }
        require(created, "identityCreationNotObserved");
        result.putString("QA_FULL_APP_IDENTITY", "createdThroughRecoveryConfirmation");
      } else if ("assertIdentity".equals(stage)) {
        String name = arguments.getString("qaExpectedName");
        String fingerprint = arguments.getString("qaExpectedFingerprint");
        require("QA_Reinstall_Isolated".equals(name), "isolatedTestNameRequired");
        require(fingerprint != null && fingerprint.matches("(?:[A-F0-9]{4}-){7}[A-F0-9]{4}"), "publicFingerprintRequired");
        if (current.stream().anyMatch(n -> label(n, "La tua nuova identità post-quantum"))) {
          AccessibilityNodeInfo later = current.stream().filter(n -> label(n, "Più tardi")).findFirst().orElse(null);
          require(later != null && later.performAction(AccessibilityNodeInfo.ACTION_CLICK), "migrationNoticeDismissalFailed");
          for (int i = 0; i < 100; i++) {
            SystemClock.sleep(100); current = nodes();
            if (current.stream().noneMatch(n -> label(n, "La tua nuova identità post-quantum"))) break;
          }
        }
        if (current.stream().noneMatch(n -> label(n, name))) {
          AccessibilityNodeInfo tab = current.stream().filter(n -> n.isClickable() &&
              value(n.getContentDescription()).startsWith("La mia identità\n")).findFirst().orElse(null);
          require(tab != null && tab.performAction(AccessibilityNodeInfo.ACTION_CLICK), "identityTabUnavailable");
          for (int i = 0; i < 100; i++) {
            SystemClock.sleep(100); current = nodes();
            if (current.stream().anyMatch(n -> label(n, name))) break;
          }
        }
        require(current.stream().anyMatch(n -> label(n, name)), "expectedIdentityNameAbsent");
        require(current.stream().anyMatch(n -> label(n, "Impronta: " + fingerprint)), "expectedIdentityFingerprintAbsent");
        result.putString("QA_FULL_APP_IDENTITY", "samePublicNameAndFingerprint");
      } else if ("assertFreshSetup".equals(stage)) {
        require(current.stream().anyMatch(n -> label(n, "Crea identità")), "freshCreationControlAbsent");
        require(current.stream().anyMatch(n -> label(n, "Ripristina identità")), "freshRestoreControlAbsent");
        require(current.stream().noneMatch(n -> label(n, "QA_Reinstall_Isolated")), "oldIdentityStillVisible");
        result.putString("QA_FULL_APP_REINSTALL", "freshSetupRequired");
      } else {
        throw new AssertionError("unsupportedStage");
      }
      finish(-1, result);
    } catch (Throwable failure) {
      // Exceptions may reference text supplied by the framework. Export only fixed categories.
      result.putString("QA_FULL_APP_FAILURE", failure instanceof AssertionError ? value(failure.getMessage()) : failure.getClass().getSimpleName());
      finish(0, result);
    }
  }
}
