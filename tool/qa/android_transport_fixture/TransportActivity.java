// Copyright 2026 Layergram. Licensed under the Apache License, Version 2.0.
package app.layergram.keyboardprobe;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Offline transport surface. Contains no identity, vault, crypto or networking. */
public final class TransportActivity extends Activity {
  private EditText field;
  private ClipboardManager clipboard;
  private Button copyIncoming;
  private String incoming;
  @Override public void onCreate(Bundle state) {
    super.onCreate(state);
    clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
    LinearLayout layout = new LinearLayout(this);
    layout.setOrientation(LinearLayout.VERTICAL);
    layout.setPadding(12, 12, 12, 12);
    field = new EditText(this);
    field.setHint("Offline carrier");
    field.setContentDescription("probe.transport.field");
    field.setSingleLine(false);
    field.setMinLines(3);
    layout.addView(field, new LinearLayout.LayoutParams(-1, 180));
    Button copy = new Button(this);
    copy.setText("Copy carrier");
    copy.setContentDescription("probe.transport.copy");
    copy.setOnClickListener(v -> clipboard.setPrimaryClip(ClipData.newPlainText("QA carrier", field.getText())));
    layout.addView(copy);
    copyIncoming = new Button(this);
    copyIncoming.setText("Copy incoming carrier");
    copyIncoming.setVisibility(android.view.View.GONE);
    copyIncoming.setOnClickListener(v -> {
      if (incoming != null) clipboard.setPrimaryClip(ClipData.newPlainText("QA incoming carrier", incoming));
    });
    layout.addView(copyIncoming);
    Button send = new Button(this);
    send.setText("Send in offline transport");
    send.setContentDescription("probe.transport.send");
    send.setOnClickListener(v -> field.setText(""));
    layout.addView(send);
    setContentView(layout);
    acceptQaCarrier(getIntent());
  }
  @Override protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    setIntent(intent);
    acceptQaCarrier(intent);
  }
  private void acceptQaCarrier(Intent intent) {
    // Explicit QA input, restricted to a carrier. Never read arbitrary app data.
    String carrier = intent.getStringExtra("qa_carrier");
    if (carrier != null && carrier.length() <= 4000 && carrier.matches(
        "(?:p1|m3|b3)\\.[A-Za-z0-9_-]+(?:\\n(?:p1|m3|b3)\\.[A-Za-z0-9_-]+)*")) {
      incoming = carrier;
      copyIncoming.setContentDescription("probe.transport.copyIncoming:" + carrierDigest(carrier));
      copyIncoming.setVisibility(android.view.View.VISIBLE);
      clipboard.setPrimaryClip(ClipData.newPlainText("QA incoming carrier", carrier));
    }
    field.requestFocus();
    ((android.view.inputmethod.InputMethodManager) getSystemService(INPUT_METHOD_SERVICE))
        .showSoftInput(field, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT);
  }
  private String carrierDigest(String carrier) {
    try {
      byte[] hash = MessageDigest.getInstance("SHA-256").digest(carrier.getBytes(StandardCharsets.UTF_8));
      StringBuilder result = new StringBuilder();
      for (byte item : hash) result.append(String.format("%02x", item & 255));
      return result.toString();
    } catch (java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException("SHA256Unavailable"); }
  }
}
