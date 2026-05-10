// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Additional FS control message types beyond the core handshake.
///
/// Spec reference: §9.2 — FS extension types.
///
/// Recommended extension types:
/// ```text
/// fs_init                — core handshake (in fs_handshake.dart)
/// fs_reply               — core handshake (in fs_handshake.dart)
/// fs_confirm             — core handshake (in fs_handshake.dart)
/// fs_ack                 — optional confirmation from responder
/// fs_simultaneous_notice — tie-break notification
/// fs_suspend             — session suspension signaling
/// fs_reset               — session reset signaling
/// fs_downgrade_notice    — downgrade notification
/// ```

import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Optional FS_ACK message from responder (B) after verifying FS_CONFIRM.
///
/// Spec §8.3.8:
/// > B may optionally send an `fs_ack`:
/// > `HMAC-SHA256(confirmKey, TH || "B acknowledges")`
///
/// `fs_ack` is an optimization/extra confirmation, not a required step.
class FsAckMessage {
  const FsAckMessage({
    required this.initId,
    required this.replyId,
    required this.ackTag,
  });

  final String initId;
  final String replyId;

  /// HMAC-SHA256(confirmKey, TH || "B acknowledges"), base64url
  final String ackTag;

  Map<String, dynamic> toJson() => {
    'v': 1,
    'type': 'fs_ack',
    'initId': initId,
    'replyId': replyId,
    'ackTag': ackTag,
  };

  factory FsAckMessage.fromJson(Map<String, dynamic> j) => FsAckMessage(
    initId: j['initId'] as String,
    replyId: j['replyId'] as String,
    ackTag: j['ackTag'] as String,
  );

  /// Computes the ack tag using the confirm key and transcript hash.
  static Future<Uint8List> computeAckTag(
    Uint8List confirmKey,
    Uint8List transcriptHash,
  ) async {
    final hmac = Hmac.sha256();
    final data = Uint8List.fromList([
      ...transcriptHash,
      ...'B acknowledges'.codeUnits,
    ]);
    final mac = await hmac.calculateMac(
      data,
      secretKey: SecretKey(confirmKey),
    );
    return Uint8List.fromList(mac.bytes);
  }
}

/// Notification sent during simultaneous FS_INIT tie-breaking.
///
/// When a tie-break results in one party yielding, this message can be
/// sent (without user content) to inform the other party.
///
/// Spec §8.3.4:
/// > If local fs_init wins: [...] send fs_simultaneous_notice without
/// > user content
class FsSimultaneousNoticeMessage {
  const FsSimultaneousNoticeMessage({
    required this.winningInitId,
    required this.losingInitId,
  });

  /// The initId that won the tie-break (lexicographically smaller canonical).
  final String winningInitId;

  /// The initId that lost the tie-break.
  final String losingInitId;

  Map<String, dynamic> toJson() => {
    'v': 1,
    'type': 'fs_simultaneous_notice',
    'winningInitId': winningInitId,
    'losingInitId': losingInitId,
  };

  factory FsSimultaneousNoticeMessage.fromJson(Map<String, dynamic> j) =>
      FsSimultaneousNoticeMessage(
        winningInitId: j['winningInitId'] as String,
        losingInitId: j['losingInitId'] as String,
      );
}

/// Session suspension message.
///
/// Sent when a session is suspended (e.g., partner key changed,
/// ratchet exhausted, device change detected).
///
/// Spec §8.8: fs_broken recovery path.
class FsSuspendMessage {
  const FsSuspendMessage({
    required this.sessionId,
    required this.reason,
  });

  /// The session ID being suspended.
  final String sessionId;

  /// Human-readable reason for suspension.
  final String reason;

  Map<String, dynamic> toJson() => {
    'v': 1,
    'type': 'fs_suspend',
    'sessionId': sessionId,
    'reason': reason,
  };

  factory FsSuspendMessage.fromJson(Map<String, dynamic> j) =>
      FsSuspendMessage(
        sessionId: j['sessionId'] as String,
        reason: j['reason'] as String,
      );
}

/// Session reset message.
///
/// Signals that the local FS session state has been reset and a new
/// handshake is needed.
///
/// In Opportunistic mode, a new fs_init is attached invisibly.
/// In Strict mode, the user must confirm before sending.
class FsResetMessage {
  const FsResetMessage({
    required this.previousSessionId,
    required this.reason,
  });

  /// The previous session ID that was reset.
  final String previousSessionId;

  /// Reason for the reset.
  final String reason;

  Map<String, dynamic> toJson() => {
    'v': 1,
    'type': 'fs_reset',
    'previousSessionId': previousSessionId,
    'reason': reason,
  };

  factory FsResetMessage.fromJson(Map<String, dynamic> j) =>
      FsResetMessage(
        previousSessionId: j['previousSessionId'] as String,
        reason: j['reason'] as String,
      );
}

/// Downgrade notification message.
///
/// Sent when a previously FS-capable contact/device sends a legacy
/// message unexpectedly. The notification is informational only.
///
/// Spec §7.6: If future messages from the same contact/device fall back
/// to legacy unexpectedly, show an internal or visible warning.
class FsDowngradeNoticeMessage {
  const FsDowngradeNoticeMessage({
    required this.previousSessionId,
    required this.previousLevel,
  });

  /// The session ID of the previously active FS session.
  final String previousSessionId;

  /// The previous security level (e.g. "fs_only", "fs_with_fallback").
  final String previousLevel;

  Map<String, dynamic> toJson() => {
    'v': 1,
    'type': 'fs_downgrade_notice',
    'previousSessionId': previousSessionId,
    'previousLevel': previousLevel,
  };

  factory FsDowngradeNoticeMessage.fromJson(Map<String, dynamic> j) =>
      FsDowngradeNoticeMessage(
        previousSessionId: j['previousSessionId'] as String,
        previousLevel: j['previousLevel'] as String,
      );
}

/// All valid FS extension type strings.
///
/// Used to dispatch incoming `x.fs` messages to the correct parser.
class FsExtensionType {
  FsExtensionType._();

  static const String fsInit = 'fs_init';
  static const String fsReply = 'fs_reply';
  static const String fsConfirm = 'fs_confirm';
  static const String fsAck = 'fs_ack';
  static const String fsSimultaneousNotice = 'fs_simultaneous_notice';
  static const String fsSuspend = 'fs_suspend';
  static const String fsReset = 'fs_reset';
  static const String fsDowngradeNotice = 'fs_downgrade_notice';

  static const Set<String> all = {
    fsInit,
    fsReply,
    fsConfirm,
    fsAck,
    fsSimultaneousNotice,
    fsSuspend,
    fsReset,
    fsDowngradeNotice,
  };
}
