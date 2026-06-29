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

/// Forward Secrecy localization key bundle.
///
/// Key groups (spec §9.5 Localization Rule):
///
///   security.fs.status.*      — Compact status labels (for chat icon tooltip).
///   security.fs.warning.*     — Warnings shown before mode changes.
///   security.fs.action.*      — Action button labels.
///   security.fs.info.*        — Info modal texts.
///   security.fs.maximum.*     — Maximum / Strict FS specific strings.
///   security.passphrase.*     — Passphrase-context FS strings.
///   security.contact.state.*  — Contact-card state descriptions.
///
/// Runtime translations live in `assets/translations/*.json`.
///
/// This bundle is an English source inventory for tests and release gates; it is
/// not registered by the app at startup.
class FsStringsBundle {
  FsStringsBundle._();

  static const Map<String, Map<String, String>> bundle = {
    'en': _en,
  };

  // ── English (source of truth) ─────────────────────────────────────────────

  static const Map<String, String> _en = {
    // Status
    'security.fs.status.legacy': 'Standard encryption',
    'security.fs.status.upgrading': 'Upgrading security…',
    'security.fs.status.active': 'Forward Secrecy active',
    'security.fs.status.strict': 'Maximum Forward Secrecy',
    'security.fs.status.strict_pending': 'Maximum FS requested',
    'security.fs.status.suspended': 'Security paused',
    'security.fs.status.broken': 'Security warning',

    // Warnings
    'security.fs.warning.recoverability':
        'If you lose access to this device, messages protected by Forward Secrecy cannot be recovered.',
    'security.fs.warning.device_bound':
        'Maximum Forward Secrecy links this conversation to your current device. Switching devices will require re-establishing the session.',
    'security.fs.warning.pending_activation':
        'Forward Secrecy upgrade is pending. Send a message to complete the handshake.',
    'security.fs.warning.fallback_allowed':
        'Forward Secrecy messages are ratchet-only. Messages are not duplicated with the legacy identity key.',
    'security.fs.warning.no_silent_downgrade':
        'Maximum Forward Secrecy is active. Messages cannot be sent without a confirmed secure channel.',

    // Multi-device (§7.9)
    'security.fs.new_device_detected':
        'New device or session detected for this contact. A new secure session is being negotiated.',

    // Actions
    'security.fs.message_lost':
        'This message was encrypted with a previous session and cannot be decrypted.',
    'security.message_not_for_me': 'No decodable Layergram message found.',
    'security.fs.message_expired_fs': 'Forward Secrecy message',
    'security.fs.session_reset_done':
        'Secure session reset. A new session will be negotiated automatically.',
    'security.fs.action.retry': 'Retry upgrade',
    'security.fs.action.reset': 'Reset session',
    'security.fs.action.request_maximum': 'Request Maximum FS',
    'security.fs.action.disable_strict': 'Disable Maximum FS',
    'security.fs.action.send_anyway': 'Send with standard encryption',

    // Send blocking errors
    'security.fs.error.session_broken':
        'This secure session is broken and cannot be used.',
    'security.fs.error.device_repair_required':
        'Maximum Forward Secrecy requires device repair before sending.',
    'security.fs.error.unexpected_device':
        'Unexpected device detected. Repair the secure session before sending.',
    'security.fs.error.sending_blocked':
        'Maximum Forward Secrecy prevents sending in the current state.',

    // Info modal
    'security.fs.info.title': 'Security with this contact',
    'security.fs.info.legacy_description':
        'Messages are encrypted end-to-end. Forward Secrecy will activate automatically as you exchange messages.',
    'security.fs.info.active_description':
        'Forward Secrecy is active. Each message uses a unique key derived from an ephemeral handshake.',
    'security.fs.info.active_advantage':
        'Past messages remain protected even if your keys are later compromised.',
    'security.fs.info.strict_description':
        'Maximum Forward Secrecy is active and bound to this device. '
            'Messages can only be sent and received through this confirmed secure channel.',
    'security.fs.info.broken_description':
        'The secure channel could not be verified. No messages have been sent or received in this state.',
    'security.fs.info.upgrading_description':
        'Forward Secrecy is upgrading automatically. Continue exchanging messages to complete the secure session.',

    // Maximum / Strict FS
    'security.fs.maximum.confirm_title': 'Enable Maximum Forward Secrecy?',
    'security.fs.maximum.confirm_body':
        'This will bind the conversation to your current device. '
            'You will need to repeat this process if you switch devices.',
    'security.fs.maximum.confirm_button': 'Enable',
    'security.fs.maximum.cancel_button': 'Cancel',
    'security.fs.maximum.pending_notice':
        'Waiting for {contact} to confirm Maximum Forward Secrecy.',
    'security.fs.maximum.setup_title': 'Maximum FS setup',
    'security.fs.maximum.setup_outgoing_body':
        'This will send only a setup message. Your message text will stay here. '
            'Take turns exchanging setup messages until Maximum FS is active, then send your message again.',
    'security.fs.maximum.setup_incoming_body':
        'This was only a setup message. Take turns exchanging setup messages until Maximum FS is active. '
            'No message text was sent yet.',
    'security.fs.maximum.setup_send_button': 'Send setup',
    'security.fs.maximum.setup_ack_button': 'I understand',

    // Info modal — mode-specific descriptions (§14.4)
    'security.fs.info.legacy_advantages':
        'Maximum compatibility with all your devices. Works across multiple devices simultaneously. Forward Secrecy upgrades automatically when supported.',
    'security.fs.info.legacy_keep_in_mind':
        'These messages are not yet protected by Forward Secrecy. Upgrade happens automatically as you exchange messages.',
    'security.fs.info.upgrading_advantages':
        'Improves protection automatically. Keeps compatibility across all your devices.',
    'security.fs.info.upgrading_keep_in_mind':
        'Forward Secrecy applies only after the secure session is established. This happens automatically by exchanging messages.',
    'security.fs.info.active_keep_in_mind':
        'If this contact changes device or reinstalls Layergram, a new secure session may be needed.',
    'security.fs.info.strict_advantages':
        'Strongest protection for this contact. Prevents silent downgrade for user messages.',
    'security.fs.info.strict_keep_in_mind':
        'If either person changes device, reinstalls Layergram, or loses session state, sending may pause until the session is repaired. Some old messages may not be recoverable.',
    'security.fs.info.strict_requested_description':
        'You requested Maximum Forward Secrecy for this contact. It is not active yet — Layergram is waiting for a confirmed secure session.',
    'security.fs.info.strict_requested_advantages':
        'Prepares this contact for the strongest device-bound mode.',
    'security.fs.info.strict_requested_keep_in_mind':
        'You and this contact should agree to use the expected device(s). Messages may not be readable from other devices until a new secure session is established.',
    'security.fs.info.broken_keep_in_mind':
        'Repair or re-establish the secure session before sending.',
    'security.fs.info.suspended_description':
        'A previous Forward Secure session cannot currently be used. Layergram may retry negotiation.',
    'security.fs.info.suspended_keep_in_mind':
        'Send a message to trigger a new secure session upgrade.',

    // Info modal — actions (§14.4)
    'security.fs.info.action_close': 'Close',
    'security.fs.info.action_view_details': 'View details',
    'security.fs.info.section_advantages': 'Advantages',
    'security.fs.info.section_keep_in_mind': 'Keep in mind',

    // Progress indicator — message exchanges remaining before FS active
    'security.fs.progress.one_more_exchange':
        'One more message exchange to activate',
    'security.fs.progress.exchanges_remaining':
        'About {n} message exchanges to activate',

    // Recoverability warning (§14.6.1)
    'security.fs.warning.recoverability_title':
        'Some messages may not be readable later',
    'security.fs.warning.recoverability_body':
        'This mode improves protection by reducing how long old keys or readable history remain available. '
            'If you delete messages, reset sessions, reinstall Layergram, or clean the encrypted archive, '
            'some older messages may not be recoverable even if you still have the correct passphrase.',
    'security.fs.warning.recoverability_confirm':
        'I understand that some old messages may become unrecoverable.',

    // Device-bound warning (§14.6.2)
    'security.fs.warning.device_bound_title':
        'This mode is bound to verified devices',
    'security.fs.warning.device_bound_body':
        'Use it only if you and this contact agree to use the expected device(s). '
            'If either person changes device, reinstalls Layergram, resets sessions, or uses an older version, '
            'messages may not be readable until a new secure session is established.',
    'security.fs.warning.device_bound_confirm':
        'I have agreed this with the contact and understand that this mode is device-bound.',

    // Pending activation (§14.6.3)
    'security.fs.warning.pending_title': 'Maximum FS requested',
    'security.fs.warning.pending_body':
        'Maximum FS is not active yet. Layergram is waiting for a confirmed secure session. '
            'Until confirmation, Layergram can send setup messages but not your message text.',

    // Historic fallback warning (§14.6.4)
    'security.fs.warning.fallback_body':
        'Legacy FS fallback is disabled. If an older message contains fallback material, Layergram will not use it without a matching FS session.',

    // Per-device/session labels (§14.4)
    'security.fs.device.session_label': 'Session {n}',
    'security.fs.device.unknown': 'Unknown session',
    'security.fs.device.fallback_allowed': 'Fallback: disabled',
    'security.fs.device.fallback_not_allowed': 'Fallback: disabled',
    'security.fs.device.mode_base': 'Mode: Base',
    'security.fs.device.mode_advanced': 'Mode: Advanced',
    'security.fs.device.mode_strict': 'Mode: Strict',

    // Contact-card section header (§14.4)
    'security.fs.card.title': 'Security for this context',
    'security.fs.card.no_sessions': 'No active sessions with this contact.',
    'security.fs.card.explanation_prefix':
        'Forward Secrecy activates automatically as you exchange messages. '
            'It protects only messages sent after the secure session is established. '
            'Messages sent before this upgrade remain protected by the previous Layergram encryption model.',

    // Passphrase context
    'security.passphrase.fs_active': 'Passphrase Forward Secrecy active',
    'security.passphrase.fs_inactive': 'Passphrase context not active',
    'security.passphrase.settings_visible_note':
        'These settings are only available while your passphrase context is active.',

    // Security mode selector (§14.3)
    'security.fs.mode.sheet_title': 'Security mode',
    'security.fs.mode.sheet_subtitle':
        'Choose the Forward Secrecy level for this contact.',
    'security.fs.mode.base_title': 'Base',
    'security.fs.mode.base_desc': 'Standard encryption. Maximum compatibility.',
    'security.fs.mode.advanced_title': 'Advanced',
    'security.fs.mode.advanced_desc':
        'Automatic Forward Secrecy when supported. No legacy content fallback.',
    'security.fs.mode.strict_title': 'Maximum',
    'security.fs.mode.strict_desc':
        'Strongest protection. Device-bound, no fallback.',
    'security.fs.mode.confirm_button': 'Apply',
    'security.fs.mode.cancel_button': 'Cancel',
    'security.fs.mode.changed_snackbar': 'Security mode updated.',
    'security.fs.action.change_mode': 'Change security mode',
    'security.fs.mode.current_label': 'Current mode: {mode}',

    // Contact card state
    'security.contact.state.primary_context': 'Primary identity',
    'security.contact.state.passphrase_context': 'Passphrase identity',
    'security.contact.state.session_id': 'Session: {sessionId}',
    'security.contact.state.no_sessions': 'No active sessions',

    // Message-level security classification (§14.4)
    'security.fs.cls.legacy': 'Standard encryption',
    'security.fs.cls.legacy.desc':
        'This message uses standard Layergram identity encryption. Forward Secrecy was not active.',
    'security.fs.cls.pre_fs': 'Pre-FS message',
    'security.fs.cls.pre_fs.desc':
        'This message was sent before Forward Secrecy was established and is not protected by FS.',
    'security.fs.cls.negotiation': 'FS negotiation',
    'security.fs.cls.negotiation.desc':
        'This message was part of the Forward Secrecy handshake negotiation.',
    'security.fs.cls.fs_fallback': 'Degraded FS',
    'security.fs.cls.fs_fallback.desc':
        'This older message included legacy fallback material and is not treated as full Forward Secrecy.',
    'security.fs.cls.fs_only': 'FS only',
    'security.fs.cls.fs_only.desc':
        'This message is protected by Forward Secrecy only. It cannot be decrypted with the legacy key.',
    'security.fs.cls.strict': 'Maximum FS',
    'security.fs.cls.strict.desc':
        'This message is protected by Maximum Forward Secrecy. Legacy fallback is disabled.',
    'security.fs.cls.failed': 'FS failed',
    'security.fs.cls.failed.desc':
        'Forward Secrecy decryption failed. The session may have been reset or the device changed.',
    'security.fs.cls.unknown': 'Unknown',
    'security.fs.cls.unknown.desc':
        'The security classification of this message could not be determined.',

    // Passphrase settings (§11.2–§11.5, §14.2)
    'security.pp.section_title': 'Security for this identity',
    'security.pp.section_subtitle':
        'Settings specific to this passphrase-derived identity.',
    'security.pp.timeout_title': 'Auto-expel passphrase',
    'security.pp.timeout_subtitle':
        'Choose a shorter timeout for stronger protection.',
    'security.pp.timeout_30s': '30 seconds',
    'security.pp.timeout_1m': '1 minute',
    'security.pp.timeout_2m': '2 minutes',
    'security.pp.timeout_5m': '5 minutes',
    'security.pp.timeout_10m': '10 minutes',
    'security.pp.timeout_manual': 'Manual only',
    'security.pp.screen_lock_title': 'Expel on screen lock',
    'security.pp.screen_lock_subtitle':
        'Destroy passphrase keys immediately when the screen locks.',
    'security.pp.history_title': 'History for this identity',
    'security.pp.history_keep': 'Keep encrypted history',
    'security.pp.history_volatile': 'Volatile history',
    'security.pp.history_ephemeral': 'Ephemeral session',
    'security.pp.fs_persistence_title': 'Forward Secrecy state',
    'security.pp.fs_persistent': 'Persistent',
    'security.pp.fs_ephemeral': 'Ephemeral',
    'security.pp.expel_now': 'Expel identity now',

    // §14.5 Warnings
    'security.warn.active_passphrase':
        'While this identity is unlocked, its keys exist in device memory. Layergram does not protect against seizure or compromise while the identity is actively unlocked.',
    'security.warn.passphrase_fs':
        'The passphrase restores this identity. It may not restore old Forward Secure messages if the required session state was deleted or expired.',
    'security.warn.volatile_history':
        'This mode is designed to reduce future recoverability. Old messages may not be readable again, even with the correct passphrase.',
    'security.warn.ephemeral_session':
        'FS state and history are RAM-only. FS restarts after every passphrase expulsion. No messages or session state will survive.',
    'security.warn.recoverability_title': 'Reduced recoverability',
    'security.warn.recoverability_body':
        'This mode improves protection by reducing how long old keys or readable history remain available. If you delete messages, reset sessions, expel this identity, reinstall Layergram, lose local state, or clean the encrypted archive, some older messages may not be recoverable even if you still have the original Layergram text or the correct passphrase.',
    'security.warn.recoverability_confirm':
        'I understand that some old messages may become unrecoverable.',

    // §13.7 Clean undecryptable data
    'security.cleanup.title': 'Clean undecryptable data',
    'security.cleanup.subtitle':
        'Remove residual data that cannot be decrypted.',
    'security.cleanup.dialog_title': 'Clean undecryptable data',
    'security.cleanup.dialog_body':
        'This may permanently delete old encrypted archives, abandoned identity data, passphrase-derived records, security sessions, and other data that Layergram cannot currently decrypt.',
    'security.cleanup.confirm_checkbox':
        'I understand this action is irreversible.',
    'security.cleanup.confirm_button': 'Clean now',
    'security.cleanup.done': 'Undecryptable data cleaned.',
  };
}
