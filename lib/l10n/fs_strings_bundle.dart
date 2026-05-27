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
/// Usage:
/// ```dart
/// AppStrings.registerStrings(FsStringsBundle.bundle);
/// ```
///
/// Place the call in `main.dart` alongside other bundle registrations.
///
/// All non-English locales fall back to English if a key is absent.
class FsStringsBundle {
  FsStringsBundle._();

  static const Map<String, Map<String, String>> bundle = {
    'en': _en,
    'it': _it,
    'es': _es,
    'de': _de,
    'fr': _fr,
    'pt': _pt,
  };

  // ── English (source of truth) ─────────────────────────────────────────────

  static const Map<String, String> _en = {
    // Status
    'security.fs.status.legacy': 'Standard encryption',
    'security.fs.status.upgrading': 'Upgrading security…',
    'security.fs.status.active': 'Forward Secrecy active',
    'security.fs.status.strict': 'Maximum Forward Secrecy',
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
        'If Forward Secrecy negotiation fails, this conversation will fall back to standard encryption.',
    'security.fs.warning.no_silent_downgrade':
        'Maximum Forward Secrecy is active. Messages cannot be sent without a confirmed secure channel.',

    // Multi-device (§7.9)
    'security.fs.new_device_detected': 'New device or session detected for this contact. A new secure session is being negotiated.',

    // Actions
    'security.fs.message_lost': 'This message was encrypted with a previous session and cannot be decrypted.',
    'security.fs.message_expired_fs': 'Forward Secrecy message',
    'security.fs.session_reset_done': 'Secure session reset. A new session will be negotiated automatically.',
    'security.fs.action.retry': 'Retry upgrade',
    'security.fs.action.reset': 'Reset session',
    'security.fs.action.request_maximum': 'Request Maximum FS',
    'security.fs.action.disable_strict': 'Disable Maximum FS',
    'security.fs.action.send_anyway': 'Send with standard encryption',

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
    'security.fs.progress.one_more_exchange': 'One more message exchange to activate',
    'security.fs.progress.exchanges_remaining': 'About {n} message exchanges to activate',

    // Recoverability warning (§14.6.1)
    'security.fs.warning.recoverability_title': 'Some messages may not be readable later',
    'security.fs.warning.recoverability_body':
        'This mode improves protection by reducing how long old keys or readable history remain available. '
        'If you delete messages, reset sessions, reinstall Layergram, or clean the encrypted archive, '
        'some older messages may not be recoverable even if you still have the correct passphrase.',
    'security.fs.warning.recoverability_confirm':
        'I understand that some old messages may become unrecoverable.',

    // Device-bound warning (§14.6.2)
    'security.fs.warning.device_bound_title': 'This mode is bound to verified devices',
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
        'Until confirmation, this contact is not yet using Maximum Forward Secrecy.',

    // Per-device/session labels (§14.4)
    'security.fs.device.session_label': 'Session {n}',
    'security.fs.device.unknown': 'Unknown session',
    'security.fs.device.fallback_allowed': 'Fallback: allowed',
    'security.fs.device.fallback_not_allowed': 'Fallback: not allowed',
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
    'security.fs.mode.sheet_subtitle': 'Choose the Forward Secrecy level for this contact.',
    'security.fs.mode.base_title': 'Base',
    'security.fs.mode.base_desc': 'Standard encryption. Maximum compatibility.',
    'security.fs.mode.advanced_title': 'Advanced',
    'security.fs.mode.advanced_desc': 'Automatic Forward Secrecy when supported. Legacy fallback allowed.',
    'security.fs.mode.strict_title': 'Maximum',
    'security.fs.mode.strict_desc': 'Strongest protection. Device-bound, no fallback.',
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
    'security.fs.cls.legacy.desc': 'This message uses standard Layergram identity encryption. Forward Secrecy was not active.',
    'security.fs.cls.pre_fs': 'Pre-FS message',
    'security.fs.cls.pre_fs.desc': 'This message was sent before Forward Secrecy was established and is not protected by FS.',
    'security.fs.cls.negotiation': 'FS negotiation',
    'security.fs.cls.negotiation.desc': 'This message was part of the Forward Secrecy handshake negotiation.',
    'security.fs.cls.fs_fallback': 'Forward Secrecy',
    'security.fs.cls.fs_fallback.desc': 'This message is protected by Forward Secrecy with compatibility fallback allowed.',
    'security.fs.cls.fs_only': 'FS only',
    'security.fs.cls.fs_only.desc': 'This message is protected by Forward Secrecy only. It cannot be decrypted with the legacy key.',
    'security.fs.cls.strict': 'Maximum FS',
    'security.fs.cls.strict.desc': 'This message is protected by Maximum Forward Secrecy. Legacy fallback is disabled.',
    'security.fs.cls.failed': 'FS failed',
    'security.fs.cls.failed.desc': 'Forward Secrecy decryption failed. The session may have been reset or the device changed.',
    'security.fs.cls.unknown': 'Unknown',
    'security.fs.cls.unknown.desc': 'The security classification of this message could not be determined.',

    // Passphrase settings (§11.2–§11.5, §14.2)
    'security.pp.section_title': 'Security for this identity',
    'security.pp.section_subtitle': 'Settings specific to this passphrase-derived identity.',
    'security.pp.timeout_title': 'Auto-expel passphrase',
    'security.pp.timeout_subtitle': 'Choose a shorter timeout for stronger protection.',
    'security.pp.timeout_30s': '30 seconds',
    'security.pp.timeout_1m': '1 minute',
    'security.pp.timeout_2m': '2 minutes',
    'security.pp.timeout_5m': '5 minutes',
    'security.pp.timeout_10m': '10 minutes',
    'security.pp.timeout_manual': 'Manual only',
    'security.pp.screen_lock_title': 'Expel on screen lock',
    'security.pp.screen_lock_subtitle': 'Destroy passphrase keys immediately when the screen locks.',
    'security.pp.history_title': 'History for this identity',
    'security.pp.history_keep': 'Keep encrypted history',
    'security.pp.history_volatile': 'Volatile history',
    'security.pp.history_ephemeral': 'Ephemeral session',
    'security.pp.fs_persistence_title': 'Forward Secrecy state',
    'security.pp.fs_persistent': 'Persistent',
    'security.pp.fs_ephemeral': 'Ephemeral',
    'security.pp.expel_now': 'Expel identity now',

    // §14.5 Warnings
    'security.warn.active_passphrase': 'While this identity is unlocked, its keys exist in device memory. Layergram does not protect against seizure or compromise while the identity is actively unlocked.',
    'security.warn.passphrase_fs': 'The passphrase restores this identity. It may not restore old Forward Secure messages if the required session state was deleted or expired.',
    'security.warn.volatile_history': 'This mode is designed to reduce future recoverability. Old messages may not be readable again, even with the correct passphrase.',
    'security.warn.ephemeral_session': 'FS state and history are RAM-only. FS restarts after every passphrase expulsion. No messages or session state will survive.',
    'security.warn.recoverability_title': 'Reduced recoverability',
    'security.warn.recoverability_body': 'This mode improves protection by reducing how long old keys or readable history remain available. If you delete messages, reset sessions, expel this identity, reinstall Layergram, lose local state, or clean the encrypted archive, some older messages may not be recoverable even if you still have the original Layergram text or the correct passphrase.',
    'security.warn.recoverability_confirm': 'I understand that some old messages may become unrecoverable.',

    // §13.7 Clean undecryptable data
    'security.cleanup.title': 'Clean undecryptable data',
    'security.cleanup.subtitle': 'Remove residual data that cannot be decrypted.',
    'security.cleanup.dialog_title': 'Clean undecryptable data',
    'security.cleanup.dialog_body': 'This may permanently delete old encrypted archives, abandoned identity data, passphrase-derived records, security sessions, and other data that Layergram cannot currently decrypt.',
    'security.cleanup.confirm_checkbox': 'I understand this action is irreversible.',
    'security.cleanup.confirm_button': 'Clean now',
    'security.cleanup.done': 'Undecryptable data cleaned.',
  };

  // ── Italian ───────────────────────────────────────────────────────────────

  static const Map<String, String> _it = {
    'security.fs.status.legacy': 'Crittografia standard',
    'security.fs.status.upgrading': 'Aggiornamento sicurezza…',
    'security.fs.status.active': 'Forward Secrecy attiva',
    'security.fs.status.strict': 'Forward Secrecy massima',
    'security.fs.status.suspended': 'Sicurezza sospesa',
    'security.fs.status.broken': 'Avviso di sicurezza',
    'security.fs.warning.recoverability':
        'Se perdi l\'accesso a questo dispositivo, i messaggi protetti da Forward Secrecy non potranno essere recuperati.',
    'security.fs.warning.device_bound':
        'La Forward Secrecy massima lega questa conversazione al tuo dispositivo attuale. Cambiare dispositivo richiederà di ristabilire la sessione.',
    'security.fs.warning.pending_activation':
        'L\'aggiornamento Forward Secrecy è in sospeso. Invia un messaggio per completare l\'handshake.',
    'security.fs.warning.fallback_allowed':
        'Se la negoziazione Forward Secrecy fallisce, questa conversazione tornerà alla crittografia standard.',
    'security.fs.warning.no_silent_downgrade':
        'Forward Secrecy massima attiva. I messaggi non possono essere inviati senza un canale sicuro confermato.',
    'security.fs.new_device_detected': 'Nuovo dispositivo o sessione rilevato per questo contatto. Una nuova sessione sicura è in fase di negoziazione.',
    'security.fs.message_lost': 'Questo messaggio era cifrato con una sessione precedente e non può essere decifrato.',
    'security.fs.message_expired_fs': 'Messaggio Forward Secrecy',
    'security.fs.session_reset_done': 'Sessione sicura reimpostata. Una nuova sessione sarà negoziata automaticamente.',
    'security.fs.action.retry': 'Riprova aggiornamento',
    'security.fs.action.reset': 'Reimposta sessione',
    'security.fs.action.request_maximum': 'Richiedi FS massima',
    'security.fs.action.disable_strict': 'Disabilita FS massima',
    'security.fs.action.send_anyway': 'Invia con crittografia standard',
    'security.fs.info.title': 'Sicurezza con questo contatto',
    'security.fs.info.legacy_description':
        'I messaggi sono cifrati end-to-end. Forward Secrecy non è ancora attiva.',
    'security.fs.info.active_description':
        'Forward Secrecy è attiva. Ogni messaggio utilizza una chiave unica derivata da un handshake effimero.',
    'security.fs.info.active_advantage':
        'I messaggi passati rimangono protetti anche se le chiavi vengono compromesse in futuro.',
    'security.fs.info.strict_description':
        'La Forward Secrecy massima è attiva ed è legata a questo dispositivo. '
        'I messaggi possono essere inviati e ricevuti solo tramite questo canale sicuro confermato.',
    'security.fs.info.broken_description':
        'Il canale sicuro non ha potuto essere verificato. Nessun messaggio è stato inviato o ricevuto in questo stato.',
    'security.fs.info.upgrading_description':
        'È in corso un aggiornamento Forward Secrecy. Completa l\'handshake scambiando un messaggio.',
    'security.fs.maximum.confirm_title': 'Abilitare Forward Secrecy massima?',
    'security.fs.maximum.confirm_body':
        'Questo legherà la conversazione al tuo dispositivo attuale. '
        'Dovrai ripetere questo processo se cambi dispositivo.',
    'security.fs.maximum.confirm_button': 'Abilita',
    'security.fs.maximum.cancel_button': 'Annulla',
    'security.fs.maximum.pending_notice':
        'In attesa che {contact} confermi la Forward Secrecy massima.',
    'security.passphrase.fs_active': 'Forward Secrecy passphrase attiva',
    'security.passphrase.fs_inactive': 'Contesto passphrase non attivo',
    'security.passphrase.settings_visible_note':
        'Queste impostazioni sono disponibili solo quando il contesto passphrase è attivo.',
    // Security mode selector (§14.3)
    'security.fs.mode.sheet_title': 'Modalità sicurezza',
    'security.fs.mode.sheet_subtitle': 'Scegli il livello di Forward Secrecy per questo contatto.',
    'security.fs.mode.base_title': 'Base',
    'security.fs.mode.base_desc': 'Crittografia standard. Massima compatibilità.',
    'security.fs.mode.advanced_title': 'Avanzata',
    'security.fs.mode.advanced_desc': 'Forward Secrecy automatica quando supportata. Fallback legacy consentito.',
    'security.fs.mode.strict_title': 'Massima',
    'security.fs.mode.strict_desc': 'Protezione più forte. Legata al dispositivo, nessun fallback.',
    'security.fs.mode.confirm_button': 'Applica',
    'security.fs.mode.cancel_button': 'Annulla',
    'security.fs.mode.changed_snackbar': 'Modalità sicurezza aggiornata.',
    'security.fs.action.change_mode': 'Cambia modalità sicurezza',
    'security.fs.mode.current_label': 'Modalità attuale: {mode}',

    'security.contact.state.primary_context': 'Identità principale',
    'security.contact.state.passphrase_context': 'Identità passphrase',
    'security.contact.state.session_id': 'Sessione: {sessionId}',
    'security.contact.state.no_sessions': 'Nessuna sessione attiva',

    'security.fs.cls.legacy': 'Crittografia standard',
    'security.fs.cls.legacy.desc': 'Questo messaggio utilizza la crittografia d\'identità standard. Forward Secrecy non era attiva.',
    'security.fs.cls.pre_fs': 'Messaggio pre-FS',
    'security.fs.cls.pre_fs.desc': 'Questo messaggio è stato inviato prima che Forward Secrecy fosse stabilita.',
    'security.fs.cls.negotiation': 'Negoziazione FS',
    'security.fs.cls.negotiation.desc': 'Questo messaggio faceva parte della negoziazione dell\'handshake Forward Secrecy.',
    'security.fs.cls.fs_fallback': 'Forward Secrecy',
    'security.fs.cls.fs_fallback.desc': 'Questo messaggio è protetto da Forward Secrecy con fallback di compatibilità consentito.',
    'security.fs.cls.fs_only': 'Solo FS',
    'security.fs.cls.fs_only.desc': 'Questo messaggio è protetto solo da Forward Secrecy. Non può essere decifrato con la chiave legacy.',
    'security.fs.cls.strict': 'FS massima',
    'security.fs.cls.strict.desc': 'Questo messaggio è protetto dalla Forward Secrecy massima. Il fallback legacy è disabilitato.',
    'security.fs.cls.failed': 'FS fallita',
    'security.fs.cls.failed.desc': 'La decifratura Forward Secrecy è fallita. La sessione potrebbe essere stata reimpostata o il dispositivo cambiato.',
    'security.fs.cls.unknown': 'Sconosciuta',
    'security.fs.cls.unknown.desc': 'La classificazione di sicurezza di questo messaggio non è stata determinata.',

    // Passphrase settings (§11.2–§11.5, §14.2)
    'security.pp.section_title': 'Sicurezza per questa identità',
    'security.pp.section_subtitle': 'Impostazioni specifiche per questa identità derivata da passphrase.',
    'security.pp.timeout_title': 'Espulsione automatica passphrase',
    'security.pp.timeout_subtitle': 'Scegli un timeout più breve per una protezione maggiore.',
    'security.pp.timeout_30s': '30 secondi',
    'security.pp.timeout_1m': '1 minuto',
    'security.pp.timeout_2m': '2 minuti',
    'security.pp.timeout_5m': '5 minuti',
    'security.pp.timeout_10m': '10 minuti',
    'security.pp.timeout_manual': 'Solo manuale',
    'security.pp.screen_lock_title': 'Espelli al blocco schermo',
    'security.pp.screen_lock_subtitle': 'Distrugge le chiavi passphrase immediatamente al blocco dello schermo.',
    'security.pp.history_title': 'Cronologia per questa identità',
    'security.pp.history_keep': 'Mantieni cronologia cifrata',
    'security.pp.history_volatile': 'Cronologia volatile',
    'security.pp.history_ephemeral': 'Sessione effimera',
    'security.pp.fs_persistence_title': 'Stato Forward Secrecy',
    'security.pp.fs_persistent': 'Persistente',
    'security.pp.fs_ephemeral': 'Effimero',
    'security.pp.expel_now': 'Espelli identità ora',

    // §14.5 Avvertenze
    'security.warn.active_passphrase': 'Finché questa identità è sbloccata, le sue chiavi esistono nella memoria del dispositivo. Layergram non protegge da sequestro o compromissione mentre l\'identità è attivamente sbloccata.',
    'security.warn.passphrase_fs': 'La passphrase ripristina questa identità. Potrebbe non ripristinare i vecchi messaggi Forward Secure se lo stato della sessione è stato eliminato o scaduto.',
    'security.warn.volatile_history': 'Questa modalità è progettata per ridurre la recuperabilità futura. I vecchi messaggi potrebbero non essere più leggibili, anche con la passphrase corretta.',
    'security.warn.ephemeral_session': 'Lo stato FS e la cronologia sono solo in RAM. La FS si riavvia dopo ogni espulsione della passphrase. Nessun messaggio o stato di sessione sopravviverà.',
    'security.warn.recoverability_title': 'Recuperabilità ridotta',
    'security.warn.recoverability_body': 'Questa modalità migliora la protezione riducendo quanto a lungo le vecchie chiavi o la cronologia leggibile rimangono disponibili. Se elimini messaggi, resetti sessioni, espelli questa identità, reinstalli Layergram, perdi lo stato locale o pulisci l\'archivio cifrato, alcuni messaggi più vecchi potrebbero non essere recuperabili anche se hai ancora il testo Layergram originale o la passphrase corretta.',
    'security.warn.recoverability_confirm': 'Capisco che alcuni vecchi messaggi potrebbero diventare irrecuperabili.',

    // §13.7 Pulizia dati indecifrabili
    'security.cleanup.title': 'Pulisci dati indecifrabili',
    'security.cleanup.subtitle': 'Rimuovi i dati residui che non possono essere decifrati.',
    'security.cleanup.dialog_title': 'Pulisci dati indecifrabili',
    'security.cleanup.dialog_body': 'Questo potrebbe eliminare permanentemente vecchi archivi cifrati, dati di identità abbandonati, record derivati da passphrase, sessioni di sicurezza e altri dati che Layergram non può attualmente decifrare.',
    'security.cleanup.confirm_checkbox': 'Capisco che questa azione è irreversibile.',
    'security.cleanup.confirm_button': 'Pulisci ora',
    'security.cleanup.done': 'Dati indecifrabili puliti.',
  };

  // ── Spanish ───────────────────────────────────────────────────────────────

  static const Map<String, String> _es = {
    'security.fs.status.legacy': 'Cifrado estándar',
    'security.fs.status.upgrading': 'Actualizando seguridad…',
    'security.fs.status.active': 'Forward Secrecy activo',
    'security.fs.status.strict': 'Forward Secrecy máximo',
    'security.fs.status.suspended': 'Seguridad pausada',
    'security.fs.status.broken': 'Advertencia de seguridad',
    'security.fs.warning.recoverability':
        'Si pierdes el acceso a este dispositivo, los mensajes protegidos por Forward Secrecy no podrán recuperarse.',
    'security.fs.warning.device_bound':
        'El Forward Secrecy máximo vincula esta conversación a tu dispositivo actual.',
    'security.fs.warning.pending_activation':
        'La actualización de Forward Secrecy está pendiente. Envía un mensaje para completar el handshake.',
    'security.fs.warning.fallback_allowed':
        'Si falla la negociación de Forward Secrecy, esta conversación volverá al cifrado estándar.',
    'security.fs.warning.no_silent_downgrade':
        'Forward Secrecy máximo activo. No se pueden enviar mensajes sin un canal seguro confirmado.',
    'security.fs.new_device_detected': 'Nuevo dispositivo o sesión detectada para este contacto. Se está negociando una nueva sesión segura.',
    'security.fs.message_lost': 'Este mensaje fue cifrado con una sesión anterior y no se puede descifrar.',
    'security.fs.message_expired_fs': 'Mensaje Forward Secrecy',
    'security.fs.session_reset_done': 'Sesión segura restablecida. Se negociará una nueva sesión automáticamente.',
    'security.fs.action.retry': 'Reintentar actualización',
    'security.fs.action.reset': 'Restablecer sesión',
    'security.fs.action.request_maximum': 'Solicitar FS máximo',
    'security.fs.action.disable_strict': 'Deshabilitar FS máximo',
    'security.fs.action.send_anyway': 'Enviar con cifrado estándar',
    'security.fs.info.title': 'Seguridad con este contacto',
    'security.fs.info.legacy_description':
        'Los mensajes están cifrados de extremo a extremo. Forward Secrecy aún no está activo.',
    'security.fs.info.active_description':
        'Forward Secrecy está activo. Cada mensaje usa una clave única derivada de un handshake efímero.',
    'security.fs.info.active_advantage':
        'Los mensajes pasados permanecen protegidos aunque tus claves se vean comprometidas más adelante.',
    'security.fs.info.strict_description':
        'El Forward Secrecy máximo está activo y vinculado a este dispositivo.',
    'security.fs.info.broken_description':
        'El canal seguro no pudo verificarse. No se han enviado ni recibido mensajes en este estado.',
    'security.fs.info.upgrading_description':
        'Se está realizando una actualización de Forward Secrecy. Completa el handshake intercambiando un mensaje.',
    'security.fs.maximum.confirm_title': '¿Habilitar Forward Secrecy máximo?',
    'security.fs.maximum.confirm_body':
        'Esto vinculará la conversación a tu dispositivo actual.',
    'security.fs.maximum.confirm_button': 'Habilitar',
    'security.fs.maximum.cancel_button': 'Cancelar',
    'security.fs.maximum.pending_notice':
        'Esperando que {contact} confirme el Forward Secrecy máximo.',
    'security.passphrase.fs_active': 'Forward Secrecy de frase de contraseña activo',
    'security.passphrase.fs_inactive': 'Contexto de frase de contraseña no activo',
    'security.passphrase.settings_visible_note':
        'Estas configuraciones solo están disponibles mientras el contexto de frase de contraseña esté activo.',
    // Security mode selector (§14.3)
    'security.fs.mode.sheet_title': 'Modo de seguridad',
    'security.fs.mode.sheet_subtitle': 'Elige el nivel de Forward Secrecy para este contacto.',
    'security.fs.mode.base_title': 'Base',
    'security.fs.mode.base_desc': 'Cifrado estándar. Máxima compatibilidad.',
    'security.fs.mode.advanced_title': 'Avanzado',
    'security.fs.mode.advanced_desc': 'Forward Secrecy automático cuando está soportado. Fallback legacy permitido.',
    'security.fs.mode.strict_title': 'Máximo',
    'security.fs.mode.strict_desc': 'Protección más fuerte. Vinculado al dispositivo, sin fallback.',
    'security.fs.mode.confirm_button': 'Aplicar',
    'security.fs.mode.cancel_button': 'Cancelar',
    'security.fs.mode.changed_snackbar': 'Modo de seguridad actualizado.',
    'security.fs.action.change_mode': 'Cambiar modo de seguridad',
    'security.fs.mode.current_label': 'Modo actual: {mode}',

    'security.contact.state.primary_context': 'Identidad principal',
    'security.contact.state.passphrase_context': 'Identidad de frase de contraseña',
    'security.contact.state.session_id': 'Sesión: {sessionId}',
    'security.contact.state.no_sessions': 'Sin sesiones activas',

    'security.fs.cls.legacy': 'Cifrado estándar',
    'security.fs.cls.legacy.desc': 'Este mensaje usa cifrado de identidad estándar. Forward Secrecy no estaba activo.',
    'security.fs.cls.pre_fs': 'Mensaje pre-FS',
    'security.fs.cls.pre_fs.desc': 'Este mensaje fue enviado antes de que se estableciera Forward Secrecy.',
    'security.fs.cls.negotiation': 'Negociación FS',
    'security.fs.cls.negotiation.desc': 'Este mensaje fue parte de la negociación del handshake de Forward Secrecy.',
    'security.fs.cls.fs_fallback': 'Forward Secrecy',
    'security.fs.cls.fs_fallback.desc': 'Este mensaje está protegido por Forward Secrecy con compatibilidad de respaldo permitida.',
    'security.fs.cls.fs_only': 'Solo FS',
    'security.fs.cls.fs_only.desc': 'Este mensaje está protegido solo por Forward Secrecy. No se puede descifrar con la clave legacy.',
    'security.fs.cls.strict': 'FS máximo',
    'security.fs.cls.strict.desc': 'Este mensaje está protegido por Forward Secrecy máximo. El respaldo legacy está deshabilitado.',
    'security.fs.cls.failed': 'FS fallido',
    'security.fs.cls.failed.desc': 'La descifrado de Forward Secrecy falló. La sesión puede haber sido restablecida o el dispositivo cambiado.',
    'security.fs.cls.unknown': 'Desconocido',
    'security.fs.cls.unknown.desc': 'No se pudo determinar la clasificación de seguridad de este mensaje.',

    // Passphrase settings (§11.2–§11.5, §14.2)
    'security.pp.section_title': 'Seguridad para esta identidad',
    'security.pp.section_subtitle': 'Ajustes específicos para esta identidad derivada de passphrase.',
    'security.pp.timeout_title': 'Expulsión automática de passphrase',
    'security.pp.timeout_subtitle': 'Elige un tiempo más corto para mayor protección.',
    'security.pp.timeout_30s': '30 segundos',
    'security.pp.timeout_1m': '1 minuto',
    'security.pp.timeout_2m': '2 minutos',
    'security.pp.timeout_5m': '5 minutos',
    'security.pp.timeout_10m': '10 minutos',
    'security.pp.timeout_manual': 'Solo manual',
    'security.pp.screen_lock_title': 'Expulsar al bloquear pantalla',
    'security.pp.screen_lock_subtitle': 'Destruye las claves de passphrase inmediatamente al bloquear la pantalla.',
    'security.pp.history_title': 'Historial para esta identidad',
    'security.pp.history_keep': 'Mantener historial cifrado',
    'security.pp.history_volatile': 'Historial volátil',
    'security.pp.history_ephemeral': 'Sesión efímera',
    'security.pp.fs_persistence_title': 'Estado Forward Secrecy',
    'security.pp.fs_persistent': 'Persistente',
    'security.pp.fs_ephemeral': 'Efímero',
    'security.pp.expel_now': 'Expulsar identidad ahora',

    // §14.5 Advertencias
    'security.warn.active_passphrase': 'Mientras esta identidad está desbloqueada, sus claves existen en la memoria del dispositivo. Layergram no protege contra incautación o compromiso mientras la identidad está activamente desbloqueada.',
    'security.warn.passphrase_fs': 'La passphrase restaura esta identidad. Puede que no restaure mensajes Forward Secure antiguos si el estado de sesión requerido fue eliminado o expiró.',
    'security.warn.volatile_history': 'Este modo está diseñado para reducir la recuperabilidad futura. Los mensajes antiguos pueden no ser legibles de nuevo, incluso con la passphrase correcta.',
    'security.warn.ephemeral_session': 'El estado FS y el historial son solo en RAM. FS se reinicia después de cada expulsión de passphrase. Ningún mensaje o estado de sesión sobrevivirá.',
    'security.warn.recoverability_title': 'Recuperabilidad reducida',
    'security.warn.recoverability_body': 'Este modo mejora la protección reduciendo cuánto tiempo las claves antiguas o el historial legible permanecen disponibles. Si eliminas mensajes, restableces sesiones, expulsas esta identidad, reinstalas Layergram, pierdes el estado local o limpias el archivo cifrado, algunos mensajes más antiguos pueden no ser recuperables incluso si aún tienes el texto Layergram original o la passphrase correcta.',
    'security.warn.recoverability_confirm': 'Entiendo que algunos mensajes antiguos pueden volverse irrecuperables.',

    // §13.7 Limpiar datos indescifrables
    'security.cleanup.title': 'Limpiar datos indescifrables',
    'security.cleanup.subtitle': 'Eliminar datos residuales que no pueden ser descifrados.',
    'security.cleanup.dialog_title': 'Limpiar datos indescifrables',
    'security.cleanup.dialog_body': 'Esto puede eliminar permanentemente archivos cifrados antiguos, datos de identidad abandonados, registros derivados de passphrase, sesiones de seguridad y otros datos que Layergram no puede descifrar actualmente.',
    'security.cleanup.confirm_checkbox': 'Entiendo que esta acción es irreversible.',
    'security.cleanup.confirm_button': 'Limpiar ahora',
    'security.cleanup.done': 'Datos indescifrables limpiados.',
  };

  // ── German ────────────────────────────────────────────────────────────────

  static const Map<String, String> _de = {
    'security.fs.status.legacy': 'Standardverschlüsselung',
    'security.fs.status.upgrading': 'Sicherheit wird aktualisiert…',
    'security.fs.status.active': 'Forward Secrecy aktiv',
    'security.fs.status.strict': 'Maximale Forward Secrecy',
    'security.fs.status.suspended': 'Sicherheit pausiert',
    'security.fs.status.broken': 'Sicherheitswarnung',
    'security.fs.warning.recoverability':
        'Wenn Sie den Zugriff auf dieses Gerät verlieren, können durch Forward Secrecy geschützte Nachrichten nicht wiederhergestellt werden.',
    'security.fs.warning.device_bound':
        'Maximale Forward Secrecy bindet diese Unterhaltung an Ihr aktuelles Gerät.',
    'security.fs.warning.pending_activation':
        'Das Forward-Secrecy-Upgrade steht aus. Senden Sie eine Nachricht, um den Handshake abzuschließen.',
    'security.fs.warning.fallback_allowed':
        'Wenn die Forward-Secrecy-Aushandlung fehlschlägt, fällt diese Unterhaltung auf die Standardverschlüsselung zurück.',
    'security.fs.warning.no_silent_downgrade':
        'Maximale Forward Secrecy aktiv. Nachrichten können nicht ohne einen bestätigten sicheren Kanal gesendet werden.',
    'security.fs.new_device_detected': 'Neues Gerät oder neue Sitzung für diesen Kontakt erkannt. Eine neue sichere Sitzung wird ausgehandelt.',
    'security.fs.message_lost': 'Diese Nachricht wurde mit einer vorherigen Sitzung verschlüsselt und kann nicht entschlüsselt werden.',
    'security.fs.message_expired_fs': 'Forward-Secrecy-Nachricht',
    'security.fs.session_reset_done': 'Sichere Sitzung zurückgesetzt. Eine neue Sitzung wird automatisch ausgehandelt.',
    'security.fs.action.retry': 'Upgrade wiederholen',
    'security.fs.action.reset': 'Sitzung zurücksetzen',
    'security.fs.action.request_maximum': 'Maximale FS anfordern',
    'security.fs.action.disable_strict': 'Maximale FS deaktivieren',
    'security.fs.action.send_anyway': 'Mit Standardverschlüsselung senden',
    'security.fs.info.title': 'Sicherheit mit diesem Kontakt',
    'security.fs.info.legacy_description':
        'Nachrichten sind Ende-zu-Ende verschlüsselt. Forward Secrecy ist noch nicht aktiv.',
    'security.fs.info.active_description':
        'Forward Secrecy ist aktiv. Jede Nachricht verwendet einen einzigartigen Schlüssel aus einem ephemeren Handshake.',
    'security.fs.info.active_advantage':
        'Vergangene Nachrichten bleiben geschützt, auch wenn Ihre Schlüssel später kompromittiert werden.',
    'security.fs.info.strict_description':
        'Maximale Forward Secrecy ist aktiv und an dieses Gerät gebunden.',
    'security.fs.info.broken_description':
        'Der sichere Kanal konnte nicht verifiziert werden.',
    'security.fs.info.upgrading_description':
        'Ein Forward-Secrecy-Upgrade ist im Gange. Schließen Sie den Handshake durch Nachrichtenaustausch ab.',
    'security.fs.maximum.confirm_title': 'Maximale Forward Secrecy aktivieren?',
    'security.fs.maximum.confirm_body':
        'Dies bindet die Unterhaltung an Ihr aktuelles Gerät.',
    'security.fs.maximum.confirm_button': 'Aktivieren',
    'security.fs.maximum.cancel_button': 'Abbrechen',
    'security.fs.maximum.pending_notice':
        'Warten auf Bestätigung der maximalen Forward Secrecy durch {contact}.',
    'security.passphrase.fs_active': 'Passphrase-Forward-Secrecy aktiv',
    'security.passphrase.fs_inactive': 'Passphrase-Kontext nicht aktiv',
    'security.passphrase.settings_visible_note':
        'Diese Einstellungen sind nur verfügbar, wenn der Passphrase-Kontext aktiv ist.',
    // Security mode selector (§14.3)
    'security.fs.mode.sheet_title': 'Sicherheitsmodus',
    'security.fs.mode.sheet_subtitle': 'Wählen Sie die Forward-Secrecy-Stufe für diesen Kontakt.',
    'security.fs.mode.base_title': 'Basis',
    'security.fs.mode.base_desc': 'Standardverschlüsselung. Maximale Kompatibilität.',
    'security.fs.mode.advanced_title': 'Erweitert',
    'security.fs.mode.advanced_desc': 'Automatische Forward Secrecy wenn unterstützt. Legacy-Fallback erlaubt.',
    'security.fs.mode.strict_title': 'Maximum',
    'security.fs.mode.strict_desc': 'Stärkster Schutz. Gerätegebunden, kein Fallback.',
    'security.fs.mode.confirm_button': 'Anwenden',
    'security.fs.mode.cancel_button': 'Abbrechen',
    'security.fs.mode.changed_snackbar': 'Sicherheitsmodus aktualisiert.',
    'security.fs.action.change_mode': 'Sicherheitsmodus ändern',
    'security.fs.mode.current_label': 'Aktueller Modus: {mode}',

    'security.contact.state.primary_context': 'Primäre Identität',
    'security.contact.state.passphrase_context': 'Passphrase-Identität',
    'security.contact.state.session_id': 'Sitzung: {sessionId}',
    'security.contact.state.no_sessions': 'Keine aktiven Sitzungen',

    'security.fs.cls.legacy': 'Standardverschlüsselung',
    'security.fs.cls.legacy.desc': 'Diese Nachricht verwendet Standard-Identitätsverschlüsselung. Forward Secrecy war nicht aktiv.',
    'security.fs.cls.pre_fs': 'Vor-FS-Nachricht',
    'security.fs.cls.pre_fs.desc': 'Diese Nachricht wurde gesendet, bevor Forward Secrecy eingerichtet wurde.',
    'security.fs.cls.negotiation': 'FS-Aushandlung',
    'security.fs.cls.negotiation.desc': 'Diese Nachricht war Teil der Forward Secrecy Handshake-Aushandlung.',
    'security.fs.cls.fs_fallback': 'Forward Secrecy',
    'security.fs.cls.fs_fallback.desc': 'Diese Nachricht ist durch Forward Secrecy mit erlaubtem Kompatibilitäts-Fallback geschützt.',
    'security.fs.cls.fs_only': 'Nur FS',
    'security.fs.cls.fs_only.desc': 'Diese Nachricht ist nur durch Forward Secrecy geschützt. Sie kann nicht mit dem Legacy-Schlüssel entschlüsselt werden.',
    'security.fs.cls.strict': 'Maximale FS',
    'security.fs.cls.strict.desc': 'Diese Nachricht ist durch maximale Forward Secrecy geschützt. Legacy-Fallback ist deaktiviert.',
    'security.fs.cls.failed': 'FS fehlgeschlagen',
    'security.fs.cls.failed.desc': 'Die Forward Secrecy Entschlüsselung ist fehlgeschlagen. Die Sitzung wurde möglicherweise zurückgesetzt oder das Gerät gewechselt.',
    'security.fs.cls.unknown': 'Unbekannt',
    'security.fs.cls.unknown.desc': 'Die Sicherheitsklassifizierung dieser Nachricht konnte nicht bestimmt werden.',

    // Passphrase settings (§11.2–§11.5, §14.2)
    'security.pp.section_title': 'Sicherheit für diese Identität',
    'security.pp.section_subtitle': 'Einstellungen für diese passphrase-abgeleitete Identität.',
    'security.pp.timeout_title': 'Passphrase automatisch löschen',
    'security.pp.timeout_subtitle': 'Wähle ein kürzeres Timeout für stärkeren Schutz.',
    'security.pp.timeout_30s': '30 Sekunden',
    'security.pp.timeout_1m': '1 Minute',
    'security.pp.timeout_2m': '2 Minuten',
    'security.pp.timeout_5m': '5 Minuten',
    'security.pp.timeout_10m': '10 Minuten',
    'security.pp.timeout_manual': 'Nur manuell',
    'security.pp.screen_lock_title': 'Bei Bildschirmsperre löschen',
    'security.pp.screen_lock_subtitle': 'Zerstört die Passphrase-Schlüssel sofort bei Bildschirmsperre.',
    'security.pp.history_title': 'Verlauf für diese Identität',
    'security.pp.history_keep': 'Verschlüsselten Verlauf behalten',
    'security.pp.history_volatile': 'Flüchtiger Verlauf',
    'security.pp.history_ephemeral': 'Ephemere Sitzung',
    'security.pp.fs_persistence_title': 'Forward-Secrecy-Status',
    'security.pp.fs_persistent': 'Persistent',
    'security.pp.fs_ephemeral': 'Ephemer',
    'security.pp.expel_now': 'Identität jetzt löschen',

    // §14.5 Warnungen
    'security.warn.active_passphrase': 'Solange diese Identität entsperrt ist, existieren ihre Schlüssel im Gerätespeicher. Layergram schützt nicht vor Beschlagnahme oder Kompromittierung, während die Identität aktiv entsperrt ist.',
    'security.warn.passphrase_fs': 'Die Passphrase stellt diese Identität wieder her. Sie stellt möglicherweise keine alten Forward-Secure-Nachrichten wieder her, wenn der erforderliche Sitzungsstatus gelöscht oder abgelaufen ist.',
    'security.warn.volatile_history': 'Dieser Modus ist darauf ausgelegt, die zukünftige Wiederherstellbarkeit zu reduzieren. Alte Nachrichten sind möglicherweise nicht mehr lesbar, auch nicht mit der richtigen Passphrase.',
    'security.warn.ephemeral_session': 'FS-Status und Verlauf sind nur im RAM. FS startet nach jeder Passphrase-Ausweisung neu. Keine Nachrichten oder Sitzungsstatus überleben.',
    'security.warn.recoverability_title': 'Reduzierte Wiederherstellbarkeit',
    'security.warn.recoverability_body': 'Dieser Modus verbessert den Schutz, indem er reduziert, wie lange alte Schlüssel oder lesbarer Verlauf verfügbar bleiben. Wenn Sie Nachrichten löschen, Sitzungen zurücksetzen, diese Identität ausweisen, Layergram neu installieren, den lokalen Status verlieren oder das verschlüsselte Archiv bereinigen, sind einige ältere Nachrichten möglicherweise nicht wiederherstellbar, auch wenn Sie noch den originalen Layergram-Text oder die richtige Passphrase haben.',
    'security.warn.recoverability_confirm': 'Ich verstehe, dass einige alte Nachrichten unwiederbringlich werden können.',

    // §13.7 Unentschlüsselbare Daten bereinigen
    'security.cleanup.title': 'Unentschlüsselbare Daten bereinigen',
    'security.cleanup.subtitle': 'Restdaten entfernen, die nicht entschlüsselt werden können.',
    'security.cleanup.dialog_title': 'Unentschlüsselbare Daten bereinigen',
    'security.cleanup.dialog_body': 'Dies kann dauerhaft alte verschlüsselte Archive, aufgegebene Identitätsdaten, von Passphrase abgeleitete Datensätze, Sicherheitssitzungen und andere Daten löschen, die Layergram derzeit nicht entschlüsseln kann.',
    'security.cleanup.confirm_checkbox': 'Ich verstehe, dass diese Aktion irreversibel ist.',
    'security.cleanup.confirm_button': 'Jetzt bereinigen',
    'security.cleanup.done': 'Unentschlüsselbare Daten bereinigt.',
  };

  // ── French ────────────────────────────────────────────────────────────────

  static const Map<String, String> _fr = {
    'security.fs.status.legacy': 'Chiffrement standard',
    'security.fs.status.upgrading': 'Mise à niveau de la sécurité…',
    'security.fs.status.active': 'Forward Secrecy actif',
    'security.fs.status.strict': 'Forward Secrecy maximal',
    'security.fs.status.suspended': 'Sécurité suspendue',
    'security.fs.status.broken': 'Avertissement de sécurité',
    'security.fs.warning.recoverability':
        'Si vous perdez l\'accès à cet appareil, les messages protégés par Forward Secrecy ne pourront pas être récupérés.',
    'security.fs.warning.device_bound':
        'Le Forward Secrecy maximal lie cette conversation à votre appareil actuel.',
    'security.fs.warning.pending_activation':
        'La mise à niveau Forward Secrecy est en attente. Envoyez un message pour finaliser la poignée de main.',
    'security.fs.warning.fallback_allowed':
        'En cas d\'échec de la négociation, cette conversation reviendra au chiffrement standard.',
    'security.fs.warning.no_silent_downgrade':
        'Forward Secrecy maximal actif. Les messages ne peuvent pas être envoyés sans canal sécurisé confirmé.',
    'security.fs.new_device_detected': 'Nouvel appareil ou session détecté pour ce contact. Une nouvelle session sécurisée est en cours de négociation.',
    'security.fs.message_lost': 'Ce message a été chiffré avec une session précédente et ne peut pas être déchiffré.',
    'security.fs.message_expired_fs': 'Message Forward Secrecy',
    'security.fs.session_reset_done': 'Session sécurisée réinitialisée. Une nouvelle session sera négociée automatiquement.',
    'security.fs.action.retry': 'Réessayer la mise à niveau',
    'security.fs.action.reset': 'Réinitialiser la session',
    'security.fs.action.request_maximum': 'Demander FS maximal',
    'security.fs.action.disable_strict': 'Désactiver FS maximal',
    'security.fs.action.send_anyway': 'Envoyer avec chiffrement standard',
    'security.fs.info.title': 'Sécurité avec ce contact',
    'security.fs.info.legacy_description':
        'Les messages sont chiffrés de bout en bout. Forward Secrecy n\'est pas encore actif.',
    'security.fs.info.active_description':
        'Forward Secrecy est actif. Chaque message utilise une clé unique issue d\'une poignée de main éphémère.',
    'security.fs.info.active_advantage':
        'Les messages passés restent protégés même si vos clés sont compromises ultérieurement.',
    'security.fs.info.strict_description':
        'Le Forward Secrecy maximal est actif et lié à cet appareil.',
    'security.fs.info.broken_description':
        'Le canal sécurisé n\'a pas pu être vérifié.',
    'security.fs.info.upgrading_description':
        'Une mise à niveau Forward Secrecy est en cours. Finalisez la poignée de main en échangeant un message.',
    'security.fs.maximum.confirm_title': 'Activer le Forward Secrecy maximal ?',
    'security.fs.maximum.confirm_body':
        'Cela liera la conversation à votre appareil actuel.',
    'security.fs.maximum.confirm_button': 'Activer',
    'security.fs.maximum.cancel_button': 'Annuler',
    'security.fs.maximum.pending_notice':
        'En attente de confirmation du Forward Secrecy maximal par {contact}.',
    'security.passphrase.fs_active': 'Forward Secrecy phrase secrète actif',
    'security.passphrase.fs_inactive': 'Contexte phrase secrète inactif',
    'security.passphrase.settings_visible_note':
        'Ces paramètres ne sont disponibles que lorsque le contexte phrase secrète est actif.',
    // Security mode selector (§14.3)
    'security.fs.mode.sheet_title': 'Mode de sécurité',
    'security.fs.mode.sheet_subtitle': 'Choisissez le niveau de Forward Secrecy pour ce contact.',
    'security.fs.mode.base_title': 'Base',
    'security.fs.mode.base_desc': 'Chiffrement standard. Compatibilité maximale.',
    'security.fs.mode.advanced_title': 'Avancé',
    'security.fs.mode.advanced_desc': 'Forward Secrecy automatique lorsque supporté. Repli legacy autorisé.',
    'security.fs.mode.strict_title': 'Maximum',
    'security.fs.mode.strict_desc': 'Protection la plus forte. Lié à l\'appareil, sans repli.',
    'security.fs.mode.confirm_button': 'Appliquer',
    'security.fs.mode.cancel_button': 'Annuler',
    'security.fs.mode.changed_snackbar': 'Mode de sécurité mis à jour.',
    'security.fs.action.change_mode': 'Changer le mode de sécurité',
    'security.fs.mode.current_label': 'Mode actuel : {mode}',

    'security.contact.state.primary_context': 'Identité principale',
    'security.contact.state.passphrase_context': 'Identité phrase secrète',
    'security.contact.state.session_id': 'Session : {sessionId}',
    'security.contact.state.no_sessions': 'Aucune session active',

    'security.fs.cls.legacy': 'Chiffrement standard',
    'security.fs.cls.legacy.desc': 'Ce message utilise le chiffrement d\'identité standard. Forward Secrecy n\'était pas actif.',
    'security.fs.cls.pre_fs': 'Message pré-FS',
    'security.fs.cls.pre_fs.desc': 'Ce message a été envoyé avant l\'établissement de Forward Secrecy.',
    'security.fs.cls.negotiation': 'Négociation FS',
    'security.fs.cls.negotiation.desc': 'Ce message faisait partie de la négociation du handshake Forward Secrecy.',
    'security.fs.cls.fs_fallback': 'Forward Secrecy',
    'security.fs.cls.fs_fallback.desc': 'Ce message est protégé par Forward Secrecy avec repli de compatibilité autorisé.',
    'security.fs.cls.fs_only': 'FS uniquement',
    'security.fs.cls.fs_only.desc': 'Ce message est protégé uniquement par Forward Secrecy. Il ne peut pas être déchiffré avec la clé legacy.',
    'security.fs.cls.strict': 'FS maximum',
    'security.fs.cls.strict.desc': 'Ce message est protégé par Forward Secrecy maximum. Le repli legacy est désactivé.',
    'security.fs.cls.failed': 'FS échoué',
    'security.fs.cls.failed.desc': 'Le déchiffrement Forward Secrecy a échoué. La session a peut-être été réinitialisée ou l\'appareil changé.',
    'security.fs.cls.unknown': 'Inconnu',
    'security.fs.cls.unknown.desc': 'La classification de sécurité de ce message n\'a pas pu être déterminée.',

    // Passphrase settings (§11.2–§11.5, §14.2)
    'security.pp.section_title': 'Sécurité pour cette identité',
    'security.pp.section_subtitle': 'Paramètres spécifiques à cette identité dérivée de la passphrase.',
    'security.pp.timeout_title': 'Expulsion automatique de la passphrase',
    'security.pp.timeout_subtitle': 'Choisissez un délai plus court pour une protection renforcée.',
    'security.pp.timeout_30s': '30 secondes',
    'security.pp.timeout_1m': '1 minute',
    'security.pp.timeout_2m': '2 minutes',
    'security.pp.timeout_5m': '5 minutes',
    'security.pp.timeout_10m': '10 minutes',
    'security.pp.timeout_manual': 'Manuel uniquement',
    'security.pp.screen_lock_title': 'Expulser au verrouillage',
    'security.pp.screen_lock_subtitle': 'Détruit les clés de passphrase immédiatement lors du verrouillage de l\'écran.',
    'security.pp.history_title': 'Historique pour cette identité',
    'security.pp.history_keep': 'Conserver l\'historique chiffré',
    'security.pp.history_volatile': 'Historique volatile',
    'security.pp.history_ephemeral': 'Session éphémère',
    'security.pp.fs_persistence_title': 'État Forward Secrecy',
    'security.pp.fs_persistent': 'Persistant',
    'security.pp.fs_ephemeral': 'Éphémère',
    'security.pp.expel_now': 'Expulser l\'identité maintenant',

    // §14.5 Avertissements
    'security.warn.active_passphrase': 'Tant que cette identité est déverrouillée, ses clés existent dans la mémoire de l\'appareil. Layergram ne protège pas contre la saisie ou la compromission tant que l\'identité est activement déverrouillée.',
    'security.warn.passphrase_fs': 'La passphrase restaure cette identité. Elle pourrait ne pas restaurer les anciens messages Forward Secure si l\'état de session requis a été supprimé ou a expiré.',
    'security.warn.volatile_history': 'Ce mode est conçu pour réduire la récupérabilité future. Les anciens messages pourraient ne plus être lisibles, même avec la bonne passphrase.',
    'security.warn.ephemeral_session': 'L\'état FS et l\'historique sont uniquement en RAM. La FS redémarre après chaque expulsion de passphrase. Aucun message ou état de session ne survivra.',
    'security.warn.recoverability_title': 'Récupérabilité réduite',
    'security.warn.recoverability_body': 'Ce mode améliore la protection en réduisant la durée pendant laquelle les anciennes clés ou l\'historique lisible restent disponibles. Si vous supprimez des messages, réinitialisez des sessions, expulsez cette identité, réinstallez Layergram, perdez l\'état local ou nettoyez l\'archive chiffrée, certains messages plus anciens pourraient ne pas être récupérables même si vous avez encore le texte Layergram original ou la bonne passphrase.',
    'security.warn.recoverability_confirm': 'Je comprends que certains anciens messages pourraient devenir irrécupérables.',

    // §13.7 Nettoyer les données indéchiffrables
    'security.cleanup.title': 'Nettoyer les données indéchiffrables',
    'security.cleanup.subtitle': 'Supprimer les données résiduelles qui ne peuvent pas être déchiffrées.',
    'security.cleanup.dialog_title': 'Nettoyer les données indéchiffrables',
    'security.cleanup.dialog_body': 'Cela peut supprimer définitivement d\'anciennes archives chiffrées, des données d\'identité abandonnées, des enregistrements dérivés de passphrase, des sessions de sécurité et d\'autres données que Layergram ne peut pas actuellement déchiffrer.',
    'security.cleanup.confirm_checkbox': 'Je comprends que cette action est irréversible.',
    'security.cleanup.confirm_button': 'Nettoyer maintenant',
    'security.cleanup.done': 'Données indéchiffrables nettoyées.',
  };

  // ── Portuguese ────────────────────────────────────────────────────────────

  static const Map<String, String> _pt = {
    'security.fs.status.legacy': 'Criptografia padrão',
    'security.fs.status.upgrading': 'Atualizando segurança…',
    'security.fs.status.active': 'Forward Secrecy ativo',
    'security.fs.status.strict': 'Forward Secrecy máximo',
    'security.fs.status.suspended': 'Segurança pausada',
    'security.fs.status.broken': 'Aviso de segurança',
    'security.fs.warning.recoverability':
        'Se você perder o acesso a este dispositivo, as mensagens protegidas pelo Forward Secrecy não poderão ser recuperadas.',
    'security.fs.warning.device_bound':
        'O Forward Secrecy máximo vincula esta conversa ao seu dispositivo atual.',
    'security.fs.warning.pending_activation':
        'A atualização do Forward Secrecy está pendente. Envie uma mensagem para concluir o handshake.',
    'security.fs.warning.fallback_allowed':
        'Se a negociação falhar, esta conversa voltará à criptografia padrão.',
    'security.fs.warning.no_silent_downgrade':
        'Forward Secrecy máximo ativo. Mensagens não podem ser enviadas sem um canal seguro confirmado.',
    'security.fs.new_device_detected': 'Novo dispositivo ou sessão detectado para este contato. Uma nova sessão segura está sendo negociada.',
    'security.fs.message_lost': 'Esta mensagem foi criptografada com uma sessão anterior e não pode ser descriptografada.',
    'security.fs.message_expired_fs': 'Mensagem Forward Secrecy',
    'security.fs.session_reset_done': 'Sessão segura redefinida. Uma nova sessão será negociada automaticamente.',
    'security.fs.action.retry': 'Tentar atualização novamente',
    'security.fs.action.reset': 'Redefinir sessão',
    'security.fs.action.request_maximum': 'Solicitar FS máximo',
    'security.fs.action.disable_strict': 'Desativar FS máximo',
    'security.fs.action.send_anyway': 'Enviar com criptografia padrão',
    'security.fs.info.title': 'Segurança com este contato',
    'security.fs.info.legacy_description':
        'As mensagens são criptografadas de ponta a ponta. Forward Secrecy ainda não está ativo.',
    'security.fs.info.active_description':
        'Forward Secrecy está ativo. Cada mensagem usa uma chave única derivada de um handshake efêmero.',
    'security.fs.info.active_advantage':
        'Mensagens passadas permanecem protegidas mesmo que suas chaves sejam comprometidas futuramente.',
    'security.fs.info.strict_description':
        'O Forward Secrecy máximo está ativo e vinculado a este dispositivo.',
    'security.fs.info.broken_description':
        'O canal seguro não pôde ser verificado.',
    'security.fs.info.upgrading_description':
        'Uma atualização de Forward Secrecy está em andamento. Conclua o handshake trocando uma mensagem.',
    'security.fs.maximum.confirm_title': 'Ativar Forward Secrecy máximo?',
    'security.fs.maximum.confirm_body':
        'Isso vinculará a conversa ao seu dispositivo atual.',
    'security.fs.maximum.confirm_button': 'Ativar',
    'security.fs.maximum.cancel_button': 'Cancelar',
    'security.fs.maximum.pending_notice':
        'Aguardando {contact} confirmar o Forward Secrecy máximo.',
    'security.passphrase.fs_active': 'Forward Secrecy de frase secreta ativo',
    'security.passphrase.fs_inactive': 'Contexto de frase secreta inativo',
    'security.passphrase.settings_visible_note':
        'Estas configurações só estão disponíveis enquanto o contexto de frase secreta estiver ativo.',
    // Security mode selector (§14.3)
    'security.fs.mode.sheet_title': 'Modo de segurança',
    'security.fs.mode.sheet_subtitle': 'Escolha o nível de Forward Secrecy para este contato.',
    'security.fs.mode.base_title': 'Base',
    'security.fs.mode.base_desc': 'Criptografia padrão. Máxima compatibilidade.',
    'security.fs.mode.advanced_title': 'Avançado',
    'security.fs.mode.advanced_desc': 'Forward Secrecy automático quando suportado. Fallback legacy permitido.',
    'security.fs.mode.strict_title': 'Máximo',
    'security.fs.mode.strict_desc': 'Proteção mais forte. Vinculado ao dispositivo, sem fallback.',
    'security.fs.mode.confirm_button': 'Aplicar',
    'security.fs.mode.cancel_button': 'Cancelar',
    'security.fs.mode.changed_snackbar': 'Modo de segurança atualizado.',
    'security.fs.action.change_mode': 'Alterar modo de segurança',
    'security.fs.mode.current_label': 'Modo atual: {mode}',

    'security.contact.state.primary_context': 'Identidade principal',
    'security.contact.state.passphrase_context': 'Identidade de frase secreta',
    'security.contact.state.session_id': 'Sessão: {sessionId}',
    'security.contact.state.no_sessions': 'Nenhuma sessão ativa',

    'security.fs.cls.legacy': 'Criptografia padrão',
    'security.fs.cls.legacy.desc': 'Esta mensagem usa criptografia de identidade padrão. Forward Secrecy não estava ativo.',
    'security.fs.cls.pre_fs': 'Mensagem pré-FS',
    'security.fs.cls.pre_fs.desc': 'Esta mensagem foi enviada antes do Forward Secrecy ser estabelecido.',
    'security.fs.cls.negotiation': 'Negociação FS',
    'security.fs.cls.negotiation.desc': 'Esta mensagem fez parte da negociação do handshake Forward Secrecy.',
    'security.fs.cls.fs_fallback': 'Forward Secrecy',
    'security.fs.cls.fs_fallback.desc': 'Esta mensagem é protegida por Forward Secrecy com fallback de compatibilidade permitido.',
    'security.fs.cls.fs_only': 'Apenas FS',
    'security.fs.cls.fs_only.desc': 'Esta mensagem é protegida apenas por Forward Secrecy. Não pode ser decifrada com a chave legacy.',
    'security.fs.cls.strict': 'FS máximo',
    'security.fs.cls.strict.desc': 'Esta mensagem é protegida por Forward Secrecy máximo. O fallback legacy está desabilitado.',
    'security.fs.cls.failed': 'FS falhou',
    'security.fs.cls.failed.desc': 'A decifragem Forward Secrecy falhou. A sessão pode ter sido redefinida ou o dispositivo alterado.',
    'security.fs.cls.unknown': 'Desconhecido',
    'security.fs.cls.unknown.desc': 'A classificação de segurança desta mensagem não pôde ser determinada.',

    // Passphrase settings (§11.2–§11.5, §14.2)
    'security.pp.section_title': 'Segurança para esta identidade',
    'security.pp.section_subtitle': 'Configurações específicas para esta identidade derivada de passphrase.',
    'security.pp.timeout_title': 'Expulsão automática da passphrase',
    'security.pp.timeout_subtitle': 'Escolha um tempo mais curto para maior proteção.',
    'security.pp.timeout_30s': '30 segundos',
    'security.pp.timeout_1m': '1 minuto',
    'security.pp.timeout_2m': '2 minutos',
    'security.pp.timeout_5m': '5 minutos',
    'security.pp.timeout_10m': '10 minutos',
    'security.pp.timeout_manual': 'Apenas manual',
    'security.pp.screen_lock_title': 'Expulsar ao bloquear tela',
    'security.pp.screen_lock_subtitle': 'Destrói as chaves da passphrase imediatamente ao bloquear a tela.',
    'security.pp.history_title': 'Histórico para esta identidade',
    'security.pp.history_keep': 'Manter histórico criptografado',
    'security.pp.history_volatile': 'Histórico volátil',
    'security.pp.history_ephemeral': 'Sessão efêmera',
    'security.pp.fs_persistence_title': 'Estado Forward Secrecy',
    'security.pp.fs_persistent': 'Persistente',
    'security.pp.fs_ephemeral': 'Efêmero',
    'security.pp.expel_now': 'Expulsar identidade agora',

    // §14.5 Avisos
    'security.warn.active_passphrase': 'Enquanto esta identidade estiver desbloqueada, suas chaves existem na memória do dispositivo. Layergram não protege contra apreensão ou comprometimento enquanto a identidade está ativamente desbloqueada.',
    'security.warn.passphrase_fs': 'A passphrase restaura esta identidade. Ela pode não restaurar mensagens Forward Secure antigas se o estado de sessão necessário foi excluído ou expirou.',
    'security.warn.volatile_history': 'Este modo é projetado para reduzir a recuperabilidade futura. Mensagens antigas podem não ser legíveis novamente, mesmo com a passphrase correta.',
    'security.warn.ephemeral_session': 'O estado FS e o histórico são apenas em RAM. A FS reinicia após cada expulsão de passphrase. Nenhuma mensagem ou estado de sessão sobreviverá.',
    'security.warn.recoverability_title': 'Recuperabilidade reduzida',
    'security.warn.recoverability_body': 'Este modo melhora a proteção reduzindo quanto tempo as chaves antigas ou o histórico legível permanecem disponíveis. Se você excluir mensagens, redefinir sessões, expulsar esta identidade, reinstalar o Layergram, perder o estado local ou limpar o arquivo criptografado, algumas mensagens mais antigas podem não ser recuperáveis mesmo se você ainda tiver o texto Layergram original ou a passphrase correta.',
    'security.warn.recoverability_confirm': 'Entendo que algumas mensagens antigas podem se tornar irrecuperáveis.',

    // §13.7 Limpar dados indecifráveis
    'security.cleanup.title': 'Limpar dados indecifráveis',
    'security.cleanup.subtitle': 'Remover dados residuais que não podem ser decifrados.',
    'security.cleanup.dialog_title': 'Limpar dados indecifráveis',
    'security.cleanup.dialog_body': 'Isso pode excluir permanentemente arquivos criptografados antigos, dados de identidade abandonados, registros derivados de passphrase, sessões de segurança e outros dados que o Layergram não pode atualmente decifrar.',
    'security.cleanup.confirm_checkbox': 'Entendo que esta ação é irreversível.',
    'security.cleanup.confirm_button': 'Limpar agora',
    'security.cleanup.done': 'Dados indecifráveis limpos.',
  };
}
