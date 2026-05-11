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

    // Contact card state
    'security.contact.state.primary_context': 'Primary identity',
    'security.contact.state.passphrase_context': 'Passphrase identity',
    'security.contact.state.session_id': 'Session: {sessionId}',
    'security.contact.state.no_sessions': 'No active sessions',
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
    'security.contact.state.primary_context': 'Identità principale',
    'security.contact.state.passphrase_context': 'Identità passphrase',
    'security.contact.state.session_id': 'Sessione: {sessionId}',
    'security.contact.state.no_sessions': 'Nessuna sessione attiva',
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
    'security.contact.state.primary_context': 'Identidad principal',
    'security.contact.state.passphrase_context': 'Identidad de frase de contraseña',
    'security.contact.state.session_id': 'Sesión: {sessionId}',
    'security.contact.state.no_sessions': 'Sin sesiones activas',
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
    'security.contact.state.primary_context': 'Primäre Identität',
    'security.contact.state.passphrase_context': 'Passphrase-Identität',
    'security.contact.state.session_id': 'Sitzung: {sessionId}',
    'security.contact.state.no_sessions': 'Keine aktiven Sitzungen',
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
    'security.contact.state.primary_context': 'Identité principale',
    'security.contact.state.passphrase_context': 'Identité phrase secrète',
    'security.contact.state.session_id': 'Session : {sessionId}',
    'security.contact.state.no_sessions': 'Aucune session active',
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
    'security.contact.state.primary_context': 'Identidade principal',
    'security.contact.state.passphrase_context': 'Identidade de frase secreta',
    'security.contact.state.session_id': 'Sessão: {sessionId}',
    'security.contact.state.no_sessions': 'Nenhuma sessão ativa',
  };
}
