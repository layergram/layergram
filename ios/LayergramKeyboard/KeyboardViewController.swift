import SystemKeyboardCore
import UIKit

/// Native Layergram keyboard for iOS.
///
/// This class is the whole extension UI. It contains **no** cryptography, no
/// engine, no vault, no network and no identity material: it edits a local draft
/// and exchanges bounded JSON maps with the already running Layergram app owner
/// through `SystemKeyboardCore`'s App Group mailbox.
///
/// Hard rules implemented here:
/// * no `UITextField`/`UITextView` first responder and no host plaintext typing;
/// * the only host reads are `textDocumentProxy.documentIdentifier` (opaque,
///   compared only, never displayed) and one `UIPasteboard.general.string` read
///   behind an explicit user paste tap;
/// * the only host write is a single `insertText(carrier)` for a freshly
///   authorized encrypted carrier, which returns `Void` — so a tap can never
///   claim that the host accepted or delivered anything;
/// * the always-present globe key calls `advanceToNextInputMode()`;
/// * no surrounding text, document context or selected text is ever read.
///
/// The 20 s owner window is fixed and never renewed. A separate <= 1 s freshness
/// lease, refreshed by each accepted heartbeat, gates every local read, edit,
/// contact action and the single insertion; when it lapses everything sensitive
/// is cleared and the transport is dropped, even inside the 20 s window.
final class KeyboardViewController: UIInputViewController {
    // MARK: - Copy

    /// User-facing copy. English, Italian and Spanish are carried locally; any
    /// other system language falls back to English. No passphrase, identity
    /// reason, icon or lock detail is ever shown. Nothing here is secret.
    enum Language: Equatable {
        case english, italian, spanish

        static func forLocale(_ locale: Locale) -> Language {
            switch locale.languageCode?.lowercased() {
            case "it": return .italian
            case "es": return .spanish
            default: return .english
            }
        }
    }

    enum StringKey: CaseIterable {
        case space, returnKey, deleteKey
        case contacts, paste, encryptInsert, pasteDecrypt
        case confirm, cancel, newMessage, recipient, draft, window, fingerprint, previewTitle, compose, readMessage
        case globeSwitch
        case confirmPrompt, emptyDraftHint
        case minimumSystem, openApp, unavailable, noFullAccess
        case starting, sessionActive, waiting, exported, sessionExpired
        case tooLong, pasteTooLong, emptyPaste, noContacts, rejected, chooseRecipient
        case handOffNote
        /// The decoded sender line and the explicit reply shortcut.
        case from, to, replyTo, senderTapHint
    }

    enum Copy {
        static func locale(_ language: Language) -> Locale {
            switch language {
            case .english: return Locale(identifier: "en_US")
            case .italian: return Locale(identifier: "it_IT")
            case .spanish: return Locale(identifier: "es_ES")
            }
        }

        static func language(_ locale: Locale) -> Language { Language.forLocale(locale) }

        /// Localized string for an explicit language. The table is total, so a
        /// missing translation is a compile-time gap, not a silent raw key.
        static func string(_ key: StringKey, in language: Language) -> String {
            switch key {
            case .space:
                if language == .italian { return "spazio" }
                if language == .spanish { return "espacio" }
                return "space"
            case .returnKey:
                if language == .italian { return "invio" }
                if language == .spanish { return "intro" }
                return "return"
            case .deleteKey:
                if language == .italian { return "canc" }
                if language == .spanish { return "borrar" }
                return "del"
            case .contacts:
                if language == .italian { return "Rubrica" }
                if language == .spanish { return "Contactos" }
                return "Contacts"
            case .paste:
                if language == .italian { return "Incolla" }
                if language == .spanish { return "Pegar" }
                return "Paste"
            case .encryptInsert:
                if language == .italian { return "Cifra e inserisci" }
                if language == .spanish { return "Cifrar e insertar" }
                return "Encrypt & insert"
            case .pasteDecrypt:
                if language == .italian { return "Incolla e decifra" }
                if language == .spanish { return "Pegar y descifrar" }
                return "Paste & decrypt"
            case .confirm:
                if language == .italian { return "Conferma" }
                if language == .spanish { return "Confirmar" }
                return "Confirm"
            case .cancel:
                if language == .italian { return "Annulla" }
                if language == .spanish { return "Cancelar" }
                return "Cancel"
            case .newMessage:
                if language == .italian { return "Nuovo" }
                if language == .spanish { return "Nuevo" }
                return "New"
            case .compose:
                if language == .italian { return "Scrivi" }
                if language == .spanish { return "Escribir" }
                return "Compose"
            case .readMessage:
                if language == .italian { return "Leggi" }
                if language == .spanish { return "Leer" }
                return "Read"
            case .recipient:
                if language == .italian { return "Destinatario" }
                if language == .spanish { return "Destinatario" }
                return "Recipient"
            case .draft:
                if language == .italian { return "Bozza" }
                if language == .spanish { return "Borrador" }
                return "Draft"
            case .window:
                if language == .italian { return "Finestra" }
                if language == .spanish { return "Ventana" }
                return "Window"
            case .fingerprint:
                if language == .italian { return "Impronta" }
                if language == .spanish { return "Huella" }
                return "Fingerprint"
            case .previewTitle:
                if language == .italian { return "Anteprima" }
                if language == .spanish { return "Vista previa" }
                return "Preview"
            case .globeSwitch:
                if language == .italian { return "Cambia tastiera" }
                if language == .spanish { return "Cambiar teclado" }
                return "Next keyboard"
            case .confirmPrompt:
                if language == .italian { return "Conferma il destinatario e verifica l'impronta." }
                if language == .spanish { return "Confirma el destinatario y revisa la huella." }
                return "Confirm the recipient and check the fingerprint."
            case .emptyDraftHint:
                if language == .italian { return "Scrivi un messaggio, poi tocca Cifra e inserisci." }
                if language == .spanish { return "Escribe un mensaje y toca Cifrar e insertar." }
                return "Type a message, then tap Encrypt & insert."
            case .minimumSystem:
                if language == .italian { return "La tastiera richiede iOS 26 o successivo." }
                if language == .spanish { return "El teclado requiere iOS 26 o posterior." }
                return "The keyboard requires iOS 26 or later."
            case .openApp:
                if language == .italian {
                    return "Apri e sblocca Layergram manualmente, poi torna qui."
                }
                if language == .spanish {
                    return "Abre y desbloquea Layergram manualmente y vuelve aquí."
                }
                return "Open and unlock Layergram manually, then come back here."
            case .unavailable:
                if language == .italian { return "Layergram non è disponibile." }
                if language == .spanish { return "Layergram no está disponible." }
                return "Layergram is unavailable."
            case .noFullAccess:
                if language == .italian {
                    return "Serve l'accesso completo per la tastiera Layergram. Attivalo in Impostazioni > Tastiere."
                }
                if language == .spanish {
                    return "Se necesita acceso completo para el teclado Layergram. Actívalo en Ajustes > Teclados."
                }
                return "Full Access is required for the Layergram keyboard. Enable it in Settings > Keyboards."
            case .starting:
                if language == .italian { return "Avvio sicuro in corso…" }
                if language == .spanish { return "Iniciando de forma segura…" }
                return "Starting securely…"
            case .sessionActive:
                if language == .italian { return "Sessione attiva." }
                if language == .spanish { return "Sesión activa." }
                return "Session active."
            case .waiting:
                if language == .italian { return "In attesa dell'app…" }
                if language == .spanish { return "Esperando la app…" }
                return "Waiting for the app…"
            case .exported:
                // `insertText` returns `Void`: the keyboard can only say the
                // encrypted text was handed to the host app. It never claims the
                // host accepted, inserted or delivered anything.
                if language == .italian {
                    return "Testo cifrato passato all'app. Premi invio nell'app per spedirlo. Nessuna conferma di consegna."
                }
                if language == .spanish {
                    return "Texto cifrado pasado a la app. Pulsa enviar en la app para mandarlo. Sin confirmación de entrega."
                }
                return "Encrypted text passed to the app. Press send in the app to post it. No delivery confirmation."
            case .sessionExpired:
                if language == .italian {
                    return "Sessione scaduta. Torna in Layergram per aprirne una nuova."
                }
                if language == .spanish {
                    return "Sesión caducada. Vuelve a Layergram para abrir una nueva."
                }
                return "Session expired. Return to Layergram to open a new one."
            case .tooLong:
                if language == .italian { return "Testo troppo lungo." }
                if language == .spanish { return "El texto es demasiado largo." }
                return "Text is too long."
            case .pasteTooLong:
                if language == .italian { return "Contenuto incollato troppo lungo." }
                if language == .spanish { return "El contenido pegado es demasiado largo." }
                return "Pasted content is too long."
            case .emptyPaste:
                if language == .italian { return "Negli appunti non c'è testo." }
                if language == .spanish { return "El portapapeles no contiene texto." }
                return "The clipboard has no text."
            case .noContacts:
                if language == .italian { return "Nessun contatto disponibile." }
                if language == .spanish { return "No hay contactos disponibles." }
                return "No contacts available."
            case .rejected:
                if language == .italian { return "Messaggio non supportato." }
                if language == .spanish { return "Mensaje no compatible." }
                return "Unsupported message."
            case .chooseRecipient:
                if language == .italian { return "Scegli un destinatario." }
                if language == .spanish { return "Elige un destinatario." }
                return "Choose a recipient."
            case .handOffNote:
                if language == .italian {
                    return "Dopo l'inserimento premi invio nell'app di destinazione."
                }
                if language == .spanish {
                    return "Tras insertar, pulsa enviar en la app de destino."
                }
                return "After insertion, press send in the host app."
            case .from:
                if language == .italian { return "Da" }
                if language == .spanish { return "De" }
                return "From"
            case .to:
                if language == .italian { return "A" }
                if language == .spanish { return "Para" }
                return "To"
            case .replyTo:
                if language == .italian { return "Rispondi a" }
                if language == .spanish { return "Responder a" }
                return "Reply to"
            case .senderTapHint:
                if language == .italian { return "Tocca per rispondere a questo mittente." }
                if language == .spanish { return "Toca para responder a este remitente." }
                return "Tap to reply to this sender."
            }
        }

        static func string(_ key: StringKey, in locale: Locale) -> String {
            string(key, in: language(locale))
        }

        static func isItalian(_ locale: Locale) -> Bool {
            language(locale) == .italian
        }

        static func localeCode(_ locale: Locale) -> String {
            switch language(locale) {
            case .english: return "en"
            case .italian: return "it"
            case .spanish: return "es"
            }
        }
    }

    // MARK: - State

    enum ShiftState { case off, on, locked }
    enum Layer { case letters, numbers, symbols }
    enum Surface { case keys, contacts, confirmation, preview }

    /// Action keys are positional: the neutral scramble never moves them and
    /// they keep the same identifier whatever the current layer is.
    enum KeyAction: String, CaseIterable {
        case shift, backspace, space, newline, globe, layer, symbols

        static let identifierPrefix = "layergram.key."

        var identifier: String { "\(Self.identifierPrefix)\(rawValue)" }

        static func from(_ identifier: String?) -> KeyAction? {
            guard let identifier, identifier.hasPrefix(Self.identifierPrefix) else { return nil }
            return KeyAction(
                rawValue: String(identifier.dropFirst(Self.identifierPrefix.count))
            )
        }
    }

    /// One key of the rendered layout. Text keys carry the character they type
    /// (already shifted for letters); action keys carry their fixed action.
    enum KeyKind: Equatable {
        case text(String)
        case action(KeyAction)
    }

    struct KeyboardKey: Equatable {
        let label: String
        let kind: KeyKind
        /// Stable tag used only to resolve a tapped text key. Positional action
        /// keys are resolved by identifier, so they never need a tag.
        let textTag: Int?

        var action: KeyAction? {
            if case .action(let action) = kind { return action }
            return nil
        }
    }

    struct KeyboardRow: Equatable {
        let keys: [KeyboardKey]
        let inset: Bool
    }

    /// What a tap on the primary action does for the current local state. The
    /// decision is pure, so the empty-draft, admission and no-recipient rules can
    /// be checked without forging an owner session.
    enum PrimaryIntent: Equatable {
        /// No live admission: keep the need-Full-Access / open-the-app message
        /// instead of overwriting it with a workflow hint.
        case blockedByAdmission
        /// Nothing to send yet: explain the workflow and change nothing.
        case promptEmptyDraft
        /// A draft exists but no recipient is usable: select one first.
        case openRecipientSelection
        /// Recipient usable and draft valid: this tap is the explicit send.
        case send
    }

    /// One decoded inbound message as displayed: the sender metadata plus the
    /// preview text. Display-only; it is never a recipient selection.
    struct DecodedPreviewDisplay: Equatable {
        let contactId: String
        let contactName: String
        let fingerprint: String
        let text: String
    }

    private let policy = KeyboardEditorPolicy()
    private var locale: Locale { Locale.current }

    private var storage: MailboxStorage?
    private var client: MailboxClient?
    private var session: MailboxClientSession?
    private var sessionDeadlineMonotonicMillis: Int64 = 0
    private var started = false
    private var pollTimer: Timer?
    private var expiryTimer: Timer?
    private var repeatTimer: Timer?
    private var lastHeartbeatMonotonicMillis: Int64 = 0

    // Local editor state. `draft` and `pendingSelection` are readable inside the
    // module so native tests can drive the flow decisions; they are never
    // writable from outside and they never grant a session on their own.
    private(set) var draft = ""
    private var shift: ShiftState = .off
    private var layer: Layer = .letters
    private(set) var surface: Surface = .keys
    private var contacts: [KeyboardContact] = []
    private(set) var status = ""
    private var operation: KeyboardOperation?
    private(set) var pendingSelection: KeyboardContact?
    /// The sender of the last successful authenticated decode, kept only so the
    /// user can explicitly reply to them. It is deliberately **separate** from
    /// `pendingSelection`: a decoded message never preselects a recipient, and
    /// this value never counts as a confirmed selection.
    private(set) var displayedSender: KeyboardContact?
    private var scrambledIndex: [Int: [Int]] = [:]
    private var scrambleEnabled = false

    // MARK: - Views

    private let statusLabel = UILabel()
    private let draftLabel = UILabel()
    private let recipientLabel = UILabel()
    private let windowLabel = UILabel()
    private let previewLabel = UILabel()
    private let previewScroll = UIScrollView()
    private let contactsView = UITableView(frame: .zero, style: .plain)
    private let keysContainer = UIView()
    private let keysStack = UIStackView()
    private let confirmView = UIView()
    private let confirmLabel = UILabel()
    private let shortcutsStack = UIStackView()
    /// The explicit reply shortcut for a decoded sender. Visible only while a
    /// sender display exists on the key surface.
    private let senderButton = UIButton(type: .system)
    /// The always-available input-mode control for the surfaces where the key
    /// layout (and therefore its globe key) is hidden. It lives outside
    /// `keysContainer` so hiding that container can never hide the globe.
    private let fallbackGlobeButton = UIButton(type: .system)
    private let footerStack = UIStackView()
    private let previewContainer = UIStackView()
    /// Action buttons of the current key layout, keyed by their fixed action.
    /// They are retained so a shifted character only repaints the shift key
    /// instead of rebuilding every key of the layout.
    private var actionButtons: [KeyAction: UIButton] = [:]
    private var rowsSignature = ""

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        buildLayout()
        policy.listener = self
        observeCaptureState()
        render()
    }

    /// Start only once the input view is actually attached and visible.
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        started = true
        startSession()
    }

    /// Drop the editor binding and the transport immediately: never wait for
    /// `viewDidDisappear` to revoke.
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        teardownSession()
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        started = false
    }

    deinit {
        pollTimer?.invalidate()
        expiryTimer?.invalidate()
        repeatTimer?.invalidate()
        NotificationCenter.default.removeObserver(self)
    }

    // MARK: - Transport

    /// App Group identifier the enclosing bundle was built with. Nothing else is
    /// read from the bundle or from the app.
    private var appGroupIdentifier: String? {
        Bundle.main.object(forInfoDictionaryKey: "AppGroupId") as? String
    }

    private var monotonicNow: Int64 { MailboxClock.system().monotonicMillis }

    /// The proxy may not have a document during initial layout or detachment.
    /// Only its opaque identifier is compared, never host text.
    private var documentIdentifier: String? {
        LGKeyboardDocumentIdentifier(textDocumentProxy)
    }

    /// The live capture state of the screen this input view is actually on.
    private var isScreenCaptured: Bool {
        if let screen = viewIfLoaded?.window?.screen { return screen.isCaptured }
        return UIScreen.main.isCaptured
    }

    private func snapshot() -> KeyboardEditorSnapshot {
        KeyboardEditorSnapshot(
            isViewVisible: viewIfLoaded?.window != nil,
            hasFullAccess: hasFullAccess,
            isCaptured: isScreenCaptured,
            documentIdentifier: documentIdentifier,
            monotonicMillis: monotonicNow
        )
    }

    /// Bind a fresh editor and attach to the live owner window. The extension can
    /// never open, wake or renew that window: when it is absent the UI stays
    /// generic and asks the user to open Layergram.
    private func startSession() {
        guard started, session == nil else { return }
        guard MailboxCryptoAvailability.isSupported else {
            status = Copy.string(.minimumSystem, in: locale)
            render()
            return
        }
        guard hasFullAccess else {
            status = Copy.string(.noFullAccess, in: locale)
            render()
            return
        }
        guard let documentIdentifier, !documentIdentifier.isEmpty else {
            status = Copy.string(.openApp, in: locale)
            render()
            return
        }
        guard let group = appGroupIdentifier, !group.isEmpty else {
            status = Copy.string(.openApp, in: locale)
            render()
            return
        }
        do {
            let storage = try self.storage ?? MailboxStorage(appGroupIdentifier: group)
            self.storage = storage
            let client = self.client ?? MailboxClient(storage: storage)
            self.client = client
            guard client.hasLiveWindow() else {
                status = Copy.string(.openApp, in: locale)
                render()
                return
            }
            session?.revoke()
            let session = try client.attach()
            self.session = session
            sessionDeadlineMonotonicMillis = session.deadlineMonotonicMillis
            guard policy.begin(
                documentIdentifier: documentIdentifier,
                windowDeadlineMonotonicMillis: sessionDeadlineMonotonicMillis
            ) else {
                invalidateEditor(status: Copy.string(.openApp, in: locale))
                return
            }
            draft = ""
            contacts = []
            pendingSelection = nil
            scrambledIndex = [:]
            scrambleEnabled = false
            surface = .keys
            layer = .letters
            shift = .off
            lastHeartbeatMonotonicMillis = 0
            status = Copy.string(.starting, in: locale)
            render()
            let begin = try policy.beginRequestData()
            try session.send(payload: begin)
            operation = .begin
            scheduleTimers()
        } catch {
            // Storage, rendezvous and admission problems collapse into one
            // generic state: no reason, no owner detail, no retry of an old send.
            invalidateEditor(status: Copy.string(.openApp, in: locale))
        }
    }

    /// Queue one request for the live owner. Returns `false` when admission or
    /// the transport refused it, so the caller never assumes a send happened.
    @discardableResult
    private func queue(
        _ operation: KeyboardOperation,
        payload: [String: KeyboardRequestValue] = [:]
    ) -> Bool {
        guard let session else { return false }
        // A tap during an in-flight heartbeat must not invalidate the editor.
        // No payload is retained or replayed; the user can tap once it completes.
        guard self.operation == nil else { return false }
        do {
            let data = try policy.requestData(operation, payload: payload, snapshot: snapshot())
            try session.send(payload: data)
            self.operation = operation
            return true
        } catch {
            invalidateEditor(status: Copy.string(.openApp, in: locale))
            return false
        }
    }

    private func scheduleTimers() {
        pollTimer?.invalidate()
        let timer = Timer(timeInterval: 0.05, repeats: true) { [weak self] _ in
            self?.poll()
        }
        pollTimer = timer
        RunLoop.main.add(timer, forMode: .common)

        expiryTimer?.invalidate()
        let remainingSeconds = Double(sessionDeadlineMonotonicMillis - monotonicNow) / 1000
        let expiry = Timer(timeInterval: max(remainingSeconds, 0.1), repeats: false) {
            [weak self] _ in
            self?.expiredState()
        }
        expiryTimer = expiry
        RunLoop.main.add(expiry, forMode: .common)
    }

    /// Polls at ~50 ms while a request is outstanding; sends one idle heartbeat
    /// at most every 250 ms. Nothing here renews the owner window.
    private func poll() {
        guard started, let session else { return }
        let current = snapshot()
        if monotonicNow >= sessionDeadlineMonotonicMillis || !current.isViewVisible {
            expiredState()
            return
        }
        // Bootstrap: the first accepted `begin` is bounded to <= 1 s.
        if policy.isBootstrapExpired {
            invalidateEditor(status: Copy.string(.openApp, in: locale))
            return
        }
        if policy.isBeginAccepted {
            // Every poll needs full admission (Full Access, no capture, exact
            // document binding) plus the live <= 1 s freshness lease.
            if !policy.revalidate(current) {
                invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
                return
            }
            // A lapsed lease clears everything and drops the client even while
            // the 20 s window is still open.
            if policy.clearIfLeaseExpired(at: monotonicNow) {
                invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
                return
            }
        }
        windowLabel.text = remainingWindowText()
        if operation != nil {
            do {
                switch try session.pollResponse() {
                case .idle:
                    break
                case .response(let data):
                    handleResponse(data)
                }
            } catch {
                invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            }
            return
        }
        guard policy.isAwaitingResponse == false,
              policy.hasLiveLease(at: monotonicNow),
              monotonicNow &- lastHeartbeatMonotonicMillis >= 250 else { return }
        lastHeartbeatMonotonicMillis = monotonicNow
        _ = queue(.heartbeat)
    }

    /// Best-effort `end` for the editor that is going away. The owner rejects an
    /// `end` from an older editor, so this can never close a newer one.
    private func sendEnd(nonce: String) {
        guard let session else { return }
        do {
            let data = try policy.endRequestData(editorNonce: nonce)
            try session.send(payload: data)
        } catch {
            // Best effort only: the local binding is already gone.
        }
    }

    private func stopTimers() {
        pollTimer?.invalidate()
        pollTimer = nil
        expiryTimer?.invalidate()
        expiryTimer = nil
        repeatTimer?.invalidate()
        repeatTimer = nil
    }

    private func teardownSession() {
        stopTimers()
        if let nonce = policy.endEditor() { sendEnd(nonce: nonce) }
        session?.revoke()
        session = nil
        started = false
        clearSensitiveValues()
        render()
    }

    private func unavailableState() {
        invalidateEditor(status: Copy.string(.openApp, in: locale))
    }

    private func expiredState() {
        invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
    }

    /// Complete invalidation: end the editor binding, best-effort `end`, drop the
    /// transport, clear every retained label and plaintext value, then render.
    private func invalidateEditor(status newStatus: String) {
        stopTimers()
        if let nonce = policy.endEditor() { sendEnd(nonce: nonce) }
        session?.revoke()
        session = nil
        clearSensitiveValues()
        status = newStatus
        render()
    }

    /// Drop every sensitive value and label because the editor is gone.
    private func clearSensitiveValues() {
        repeatTimer?.invalidate()
        repeatTimer = nil
        draft = ""
        contacts = []
        pendingSelection = nil
        // The decoded-sender shortcut dies with every other sensitive value, so
        // an expired, rejected or superseded message can never leave a stale
        // reply affordance behind.
        displayedSender = nil
        operation = nil
        surface = .keys
        scrambledIndex = [:]
        scrambleEnabled = false
        rowsSignature = ""
        actionButtons = [:]
        draftLabel.text = nil
        draftLabel.accessibilityLabel = nil
        previewLabel.text = nil
        previewLabel.accessibilityLabel = nil
        senderButton.setTitle(nil, for: .normal)
        senderButton.accessibilityLabel = nil
        confirmLabel.text = nil
        confirmLabel.accessibilityLabel = nil
        recipientLabel.text = nil
        recipientLabel.accessibilityLabel = nil
        windowLabel.text = nil
        windowLabel.accessibilityLabel = nil
        contactsView.reloadData()
    }

    // MARK: - Responses

    private func handleResponse(_ data: Data) {
        let completed = operation
        guard let response = policy.acceptResponse(data, snapshot: snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        operation = nil
        if completed == .begin, let ready = policy.readyState() {
            // `begin.data.scramble` is a neutral display capability: only an
            // exact `true` enables the local key-layout shuffle.
            scrambleEnabled = ready
            scrambledIndex = [:]
        }
        switch response {
        case .failed(let statusCode):
            handleFailure(statusCode)
        case .granted:
            handleGrant(completed)
        }
        if completed != .heartbeat { render() }
    }

    private func handleGrant(_ completed: KeyboardOperation?) {
        guard let completed else { return }
        switch completed {
        case .begin:
            status = Copy.string(.sessionActive, in: locale)
        case .heartbeat:
            break
        case .contacts:
            contacts = policy.contacts() ?? []
            surface = .contacts
            status = contacts.isEmpty ? Copy.string(.noContacts, in: locale) : Copy.string(.recipient, in: locale)
        case .select:
            if let confirmed = policy.selection() {
                pendingSelection = confirmed
                status = Copy.string(.recipient, in: locale)
            } else {
                pendingSelection = nil
                status = Copy.string(.unavailable, in: locale)
            }
            // The confirmation sheet is gone: drop its retained text too.
            confirmLabel.text = nil
            confirmLabel.accessibilityLabel = nil
            surface = .keys
        case .prepare:
            guard let pendingId = policy.pendingId() else {
                invalidateEditor(status: Copy.string(.unavailable, in: locale))
                return
            }
            status = Copy.string(.waiting, in: locale)
            _ = queue(.authorize, payload: ["pendingId": .string(pendingId)])
        case .authorize:
            insertAuthorizedCarrier()
        case .ack:
            status = Copy.string(.exported, in: locale)
        case .decode:
            if let preview = policy.preview() {
                applyDecodedPreview(
                    DecodedPreviewDisplay(
                        contactId: preview.contactId,
                        contactName: preview.contactName,
                        fingerprint: preview.fingerprint,
                        text: preview.text
                    )
                )
                status = Copy.string(.previewTitle, in: locale)
            } else {
                // A non-`ok` reply and an unprojectable one both leave the
                // preview empty: there is no ciphertext fallback, no retry and no
                // retained sender shortcut.
                applyDecodedPreview(nil)
                status = Copy.string(.rejected, in: locale)
            }
        case .end:
            break
        }
    }

    private func handleFailure(_ statusCode: String) {
        // Every closed failure clears the whole sensitive surface and drops the
        // transport. Nothing is retried and nothing decoded earlier survives.
        let newStatus: String
        switch statusCode {
        case KeyboardChannelStatus.oversize:
            newStatus = Copy.string(.tooLong, in: locale)
        case KeyboardChannelStatus.openAppRequired,
             KeyboardChannelStatus.unavailable,
             KeyboardChannelStatus.busy,
             KeyboardChannelStatus.noMessage:
            newStatus = Copy.string(.openApp, in: locale)
        default:
            newStatus = Copy.string(.unavailable, in: locale)
        }
        invalidateEditor(status: newStatus)
    }

    /// The single host write of this feature.
    ///
    /// `insertText` returns `Void` and gives no acceptance result, so this method
    /// never claims delivery, never marks a message as delivered and never sends
    /// a receipt. The draft and the recipient are cleared immediately whether or
    /// not the host accepted anything, and a callback that invalidated the
    /// editor during the call means nothing is resurrected and no acknowledgement
    /// is attempted. When the same editor is still valid a best-effort
    /// `ack {pendingId, commitText: true}` is sent, which marks the **export
    /// attempt** only; the owner already stores the prepared message if it cannot
    /// run.
    private func insertAuthorizedCarrier() {
        let current = snapshot()
        let permit: KeyboardInsertionPermit
        do {
            permit = try policy.insertionPermit(snapshot: current)
        } catch {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        // The one carrier value and the one host write. `insertText` returns
        // `Void` and gives no acceptance result.
        let carrier = permit.carrier
        textDocumentProxy.insertText(carrier)
        // Clear the locally held plaintext and recipient regardless of the
        // result: the API gives no acceptance result and the permit is one-use.
        draft = ""
        pendingSelection = nil
        policy.clearSelection()
        draftLabel.text = nil
        draftLabel.accessibilityLabel = nil
        recipientLabel.text = nil
        recipientLabel.accessibilityLabel = nil
        guard policy.liveControl(snapshot()) else {
            // A host callback invalidated the editor during the insertion: do not
            // resurrect any context to acknowledge.
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        status = Copy.string(.exported, in: locale)
        _ = queue(.ack, payload: [
            "pendingId": .string(permit.pendingId),
            "commitText": .bool(true)
        ])
        render()
    }

    // MARK: - Local editing

    private func editable() -> Bool {
        guard started else { return false }
        guard policy.liveControl(snapshot()) else {
            // A failing edit guard is a complete invalidation, never a status
            // change that keeps the local plaintext around.
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return false
        }
        return true
    }

    private func insert(_ character: String) {
        guard editable() else { return }
        guard let next = KeyboardTextEdit.append(character, to: draft) else {
            invalidateEditor(status: Copy.string(.tooLong, in: locale))
            return
        }
        draft = next
        if case .on = shift { shift = .off }
        if status == Copy.string(.starting, in: locale) { status = Copy.string(.sessionActive, in: locale) }
        render()
    }

    private func backspace() {
        guard editable() else { return }
        draft = KeyboardTextEdit.backspace(draft)
        render()
    }

    private func insertSpace() {
        guard editable() else { return }
        if let next = KeyboardTextEdit.append(" ", to: draft) { draft = next }
        render()
    }

    private func insertNewline() {
        guard editable() else { return }
        if let next = KeyboardTextEdit.append("\n", to: draft) { draft = next }
        render()
    }

    // MARK: - Actions

    private func requestContacts() {
        guard hasFullAccess else {
            invalidateEditor(status: Copy.string(.noFullAccess, in: locale))
            return
        }
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        guard queue(.contacts) else { return }
        status = Copy.string(.waiting, in: locale)
        render()
    }

    func selectContact(_ contact: KeyboardContact) {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        pendingSelection = contact
        surface = .confirmation
        confirmLabel.text = """
        \(Copy.string(.confirmPrompt, in: locale))

        \(contact.name)
        \(Copy.string(.fingerprint, in: locale)): \(contact.fingerprint)
        """
        confirmLabel.accessibilityLabel = confirmLabel.text
        render()
    }

    func confirmSelection() {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        guard let contact = pendingSelection else {
            invalidateEditor(status: Copy.string(.chooseRecipient, in: locale))
            return
        }
        // The explicit confirm is typed as a real JSON boolean.
        guard queue(.select, payload: [
            "contactId": .string(contact.id),
            "confirm": .bool(true)
        ]) else {
            return
        }
        // The recipient becomes usable only once the owner re-confirms it in the
        // `select` reply; until then `policy.hasSelection` stays false.
        surface = .keys
        status = Copy.string(.waiting, in: locale)
        render()
    }

    func cancelConfirmation() {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        pendingSelection = nil
        confirmLabel.text = nil
        confirmLabel.accessibilityLabel = nil
        surface = contacts.isEmpty ? .keys : .contacts
        render()
    }

    /// Display the sender of an accepted decode, or clear it.
    ///
    /// This is deliberately display-only and is the single code path used by the
    /// decode grant: it never sets `pendingSelection`, never touches
    /// `policy.hasSelection`, never queues a `select` and never runs from
    /// `render`, a timer or a completion. The sender stays a shortcut the user
    /// must tap explicitly.
    func applyDecodedPreview(_ preview: DecodedPreviewDisplay?) {
        guard let preview else {
            displayedSender = nil
            previewLabel.text = nil
            previewLabel.accessibilityLabel = nil
            if surface == .preview { surface = .keys }
            render()
            return
        }
        displayedSender = KeyboardContact(
            id: preview.contactId,
            name: preview.contactName,
            fingerprint: preview.fingerprint
        )
        previewLabel.text = "\(Copy.string(.from, in: locale)): \(preview.contactName)\n\(preview.text)"
        previewLabel.accessibilityLabel = previewLabel.text
        surface = .preview
        render()
    }

    /// The exact payload of the sender shortcut. It is the same explicit
    /// `select {contactId, confirm:true}` the manual flow uses: no `prepare`, no
    /// `authorize` and no client-side ciphertext.
    func senderSelectPayload(for sender: KeyboardContact) -> [String: KeyboardRequestValue] {
        ["contactId": .string(sender.id), "confirm": .bool(true)]
    }

    /// The explicit sender tap. It is the only thing that can turn a decoded
    /// sender into a recipient, it needs the current live freshness lease, and it
    /// only queues the request: `To:` appears only after the owner re-confirms the
    /// selection in the `select` reply.
    func tapSender() {
        guard let sender = displayedSender else { return }
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        // A tap while another request is in flight is ignored: it never claims a
        // selection and never replaces the outstanding operation.
        guard operation == nil else { return }
        guard queue(.select, payload: senderSelectPayload(for: sender)) else {
            // Refused by admission or the transport: `displayedSender` survives
            // but no selection is claimed and `To:` stays hidden.
            return
        }
        status = Copy.string(.waiting, in: locale)
        render()
    }

    /// Explicit, user-initiated paste. This is the only clipboard read in the
    /// extension: no listener, no timer and no automatic read.
    private func pasteAndDecode() {
        guard hasFullAccess else {
            invalidateEditor(status: Copy.string(.noFullAccess, in: locale))
            return
        }
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        // An explicit decode always drops any previously confirmed recipient and
        // local draft, so a preview can never inherit them, and it drops the
        // previous message's sender shortcut before the new one is known.
        draft = ""
        pendingSelection = nil
        policy.clearSelection()
        draftLabel.text = nil
        draftLabel.accessibilityLabel = nil
        recipientLabel.text = nil
        recipientLabel.accessibilityLabel = nil
        applyDecodedPreview(nil)
        guard let pasted = UIPasteboard.general.string, !pasted.isEmpty else {
            status = Copy.string(.emptyPaste, in: locale)
            render()
            return
        }
        guard pasted.utf16.count <= KeyboardSurfaceBounds.maxInboundCarrierUTF16 else {
            status = Copy.string(.pasteTooLong, in: locale)
            render()
            return
        }
        guard queue(.decode, payload: ["carrier": .string(pasted)]) else { return }
        status = Copy.string(.waiting, in: locale)
        render()
    }

    /// Start one explicit send. The recipient was already confirmed by an
    /// explicit tap plus the owner `select` reply, the draft is non-empty and
    /// bounded, and nothing is inserted until the owner returns a freshly
    /// authorized carrier.
    private func beginSend() {
        guard hasFullAccess else {
            invalidateEditor(status: Copy.string(.noFullAccess, in: locale))
            return
        }
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        guard policy.hasSelection, pendingSelection != nil else {
            invalidateEditor(status: Copy.string(.chooseRecipient, in: locale))
            return
        }
        guard KeyboardTextEdit.isValidDraft(draft) else {
            invalidateEditor(status: Copy.string(.tooLong, in: locale))
            return
        }
        guard queue(.prepare, payload: ["text": .string(draft)]) else { return }
        status = Copy.string(.waiting, in: locale)
        render()
    }

    // MARK: - Host callbacks and notifications

    /// The only OS notification this extension observes is the screen-capture
    /// state it can legally and reliably receive. Device lock is not observable
    /// here: the app host owns the protected-data notification and the extension
    /// relies on disappearance, the heartbeat/grant freshness lease and the
    /// protected App Group storage instead. Memory pressure, host editor changes
    /// and the fixed window are handled by `didReceiveMemoryWarning`, the
    /// text/selection callbacks and the local deadline timers.
    private func observeCaptureState() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(systemInvalidation),
            name: UIScreen.capturedDidChangeNotification,
            object: nil
        )
    }

    /// Capture cannot be blocked and is never claimed to be blocked: the keyboard
    /// simply drops every sensitive value and asks for a new window.
    @objc private func systemInvalidation() {
        invalidateEditor(status: Copy.string(.openApp, in: locale))
    }

    /// Every host text or selection change invalidates the bound editor
    /// generation and every value that belonged to it. This holds even when iOS
    /// reuses the same opaque document identifier for a different host
    /// conversation, and there is deliberately no ignore flag for our own single
    /// insertion.
    private func editorInvalidated() {
        guard started else { return }
        invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
    }

    override func textWillChange(_ textInput: UITextInput?) {
        editorInvalidated()
    }

    override func textDidChange(_ textInput: UITextInput?) {
        editorInvalidated()
    }

    override func selectionWillChange(_ textInput: UITextInput?) {
        editorInvalidated()
    }

    override func selectionDidChange(_ textInput: UITextInput?) {
        editorInvalidated()
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        invalidateEditor(status: Copy.string(.openApp, in: locale))
    }

    // MARK: - Layout

    private static let preferredHeight: CGFloat = 320

    private func buildLayout() {
        view.backgroundColor = .secondarySystemBackground

        statusLabel.font = .preferredFont(forTextStyle: .footnote)
        statusLabel.adjustsFontForContentSizeCategory = true
        statusLabel.textColor = .label
        statusLabel.numberOfLines = 1
        statusLabel.lineBreakMode = .byTruncatingTail
        statusLabel.accessibilityIdentifier = "layergram.status"
        statusLabel.setContentCompressionResistancePriority(.required, for: .vertical)

        draftLabel.font = .preferredFont(forTextStyle: .footnote)
        draftLabel.adjustsFontForContentSizeCategory = true
        draftLabel.textColor = .label
        draftLabel.numberOfLines = 1
        draftLabel.lineBreakMode = .byTruncatingHead
        draftLabel.setContentCompressionResistancePriority(.required, for: .vertical)
        // The local draft never becomes an accessibility value exposed to the
        // host UI.
        draftLabel.isAccessibilityElement = false

        recipientLabel.font = .preferredFont(forTextStyle: .caption1)
        recipientLabel.adjustsFontForContentSizeCategory = true
        recipientLabel.textColor = .secondaryLabel
        recipientLabel.numberOfLines = 1
        recipientLabel.lineBreakMode = .byTruncatingMiddle
        recipientLabel.setContentCompressionResistancePriority(.required, for: .vertical)

        windowLabel.font = .preferredFont(forTextStyle: .caption1)
        windowLabel.adjustsFontForContentSizeCategory = true
        windowLabel.textColor = .secondaryLabel
        windowLabel.textAlignment = .right
        windowLabel.numberOfLines = 1
        windowLabel.setContentCompressionResistancePriority(.required, for: .vertical)

        let infoRow = UIStackView(arrangedSubviews: [recipientLabel, windowLabel])
        infoRow.axis = .horizontal
        infoRow.spacing = 6
        infoRow.distribution = .fillEqually

        previewLabel.font = .preferredFont(forTextStyle: .body)
        previewLabel.adjustsFontForContentSizeCategory = true
        previewLabel.textColor = .label
        previewLabel.numberOfLines = 0
        previewLabel.isUserInteractionEnabled = false
        previewScroll.addSubview(previewLabel)
        previewScroll.showsVerticalScrollIndicator = true
        previewScroll.alwaysBounceVertical = true
        previewScroll.layer.cornerRadius = 8
        previewScroll.backgroundColor = .tertiarySystemBackground
        previewScroll.translatesAutoresizingMaskIntoConstraints = false
        previewLabel.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            previewLabel.leadingAnchor.constraint(equalTo: previewScroll.leadingAnchor, constant: 8),
            previewLabel.trailingAnchor.constraint(equalTo: previewScroll.trailingAnchor, constant: -8),
            previewLabel.topAnchor.constraint(equalTo: previewScroll.topAnchor, constant: 6),
            previewLabel.bottomAnchor.constraint(equalTo: previewScroll.bottomAnchor, constant: -6),
            previewLabel.widthAnchor.constraint(equalTo: previewScroll.widthAnchor, constant: -16)
        ])
        let previewHeight = previewScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 46)
        previewHeight.priority = UILayoutPriority(999)
        previewHeight.isActive = true
        previewScroll.accessibilityIdentifier = "layergram.preview"

        contactsView.dataSource = self
        contactsView.delegate = self
        contactsView.register(UITableViewCell.self, forCellReuseIdentifier: "contact")
        contactsView.backgroundColor = .tertiarySystemBackground
        contactsView.layer.cornerRadius = 8

        keysStack.axis = .vertical
        keysStack.spacing = 6
        keysStack.distribution = .fillEqually
        keysStack.translatesAutoresizingMaskIntoConstraints = false
        keysContainer.addSubview(keysStack)
        NSLayoutConstraint.activate([
            keysStack.leadingAnchor.constraint(equalTo: keysContainer.leadingAnchor),
            keysStack.trailingAnchor.constraint(equalTo: keysContainer.trailingAnchor),
            keysStack.topAnchor.constraint(equalTo: keysContainer.topAnchor),
            keysStack.bottomAnchor.constraint(lessThanOrEqualTo: keysContainer.bottomAnchor)
        ])

        confirmLabel.font = .preferredFont(forTextStyle: .footnote)
        confirmLabel.adjustsFontForContentSizeCategory = true
        confirmLabel.numberOfLines = 0
        confirmLabel.translatesAutoresizingMaskIntoConstraints = false
        confirmView.addSubview(confirmLabel)
        NSLayoutConstraint.activate([
            confirmLabel.leadingAnchor.constraint(equalTo: confirmView.leadingAnchor, constant: 8),
            confirmLabel.trailingAnchor.constraint(equalTo: confirmView.trailingAnchor, constant: -8),
            confirmLabel.topAnchor.constraint(equalTo: confirmView.topAnchor, constant: 4)
        ])

        shortcutsStack.axis = .horizontal
        shortcutsStack.spacing = 6
        shortcutsStack.distribution = .fillProportionally
        shortcutsStack.alignment = .fill

        // The decoded-sender reply shortcut. It is display-only until tapped and
        // lives in the header next to the preview it belongs to.
        senderButton.setTitleColor(.label, for: .normal)
        senderButton.titleLabel?.font = .preferredFont(forTextStyle: .footnote)
        senderButton.titleLabel?.adjustsFontForContentSizeCategory = true
        senderButton.titleLabel?.numberOfLines = 1
        senderButton.titleLabel?.lineBreakMode = .byTruncatingTail
        senderButton.backgroundColor = .secondarySystemFill
        senderButton.layer.cornerRadius = 6
        senderButton.accessibilityIdentifier = "layergram.action.sender"
        senderButton.addTarget(self, action: #selector(tapSenderButton), for: .touchUpInside)
        senderButton.isHidden = true
        let senderHeight = senderButton.heightAnchor.constraint(equalToConstant: 44)
        senderHeight.priority = UILayoutPriority(999)
        senderHeight.isActive = true

        // The persistent fallback globe lives outside `keysContainer`, so the
        // globe stays reachable on the contacts and confirmation surfaces where
        // the whole key layout (including its bottom-row globe) is hidden.
        fallbackGlobeButton.setTitle("🌐", for: .normal)
        fallbackGlobeButton.titleLabel?.font = .preferredFont(forTextStyle: .body)
        fallbackGlobeButton.titleLabel?.adjustsFontForContentSizeCategory = true
        fallbackGlobeButton.setTitleColor(.label, for: .normal)
        fallbackGlobeButton.backgroundColor = .secondarySystemFill
        fallbackGlobeButton.layer.cornerRadius = 6
        fallbackGlobeButton.accessibilityIdentifier = "layergram.action.globe"
        fallbackGlobeButton.accessibilityLabel = Copy.string(.globeSwitch, in: locale)
        fallbackGlobeButton.addTarget(
            self,
            action: #selector(tapFallbackGlobe),
            for: .touchUpInside
        )
        fallbackGlobeButton.isHidden = true
        footerStack.axis = .horizontal
        footerStack.distribution = .fill
        footerStack.addArrangedSubview(fallbackGlobeButton)
        footerStack.addArrangedSubview(UIView())
        fallbackGlobeButton.heightAnchor.constraint(
            equalToConstant: Self.keyRowHeight
        ).isActive = true
        fallbackGlobeButton.widthAnchor.constraint(equalToConstant: 64).isActive = true

        let header = UIStackView(arrangedSubviews: [statusLabel, infoRow, draftLabel])
        header.axis = .vertical
        header.spacing = 2
        header.setContentHuggingPriority(.required, for: .vertical)

        // Reading uses the key area, so plaintext and its reply action keep
        // usable frames instead of competing with four fixed-height key rows.
        previewContainer.axis = .vertical
        previewContainer.spacing = 6
        previewContainer.addArrangedSubview(previewScroll)
        previewContainer.addArrangedSubview(senderButton)

        let content = UIStackView(arrangedSubviews: [contactsView, confirmView, keysContainer, previewContainer])
        content.axis = .vertical
        content.setContentHuggingPriority(.defaultLow, for: .vertical)

        // The action bar is always present: choosing a recipient, encrypting and
        // pasting are discoverable before any recipient exists. The globe lives
        // inside the key layout's bottom row and, when that row is hidden, in the
        // persistent footer instead of this bar.
        let actions = UIStackView(arrangedSubviews: [shortcutsStack])
        actions.axis = .vertical
        actions.spacing = 6
        let actionHeight = actions.heightAnchor.constraint(
            greaterThanOrEqualToConstant: Self.actionBarMinimumHeight
        )
        actionHeight.priority = .required
        actionHeight.isActive = true

        let root = UIStackView(arrangedSubviews: [header, content, actions, footerStack])
        root.axis = .vertical
        root.spacing = 6
        root.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 6),
            root.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -6),
            root.topAnchor.constraint(equalTo: view.topAnchor, constant: 6),
            root.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -6)
        ])
        // A preference only: the system may impose its own input-view height, so
        // this constraint is never required and cannot conflict.
        let height = view.heightAnchor.constraint(equalToConstant: Self.preferredHeight)
        height.priority = .defaultHigh
        height.isActive = true
    }

    private func remainingWindowText() -> String? {
        guard started, policy.isBeginAccepted else { return nil }
        let remaining = sessionDeadlineMonotonicMillis - monotonicNow
        guard remaining > 0 else { return nil }
        let seconds = (remaining + 999) / 1000
        return "\(Copy.string(.window, in: locale)): \(seconds)s"
    }

    private func render() {
        statusLabel.text = status
        draftLabel.text = draft.isEmpty ? nil : "\(Copy.string(.draft, in: locale)): \(draft)"
        draftLabel.isHidden = draft.isEmpty
        draftLabel.accessibilityLabel = nil
        if let name = pendingSelection?.name {
            recipientLabel.text = "\(Copy.string(.to, in: locale)): \(name)"
        } else {
            recipientLabel.text = nil
        }
        recipientLabel.accessibilityLabel = nil
        windowLabel.text = remainingWindowText()
        windowLabel.accessibilityLabel = nil
        let hasPreview = !(previewLabel.text ?? "").isEmpty
        previewScroll.isHidden = !hasPreview
        // The sender shortcut is shown only while a decoded sender exists on the
        // key surface. Rendering never selects it: only an explicit tap does.
        if let sender = displayedSender, surface == .preview {
            senderButton.setTitle(
                "\(Copy.string(.replyTo, in: locale)) \(sender.name)",
                for: .normal
            )
            senderButton.accessibilityLabel =
                "\(Copy.string(.replyTo, in: locale)) \(sender.name)"
            senderButton.accessibilityHint = Copy.string(.senderTapHint, in: locale)
            senderButton.isHidden = false
        } else {
            senderButton.setTitle(nil, for: .normal)
            senderButton.accessibilityLabel = nil
            senderButton.accessibilityHint = nil
            senderButton.isHidden = true
        }
        contactsView.isHidden = (surface != .contacts)
        confirmView.isHidden = (surface != .confirmation)
        keysContainer.isHidden = (surface != .keys)
        previewContainer.isHidden = (surface != .preview)
        // The fallback globe is exactly the inverse of the key surface: when the
        // key layout (and its bottom-row globe) is hidden, this control keeps
        // input-mode switching available.
        fallbackGlobeButton.isHidden = (surface == .keys)
        footerStack.isHidden = (surface == .keys)
        if surface == .contacts { contactsView.reloadData() }
        if surface == .keys { renderKeys() }
        renderShortcuts()
    }

    // MARK: - Key layout

    /// Width removed on each side of the second and third letter rows, so the
    /// familiar iPhone rows are visibly inset under the ten-key top row.
    static let insetRowInset: CGFloat = 14
    /// Rows are laid out at a fixed, tappable height. The height is fixed
    /// precisely so an ordinary character can repaint labels without rebuilding
    /// or re-measuring the whole key layout.
    static let keyRowHeight: CGFloat = 44
    private static let keySpacing: CGFloat = 5
    /// Minimum height of the persistent action bar that always holds recipient,
    /// encrypt and paste controls.
    static let actionBarMinimumHeight: CGFloat = 44

    /// The complete, layer-dependent key layout. It is pure: it takes the layer,
    /// shift and an explicit text permutation and builds no view. Only the text
    /// slots of the letter rows are ever permuted; the surrounding action keys are
    /// not part of these rows at all.
    static func layout(
        layer: Layer,
        shift: ShiftState,
        permutation: [Int: [Int]]?
    ) -> [KeyboardRow] {
        switch layer {
        case .letters:
            var tag = 0
            return letterRowCharacters.enumerated().map { index, letters in
                let ordered = permuted(letters, order: permutation?[index])
                let keys = ordered.map { character -> KeyboardKey in
                    let label = shifted(character, shift: shift)
                    let key = KeyboardKey(label: label, kind: .text(label), textTag: tag)
                    tag += 1
                    return key
                }
                return KeyboardRow(keys: keys, inset: index > 0)
            }
        case .numbers:
            return rows(from: numericRows)
        case .symbols:
            return rows(from: symbolRows)
        }
    }

    /// Instance view of `layout(layer:shift:permutation:)` using the live local
    /// state. The neutral permutation only exists once the owner reported the
    /// scramble capability; it is chosen once per keyboard open.
    func keyboardLayout() -> [KeyboardRow] {
        Self.layout(layer: layer, shift: shift, permutation: currentPermutation())
    }

    private func currentPermutation() -> [Int: [Int]]? {
        guard scrambleEnabled else { return nil }
        for index in Self.letterRowCharacters.indices where scrambledIndex[index] == nil {
            scrambledIndex[index] = Array(Self.letterRowCharacters[index].indices).shuffled()
        }
        return scrambledIndex
    }

    /// Reorders one text run by an explicit permutation. `nil` is the identity,
    /// and a malformed order is ignored rather than silently mis-mapping a key.
    static func permuted(_ characters: [String], order: [Int]?) -> [String] {
        guard let order,
              order.count == characters.count,
              Set(order) == Set(characters.indices) else { return characters }
        return order.map { characters[$0] }
    }

    static func shifted(_ character: String, shift: ShiftState) -> String {
        switch shift {
        case .off: return character.lowercased()
        case .on, .locked: return character.uppercased()
        }
    }

    /// Builds the rows of an explicit non-letter layer. Every row is a complete,
    /// hand-chosen keyset, so no key is ever silently dropped to fit geometry.
    static func rows(from source: [[String]]) -> [KeyboardRow] {
        source.enumerated().map { index, characters in
            let keys = characters.map { character in
                KeyboardKey(label: character, kind: .text(character), textTag: nil)
            }
            return KeyboardRow(keys: keys, inset: index > 0)
        }
    }

    /// The unwrapped order of each letter row. Only these characters are ever
    /// permuted; the surrounding action keys are not part of the rows.
    static let letterRowCharacters: [[String]] = [
        ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
        ["a", "s", "d", "f", "g", "h", "j", "k", "l"],
        ["z", "x", "c", "v", "b", "n", "m"]
    ]

    /// The numeric page. The third row holds exactly seven keys because it sits
    /// between the layer toggle and backspace, so the common operators (`+`, `=`,
    /// `*`) live on the reachable `#+=` page instead of being trimmed away.
    static let numericRows: [[String]] = [
        ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"],
        ["-", "/", ":", ";", "(", ")", "$", "&", "@", "\""],
        [".", ",", "?", "!", "'", "#", "%"]
    ]

    /// The explicit `#+=` page. It keeps the common operators (`+`, `=`, `*`) and
    /// the currency/typographic symbols reachable in one extra tap from numbers.
    static let symbolRows: [[String]] = [
        ["[", "]", "{", "}", "#", "%", "^", "*", "+", "="],
        ["_", "\\", "|", "~", "<", ">", "€", "£", "¥", "•"],
        ["…", "—", "°", "±", "§", "¶", "×"]
    ]

    /// Positional bottom row: layer, globe, wide space, return. The globe is
    /// always present and always before space, even when the session is
    /// unavailable, so switching keyboards never depends on Layergram.
    private func bottomRow() -> UIStackView {
        let row = UIStackView()
        row.axis = .horizontal
        row.spacing = Self.keySpacing
        row.distribution = .fill

        let layerPresentation = Self.layerPresentation(for: layer)
        let layerButton = makeActionButton(layerPresentation.title, action: layerPresentation.action)
        layerButton.widthAnchor.constraint(equalToConstant: 44).isActive = true
        let globe = makeActionButton("🌐", action: .globe)
        globe.accessibilityLabel = Copy.string(.globeSwitch, in: locale)
        globe.widthAnchor.constraint(equalToConstant: 44).isActive = true
        let space = makeActionButton(Copy.string(.space, in: locale), action: .space)
        // The space key stays the widest control without letting the spacers
        // collapse it on a narrow 320 pt input view.
        let spaceWidth = space.widthAnchor.constraint(greaterThanOrEqualToConstant: 120)
        spaceWidth.priority = .defaultHigh
        spaceWidth.isActive = true
        let newline = makeActionButton(Copy.string(.returnKey, in: locale), action: .newline)
        newline.widthAnchor.constraint(equalToConstant: 64).isActive = true
        newline.titleLabel?.adjustsFontSizeToFitWidth = true
        newline.titleLabel?.minimumScaleFactor = 0.7
        space.setContentHuggingPriority(.defaultLow, for: .horizontal)

        for key in [layerButton, globe, space, newline] {
            key.heightAnchor.constraint(equalToConstant: Self.keyRowHeight).isActive = true
        }
        row.addArrangedSubview(layerButton)
        row.addArrangedSubview(globe)
        row.addArrangedSubview(space)
        row.addArrangedSubview(newline)
        return row
    }

    private func renderKeys() {
        // Build the (pure) layout first: shift is applied to the labels here, so
        // the signature below also covers the shift and permutation state.
        let layout = keyboardLayout()
        let leading = Self.thirdRowLeadingPresentation(for: layer, shift: shift)
        let signature = "\(layer)|\(leading.title)|\(leading.action.rawValue)|" + layout
            .map { $0.keys.map(\.label).joined(separator: ",") }
            .joined(separator: "/")
        // Rebuild only when the layout itself changed: an ordinary character
        // only repaints the draft label, never the key views.
        guard signature != rowsSignature else {
            refreshShiftTitles()
            return
        }
        for view in keysStack.arrangedSubviews {
            keysStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
        actionButtons = [:]
        // Stable identity for every text key view, used by accessibility and the
        // native layout tests. The typed character still comes from the button
        // title, so a permuted label keeps typing what it shows.
        var textSlot = 0

        for (index, descriptor) in layout.enumerated() {
            if index == layout.count - 1 { continue }
            let row = UIStackView()
            row.axis = .horizontal
            row.spacing = Self.keySpacing
            row.distribution = .fillEqually
            for key in descriptor.keys {
                guard case .text(let character) = key.kind else { continue }
                let button = makeKeyButton(character)
                button.tag = key.textTag ?? 0
                Self.identifyTextKey(button, slot: textSlot)
                textSlot += 1
                button.heightAnchor.constraint(equalToConstant: Self.keyRowHeight).isActive = true
                row.addArrangedSubview(button)
            }
            keysStack.addArrangedSubview(insetRow(row, descriptor.inset))
        }

        // The third row is the familiar leading action / seven text keys /
        // backspace run. On the letters layer the leading action is Shift; on the
        // numeric and symbol pages it is the `#+=` / `123` page toggle, so the
        // action keys never sit inside the permuted text run.
        let actionRow = UIStackView()
        actionRow.axis = .horizontal
        actionRow.spacing = Self.keySpacing
        actionRow.distribution = .fillEqually
        let leadingButton: UIButton
        if leading.action == .shift {
            leadingButton = makeActionButton(Self.shiftGlyph(for: shift), action: .shift)
        } else {
            leadingButton = makeActionButton(leading.title, action: leading.action)
        }
        let backspaceButton = makeActionButton(Copy.string(.deleteKey, in: locale), action: .backspace)
        backspaceButton.setImage(deleteSymbolImage(), for: .normal)
        actionRow.addArrangedSubview(leadingButton)
        for key in layout.last?.keys ?? [] {
            guard case .text(let character) = key.kind else { continue }
            let button = makeKeyButton(character)
            button.tag = key.textTag ?? 0
            Self.identifyTextKey(button, slot: textSlot)
            textSlot += 1
            button.heightAnchor.constraint(equalToConstant: Self.keyRowHeight).isActive = true
            actionRow.addArrangedSubview(button)
        }
        actionRow.addArrangedSubview(backspaceButton)
        for button in actionRow.arrangedSubviews.compactMap({ $0 as? UIButton }) {
            button.heightAnchor.constraint(equalToConstant: Self.keyRowHeight).isActive = true
        }
        keysStack.addArrangedSubview(insetRow(actionRow, true))
        keysStack.addArrangedSubview(bottomRow())
        rowsSignature = signature
        refreshShiftTitles()
    }

    /// The layout as [row][keys] with the action keys included, in render order.
    /// Pure: tests can assert every layer and an explicit permutation without a
    /// live owner session, and this is the exact geometry the keyboard renders.
    static func renderedLayout(
        layer: Layer,
        shift: ShiftState,
        permutation: [Int: [Int]]?,
        language: Language
    ) -> [[KeyboardKey]] {
        let rows = layout(layer: layer, shift: shift, permutation: permutation)
        var result: [[KeyboardKey]] = rows.dropLast().map(\.keys)
        let third = rows.last?.keys ?? []
        let leading = thirdRowLeadingPresentation(for: layer, shift: shift)
        let backspace = KeyboardKey(
            label: Copy.string(.deleteKey, in: language),
            kind: .action(.backspace),
            textTag: nil
        )
        result.append(
            [KeyboardKey(label: leading.title, kind: .action(leading.action), textTag: nil)]
                + third + [backspace]
        )
        let layerPresentation = layerPresentation(for: layer)
        result.append([
            KeyboardKey(
                label: layerPresentation.title,
                kind: .action(layerPresentation.action),
                textTag: nil
            ),
            KeyboardKey(label: "🌐", kind: .action(.globe), textTag: nil),
            KeyboardKey(
                label: Copy.string(.space, in: language),
                kind: .action(.space),
                textTag: nil
            ),
            KeyboardKey(
                label: Copy.string(.returnKey, in: language),
                kind: .action(.newline),
                textTag: nil
            )
        ])
        return result
    }

    /// Instance view of the pure `renderedLayout` using the live local state.
    func renderedLayout() -> [[KeyboardKey]] {
        Self.renderedLayout(
            layer: layer,
            shift: shift,
            permutation: currentPermutation(),
            language: Copy.language(locale)
        )
    }

    static func shiftGlyph(for state: ShiftState) -> String {
        switch state {
        case .off, .on: return "⇧"
        case .locked: return "⇪"
        }
    }

    /// The leading action of the third row. Letters keep the familiar Shift key;
    /// the numeric and symbol pages put their page toggle there, so no useless
    /// Shift key appears and no layer needs a three-step cycle back to letters.
    static func thirdRowLeadingPresentation(
        for layer: Layer,
        shift: ShiftState
    ) -> (title: String, action: KeyAction) {
        switch layer {
        case .letters: return (shiftGlyph(for: shift), .shift)
        case .numbers: return ("#+=", .symbols)
        case .symbols: return ("123", .symbols)
        }
    }

    /// The title and action of the bottom-left layer key. Letters offer `123`;
    /// the numeric and symbol pages offer `ABC` and return straight to letters.
    static func layerPresentation(for layer: Layer) -> (title: String, action: KeyAction) {
        switch layer {
        case .letters: return ("123", .layer)
        case .numbers, .symbols: return ("ABC", .layer)
        }
    }

    /// Pure layer transition for the two layer controls. `.layer` is the
    /// bottom-left key: letters <-> numbers, and both non-letter pages return
    /// directly to letters. `.symbols` is the third-row toggle between the two
    /// non-letter pages.
    static func layerAfter(_ layer: Layer, tapped action: KeyAction) -> Layer {
        switch action {
        case .layer:
            return (layer == .letters) ? .numbers : .letters
        case .symbols:
            if layer == .numbers { return .symbols }
            if layer == .symbols { return .numbers }
            return layer
        default:
            return layer
        }
    }

    /// Repaint only the titles that depend on the shift state, leaving the key
    /// views in place.
    private func refreshShiftTitles() {
        actionButtons[.shift]?.setTitle(Self.shiftGlyph(for: shift), for: .normal)
        actionButtons[.backspace]?.setTitle(nil, for: .normal)
        actionButtons[.backspace]?.accessibilityLabel = Copy.string(.deleteKey, in: locale)
    }

    private func insetRow(_ row: UIStackView, _ inset: Bool) -> UIView {
        guard inset else { return row }
        let container = UIView()
        row.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(row)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(
                equalTo: container.leadingAnchor,
                constant: Self.insetRowInset
            ),
            row.trailingAnchor.constraint(
                equalTo: container.trailingAnchor,
                constant: -Self.insetRowInset
            ),
            row.topAnchor.constraint(equalTo: container.topAnchor),
            row.bottomAnchor.constraint(equalTo: container.bottomAnchor)
        ])
        return container
    }

    private func deleteSymbolImage() -> UIImage? {
        guard #available(iOS 13.0, *) else { return nil }
        return UIImage(systemName: "delete.left")
    }

    private func renderShortcuts() {
        for view in shortcutsStack.arrangedSubviews {
            shortcutsStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
        if surface == .confirmation {
            shortcutsStack.addArrangedSubview(
                makeShortcut(
                    Copy.string(.cancel, in: locale),
                    action: #selector(tapCancel),
                    identifier: "layergram.action.cancel"
                )
            )
            shortcutsStack.addArrangedSubview(
                makeShortcut(
                    Copy.string(.confirm, in: locale),
                    action: #selector(tapConfirm),
                    identifier: "layergram.action.confirm"
                )
            )
            return
        }
        if surface == .contacts || surface == .preview {
            shortcutsStack.addArrangedSubview(
                makeShortcut(
                    Copy.string(.compose, in: locale),
                    action: #selector(tapBackToKeys),
                    identifier: "layergram.action.back"
                )
            )
            return
        }
        // Persistent, always visible: choosing the recipient, encrypting and
        // pasting are discoverable before any recipient exists. The primary
        // action never disappears and is never hidden behind a selection.
        shortcutsStack.addArrangedSubview(
            makeShortcut(
                Copy.string(.contacts, in: locale),
                action: #selector(tapContacts),
                identifier: "layergram.action.recipient"
            )
        )
        if displayedSender != nil {
            shortcutsStack.addArrangedSubview(makeShortcut(
                Copy.string(.readMessage, in: locale), action: #selector(tapReadMessage),
                identifier: "layergram.action.read"
            ))
        }
        let primary = makeShortcut(
            primaryActionTitle(),
            action: #selector(tapPrimary),
            identifier: "layergram.action.primary"
        )
        primary.titleLabel?.font = .preferredFont(forTextStyle: .subheadline)
        shortcutsStack.addArrangedSubview(primary)
        shortcutsStack.addArrangedSubview(
            makeShortcut(
                Copy.string(.pasteDecrypt, in: locale),
                action: #selector(tapPaste),
                identifier: "layergram.action.paste"
            )
        )
        if !draft.isEmpty || pendingSelection != nil {
            shortcutsStack.addArrangedSubview(
                makeShortcut(
                    Copy.string(.newMessage, in: locale),
                    action: #selector(tapNewMessage),
                    identifier: "layergram.action.new"
                )
            )
        }
    }

    /// The pure primary-action decision.
    ///
    /// Admission is decided first: without a live session the action must not
    /// replace the need-Full-Access / open-the-app message with a workflow hint.
    /// With admission, a usable recipient needs both the owner-confirmed
    /// selection and a non-empty draft; anything else selects a recipient and
    /// never sends.
    func primaryIntent(
        admitted: Bool,
        draft: String,
        recipient: Bool,
        candidate: Bool
    ) -> PrimaryIntent {
        guard admitted else { return .blockedByAdmission }
        guard !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return .promptEmptyDraft
        }
        return (recipient && candidate) ? .send : .openRecipientSelection
    }

    func primaryIntentForCurrentState() -> PrimaryIntent {
        primaryIntent(
            admitted: policy.liveControl(snapshot()),
            draft: draft,
            recipient: policy.hasSelection,
            candidate: pendingSelection != nil
        )
    }

    private func primaryActionTitle() -> String {
        Copy.string(.encryptInsert, in: locale)
    }

    /// A tap on the primary action. It only ever opens recipient selection or
    /// queues the explicit send: it never sends by itself, never clears the
    /// draft to reach a recipient, and never revokes a valid session because the
    /// draft happens to be empty.
    private func receivePrimaryTap() {
        switch primaryIntentForCurrentState() {
        case .blockedByAdmission:
            // Keep the admission status untouched and revoke nothing.
            render()
        case .promptEmptyDraft:
            status = Copy.string(.emptyDraftHint, in: locale)
            render()
        case .openRecipientSelection:
            requestContacts()
        case .send:
            beginSend()
        }
    }

    private func makeShortcut(_ title: String, action: Selector, identifier: String) -> UIButton {
        let button = UIButton(type: .system)
        button.setTitle(title, for: .normal)
        button.titleLabel?.font = .preferredFont(forTextStyle: .footnote)
        button.titleLabel?.adjustsFontForContentSizeCategory = true
        button.titleLabel?.numberOfLines = 2
        button.titleLabel?.textAlignment = .center
        button.backgroundColor = .tertiarySystemFill
        button.layer.cornerRadius = 6
        button.accessibilityIdentifier = identifier
        button.addTarget(self, action: action, for: .touchUpInside)
        return button
    }

    /// Give a text key view a stable, non-action identity. `KeyAction.from`
    /// rejects it, so it can never be mistaken for a positional action key.
    private static func identifyTextKey(_ button: UIButton, slot: Int) {
        button.accessibilityIdentifier = "\(KeyAction.identifierPrefix)text.\(slot)"
    }

    private func makeKeyButton(_ label: String) -> UIButton {
        let button = UIButton(type: .system)
        button.setTitle(label, for: .normal)
        button.titleLabel?.font = .preferredFont(forTextStyle: .title3)
        button.titleLabel?.adjustsFontForContentSizeCategory = true
        button.setTitleColor(.label, for: .normal)
        button.backgroundColor = .systemBackground
        button.layer.cornerRadius = 6
        button.addTarget(self, action: #selector(tapKey(_:)), for: .touchUpInside)
        return button
    }

    private func makeActionButton(_ label: String, action: KeyAction) -> UIButton {
        let button = UIButton(type: .system)
        button.setTitle(label, for: .normal)
        button.titleLabel?.font = .preferredFont(forTextStyle: .body)
        button.titleLabel?.adjustsFontForContentSizeCategory = true
        button.setTitleColor(.label, for: .normal)
        button.backgroundColor = .secondarySystemFill
        button.layer.cornerRadius = 6
        button.accessibilityIdentifier = action.identifier
        button.addTarget(self, action: #selector(tapAction(_:)), for: .touchUpInside)
        if action == .backspace {
            let hold = UILongPressGestureRecognizer(
                target: self,
                action: #selector(holdBackspace(_:))
            )
            hold.minimumPressDuration = 0.4
            button.addGestureRecognizer(hold)
        }
        actionButtons[action] = button
        return button
    }

    /// Resolve a tapped action key from its stable identifier. Kept free of any
    /// admission check so the globe can be exercised directly.
    func resolveKeyAction(_ identifier: String?) -> KeyAction? {
        KeyAction.from(identifier)
    }

    /// Seed the local draft so the workflow decisions can be exercised without a
    /// live owner session. This only sets display state: it grants no admission,
    /// no lease and no recipient, so it cannot be used to bypass a policy gate.
    func setLocalDraft(_ text: String) {
        draft = KeyboardTextEdit.isValidDraft(text) ? text : draft
        render()
    }

    /// Put the keyboard on one surface so the persistent-control and visibility
    /// rules can be asserted. Display state only: it grants no admission, no
    /// lease, no recipient and cannot queue anything.
    func setSurfaceForDisplay(_ newSurface: Surface) {
        surface = newSurface
        render()
    }

    /// Read-only view of the key container, so tests can prove the fallback globe
    /// is not inside the container that gets hidden off the key surface.
    var keysContainerView: UIView { keysContainer }

    /// Read-only proof of the owner-confirmed recipient. A decoded sender must
    /// never make this `true` on its own.
    var hasConfirmedOwnerSelection: Bool { policy.hasSelection }

    // MARK: - Key handling

    /// The tapped character comes from the button title itself, so the tagged
    /// text buttons stay correct even when the neutral scramble is active.
    @objc private func tapKey(_ sender: UIButton) {
        guard let label = sender.title(for: .normal), !label.isEmpty else { return }
        insert(label)
    }

    @objc private func tapAction(_ sender: UIButton) {
        guard let action = KeyAction.from(sender.accessibilityIdentifier) else { return }
        if action == .globe {
            // The globe is always available: switching keyboards never depends on
            // a live Layergram session.
            advanceToNextInputMode()
            return
        }
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        switch action {
        case .shift:
            switch shift {
            case .off: shift = .on
            case .on: shift = .locked
            case .locked: shift = .off
            }
            render()
        case .backspace:
            backspace()
        case .space:
            insertSpace()
        case .newline:
            insertNewline()
        case .globe:
            advanceToNextInputMode()
        case .layer, .symbols:
            layer = Self.layerAfter(layer, tapped: action)
            render()
        }
    }

    @objc private func holdBackspace(_ recognizer: UILongPressGestureRecognizer) {
        switch recognizer.state {
        case .began:
            backspace()
            let timer = Timer(timeInterval: 0.08, repeats: true) { [weak self] _ in
                self?.backspace()
            }
            repeatTimer = timer
            RunLoop.main.add(timer, forMode: .common)
        case .ended, .cancelled, .failed:
            repeatTimer?.invalidate()
            repeatTimer = nil
        default:
            break
        }
    }

    @objc private func tapContacts() {
        switch surface {
        case .keys, .preview:
            requestContacts()
        case .contacts:
            tapBackToKeys()
        case .confirmation:
            guard policy.liveControl(snapshot()) else {
                invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
                return
            }
            surface = .contacts
            render()
        }
    }

    @objc private func tapBackToKeys() {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        surface = .keys
        render()
    }

    @objc private func tapReadMessage() {
        guard displayedSender != nil, policy.liveControl(snapshot()) else { return }
        surface = .preview
        render()
    }

    @objc private func tapPaste() {
        pasteAndDecode()
    }

    /// The explicit sender shortcut. There is no other path from a decoded
    /// message to a recipient, and this one still requires the owner to accept
    /// the `select`.
    @objc private func tapSenderButton() {
        tapSender()
    }

    /// The persistent fallback globe. Like the bottom-row globe it is never
    /// admission gated, so switching keyboards always works.
    @objc private func tapFallbackGlobe() {
        advanceToNextInputMode()
    }

    /// The persistent primary control. Kept internal so the flow rules can be
    /// exercised directly; it only decides between explanation, recipient
    /// selection and one explicit send.
    @objc func tapPrimary() {
        receivePrimaryTap()
    }

    @objc private func tapConfirm() {
        confirmSelection()
    }

    @objc private func tapCancel() {
        cancelConfirmation()
    }

    @objc private func tapNewMessage() {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        draft = ""
        policy.clearSelection()
        pendingSelection = nil
        // A new message drops the previous decode, its preview and its sender
        // shortcut.
        applyDecodedPreview(nil)
        confirmLabel.text = nil
        confirmLabel.accessibilityLabel = nil
        surface = .keys
        status = Copy.string(.sessionActive, in: locale)
        render()
    }
}

// MARK: - Policy listener

extension KeyboardViewController: KeyboardPolicyListener {
    func keyboardPolicyReady(scramble: Bool) {
        // Only an exact `true` from `begin.data.scramble` enables the local
        // key-layout shuffle; it never scrambles anything the owner sends.
        scrambleEnabled = scramble
        scrambledIndex = [:]
        render()
    }

    func keyboardPolicyResponse(_ response: KeyboardResponse, operation: KeyboardOperation) {
        // The view controller drives its own state from the polled reply; this
        // sink keeps the policy free of any UI reference.
    }

    func keyboardPolicyCleared() {
        clearSensitiveValues()
        render()
    }
}

// MARK: - Contacts list

extension KeyboardViewController: UITableViewDataSource, UITableViewDelegate {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        policy.liveControl(snapshot()) ? contacts.count : 0
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "contact", for: indexPath)
        var configuration = cell.defaultContentConfiguration()
        guard policy.liveControl(snapshot()), indexPath.row < contacts.count else {
            // A reusable cell is always blanked before it can be reused.
            configuration.text = nil
            configuration.secondaryText = nil
            cell.contentConfiguration = configuration
            return cell
        }
        let contact = contacts[indexPath.row]
        configuration.text = contact.name
        configuration.secondaryText = "\(Copy.string(.fingerprint, in: locale)): \(contact.fingerprint)"
        cell.contentConfiguration = configuration
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: false)
        guard policy.liveControl(snapshot()), indexPath.row < contacts.count else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        // An explicit tap opens confirmation; a decoded contact is never selected
        // automatically.
        selectContact(contacts[indexPath.row])
    }
}
