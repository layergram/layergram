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

    /// Local Italian and English labels. No passphrase, identity reason, icon or
    /// lock detail is ever shown.
    private enum Copy {
        static func isItalian(_ locale: Locale) -> Bool {
            locale.languageCode?.lowercased() == "it"
        }

        static func space(_ l: Locale) -> String { isItalian(l) ? "spazio" : "space" }
        static func returnKey(_ l: Locale) -> String { isItalian(l) ? "invio" : "return" }
        static func deleteKey(_ l: Locale) -> String { isItalian(l) ? "canc" : "del" }
        static func contacts(_ l: Locale) -> String { isItalian(l) ? "Rubrica" : "Contacts" }
        static func paste(_ l: Locale) -> String { isItalian(l) ? "Incolla" : "Paste" }
        static func send(_ l: Locale) -> String { isItalian(l) ? "Cifra" : "Encrypt" }
        static func confirm(_ l: Locale) -> String { isItalian(l) ? "Conferma" : "Confirm" }
        static func cancel(_ l: Locale) -> String { isItalian(l) ? "Annulla" : "Cancel" }
        static func newMessage(_ l: Locale) -> String { isItalian(l) ? "Nuovo" : "New" }
        static func recipient(_ l: Locale) -> String { isItalian(l) ? "Destinatario" : "Recipient" }
        static func draft(_ l: Locale) -> String { isItalian(l) ? "Bozza" : "Draft" }
        static func window(_ l: Locale) -> String { isItalian(l) ? "Finestra" : "Window" }
        static func fp(_ l: Locale) -> String { isItalian(l) ? "Impronta" : "Fingerprint" }
        static func previewTitle(_ l: Locale) -> String { isItalian(l) ? "Anteprima" : "Preview" }

        static func confirmPrompt(_ l: Locale) -> String {
            isItalian(l)
                ? "Conferma il destinatario e verifica l'impronta."
                : "Confirm the recipient and check the fingerprint."
        }
        static func minimumSystem(_ l: Locale) -> String {
            isItalian(l) ? "La tastiera richiede iOS 26 o successivo."
                : "The keyboard requires iOS 26 or later."
        }
        static func openApp(_ l: Locale) -> String {
            isItalian(l)
                ? "Apri e sblocca Layergram manualmente, poi torna qui."
                : "Open and unlock Layergram manually, then come back here."
        }
        static func unavailable(_ l: Locale) -> String {
            isItalian(l) ? "Layergram non è disponibile." : "Layergram is unavailable."
        }
        static func noFullAccess(_ l: Locale) -> String {
            isItalian(l)
                ? "Serve l'accesso completo per la tastiera Layergram. Attivalo in Impostazioni > Tastiere."
                : "Full Access is required for the Layergram keyboard. Enable it in Settings > Keyboards."
        }
        static func starting(_ l: Locale) -> String {
            isItalian(l) ? "Avvio sicuro in corso…" : "Starting securely…"
        }
        static func idle(_ l: Locale) -> String {
            isItalian(l) ? "Sessione attiva." : "Session active."
        }
        static func waiting(_ l: Locale) -> String {
            isItalian(l) ? "In attesa dell'app…" : "Waiting for the app…"
        }
        static func exported(_ l: Locale) -> String {
            isItalian(l)
                ? "Cifratura passata alla tastiera di sistema (nessuna conferma di consegna)."
                : "Ciphertext handed to the system keyboard (no delivery confirmation)."
        }
        static func sessionOver(_ l: Locale) -> String {
            isItalian(l)
                ? "Sessione scaduta. Torna in Layergram per aprirne una nuova."
                : "Session expired. Return to Layergram to open a new one."
        }
        static func tooLong(_ l: Locale) -> String {
            isItalian(l) ? "Testo troppo lungo." : "Text is too long."
        }
        static func pasteTooLong(_ l: Locale) -> String {
            isItalian(l) ? "Contenuto incollato troppo lungo." : "Pasted content is too long."
        }
        static func emptyPaste(_ l: Locale) -> String {
            isItalian(l) ? "Negli appunti non c'è testo." : "The clipboard has no text."
        }
        static func noContacts(_ l: Locale) -> String {
            isItalian(l) ? "Nessun contatto disponibile." : "No contacts available."
        }
        static func rejected(_ l: Locale) -> String {
            isItalian(l) ? "Messaggio non supportato." : "Unsupported message."
        }
        static func noRecipient(_ l: Locale) -> String {
            isItalian(l) ? "Scegli un destinatario." : "Choose a recipient."
        }
    }

    // MARK: - State

    private enum ShiftState { case off, on, locked }
    private enum Layer { case letters, numbers, symbols }
    private enum Surface { case keys, contacts, confirmation }
    private enum KeyAction: String {
        case shift, backspace, space, newline, globe, layer, symbols

        var identifier: String { "layergram.key.\(rawValue)" }

        static func from(_ identifier: String?) -> KeyAction? {
            guard let identifier else { return nil }
            return KeyAction(
                rawValue: identifier.replacingOccurrences(of: "layergram.key.", with: "")
            )
        }
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

    private var draft = ""
    private var shift: ShiftState = .off
    private var layer: Layer = .letters
    private var surface: Surface = .keys
    private var contacts: [KeyboardContact] = []
    private var status = ""
    private var operation: KeyboardOperation?
    private var pendingSelection: KeyboardContact?
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

    /// The opaque editor binding. iOS exposes `documentIdentifier` as a `UUID`;
    /// only its string form is compared, never displayed, logged or stored.
    private var documentIdentifier: String {
        textDocumentProxy.documentIdentifier.uuidString
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
            status = Copy.minimumSystem(locale)
            render()
            return
        }
        guard hasFullAccess else {
            status = Copy.noFullAccess(locale)
            render()
            return
        }
        guard let group = appGroupIdentifier, !group.isEmpty else {
            status = Copy.openApp(locale)
            render()
            return
        }
        do {
            let storage = try self.storage ?? MailboxStorage(appGroupIdentifier: group)
            self.storage = storage
            let client = self.client ?? MailboxClient(storage: storage)
            self.client = client
            guard client.hasLiveWindow() else {
                status = Copy.openApp(locale)
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
                invalidateEditor(status: Copy.openApp(locale))
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
            status = Copy.starting(locale)
            render()
            let begin = try policy.beginRequestData()
            try session.send(payload: begin)
            operation = .begin
            scheduleTimers()
        } catch {
            // Storage, rendezvous and admission problems collapse into one
            // generic state: no reason, no owner detail, no retry of an old send.
            invalidateEditor(status: Copy.openApp(locale))
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
            invalidateEditor(status: Copy.openApp(locale))
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
            invalidateEditor(status: Copy.openApp(locale))
            return
        }
        if policy.isBeginAccepted {
            // Every poll needs full admission (Full Access, no capture, exact
            // document binding) plus the live <= 1 s freshness lease.
            if !policy.revalidate(current) {
                invalidateEditor(status: Copy.sessionOver(locale))
                return
            }
            // A lapsed lease clears everything and drops the client even while
            // the 20 s window is still open.
            if policy.clearIfLeaseExpired(at: monotonicNow) {
                invalidateEditor(status: Copy.sessionOver(locale))
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
                invalidateEditor(status: Copy.sessionOver(locale))
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
        invalidateEditor(status: Copy.openApp(locale))
    }

    private func expiredState() {
        invalidateEditor(status: Copy.sessionOver(locale))
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
        operation = nil
        surface = .keys
        scrambledIndex = [:]
        scrambleEnabled = false
        draftLabel.text = nil
        draftLabel.accessibilityLabel = nil
        previewLabel.text = nil
        previewLabel.accessibilityLabel = nil
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
            invalidateEditor(status: Copy.sessionOver(locale))
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
            status = Copy.idle(locale)
        case .heartbeat:
            break
        case .contacts:
            contacts = policy.contacts() ?? []
            surface = .contacts
            status = contacts.isEmpty ? Copy.noContacts(locale) : Copy.recipient(locale)
        case .select:
            if let confirmed = policy.selection() {
                pendingSelection = confirmed
                status = Copy.recipient(locale)
            } else {
                pendingSelection = nil
                status = Copy.unavailable(locale)
            }
            // The confirmation sheet is gone: drop its retained text too.
            confirmLabel.text = nil
            confirmLabel.accessibilityLabel = nil
            surface = .keys
        case .prepare:
            guard let pendingId = policy.pendingId() else {
                invalidateEditor(status: Copy.unavailable(locale))
                return
            }
            status = Copy.waiting(locale)
            _ = queue(.authorize, payload: ["pendingId": .string(pendingId)])
        case .authorize:
            insertAuthorizedCarrier()
        case .ack:
            status = Copy.exported(locale)
        case .decode:
            if let preview = policy.preview() {
                previewLabel.text =
                    "\(Copy.previewTitle(locale)) · \(preview.contactName)\n\(preview.text)"
                previewLabel.accessibilityLabel = previewLabel.text
                status = Copy.previewTitle(locale)
            } else {
                // A non-`ok` reply and an unprojectable one both leave the
                // preview empty: there is no ciphertext fallback and no retry.
                previewLabel.text = nil
                previewLabel.accessibilityLabel = nil
                status = Copy.rejected(locale)
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
            newStatus = Copy.tooLong(locale)
        case KeyboardChannelStatus.openAppRequired,
             KeyboardChannelStatus.unavailable,
             KeyboardChannelStatus.busy,
             KeyboardChannelStatus.noMessage:
            newStatus = Copy.openApp(locale)
        default:
            newStatus = Copy.unavailable(locale)
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
            invalidateEditor(status: Copy.sessionOver(locale))
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
            invalidateEditor(status: Copy.sessionOver(locale))
            return
        }
        status = Copy.exported(locale)
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
            invalidateEditor(status: Copy.sessionOver(locale))
            return false
        }
        return true
    }

    private func insert(_ character: String) {
        guard editable() else { return }
        guard let next = KeyboardTextEdit.append(character, to: draft) else {
            invalidateEditor(status: Copy.tooLong(locale))
            return
        }
        draft = next
        if case .on = shift { shift = .off }
        if status == Copy.starting(locale) { status = Copy.idle(locale) }
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
            invalidateEditor(status: Copy.noFullAccess(locale))
            return
        }
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.sessionOver(locale))
            return
        }
        guard queue(.contacts) else { return }
        status = Copy.waiting(locale)
        render()
    }

    private func selectContact(_ contact: KeyboardContact) {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.sessionOver(locale))
            return
        }
        pendingSelection = contact
        surface = .confirmation
        confirmLabel.text = """
        \(Copy.confirmPrompt(locale))

        \(contact.name)
        \(Copy.fp(locale)): \(contact.fingerprint)
        """
        confirmLabel.accessibilityLabel = confirmLabel.text
        render()
    }

    private func confirmSelection() {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.sessionOver(locale))
            return
        }
        guard let contact = pendingSelection else {
            invalidateEditor(status: Copy.noRecipient(locale))
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
        status = Copy.waiting(locale)
        render()
    }

    private func cancelConfirmation() {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.sessionOver(locale))
            return
        }
        pendingSelection = nil
        confirmLabel.text = nil
        confirmLabel.accessibilityLabel = nil
        surface = contacts.isEmpty ? .keys : .contacts
        render()
    }

    /// Explicit, user-initiated paste. This is the only clipboard read in the
    /// extension: no listener, no timer and no automatic read.
    private func pasteAndDecode() {
        guard hasFullAccess else {
            invalidateEditor(status: Copy.noFullAccess(locale))
            return
        }
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.sessionOver(locale))
            return
        }
        // An explicit decode always drops any previously confirmed recipient and
        // local draft, so a preview can never inherit them.
        draft = ""
        pendingSelection = nil
        policy.clearSelection()
        draftLabel.text = nil
        draftLabel.accessibilityLabel = nil
        recipientLabel.text = nil
        recipientLabel.accessibilityLabel = nil
        previewLabel.text = nil
        previewLabel.accessibilityLabel = nil
        guard let pasted = UIPasteboard.general.string, !pasted.isEmpty else {
            status = Copy.emptyPaste(locale)
            render()
            return
        }
        guard pasted.utf16.count <= KeyboardSurfaceBounds.maxInboundCarrierUTF16 else {
            status = Copy.pasteTooLong(locale)
            render()
            return
        }
        guard queue(.decode, payload: ["carrier": .string(pasted)]) else { return }
        status = Copy.waiting(locale)
        render()
    }

    /// Start one explicit send. The recipient was already confirmed by an
    /// explicit tap plus the owner `select` reply, the draft is non-empty and
    /// bounded, and nothing is inserted until the owner returns a freshly
    /// authorized carrier.
    private func beginSend() {
        guard hasFullAccess else {
            invalidateEditor(status: Copy.noFullAccess(locale))
            return
        }
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.sessionOver(locale))
            return
        }
        guard policy.hasSelection, pendingSelection != nil else {
            invalidateEditor(status: Copy.noRecipient(locale))
            return
        }
        guard KeyboardTextEdit.isValidDraft(draft) else {
            invalidateEditor(status: Copy.tooLong(locale))
            return
        }
        guard queue(.prepare, payload: ["text": .string(draft)]) else { return }
        status = Copy.waiting(locale)
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
        invalidateEditor(status: Copy.openApp(locale))
    }

    /// Every host text or selection change invalidates the bound editor
    /// generation and every value that belonged to it. This holds even when iOS
    /// reuses the same opaque document identifier for a different host
    /// conversation, and there is deliberately no ignore flag for our own single
    /// insertion.
    private func editorInvalidated() {
        guard started else { return }
        invalidateEditor(status: Copy.sessionOver(locale))
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
        invalidateEditor(status: Copy.openApp(locale))
    }

    // MARK: - Layout

    private static let preferredHeight: CGFloat = 320

    private func buildLayout() {
        view.backgroundColor = .secondarySystemBackground

        statusLabel.font = .preferredFont(forTextStyle: .footnote)
        statusLabel.adjustsFontForContentSizeCategory = true
        statusLabel.textColor = .label
        statusLabel.numberOfLines = 3
        statusLabel.setContentCompressionResistancePriority(.defaultLow, for: .vertical)

        draftLabel.font = .preferredFont(forTextStyle: .footnote)
        draftLabel.adjustsFontForContentSizeCategory = true
        draftLabel.textColor = .label
        draftLabel.numberOfLines = 1
        draftLabel.lineBreakMode = .byTruncatingHead
        // The local draft never becomes an accessibility value exposed to the
        // host UI.
        draftLabel.isAccessibilityElement = false

        recipientLabel.font = .preferredFont(forTextStyle: .caption1)
        recipientLabel.adjustsFontForContentSizeCategory = true
        recipientLabel.textColor = .secondaryLabel
        recipientLabel.numberOfLines = 1
        recipientLabel.lineBreakMode = .byTruncatingMiddle

        windowLabel.font = .preferredFont(forTextStyle: .caption1)
        windowLabel.adjustsFontForContentSizeCategory = true
        windowLabel.textColor = .secondaryLabel
        windowLabel.textAlignment = .right
        windowLabel.numberOfLines = 1

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
        let previewHeight = previewScroll.heightAnchor.constraint(equalToConstant: 46)
        previewHeight.priority = .defaultHigh
        previewHeight.isActive = true

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

        let header = UIStackView(arrangedSubviews: [
            statusLabel, infoRow, draftLabel, previewScroll
        ])
        header.axis = .vertical
        header.spacing = 6

        let content = UIStackView(arrangedSubviews: [contactsView, confirmView, keysContainer])
        content.axis = .vertical
        content.setContentHuggingPriority(.defaultLow, for: .vertical)

        let nextKeyboard = makeActionButton("🌐", action: .globe)
        nextKeyboard.accessibilityLabel = Copy.isItalian(locale)
            ? "Cambia tastiera" : "Next keyboard"
        let footer = UIStackView(arrangedSubviews: [nextKeyboard, shortcutsStack])
        footer.axis = .horizontal
        footer.spacing = 6
        nextKeyboard.setContentHuggingPriority(.required, for: .horizontal)
        let root = UIStackView(arrangedSubviews: [header, content, footer])
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
        return "\(Copy.window(locale)): \(seconds)s"
    }

    private func render() {
        statusLabel.text = status
        draftLabel.text = draft.isEmpty ? nil : "\(Copy.draft(locale)): \(draft)"
        draftLabel.accessibilityLabel = nil
        if let name = pendingSelection?.name {
            recipientLabel.text = "\(Copy.recipient(locale)): \(name)"
        } else {
            recipientLabel.text = nil
        }
        recipientLabel.accessibilityLabel = nil
        windowLabel.text = remainingWindowText()
        windowLabel.accessibilityLabel = nil
        let hasPreview = !(previewLabel.text ?? "").isEmpty
        previewScroll.isHidden = !hasPreview
        contactsView.isHidden = (surface != .contacts)
        confirmView.isHidden = (surface != .confirmation)
        keysContainer.isHidden = (surface != .keys)
        if surface == .contacts { contactsView.reloadData() }
        if surface == .keys { renderKeys() }
        renderShortcuts()
    }

    private func renderKeys() {
        for view in keysStack.arrangedSubviews {
            keysStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }

        var index = 0
        for labels in keyRows() {
            let row = UIStackView()
            row.axis = .horizontal
            row.spacing = 5
            row.distribution = .fillEqually
            for label in labels {
                let button = makeKeyButton(label)
                button.tag = index
                index += 1
                row.addArrangedSubview(button)
            }
            keysStack.addArrangedSubview(row)
        }

        let bottom = UIStackView()
        bottom.axis = .horizontal
        bottom.spacing = 5
        bottom.distribution = .fillProportionally
        let controls: [(String, KeyAction?)] = [
            (shift == .off ? "⇧" : (shift == .on ? "⇧" : "⇪"), .shift),
            (Copy.deleteKey(locale), .backspace),
            (Copy.space(locale), .space),
            (Copy.returnKey(locale), .newline),
            (layer == .letters ? "123" : "ABC", .layer),
            ("#+=", .symbols)
        ]
        for (label, action) in controls {
            guard let action else { continue }
            bottom.addArrangedSubview(makeActionButton(label, action: action))
        }
        keysStack.addArrangedSubview(bottom)
    }

    private func renderShortcuts() {
        for view in shortcutsStack.arrangedSubviews {
            shortcutsStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
        if surface == .confirmation {
            shortcutsStack.addArrangedSubview(
                makeShortcut(Copy.cancel(locale), action: #selector(tapCancel))
            )
            shortcutsStack.addArrangedSubview(
                makeShortcut(Copy.confirm(locale), action: #selector(tapConfirm))
            )
            return
        }
        if surface == .contacts {
            shortcutsStack.addArrangedSubview(
                makeShortcut(Copy.newMessage(locale), action: #selector(tapBackToKeys))
            )
            return
        }
        shortcutsStack.addArrangedSubview(
            makeShortcut(Copy.contacts(locale), action: #selector(tapContacts))
        )
        shortcutsStack.addArrangedSubview(
            makeShortcut(Copy.paste(locale), action: #selector(tapPaste))
        )
        if policy.hasSelection {
            shortcutsStack.addArrangedSubview(
                makeShortcut(Copy.send(locale), action: #selector(tapSend))
            )
        }
        if !draft.isEmpty {
            shortcutsStack.addArrangedSubview(
                makeShortcut(Copy.newMessage(locale), action: #selector(tapNewMessage))
            )
        }
    }

    private func makeShortcut(_ title: String, action: Selector) -> UIButton {
        let button = UIButton(type: .system)
        button.setTitle(title, for: .normal)
        button.titleLabel?.font = .preferredFont(forTextStyle: .footnote)
        button.titleLabel?.adjustsFontForContentSizeCategory = true
        button.titleLabel?.numberOfLines = 2
        button.titleLabel?.textAlignment = .center
        button.backgroundColor = .tertiarySystemFill
        button.layer.cornerRadius = 6
        button.addTarget(self, action: action, for: .touchUpInside)
        return button
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
        return button
    }

    // MARK: - Key data

    private func keyRows() -> [[String]] {
        switch layer {
        case .letters:
            return letterRows()
        case .numbers:
            return [
                ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"],
                ["-", "/", ":", ";", "(", ")", "$", "&", "@", "\""],
                [".", ",", "?", "!", "'", "#", "%", "+", "=", "*"]
            ]
        case .symbols:
            return [
                ["[", "]", "{", "}", "<", ">", "€", "£", "¥", "•"],
                ["_", "\\", "|", "~", "^", "`", "°", "±", "§", "¶"],
                ["…", "—", "–", "«", "»", "“", "”", "‘", "’", "×"]
            ]
        }
    }

    /// The displayed letter rows. A session-stable permutation is chosen once per
    /// keyboard open when the owner reported the neutral scramble capability, so
    /// the same key always types the same character while the layout is shuffled.
    private func letterRows() -> [[String]] {
        let rows = [
            ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
            ["a", "s", "d", "f", "g", "h", "j", "k", "l"],
            ["z", "x", "c", "v", "b", "n", "m"]
        ]
        guard scrambleEnabled else { return rows }
        for index in rows.indices where scrambledIndex[index] == nil {
            scrambledIndex[index] = Array(rows[index].indices).shuffled()
        }
        return rows.enumerated().map { index, row in
            let order = scrambledIndex[index] ?? Array(row.indices)
            return order.compactMap { row.indices.contains($0) ? row[$0] : nil }
        }
    }

    private func letterKey(_ label: String) -> String {
        switch shift {
        case .off: return label.lowercased()
        case .on, .locked: return label.uppercased()
        }
    }

    // MARK: - Key handling

    @objc private func tapKey(_ sender: UIButton) {
        let rows = keyRows()
        var remaining = sender.tag
        var label: String?
        for row in rows {
            if remaining < row.count {
                label = row[remaining]
                break
            }
            remaining -= row.count
        }
        guard let label else { return }
        insert(layer == .letters ? letterKey(label) : label)
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
            invalidateEditor(status: Copy.sessionOver(locale))
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
        case .layer:
            layer = (layer == .letters) ? .numbers : .letters
            render()
        case .symbols:
            layer = (layer == .symbols) ? .numbers : .symbols
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
        case .keys:
            requestContacts()
        case .contacts:
            tapBackToKeys()
        case .confirmation:
            guard policy.liveControl(snapshot()) else {
                invalidateEditor(status: Copy.sessionOver(locale))
                return
            }
            surface = .contacts
            render()
        }
    }

    @objc private func tapBackToKeys() {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.sessionOver(locale))
            return
        }
        surface = .keys
        render()
    }

    @objc private func tapPaste() {
        pasteAndDecode()
    }

    @objc private func tapSend() {
        beginSend()
    }

    @objc private func tapConfirm() {
        confirmSelection()
    }

    @objc private func tapCancel() {
        cancelConfirmation()
    }

    @objc private func tapNewMessage() {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.sessionOver(locale))
            return
        }
        draft = ""
        policy.clearSelection()
        pendingSelection = nil
        previewLabel.text = nil
        previewLabel.accessibilityLabel = nil
        confirmLabel.text = nil
        confirmLabel.accessibilityLabel = nil
        surface = .keys
        status = Copy.idle(locale)
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
        configuration.secondaryText = "\(Copy.fp(locale)): \(contact.fingerprint)"
        cell.contentConfiguration = configuration
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: false)
        guard policy.liveControl(snapshot()), indexPath.row < contacts.count else {
            invalidateEditor(status: Copy.sessionOver(locale))
            return
        }
        // An explicit tap opens confirmation; a decoded contact is never selected
        // automatically.
        selectContact(contacts[indexPath.row])
    }
}
