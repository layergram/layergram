import SystemKeyboardCore
import UIKit
import os.log
import QuartzCore
#if LAYERGRAM_AUTONOMOUS_KEYBOARD
import Flutter

private final class KeyboardActivityRecognizer: UIGestureRecognizer {
    var activity: ((UITouch) -> Void)?
    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        if let touch = touches.first { activity?(touch) }
        state = .failed // Observe without consuming the key/scroll gesture.
    }
}
#endif

/// Displays a local draft without ever becoming an editor of the host app.
private final class LocalDraftTextView: UITextView {
    override var canBecomeFirstResponder: Bool { false }
}

/// Contact filtering belongs to the extension's own keys. UIKit must never
/// promote this display field into a second text editor in the host app.
private final class LocalContactSearchField: UISearchTextField {
    override var canBecomeFirstResponder: Bool { false }
}

/// Secure rendering surface; it must never become the host editor or summon
/// another keyboard. UIKit's capture treatment of its canvas is verified on
/// physical devices because it is not a documented screenshot API.
private final class KeyboardSecureCaptureTextField: UITextField {
    override var canBecomeFirstResponder: Bool { false }
    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool { false }
}

private final class KeyboardEmojiCell: UICollectionViewCell {
    let label = UILabel()

    override init(frame: CGRect) {
        super.init(frame: frame)
        label.font = .systemFont(ofSize: 27)
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            label.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
            label.topAnchor.constraint(equalTo: contentView.topAnchor),
            label.bottomAnchor.constraint(equalTo: contentView.bottomAnchor)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }
}

/// Native Layergram keyboard for iOS.
///
/// Native draft, contact picker and preview. The optional autonomous build
/// delegates a fresh grant to a headless runtime; ordinary experimental builds
/// use the containing app's bounded encrypted mailbox. Neither route loads an
/// identity vault, registers app plugins or reads surrounding host text.
///
/// Hard rules implemented here:
/// * no `UITextField`/`UITextView` first responder and no host plaintext typing;
/// * the only host reads are `textDocumentProxy.documentIdentifier` (opaque,
///   compared only, never displayed), `documentInputMode.primaryLanguage` (a
///   language tag for local key layout), and text delivered by the system
///   `UIPasteControl` after an explicit user paste tap (a direct pasteboard
///   read remains only for iOS 15);
/// * the only host write is a single `insertText(carrier)` for a freshly
///   authorized encrypted carrier, which returns `Void` — so a tap can never
///   claim that the host accepted or delivered anything;
/// * the always-present globe key calls `advanceToNextInputMode()`;
/// * no surrounding text, document context or selected text is ever read.
///
/// The mailbox bootstrap has a fixed parent execution window. Once autonomous
/// custody is accepted, native inactivity and revocation checks become the live
/// authority; only physical keyboard interaction renews that inactivity period.
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

    /// The input-mode language determines the Latin key geometry when UIKit
    /// supplies a distinct language. When it merely echoes this extension's
    /// advertised language, use the device locale so localized labels and
    /// letters do not contradict each other.
    enum InputLayout: Equatable {
        case qwerty, spanish, portuguese, french, german
        case swedish, norwegian, danish

        static func resolve(_ languageTag: String?, fallback: Locale,
                            advertisedLanguage: String? = nil) -> InputLayout {
            let mode = languageTag.flatMap { $0.isEmpty ? nil : $0 }
            let echoedExtensionLanguage: Bool
            if let mode, let advertisedLanguage {
                echoedExtensionLanguage = mode.caseInsensitiveCompare(advertisedLanguage) == .orderedSame
            } else {
                echoedExtensionLanguage = false
            }
            let tag = echoedExtensionLanguage ? fallback.identifier : (mode ?? fallback.identifier)
            let code = tag.replacingOccurrences(of: "_", with: "-")
                .split(separator: "-").first.map(String.init)?.lowercased()
            switch code {
            case "es": return .spanish
            case "pt": return .portuguese
            case "fr": return .french
            case "de": return .german
            case "sv": return .swedish
            case "nb", "nn", "no": return .norwegian
            case "da": return .danish
            default: return .qwerty
            }
        }

        var letterRows: [[String]] {
            switch self {
            case .qwerty:
                return KeyboardViewController.letterRowCharacters
            case .spanish:
                return [["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
                        ["a", "s", "d", "f", "g", "h", "j", "k", "l", "ñ"],
                        ["z", "x", "c", "v", "b", "n", "m"]]
            case .portuguese:
                return [["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
                        ["a", "s", "d", "f", "g", "h", "j", "k", "l", "ç"],
                        ["z", "x", "c", "v", "b", "n", "m"]]
            case .french:
                return [["a", "z", "e", "r", "t", "y", "u", "i", "o", "p"],
                        ["q", "s", "d", "f", "g", "h", "j", "k", "l", "m"],
                        ["w", "x", "c", "v", "b", "n"]]
            case .german:
                return [["q", "w", "e", "r", "t", "z", "u", "i", "o", "p", "ü"],
                        ["a", "s", "d", "f", "g", "h", "j", "k", "l", "ö", "ä"],
                        ["y", "x", "c", "v", "b", "n", "m"]]
            case .swedish:
                return [["q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "å"],
                        ["a", "s", "d", "f", "g", "h", "j", "k", "l", "ö", "ä"],
                        ["z", "x", "c", "v", "b", "n", "m"]]
            case .norwegian:
                return [["q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "å"],
                        ["a", "s", "d", "f", "g", "h", "j", "k", "l", "ø", "æ"],
                        ["z", "x", "c", "v", "b", "n", "m"]]
            case .danish:
                return [["q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "å"],
                        ["a", "s", "d", "f", "g", "h", "j", "k", "l", "æ", "ø"],
                        ["z", "x", "c", "v", "b", "n", "m"]]
            }
        }
    }

    enum StringKey: CaseIterable {
        case space, returnKey, deleteKey
        case contacts, searchContacts, clearSearch, clearSecretMessage, doneSearching, paste, encryptInsert, pasteDecrypt
        case confirm, cancel, newMessage, recipient, secretMessage, window, fingerprint, previewTitle, compose, readMessage
        case globeSwitch
        case confirmPrompt, emptyDraftHint
        case minimumSystem, openApp, unavailable, noFullAccess
        case starting, sessionActive, waiting, exported, sessionExpired
        case tooLong, pasteTooLong, emptyPaste, identityImport, noContacts, rejected, chooseRecipient
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
                if language == .italian { return "a capo" }
                if language == .spanish { return "salto de línea" }
                return "new line"
            case .deleteKey:
                if language == .italian { return "canc" }
                if language == .spanish { return "borrar" }
                return "del"
            case .contacts:
                if language == .italian { return "Rubrica" }
                if language == .spanish { return "Contactos" }
                return "Contacts"
            case .searchContacts:
                if language == .italian { return "Cerca contatto" }
                if language == .spanish { return "Buscar contacto" }
                return "Search contacts"
            case .clearSearch:
                if language == .italian { return "Cancella ricerca" }
                if language == .spanish { return "Borrar búsqueda" }
                return "Clear search"
            case .clearSecretMessage:
                if language == .italian { return "Cancella messaggio segreto" }
                if language == .spanish { return "Borrar mensaje secreto" }
                return "Clear secret message"
            case .doneSearching:
                if language == .italian { return "Fine" }
                if language == .spanish { return "Listo" }
                return "Done"
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
            case .secretMessage:
                if language == .italian { return "Messaggio segreto" }
                if language == .spanish { return "Texto secreto" }
                return "Secret message"
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
                    return "Apri e sblocca Layergram"
                }
                if language == .spanish {
                    return "Abre y desbloquea Layergram"
                }
                return "Open and unlock Layergram"
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
                if language == .italian { return "Avvio…" }
                if language == .spanish { return "Iniciando…" }
                return "Starting…"
            case .sessionActive:
                if language == .italian { return "Sessione attiva" }
                if language == .spanish { return "Sesión activa" }
                return "Session active"
            case .waiting:
                if language == .italian { return "In attesa dell'app…" }
                if language == .spanish { return "Esperando la app…" }
                return "Waiting for the app…"
            case .exported:
                // `insertText` returns `Void`: the keyboard can only say the
                // encrypted text was handed to the host app. It never claims the
                // host accepted, inserted or delivered anything.
                if language == .italian {
                    return "Testo cifrato passato all'app · Tocca Invia"
                }
                if language == .spanish {
                    return "Cifrado pasado a la app · Pulsa Enviar"
                }
                return "Encrypted text passed to app · Tap Send"
            case .sessionExpired:
                if language == .italian {
                    return "Sessione scaduta · Apri Layergram"
                }
                if language == .spanish {
                    return "Sesión caducada · Abre Layergram"
                }
                return "Session expired · Open Layergram"
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
            case .identityImport:
                if language == .italian { return "Identità da importare · Apri Layergram e tocca Incolla" }
                if language == .spanish { return "Identidad para importar · Abre Layergram y pulsa Pegar" }
                return "Identity to import · Open Layergram and tap Paste"
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
        case shift, backspace, space, newline, globe, layer, symbols, emoji

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
    private static let advertisedLanguage: String? = {
        let configuration = Bundle.main.object(forInfoDictionaryKey: "NSExtension") as? [String: Any]
        let attributes = configuration?["NSExtensionAttributes"] as? [String: Any]
        return attributes?["PrimaryLanguage"] as? String
    }()
    private var inputLayout: InputLayout {
        InputLayout.resolve(textDocumentProxy.documentInputMode?.primaryLanguage,
                            fallback: locale, advertisedLanguage: Self.advertisedLanguage)
    }

    private var storage: MailboxStorage?
    private var client: MailboxClient?
    private var session: MailboxClientSession?
    private var lastBootstrapSessionId: Data?
    #if LAYERGRAM_AUTONOMOUS_KEYBOARD
    private var runtimeBridge: KeyboardRuntimeBridge?
    private var biometricResumeAvailable = false
    private var biometricResumePending = false
    private var biometricResumeGeneration: UInt64 = 0
    private var biometricResumeExpiresAt: Int64?
    private var biometricResumeDocument: String?
    private struct DeferredPasteIntent {
        let provider: NSItemProvider
        let document: String
        let generation: UInt64
        let createdAt: Int64
    }
    private var deferredPasteIntent: DeferredPasteIntent?
    private var lastBiometricHintTrace: String?
    private var delegationNonce: String?
    private var delegationDocument: String?
    private var delegationPending = false
    private var nextDelegationAttempt: Int64 = 0
    private var ownInsertionPending = false
    private var rebindInProgress = false
    private var endingEditorForRebind = false
    // Only an export initiated here can carry a confirmed choice into the
    // next editor generation. The runtime must approve the contact again.
    private var recipientAfterOwnExport: KeyboardContact?
    private var documentAfterOwnExport: String?
    #endif
    private var sessionDeadlineMonotonicMillis: Int64 = 0
    private var started = false
    private var pollTimer: Timer?
    private var expiryTimer: Timer?
    private var reconnectTimer: Timer?
    private var repeatTimer: Timer?
    private var lastHeartbeatMonotonicMillis: Int64 = 0

    // Local editor state. `draft` and `pendingSelection` are readable inside the
    // module so native tests can drive the flow decisions; they are never
    // writable from outside and they never grant a session on their own.
    private(set) var draft = ""
    private var draftCursor = 0 // Character boundary, never a UTF-16 midpoint.
    private var shift: ShiftState = .off
    private var layer: Layer = .letters
    private(set) var surface: Surface = .keys
    private var contacts: [KeyboardContact] = []
    private var contactQuery = ""
    private var contactSearchActive = false
    private var emojiPickerVisible = false
    private var emojiCategoryIndex = 0
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
    private let draftView = LocalDraftTextView()
    private let draftCaret = UIView()
    private let draftPlaceholder = UILabel()
    private let clearDraftButton = UIButton(type: .system)
    private let composeContactsButton = UIButton(type: .system)
    private let composeActionButton = UIButton(type: .system)
    private let composeActionSlot = UIView()
    private var composePasteControl: UIControl?
    private let composeRow = UIStackView()
    private let recipientLabel = UILabel()
    private let recipientRow = UIStackView()
    private let windowLabel = UILabel()
    private let previewLabel = UILabel()
    private let previewScroll = UIScrollView()
    private let contactsView = UITableView(frame: .zero, style: .plain)
    private let contactsContainer = UIStackView()
    private let contactSearchField = LocalContactSearchField()
    private let emptyContactsLabel = UILabel()
    private let contactSearchButton = UIButton(type: .custom)
    private let clearContactSearchButton = UIButton(type: .system)
    private var heightConstraint: NSLayoutConstraint?
    private let keysContainer = UIView()
    private let keysStack = UIStackView()
    private let emojiContainer = UIStackView()
    private let emojiCategories = UISegmentedControl(items: ["😀", "🐾", "🍽", "🌍", "♥️"])
    private let emojiGrid = UICollectionView(frame: .zero, collectionViewLayout: UICollectionViewFlowLayout())
    private var keyFeedback: UIImpactFeedbackGenerator?
    private var buttonFeedback: UIImpactFeedbackGenerator?
    private var emojiBottomConstraint: NSLayoutConstraint?
    private var emojiButton: UIButton?
    private var accentPopup: UIStackView?
    private var accentSelection = 0
    private var spaceDragOrigin: CGPoint?
    private var spaceDragCursor = 0
    private var spaceDragCaretOrigin: CGPoint?
    private static let brandGreen = UIColor(red: 11/255, green: 82/255, blue: 69/255, alpha: 1)
    // Keep the extension's controls in sync with AppTheme.dark().filledButtonTheme.
    private static let functionBackground = UIColor { traits in
        traits.userInterfaceStyle == .dark
            ? UIColor(red: 154/255, green: 203/255, blue: 250/255, alpha: 1)
            : KeyboardViewController.brandGreen
    }
    private static let functionForeground = UIColor { traits in
        traits.userInterfaceStyle == .dark
            ? UIColor(red: 0, green: 51/255, blue: 82/255, alpha: 1)
            : .white
    }
    private static let pasteActionIcon = UIImage(systemName: "doc.on.clipboard")
    // Match the system keyboard container visible above the extension on the
    // validation iPhone. UIKit's dark systemGray5 is lighter than that chrome.
    static let keyboardChromeBackground = UIColor { traits in
        traits.userInterfaceStyle == .dark ? UIColor(white: 33/255, alpha: 1) :
            UIColor(red: 223/255, green: 225/255, blue: 228/255, alpha: 1)
    }
    private static let sendActionIcon = sendLockedIcon()
    private static let textAccent = UIColor { traits in
        traits.userInterfaceStyle == .dark ? .white : KeyboardViewController.brandGreen
    }
    private let confirmView = UIView()
    private let confirmLabel = UILabel()
    private let shortcutsStack = UIStackView()
    private let shortcutsContainer = UIStackView()
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
    private static let screenProtectionPreferenceKey = "keyboard_screen_protection_enabled"
    private let captureTextField = KeyboardSecureCaptureTextField()
    private weak var captureHostView: UIView?
    private weak var keyboardRootLayout: UIView?
    private var keyboardRootConstraints: [NSLayoutConstraint] = []
    private var screenProtectionEnabled = true

    private func readScreenProtectionPreference() -> Bool {
        guard let group = appGroupIdentifier,
              let defaults = UserDefaults(suiteName: group),
              let enabled = defaults.object(forKey: Self.screenProtectionPreferenceKey) as? Bool
        else { return true }
        return enabled
    }

    private func findSecureCaptureHost(in root: UIView) -> UIView? {
        for child in root.subviews {
            let name = NSStringFromClass(type(of: child))
            if name.contains("LayoutCanvasView") || name.contains("CanvasView") { return child }
            if let nested = findSecureCaptureHost(in: child) { return nested }
        }
        return nil
    }

    private func configureSecureCaptureSurface() {
        screenProtectionEnabled = readScreenProtectionPreference()
        captureTextField.translatesAutoresizingMaskIntoConstraints = false
        captureTextField.isSecureTextEntry = true
        captureTextField.borderStyle = .none
        captureTextField.backgroundColor = .clear
        captureTextField.textColor = .clear
        captureTextField.tintColor = .clear
        captureTextField.text = " "
        view.addSubview(captureTextField)
        NSLayoutConstraint.activate([
            captureTextField.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            captureTextField.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            captureTextField.topAnchor.constraint(equalTo: view.topAnchor),
            captureTextField.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        view.layoutIfNeeded()
        captureHostView = findSecureCaptureHost(in: captureTextField)
        if let captureHostView {
            captureHostView.isUserInteractionEnabled = true
            traceLifecycle("secureCaptureHostFound")
        } else {
            captureTextField.removeFromSuperview()
            traceLifecycle("secureCaptureHostMissing")
        }
        captureTextField.isHidden = !screenProtectionEnabled
    }

    private var keyboardLayoutHost: UIView {
        if screenProtectionEnabled, let captureHostView { return captureHostView }
        return view
    }

    private func attachKeyboardRoot(_ root: UIView, to host: UIView) {
        guard root.superview !== host else { return }
        NSLayoutConstraint.deactivate(keyboardRootConstraints)
        root.removeFromSuperview()
        host.addSubview(root)
        keyboardRootConstraints = [
            root.leadingAnchor.constraint(equalTo: host.leadingAnchor, constant: 6),
            root.trailingAnchor.constraint(equalTo: host.trailingAnchor, constant: -6),
            // iOS already leaves room in the rounded keyboard cap above this
            // host. Keep just enough clearance for the status text's ascenders.
            root.topAnchor.constraint(equalTo: host.topAnchor, constant: 2),
            root.bottomAnchor.constraint(equalTo: host.bottomAnchor, constant: -3)
        ]
        NSLayoutConstraint.activate(keyboardRootConstraints)
    }

    private func refreshScreenProtectionPreference() {
        let enabled = readScreenProtectionPreference()
        guard enabled != screenProtectionEnabled else { return }
        screenProtectionEnabled = enabled
        captureTextField.isHidden = !enabled
        if let keyboardRootLayout {
            attachKeyboardRoot(keyboardRootLayout, to: keyboardLayoutHost)
        }
        // A changed privacy preference cannot inherit a previous editor grant.
        invalidateEditor(status: Copy.string(.openApp, in: locale))
    }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        #if LAYERGRAM_KEYBOARD_TRACE
        if let group = appGroupIdentifier,
           let custodyStorage = try? MailboxStorage(
               appGroupIdentifier: group,
               directoryName: KeyboardCustodyStore.directoryName) {
            let file = (try? custodyStorage.readCustodyState()) != nil
            let control = (try? custodyStorage.readCustodyControl()) != nil
            let mirror = (try? KeyboardKeychainCustodyMirror.hasAny(group: group)) == true
            let container = custodyStorage.directoryURL.deletingLastPathComponent().lastPathComponent
            os_log("LayergramCustodyTrace %{public}@", log: .default, type: .info,
                   "keyboardInit file=\(file) control=\(control) mirror=\(mirror) container=\(container)")
        }
        #endif
        configureSecureCaptureSurface()
        buildLayout()
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        let activity = KeyboardActivityRecognizer()
        activity.cancelsTouchesInView = false
        activity.delaysTouchesBegan = false
        activity.activity = { [weak self] touch in
            guard let self else { return }
            guard let runtime = self.runtimeBridge else {
                // Let UIKit deliver the explicit system paste first. Starting
                // Face ID on touch-down can cancel the control's touch-up and
                // force the user to tap Incolla a second time.
                if self.isPasteControlTouch(touch) { return }
                self.attemptBiometricResume()
                return
            }
            if runtime.recordUserInteraction() {
                self.sessionDeadlineMonotonicMillis = runtime.deadlineMonotonicMillis
                self.updateWindowLabel()
            }
        }
        view.addGestureRecognizer(activity)
        #endif
        policy.listener = self
        observeCaptureState()
        render()
    }

    private func prepareFeedback() {
        // The extension view must already belong to its host window before
        // UIKit can route the feedback to this keyboard's haptic environment.
        if #available(iOS 17.5, *) {
            keyFeedback = UIImpactFeedbackGenerator(style: .medium, view: view)
            buttonFeedback = UIImpactFeedbackGenerator(style: .light, view: view)
        } else {
            keyFeedback = UIImpactFeedbackGenerator(style: .medium)
            buttonFeedback = UIImpactFeedbackGenerator(style: .light)
        }
        keyFeedback?.prepare()
        buttonFeedback?.prepare()
    }

    /// Start only once the input view is actually attached and visible.
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        refreshScreenProtectionPreference()
        // UIKit may install its own input-view chrome after viewDidLoad. Match
        // the adjoining system surface once the extension is on screen.
        view.backgroundColor = Self.keyboardChromeBackground
        #if LAYERGRAM_KEYBOARD_TRACE
        let chrome = view.backgroundColor?.resolvedColor(with: traitCollection)
        var red: CGFloat = 0, green: CGFloat = 0, blue: CGFloat = 0, alpha: CGFloat = 0
        chrome?.getRed(&red, green: &green, blue: &blue, alpha: &alpha)
        traceLifecycle("chrome_\(Int(red * 255))_\(Int(green * 255))_\(Int(blue * 255))")
        #endif
        traceLifecycle("appeared")
        traceInputLanguage()
        prepareFeedback()
        started = true
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        restoreBiometricResumeHint()
        #endif
        // iOS can retain a keyboard controller while the user visits the app
        // and comes back. A fresh app-owned window must be discovered even if
        // UIKit does not send another viewDidAppear callback.
        render()
        reconnectTimer?.invalidate()
        let reconnect = Timer(timeInterval: 0.3, repeats: true) { [weak self] _ in
            guard let self, self.started, self.session == nil,
                  self.snapshot().isViewVisible, !self.isScreenCaptured else { return }
            #if LAYERGRAM_AUTONOMOUS_KEYBOARD
            switch KeyboardBiometricResumeGate.reconnectAction(
                hasRuntime: self.runtimeBridge != nil,
                authenticationPending: self.biometricResumePending,
                expiresAt: self.biometricResumeExpiresAt, now: self.monotonicNow) {
            case .keepRuntime, .waitForAuthentication:
                return
            case .expireShortcut:
                self.traceLifecycle("biometricShortcutExpired")
                self.invalidateEditor(status: Copy.string(.openApp, in: self.locale))
                return
            case .seekAppWindow:
                break
            }
            // The proxy can acquire its real host document only after the
            // first appearance callback. Retry the sealed hint before looking
            // for a one-use app bootstrap window.
            if !self.biometricResumeAvailable {
                self.restoreBiometricResumeHint()
                if self.biometricResumeAvailable { self.render() }
            }
            #endif
            self.startSession()
        }
        reconnectTimer = reconnect
        RunLoop.main.add(reconnect, forMode: .common)
        startSession()
    }

    /// Drop the editor binding and the transport immediately: never wait for
    /// `viewDidDisappear` to revoke.
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        traceLifecycle("viewWillDisappear")
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        if ownInsertionPending { traceLifecycle("viewWillDisappear_exportPending") }
        if operation == .ack { traceLifecycle("viewWillDisappear_ackPending") }
        if rebindInProgress { traceLifecycle("viewWillDisappear_rebindPending") }
        #endif
        reconnectTimer?.invalidate()
        reconnectTimer = nil
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        teardownSession(preserveResumeTicket: canPreserveProtectedBiometricResume())
        #else
        teardownSession()
        #endif
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        started = false
    }

    deinit {
        pollTimer?.invalidate()
        expiryTimer?.invalidate()
        reconnectTimer?.invalidate()
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

    /// Fixture-only lifecycle codes; never include text, identity or host data.
    private let traceControllerID = String(UUID().uuidString.prefix(8))
    #if LAYERGRAM_KEYBOARD_TRACE
    private var fixtureLifecycleStages: [String] = []
    #endif

    private func traceLifecycle(_ code: String) {
        #if LAYERGRAM_KEYBOARD_TRACE
        os_log("LayergramKeyboardTrace %{public}@ %{public}@", log: .default,
               type: .info, code, traceControllerID)
        fixtureLifecycleStages.append(code)
        fixtureLifecycleStages = Array(fixtureLifecycleStages.suffix(20))
        let hostStages = appGroupIdentifier.flatMap {
            UserDefaults(suiteName: $0)?.stringArray(forKey: "fixtureHostStages")
        } ?? []
        statusLabel.accessibilityValue = (hostStages + fixtureLifecycleStages).joined(separator: ",")
        #endif
    }

    #if LAYERGRAM_AUTONOMOUS_KEYBOARD
    private func traceBiometricHint(_ code: String) {
        guard lastBiometricHintTrace != code else { return }
        lastBiometricHintTrace = code
        traceLifecycle(code)
    }
    #endif

    #if LAYERGRAM_KEYBOARD_TRACE
    private func traceSlow(_ phase: String, since start: CFTimeInterval) {
        let millis = Int((CACurrentMediaTime() - start) * 1_000)
        if millis >= 16 { traceLifecycle("slow_\(phase)_\(millis)ms") }
    }
    #endif

    private func traceInputLanguage() {
        #if LAYERGRAM_KEYBOARD_TRACE
        let mode = textDocumentProxy.documentInputMode?.primaryLanguage ?? "nil"
        os_log("LayergramKeyboardLanguage mode=%{public}@ advertised=%{public}@ locale=%{public}@ layout=%{public}@",
               log: .default, type: .info, mode, Self.advertisedLanguage ?? "nil",
               locale.identifier, String(describing: inputLayout))
        #endif
    }

    /// The live capture state of the screen this input view is actually on.
    private var isScreenCaptured: Bool {
        if #available(iOS 17.0, *), traitCollection.sceneCaptureState == .active {
            return true
        }
        if let screen = viewIfLoaded?.window?.screen { return screen.isCaptured }
        return UIScreen.main.isCaptured
    }

    private func snapshot() -> KeyboardEditorSnapshot {
        KeyboardEditorSnapshot(
            isViewVisible: viewIfLoaded?.window != nil &&
                (!screenProtectionEnabled || captureHostView != nil),
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
        guard !screenProtectionEnabled || captureHostView != nil else {
            status = Copy.string(.openApp, in: locale)
            render()
            return
        }
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        guard runtimeBridge == nil else { return }
        #endif
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
            guard client.hasLiveWindow(excluding: lastBootstrapSessionId) else {
                #if LAYERGRAM_AUTONOMOUS_KEYBOARD
                if biometricResumeAvailable { return }
                #endif
                if status != Copy.string(.openApp, in: locale) {
                    traceLifecycle(client.hasLiveWindow() ? "oldBootstrapWindow" : "noBootstrapWindow")
                    status = Copy.string(.openApp, in: locale)
                    render()
                }
                return
            }
            traceLifecycle("newBootstrapWindow")
            session?.revoke()
            let session = try client.attach()
            guard session.sessionId != lastBootstrapSessionId else {
                traceLifecycle("sameBootstrapSession")
                session.revoke()
                return
            }
            lastBootstrapSessionId = session.sessionId
            self.session = session
            sessionDeadlineMonotonicMillis = session.deadlineMonotonicMillis
            #if LAYERGRAM_AUTONOMOUS_KEYBOARD
            if beginDelegation(document: documentIdentifier) { return }
            #endif
            guard policy.begin(
                documentIdentifier: documentIdentifier,
                windowDeadlineMonotonicMillis: sessionDeadlineMonotonicMillis
            ) else {
                invalidateEditor(status: Copy.string(.openApp, in: locale))
                return
            }
            draft = ""
            draftCursor = 0
            contacts = []
            contactQuery = ""
            contactSearchActive = false
            emojiPickerVisible = false
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
            traceLifecycle("bootstrapAttachFailed")
            // Storage, rendezvous and admission problems collapse into one
            // generic state: no reason, no owner detail, no retry of an old send.
            invalidateEditor(status: Copy.string(.openApp, in: locale))
        }
    }

    #if LAYERGRAM_AUTONOMOUS_KEYBOARD
    private func beginDelegation(document: String) -> Bool {
        traceLifecycle("beginDelegation")
        clearSensitiveValues()
        delegationNonce = UUID().uuidString
        delegationDocument = document
        nextDelegationAttempt = 0
        status = Copy.string(.starting, in: locale)
        scheduleTimers()
        render()
        pollDelegation()
        return true
    }

    private func pollDelegation() {
        guard started, let session, let nonce = delegationNonce else { return }
        let current = snapshot()
        guard current.isViewVisible, current.hasFullAccess, !current.isCaptured,
              let document = current.documentIdentifier,
              document == delegationDocument,
              monotonicNow < sessionDeadlineMonotonicMillis else {
            traceLifecycle("delegationDeadlineOrView")
            expiredState(); return
        }
        do {
            if !delegationPending {
                guard monotonicNow >= nextDelegationAttempt else { return }
                let data = try JSONSerialization.data(withJSONObject: [
                    "operation": "delegate", "editorNonce": nonce, "requestId": UUID().uuidString])
                guard try session.sendIfStorageReady(payload: data) != nil else {
                    nextDelegationAttempt = monotonicNow + 250
                    return
                }
                delegationPending = true
                traceLifecycle("delegateSent")
                return
            }
            guard case .response(let bytes) = try session.pollResponse() else { return }
            delegationPending = false
            guard let reply = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
                expiredState(); return
            }
            if reply["status"] as? String == "busy" {
                if nextDelegationAttempt == 0 { traceLifecycle("delegateBusy") }
                nextDelegationAttempt = monotonicNow + 250
                return
            }
            guard reply["status"] as? String == "ok" else {
                #if LAYERGRAM_KEYBOARD_TRACE
                let stages: Set<String> = [
                    "delegateClockUnavailable", "delegateServiceDisposed",
                    "delegateServiceNotStarted", "delegateInvalidRequest",
                    "delegateNoCoordinator", "delegateNoIdentity",
                    "delegateAdmissionDenied", "delegatePipelinePreparing",
                    "delegateGrantMissing"
                ]
                if let stage = reply["diagnosticStage"] as? String, stages.contains(stage) {
                    traceLifecycle(stage)
                }
                #endif
                traceLifecycle("delegateRejected")
                expiredState()
                return
            }
            guard reply["status"] as? String == "ok", reply["mode"] as? String == "autonomous-v1",
                  let keyText = reply["key"] as? String, var key = Data(base64Encoded: keyText), key.count == 32,
                  let raw = reply["configuration"] as? [String: Any],
                  raw["editorNonce"] as? String == nonce,
                  let group = appGroupIdentifier else {
                traceLifecycle("delegateMalformed")
                expiredState(); return
            }
            traceLifecycle("delegateAccepted")
            defer { key.resetBytes(in: 0..<key.count) }
            let configuration = try Self.nativeConfiguration(raw)
            guard let epoch = configuration["epoch"] as? FlutterStandardTypedData else { expiredState(); return }
            let runtime = try KeyboardRuntimeBridge(groupIdentifier: group, epoch: epoch.data, key: key,
                configuration: configuration, snapshot: { [weak self] in
                    self?.snapshot() ?? KeyboardEditorSnapshot(isViewVisible: false, hasFullAccess: false,
                        isCaptured: true, documentIdentifier: nil, monotonicMillis: 0)
                })
            // The grant was consumed once. Its bootstrap channel can now close.
            _ = try? session.send(payload: JSONSerialization.data(withJSONObject: [
                "operation": "delegateAck", "editorNonce": nonce, "requestId": UUID().uuidString]))
            session.revoke()
            self.session = nil
            delegationNonce = nil
            delegationDocument = nil
            biometricResumeAvailable = false
            biometricResumeExpiresAt = nil
            biometricResumeDocument = nil
            KeyboardBiometricResumeStore.remove(group: group)
            if raw["biometricResume"] as? Bool == true {
                let ticketCreated = monotonicNow
                if let bytes = KeyboardBiometricResumeTicket.encode(
                    document: document, key: key, configuration: raw,
                    createdAt: ticketCreated) {
                    biometricResumeAvailable = KeyboardBiometricResumeStore.save(bytes, group: group)
                    biometricResumeExpiresAt = biometricResumeAvailable
                        ? KeyboardBiometricResumeTicket.revocableDeadlineMillis : nil
                    biometricResumeDocument = biometricResumeAvailable ? document : nil
                    traceLifecycle(biometricResumeAvailable ? "biometricTicketSaved" : "biometricTicketRejected")
                }
            }
            activateRuntime(runtime, nonce: nonce)
        } catch {
            // Only the initial delegation can try a fresh lease. No message,
            // export, ACK or expired response is replayed. The original app
            // window and this exact visible document remain authoritative.
            if let error = error as? MailboxError, error.kind == .unavailable,
               session.canReplaceExpiredRequest {
                delegationPending = false
                nextDelegationAttempt = monotonicNow + 250
                traceLifecycle("delegateLeaseRetry")
                return
            }
            if let mailboxError = error as? MailboxError {
                traceLifecycle("delegateException_\(mailboxError.kind.rawValue)")
            } else {
                traceLifecycle("delegateException_other")
            }
            expiredState()
        }
    }

    private func activateRuntime(_ runtime: KeyboardRuntimeBridge, nonce: String) {
        runtimeBridge = runtime
        runtime.onClosed = { [weak self, weak runtime] in
            self?.traceLifecycle("runtimeClosed")
            self?.expiredState(resumable: runtime?.lastClosureWasIdle == true)
        }
        sessionDeadlineMonotonicMillis = runtime.deadlineMonotonicMillis
        scheduleTimers()
        runtime.start { [weak self, weak runtime] accepted in
            guard let self, let runtime, self.runtimeBridge === runtime else { return }
            self.traceLifecycle(accepted ? "runtimeReady" : "runtimeStartDenied")
            guard accepted, self.policy.beginAutonomous(snapshot: self.snapshot(), editorNonce: nonce,
                authorization: { [weak runtime] _ in
                    guard let runtime, runtime.validate() else { return nil }
                    return runtime.deadlineMonotonicMillis
                }) else {
                    self.traceLifecycle("runtimeStartOrPolicy")
                    self.expiredState(); return
                }
            do {
                let begin = try self.policy.beginRequestData()
                self.operation = .begin
                runtime.request(begin) { [weak self, weak runtime] response in
                    guard let self, let runtime, self.runtimeBridge === runtime else { return }
                    guard let response else { self.expiredState(); return }
                    self.handleResponse(response)
                }
            } catch { self.expiredState() }
        }
    }

    /// The expired grant never revives. A physical tap may request a *new* grant
    /// from a biometric-sealed capability; current custody and editor admission
    /// are still mandatory, and the active grant retains its idle deadline.
    private func attemptBiometricResume() {
        guard biometricResumeAvailable, !biometricResumePending, runtimeBridge == nil,
              started, let group = appGroupIdentifier,
              let document = documentIdentifier,
              KeyboardBiometricResumeGate.mayAttempt(available: biometricResumeAvailable,
                  expectedDocument: biometricResumeDocument, expiresAt: biometricResumeExpiresAt,
                  snapshot: snapshot()) else { return }
        biometricResumePending = true
        traceLifecycle("biometricPromptStarted")
        let generation = biometricResumeGeneration
        let reason: String
        switch Language.forLocale(locale) {
        case .italian: reason = "Riapri la sessione della tastiera Layergram"
        case .spanish: reason = "Reabrir la sesión del teclado Layergram"
        case .english: reason = "Reopen the Layergram keyboard session"
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = KeyboardBiometricResumeStore.load(group: group, reason: reason)
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                guard self.biometricResumeGeneration == generation else { return }
                self.biometricResumePending = false
                guard self.started,
                      self.biometricResumeAvailable,
                      self.runtimeBridge == nil else { return }
                guard KeyboardBiometricResumeGate.mayAttempt(
                          available: self.biometricResumeAvailable,
                          expectedDocument: self.biometricResumeDocument,
                          expiresAt: self.biometricResumeExpiresAt,
                          snapshot: self.snapshot()),
                      self.documentIdentifier == document else {
                    self.traceLifecycle("biometricEditorChanged")
                    self.invalidateEditor(status: Copy.string(.openApp, in: self.locale))
                    return
                }
                let bytes: Data
                switch result {
                case .success(let recovered):
                    bytes = recovered
                case .retryable:
                    // A cancelled first-use consent or biometric attempt does
                    // not revoke custody. The next deliberate tap may retry.
                    self.deferredPasteIntent = nil
                    self.traceLifecycle("biometricPromptRetryable")
                    return
                case .unavailable:
                    self.traceLifecycle("biometricCredentialUnavailable")
                    self.invalidateEditor(status: Copy.string(.openApp, in: self.locale))
                    return
                }
                guard let ticket = KeyboardBiometricResumeTicket(
                          data: bytes, document: document, now: self.monotonicNow,
                          allowBiometricEditorRebind: true) else {
                    self.traceLifecycle("biometricTicketInvalid")
                    self.invalidateEditor(status: Copy.string(.openApp, in: self.locale))
                    return
                }
                var key = ticket.key
                defer { key.resetBytes(in: 0..<key.count) }
                let nonce = UUID().uuidString
                var raw = ticket.configuration
                raw["editorNonce"] = nonce
                do {
                    let config = try Self.nativeConfiguration(raw)
                    let runtime = try KeyboardRuntimeBridge(groupIdentifier: group,
                        epoch: ticket.epoch, key: key, configuration: config,
                        snapshot: { [weak self] in
                            self?.snapshot() ?? KeyboardEditorSnapshot(
                                isViewVisible: false, hasFullAccess: false,
                                isCaptured: true, documentIdentifier: nil,
                                monotonicMillis: 0)
                        })
                    self.biometricResumeAvailable = true
                    self.traceLifecycle("biometricRuntimeStarting")
                    self.activateRuntime(runtime, nonce: nonce)
                } catch {
                    self.traceLifecycle("biometricRuntimeDenied")
                    self.invalidateEditor(status: Copy.string(.openApp, in: self.locale))
                }
            }
        }
    }

    private func restoreBiometricResumeHint() {
        guard KeyboardBiometricResumeGate.mayKeepSealedHint(
            protectionEnabled: screenProtectionEnabled, secureHostReady: captureHostView != nil,
            fullAccess: hasFullAccess, captured: isScreenCaptured) else {
            traceBiometricHint("biometricHintProtectionUnavailable"); return
        }
        guard let group = appGroupIdentifier else {
            traceBiometricHint("biometricHintNoGroup"); return
        }
        guard let document = documentIdentifier else {
            traceBiometricHint("biometricHintNoDocument"); return
        }
        guard let expiry = KeyboardBiometricResumeStore.resumeDeadline(
            group: group, document: document, now: monotonicNow,
            allowBiometricEditorRebind: true) else {
            traceBiometricHint("biometricHintMiss")
            biometricResumeAvailable = false
            biometricResumeExpiresAt = nil
            biometricResumeDocument = nil
            return
        }
        biometricResumeAvailable = true
        biometricResumeExpiresAt = expiry
        biometricResumeDocument = document
        status = biometricResumePromptStatus
        traceBiometricHint("biometricTicketRecovered")
    }

    private var biometricResumePromptStatus: String {
        switch Language.forLocale(locale) {
        case .italian: return "Tocca un tasto per Face ID o Touch ID"
        case .spanish: return "Toca una tecla para Face ID o Touch ID"
        case .english: return "Tap a key for Face ID or Touch ID"
        }
    }

    /// Retain only the sealed Face ID capability when the secure
    /// keyboard surface disappears. No editor grant, draft or runtime survives.
    /// A new instance still has to match the OS editor and prove FS custody.
    private func canPreserveProtectedBiometricResume() -> Bool {
        guard KeyboardBiometricResumeGate.mayKeepSealedHint(
                protectionEnabled: screenProtectionEnabled, secureHostReady: captureHostView != nil,
                fullAccess: hasFullAccess, captured: isScreenCaptured), biometricResumeAvailable,
              let group = appGroupIdentifier,
              let document = biometricResumeDocument,
              let expiry = biometricResumeExpiresAt,
              monotonicNow < expiry else { return false }
        // A screenshot sheet may temporarily replace the host editor before
        // dismissing this extension. Do not bind to that transient document:
        // only a new controller back on the original OS document can read the
        // hint and offer Face ID. The old runtime and draft are always closed.
        return KeyboardBiometricResumeStore.resumeDeadline(
            group: group, document: document, now: monotonicNow,
            allowBiometricEditorRebind: true) == expiry
    }

    /// UIKit may warn a new controller about memory before `viewDidAppear`.
    /// It has no live grant to revoke and has not read the Keychain hint yet.
    /// Leaving the sealed item in place grants nothing without fresh Face ID.
    private func canDeferSealedTicketRevocationBeforeAppearance() -> Bool {
        KeyboardBiometricResumeGate.mayDeferSealedTicketRevocationBeforeAppearance(
            hasRuntime: runtimeBridge != nil, hasOwnerSession: session != nil,
            hasAppeared: started, protectionEnabled: screenProtectionEnabled,
            secureHostReady: captureHostView != nil, fullAccess: hasFullAccess,
            captured: isScreenCaptured)
    }


    /// JSON is confined to the encrypted one-shot bootstrap. The identity
    /// capability stays in this process and is consumed by the headless runtime.
    private static func nativeConfiguration(_ raw: [String: Any]) throws -> [String: Any] {
        guard (raw.count == 10 || (raw.count == 11 && raw["saveHistory"] != nil) ||
               (raw.count == 12 && raw["saveHistory"] != nil && raw["biometricResume"] != nil)),
              raw["v"] as? Int == 2,
              (raw["saveHistory"] == nil || raw["saveHistory"] is Bool),
              (raw["biometricResume"] == nil || raw["biometricResume"] is Bool),
              let rows = raw["contacts"] as? [[String: Any]], rows.count <= 64 else {
            throw KeyboardPolicyError.invalid
        }
        var result = raw
        // This preference is enforced by native Keychain admission, not Dart.
        result.removeValue(forKey: "biometricResume")
        for name in ["publicIdentity", "identityKeyMaterial", "localDeviceId", "epoch"] {
            guard let text = raw[name] as? String, text.utf8.count <= 4096,
                  let bytes = Data(base64Encoded: text) else { throw KeyboardPolicyError.invalid }
            if name == "identityKeyMaterial" && (bytes.count != 97 || bytes.first != 1) {
                throw KeyboardPolicyError.invalid
            }
            result[name] = FlutterStandardTypedData(bytes: bytes)
        }
        result["contacts"] = try rows.map { row in
            guard row.count == 6, let text = row["identity"] as? String, text.utf8.count <= 4096,
                  let bytes = Data(base64Encoded: text) else { throw KeyboardPolicyError.invalid }
            var mapped = row
            mapped["identity"] = FlutterStandardTypedData(bytes: bytes)
            return mapped
        }
        return result
    }
    #endif

    /// Queue one request for the live owner. Returns `false` when admission or
    /// the transport refused it, so the caller never assumes a send happened.
    @discardableResult
    private func queue(
        _ operation: KeyboardOperation,
        payload: [String: KeyboardRequestValue] = [:]
    ) -> Bool {
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        if let runtime = runtimeBridge {
            guard self.operation == nil, runtime.isReady, runtime.validate() else { return false }
            do {
                let data = try policy.requestData(operation, payload: payload, snapshot: snapshot())
                self.operation = operation
                runtime.request(data) { [weak self, weak runtime] response in
                    guard let self, let runtime, self.runtimeBridge === runtime else { return }
                    guard let response else { self.expiredState(); return }
                    self.handleResponse(response)
                }
                return true
            } catch { expiredState(); return false }
        }
        #endif
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
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        if runtimeBridge != nil { expiryTimer = nil; return }
        #endif
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
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        if let runtime = runtimeBridge {
            guard started, runtime.validate() else {
                traceLifecycle("runtimePollValidation")
                expiredState(); return
            }
            sessionDeadlineMonotonicMillis = runtime.deadlineMonotonicMillis
            // The old editor was intentionally ended while Dart binds the
            // next one. Native admission remains checked above; the policy is
            // unbound only for this short handoff and must not expire it.
            if Self.needsEditorPolicyRevalidation(runtimeReady: runtime.isReady,
                                                  rebindInProgress: rebindInProgress),
               !policy.revalidate(snapshot()) {
                traceLifecycle("editorPolicyRevalidation")
                expiredState(); return
            }
            updateWindowLabel()
            return
        }
        if delegationNonce != nil { pollDelegation(); return }
        #endif
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
        updateWindowLabel()
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
        accentPopup?.removeFromSuperview()
        accentPopup = nil
        spaceDragOrigin = nil
        spaceDragCaretOrigin = nil
    }

    private func teardownSession(preserveResumeTicket: Bool = false) {
        traceLifecycle("teardownSession")
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        deferredPasteIntent = nil
        traceLifecycle(preserveResumeTicket ? "biometricTicketPreservedOnExit" : "biometricTicketRevokedOnExit")
        biometricResumePending = false
        biometricResumeGeneration &+= 1
        if !preserveResumeTicket {
            biometricResumeAvailable = false
            biometricResumeExpiresAt = nil
            biometricResumeDocument = nil
            if let group = appGroupIdentifier { KeyboardBiometricResumeStore.remove(group: group) }
        }
        #endif
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

    private func expiredState(resumable: Bool = false) {
        traceLifecycle("expiredState")
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        let wasAlreadyIdle = biometricResumeAvailable && runtimeBridge == nil
        let canResume = resumable || wasAlreadyIdle || canPreserveProtectedBiometricResume()
        let expiredStatus = canResume && biometricResumeAvailable
            ? biometricResumePromptStatus : Copy.string(.sessionExpired, in: locale)
        invalidateEditor(status: expiredStatus,
                         preserveResumeTicket: canResume)
        #else
        invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
        #endif
    }

    /// Complete invalidation: end the editor binding, best-effort `end`, drop the
    /// transport, clear every retained label and plaintext value, then render.
    private func invalidateEditor(status newStatus: String, line: Int = #line,
                                  preserveResumeTicket: Bool = false) {
        traceLifecycle("invalidateLine_\(line)")
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        deferredPasteIntent = nil
        traceLifecycle(preserveResumeTicket ? "biometricTicketPreservedOnInvalidation" : "biometricTicketRevokedOnInvalidation")
        if !preserveResumeTicket {
            biometricResumeAvailable = false
            biometricResumeExpiresAt = nil
            biometricResumeDocument = nil
            biometricResumeGeneration &+= 1
            if let group = appGroupIdentifier { KeyboardBiometricResumeStore.remove(group: group) }
        }
        #endif
        stopTimers()
        if let nonce = policy.endEditor() { sendEnd(nonce: nonce) }
        session?.revoke()
        session = nil
        clearSensitiveValues()
        status = newStatus
        render()
    }

    /// Drop every sensitive value and label because the editor is gone.
    private func clearSensitiveValues(preservingAutonomousRuntime: Bool = false) {
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        delegationNonce = nil
        delegationDocument = nil
        delegationPending = false
        ownInsertionPending = false
        if !preservingAutonomousRuntime {
            rebindInProgress = false
            recipientAfterOwnExport = nil
            documentAfterOwnExport = nil
            let runtime = runtimeBridge
            runtimeBridge = nil
            if runtime != nil { traceLifecycle("clearRuntime") }
            runtime?.onClosed = nil
            runtime?.close()
        }
        #endif
        repeatTimer?.invalidate()
        repeatTimer = nil
        draft = ""
        draftCursor = 0
        contacts = []
        contactQuery = ""
        contactSearchActive = false
        emojiPickerVisible = false
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
        draftView.text = nil
        draftView.accessibilityLabel = nil
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
            if completed == .begin { traceLifecycle("beginResponseRejected") }
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        if completed == .begin {
            switch response {
            case .failed: traceLifecycle("beginResponseFailed")
            case .granted: traceLifecycle("beginResponseGranted")
            }
            // A host callback from our own insertion may arrive while the new
            // editor's begin is in flight. Keep the rebound generation guarded
            // until its begin reply has actually been accepted.
            #if LAYERGRAM_AUTONOMOUS_KEYBOARD
            rebindInProgress = false
            #endif
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
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        resumeDeferredPasteIfReady()
        #endif
        #if LAYERGRAM_KEYBOARD_TRACE
        if completed == .begin { traceCountdownGeometry("begin") }
        if completed == .select { traceCountdownGeometry("select") }
        if completed == .ack { traceCountdownGeometry("ack") }
        #endif
    }

    private func handleGrant(_ completed: KeyboardOperation?) {
        guard let completed else { return }
        switch completed {
        case .begin:
            status = Copy.string(.sessionActive, in: locale)
            #if LAYERGRAM_AUTONOMOUS_KEYBOARD
            if Self.canRestoreRecipientAfterOwnExport(
                recipientAfterOwnExport, exportDocument: documentAfterOwnExport,
                currentDocument: snapshot().documentIdentifier
            ), let recipient = recipientAfterOwnExport {
                // Revalidate the previous explicit choice in the delegated
                // runtime. No name is shown until its fresh select succeeds.
                status = Copy.string(.waiting, in: locale)
                _ = queue(.select, payload: [
                    "contactId": .string(recipient.id), "confirm": .bool(true)
                ])
            } else {
                recipientAfterOwnExport = nil
                documentAfterOwnExport = nil
            }
            #endif
        case .heartbeat:
            break
        case .contacts:
            contacts = policy.contacts() ?? []
            contactQuery = ""
            contactSearchActive = false
            surface = .contacts
            status = contacts.isEmpty ? Copy.string(.noContacts, in: locale) : Copy.string(.recipient, in: locale)
        case .select:
            if let confirmed = policy.selection() {
                #if LAYERGRAM_AUTONOMOUS_KEYBOARD
                if let previous = recipientAfterOwnExport,
                   !Self.matchesRecipientAfterOwnExport(previous, confirmed: confirmed) {
                    policy.clearSelection()
                    pendingSelection = nil
                    status = Copy.string(.chooseRecipient, in: locale)
                } else {
                    pendingSelection = confirmed
                    status = Copy.string(.recipient, in: locale)
                }
                recipientAfterOwnExport = nil
                documentAfterOwnExport = nil
                #else
                pendingSelection = confirmed
                status = Copy.string(.recipient, in: locale)
                #endif
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
            traceLifecycle("ackGranted")
            status = Copy.string(.exported, in: locale)
            #if LAYERGRAM_AUTONOMOUS_KEYBOARD
            if ownInsertionPending {
                ownInsertionPending = false
                rebindAutonomousEditor()
            }
            #endif
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
        traceLifecycle("insertAuthorizedCarrier")
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
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        ownInsertionPending = runtimeBridge != nil
        if ownInsertionPending {
            recipientAfterOwnExport = pendingSelection
            documentAfterOwnExport = current.documentIdentifier
        }
        #endif
        textDocumentProxy.insertText(carrier)
        // Clear the plaintext and live selection regardless of the result:
        // the API gives no acceptance result and the permit is one-use. Only
        // the separately guarded recipient choice may be approved again.
        draft = ""
        draftCursor = 0
        pendingSelection = nil
        policy.clearSelection()
        draftView.text = nil
        draftView.accessibilityLabel = nil
        recipientLabel.text = nil
        recipientLabel.accessibilityLabel = nil
        guard policy.liveControl(snapshot()) else {
            // A host callback invalidated the editor during the insertion: do not
            // resurrect any context to acknowledge.
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        status = Copy.string(.exported, in: locale)
        guard queue(.ack, payload: [
            "pendingId": .string(permit.pendingId),
            "commitText": .bool(true)
        ]) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        traceLifecycle("ackQueued")
        render()
    }

    // MARK: - Local editing

    #if LAYERGRAM_AUTONOMOUS_KEYBOARD
    private func isPasteControlTouch(_ touch: UITouch) -> Bool {
        guard let control = composePasteControl else { return false }
        var candidate = touch.view
        while let view = candidate {
            if view === control { return true }
            candidate = view.superview
        }
        return false
    }
    #endif

    /// The first touch after idle expiry is an authentication gesture, not an
    /// edit. UIKit also delivers that touch to its button; consume it without
    /// deleting a still-valid biometric ticket or inserting plaintext.
    private func deferTouchForBiometricResume() -> Bool {
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        if let runtime = runtimeBridge, !runtime.isReady { return true }
        guard runtimeBridge == nil,
              KeyboardBiometricResumeGate.mayAttempt(
                  available: biometricResumeAvailable,
                  expectedDocument: biometricResumeDocument,
                  expiresAt: biometricResumeExpiresAt,
                  snapshot: snapshot()) else { return false }
        attemptBiometricResume()
        return true
        #else
        return false
        #endif
    }

    private func editable() -> Bool {
        guard started else { return false }
        guard policy.liveControl(snapshot()) else {
            if deferTouchForBiometricResume() { return false }
            traceLifecycle("editAdmissionRejected")
            // A failing edit guard is a complete invalidation, never a status
            // change that keeps the local plaintext around.
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return false
        }
        return true
    }

    private func insert(_ character: String) {
        #if LAYERGRAM_KEYBOARD_TRACE
        let startedAt = CACurrentMediaTime()
        defer { traceSlow("insert", since: startedAt) }
        #endif
        guard editable() else { return }
        if surface == .contacts && contactSearchActive {
            if (contactQuery + character).count <= 64 { contactQuery += character }
            if case .on = shift {
                shift = .off
                renderKeys()
            }
            renderContactSearch()
            return
        }
        guard surface == .keys else { return }
        var characters = Array(draft)
        let insertion = Array(character)
        let offset = min(draftCursor, characters.count)
        characters.insert(contentsOf: insertion, at: offset)
        let next = String(characters)
        guard next.utf16.count <= KeyboardSurfaceBounds.maxDraftUTF16 else {
            invalidateEditor(status: Copy.string(.tooLong, in: locale))
            return
        }
        draft = next
        draftCursor = offset + insertion.count
        if case .on = shift { shift = .off }
        if status == Copy.string(.starting, in: locale) { status = Copy.string(.sessionActive, in: locale) }
        render()
    }

    private func backspace() {
        guard editable() else { return }
        if surface == .contacts && contactSearchActive {
            if !contactQuery.isEmpty { contactQuery.removeLast() }
            renderContactSearch()
            return
        }
        guard surface == .keys, draftCursor > 0 else { return }
        var characters = Array(draft)
        characters.remove(at: min(draftCursor, characters.count) - 1)
        draft = String(characters)
        draftCursor -= 1
        render()
    }

    private func insertSpace() {
        insert(" ")
    }

    private func insertNewline() {
        if surface == .contacts && contactSearchActive {
            tapDoneSearch()
        } else {
            insert("\n")
        }
    }

    // MARK: - Actions

    private func requestContacts() {
        guard hasFullAccess else {
            invalidateEditor(status: Copy.string(.noFullAccess, in: locale))
            return
        }
        guard policy.liveControl(snapshot()) else {
            if deferTouchForBiometricResume() { return }
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
        let heading = NSMutableAttributedString(
            attributedString: Self.contactHeading(preview.contactName, font: previewLabel.font)
        )
        heading.append(NSAttributedString(string: "\n\(preview.text)"))
        previewLabel.attributedText = heading
        previewLabel.accessibilityLabel =
            "\(Copy.string(.from, in: locale)): \(preview.contactName)\n\(preview.text)"
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

    /// The system paste control delivers item providers without the iOS 16+
    /// programmatic-paste permission sheet. An asynchronous provider result is
    /// accepted only for the exact live editor that received the user tap.
    override func paste(itemProviders: [NSItemProvider]) {
        guard hasFullAccess else {
            invalidateEditor(status: Copy.string(.noFullAccess, in: locale))
            return
        }
        guard let provider = itemProviders.first(where: {
            $0.canLoadObject(ofClass: NSString.self) ||
            $0.canLoadObject(ofClass: NSURL.self)
        }) else {
            status = Copy.string(.emptyPaste, in: locale)
            render()
            return
        }
        guard policy.liveControl(snapshot()) else {
            #if LAYERGRAM_AUTONOMOUS_KEYBOARD
            if deferTouchForBiometricResume(), let document = documentIdentifier {
                deferredPasteIntent = DeferredPasteIntent(
                    provider: provider, document: document,
                    generation: biometricResumeGeneration, createdAt: monotonicNow)
                traceLifecycle("pasteDeferredForBiometric")
                return
            }
            #else
            if deferTouchForBiometricResume() { return }
            #endif
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        guard let nonce = policy.currentEditorNonce,
              let document = documentIdentifier
        else {
            status = Copy.string(.emptyPaste, in: locale)
            render()
            return
        }
        loadPasteProvider(provider, nonce: nonce, document: document)
    }

    #if LAYERGRAM_AUTONOMOUS_KEYBOARD
    private func resumeDeferredPasteIfReady() {
        guard let intent = deferredPasteIntent, operation == nil,
              policy.liveControl(snapshot()) else { return }
        deferredPasteIntent = nil
        guard Self.matchesDeferredPaste(expectedDocument: intent.document,
                currentDocument: documentIdentifier,
                expectedGeneration: intent.generation,
                currentGeneration: biometricResumeGeneration,
                createdAt: intent.createdAt, now: monotonicNow),
              let nonce = policy.currentEditorNonce else { return }
        traceLifecycle("pasteResumedAfterBiometric")
        loadPasteProvider(intent.provider, nonce: nonce, document: intent.document)
    }
    #endif

    static func matchesDeferredPaste(expectedDocument: String?, currentDocument: String?,
                                     expectedGeneration: UInt64, currentGeneration: UInt64,
                                     createdAt: Int64, now: Int64) -> Bool {
        guard let expectedDocument, !expectedDocument.isEmpty else { return false }
        return expectedDocument == currentDocument &&
            expectedGeneration == currentGeneration && now >= createdAt &&
            now - createdAt <= 60_000
    }

    private func loadPasteProvider(_ provider: NSItemProvider, nonce: String,
                                   document: String) {
        let accept: (String?) -> Void = { [weak self] text in
            DispatchQueue.main.async { [weak self] in
                guard let self,
                      Self.matchesPasteDelivery(expectedNonce: nonce,
                          currentNonce: self.policy.currentEditorNonce,
                          expectedDocument: document,
                          currentDocument: self.documentIdentifier),
                      self.policy.liveControl(self.snapshot()) else { return }
                self.decodePastedCarrier(text)
            }
        }
        if provider.canLoadObject(ofClass: NSString.self) {
            provider.loadObject(ofClass: NSString.self) { object, _ in
                accept(object as? String)
            }
        } else {
            provider.loadObject(ofClass: NSURL.self) { object, _ in
                accept((object as? URL)?.absoluteString)
            }
        }
    }

    static func matchesPasteDelivery(expectedNonce: String?, currentNonce: String?,
                                     expectedDocument: String?, currentDocument: String?) -> Bool {
        guard let expectedNonce, !expectedNonce.isEmpty,
              let expectedDocument, !expectedDocument.isEmpty else { return false }
        return expectedNonce == currentNonce && expectedDocument == currentDocument
    }

    /// Compatibility path for iOS 15, before UIPasteControl existed. There is
    /// no programmatic pasteboard read on iOS 16 or later.
    private func pasteAndDecode() {
        if #available(iOS 16.0, *) { return }
        guard hasFullAccess else {
            invalidateEditor(status: Copy.string(.noFullAccess, in: locale))
            return
        }
        guard policy.liveControl(snapshot()) else {
            if deferTouchForBiometricResume() { return }
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        decodePastedCarrier(UIPasteboard.general.string)
    }

    private func decodePastedCarrier(_ pasted: String?) {
        // An explicit decode always drops any previously confirmed recipient and
        // local draft, so a preview can never inherit them, and it drops the
        // previous message's sender shortcut before the new one is known.
        draft = ""
        draftCursor = 0
        pendingSelection = nil
        policy.clearSelection()
        draftView.text = nil
        draftView.accessibilityLabel = nil
        recipientLabel.text = nil
        recipientLabel.accessibilityLabel = nil
        applyDecodedPreview(nil)
        guard let pasted, !pasted.isEmpty else {
            status = Copy.string(.emptyPaste, in: locale)
            render()
            return
        }
        guard pasted.utf16.count <= KeyboardSurfaceBounds.maxInboundCarrierUTF16 else {
            status = Copy.string(.pasteTooLong, in: locale)
            render()
            return
        }
        // A public contact card is not an encrypted chat message. Keep it in
        // the user's clipboard so the containing app can parse and show the
        // fingerprint before import. Keyboard extensions cannot reliably open
        // their containing app, and the keyboard must not add contacts itself.
        if Self.looksLikePublicIdentity(pasted) {
            status = Copy.string(.identityImport, in: locale)
            render()
            return
        }
        guard queue(.decode, payload: ["carrier": .string(pasted)]) else { return }
        status = Copy.string(.waiting, in: locale)
        render()
    }

    static func looksLikePublicIdentity(_ text: String) -> Bool {
        let normalized = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.utf16.count <= 4096 else { return false }
        let lower = normalized.lowercased()
        return lower.hasPrefix("layergram://i/") ||
            normalized.hasPrefix("v3.") ||
            lower.hasPrefix("[layergram identity]")
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
    /// text/selection callbacks and the local deadline timers. A memory warning
    /// trims disposable UI objects but does not itself revoke a valid grant.
    private func observeCaptureState() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(captureStateChanged),
            name: UIScreen.capturedDidChangeNotification,
            object: nil
        )
        // iOS posts this only AFTER a still image has been captured. The secure
        // capture host hides our content in the captured frame. Retain the
        // draft only while that host and the authorized session remain live.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(stillScreenshotTaken),
            name: UIApplication.userDidTakeScreenshotNotification,
            object: nil
        )
        if #available(iOS 17.0, *) {
            registerForTraitChanges([UITraitSceneCaptureState.self]) {
                (controller: KeyboardViewController, _: UITraitCollection) in
                controller.captureStateChanged()
            }
        }
    }

    @objc private func stillScreenshotTaken() {
        // liveControl rechecks the bound editor, native custody and idle
        // deadline; an old "ready" bit alone is never enough to keep a draft.
        let sessionActive = policy.liveControl(snapshot())
        guard Self.canRetainDraftAfterStillScreenshot(
            protectionEnabled: screenProtectionEnabled,
            secureHostReady: captureHostView != nil,
            sessionActive: sessionActive,
            viewVisible: viewIfLoaded?.window != nil,
            recordingActive: isScreenCaptured
        ) else {
            #if LAYERGRAM_AUTONOMOUS_KEYBOARD
            invalidateEditor(status: Copy.string(.openApp, in: locale),
                             preserveResumeTicket: canPreserveProtectedBiometricResume())
            #else
            invalidateEditor(status: Copy.string(.openApp, in: locale))
            #endif
            return
        }
        traceLifecycle("protectedStillScreenshot")
    }

    static func canRetainDraftAfterStillScreenshot(protectionEnabled: Bool,
                                                    secureHostReady: Bool,
                                                    sessionActive: Bool,
                                                    viewVisible: Bool,
                                                    recordingActive: Bool) -> Bool {
        protectionEnabled && secureHostReady && sessionActive && viewVisible && !recordingActive
    }

    @objc private func captureStateChanged() {
        handleCaptureChange(captured: isScreenCaptured)
    }

    /// UIKit also posts capture changes when recording stops. Revoke on the
    /// live captured state only: a delayed stop notification must not erase a
    /// fresh app grant. Stopping never restores the old editor, draft or ticket;
    /// ordinary bootstrap admission still requires a new app departure window.
    func handleCaptureChange(captured: Bool) {
        guard captured else {
            traceLifecycle("captureStoppedNoRevocation")
            return
        }
        traceLifecycle("captureActiveRevocation")
        systemInvalidation()
    }

    /// A recording or unsupported capture state invalidates the editor and
    /// clears every sensitive value.
    @objc private func systemInvalidation() {
        invalidateEditor(status: Copy.string(.openApp, in: locale))
    }

    enum HostCallbackAction: Equatable {
        case deferOwnExport, rebind, invalidate
    }

    /// A UIKit callback during first attachment can precede the autonomous
    /// grant. Keep only the blank, app-authorized bootstrap for the same
    /// visible editor; this neither grants an editor nor extends its deadline.
    static func canContinuePendingDelegation(pending: Bool, document: String?,
                                             deadline: Int64,
                                             snapshot: KeyboardEditorSnapshot) -> Bool {
        pending && document != nil && document?.isEmpty == false &&
            snapshot.documentIdentifier == document && snapshot.isViewVisible &&
            snapshot.hasFullAccess && !snapshot.isCaptured &&
            snapshot.monotonicMillis < deadline
    }

    static func needsEditorPolicyRevalidation(runtimeReady: Bool,
                                              rebindInProgress: Bool) -> Bool {
        runtimeReady && !rebindInProgress
    }

    static func hostCallbackAction(ownInsertionPending: Bool,
                                   rebindInProgress: Bool,
                                   requestInFlight: Bool) -> HostCallbackAction {
        if ownInsertionPending || rebindInProgress { return .deferOwnExport }
        return requestInFlight ? .invalidate : .rebind
    }

    static func canRestoreRecipientAfterOwnExport(_ recipient: KeyboardContact?,
                                                 exportDocument: String?,
                                                 currentDocument: String?) -> Bool {
        recipient != nil && exportDocument != nil && exportDocument == currentDocument
    }

    static func matchesRecipientAfterOwnExport(_ previous: KeyboardContact,
                                               confirmed: KeyboardContact) -> Bool {
        previous.id == confirmed.id && previous.fingerprint == confirmed.fingerprint
    }

    #if LAYERGRAM_AUTONOMOUS_KEYBOARD
    /// Starts a fresh editor generation inside the same live native grant.
    /// Draft, preview, request IDs and selection disappear before the new begin.
    /// An explicitly confirmed recipient may be revalidated only for the exact
    /// same OS document. The OS document and custody are still pinned, and
    /// this does not refresh either inactivity deadline.
    private func rebindAutonomousEditor() {
        traceLifecycle("rebindAutonomousEditor")
        guard !rebindInProgress else { traceLifecycle("rebindAlreadyRunning"); return }
        guard let runtime = runtimeBridge else {
            traceLifecycle("rebindRuntimeMissing"); expiredState(); return
        }
        guard runtime.validate() else {
            traceLifecycle("rebindRuntimeInvalid"); expiredState(); return
        }
        guard snapshot().documentIdentifier != nil else {
            traceLifecycle("rebindDocumentMissing"); expiredState(); return
        }
        if recipientAfterOwnExport == nil,
           Self.canRestoreRecipientAfterOwnExport(pendingSelection,
                exportDocument: policy.currentDocumentIdentifier,
                currentDocument: snapshot().documentIdentifier) {
            // Sending through the host clears its field, but does not by itself
            // change the opaque document. Keep only the explicit contact choice;
            // the fresh begin/select still checks its identity fingerprint.
            recipientAfterOwnExport = pendingSelection
            documentAfterOwnExport = policy.currentDocumentIdentifier
        }
        rebindInProgress = true
        // endEditor synchronously calls keyboardPolicyCleared(). The listener
        // must keep this still-valid native grant while it clears the old editor.
        endingEditorForRebind = true
        _ = policy.endEditor()
        endingEditorForRebind = false
        let nonce = UUID().uuidString
        status = Copy.string(.starting, in: locale)
        render()
        runtime.rebind(editorNonce: nonce) { [weak self, weak runtime] accepted in
            guard let self, let runtime else { return }
            guard self.runtimeBridge === runtime else {
                self.traceLifecycle("rebindRuntimeReplaced"); return
            }
            self.traceLifecycle(accepted ? "rebindAccepted" : "rebindRejected")
            guard accepted,
                  self.policy.beginAutonomous(snapshot: self.snapshot(), editorNonce: nonce,
                    authorization: { [weak runtime] _ in
                        guard let runtime, runtime.validate() else { return nil }
                        return runtime.deadlineMonotonicMillis
                    }) else {
                self.traceLifecycle("rebindPolicyDenied")
                self.expiredState(); return
            }
            do {
                let begin = try self.policy.beginRequestData()
                self.operation = .begin
                runtime.request(begin) { [weak self, weak runtime] response in
                    guard let self, let runtime, self.runtimeBridge === runtime else { return }
                    guard let response else { self.expiredState(); return }
                    self.handleResponse(response)
                }
            } catch { self.expiredState() }
        }
    }
    #endif

    /// Host changes always discard the old editor context. A live autonomous
    /// grant can bind a *new* generation for the same OS document, but no
    /// plaintext survives the transition. An exact-document recipient is checked
    /// again through a fresh select. During our own insert,
    /// callbacks are deferred only until the single export ACK is processed.
    private func editorInvalidated() {
        guard started else { return }
        traceLifecycle("hostEditorCallback")
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        if runtimeBridge == nil,
           Self.canContinuePendingDelegation(
                pending: session != nil && delegationNonce != nil,
                document: delegationDocument, deadline: sessionDeadlineMonotonicMillis,
                snapshot: snapshot()) {
            traceLifecycle("hostCallbackBootstrapContinues")
            return
        }
        if let runtime = runtimeBridge, runtime.validate() {
            // WhatsApp and other hosts can deliver text/selection callbacks
            // both during insertText/ACK and after the fresh editor is bound.
            // All sensitive local state is already cleared in the latter case;
            // these callbacks belong to the export we initiated, not to a new
            // user edit. Native document/custody admission was checked above.
            let action = Self.hostCallbackAction(ownInsertionPending: ownInsertionPending,
                                           rebindInProgress: rebindInProgress,
                                           requestInFlight: operation != nil)
            switch action {
            case .deferOwnExport:
                traceLifecycle("hostCallbackDeferred")
                return
            case .rebind:
                traceLifecycle("hostCallbackRebind")
                rebindAutonomousEditor()
                return
            case .invalidate:
                traceLifecycle("hostCallbackInvalidated")
                break
            }
        }
        #endif
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        if runtimeBridge == nil && session == nil {
            // UIKit can send an editor callback to a newly created extension
            // before its host document is ready. There is no live grant to
            // revoke; wipe display state while keeping a sealed hint eligible
            // for an exact-document Face ID check once the proxy settles.
            if !biometricResumeAvailable { restoreBiometricResumeHint() }
            let protected = KeyboardBiometricResumeGate.mayKeepSealedHint(
                protectionEnabled: screenProtectionEnabled, secureHostReady: captureHostView != nil,
                fullAccess: hasFullAccess, captured: isScreenCaptured)
            let ready = KeyboardBiometricResumeGate.mayAttempt(
                available: biometricResumeAvailable,
                expectedDocument: biometricResumeDocument,
                expiresAt: biometricResumeExpiresAt,
                snapshot: snapshot())
            invalidateEditor(status: ready ? biometricResumePromptStatus
                                           : Copy.string(.openApp, in: locale),
                             preserveResumeTicket: protected)
            return
        }
        // A still screenshot can temporarily detach the input view before its
        // notification arrives. Clear the editor and draft now; keep only the
        // biometric-sealed capability when the same protected editor and FS
        // custody are still eligible for a fresh Face ID check.
        let mayResume = canPreserveProtectedBiometricResume()
        invalidateEditor(status: mayResume ? biometricResumePromptStatus
                                         : Copy.string(.sessionExpired, in: locale),
                         preserveResumeTicket: mayResume)
        #else
        invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
        #endif
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
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        // A memory warning is advisory, not a revocation of the editor or its
        // custody grant. Closing a valid runtime strands the one-use bootstrap.
        // Release disposable UI state; every touch and poll still checks admission.
        if let runtime = runtimeBridge, runtime.validate() {
            traceLifecycle("memoryWarningTrimmed")
            repeatTimer?.invalidate()
            repeatTimer = nil
            accentPopup?.removeFromSuperview()
            accentPopup = nil
            keyFeedback = nil
            buttonFeedback = nil
            return
        }
        #endif
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        // iOS may issue this while its screenshot sheet replaces the host
        // editor, including before a newly created controller first appears.
        // Drop runtime and draft but do not delete its still-sealed Face ID
        // ticket before that controller can inspect the hint.
        let preserveSealedTicket = canPreserveProtectedBiometricResume() ||
            canDeferSealedTicketRevocationBeforeAppearance()
        if preserveSealedTicket { traceLifecycle("memoryWarningSealedTicketRetained") }
        invalidateEditor(status: Copy.string(.openApp, in: locale),
                         preserveResumeTicket: preserveSealedTicket)
        #else
        invalidateEditor(status: Copy.string(.openApp, in: locale))
        #endif
    }

    // MARK: - Layout

    // The key rows end at the input view's lower inset. The system owns any
    // separate Face ID input-mode area below our view.
    private static let preferredHeight: CGFloat = 296
    private static let selectedRecipientMinimumExtraHeight: CGFloat = 30
    private static let maximumContactHeight: CGFloat = 740
    /// UIKit's answer is unreliable before the extension is attached to a
    /// host editor. The initial unattached render omits our globe; attachment
    /// triggers a new render and adds it only when UIKit asks for one.
    var showsEmbeddedInputSwitcher: Bool {
        guard view.window != nil else { return false }
        return needsInputModeSwitchKey
    }
    static let emojiCatalog: [[String]] = [
        ["😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😍", "🥰", "😘", "😉", "😎", "🤩", "🥳", "🙂", "🙃", "😇", "🤗", "🤔", "😐", "😔", "😢", "😭", "😡", "😱", "😴", "🤯", "🥹", "🫠", "🫶", "👍", "👎", "👏", "🙌", "🙏", "🤝", "👋", "💪"],
        ["🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵", "🐔", "🐧", "🐦", "🦋", "🐝", "🐢", "🐬", "🐳", "🌸", "🌻", "🌹", "🌷", "🌲", "🍀", "🌈"],
        ["🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🍒", "🍑", "🥑", "🥕", "🍕", "🍔", "🍟", "🌮", "🍣", "🍝", "🍰", "🎂", "🍪", "🍫", "☕️", "🍵", "🥤", "🍺", "🍷", "🥂", "🍽️", "🧁"],
        ["🚗", "🚕", "🚌", "🚆", "✈️", "🚀", "🚲", "🛴", "🏠", "🏙️", "🏖️", "🏔️", "🌍", "🌎", "🌏", "☀️", "🌤️", "☁️", "🌧️", "❄️", "⚡️", "🌙", "⭐️", "🔥", "🎉", "🎁", "🎵", "⚽️", "🏆", "📱"],
        ["❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "💔", "💕", "💖", "💯", "✅", "❌", "⚠️", "❗️", "❓", "💬", "💡", "🔒", "🔑", "📌", "📷", "📍", "➡️", "⬅️", "⬆️", "⬇️", "∞", "©️"]
    ]

    /// Keep the visible contact heading compact; the explicit direction stays
    /// in the localized accessibility label instead of consuming screen space.
    struct SecurityShieldAppearance {
        let symbol: String
        let color: UIColor
        let goldRim: Bool
    }

    static func securityShieldAppearance(_ phase: KeyboardSecurityPhase?)
        -> SecurityShieldAppearance {
        switch phase {
        case .setupRequired, .setupPending, .maximumSetupRequired, .maximumSetupPending:
            return SecurityShieldAppearance(symbol: "shield.fill", color: .systemOrange,
                goldRim: phase == .maximumSetupRequired || phase == .maximumSetupPending)
        case .normalActive, .maximumActive:
            return SecurityShieldAppearance(symbol: "shield.fill", color: .systemGreen,
                goldRim: phase == .maximumActive)
        case .recoveryRequired, .maximumRecoveryRequired:
            return SecurityShieldAppearance(symbol: "exclamationmark.shield.fill",
                color: .systemRed, goldRim: phase == .maximumRecoveryRequired)
        case nil:
            return SecurityShieldAppearance(symbol: "shield.fill",
                color: .secondaryLabel, goldRim: false)
        }
    }

    static func contactHeading(_ name: String, font: UIFont,
                               securityPhase: KeyboardSecurityPhase? = nil,
                               showUnknownShield: Bool = true) -> NSAttributedString {
        // Confirmation may precede a trustworthy FS reading. A gray shield
        // would suggest "without FS" even when selection reveals orange.
        if securityPhase == nil && !showUnknownShield {
            return NSAttributedString(string: name, attributes: [
                .font: font, .foregroundColor: UIColor.label
            ])
        }
        let attachment = NSTextAttachment()
        let appearance = securityShieldAppearance(securityPhase)
        let configuration = UIImage.SymbolConfiguration(pointSize: 13, weight: .semibold)
        if appearance.goldRim,
           let rim = UIImage(systemName: "shield.fill", withConfiguration: configuration)?
               .withTintColor(.systemYellow, renderingMode: .alwaysOriginal),
           let fill = UIImage(systemName: "shield.fill", withConfiguration: configuration)?
               .withTintColor(appearance.color, renderingMode: .alwaysOriginal) {
            attachment.image = UIGraphicsImageRenderer(size: CGSize(width: 13, height: 13))
                .image { _ in
                    rim.draw(in: CGRect(x: 0, y: 0, width: 13, height: 13))
                    fill.draw(in: CGRect(x: 2, y: 2, width: 9, height: 9))
                }
        } else {
            let symbol = UIImage(systemName: appearance.symbol, withConfiguration: configuration)
                ?? UIImage(systemName: "shield.fill", withConfiguration: configuration)
            attachment.image = symbol?
                .withTintColor(appearance.color, renderingMode: .alwaysOriginal)
        }
        // A nil attachment image is rendered by UIKit as a generic document.
        // Keep the contact name clean even on a system missing an SF Symbol.
        guard attachment.image != nil else {
            return NSAttributedString(string: name, attributes: [
                .font: font, .foregroundColor: UIColor.label
            ])
        }
        attachment.bounds = CGRect(x: 0, y: -1, width: 13, height: 13)
        let heading = NSMutableAttributedString(attachment: attachment)
        heading.append(NSAttributedString(string: "  \(name)", attributes: [
            .font: font,
            .foregroundColor: UIColor.label
        ]))
        return heading
    }

    static func securityPhaseLabel(_ phase: KeyboardSecurityPhase?,
                                   language: Language) -> String {
        switch phase {
        case .setupRequired, .setupPending:
            if language == .italian { return "FS in negoziazione" }
            if language == .spanish { return "FS en negociación" }
            return "FS negotiating"
        case .maximumSetupRequired, .maximumSetupPending:
            if language == .italian { return "FS Maximum in negoziazione" }
            if language == .spanish { return "FS Maximum en negociación" }
            return "Maximum FS negotiating"
        case .normalActive:
            if language == .italian { return "FS attiva" }
            if language == .spanish { return "FS activa" }
            return "FS active"
        case .maximumActive:
            if language == .italian { return "FS Maximum attiva" }
            if language == .spanish { return "FS Maximum activa" }
            return "Maximum FS active"
        case .recoveryRequired, .maximumRecoveryRequired:
            if language == .italian { return "FS da ripristinare" }
            if language == .spanish { return "FS requiere recuperación" }
            return "FS needs recovery"
        case nil:
            if language == .italian { return "stato FS non disponibile" }
            if language == .spanish { return "estado FS no disponible" }
            return "FS status unavailable"
        }
    }

    static func contactCellContent(_ contact: KeyboardContact?, language: Language)
        -> UIListContentConfiguration {
        var configuration = UIListContentConfiguration.cell()
        // A reused cell must not inherit an arbitrary document image. The
        // fingerprint remains the only secondary identity cue until selection.
        configuration.image = nil
        if let contact {
            configuration.text = contact.name
            configuration.secondaryText = "\(Copy.string(.fingerprint, in: language)): \(contact.fingerprint)"
        }
        return configuration
    }

    private func buildLayout() {
        view.backgroundColor = Self.keyboardChromeBackground

        statusLabel.font = .preferredFont(forTextStyle: .caption2)
        statusLabel.adjustsFontForContentSizeCategory = true
        statusLabel.textColor = .secondaryLabel
        statusLabel.numberOfLines = 1
        statusLabel.lineBreakMode = .byTruncatingTail
        statusLabel.accessibilityIdentifier = "layergram.status"
        statusLabel.setContentCompressionResistancePriority(.required, for: .vertical)

        draftView.font = .preferredFont(forTextStyle: .body)
        draftView.adjustsFontForContentSizeCategory = true
        draftView.textColor = .label
        draftView.backgroundColor = .tertiarySystemBackground
        draftView.layer.cornerRadius = 10
        draftView.isEditable = false
        draftView.isSelectable = false
        draftView.isScrollEnabled = true
        draftView.bounces = false
        if #available(iOS 26.0, *) {
            // The system's soft scroll-edge effect blurs the upper line in
            // this compact two-line composer as soon as the caret scrolls.
            draftView.topEdgeEffect.isHidden = true
            draftView.bottomEdgeEffect.isHidden = true
        }
        draftView.textContainerInset = UIEdgeInsets(top: 4, left: 8, bottom: 4, right: 38)
        draftView.accessibilityIdentifier = "layergram.draft"
        draftView.translatesAutoresizingMaskIntoConstraints = false
        draftView.addGestureRecognizer(UITapGestureRecognizer(
            target: self, action: #selector(tapDraft(_:))
        ))
        draftPlaceholder.text = Copy.string(.secretMessage, in: locale)
        draftPlaceholder.textColor = .placeholderText
        draftPlaceholder.font = .preferredFont(forTextStyle: .body)
        draftPlaceholder.isUserInteractionEnabled = false
        draftPlaceholder.translatesAutoresizingMaskIntoConstraints = false
        draftView.addSubview(draftPlaceholder)
        NSLayoutConstraint.activate([
            draftPlaceholder.leadingAnchor.constraint(equalTo: draftView.leadingAnchor, constant: 13),
            draftPlaceholder.topAnchor.constraint(equalTo: draftView.topAnchor, constant: 10)
        ])
        draftCaret.backgroundColor = Self.textAccent
        draftCaret.layer.cornerRadius = 1
        draftCaret.isUserInteractionEnabled = false
        draftView.addSubview(draftCaret)
        // The draft remains local and is never an accessibility value exposed
        // to the host application.
        draftView.isAccessibilityElement = false

        clearDraftButton.setImage(UIImage(systemName: "xmark.circle.fill"), for: .normal)
        clearDraftButton.tintColor = .secondaryLabel
        clearDraftButton.accessibilityIdentifier = "layergram.action.clearDraft"
        clearDraftButton.accessibilityLabel = Copy.string(.clearSecretMessage, in: locale)
        clearDraftButton.addTarget(self, action: #selector(tapClearDraft), for: .touchUpInside)
        clearDraftButton.addTarget(self, action: #selector(hapticButton), for: .touchDown)
        clearDraftButton.translatesAutoresizingMaskIntoConstraints = false
        let draftBox = UIView()
        draftBox.addSubview(draftView)
        draftBox.addSubview(clearDraftButton)
        NSLayoutConstraint.activate([
            draftBox.heightAnchor.constraint(equalToConstant: 58),
            draftView.leadingAnchor.constraint(equalTo: draftBox.leadingAnchor),
            draftView.trailingAnchor.constraint(equalTo: draftBox.trailingAnchor),
            draftView.topAnchor.constraint(equalTo: draftBox.topAnchor),
            draftView.bottomAnchor.constraint(equalTo: draftBox.bottomAnchor),
            clearDraftButton.trailingAnchor.constraint(equalTo: draftBox.trailingAnchor, constant: -4),
            clearDraftButton.centerYAnchor.constraint(equalTo: draftBox.centerYAnchor),
            clearDraftButton.widthAnchor.constraint(equalToConstant: 32),
            clearDraftButton.heightAnchor.constraint(equalToConstant: 40)
        ])
        configureRoundAction(composeContactsButton, identifier: "layergram.action.recipient",
                             label: Copy.string(.contacts, in: locale),
                             image: UIImage(systemName: "person.fill"),
                             action: #selector(tapContacts))
        var contactsConfiguration = composeContactsButton.configuration
        contactsConfiguration?.preferredSymbolConfigurationForImage = UIImage.SymbolConfiguration(
            pointSize: 16, weight: .medium)
        composeContactsButton.configuration = contactsConfiguration
        configureRoundAction(composeActionButton, identifier: "layergram.action.paste",
                             label: Copy.string(.pasteDecrypt, in: locale),
                             image: Self.pasteActionIcon,
                             action: #selector(tapContextualAction))
        var pasteConfiguration = composeActionButton.configuration
        pasteConfiguration?.preferredSymbolConfigurationForImage = UIImage.SymbolConfiguration(
            pointSize: 16, weight: .medium)
        composeActionButton.configuration = pasteConfiguration
        composeActionSlot.translatesAutoresizingMaskIntoConstraints = false
        composeActionButton.translatesAutoresizingMaskIntoConstraints = false
        composeActionSlot.addSubview(composeActionButton)
        NSLayoutConstraint.activate([
            composeActionSlot.widthAnchor.constraint(equalToConstant: 40),
            composeActionSlot.heightAnchor.constraint(equalToConstant: 40),
            composeActionButton.centerXAnchor.constraint(equalTo: composeActionSlot.centerXAnchor),
            composeActionButton.centerYAnchor.constraint(equalTo: composeActionSlot.centerYAnchor)
        ])
        if #available(iOS 16.0, *) {
            // UIKit grants the pasteboard read to this visible system control.
            // Reading UIPasteboard.general.string from our UIButton would show
            // a permission sheet and can detach the keyboard mid-request.
            let acceptedTypes = UIPasteConfiguration(forAccepting: NSString.self)
            acceptedTypes.addTypeIdentifiers(forAccepting: NSURL.self)
            self.pasteConfiguration = acceptedTypes
            let configuration = UIPasteControl.Configuration()
            configuration.displayMode = .iconOnly
            configuration.cornerStyle = .capsule
            configuration.baseForegroundColor = Self.functionForeground
            configuration.baseBackgroundColor = Self.functionBackground
            let control = UIPasteControl(configuration: configuration)
            control.target = self
            control.accessibilityIdentifier = "layergram.action.paste"
            // iOS may not supply a label until this control is attached. Keep
            // its explicit purpose accessible in every supported locale.
            control.accessibilityLabel = Copy.string(.pasteDecrypt, in: locale)
            control.accessibilityHint = Copy.string(.pasteDecrypt, in: locale)
            control.addTarget(self, action: #selector(hapticButton), for: .touchDown)
            control.translatesAutoresizingMaskIntoConstraints = false
            composeActionSlot.addSubview(control)
            NSLayoutConstraint.activate([
                control.centerXAnchor.constraint(equalTo: composeActionSlot.centerXAnchor),
                control.centerYAnchor.constraint(equalTo: composeActionSlot.centerYAnchor),
                control.widthAnchor.constraint(equalToConstant: 40),
                control.heightAnchor.constraint(equalToConstant: 40)
            ])
            composePasteControl = control
        }
        composeRow.axis = .horizontal
        composeRow.alignment = .center
        composeRow.spacing = 6
        composeRow.accessibilityIdentifier = "layergram.compose.row"
        composeRow.addArrangedSubview(composeContactsButton)
        composeRow.addArrangedSubview(draftBox)
        composeRow.addArrangedSubview(composeActionSlot)
        let composeHeight = composeRow.heightAnchor.constraint(equalToConstant: 58)
        composeHeight.priority = UILayoutPriority(999)
        composeHeight.isActive = true

        recipientLabel.font = UIFontMetrics(forTextStyle: .subheadline)
            .scaledFont(for: .systemFont(ofSize: 14, weight: .medium))
        recipientLabel.adjustsFontForContentSizeCategory = true
        recipientLabel.textColor = .label
        recipientLabel.backgroundColor = .clear
        recipientLabel.numberOfLines = 1
        recipientLabel.lineBreakMode = .byTruncatingTail
        recipientLabel.accessibilityIdentifier = "layergram.recipient.name"
        recipientLabel.setContentCompressionResistancePriority(.defaultHigh, for: .horizontal)
        recipientLabel.setContentCompressionResistancePriority(.required, for: .vertical)

        windowLabel.font = .preferredFont(forTextStyle: .caption1)
        windowLabel.adjustsFontForContentSizeCategory = true
        windowLabel.textColor = .secondaryLabel
        windowLabel.textAlignment = .right
        windowLabel.accessibilityIdentifier = "layergram.window"
        windowLabel.numberOfLines = 1
        windowLabel.setContentHuggingPriority(.required, for: .horizontal)
        windowLabel.setContentCompressionResistancePriority(.required, for: .horizontal)
        windowLabel.setContentCompressionResistancePriority(.required, for: .vertical)

        let statusRow = UIStackView(arrangedSubviews: [statusLabel, windowLabel])
        statusRow.axis = .horizontal
        statusRow.spacing = 6
        statusRow.distribution = .fill
        // The host's rounded keyboard edge supplies the top chrome. Pull this
        // short row into its lower curve while keeping both ends inside it.
        statusRow.isLayoutMarginsRelativeArrangement = true
        statusRow.layoutMargins = UIEdgeInsets(top: 0, left: 10, bottom: 0, right: 10)

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
        contactsView.accessibilityIdentifier = "layergram.contacts.list"
        emptyContactsLabel.text = Copy.string(.noContacts, in: locale)
        emptyContactsLabel.textAlignment = .center
        emptyContactsLabel.textColor = .secondaryLabel

        // This search field is display-only. The extension's own keys update
        // its local query; it cannot become first responder or switch the
        // host editor, and no search character is sent to the host app.
        contactSearchField.placeholder = Copy.string(.searchContacts, in: locale)
        contactSearchField.isUserInteractionEnabled = false
        contactSearchField.isAccessibilityElement = false
        contactSearchField.clearButtonMode = .never
        contactSearchField.translatesAutoresizingMaskIntoConstraints = false
        contactSearchButton.accessibilityIdentifier = "layergram.contacts.search"
        contactSearchButton.accessibilityLabel = Copy.string(.searchContacts, in: locale)
        contactSearchButton.addTarget(self, action: #selector(tapContactSearch), for: .touchUpInside)
        contactSearchButton.addTarget(self, action: #selector(hapticButton), for: .touchDown)
        contactSearchButton.translatesAutoresizingMaskIntoConstraints = false
        clearContactSearchButton.setTitle("×", for: .normal)
        clearContactSearchButton.titleLabel?.font = .preferredFont(forTextStyle: .title3)
        clearContactSearchButton.accessibilityIdentifier = "layergram.contacts.clear"
        clearContactSearchButton.accessibilityLabel = Copy.string(.clearSearch, in: locale)
        clearContactSearchButton.addTarget(self, action: #selector(tapClearContactSearch), for: .touchUpInside)
        clearContactSearchButton.addTarget(self, action: #selector(hapticButton), for: .touchDown)
        clearContactSearchButton.translatesAutoresizingMaskIntoConstraints = false
        let searchBox = UIView()
        searchBox.addSubview(contactSearchField)
        searchBox.addSubview(contactSearchButton)
        searchBox.addSubview(clearContactSearchButton)
        NSLayoutConstraint.activate([
            searchBox.heightAnchor.constraint(equalToConstant: 44),
            contactSearchField.leadingAnchor.constraint(equalTo: searchBox.leadingAnchor),
            contactSearchField.trailingAnchor.constraint(equalTo: searchBox.trailingAnchor),
            contactSearchField.topAnchor.constraint(equalTo: searchBox.topAnchor),
            contactSearchField.bottomAnchor.constraint(equalTo: searchBox.bottomAnchor),
            contactSearchButton.leadingAnchor.constraint(equalTo: searchBox.leadingAnchor),
            contactSearchButton.trailingAnchor.constraint(equalTo: clearContactSearchButton.leadingAnchor),
            contactSearchButton.topAnchor.constraint(equalTo: searchBox.topAnchor),
            contactSearchButton.bottomAnchor.constraint(equalTo: searchBox.bottomAnchor),
            clearContactSearchButton.trailingAnchor.constraint(equalTo: searchBox.trailingAnchor),
            clearContactSearchButton.topAnchor.constraint(equalTo: searchBox.topAnchor),
            clearContactSearchButton.bottomAnchor.constraint(equalTo: searchBox.bottomAnchor),
            clearContactSearchButton.widthAnchor.constraint(equalToConstant: 44)
        ])
        contactsContainer.axis = .vertical
        contactsContainer.spacing = 6
        contactsContainer.addArrangedSubview(searchBox)
        contactsContainer.addArrangedSubview(contactsView)

        keysStack.axis = .vertical
        keysStack.spacing = 6
        keysStack.distribution = .fillEqually
        keysStack.translatesAutoresizingMaskIntoConstraints = false
        keysContainer.addSubview(keysStack)
        NSLayoutConstraint.activate([
            keysStack.leadingAnchor.constraint(equalTo: keysContainer.leadingAnchor),
            keysStack.trailingAnchor.constraint(equalTo: keysContainer.trailingAnchor),
            keysStack.topAnchor.constraint(equalTo: keysContainer.topAnchor),
            keysStack.bottomAnchor.constraint(equalTo: keysContainer.bottomAnchor)
        ])
        // In the contact picker the table consumes spare height while the
        // typing rows remain attached to the bottom of the keyboard surface.
        keysContainer.setContentHuggingPriority(.required, for: .vertical)
        keysContainer.setContentCompressionResistancePriority(.required, for: .vertical)

        emojiContainer.axis = .vertical
        emojiContainer.spacing = 5
        emojiContainer.backgroundColor = .tertiarySystemBackground
        emojiContainer.layer.cornerRadius = 10
        emojiCategories.selectedSegmentIndex = 0
        emojiCategories.accessibilityIdentifier = "layergram.emoji.categories"
        emojiCategories.addTarget(self, action: #selector(changeEmojiCategory), for: .valueChanged)
        let emojiDelete = UIButton(type: .system)
        emojiDelete.setImage(UIImage(systemName: "delete.left"), for: .normal)
        emojiDelete.accessibilityIdentifier = "layergram.emoji.delete"
        emojiDelete.accessibilityLabel = Copy.string(.deleteKey, in: locale)
        emojiDelete.addTarget(self, action: #selector(tapEmojiDelete), for: .touchUpInside)
        emojiDelete.addTarget(self, action: #selector(hapticButton), for: .touchDown)
        emojiDelete.widthAnchor.constraint(equalToConstant: 44).isActive = true
        let emojiHeader = UIStackView(arrangedSubviews: [emojiCategories, emojiDelete])
        emojiHeader.axis = .horizontal
        emojiHeader.spacing = 5
        emojiHeader.heightAnchor.constraint(equalToConstant: 38).isActive = true
        emojiGrid.backgroundColor = .clear
        emojiGrid.dataSource = self
        emojiGrid.delegate = self
        emojiGrid.register(KeyboardEmojiCell.self, forCellWithReuseIdentifier: "emoji")
        emojiGrid.accessibilityIdentifier = "layergram.emoji.grid"
        emojiGrid.alwaysBounceVertical = true
        emojiGrid.showsVerticalScrollIndicator = true
        emojiContainer.addArrangedSubview(emojiHeader)
        emojiContainer.addArrangedSubview(emojiGrid)
        emojiContainer.translatesAutoresizingMaskIntoConstraints = false
        keysContainer.addSubview(emojiContainer)
        NSLayoutConstraint.activate([
            emojiContainer.leadingAnchor.constraint(equalTo: keysContainer.leadingAnchor),
            emojiContainer.trailingAnchor.constraint(equalTo: keysContainer.trailingAnchor),
            emojiContainer.topAnchor.constraint(equalTo: keysContainer.topAnchor)
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
        shortcutsStack.distribution = .fillEqually
        shortcutsStack.alignment = .fill
        shortcutsStack.isLayoutMarginsRelativeArrangement = true
        shortcutsStack.layoutMargins = UIEdgeInsets(top: 0, left: 8, bottom: 0, right: 8)

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
        fallbackGlobeButton.addTarget(self, action: #selector(hapticButton), for: .touchDown)
        fallbackGlobeButton.isHidden = true
        footerStack.axis = .horizontal
        footerStack.distribution = .fill
        footerStack.addArrangedSubview(fallbackGlobeButton)
        footerStack.addArrangedSubview(UIView())
        fallbackGlobeButton.heightAnchor.constraint(
            equalToConstant: Self.keyRowHeight
        ).isActive = true
        fallbackGlobeButton.widthAnchor.constraint(equalToConstant: 64).isActive = true

        recipientRow.axis = .horizontal
        recipientRow.isLayoutMarginsRelativeArrangement = true
        recipientRow.layoutMargins = UIEdgeInsets(top: 3, left: 10, bottom: 3, right: 10)
        recipientRow.addArrangedSubview(recipientLabel)
        let header = UIStackView(arrangedSubviews: [statusRow, recipientRow])
        header.axis = .vertical
        header.spacing = 5
        header.setContentHuggingPriority(.required, for: .vertical)

        // Reading uses the key area, so plaintext and its reply action keep
        // usable frames instead of competing with four fixed-height key rows.
        previewContainer.axis = .vertical
        previewContainer.spacing = 6
        previewContainer.addArrangedSubview(previewScroll)
        previewContainer.addArrangedSubview(senderButton)

        let content = UIStackView(arrangedSubviews: [contactsContainer, confirmView, keysContainer, previewContainer])
        content.axis = .vertical
        content.spacing = 10
        content.setContentHuggingPriority(.defaultLow, for: .vertical)

        // Secondary controls appear only on contacts/preview/confirmation or
        // when a decoded preview can be reopened. Ordinary composition keeps
        // all three primary controls beside the two-line local message field.
        shortcutsContainer.addArrangedSubview(shortcutsStack)
        shortcutsContainer.axis = .vertical
        shortcutsContainer.spacing = 6
        let actionHeight = shortcutsContainer.heightAnchor.constraint(
            greaterThanOrEqualToConstant: Self.actionBarMinimumHeight
        )
        actionHeight.priority = UILayoutPriority(999)
        actionHeight.isActive = true

        let root = UIStackView(arrangedSubviews: [header, shortcutsContainer, composeRow, content, footerStack])
        root.axis = .vertical
        root.spacing = 6
        // Keep the selected recipient distinct from the composer while the
        // status row sits just below the host's rounded keyboard edge.
        root.setCustomSpacing(8, after: header)
        root.translatesAutoresizingMaskIntoConstraints = false
        keyboardRootLayout = root
        attachKeyboardRoot(root, to: keyboardLayoutHost)
        // A preference only: the system may impose its own input-view height, so
        // this constraint is never required and cannot conflict.
        let height = view.heightAnchor.constraint(equalToConstant: Self.preferredHeight)
        height.priority = UILayoutPriority(999)
        height.isActive = true
        heightConstraint = height
    }

    private func remainingWindowText() -> String? {
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        // The idle window begins when the native keyboard takes custody, before
        // the first Dart `begin` response. Waiting to display the timer until
        // that response makes a valid session look timeless, then "suddenly"
        // expired when the user has not typed yet.
        let hasIdleWindow = policy.isBeginAccepted || runtimeBridge?.isReady == true
        #else
        let hasIdleWindow = policy.isBeginAccepted
        #endif
        guard started, hasIdleWindow else { return nil }
        let remaining = sessionDeadlineMonotonicMillis - monotonicNow
        guard remaining > 0 else { return nil }
        let seconds = (remaining + 999) / 1000
        return "\(Copy.string(.window, in: locale)): \(seconds)s"
    }

    private func updateWindowLabel() {
        let description = remainingWindowText()
        windowLabel.text = description.flatMap { $0.split(separator: " ").last.map(String.init) }
        windowLabel.accessibilityLabel = description
    }

    private func traceCountdownGeometry(_ phase: String) {
        #if LAYERGRAM_KEYBOARD_TRACE
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.view.layoutIfNeeded()
            let shown = self.windowLabel.text == nil ? "empty" : "set"
            let frame = self.windowLabel.convert(self.windowLabel.bounds, to: self.view)
            let statusFrame = self.statusLabel.convert(self.statusLabel.bounds, to: self.view)
            self.traceLifecycle("timer_\(phase)_\(shown)_w\(Int(frame.width))_x\(Int(frame.maxX))_y\(Int(frame.minY))_h\(Int(frame.height))_statusY\(Int(statusFrame.minY))_view\(Int(self.view.bounds.width))x\(Int(self.view.bounds.height))")
        }
        #endif
    }

    static func matchingContacts(_ contacts: [KeyboardContact], query: String) -> [KeyboardContact] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if needle.isEmpty { return contacts }
        let compactNeedle = needle.replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: " ", with: "")
        return contacts.filter { contact in
            contact.name.localizedStandardContains(needle) ||
            contact.fingerprint.localizedStandardContains(needle) ||
            contact.fingerprint.replacingOccurrences(of: "-", with: "")
                .localizedStandardContains(compactNeedle)
        }
    }

    private var visibleContacts: [KeyboardContact] {
        Self.matchingContacts(contacts, query: contactQuery)
    }

    private func updateKeyboardHeight() {
        let screen = view.window?.windowScene?.screen.bounds ?? UIScreen.main.bounds
        let target: CGFloat
        if surface == .contacts {
            let ceiling = screen.height >= screen.width ? Self.maximumContactHeight : 340
            target = min(ceiling, max(Self.preferredHeight, screen.height * 0.82))
        } else if surface == .keys {
            // Showing a recipient adds the label, its vertical margins and the
            // gap inside the header. A fixed 30 pt allowance clips larger text
            // sizes, and changing the selection must resize the input view in
            // the same render pass.
            let recipientExtraHeight = recipientRow.isHidden ? 0 : max(
                Self.selectedRecipientMinimumExtraHeight,
                ceil(recipientLabel.intrinsicContentSize.height)
                    + recipientRow.layoutMargins.top + recipientRow.layoutMargins.bottom + 5)
            target = Self.preferredHeight
                + (displayedSender == nil ? 0 : Self.actionBarMinimumHeight + 6)
                + recipientExtraHeight
        } else {
            target = Self.preferredHeight
        }
        if heightConstraint?.constant != target {
            heightConstraint?.constant = target
            view.setNeedsLayout()
        }
    }

    private func render() {
        #if LAYERGRAM_KEYBOARD_TRACE
        let startedAt = CACurrentMediaTime()
        defer { traceSlow("render", since: startedAt) }
        #endif
        statusLabel.text = "●  \(status)"
        statusLabel.textColor = status == Copy.string(.sessionActive, in: locale)
            ? Self.textAccent : .secondaryLabel
        draftView.text = draft
        composeRow.isHidden = (surface != .keys)
        draftPlaceholder.isHidden = !draft.isEmpty
        clearDraftButton.isHidden = draft.isEmpty
        let hasDraft = !draft.isEmpty
        var contextual = composeActionButton.configuration
        contextual?.image = hasDraft ? Self.sendActionIcon : Self.pasteActionIcon
        composeActionButton.configuration = contextual
        composeActionButton.isHidden = composePasteControl != nil && !hasDraft
        composePasteControl?.isHidden = hasDraft
        composeActionButton.accessibilityIdentifier = hasDraft
            ? "layergram.action.primary" :
              (composePasteControl == nil ? "layergram.action.paste" : "layergram.action.fallbackPaste")
        composeActionButton.accessibilityLabel = hasDraft
            ? Copy.string(.encryptInsert, in: locale)
            : Copy.string(.pasteDecrypt, in: locale)
        updateDraftCaret()
        draftView.accessibilityLabel = nil
        if let name = pendingSelection?.name {
            recipientLabel.attributedText = Self.contactHeading(
                name, font: recipientLabel.font,
                securityPhase: pendingSelection?.securityPhase,
                showUnknownShield: surface != .confirmation)
            recipientLabel.accessibilityLabel = "\(Copy.string(.to, in: locale)): \(name), \(Self.securityPhaseLabel(pendingSelection?.securityPhase, language: Copy.language(locale)))"
            recipientLabel.isHidden = false
            recipientRow.isHidden = false
        } else {
            recipientLabel.text = nil
            recipientLabel.accessibilityLabel = nil
            recipientLabel.isHidden = true
            recipientRow.isHidden = true
        }
        updateKeyboardHeight()
        updateWindowLabel()
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
        contactsContainer.isHidden = (surface != .contacts)
        confirmView.isHidden = (surface != .confirmation)
        let showsKeys = surface == .keys ||
            (surface == .contacts && contactSearchActive)
        keysContainer.isHidden = !showsKeys
        emojiContainer.isHidden = !(surface == .keys && emojiPickerVisible)
        previewContainer.isHidden = (surface != .preview)
        // The fallback globe is exactly the inverse of the key surface: when the
        // key layout (and its bottom-row globe) is hidden, this control keeps
        // input-mode switching available.
        fallbackGlobeButton.isHidden = showsKeys || !showsEmbeddedInputSwitcher
        footerStack.isHidden = showsKeys || !showsEmbeddedInputSwitcher
        if surface == .contacts {
            renderContactSearch()
        }
        if showsKeys { renderKeys() }
        for row in keysStack.arrangedSubviews.dropLast() {
            row.alpha = emojiPickerVisible && surface == .keys ? 0 : 1
            row.isUserInteractionEnabled = !(emojiPickerVisible && surface == .keys)
        }
        emojiButton?.setImage(UIImage(systemName: emojiPickerVisible ? "keyboard" : "face.smiling"), for: .normal)
        emojiButton?.accessibilityLabel = emojiPickerVisible ? "ABC" : "Emoji"
        if emojiPickerVisible { emojiGrid.reloadData() }
        renderShortcuts()
        shortcutsContainer.isHidden = surface == .keys && displayedSender == nil
    }

    /// Filtering changes only the local list. Rebuilding the entire keyboard
    /// on every search key both moves touch targets and delays typing.
    private func renderContactSearch() {
        guard surface == .contacts else { return }
        contactSearchField.text = contactQuery
        clearContactSearchButton.isHidden = contactQuery.isEmpty
        contactsView.reloadData()
        contactsView.backgroundView = visibleContacts.isEmpty ? emptyContactsLabel : nil
        if !contactQuery.isEmpty {
            contactsView.setContentOffset(.zero, animated: false)
        }
    }

    private func updateDraftCaret() {
        #if LAYERGRAM_KEYBOARD_TRACE
        let startedAt = CACurrentMediaTime()
        defer { traceSlow("caret", since: startedAt) }
        #endif
        guard surface == .keys else {
            draftCaret.isHidden = true
            return
        }
        let prefix = String(draft.prefix(draftCursor))
        let offset = prefix.utf16.count
        guard let position = draftView.position(from: draftView.beginningOfDocument, offset: offset) else {
            draftCaret.isHidden = true
            return
        }
        // The view is deliberately not selectable or first responder. UIKit
        // therefore does not keep its insertion point visible for us. Reveal
        // the local cursor explicitly after every edit, newline and trackpad
        // move, including the line just after a trailing newline.
        let rect = draftView.caretRect(for: position)
        if draftView.bounds.height > 0, draftView.bounds.width > 0 {
            let first = draftView.caretRect(for: draftView.beginningOfDocument)
            let top = draftView.contentOffset.y
            let bottom = top + draftView.bounds.height
            let padding: CGFloat = 4
            let target: CGFloat?
            if rect.maxY - first.minY <= draftView.bounds.height - 2 * padding {
                // A short message fits entirely. Keep both lines visible and
                // do not scroll down then back up on every character.
                target = max(0, first.minY - padding)
            } else if rect.minY < top + padding {
                target = max(0, rect.minY - padding)
            } else if rect.maxY > bottom - padding {
                target = rect.maxY - draftView.bounds.height + padding
            } else {
                target = nil
            }
            if let target, abs(target - top) > 0.5 {
                draftView.setContentOffset(CGPoint(x: draftView.contentOffset.x, y: target),
                                           animated: false)
            }
        }
        draftCaret.isHidden = !policy.liveControl(snapshot())
        draftCaret.frame = CGRect(x: rect.minX, y: rect.minY, width: 2, height: max(18, rect.height))
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
    /// Minimum height of secondary actions on non-compose surfaces.
    static let actionBarMinimumHeight: CGFloat = 40

    /// The complete, layer-dependent key layout. It is pure: it takes the layer,
    /// shift and an explicit text permutation and builds no view. Only the text
    /// slots of the letter rows are ever permuted; the surrounding action keys are
    /// not part of these rows at all.
    static func layout(
        layer: Layer,
        shift: ShiftState,
        permutation: [Int: [Int]]?,
        inputLayout: InputLayout = .qwerty
    ) -> [KeyboardRow] {
        switch layer {
        case .letters:
            var tag = 0
            return inputLayout.letterRows.enumerated().map { index, letters in
                let ordered = permuted(letters, order: permutation?[index])
                let keys = ordered.map { character -> KeyboardKey in
                    let label = shifted(character, shift: shift)
                    let key = KeyboardKey(label: label, kind: .text(label), textTag: tag)
                    tag += 1
                    return key
                }
                // Extra letters on an international row need the full width on
                // compact devices; a fixed inset would make their touch targets
                // unnecessarily small.
                return KeyboardRow(keys: keys, inset: index > 0 && letters.count < 10)
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
        Self.layout(layer: layer, shift: shift, permutation: currentPermutation(),
                    inputLayout: inputLayout)
    }

    private func currentPermutation() -> [Int: [Int]]? {
        guard scrambleEnabled else { return nil }
        for (index, letters) in inputLayout.letterRows.enumerated() {
            if scrambledIndex[index]?.count != letters.count {
                scrambledIndex[index] = Array(letters.indices).shuffled()
            }
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

    /// iOS exposes the input-mode switcher outside the keyboard on Face ID
    /// devices. Add our own globe only when UIKit explicitly requires it.
    private func bottomRow() -> UIStackView {
        let row = UIStackView()
        row.axis = .horizontal
        row.spacing = Self.keySpacing
        row.distribution = .fill

        let layerPresentation = Self.layerPresentation(for: layer)
        let layerButton = makeActionButton(layerPresentation.title, action: layerPresentation.action)
        layerButton.widthAnchor.constraint(equalToConstant: 44).isActive = true
        let globe: UIButton? = showsEmbeddedInputSwitcher
            ? makeActionButton("🌐", action: .globe) : nil
        globe?.accessibilityLabel = Copy.string(.globeSwitch, in: locale)
        globe?.widthAnchor.constraint(equalToConstant: 44).isActive = true
        let emoji = UIButton(type: .system)
        emoji.setImage(UIImage(systemName: emojiPickerVisible ? "keyboard" : "face.smiling"), for: .normal)
        emoji.accessibilityIdentifier = "layergram.action.emoji"
        emoji.accessibilityLabel = emojiPickerVisible ? "ABC" : "Emoji"
        emoji.tintColor = .label
        emoji.backgroundColor = .secondarySystemFill
        emoji.layer.cornerRadius = 6
        emoji.addTarget(self, action: #selector(tapEmojiPicker), for: .touchUpInside)
        emoji.addTarget(self, action: #selector(hapticButton), for: .touchDown)
        emoji.widthAnchor.constraint(equalToConstant: 44).isActive = true
        emojiButton = emoji
        let space = makeActionButton(Copy.string(.space, in: locale), action: .space)
        // The space key stays the widest control without letting the spacers
        // collapse it on a narrow 320 pt input view.
        let spaceWidth = space.widthAnchor.constraint(greaterThanOrEqualToConstant: 120)
        spaceWidth.priority = .defaultHigh
        spaceWidth.isActive = true
        let newline = makeActionButton("↵", action: .newline)
        newline.accessibilityLabel = Copy.string(.returnKey, in: locale)
        newline.widthAnchor.constraint(equalToConstant: 64).isActive = true
        newline.titleLabel?.adjustsFontSizeToFitWidth = true
        newline.titleLabel?.minimumScaleFactor = 0.7
        space.setContentHuggingPriority(.defaultLow, for: .horizontal)

        for key in [layerButton, emoji, space, newline] + (globe.map { [$0] } ?? []) {
            key.heightAnchor.constraint(equalToConstant: Self.keyRowHeight).isActive = true
        }
        row.addArrangedSubview(layerButton)
        if let globe { row.addArrangedSubview(globe) }
        row.addArrangedSubview(emoji)
        row.addArrangedSubview(space)
        row.addArrangedSubview(newline)
        return row
    }

    private func renderKeys() {
        // Build the (pure) layout first: shift is applied to the labels here, so
        // the signature below also covers the shift and permutation state.
        let layout = keyboardLayout()
        let leading = Self.thirdRowLeadingPresentation(for: layer, shift: shift)
        let signature = "\(layer)|\(leading.title)|\(leading.action.rawValue)|\(showsEmbeddedInputSwitcher)|" + layout
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
        backspaceButton.tintColor = .label
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
        let bottom = bottomRow()
        keysStack.addArrangedSubview(bottom)
        emojiBottomConstraint?.isActive = false
        emojiBottomConstraint = emojiContainer.bottomAnchor.constraint(equalTo: bottom.topAnchor, constant: -Self.keySpacing)
        emojiBottomConstraint?.isActive = true
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
        language: Language,
        inputLayout: InputLayout = .qwerty
    ) -> [[KeyboardKey]] {
        let rows = layout(layer: layer, shift: shift, permutation: permutation,
                          inputLayout: inputLayout)
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
            KeyboardKey(label: "", kind: .action(.emoji), textTag: nil),
            KeyboardKey(
                label: Copy.string(.space, in: language),
                kind: .action(.space),
                textTag: nil
            ),
            KeyboardKey(
                label: "↵",
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
            language: Copy.language(locale),
            inputLayout: inputLayout
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
        if surface == .contacts && contactSearchActive {
            shortcutsStack.addArrangedSubview(
                makeShortcut(
                    Copy.string(.doneSearching, in: locale),
                    action: #selector(tapDoneSearch),
                    identifier: "layergram.action.doneSearch"
                )
            )
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
        // A decoded preview remains reachable after Compose without adding a
        // permanent row to the ordinary two-line composer.
        if displayedSender != nil {
            shortcutsStack.addArrangedSubview(makeShortcut(
                Copy.string(.readMessage, in: locale), action: #selector(tapReadMessage),
                identifier: "layergram.action.read"
            ))
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
        let symbol: String
        switch identifier {
        case "layergram.action.read": symbol = "text.book.closed"
        case "layergram.action.back": symbol = "square.and.pencil"
        case "layergram.action.doneSearch": symbol = "checkmark"
        case "layergram.action.confirm": symbol = "checkmark.shield"
        case "layergram.action.cancel": symbol = "xmark"
        default: symbol = "circle"
        }
        var configuration = UIButton.Configuration.filled()
        configuration.title = title
        configuration.image = UIImage(systemName: symbol)
        configuration.preferredSymbolConfigurationForImage = UIImage.SymbolConfiguration(
            pointSize: 15, weight: .semibold)
        configuration.imagePlacement = .leading
        configuration.imagePadding = 7
        configuration.titleLineBreakMode = .byTruncatingTail
        configuration.contentInsets = NSDirectionalEdgeInsets(
            top: 6, leading: 12, bottom: 6, trailing: 12)
        configuration.baseForegroundColor = Self.functionForeground
        configuration.baseBackgroundColor = Self.functionBackground
        button.configuration = configuration
        button.accessibilityLabel = title
        button.titleLabel?.font = .preferredFont(forTextStyle: .footnote)
        button.titleLabel?.adjustsFontForContentSizeCategory = true
        button.titleLabel?.numberOfLines = 1
        button.titleLabel?.textAlignment = .center
        button.layer.cornerRadius = 6
        button.heightAnchor.constraint(equalToConstant: Self.actionBarMinimumHeight).isActive = true
        button.accessibilityIdentifier = identifier
        button.addTarget(self, action: action, for: .touchUpInside)
        button.addTarget(self, action: #selector(hapticButton), for: .touchDown)
        return button
    }

    private func configureRoundAction(
        _ button: UIButton, identifier: String, label: String,
        image: UIImage?, action: Selector
    ) {
        var configuration = UIButton.Configuration.filled()
        configuration.image = image
        configuration.preferredSymbolConfigurationForImage = UIImage.SymbolConfiguration(
            pointSize: 19, weight: .semibold)
        configuration.contentInsets = .zero
        configuration.cornerStyle = .capsule
        configuration.baseForegroundColor = Self.functionForeground
        configuration.baseBackgroundColor = Self.functionBackground
        button.configuration = configuration
        button.accessibilityIdentifier = identifier
        button.accessibilityLabel = label
        button.widthAnchor.constraint(equalToConstant: 40).isActive = true
        button.heightAnchor.constraint(equalToConstant: 40).isActive = true
        button.addTarget(self, action: action, for: .touchUpInside)
        button.addTarget(self, action: #selector(hapticButton), for: .touchDown)
    }

    /// Template rendering makes the plane and lock follow the button's
    /// appearance-specific foreground without a baked-in green badge.
    private static func sendLockedIcon() -> UIImage {
        let image = UIGraphicsImageRenderer(size: CGSize(width: 26, height: 26))
            .image { renderer in
                UIImage(systemName: "paperplane.fill")?
                    .withTintColor(.black, renderingMode: .alwaysOriginal)
                    .draw(in: CGRect(x: 1, y: 1, width: 22, height: 22))
                let badge = UIBezierPath(ovalIn: CGRect(x: 12, y: 12, width: 14, height: 14))
                renderer.cgContext.setBlendMode(.clear)
                badge.fill()
                renderer.cgContext.setBlendMode(.normal)
                UIColor.black.setStroke()
                badge.lineWidth = 1.5
                badge.stroke()
                UIImage(systemName: "lock.fill")?
                    .withTintColor(.black, renderingMode: .alwaysOriginal)
                    .draw(in: CGRect(x: 15, y: 15, width: 8, height: 8))
            }
        return image.withRenderingMode(.alwaysTemplate)
    }

    /// A compact, single-color rendering of Layergram's three-layer mark and
    /// the direction of transfer. Template rendering gives both parts exactly
    /// the same foreground color in light and dark mode.
    private static func transferIcon(outbound: Bool) -> UIImage {
        let format = UIGraphicsImageRendererFormat.default()
        format.opaque = false
        let image = UIGraphicsImageRenderer(size: CGSize(width: 46, height: 24), format: format)
            .image { _ in
                UIColor.black.setStroke()
                let logoX: CGFloat = outbound ? 0 : 22
                let arrowX: CGFloat = outbound ? 28 : 0

                func stroke(_ points: [CGPoint], closed: Bool = false) {
                    let path = UIBezierPath()
                    guard let first = points.first else { return }
                    path.move(to: first)
                    for point in points.dropFirst() { path.addLine(to: point) }
                    if closed { path.close() }
                    path.lineWidth = 1.9
                    path.lineCapStyle = .round
                    path.lineJoinStyle = .round
                    path.stroke()
                }
                func logoPoint(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
                    CGPoint(x: logoX + x, y: y)
                }

                stroke([logoPoint(2, 7), logoPoint(12, 2), logoPoint(22, 7),
                        logoPoint(12, 12)], closed: true)
                stroke([logoPoint(2, 10.5), logoPoint(12, 15.5), logoPoint(22, 10.5)])
                stroke([logoPoint(2, 14.5), logoPoint(12, 19.5), logoPoint(22, 14.5)])
                stroke([logoPoint(7, 17), logoPoint(7.8, 22), logoPoint(10.5, 19)])

                let tipY: CGFloat = outbound ? 4 : 20
                let stemY: CGFloat = outbound ? 20 : 4
                let shoulderY: CGFloat = outbound ? 10 : 14
                stroke([CGPoint(x: arrowX + 8, y: stemY),
                        CGPoint(x: arrowX + 8, y: tipY)])
                stroke([CGPoint(x: arrowX + 2, y: shoulderY),
                        CGPoint(x: arrowX + 8, y: tipY),
                        CGPoint(x: arrowX + 14, y: shoulderY)])
            }
        return image.withRenderingMode(.alwaysTemplate)
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
        button.addTarget(self, action: #selector(hapticKey), for: .touchDown)
        if Self.accentOptions(for: label) != nil {
            let hold = UILongPressGestureRecognizer(target: self, action: #selector(holdAccent(_:)))
            hold.minimumPressDuration = 0.35
            button.addGestureRecognizer(hold)
        }
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
        button.addTarget(self, action: #selector(hapticKey), for: .touchDown)
        if action == .backspace {
            let hold = UILongPressGestureRecognizer(
                target: self,
                action: #selector(holdBackspace(_:))
            )
            hold.minimumPressDuration = 0.4
            button.addGestureRecognizer(hold)
        } else if action == .space {
            let hold = UILongPressGestureRecognizer(target: self, action: #selector(holdSpace(_:)))
            hold.minimumPressDuration = 0.35
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
        draftCursor = draft.count
        render()
    }

    /// Move only the display cursor in an unattached native UI test. It cannot
    /// grant a session, change the draft or write to the host editor.
    func setLocalDraftCursorForDisplay(_ cursor: Int) {
        draftCursor = min(max(cursor, 0), draft.count)
        updateDraftCaret()
    }

    /// Put the keyboard on one surface so the persistent-control and visibility
    /// rules can be asserted. Display state only: it grants no admission, no
    /// lease, no recipient and cannot queue anything.
    func setSurfaceForDisplay(_ newSurface: Surface) {
        surface = newSurface
        render()
    }

    /// Reproduce the confirmed-contact header geometry without admitting an
    /// editor or selecting a recipient for cryptographic operations.
    func setConfirmedHeaderForDisplay(_ name: String, seconds: String) {
        pendingSelection = KeyboardContact(id: "display-only", name: name, fingerprint: "")
        render()
        windowLabel.text = seconds
    }

    /// Geometry-only search display for unattached UI tests. This never loads
    /// contacts, grants editor admission or changes the host text field.
    func setContactSearchForDisplay() {
        surface = .contacts
        contactSearchActive = true
        render()
    }

    /// Display-only seam for verifying the stable emoji panel geometry. It does
    /// not grant admission, edit the host, or authorize a keyboard session.
    func setEmojiPickerForDisplay(_ visible: Bool) {
        emojiPickerVisible = visible
        render()
    }

    /// Read-only view of the key container, so tests can prove the fallback globe
    /// is not inside the container that gets hidden off the key surface.
    var keysContainerView: UIView { keysContainer }

    /// Read-only proof of the owner-confirmed recipient. A decoded sender must
    /// never make this `true` on its own.
    var hasConfirmedOwnerSelection: Bool { policy.hasSelection }

    // MARK: - Key handling

    @objc private func hapticKey() {
        if keyFeedback == nil { prepareFeedback() }
        keyFeedback?.impactOccurred(intensity: 1)
        keyFeedback?.prepare()
    }

    @objc private func hapticButton() {
        if buttonFeedback == nil { prepareFeedback() }
        buttonFeedback?.impactOccurred(intensity: 1)
        buttonFeedback?.prepare()
    }

    /// The tapped character comes from the button title itself, so the tagged
    /// text buttons stay correct even when the neutral scramble is active.
    @objc private func tapKey(_ sender: UIButton) {
        guard let label = sender.title(for: .normal), !label.isEmpty else { return }
        insert(label)
    }

    /// Latin-script long-press variants stay in the local message; the host
    /// editor never receives them as plaintext.
    static func accentOptions(for key: String) -> [String]? {
        let options: [String]
        switch key.lowercased() {
        case "a": options = ["à", "á", "â", "ä", "ã", "å", "æ"]
        case "e": options = ["è", "é", "ê", "ë", "ę"]
        case "i": options = ["ì", "í", "î", "ï"]
        case "o": options = ["ò", "ó", "ô", "ö", "õ", "ø"]
        case "u": options = ["ù", "ú", "û", "ü"]
        case "y": options = ["ý", "ÿ"]
        case "c": options = ["ç", "ć", "č"]
        case "d": options = ["ď", "đ", "ð"]
        case "g": options = ["ğ"]
        case "l": options = ["ł", "ľ", "ĺ"]
        case "n": options = ["ñ", "ń", "ň"]
        case "r": options = ["ř", "ŕ"]
        case "s": options = ["ß", "ś", "š", "ş", "ș"]
        case "t": options = ["ť", "ț", "þ"]
        case "z": options = ["ź", "ż", "ž"]
        default: return nil
        }
        return key == key.uppercased()
            ? options.map { $0 == "ß" ? "ẞ" : $0.uppercased() }
            : options
    }

    @objc private func holdAccent(_ recognizer: UILongPressGestureRecognizer) {
        guard let key = recognizer.view as? UIButton,
              let title = key.title(for: .normal),
              let options = Self.accentOptions(for: title) else { return }
        switch recognizer.state {
        case .began:
            guard surface == .keys, layer == .letters, editable() else { return }
            accentPopup?.removeFromSuperview()
            let popup = UIStackView()
            popup.axis = .horizontal
            popup.spacing = 2
            popup.distribution = .fillEqually
            popup.backgroundColor = .secondarySystemBackground
            popup.layer.cornerRadius = 8
            popup.layer.borderWidth = 1
            popup.layer.borderColor = UIColor.separator.cgColor
            let width = CGFloat(options.count) * 37 + CGFloat(options.count - 1) * 2 + 8
            let popupHost = keyboardLayoutHost
            let keyFrame = key.convert(key.bounds, to: popupHost)
            popup.frame = CGRect(
                x: min(max(0, keyFrame.midX - width / 2), max(0, popupHost.bounds.width - width)),
                y: max(0, keyFrame.minY - 50), width: width, height: 46
            )
            for option in options {
                let label = UILabel()
                label.text = option
                label.textAlignment = .center
                label.font = .preferredFont(forTextStyle: .title3)
                label.layer.cornerRadius = 5
                label.clipsToBounds = true
                popup.addArrangedSubview(label)
            }
            popupHost.addSubview(popup)
            accentPopup = popup
            accentSelection = 0
            paintAccentSelection()
            hapticKey()
        case .changed:
            guard let popup = accentPopup else { return }
            let x = recognizer.location(in: popup).x
            let index = min(options.count - 1, max(0, Int((x - 4) / 39)))
            if index != accentSelection {
                accentSelection = index
                paintAccentSelection()
                hapticKey()
            }
        case .ended:
            guard accentPopup != nil else { return }
            let selected = options[accentSelection]
            accentPopup?.removeFromSuperview()
            accentPopup = nil
            insert(selected)
        case .cancelled, .failed:
            accentPopup?.removeFromSuperview()
            accentPopup = nil
        default: break
        }
    }

    private func paintAccentSelection() {
        guard let popup = accentPopup else { return }
        for (index, item) in popup.arrangedSubviews.enumerated() {
            guard let label = item as? UILabel else { continue }
            label.backgroundColor = index == accentSelection ? Self.functionBackground : .clear
            label.textColor = index == accentSelection ? Self.functionForeground : .label
        }
    }

    /// One character boundary per 12 points keeps an emoji or combined glyph intact.
    static func cursorAfterSpaceDrag(start: Int, deltaX: CGFloat, count: Int) -> Int {
        min(max(0, start + Int(deltaX / 12)), count)
    }

    static func characterCursor(in text: String, utf16Offset: Int) -> Int {
        var offset = 0
        var cursor = 0
        for character in text {
            let end = offset + String(character).utf16.count
            if utf16Offset < end { break }
            cursor += 1
            offset = end
        }
        return cursor
    }

    @objc private func holdSpace(_ recognizer: UILongPressGestureRecognizer) {
        switch recognizer.state {
        case .began:
            guard surface == .keys, editable() else { return }
            spaceDragOrigin = recognizer.location(in: view)
            spaceDragCursor = draftCursor
            let offset = String(draft.prefix(draftCursor)).utf16.count
            if let position = draftView.position(from: draftView.beginningOfDocument, offset: offset) {
                let caret = draftView.caretRect(for: position)
                spaceDragCaretOrigin = CGPoint(x: caret.midX, y: caret.midY)
            }
            recognizer.view?.backgroundColor = .systemFill
            hapticKey()
        case .changed:
            #if LAYERGRAM_KEYBOARD_TRACE
            let startedAt = CACurrentMediaTime()
            defer { traceSlow("cursorDrag", since: startedAt) }
            #endif
            guard let origin = spaceDragOrigin, editable() else { return }
            let point = recognizer.location(in: view)
            let deltaX = point.x - origin.x
            let deltaY = point.y - origin.y
            var next = Self.cursorAfterSpaceDrag(
                start: spaceDragCursor, deltaX: deltaX, count: draft.count
            )
            if abs(deltaY) > 8, let caret = spaceDragCaretOrigin,
               let position = draftView.closestPosition(to: CGPoint(
                   x: caret.x + deltaX, y: caret.y + deltaY
               )) {
                next = Self.characterCursor(
                    in: draft,
                    utf16Offset: draftView.offset(from: draftView.beginningOfDocument, to: position)
                )
            }
            if next != draftCursor {
                draftCursor = next
                updateDraftCaret()
                hapticKey()
            }
        case .ended, .cancelled, .failed:
            spaceDragOrigin = nil
            spaceDragCaretOrigin = nil
            recognizer.view?.backgroundColor = .secondarySystemFill
        default: break
        }
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
            if deferTouchForBiometricResume() { return }
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
        case .emoji:
            tapEmojiPicker()
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

    @objc private func tapContextualAction() {
        if draft.isEmpty {
            pasteAndDecode()
        } else {
            receivePrimaryTap()
        }
    }

    @objc private func tapClearDraft() {
        guard surface == .keys else { return }
        draft = ""
        draftCursor = 0
        render()
    }

    @objc private func tapContactSearch() {
        guard surface == .contacts, editable() else { return }
        traceLifecycle("contactSearchTapped")
        contactSearchActive = true
        render()
        traceLifecycle("contactSearchVisible")
    }

    @objc private func tapEmojiPicker() {
        guard surface == .keys, editable() else { return }
        emojiPickerVisible.toggle()
        render()
    }

    @objc private func changeEmojiCategory() {
        guard surface == .keys, editable() else { return }
        hapticButton()
        emojiCategoryIndex = min(max(emojiCategories.selectedSegmentIndex, 0),
                                 Self.emojiCatalog.count - 1)
        emojiGrid.reloadData()
        emojiGrid.setContentOffset(.zero, animated: false)
    }

    @objc private func tapEmojiDelete() {
        guard surface == .keys, emojiPickerVisible else { return }
        backspace()
    }

    @objc private func tapClearContactSearch() {
        guard surface == .contacts, editable() else { return }
        contactQuery = ""
        contactSearchActive = true
        renderContactSearch()
    }

    @objc private func tapDoneSearch() {
        guard surface == .contacts, editable() else { return }
        contactSearchActive = false
        render()
    }

    @objc private func tapDraft(_ recognizer: UITapGestureRecognizer) {
        guard surface == .keys, editable() else { return }
        hapticButton()
        let point = recognizer.location(in: draftView)
        guard let position = draftView.closestPosition(to: point) else { return }
        let utf16Offset = draftView.offset(from: draftView.beginningOfDocument, to: position)
        draftCursor = Self.characterCursor(in: draft, utf16Offset: utf16Offset)
        updateDraftCaret()
    }

    @objc private func tapBackToKeys() {
        guard policy.liveControl(snapshot()) else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        surface = .keys
        contactSearchActive = false
        contactQuery = ""
        emojiPickerVisible = false
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
        draftCursor = 0
        policy.clearSelection()
        emojiPickerVisible = false
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
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        traceLifecycle(endingEditorForRebind ? "policyClearedForRebind" : "policyClearedTerminal")
        #endif
        #if LAYERGRAM_AUTONOMOUS_KEYBOARD
        // A successful export and a host editor callback both rebind within
        // the same live custody grant. Closing it here would strand the next
        // message behind an already-consumed app bootstrap window.
        clearSensitiveValues(preservingAutonomousRuntime: endingEditorForRebind)
        #else
        clearSensitiveValues()
        #endif
        render()
    }
}

// MARK: - Contacts list

extension KeyboardViewController: UITableViewDataSource, UITableViewDelegate {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        policy.liveControl(snapshot()) ? visibleContacts.count : 0
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "contact", for: indexPath)
        let candidates = visibleContacts
        guard policy.liveControl(snapshot()), indexPath.row < candidates.count else {
            // A reusable cell is always blanked before it can be reused.
            cell.imageView?.image = nil
            cell.contentConfiguration = Self.contactCellContent(nil, language: Copy.language(locale))
            return cell
        }
        cell.imageView?.image = nil
        cell.contentConfiguration = Self.contactCellContent(
            candidates[indexPath.row], language: Copy.language(locale))
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: false)
        hapticButton()
        let candidates = visibleContacts
        guard policy.liveControl(snapshot()), indexPath.row < candidates.count else {
            invalidateEditor(status: Copy.string(.sessionExpired, in: locale))
            return
        }
        // An explicit tap opens confirmation; a decoded contact is never selected
        // automatically.
        selectContact(candidates[indexPath.row])
    }
}

// MARK: - Local emoji picker

extension KeyboardViewController: UICollectionViewDataSource, UICollectionViewDelegateFlowLayout {
    func collectionView(_ collectionView: UICollectionView,
                        numberOfItemsInSection section: Int) -> Int {
        guard collectionView === emojiGrid, surface == .keys,
              emojiPickerVisible else { return 0 }
        return Self.emojiCatalog[emojiCategoryIndex].count
    }

    func collectionView(_ collectionView: UICollectionView,
                        cellForItemAt indexPath: IndexPath) -> UICollectionViewCell {
        let cell = collectionView.dequeueReusableCell(withReuseIdentifier: "emoji", for: indexPath)
        guard let emojiCell = cell as? KeyboardEmojiCell,
              indexPath.item < Self.emojiCatalog[emojiCategoryIndex].count else { return cell }
        emojiCell.label.text = Self.emojiCatalog[emojiCategoryIndex][indexPath.item]
        return emojiCell
    }

    func collectionView(_ collectionView: UICollectionView,
                        didSelectItemAt indexPath: IndexPath) {
        guard collectionView === emojiGrid, surface == .keys,
              emojiPickerVisible, editable(),
              indexPath.item < Self.emojiCatalog[emojiCategoryIndex].count else { return }
        hapticKey()
        insert(Self.emojiCatalog[emojiCategoryIndex][indexPath.item])
    }

    func collectionView(_ collectionView: UICollectionView,
                        layout collectionViewLayout: UICollectionViewLayout,
                        sizeForItemAt indexPath: IndexPath) -> CGSize {
        let columns = max(6, Int(collectionView.bounds.width / 43))
        let side = max(36, floor(collectionView.bounds.width / CGFloat(columns)) - 3)
        return CGSize(width: side, height: 40)
    }
}
