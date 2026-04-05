import 'dart:async';

import 'package:dotted_border/dotted_border.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_linkify/flutter_linkify.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../core/crypto/models.dart';
import '../../core/crypto/stego_encoder.dart';
import '../../core/providers.dart';
import '../../core/storage/messages_repository.dart';
import '../../l10n/app_strings.dart';
import '../../ui/passphrase_button.dart';
import '../../utils/sharing.dart';
import 'home_controller.dart';

class ChatView extends ConsumerStatefulWidget {
  const ChatView({
    super.key,
    required this.contact,
    this.initialCover,
    this.initialSecret,
    this.initialExpiry,
    this.initialDeleteAfterRead,
    this.initialLinkMode,
    this.embedded = false,
    this.initialIsSearching = false,
    this.initialSearchIndex,
    this.initialGlobalSearchQuery,
    this.initialGlobalSearchMessageId,
  });

  final RemoteIdentity contact;
  final String? initialCover;
  final String? initialSecret;
  final int? initialExpiry;
  final bool? initialDeleteAfterRead;
  final bool? initialLinkMode;
  final bool embedded;
  final bool? initialIsSearching;
  final int? initialSearchIndex;
  final String? initialGlobalSearchQuery;
  final String? initialGlobalSearchMessageId;

  @override
  ConsumerState<ChatView> createState() => ChatViewState();
}

enum _ExpiryUnit { minutes, hours, days, weeks, months }

class _ExpiryOption {
  final int? minutes;
  final int? value;
  final _ExpiryUnit? unit;
  const _ExpiryOption({required this.minutes, this.value, this.unit});
}

class ChatViewState extends ConsumerState<ChatView> {
  late final MessagesRepository _messagesRepo;
  static final RegExp _linkCandidatePattern = RegExp(
    r'(layergram://|https?://|www\.|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})',
    caseSensitive: false,
  );

  final _coverCtrl = TextEditingController();
  final _secretCtrl = TextEditingController();
  final _coverFocusNode = FocusNode();
  final _secretFocusNode = FocusNode();
  int? _selectedExpiryMinutes;
  final _revealedIds = <String>{};
  final Map<String, Timer> _revealTimers = {};
  final _composerKey = GlobalKey();

  bool _isSearching = false;
  int _searchIndex = 0;
  final _searchCtrl = TextEditingController();
  late final _searchFocusNode = FocusNode(
    onKeyEvent: (node, event) {
      if (event is KeyDownEvent || event is KeyRepeatEvent) {
        if (event.logicalKey == LogicalKeyboardKey.arrowUp) {
          _navigateSearch(1); // older match
          return KeyEventResult.handled;
        }
        if (event.logicalKey == LogicalKeyboardKey.arrowDown) {
          _navigateSearch(-1); // newer match
          return KeyEventResult.handled;
        }
        if (event.logicalKey == LogicalKeyboardKey.escape) {
          _stopSearch();
          return KeyEventResult.handled;
        }
      }
      return KeyEventResult.ignored;
    },
  );
  String _searchQuery = '';
  List<String> _searchMatchIds = []; // message IDs matching search, newest first
  final Map<String, String> _decryptedCache = {}; // messageId -> decrypted text
  final Map<String, Future<String?>> _decryptFutures = {}; // messageId -> cached Future
  Map<String, GlobalKey> _searchResultKeys = {}; // messageId -> GlobalKey for scrolling
  int _searchGeneration = 0;
  bool _searchInProgress = false;
  bool _needsSearchOnDataLoad = false;
  String? _pendingSearchMessageId;
  List<MessageRecord> _cachedThread = const [];

  Map<String, dynamic> get composerState => {
        'cover': _coverCtrl.text,
        'secret': _secretCtrl.text,
        'expiry': _selectedExpiryMinutes,
        'deleteAfterRead': _deleteAfterRead,
        'linkMode': _linkMode,
        'isSearching': _isSearching,
        'searchQuery': _searchQuery,
        'searchIndex': _searchIndex,
        'searchMessageId': (_isSearching &&
                _searchMatchIds.isNotEmpty &&
                _searchIndex < _searchMatchIds.length)
            ? _searchMatchIds[_searchIndex]
            : null,
      };

  void jumpToGlobalSearchResult(String query, String messageId) {
    setState(() {
      _isSearching = true;
      _searchCtrl.text = query;
      _searchQuery = query.toLowerCase();
      _searchIndex = 0;
      _pendingSearchMessageId = messageId;
    });
    _runSearch();
  }

  final _scrollController = ScrollController();
  int _lastMessageCount = 0;
  int _lastNewestTimestamp = 0;
  double _composerHeight = 240.0;
  bool _deleteAfterRead = false;
  bool _linkMode = false;
  String _encryptedOutput = '';
  bool _dirtySinceEncode = true;
  bool _sending = false;
  bool _handoffScheduled = false;
  bool _decryptionPrimed = false;
  Timer? _decryptionPrimeTimer;
  bool _backgroundHoldActive = false;

  int get _estimatedPayloadBytes {
    return StegoEncoder.estimatedEncryptedPayloadBytes(_secretCtrl.text);
  }

  int? get _coverLengthLimit {
    return ref.read(coverMessageLengthLimitProvider);
  }

  int _estimatedPayloadBytesForSecret(String secretText) {
    return StegoEncoder.estimatedEncryptedPayloadBytes(secretText);
  }

  int _minimumStegoCharacterCount({
    String? coverText,
    String? secretText,
  }) {
    final effectiveCover = coverText ?? _coverCtrl.text;
    final effectiveSecret = secretText ?? _secretCtrl.text;
    if (effectiveSecret.trim().isEmpty) {
      return StegoEncoder.visibleCharacterCount(effectiveCover);
    }
    return StegoEncoder.minimumEncodedLengthForBytes(
      effectiveCover,
      _estimatedPayloadBytesForSecret(effectiveSecret),
    );
  }

  bool _fitsWithinCoverLengthLimit({
    String? coverText,
    String? secretText,
  }) {
    if (_linkMode) return true;
    final limit = _coverLengthLimit;
    if (limit == null) return true;
    return _minimumStegoCharacterCount(
          coverText: coverText,
          secretText: secretText,
        ) <=
        limit;
  }

  TextEditingValue _limitStegoFieldEdit(
    TextEditingValue oldValue,
    TextEditingValue newValue, {
    required bool isCoverField,
  }) {
    if (_linkMode || _coverLengthLimit == null || newValue.text == oldValue.text) {
      return newValue;
    }

    final currentCover = isCoverField ? oldValue.text : _coverCtrl.text;
    final currentSecret = isCoverField ? _secretCtrl.text : oldValue.text;
    final nextCover = isCoverField ? newValue.text : _coverCtrl.text;
    final nextSecret = isCoverField ? _secretCtrl.text : newValue.text;

    if (_fitsWithinCoverLengthLimit(
      coverText: nextCover,
      secretText: nextSecret,
    )) {
      return newValue;
    }

    final currentFits = _fitsWithinCoverLengthLimit(
      coverText: currentCover,
      secretText: currentSecret,
    );
    final currentLength = _minimumStegoCharacterCount(
      coverText: currentCover,
      secretText: currentSecret,
    );
    final nextLength = _minimumStegoCharacterCount(
      coverText: nextCover,
      secretText: nextSecret,
    );

    if (!currentFits && nextLength < currentLength) {
      return newValue;
    }

    return oldValue;
  }

  List<TextInputFormatter> _coverLimitInputFormatters({
    required bool isCoverField,
  }) {
    if (_linkMode || _coverLengthLimit == null) return const [];
    return [
      TextInputFormatter.withFunction(
        (oldValue, newValue) => _limitStegoFieldEdit(
          oldValue,
          newValue,
          isCoverField: isCoverField,
        ),
      ),
    ];
  }

  String? _coverLimitCounterText(int? coverLengthLimit) {
    if (_linkMode || coverLengthLimit == null) return null;
    return '${_minimumStegoCharacterCount()}/$coverLengthLimit';
  }

  void _dismissMessageInputFocus(PointerDownEvent _) {
    FocusManager.instance.primaryFocus?.unfocus();
  }

  void _acquireBackgroundHold() {
    if (_backgroundHoldActive) {
      return;
    }
    final holdCount = ref.read(backgroundAnimationHoldCountProvider);
    ref.read(backgroundAnimationHoldCountProvider.notifier).state = holdCount + 1;
    _backgroundHoldActive = true;
  }

  void _releaseBackgroundHold() {
    if (!_backgroundHoldActive) {
      return;
    }
    final notifier = ref.read(backgroundAnimationHoldCountProvider.notifier);
    final next = notifier.state > 0 ? notifier.state - 1 : 0;
    notifier.state = next;
    _backgroundHoldActive = false;
  }

  static const Map<String, Map<String, String>> _expiryLexicon = {
    'en': {
      'never': 'Never',
      'min': 'min',
      'hour': 'hour',
      'day': 'day',
      'week': 'week',
      'month': 'month'
    },
    'it': {
      'never': 'Mai',
      'min': 'min',
      'hour': 'ora',
      'day': 'giorno',
      'week': 'settimana',
      'month': 'mese'
    },
    'es': {
      'never': 'Nunca',
      'min': 'min',
      'hour': 'hora',
      'day': 'día',
      'week': 'semana',
      'month': 'mes'
    },
    'pt': {
      'never': 'Nunca',
      'min': 'min',
      'hour': 'hora',
      'day': 'dia',
      'week': 'semana',
      'month': 'mês'
    },
    'pt_PT': {
      'never': 'Nunca',
      'min': 'min',
      'hour': 'hora',
      'day': 'dia',
      'week': 'semana',
      'month': 'mês'
    },
    'ru': {
      'never': 'Никогда',
      'min': 'мин',
      'hour': 'час',
      'day': 'день',
      'week': 'неделя',
      'month': 'месяц'
    },
    'id': {
      'never': 'Tidak pernah',
      'min': 'mnt',
      'hour': 'jam',
      'day': 'hari',
      'week': 'minggu',
      'month': 'bulan'
    },
    'ar': {
      'never': 'أبداً',
      'min': 'دقيقة',
      'hour': 'ساعة',
      'day': 'يوم',
      'week': 'أسبوع',
      'month': 'شهر'
    },
    'fr': {
      'never': 'Jamais',
      'min': 'min',
      'hour': 'heure',
      'day': 'jour',
      'week': 'semaine',
      'month': 'mois'
    },
    'de': {
      'never': 'Nie',
      'min': 'Min.',
      'hour': 'Stunde',
      'day': 'Tag',
      'week': 'Woche',
      'month': 'Monat'
    },
    'hi': {
      'never': 'कभी नहीं',
      'min': 'मिन',
      'hour': 'घंटा',
      'day': 'दिन',
      'week': 'सप्ताह',
      'month': 'महीना'
    },
    'nl': {
      'never': 'Nooit',
      'min': 'min',
      'hour': 'uur',
      'day': 'dag',
      'week': 'week',
      'month': 'maand'
    },
    'fa': {
      'never': 'هرگز',
      'min': 'دقیقه',
      'hour': 'ساعت',
      'day': 'روز',
      'week': 'هفته',
      'month': 'ماه'
    },
    'ro': {
      'never': 'Niciodată',
      'min': 'min',
      'hour': 'oră',
      'day': 'zi',
      'week': 'săptămână',
      'month': 'lună'
    },
    'pl': {
      'never': 'Nigdy',
      'min': 'min',
      'hour': 'godz',
      'day': 'dzień',
      'week': 'tydzień',
      'month': 'miesiąc'
    },
    'zh': {
      'never': '永不',
      'min': '分钟',
      'hour': '小时',
      'day': '天',
      'week': '周',
      'month': '月'
    },
    'tr': {
      'never': 'Asla',
      'min': 'dk',
      'hour': 'saat',
      'day': 'gün',
      'week': 'hafta',
      'month': 'ay'
    },
    'ja': {
      'never': 'なし',
      'min': '分',
      'hour': '時間',
      'day': '日',
      'week': '週',
      'month': 'ヶ月'
    },
    'ko': {
      'never': '없음',
      'min': '분',
      'hour': '시간',
      'day': '일',
      'week': '주',
      'month': '개월'
    },
    'vi': {
      'never': 'Không bao giờ',
      'min': 'phút',
      'hour': 'giờ',
      'day': 'ngày',
      'week': 'tuần',
      'month': 'tháng'
    },
    'th': {
      'never': 'ไม่หมดอายุ',
      'min': 'นาที',
      'hour': 'ชั่วโมง',
      'day': 'วัน',
      'week': 'สัปดาห์',
      'month': 'เดือน'
    },
    'el': {
      'never': 'Ποτέ',
      'min': 'λεπτό',
      'hour': 'ώρα',
      'day': 'ημέρα',
      'week': 'εβδομάδα',
      'month': 'μήνας'
    },
    'bn': {
      'never': 'কখনও নয়',
      'min': 'মিনিট',
      'hour': 'ঘন্টা',
      'day': 'দিন',
      'week': 'সপ্তাহ',
      'month': 'মাস'
    },
    'mr': {
      'never': 'कधीही नाही',
      'min': 'मिनिटे',
      'hour': 'तास',
      'day': 'दिवस',
      'week': 'आठवडा',
      'month': 'महिना'
    },
    'ur': {
      'never': 'کبھی نہیں',
      'min': 'منٹ',
      'hour': 'گھنٹہ',
      'day': 'دن',
      'week': 'ہفتہ',
      'month': 'مہینہ'
    },
    'fi': {
      'never': 'Ei koskaan',
      'min': 'min',
      'hour': 'tunti',
      'day': 'päivä',
      'week': 'viikko',
      'month': 'kuukausi'
    },
    'no': {
      'never': 'Aldri',
      'min': 'min',
      'hour': 'time',
      'day': 'dag',
      'week': 'uke',
      'month': 'måned'
    },
    'sv': {
      'never': 'Aldrig',
      'min': 'min',
      'hour': 'timme',
      'day': 'dag',
      'week': 'vecka',
      'month': 'månad'
    },
    'uk': {
      'never': 'Ніколи',
      'min': 'хв',
      'hour': 'год',
      'day': 'день',
      'week': 'тиждень',
      'month': 'місяць'
    },
    'sq': {
      'never': 'Asnjëherë',
      'min': 'min',
      'hour': 'orë',
      'day': 'ditë',
      'week': 'javë',
      'month': 'muaj'
    },
    'ca': {
      'never': 'Mai',
      'min': 'min',
      'hour': 'hora',
      'day': 'dia',
      'week': 'setmana',
      'month': 'mes'
    },
    'sw': {
      'never': 'Kamwe',
      'min': 'dakika',
      'hour': 'saa',
      'day': 'siku',
      'week': 'wiki',
      'month': 'mwezi'
    },
    'ha': {
      'never': 'Babu',
      'min': 'minti',
      'hour': 'awa',
      'day': 'rana',
      'week': 'mako',
      'month': 'wata'
    },
    'tl': {
      'never': 'Kailanman',
      'min': 'min',
      'hour': 'oras',
      'day': 'araw',
      'week': 'linggo',
      'month': 'buwan'
    },
    'ms': {
      'never': 'Tidak pernah',
      'min': 'min',
      'hour': 'jam',
      'day': 'hari',
      'week': 'minggu',
      'month': 'bulan'
    },
    'ta': {
      'never': 'எப்போதுமில்லை',
      'min': 'நிமி',
      'hour': 'மணி',
      'day': 'நாள்',
      'week': 'வாரம்',
      'month': 'மாதம்'
    },
    'te': {
      'never': 'ఎప్పుడూ కాదు',
      'min': 'నిమి',
      'hour': 'గం',
      'day': 'రోజు',
      'week': 'వారం',
      'month': 'నెల'
    },
    'gu': {
      'never': 'ક્યારેય નહીં',
      'min': 'મિનિટ',
      'hour': 'કલાક',
      'day': 'દિવસ',
      'week': 'અઠવાડિયું',
      'month': 'મહિનો'
    },
    'kn': {
      'never': 'ಎಂದಿಗೂ ಇಲ್ಲ',
      'min': 'ನಿಮಿಷ',
      'hour': 'ಗಂಟೆ',
      'day': 'ದಿನ',
      'week': 'ವಾರ',
      'month': 'ತಿಂಗಳು'
    },
    'pa': {
      'never': 'ਕਦੇ ਨਹੀਂ',
      'min': 'ਮਿੰਟ',
      'hour': 'ਘੰਟਾ',
      'day': 'ਦਿਨ',
      'week': 'ਹਫ਼ਤਾ',
      'month': 'ਮਹੀਨਾ'
    },
    'am': {
      'never': 'በፍጹም አይጠናቀቅም',
      'min': 'ደቂቃ',
      'hour': 'ሰዓት',
      'day': 'ቀን',
      'week': 'ሳምንት',
      'month': 'ወር'
    },
    'yo': {
      'never': 'Rárá',
      'min': 'iseju',
      'hour': 'wakati',
      'day': 'ọjọ́',
      'week': 'ọ̀sẹ̀',
      'month': 'osu'
    },
  };

  static const List<_ExpiryOption> _expiryOptions = [
    _ExpiryOption(minutes: null), // never
    _ExpiryOption(minutes: 5, value: 5, unit: _ExpiryUnit.minutes),
    _ExpiryOption(minutes: 10, value: 10, unit: _ExpiryUnit.minutes),
    _ExpiryOption(minutes: 15, value: 15, unit: _ExpiryUnit.minutes),
    _ExpiryOption(minutes: 45, value: 45, unit: _ExpiryUnit.minutes),
    _ExpiryOption(minutes: 60, value: 1, unit: _ExpiryUnit.hours),
    _ExpiryOption(minutes: 120, value: 2, unit: _ExpiryUnit.hours),
    _ExpiryOption(minutes: 180, value: 3, unit: _ExpiryUnit.hours),
    _ExpiryOption(minutes: 300, value: 5, unit: _ExpiryUnit.hours),
    _ExpiryOption(minutes: 720, value: 12, unit: _ExpiryUnit.hours),
    _ExpiryOption(minutes: 1440, value: 1, unit: _ExpiryUnit.days),
    _ExpiryOption(minutes: 2880, value: 2, unit: _ExpiryUnit.days),
    _ExpiryOption(minutes: 10080, value: 1, unit: _ExpiryUnit.weeks),
    _ExpiryOption(minutes: 43200, value: 1, unit: _ExpiryUnit.months),
  ];

  int _messageLimit = 50;

  @override
  void initState() {
    super.initState();
    _messagesRepo = ref.read(messagesRepositoryProvider);
    _decryptionPrimed = widget.embedded;
    if (!widget.embedded) {
      _acquireBackgroundHold();
    }
    _coverCtrl.addListener(_onFieldChanged);
    _secretCtrl.addListener(_onFieldChanged);
    _scrollController.addListener(_onScroll);
    if (widget.initialCover != null) _coverCtrl.text = widget.initialCover!;
    if (widget.initialSecret != null) _secretCtrl.text = widget.initialSecret!;
    if (widget.initialExpiry != null) {
      _selectedExpiryMinutes = widget.initialExpiry;
    }
    if (widget.initialDeleteAfterRead != null) {
      _deleteAfterRead = widget.initialDeleteAfterRead!;
    }
    if (widget.initialLinkMode != null) {
      _linkMode = widget.initialLinkMode!;
    }
    _loadPersistedChatSettings();
    // Handle initial search from global search or handoff
    if (widget.initialIsSearching == true) {
      _isSearching = true;
    }
    if (widget.initialGlobalSearchQuery != null &&
        widget.initialGlobalSearchQuery!.isNotEmpty) {
      _isSearching = true;
      _searchCtrl.text = widget.initialGlobalSearchQuery!;
      _searchQuery = widget.initialGlobalSearchQuery!.toLowerCase();
      _pendingSearchMessageId = widget.initialGlobalSearchMessageId;
      _needsSearchOnDataLoad = true;
    }
    // Cleanup any read+deleteAfterRead messages for this contact when entering the chat.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) {
        return;
      }
      unawaited(
        ref.read(homeControllerProvider).primeDisplayKey(contact: widget.contact),
      );
      if (!_decryptionPrimed) {
        _decryptionPrimeTimer = Timer(const Duration(milliseconds: 120), () {
          if (!mounted) {
            return;
          }
          setState(() {
            _decryptionPrimed = true;
          });
          _releaseBackgroundHold();
        });
      } else {
        _releaseBackgroundHold();
      }
      _messagesRepo.purgeReadDeleteAfterReadFor(widget.contact.identityId);
    });
  }

  void _onScroll() {
    if (_scrollController.position.pixels >=
        _scrollController.position.maxScrollExtent - 200) {
      if (_lastMessageCount >= _messageLimit) {
        setState(() {
          _messageLimit += 50;
        });
      }
    }
  }

  void _saveSettings() {
    final metaRepo = ref.read(chatMetaRepositoryProvider);
    metaRepo.saveChatSettings(
      chatId: widget.contact.identityId,
      linkMode: _linkMode,
      expiryMinutes: _selectedExpiryMinutes,
      deleteAfterRead: _deleteAfterRead,
    );
  }

  Future<void> _loadPersistedChatSettings() async {
    final metaRepo = ref.read(chatMetaRepositoryProvider);
    final settings =
        await metaRepo.getChatSettings(chatId: widget.contact.identityId);
    if (!mounted || settings == null) return;
    setState(() {
      _linkMode = settings['linkMode'] as bool? ?? _linkMode;
      _selectedExpiryMinutes =
          settings['expiryMinutes'] as int? ?? _selectedExpiryMinutes;
      _deleteAfterRead =
          settings['deleteAfterRead'] as bool? ?? _deleteAfterRead;
    });
  }

  void _onFieldChanged() {
    setState(() {
      _dirtySinceEncode = true;
    });
  }

  Future<String?> _getDecryptFuture(MessageRecord m) {
    return _decryptFutures.putIfAbsent(m.id, () async {
      final result = await ref.read(homeControllerProvider).decryptForDisplay(
        message: m,
        contact: widget.contact,
      );
      if (result != null) {
        _decryptedCache[m.id] = result;
      }
      return result;
    });
  }

  bool _shouldLinkify(String text) {
    return _linkCandidatePattern.hasMatch(text);
  }

  void _startSearch() {
    setState(() {
      _isSearching = true;
    });
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _searchFocusNode.requestFocus();
    });
  }

  void _stopSearch() {
    setState(() {
      _isSearching = false;
      _searchQuery = '';
      _searchCtrl.clear();
      _searchMatchIds = [];
      _searchResultKeys = {};
      _searchIndex = 0;
      _searchInProgress = false;
      _pendingSearchMessageId = null;
    });
  }

  Future<void> _runSearch() async {
    final query = _searchQuery;
    final generation = ++_searchGeneration;

    if (query.isEmpty) {
      setState(() {
        _searchMatchIds = [];
        _searchResultKeys = {};
        _searchIndex = 0;
        _searchInProgress = false;
      });
      return;
    }

    setState(() => _searchInProgress = true);

    final thread = _cachedThread;
    final controller = ref.read(homeControllerProvider);
    final matches = <String>[];

    for (final m in thread) {
      if (!mounted || generation != _searchGeneration) return;

      // Check cache first
      String? text = _decryptedCache[m.id];
      if (text == null) {
        text = await controller.decryptForDisplay(
          message: m,
          contact: widget.contact,
        );
        if (text != null) {
          _decryptedCache[m.id] = text;
        }
      }

      if (text != null && text.toLowerCase().contains(query)) {
        matches.add(m.id);
      }
    }

    if (!mounted || generation != _searchGeneration) return;

    final keys = <String, GlobalKey>{};
    for (final id in matches) {
      keys[id] = _searchResultKeys[id] ?? GlobalKey();
    }

    // Reverse so newest match is index 0 (displayed as 1/N)
    final reversed = matches.reversed.toList();

    setState(() {
      _searchMatchIds = reversed;
      _searchResultKeys = keys;
      _searchInProgress = false;
    });

    // If there's a pending message ID from global search, jump to it
    final pendingId = _pendingSearchMessageId;
    if (pendingId != null) {
      _pendingSearchMessageId = null;
      final idx = reversed.indexOf(pendingId);
      if (idx >= 0) {
        setState(() => _searchIndex = idx);
        _scrollToSearchResult();
      } else if (reversed.isNotEmpty) {
        setState(() => _searchIndex = 0);
        _scrollToSearchResult();
      }
    } else if (reversed.isNotEmpty) {
      // Default to index 0 (newest match)
      setState(() => _searchIndex = 0);
      _scrollToSearchResult();
    }
  }

  void _navigateSearch(int delta) {
    if (_searchMatchIds.isEmpty) return;
    final newIndex = (_searchIndex + delta).clamp(0, _searchMatchIds.length - 1);
    if (newIndex == _searchIndex) return;
    setState(() => _searchIndex = newIndex);
    _scrollToSearchResult();
  }

  void _scrollToSearchResult() {
    if (_searchMatchIds.isEmpty) return;
    final id = _searchMatchIds[_searchIndex];
    final key = _searchResultKeys[id];

    // Find the message index in the chronological thread.
    final threadIdx = _cachedThread.indexWhere((m) => m.id == id);
    if (threadIdx < 0) return;

    // In the reverse ListView, item 0 = newest (thread.last).
    final listIdx = _cachedThread.length - 1 - threadIdx;

    // Jump to an approximate position so the target gets rendered.
    if (_scrollController.hasClients && _cachedThread.length > 1) {
      final maxExtent = _scrollController.position.maxScrollExtent;
      final fraction = listIdx / (_cachedThread.length - 1);
      _scrollController.jumpTo((fraction * maxExtent).clamp(0.0, maxExtent));
    }

    // Fine-tune with ensureVisible once the widget is built, retrying a few frames.
    void tryEnsureVisible([int retries = 5]) {
      if (!mounted) return;
      if (key?.currentContext != null) {
        Scrollable.ensureVisible(
          key!.currentContext!,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeInOut,
          alignment: 0.5,
        );
      } else if (retries > 0) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          tryEnsureVisible(retries - 1);
        });
      }
    }
    WidgetsBinding.instance.addPostFrameCallback((_) => tryEnsureVisible());
  }

  void _showMessageContextMenu(
      BuildContext menuContext, MessageRecord message, String displayText,
      {Offset? position}) {
    final t = AppStrings.t;

    final RenderBox overlay =
        Overlay.of(context).context.findRenderObject() as RenderBox;
    final menuPosition = position != null
        ? RelativeRect.fromRect(
            Rect.fromLTWH(position.dx, position.dy, 0, 0),
            Offset.zero & overlay.size,
          )
        : const RelativeRect.fromLTRB(100, 100, 100, 100);

    final hasCover = message.rawSource != null && message.rawSource!.isNotEmpty;

    showMenu(
      context: context,
      position: menuPosition,
      items: [
        if (hasCover)
          PopupMenuItem(
            value: 'reveal',
            child: Row(
              children: [
                const Icon(Icons.visibility_outlined, size: 20),
                const SizedBox(width: 12),
                Text(t(context, 'revealCover')),
              ],
            ),
          ),
        PopupMenuItem(
          value: 'copy',
          child: Row(
            children: [
              const Icon(Icons.copy_outlined, size: 20),
              const SizedBox(width: 12),
              Text(t(context, 'copy')),
            ],
          ),
        ),
        PopupMenuItem(
          value: 'share',
          child: Row(
            children: [
              const Icon(Icons.ios_share_outlined, size: 20),
              const SizedBox(width: 12),
              Text(t(context, 'share')),
            ],
          ),
        ),
        PopupMenuItem(
          value: 'delete',
          child: Row(
            children: [
              const Icon(Icons.delete_outline, size: 20),
              const SizedBox(width: 12),
              Text(t(context, 'delete')),
            ],
          ),
        ),
      ],
    ).then((value) async {
      if (value == null) return;

      switch (value) {
        case 'reveal':
          setState(() {
            _revealedIds.add(message.id);
            _revealTimers[message.id]?.cancel();
            _revealTimers[message.id] = Timer(const Duration(seconds: 15), () {
              if (mounted) {
                setState(() {
                  _revealedIds.remove(message.id);
                  _revealTimers.remove(message.id);
                });
              }
            });
          });
          break;
        case 'copy':
          await ref.read(clipboardServiceProvider).writeText(displayText);
          if (!menuContext.mounted) return;
          ScaffoldMessenger.of(menuContext).showSnackBar(
            SnackBar(content: Text(t(menuContext, 'messageCopiedClipboard'))),
          );
          break;
        case 'share':
          if (!mounted) return;
          await shareTextExternally(context, displayText);
          break;
        case 'delete':
          if (!menuContext.mounted) return;
          final confirmed = await showDialog<bool>(
            context: menuContext,
            builder: (context) => AlertDialog(
              title: Text(t(context, 'delete')),
              content: Text(t(context, 'deleteChatConfirm')), // Using existing key for confirmation
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(false),
                  child: Text(t(context, 'cancel')),
                ),
                TextButton(
                  onPressed: () => Navigator.of(context).pop(true),
                  child: Text(t(context, 'delete')),
                ),
              ],
            ),
          );
          if (confirmed == true) {
            await ref.read(messagesRepositoryProvider).delete(message.id);
          }
          break;
      }
    });
  }

  String _expiryLabel(BuildContext context, _ExpiryOption opt) {
    final locale = Localizations.localeOf(context);
    final lang = locale.languageCode;
    final country = locale.countryCode;
    final lex = _expiryLexicon['${lang}_${country ?? ''}'] ??
        _expiryLexicon[lang] ??
        _expiryLexicon['en']!;
    if (opt.minutes == null) return lex['never'] ?? 'Never';
    final value = opt.value ?? opt.minutes!;
    final unit = opt.unit ?? _ExpiryUnit.minutes;
    switch (unit) {
      case _ExpiryUnit.minutes:
        return '$value ${lex['min'] ?? 'min'}';
      case _ExpiryUnit.hours:
        return '$value ${lex['hour'] ?? 'hour'}';
      case _ExpiryUnit.days:
        return '$value ${lex['day'] ?? 'day'}';
      case _ExpiryUnit.weeks:
        return '$value ${lex['week'] ?? 'week'}';
      case _ExpiryUnit.months:
        return '$value ${lex['month'] ?? 'month'}';
    }
  }

  void _scrollToBottom() {
    // With reverse: true, offset 0 is the bottom (latest message). Jump there after frame.
    WidgetsBinding.instance.endOfFrame.then((_) {
      if (!mounted) {
        return;
      }
      if (_scrollController.hasClients) {
        try {
          _scrollController.jumpTo(0);
        } catch (_) {
          _scrollController.animateTo(
            0,
            duration: const Duration(milliseconds: 120),
            curve: Curves.easeOut,
          );
        }
      }
    });
  }

  bool get _coverTooShort {
    if (_linkMode || _secretCtrl.text.trim().isEmpty) return false;
    return !StegoEncoder.canEmbedBytes(_coverCtrl.text, _estimatedPayloadBytes);
  }

  int get _coverMissingCount {
    if (_linkMode || _secretCtrl.text.trim().isEmpty) {
      return 0;
    }
    return StegoEncoder.missingCoverCapacityForBytes(
      _coverCtrl.text,
      _estimatedPayloadBytes,
    );
  }

  bool get _coverLengthLimitExceeded {
    if (_linkMode) return false;
    return !_fitsWithinCoverLengthLimit();
  }

  String _stripZeroWidth(String value) {
    return value.replaceAll(
      RegExp(
        '[\u200B\u200C\u200D\u200E\u200F\u2060\u2061\u2062\u2063\u2064\uFEFF]',
      ),
      '',
    );
  }

  @override
  void dispose() {
    for (final timer in _revealTimers.values) {
      timer.cancel();
    }
    _revealTimers.clear();
    _decryptionPrimeTimer?.cancel();
    _releaseBackgroundHold();
    _searchCtrl.dispose();
    _searchFocusNode.dispose();
    _coverCtrl.removeListener(_onFieldChanged);
    _secretCtrl.removeListener(_onFieldChanged);
    _coverCtrl.dispose();
    _secretCtrl.dispose();
    _coverFocusNode.dispose();
    _secretFocusNode.dispose();
    _scrollController.removeListener(_onScroll);
    // Purge messages marked deleteAfterRead that have been read in this thread.
    _messagesRepo.purgeReadDeleteAfterReadFor(widget.contact.identityId);
    _scrollController.dispose();
    super.dispose();
  }

  bool get _isInputValid {
    if (_linkMode) {
      return _secretCtrl.text.trim().isNotEmpty;
    }
    return !_coverTooShort &&
        !_coverLengthLimitExceeded &&
        _secretCtrl.text.trim().isNotEmpty &&
        _coverCtrl.text.trim().isNotEmpty;
  }

  Future<String?> _encodeAndPersist() async {
    if (!_dirtySinceEncode && _encryptedOutput.isNotEmpty) {
      return _encryptedOutput;
    }
    if (!_isInputValid) return null;
    if (_sending) return null;
    setState(() => _sending = true);
    final recipient = widget.contact;

    try {
      final expiresMinutes = _selectedExpiryMinutes;
      final expireAfter = expiresMinutes == null
          ? null
          : (DateTime.now().millisecondsSinceEpoch ~/ 1000) +
              (expiresMinutes * 60);

      final encrypted =
          await ref.read(homeControllerProvider).encryptForRecipient(
                secretText: _secretCtrl.text,
                recipient: recipient,
                expireAfter: expireAfter,
                deleteAfterRead: _deleteAfterRead,
              );

      final output = _linkMode
          ? ref.read(homeControllerProvider).buildLinkPayload(encrypted)
          : ref
              .read(stegoEncoderProvider)
              .encodeBytes(
                _coverCtrl.text,
                encrypted.toRawBytes(),
                maxTotalCharacters: _coverLengthLimit,
              );

      final controller = ref.read(homeControllerProvider);
      final keyTag = await controller.currentKeyTag();
      final storageKey = await controller.currentStorageKey();
      await ref.read(messagesRepositoryProvider).add(
            MessageRecord(
              id: DateTime.now().microsecondsSinceEpoch.toString(),
              senderId: 'me',
              recipientId: recipient.identityId,
              direction: 'outgoing',
              timestamp: DateTime.now().millisecondsSinceEpoch ~/ 1000,
              ciphertextBase64: encrypted.ciphertextBase64,
              nonceBase64: encrypted.nonceBase64,
              rawSource: output,
              expireAfter: expireAfter,
              deleteAfterRead: _deleteAfterRead,
              keyTag: keyTag,
            ),
            storageKey: storageKey,
          );

      if (!mounted) return null;
      setState(() {
        _encryptedOutput = output;
        _dirtySinceEncode = false;
      });
      _scrollToBottom();
      return output;
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  Widget _buildCompactComposer(
    BuildContext context,
    String Function(BuildContext, String) t,
    int? coverLengthLimit,
  ) {
    return SafeArea(
      top: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(8, 4, 8, 4),
        child: Card(
          key: _composerKey,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Row(
                  children: [
                    ToggleButtons(
                      constraints: const BoxConstraints(minHeight: 32, minWidth: 32),
                      isSelected: [_linkMode == false, _linkMode == true],
                      onPressed: (index) {
                        setState(() {
                          _linkMode = index == 1;
                          _encryptedOutput = '';
                          _dirtySinceEncode = true;
                        });
                        _saveSettings();
                      },
                      borderRadius: const BorderRadius.all(Radius.circular(12)),
                      children: const [
                        Padding(
                          padding: EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                          child: Icon(Icons.chat_bubble_outline, size: 18),
                        ),
                        Padding(
                          padding: EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                          child: Icon(Icons.link, size: 18),
                        ),
                      ],
                    ),
                    const SizedBox(width: 8),
                    SizedBox(
                      width: 120,
                      child: Row(
                        children: [
                          Icon(Icons.hourglass_bottom_outlined, size: 16,
                            color: Theme.of(context).colorScheme.onSurfaceVariant),
                          const SizedBox(width: 2),
                          Expanded(
                            child: DropdownButton<int?>(
                              isExpanded: true,
                              isDense: true,
                              value: _selectedExpiryMinutes,
                              items: _expiryOptions.map((opt) =>
                                DropdownMenuItem<int?>(
                                  value: opt.minutes,
                                  child: Text(
                                    _expiryLabel(context, opt),
                                    overflow: TextOverflow.ellipsis,
                                    style: const TextStyle(fontSize: 12),
                                  ),
                                ),
                              ).toList(),
                              onChanged: (val) {
                                setState(() {
                                  _selectedExpiryMinutes = val;
                                  _encryptedOutput = '';
                                  _dirtySinceEncode = true;
                                });
                                _saveSettings();
                              },
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 4),
                    SizedBox(
                      width: 20,
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.visibility_outlined, size: 12,
                            color: Theme.of(context).colorScheme.onSurfaceVariant),
                          Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(Icons.arrow_right_alt, size: 8,
                                color: Theme.of(context).colorScheme.onSurfaceVariant),
                              Icon(Icons.delete_outline, size: 8,
                                color: Theme.of(context).colorScheme.onSurfaceVariant),
                            ],
                          ),
                        ],
                      ),
                    ),
                    Switch.adaptive(
                      value: _deleteAfterRead,
                      onChanged: (v) {
                        setState(() {
                          _deleteAfterRead = v;
                          _dirtySinceEncode = true;
                        });
                        _saveSettings();
                      },
                    ),
                    const Spacer(),
                    const PassphraseButton(iconSize: 18),
                    IconButton(
                      icon: const Icon(Icons.copy_outlined, size: 20),
                      tooltip: t(context, 'copy'),
                      onPressed: (!_isInputValid || _sending)
                          ? null
                          : () async {
                              final output = await _encodeAndPersist();
                              if (output == null || !context.mounted) { return; }
                              final messenger = ScaffoldMessenger.of(context);
                              await ref.read(clipboardServiceProvider).writeText(output);
                              if (!context.mounted) { return; }
                              messenger.showSnackBar(
                                SnackBar(content: Text(t(context, 'messageCopiedClipboard'))),
                              );
                            },
                    ),
                    IconButton(
                      icon: const Icon(Icons.ios_share_outlined, size: 20),
                      tooltip: t(context, 'share'),
                      onPressed: (!_isInputValid || _sending)
                          ? null
                          : () async {
                              final output = await _encodeAndPersist();
                              if (output == null || !context.mounted) { return; }
                              await shareTextExternally(context, output);
                            },
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Row(
                  children: [
                    if (!_linkMode) ...[
                      Expanded(
                        child: TextField(
                          controller: _coverCtrl,
                          maxLines: 1,
                          focusNode: _coverFocusNode,
                          onTapOutside: _dismissMessageInputFocus,
                          inputFormatters: _coverLimitInputFormatters(
                            isCoverField: true,
                          ),
                          style: const TextStyle(fontSize: 13),
                          decoration: InputDecoration(
                            isDense: true,
                            contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                            labelText: t(context, 'coverText'),
                            labelStyle: const TextStyle(fontSize: 12),
                            helperText: _coverTooShort
                                ? t(context, 'coverTooShort').replaceAll('{n}', '$_coverMissingCount')
                                : null,
                            helperStyle: _coverTooShort
                                ? TextStyle(color: Theme.of(context).colorScheme.error, fontSize: 10)
                                : null,
                            counterText: _coverLimitCounterText(coverLengthLimit),
                            counterStyle: _coverLengthLimitExceeded
                                ? TextStyle(
                                    color: Theme.of(context).colorScheme.error,
                                    fontSize: 10,
                                  )
                                : const TextStyle(fontSize: 10),
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                    ],
                    Expanded(
                      child: TextField(
                        controller: _secretCtrl,
                        maxLines: 1,
                        focusNode: _secretFocusNode,
                        onTapOutside: _dismissMessageInputFocus,
                        inputFormatters: _coverLimitInputFormatters(
                          isCoverField: false,
                        ),
                        style: const TextStyle(fontSize: 13),
                        decoration: InputDecoration(
                          isDense: true,
                          contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                          labelText: t(context, 'secretText'),
                          labelStyle: const TextStyle(fontSize: 12),
                          counterText: _coverLimitCounterText(coverLengthLimit),
                          counterStyle: _coverLengthLimitExceeded
                              ? TextStyle(
                                  color: Theme.of(context).colorScheme.error,
                                  fontSize: 10,
                                )
                              : const TextStyle(fontSize: 10),
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final t = AppStrings.t;
    final coverLengthLimit = ref.watch(coverMessageLengthLimitProvider);

    final isWide = MediaQuery.of(context).size.width >= 980;
    if (isWide && !_handoffScheduled && !widget.embedded) {
      _handoffScheduled = true;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) {
          return;
        }
        Navigator.of(context).pop({
          'contact': widget.contact,
          ...composerState,
        });
      });
      // Do not return SizedBox.shrink() here, let it render normally while popping to avoid a black flash
    }

    // Detect tight mobile landscape – sacrifice message list for composer space.
    // Do NOT include viewInsets (keyboard) in this condition: the keyboard
    // opening must not flip the layout, otherwise TextFields lose focus and
    // the keyboard immediately closes again (oscillation).
    final mqData = MediaQuery.of(context);
    final tightLandscape = mqData.orientation == Orientation.landscape
        && mqData.size.height < 500;
    final showComposer = !_isSearching;
    final showMessageList = !tightLandscape || _isSearching;

    // Schedule composer height measurement after layout to avoid querying size during build.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final renderBox =
          _composerKey.currentContext?.findRenderObject() as RenderBox?;
      final measured = renderBox?.size.height;
      if (measured != null &&
          measured > 0 &&
          measured != _composerHeight &&
          mounted) {
        setState(() => _composerHeight = measured);
      }
    });

    return Scaffold(
      backgroundColor: Colors.transparent,
      appBar: AppBar(
        title: Text(widget.contact.displayName),
        actions: [
          IconButton(
            tooltip: t(context, 'search'),
            icon: Icon(_isSearching ? Icons.search_off : Icons.search),
            onPressed: () {
              if (_isSearching) {
                _stopSearch();
              } else {
                _startSearch();
              }
            },
          ),
          IconButton(
            tooltip: t(context, 'pasteDecode'),
            icon: const Icon(Icons.paste),
            onPressed: () async {
              final source =
                  await ref.read(clipboardServiceProvider).readText();
              final outcome = await ref
                  .read(homeControllerProvider)
                  .decodeHiddenMessage(source, hintContactId: widget.contact.identityId);
              if (!mounted) {
                return;
              }

              switch (outcome.kind) {
                case DecodeKind.success:
                  final senderId = outcome.payload?.senderId;
                  final sender = senderId == null
                      ? null
                      : await ref
                          .read(identitiesRepositoryProvider)
                          .getRemoteById(senderId);
                  if (!context.mounted) {
                    return;
                  }
                  if (sender != null) {
                    if (sender.identityId == widget.contact.identityId) {
                      // Already on the correct chat; just show success.
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text(t(context, 'messageDecoded'))),
                      );
                      _scrollToBottom();
                    } else {
                      await Navigator.of(context).pushReplacement(
                        MaterialPageRoute(
                          builder: (_) => ChatView(contact: sender),
                        ),
                      );
                    }
                  } else {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text(t(context, 'unknownSender'))),
                    );
                  }
                  break;
                case DecodeKind.expired:
                  if (!context.mounted) {
                    return;
                  }
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(t(context, 'messageExpired'))),
                  );
                  break;
                case DecodeKind.noData:
                  if (!context.mounted) {
                    return;
                  }
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(t(context, 'noMessageFoundDesc'))),
                  );
                  break;
                case DecodeKind.notForMe:
                  if (!context.mounted) {
                    return;
                  }
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(t(context, 'noMessageFoundDesc'))),
                  );
                  break;
                case DecodeKind.unknownSender:
                  if (!context.mounted) {
                    return;
                  }
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(t(context, 'unknownSender'))),
                  );
                  break;
                case DecodeKind.error:
                  if (!context.mounted) {
                    return;
                  }
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(t(context, 'decodeError'))),
                  );
                  break;
              }
            },
          ),
        ],
      ),
      body: Column(
        children: [
          if (_isSearching)
            Material(
              elevation: 1,
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                child: Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _searchCtrl,
                        focusNode: _searchFocusNode,
                        decoration: InputDecoration(
                          isDense: true,
                          contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                          hintText: t(context, 'search'),
                          prefixIcon: const Icon(Icons.search, size: 20),
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(20),
                          ),
                        ),
                        onTapOutside: (_) => FocusScope.of(context).unfocus(),
                        onChanged: (val) {
                          _searchQuery = val.trim().toLowerCase();
                          _runSearch();
                        },
                        onSubmitted: (_) => _navigateSearch(1),
                      ),
                    ),
                    const SizedBox(width: 4),
                    if (_searchInProgress)
                      const SizedBox(
                        width: 20, height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    else if (_searchMatchIds.isNotEmpty)
                      Text(
                        '${_searchIndex + 1}/${_searchMatchIds.length}',
                        style: Theme.of(context).textTheme.bodySmall,
                      )
                    else if (_searchQuery.isNotEmpty)
                      Text(
                        '0/0',
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    IconButton(
                      icon: const Icon(Icons.keyboard_arrow_up, size: 20),
                      onPressed: _searchMatchIds.isEmpty ? null : () => _navigateSearch(1),
                      visualDensity: VisualDensity.compact,
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
                    ),
                    IconButton(
                      icon: const Icon(Icons.keyboard_arrow_down, size: 20),
                      onPressed: _searchMatchIds.isEmpty ? null : () => _navigateSearch(-1),
                      visualDensity: VisualDensity.compact,
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
                    ),
                    IconButton(
                      icon: const Icon(Icons.close, size: 20),
                      onPressed: _stopSearch,
                      visualDensity: VisualDensity.compact,
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
                    ),
                  ],
                ),
              ),
            ),
          if (showMessageList)
            Expanded(
              child: StreamBuilder<List<MessageRecord>>(
                stream: ref
                    .read(messagesRepositoryProvider)
                    .watchThread(widget.contact.identityId, limit: _isSearching ? 999999 : _messageLimit),
                builder: (context, snapshot) {
                  final all = snapshot.data ?? const <MessageRecord>[];
                  final effectiveTag = ref.watch(effectiveKeyTagProvider);
                  final thread = all.where((m) {
                    if (effectiveTag == null) return true;
                    return m.keyTag == effectiveTag;
                  }).toList()
                    ..sort((a, b) => a.timestamp.compareTo(b.timestamp));

                  _cachedThread = thread;

                  if (_needsSearchOnDataLoad && thread.isNotEmpty) {
                    _needsSearchOnDataLoad = false;
                    WidgetsBinding.instance.addPostFrameCallback((_) {
                      if (mounted) _runSearch();
                    });
                  }

                  final newestTs = thread.isEmpty ? 0 : thread.last.timestamp;
                  if (newestTs > _lastNewestTimestamp && _lastNewestTimestamp > 0) {
                    _scrollToBottom();
                  }
                  _lastNewestTimestamp = newestTs;
                  _lastMessageCount = thread.length;

                  if (thread.isEmpty) {
                    return Center(child: Text(t(context, 'noMessagesYet')));
                  }

                  final media = MediaQuery.of(context);
                  final bottomInset = media.viewInsets.bottom;
                  final safeBottom = media.padding.bottom;
                  const basePad = 8.0;
                  final bottomPadding = basePad + bottomInset + safeBottom;
                  return ListView.builder(
                    controller: _scrollController,
                    reverse: true,
                    physics: const ClampingScrollPhysics(),
                    padding: EdgeInsets.fromLTRB(12, bottomPadding, 12, 12),
                    itemCount: thread.length,
                    itemBuilder: (context, index) {
                      final m = thread[thread.length - 1 - index];
                      final incoming = m.direction == 'incoming';
                      final when =
                          DateTime.fromMillisecondsSinceEpoch(m.timestamp * 1000);
                      final nowSec =
                          DateTime.now().millisecondsSinceEpoch ~/ 1000;
                      final expired =
                          m.expireAfter != null && m.expireAfter! < nowSec;
                      final isEncrypted =
                          m.ciphertextBase64 != null && m.nonceBase64 != null;

                      return FutureBuilder<String?>(
                        future: _decryptionPrimed ? _getDecryptFuture(m) : null,
                        builder: (context, snapshot) {
                          final decrypted = snapshot.data ?? _decryptedCache[m.id];

                          if (isEncrypted && !_decryptionPrimed) {
                            return Align(
                              alignment: incoming
                                  ? Alignment.centerLeft
                                  : Alignment.centerRight,
                              child: Padding(
                                padding: const EdgeInsets.symmetric(vertical: 4),
                                child: Container(
                                  width: 132,
                                  height: 44,
                                  decoration: ShapeDecoration(
                                    color: incoming
                                        ? Theme.of(context)
                                            .colorScheme
                                            .surfaceContainerHighest
                                        : Theme.of(context)
                                            .colorScheme
                                            .primary
                                            .withValues(alpha: 0.14),
                                    shape: ContinuousRectangleBorder(
                                      borderRadius: BorderRadius.circular(28),
                                    ),
                                  ),
                                ),
                              ),
                            );
                          }

                          if (isEncrypted && decrypted == null &&
                              snapshot.connectionState == ConnectionState.done) {
                            return const SizedBox.shrink();
                          }
                          if (isEncrypted && decrypted == null) {
                            return const SizedBox.shrink();
                          }

                          final revealed = _revealedIds.contains(m.id);
                          final decryptedText =
                              decrypted ?? (isEncrypted ? null : m.text);
                          final displayTextRaw = expired
                              ? t(context, 'messageExpired')
                              : revealed
                                  ? (m.rawSource ??
                                      decryptedText ??
                                      t(context, 'decryptError'))
                                  : (decryptedText ??
                                      (isEncrypted
                                          ? t(context, 'decryptError')
                                          : (m.text ?? '')));
                          final displayText =
                              _stripZeroWidth(displayTextRaw.trimRight());

                          final isSearchMatch = _isSearching && _searchMatchIds.contains(m.id);
                          final isCurrentMatch = isSearchMatch &&
                              _searchIndex < _searchMatchIds.length &&
                              _searchMatchIds[_searchIndex] == m.id;
                          final searchKey = isSearchMatch ? _searchResultKeys[m.id] : null;

                          return Align(
                            key: searchKey,
                            alignment: incoming
                                ? Alignment.centerLeft
                                : Alignment.centerRight,
                            child: GestureDetector(
                              onTap: revealed
                                  ? () {
                                      setState(() {
                                        _revealedIds.remove(m.id);
                                        _revealTimers[m.id]?.cancel();
                                        _revealTimers.remove(m.id);
                                      });
                                    }
                                  : null,
                              onLongPressStart: (details) {
                                _showMessageContextMenu(
                                    context, m, displayText,
                                    position: details.globalPosition);
                              },
                              onSecondaryTapDown: (details) {
                                _showMessageContextMenu(
                                    context, m, displayText,
                                    position: details.globalPosition);
                              },
                              child: LayoutBuilder(
                                builder: (context, constraints) {
                                  final maxWidth = constraints.maxWidth;
                                  final bubbleMaxWidth = maxWidth < 600
                                      ? maxWidth * 0.8
                                      : maxWidth < 520
                                          ? maxWidth
                                          : 520.0;

                                  final baseBubbleColor = incoming
                                          ? Theme.of(context)
                                              .colorScheme
                                              .surfaceContainerHighest
                                          : Theme.of(context)
                                              .colorScheme
                                              .primary
                                              .withValues(alpha: 0.22);
                                  final bubbleColor = isCurrentMatch
                                      ? Theme.of(context).colorScheme.primaryContainer
                                      : baseBubbleColor;

                                  final bubbleShape = ContinuousRectangleBorder(
                                        borderRadius: BorderRadius.circular(28),
                                        side: isCurrentMatch
                                            ? BorderSide(
                                                color: Theme.of(context).colorScheme.primary,
                                                width: 2,
                                              )
                                            : BorderSide.none,
                                      );

                                  Widget bubbleContent = Container(
                                    padding: const EdgeInsets.all(12),
                                    constraints:
                                        BoxConstraints(maxWidth: bubbleMaxWidth),
                                    decoration: ShapeDecoration(
                                      color: bubbleColor,
                                      shape: bubbleShape,
                                    ),
                                    child: Column(
                                      crossAxisAlignment: incoming
                                          ? CrossAxisAlignment.start
                                          : CrossAxisAlignment.end,
                                      children: [
                                        _shouldLinkify(displayText)
                                            ? Linkify(
                                                onOpen: (link) async {
                                                  final url = Uri.parse(link.url);
                                                  if (await canLaunchUrl(url)) {
                                                    await launchUrl(url, mode: LaunchMode.externalApplication);
                                                  }
                                                },
                                                text: displayText,
                                                style: Theme.of(context).textTheme.bodyMedium,
                                                linkStyle: TextStyle(
                                                  color: Theme.of(context).colorScheme.primary,
                                                  decoration: TextDecoration.underline,
                                                ),
                                                options: const LinkifyOptions(humanize: false),
                                              )
                                            : Text(
                                                displayText,
                                                style: Theme.of(context).textTheme.bodyMedium,
                                              ),
                                        const SizedBox(height: 6),
                                        Text(
                                          '${when.hour.toString().padLeft(2, '0')}:${when.minute.toString().padLeft(2, '0')}',
                                          style: Theme.of(context)
                                              .textTheme
                                              .bodySmall,
                                        ),
                                      ],
                                    ),
                                  );

                                  if (revealed) {
                                    bubbleContent = DottedBorder(
                                      options: CustomPathDottedBorderOptions(
                                        color: Theme.of(context).colorScheme.outline,
                                        strokeWidth: 2,
                                        dashPattern: const [6, 4],
                                        customPath: (size) => bubbleShape.getOuterPath(Offset.zero & size),
                                      ),
                                      child: bubbleContent,
                                    );
                                  }

                                  return Padding(
                                    padding: const EdgeInsets.symmetric(vertical: 4),
                                    child: bubbleContent,
                                  );
                                },
                              ),
                            ),
                          );
                        },
                      );
                    },
                  );
                },
              ),
            ),
          if (showComposer)
            if (tightLandscape)
              Expanded(child: _buildCompactComposer(context, t, coverLengthLimit))
            else
              SafeArea(
                top: false,
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
                  child: Card(
                    key: _composerKey,
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: FocusScope(
                        child: FocusTraversalGroup(
                          policy: OrderedTraversalPolicy(),
                          child: SingleChildScrollView(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                          crossAxisAlignment: CrossAxisAlignment.center,
                          children: [
                        ConstrainedBox(
                          constraints: BoxConstraints(
                              maxHeight: MediaQuery.of(context).size.height > 500
                                  ? 220
                                  : 120),
                          child: SingleChildScrollView(
                            child: Column(
                              children: [
                                LayoutBuilder(
                                  builder: (context, constraints) {
                                    final singleRow = constraints.maxWidth >= 360;
                                    final compactControls = constraints.maxWidth < 400;
                                    final optionSpacing = compactControls ? 8.0 : 12.0;
                                    final toggleMinSize = compactControls ? 32.0 : 36.0;
                                    final togglePadding = compactControls
                                        ? const EdgeInsets.symmetric(
                                            horizontal: 6,
                                            vertical: 3,
                                          )
                                        : const EdgeInsets.symmetric(
                                            horizontal: 8,
                                            vertical: 4,
                                          );
                                    final toggleIconSize = compactControls ? 18.0 : 20.0;
                                    final expiryWidth = compactControls ? 122.0 : 140.0;
                                    final expiryIconSize = compactControls ? 18.0 : 20.0;
                                    final deleteIconColumnWidth = compactControls ? 18.0 : 20.0;
                                    final deletePrimaryIconSize = compactControls ? 12.0 : 14.0;
                                    final deleteSecondaryIconSize = compactControls ? 8.0 : 10.0;
                                    final toggle = FocusTraversalOrder(
                                      order: const NumericFocusOrder(5),
                                      child: ToggleButtons(
                                        constraints: BoxConstraints(
                                          minHeight: toggleMinSize,
                                          minWidth: toggleMinSize,
                                        ),
                                        isSelected: [
                                          _linkMode == false,
                                          _linkMode == true
                                        ],
                                        onPressed: (index) {
                                          setState(() {
                                            _linkMode = index == 1;
                                            _encryptedOutput = '';
                                            _dirtySinceEncode = true;
                                          });
                                          _saveSettings();
                                        },
                                        borderRadius: const BorderRadius.all(
                                            Radius.circular(12)),
                                        children: [
                                          Padding(
                                            padding: togglePadding,
                                            child: Icon(Icons.chat_bubble_outline,
                                                size: toggleIconSize),
                                          ),
                                          Padding(
                                            padding: togglePadding,
                                            child: Icon(Icons.link, size: toggleIconSize),
                                          ),
                                        ],
                                      ),
                                    );

                                    final expiry = FocusTraversalOrder(
                                      order: const NumericFocusOrder(6),
                                      child: SizedBox(
                                        width: expiryWidth,
                                        child: Row(
                                          children: [
                                            Icon(
                                              Icons.hourglass_bottom_outlined,
                                              size: expiryIconSize,
                                              color: Theme.of(context)
                                                  .colorScheme
                                                  .onSurfaceVariant,
                                            ),
                                            SizedBox(width: compactControls ? 2 : 4),
                                            Expanded(
                                              child: DropdownButton<int?>(
                                                isExpanded: true,
                                                isDense: true,
                                                value: _selectedExpiryMinutes,
                                                items: _expiryOptions
                                                    .map(
                                                      (opt) =>
                                                          DropdownMenuItem<int?>(
                                                        value: opt.minutes,
                                                        child: Text(
                                                          _expiryLabel(
                                                              context, opt),
                                                          overflow:
                                                              TextOverflow.ellipsis,
                                                          style: TextStyle(
                                                            fontSize: compactControls ? 13 : null,
                                                          ),
                                                        ),
                                                      ),
                                                    )
                                                    .toList(),
                                                onChanged: (val) {
                                                  setState(() {
                                                    _selectedExpiryMinutes = val;
                                                    _encryptedOutput = '';
                                                    _dirtySinceEncode = true;
                                                  });
                                                  _saveSettings();
                                                },
                                              ),
                                            ),
                                          ],
                                        ),
                                      ),
                                    );

                                    final deleteSwitch = FocusTraversalOrder(
                                      order: const NumericFocusOrder(7),
                                      child: Row(
                                        mainAxisSize: MainAxisSize.min,
                                        mainAxisAlignment: MainAxisAlignment.end,
                                        children: [
                                          SizedBox(
                                            width: deleteIconColumnWidth,
                                            child: Column(
                                              mainAxisSize: MainAxisSize.min,
                                              children: [
                                                Icon(
                                                  Icons.visibility_outlined,
                                                  size: deletePrimaryIconSize,
                                                  color: Theme.of(context)
                                                      .colorScheme
                                                      .onSurfaceVariant,
                                                ),
                                                Row(
                                                  mainAxisSize: MainAxisSize.min,
                                                  mainAxisAlignment:
                                                      MainAxisAlignment.center,
                                                  children: [
                                                    Icon(
                                                      Icons.arrow_right_alt,
                                                      size: deleteSecondaryIconSize,
                                                      color: Theme.of(context)
                                                          .colorScheme
                                                          .onSurfaceVariant,
                                                    ),
                                                    Icon(
                                                      Icons.delete_outline,
                                                      size: deleteSecondaryIconSize,
                                                      color: Theme.of(context)
                                                          .colorScheme
                                                          .onSurfaceVariant,
                                                    ),
                                                  ],
                                                ),
                                              ],
                                            ),
                                          ),
                                          SizedBox(width: compactControls ? 2 : 4),
                                          Switch.adaptive(
                                            value: _deleteAfterRead,
                                            materialTapTargetSize:
                                                MaterialTapTargetSize.shrinkWrap,
                                            onChanged: (v) {
                                              setState(() {
                                                _deleteAfterRead = v;
                                                _dirtySinceEncode = true;
                                              });
                                              _saveSettings();
                                            },
                                          ),
                                        ],
                                      ),
                                    );

                                    if (singleRow) {
                                      return Row(
                                        crossAxisAlignment:
                                            CrossAxisAlignment.center,
                                        children: [
                                          toggle,
                                          const Spacer(),
                                          expiry,
                                          SizedBox(width: optionSpacing),
                                          deleteSwitch,
                                        ],
                                      );
                                    }

                                    return Wrap(
                                      spacing: optionSpacing,
                                      runSpacing: 8,
                                      crossAxisAlignment:
                                          WrapCrossAlignment.center,
                                      alignment: WrapAlignment.spaceBetween,
                                      children: [
                                        toggle,
                                        expiry,
                                        deleteSwitch,
                                      ],
                                    );
                                  },
                                ),
                                const SizedBox(height: 8),
                                if (!_linkMode) ...[
                                  FocusTraversalOrder(
                                    order: const NumericFocusOrder(1),
                                    child: TextField(
                                      controller: _coverCtrl,
                                      maxLines: 2,
                                      focusNode: _coverFocusNode,
                                      onTapOutside: _dismissMessageInputFocus,
                                      inputFormatters: _coverLimitInputFormatters(
                                        isCoverField: true,
                                      ),
                                      decoration: InputDecoration(
                                        labelText: t(context, 'coverText'),
                                        helperText: _coverTooShort
                                            ? t(context, 'coverTooShort')
                                                .replaceAll('{n}', '$_coverMissingCount')
                                            : null,
                                        helperStyle: _coverTooShort
                                            ? TextStyle(
                                                color: Theme.of(context)
                                                    .colorScheme
                                                    .error,
                                              )
                                            : null,
                                        counterText: _coverLimitCounterText(
                                          coverLengthLimit,
                                        ),
                                        counterStyle: _coverLengthLimitExceeded
                                            ? TextStyle(
                                                color: Theme.of(context)
                                                    .colorScheme
                                                    .error,
                                              )
                                            : null,
                                      ),
                                    ),
                                  ),
                                  const SizedBox(height: 8),
                                ],
                                FocusTraversalOrder(
                                  order: const NumericFocusOrder(2),
                                  child: TextField(
                                    controller: _secretCtrl,
                                    maxLines: 2,
                                    focusNode: _secretFocusNode,
                                    onTapOutside: _dismissMessageInputFocus,
                                    inputFormatters: _coverLimitInputFormatters(
                                      isCoverField: false,
                                    ),
                                    decoration: InputDecoration(
                                      labelText: t(context, 'secretText'),
                                      counterText: _coverLimitCounterText(
                                        coverLengthLimit,
                                      ),
                                      counterStyle: _coverLengthLimitExceeded
                                          ? TextStyle(
                                              color: Theme.of(context)
                                                  .colorScheme
                                                  .error,
                                            )
                                          : null,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(height: 8),
                        Row(
                          children: [
                            const PassphraseButton(),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Align(
                                alignment: Alignment.centerRight,
                                child: ConstrainedBox(
                                  constraints: const BoxConstraints(maxWidth: 260),
                                  child: Row(
                                    mainAxisAlignment: MainAxisAlignment.end,
                                    children: [
                                      Expanded(
                                        child: FocusTraversalOrder(
                                          order: const NumericFocusOrder(3),
                                          child: OutlinedButton.icon(
                                            onPressed: (!_isInputValid || _sending)
                                                ? null
                                                : () async {
                                                    final output =
                                                        await _encodeAndPersist();
                                                    if (output == null || !context.mounted) { return; }
                                                    final messenger =
                                                        ScaffoldMessenger.of(context);
                                                    await ref
                                                        .read(clipboardServiceProvider)
                                                        .writeText(output);
                                                    if (!context.mounted) {
                                                      return;
                                                    }
                                                    messenger.showSnackBar(
                                                      SnackBar(
                                                        content: Text(t(context,
                                                            'messageCopiedClipboard')),
                                                      ),
                                                    );
                                                  },
                                            icon: const Icon(Icons.copy_outlined, size: 18),
                                            label: FittedBox(fit: BoxFit.scaleDown, child: Text(t(context, 'copy'))),
                                          ),
                                        ),
                                      ),
                                      const SizedBox(width: 8),
                                      Expanded(
                                        child: FocusTraversalOrder(
                                          order: const NumericFocusOrder(4),
                                          child: OutlinedButton.icon(
                                            onPressed: (!_isInputValid || _sending)
                                                ? null
                                                : () async {
                                                    final output =
                                                        await _encodeAndPersist();
                                                    if (output == null || !context.mounted) { return; }
                                                    await shareTextExternally(context, output);
                                                  },
                                            icon: const Icon(Icons.ios_share_outlined, size: 18),
                                            label: FittedBox(fit: BoxFit.scaleDown, child: Text(t(context, 'share'))),
                                          ),
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ),
                        ],
                      ),
                    ),
                    ),
                    ),
                    ),
                  ),
                ),
              ),
        ],
      ),
    );
  }
}
