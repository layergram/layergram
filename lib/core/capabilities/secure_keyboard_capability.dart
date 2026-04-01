enum SecureKeyboardFieldType {
  plainText,
  multiline,
  secretText,
  numeric,
  url,
}

enum SecureKeyboardLayoutFamily {
  qwerty,
  azerty,
  qwertz,
  symbols,
  numeric,
  custom,
}

class SecureKeyboardLocaleProfile {
  const SecureKeyboardLocaleProfile({
    required this.id,
    required this.localeTag,
    required this.label,
    required this.layoutFamily,
    this.supportsScramble = false,
  });

  final String id;
  final String localeTag;
  final String label;
  final SecureKeyboardLayoutFamily layoutFamily;
  final bool supportsScramble;
}

class SecureKeyboardRequest {
  const SecureKeyboardRequest({
    required this.localeId,
    this.fieldType = SecureKeyboardFieldType.plainText,
    this.scrambleEnabled = false,
    this.obscureText = false,
    this.allowHaptics = true,
  });

  final String localeId;
  final SecureKeyboardFieldType fieldType;
  final bool scrambleEnabled;
  final bool obscureText;
  final bool allowHaptics;
}

class SecureKeyboardSession {
  const SecureKeyboardSession({
    required this.locale,
    required this.fieldType,
    required this.scrambleEnabled,
    required this.obscureText,
  });

  final SecureKeyboardLocaleProfile locale;
  final SecureKeyboardFieldType fieldType;
  final bool scrambleEnabled;
  final bool obscureText;
}

abstract class SecureKeyboardCapability {
  bool get isAvailable;

  bool get supportsScramble;

  Future<List<SecureKeyboardLocaleProfile>> supportedLocales();

  Future<SecureKeyboardSession?> createSession({
    required SecureKeyboardRequest request,
  });
}

class NoSecureKeyboardCapability implements SecureKeyboardCapability {
  const NoSecureKeyboardCapability();

  @override
  bool get isAvailable => false;

  @override
  bool get supportsScramble => false;

  @override
  Future<List<SecureKeyboardLocaleProfile>> supportedLocales() async =>
      const <SecureKeyboardLocaleProfile>[];

  @override
  Future<SecureKeyboardSession?> createSession({
    required SecureKeyboardRequest request,
  }) async {
    return null;
  }
}
