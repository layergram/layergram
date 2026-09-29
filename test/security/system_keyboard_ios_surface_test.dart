import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// These checks guard native build/privacy boundaries. Behavioral replay, expiry
// and editor-generation cases live in the Swift package and Dart owner suites.
void main() {
  String read(String path) => File(path).readAsStringSync();
  String code(String path) => read(path)
      .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
      .replaceAll(RegExp(r'//[^\n]*'), '');

  test('keyboard has a dedicated group, outside the existing share extension',
      () {
    final String keyboard = read(
      'ios/LayergramKeyboard/LayergramKeyboard.entitlements',
    );
    final String experimental = read('ios/Runner/RunnerKeyboard.entitlements');
    expect(keyboard, contains(r'$(CUSTOM_KEYBOARD_GROUP_ID)'));
    expect(keyboard, isNot(contains(r'$(CUSTOM_GROUP_ID)')));
    expect(experimental, contains(r'$(CUSTOM_KEYBOARD_GROUP_ID)'));
    expect(experimental, contains(r'$(CUSTOM_GROUP_ID)'));
    expect(read('ios/Runner/Runner.entitlements'),
        isNot(contains('CUSTOM_KEYBOARD_GROUP_ID')));
    expect(read('ios/Share Extension/ShareExtension.entitlements'),
        isNot(contains('CUSTOM_KEYBOARD_GROUP_ID')));
    expect(read('ios/Runner/Info.plist'), contains('KeyboardAppGroupId'));
    expect(read('ios/LayergramKeyboard/Info.plist'),
        contains('com.apple.keyboard-service'));
    expect(read('ios/LayergramKeyboard/Info.plist'),
        contains('<key>RequestsOpenAccess</key><true/>'));
  });

  test('ordinary builds do not implicitly build or embed the extension', () {
    final String project = read('ios/Runner.xcodeproj/project.pbxproj');
    expect(project, contains('LayergramKeyboard.appex'));
    expect(project, contains('SystemKeyboardHost.swift in Sources'));
    expect(project, contains('XCLocalSwiftPackageReference'));
    expect(project, contains('Embed Experimental Keyboard'));
    final String embed = read('ios/Runner/embed_system_keyboard.sh');
    expect(embed, contains(r'${LAYERGRAM_KEYBOARD_EMBED:-NO}'));
    expect(embed, contains(r'rm -rf "$keyboard_destination"'));
    final String helper = read('tool/build_ios_system_keyboard.sh');
    expect(helper, contains('LAYERGRAM_EXPERIMENTAL_SYSTEM_KEYBOARD=true'));
    expect(helper, contains('-scheme LayergramKeyboard build'));
    expect(helper, contains('LAYERGRAM_KEYBOARD_EMBED=YES'));
    expect(
        helper,
        contains(
            'LAYERGRAM_RUNNER_ENTITLEMENTS=Runner/RunnerKeyboard.entitlements'));
  });

  test('host uses existing owner and a finite foreground-initiated task', () {
    final String host = code('ios/Runner/SystemKeyboardHost.swift');
    expect(host, contains('layergram/system_keyboard'));
    expect(host, contains('channel.invokeMethod("request"'));
    expect(host, contains('beginBackgroundTask'));
    expect(host, contains('endBackgroundTask'));
    expect(host, contains('self.epoch == capturedEpoch'));
    expect(host, contains('self.owner === owner'));
    expect(host, contains('protectedDataWillBecomeUnavailableNotification'));
    expect(host, contains('deadlineMonotonicMillis'));
    expect(host, contains('guard !departed'));
    final String scene = code('ios/Runner/SceneDelegate.swift');
    expect(scene, contains('systemKeyboardHost?.willResignActive()'));
    expect(scene, contains('systemKeyboardHost?.didBecomeActive()'));
    expect(scene, contains('systemKeyboardHost?.disconnect()'));
    for (final String forbidden in <String>[
      'FlutterEngine(',
      'BGTaskScheduler',
      'beginReceivingRemoteControlEvents',
      'AVAudioSession',
      'SecItem',
      'UIPasteboard',
    ]) {
      expect(host, isNot(contains(forbidden)), reason: forbidden);
    }
  });

  test('keyboard has no host text reads, network, vault or second owner', () {
    final String ui =
        code('ios/LayergramKeyboard/KeyboardViewController.swift');
    for (final String forbidden in <String>[
      'documentContextBeforeInput',
      'documentContextAfterInput',
      'selectedText',
      'adjustTextPosition',
      'textDocumentProxy.deleteBackward',
      'setMarkedText',
      'UITextField(',
      'UITextView(',
      'URLSession',
      'URLRequest',
      'NWConnection',
      'Socket(',
      'FlutterEngine',
      'SecItem',
      'sqlite',
      'print(',
      'NSLog(',
      'UIPasteboard.changedNotification',
    ]) {
      expect(ui, isNot(contains(forbidden)), reason: forbidden);
    }
    // The extension reads exactly one shared, non-secret screen-protection
    // preference. Identity, messages and session state stay outside defaults.
    final productionUi = ui.replaceAll(
      RegExp(r'#if LAYERGRAM_KEYBOARD_TRACE\b[\s\S]*?#endif'),
      '',
    );
    expect(RegExp(r'UserDefaults\(').allMatches(productionUi).length, 1);
    final fixtureReads = RegExp(
      r'#if LAYERGRAM_KEYBOARD_TRACE\b[\s\S]*?UserDefaults\([\s\S]*?#endif',
    ).allMatches(ui);
    expect(fixtureReads.length, 1);
    expect(fixtureReads.single.group(0),
        contains('stringArray(forKey: "fixtureHostStages")'));
    expect(ui, contains('Self.screenProtectionPreferenceKey'));
    expect(ui, contains('hasFullAccess'));
    expect(ui, contains('documentIdentifier'));
    expect(ui, contains('MailboxClient'));
    expect(ui, contains('viewWillDisappear'));
    expect(ui, contains('textWillChange'));
    expect(ui, contains('textDidChange'));
    expect(ui, contains('capturedDidChangeNotification'));
    expect(ui, contains('userDidTakeScreenshotNotification'));
    expect(ui, contains('sceneCaptureState'));
    expect(ui, isNot(contains('UIApplication.shared')));
    expect(ui, contains('advanceToNextInputMode'));
    final List<RegExpMatch> insertions =
        RegExp(r'textDocumentProxy\.insertText\(([^)]*)\)')
            .allMatches(ui)
            .toList();
    expect(insertions, hasLength(1));
    expect(insertions.single.group(1), 'carrier');
    expect(
        RegExp(r'UIPasteboard\.general\.string').allMatches(ui), hasLength(1));
  });

  test('screenshot protection preference reaches only the keyboard group', () {
    final String scene = code('ios/Runner/SceneDelegate.swift');
    final String keyboard =
        code('ios/LayergramKeyboard/KeyboardViewController.swift');
    expect(scene, contains('keyboard_screen_protection_enabled'));
    expect(scene, contains('KeyboardAppGroupId'));
    expect(scene, contains('syncKeyboardScreenProtectionPreference()'));
    expect(keyboard, contains('keyboard_screen_protection_enabled'));
    expect(keyboard, contains('canRetainDraftAfterStillScreenshot'));
    expect(keyboard, contains('policy.liveControl(snapshot())'));
  });

  test('biometric shortcut stays device-only, opt-in and revocable', () {
    final String store = read(
      'ios/SystemKeyboardCore/Sources/SystemKeyboardCore/KeyboardBiometricResumeStore.swift',
    );
    final String ticket = read(
      'ios/SystemKeyboardCore/Sources/SystemKeyboardCore/KeyboardBiometricResumeTicket.swift',
    );
    final String host = read('ios/Runner/SystemKeyboardHost.swift');
    final String keyboard =
        read('ios/LayergramKeyboard/KeyboardViewController.swift');
    expect(store, contains('kSecAttrAccessibleWhenUnlockedThisDeviceOnly'));
    expect(store, contains('.biometryCurrentSet'));
    expect(store, contains('kSecAttrAccessGroup'));
    expect(store, contains('deviceOwnerAuthenticationWithBiometrics'));
    expect(ticket, contains('lifetimeMillis: Int64 = 600_000'));
    expect(ticket, contains('expires <= created + Self.lifetimeMillis'));
    expect(ticket, contains('revocableDeadlineMillis: Int64 = Int64.max'));
    expect(ticket, contains('"v": 2'));
    expect(keyboard, contains('KeyboardBiometricResumeTicket.revocableDeadlineMillis'));
    expect(host, contains('KeyboardBiometricResumeStore.remove'));
    expect(keyboard, contains('KeyboardBiometricResumeTicket('));
    expect(keyboard, contains('lastClosureWasIdle'));
    final int resumeStart =
        keyboard.indexOf('private func attemptBiometricResume()');
    final int resumeEnd = keyboard.indexOf(
        'private func restoreBiometricResumeHint()', resumeStart);
    expect(resumeStart, greaterThanOrEqualTo(0));
    expect(resumeEnd, greaterThan(resumeStart));
    final String resume = keyboard.substring(resumeStart, resumeEnd);
    expect(resume.indexOf('KeyboardBiometricResumeStore.load('),
        lessThan(resume.indexOf('allowBiometricEditorRebind: true')));
    expect(resume, contains('KeyboardBiometricResumeGate.mayAttempt('));
    expect(resume, isNot(contains('textDocumentProxy.insertText')));
  });

  test('memory warning preserves only an eligible sealed biometric ticket', () {
    final String keyboard = read(
      'ios/LayergramKeyboard/KeyboardViewController.swift',
    );
    final int start =
        keyboard.indexOf('override func didReceiveMemoryWarning()');
    final int end = keyboard.indexOf('// MARK: - Layout', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final String handler = keyboard.substring(start, end);
    expect(
        handler,
        contains(
            'let preserveSealedTicket = canPreserveProtectedBiometricResume() ||'));
    expect(
        handler,
        contains(
            'invalidateEditor(status: Copy.string(.openApp, in: locale))'));
    expect(
        handler, contains('canDeferSealedTicketRevocationBeforeAppearance()'));
    expect(handler, contains('preserveResumeTicket: preserveSealedTicket'));
    expect(keyboard, contains('if runtimeBridge == nil && session == nil {'));
    expect(keyboard, contains('if !self.biometricResumeAvailable {'));
    expect(keyboard, contains('self.restoreBiometricResumeHint()'));
  });

  test('consent explains iOS full access, deadline and screenshot limitations',
      () {
    final String settings = read(
      'lib/features/system_keyboard/system_keyboard_settings.dart',
    );
    for (final String required in <String>[
      'AppPlatform.isIOS',
      'Full Access',
      'Accesso completo',
      '20 seconds',
      '20 secondi',
      'cannot prevent screenshots',
      'non può impedire',
    ]) {
      expect(settings, contains(required));
    }
    final String service = read(
      'lib/features/system_keyboard/system_keyboard_app_service.dart',
    );
    expect(service, contains('defaultValue: false'));
    expect(service, contains('AppPlatform.isAndroid || AppPlatform.isIOS'));
    expect(
        service, contains('AppPlatform.isIOS ? const Duration(seconds: 20)'));
    expect(service, contains('_effectiveBackgroundDeadline'));
    expect(service, contains('passphraseActive: passphrase.isActive'));
  });
}
