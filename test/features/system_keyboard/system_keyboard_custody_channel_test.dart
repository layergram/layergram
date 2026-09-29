import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:layergram/features/system_keyboard/system_keyboard_custody_channel.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('native snapshot is copied into wipeable keyboard custody memory',
      () async {
    const channel = MethodChannel('test/keyboard_custody_immutable_snapshot');
    final source = Uint8List.fromList([1, 2, 3]);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      expect(call.method, 'reclaim');
      return {'revision': 0, 'snapshot': source.asUnmodifiableView()};
    });
    addTearDown(() => TestDefaultBinaryMessengerBinding
        .instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null));

    final result =
        await const MethodChannelSystemKeyboardCustodyNative(channel: channel)
            .reclaim(Uint8List(16), Uint8List(32));
    result.bytes.fillRange(0, result.bytes.length, 0);
    expect(result.bytes, [0, 0, 0]);
    expect(source, [1, 2, 3]);
  });
}
