// Isolated physical/simulator QA uses the same two-peer real V3 fixture as
// Android. These AOT entrypoints are packaged only by the isolated QA build.
import 'android_keyboard_fixture.dart' as fixture;

void main() => fixture.main();

@pragma('vm:entry-point')
void layergramKeyboardMain() => fixture.layergramKeyboardMain();

@pragma('vm:entry-point')
void layergramKeyboardValidationMain() =>
    fixture.layergramKeyboardValidationMain();
