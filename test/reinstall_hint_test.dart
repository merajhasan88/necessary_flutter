// The reinstall hint's bytes: what a backend keys and stores to link
// reinstalls, so a phone's hint must not change when the plugin's code does.
// The digests are computed apart, by Python's hashlib.
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:necessary/necessary.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const MethodChannel channel = MethodChannel('necessary/installation_key_v2');
  String? identifier;

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (MethodCall call) async {
          expect(call.method, 'reinstallHintIdentifier');
          return identifier;
        });
  });

  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('Android: ANDROID_ID, trimmed and in lower case', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    identifier = ' 9774D56D682E549C ';
    final ReinstallHint? hint = await ReinstallHintReader().read();
    expect(hint?.kind, 'android_id_sha256');
    expect(
      hint?.value,
      'fe8339ee3d9adfd02d18c670d45a27b139a58455c395e2972a14529d76316d24',
    );
  });

  test('iOS: the identifier for vendor, in lower case', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    identifier = '6F0C2A1E-7B3D-4C5E-9F8A-1B2C3D4E5F60';
    final ReinstallHint? hint = await ReinstallHintReader().read();
    expect(hint?.kind, 'idfv_sha256');
    expect(
      hint?.value,
      'a67ac309e7a6b8cac7fbf58e8d964b07bd525408624d1957f3a8fe7c670461e5',
    );
  });

  test('no identifier, or another platform: no hint', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    identifier = '';
    expect(await ReinstallHintReader().read(), isNull);
    identifier = null;
    expect(await ReinstallHintReader().read(), isNull);
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    identifier = '9774d56d682e549c';
    expect(await ReinstallHintReader().read(), isNull);
  });
}
