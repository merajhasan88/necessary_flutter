// When the app replaces a step-up key its options do not accept
// (replacesStepUpKey). Under a per-use passcode policy, which Android 9
// cannot make a key for, the registration that follows each re-enrolment must
// not replace the key the server has just bound, or step-up stays unavailable.
import 'package:flutter_test/flutter_test.dart';
import 'package:necessary/necessary.dart';

StepUpKeyMetadata _key({String mode = 'windowed', bool created = false}) =>
    StepUpKeyMetadata(
      publicKey: const <String, dynamic>{
        'kty': 'EC',
        'crv': 'P-256',
        'alg': 'ES256',
        'x': 'x',
        'y': 'y',
      },
      factor: 'passcode',
      mode: mode,
      windowSeconds: mode == 'windowed' ? 30 : 0,
      securityLevel: 'tee',
      hardwareBacked: true,
      created: created,
    );

const StepUpOptions _perUse = StepUpOptions();

void main() {
  test('a known installation keeps a key the options want more of', () {
    expect(
      replacesStepUpKey(
        _key(),
        _perUse,
        replaceMismatched: false,
        knownInstallation: true,
      ),
      isFalse,
    );
  });

  test('a re-enrolment replaces it, and binds the new one', () {
    expect(
      replacesStepUpKey(
        _key(),
        _perUse,
        replaceMismatched: true,
        knownInstallation: true,
      ),
      isTrue,
    );
  });

  test("an installation's first registration replaces it", () {
    expect(
      replacesStepUpKey(
        _key(),
        _perUse,
        replaceMismatched: false,
        knownInstallation: false,
      ),
      isTrue,
    );
  });

  test('a key just made, or one the options accept, is never replaced', () {
    for (final bool known in <bool>[true, false]) {
      expect(
        replacesStepUpKey(
          _key(created: true),
          _perUse,
          replaceMismatched: true,
          knownInstallation: known,
        ),
        isFalse,
      );
      expect(
        replacesStepUpKey(
          _key(mode: 'per_use'),
          _perUse,
          replaceMismatched: true,
          knownInstallation: known,
        ),
        isFalse,
      );
    }
  });
}
