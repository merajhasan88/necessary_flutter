// The plugin end to end against a sample backend (backend/), over real HTTP
// with real P-256 signatures: only the phone's keystore and collector are
// replaced, by a software key and the contract's Android samples -- the
// complete one unless a test says otherwise.
// Runs when NECESSARY_BACKEND_URL names a backend; skipped otherwise. The
// protocol-error test needs the backend's test controls on, and
// NECESSARY_TEST_TOKEN the token they answer (backend/run_e2e.sh does both);
// without the token it is skipped, as for a deployed sample.
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:necessary/necessary.dart';
import 'package:pointycastle/export.dart';
import 'package:uuid/uuid.dart';

import 'repository_files.dart';

final String? _backend = Platform.environment['NECESSARY_BACKEND_URL'];
final String? _testToken = Platform.environment['NECESSARY_TEST_TOKEN'];

SecureRandom _random() {
  final Random seed = Random.secure();
  return FortunaRandom()..seed(
    KeyParameter(
      Uint8List.fromList(List<int>.generate(32, (_) => seed.nextInt(256))),
    ),
  );
}

List<int> _unsigned(BigInt value, [int? length]) {
  String hex = value.toRadixString(16);
  if (hex.length.isOdd) {
    hex = '0$hex';
  }
  final List<int> bytes = <int>[
    for (int i = 0; i < hex.length; i += 2)
      int.parse(hex.substring(i, i + 2), radix: 16),
  ];
  return length == null
      ? bytes
      : <int>[...List<int>.filled(length - bytes.length, 0), ...bytes];
}

List<int> _derInteger(BigInt value) {
  final List<int> bytes = _unsigned(value);
  final List<int> body = bytes.first >= 0x80 ? <int>[0, ...bytes] : bytes;
  return <int>[0x02, body.length, ...body];
}

/// A P-256 key in software: signs as the phone's keystore does, ECDSA over
/// SHA-256 with an ASN.1 DER signature.
class _SoftwareKey {
  _SoftwareKey() {
    final ECKeyGenerator generator = ECKeyGenerator()
      ..init(
        ParametersWithRandom(
          ECKeyGeneratorParameters(ECDomainParameters('secp256r1')),
          _random(),
        ),
      );
    final AsymmetricKeyPair<PublicKey, PrivateKey> pair = generator
        .generateKeyPair();
    _private = pair.privateKey as ECPrivateKey;
    final ECPoint point = (pair.publicKey as ECPublicKey).Q!;
    jwk = <String, dynamic>{
      'kty': 'EC',
      'crv': 'P-256',
      'alg': 'ES256',
      'x': base64UrlNoPadding(_unsigned(point.x!.toBigInteger()!, 32)),
      'y': base64UrlNoPadding(_unsigned(point.y!.toBigInteger()!, 32)),
    };
  }

  late final ECPrivateKey _private;
  late final Map<String, dynamic> jwk;

  String sign(String payloadBase64Url) {
    final ECDSASigner signer = ECDSASigner(
      SHA256Digest(),
      HMac(SHA256Digest(), 64),
    )..init(true, PrivateKeyParameter<ECPrivateKey>(_private));
    final ECSignature signature =
        signer.generateSignature(
              Uint8List.fromList(
                base64Url.decode(base64Url.normalize(payloadBase64Url)),
              ),
            )
            as ECSignature;
    final List<int> body = <int>[
      ..._derInteger(signature.r),
      ..._derInteger(signature.s),
    ];
    return base64UrlNoPadding(<int>[0x30, body.length, ...body]);
  }
}

class _InstallationKey implements NativeInstallationKey {
  final _SoftwareKey key = _SoftwareKey();
  bool made = false;

  @override
  Future<NativeKeyMetadata> getOrCreateKey() async {
    final bool created = !made;
    made = true;
    return NativeKeyMetadata(
      publicKey: key.jwk,
      algorithm: 'ES256',
      keyAlias: 'software',
      provider: 'AndroidKeyStore',
      securityLevel: 'software',
      hardwareBacked: false,
      privateKeyExportable: false,
      signatureFormat: 'der',
      created: created,
    );
  }

  @override
  Future<String> signPayload(String payloadBase64Url) async =>
      key.sign(payloadBase64Url);

  @override
  Future<void> deleteKey() async => made = false;
}

/// The installation ID in memory, beside the software key.
class _MemoryStore extends InstallationStore {
  _MemoryStore() : super(key: _InstallationKey());

  String? stored;

  @override
  Future<InstallationIdentity> loadOrCreate() async {
    final NativeKeyMetadata metadata = await key.getOrCreateKey();
    if (stored == null || metadata.created) {
      stored = const Uuid().v4();
    }
    return InstallationIdentity(
      installationId: stored!,
      nativeKey: key,
      metadata: metadata,
    );
  }

  @override
  Future<void> saveInstallationId(String installationId) async =>
      stored = installationId;

  bool reenrolPending = false;

  @override
  Future<bool> stepUpReenrolPending() async => reenrolPending;

  @override
  Future<void> setStepUpReenrolPending(bool pending) async =>
      reenrolPending = pending;
}

class _StepUpKey extends NativeStepUpKey {
  _SoftwareKey key = _SoftwareKey();

  /// The screen lock removed: the key can no longer sign.
  bool dead = false;

  /// Whether the phone has a screen lock: without one no key is made.
  bool locked = true;

  @override
  Future<StepUpKeyMetadata> getOrCreateKey({
    required String factor,
    required String mode,
    required int windowSeconds,
  }) async => !locked
      ? throw NativeKeyException('STEPUP_NO_DEVICE_CREDENTIAL', 'no lock')
      : StepUpKeyMetadata(
          publicKey: key.jwk,
          factor: factor,
          mode: mode,
          windowSeconds: windowSeconds,
          securityLevel: 'software',
          hardwareBacked: false,
          created: false,
        );

  @override
  Future<String> sign(String payloadBase64Url, {required String reason}) async {
    if (dead) {
      throw NativeKeyException(
        'STEPUP_KEY_INVALIDATED',
        'the lock was removed',
      );
    }
    return key.sign(payloadBase64Url);
  }

  @override
  Future<void> deleteKey() async {
    key = _SoftwareKey();
    dead = false;
  }
}

const String _samples = 'contract/report-1/android-8-ios-5/samples';

/// One of the contract's sample reports, with its plan and how it is judged.
Map<String, dynamic> _sample(String name) =>
    jsonDecode(repositoryFile('$_samples/$name.json').readAsStringSync())
        as Map<String, dynamic>;

/// Answers with one of the contract's Android samples, whatever is asked.
class _SampleCollector extends NativeIntegrityCollector {
  _SampleCollector([
    String sample = 'android-8-complete',
    this.collectorVersion = 8,
  ]) : _probes =
           (_sample(sample)['report'] as Map<String, dynamic>)['probe_results']
               as Map<String, dynamic>;

  final Map<String, dynamic> _probes;
  final int collectorVersion;

  @override
  Future<Map<String, dynamic>> collect({
    required List<String> requiredProbes,
    required String challengeNonce,
    required List<String> enabledMeasurements,
    List<String> optionalProbes = const <String>[],
  }) async => <String, dynamic>{
    'platform': 'android',
    'challenge_nonce_echo': challengeNonce,
    'collector_version': collectorVersion,
    'probes': _probes,
  };
}

class _Hint extends ReinstallHintReader {
  @override
  Future<ReinstallHint?> read() async => ReinstallHint(
    kind: 'android_id_sha256',
    value: List<String>.generate(
      64,
      (int i) => '0123456789abcdef'[Random().nextInt(16)],
    ).join(),
  );
}

DeviceTrust _trust({
  StepUpOptions? stepUp,
  AppPinOptions? appPin,
  _StepUpKey? stepUpKey,
  _SampleCollector? collector,
}) => DeviceTrust.over(
  HttpTransport(_backend!),
  stepUp: stepUp,
  appPin: appPin,
  store: _MemoryStore(),
  collector: collector ?? _SampleCollector(),
  hintReader: _Hint(),
  stepUpKey: stepUpKey ?? _StepUpKey(),
);

/// A test control, and its answer.
Future<Map<String, dynamic>> _control(
  String path,
  Map<String, dynamic> body,
) async {
  final http.Response response = await http.post(
    Uri.parse('$_backend$path'),
    headers: <String, String>{
      'Content-Type': 'application/json',
      'X-Test-Token': _testToken ?? '',
    },
    body: jsonEncode(body),
  );
  expect(
    response.statusCode,
    200,
    reason:
        'the backend runs with --test-controls, answering NECESSARY_TEST_TOKEN',
  );
  return jsonDecode(response.body) as Map<String, dynamic>;
}

/// From now on the backend holds each app PIN check once it has claimed its
/// attempt, until [_releasePinChecks].
Future<void> _holdPinChecks() =>
    _control('/test/pin-checks', <String, dynamic>{'hold': true});

/// Releases the checks held -- with [fail], as if their verifier broke.
Future<void> _releasePinChecks({bool fail = false}) => _control(
  '/test/pin-checks',
  <String, dynamic>{'hold': false, 'fail': fail},
);

/// Waits until [count] app PIN checks are held.
Future<void> _pinChecksHeld(int count) async {
  for (int i = 0; i < 200; i++) {
    final Map<String, dynamic> answer = await _control(
      '/test/pin-checks',
      <String, dynamic>{},
    );
    if (answer['waiting'] == count) {
      return;
    }
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
  fail('the backend never held $count app PIN checks');
}

/// This backend's own sign-in, under the installation session: its account
/// session for this installation.
Future<String> _signIn(
  DeviceTrust trust, {
  String password = 'correct horse',
}) async {
  final RequestProof proof = await trust.signRequest(
    method: 'POST',
    path: '/v1/demo/sign-in',
    bearer: trust.installationSession!,
    body: jsonEncode(<String, dynamic>{
      'handle': 'e2e-${Random.secure().nextInt(1 << 32)}',
      'password': password,
    }),
  );
  return (await trust.send(proof))['account_session'] as String;
}

/// Refused with [code] -- and, like every refusal here, without naming the
/// check that failed: the phone is told what to do next, never what gave a
/// request away.
Matcher _refused(String code) => throwsA(
  isA<ApiException>()
      .having((ApiException e) => e.code, 'code', code)
      .having(
        (ApiException e) =>
            e.details?.keys.toSet().intersection(<String>{'check', 'at'}),
        'the failed check named',
        anyOf(isNull, isEmpty),
      ),
);

void main() {
  setUp(() => debugDefaultTargetPlatformOverride = TargetPlatform.android);
  tearDown(() => debugDefaultTargetPlatformOverride = null);

  group('against $_backend', () {
    test(
      'start registers and proves; a scan is answered with integrity.report_id',
      () async {
        final DeviceTrust trust = _trust();
        await trust.start();
        final ScanResult scan = await trust.scan();
        expect(scan.reportId, isNotEmpty);
        expect(
          (scan.answer['integrity'] as Map<String, dynamic>)['next'],
          'allow',
        );
        // What catches hooks, gadgets and changes in memory is asked for on
        // every scan, never left to chance.
        for (int i = 0; i < 3; i++) {
          expect(
            (await trust.scan()).challenge.requiredProbes,
            containsAll(<String>[
              'runtime_maps',
              'frida_ports',
              'instrumentation_threads',
              'exec_mappings',
              'code_integrity',
              'tracer',
              'debug_state',
            ]),
          );
        }
        // Every personal measurement is asked for, so that the example app
        // can show each one it enables.
        expect(scan.challenge.optionalProbes, <String>[
          for (final PersonalMeasurement measurement
              in PersonalMeasurement.values)
            measurement.wireName,
        ]);
      },
    );

    test("a request carries its proof once", () async {
      final DeviceTrust trust = _trust();
      await trust.start();
      final String account = await _signIn(trust);
      final RequestProof proof = await trust.signRequest(
        method: 'POST',
        path: '/v1/demo/echo',
        bearer: account,
        body: '{"hello":1}',
      );
      expect(await trust.send(proof), containsPair('done', '/v1/demo/echo'));
      await expectLater(trust.send(proof), _refused('proof_reused'));
    });

    test('a scan for one action approves that request, once', () async {
      final DeviceTrust trust = _trust();
      await trust.start();
      final String account = await _signIn(trust);
      const String body = '{"amount":25,"to":"payee-7"}';
      final ScanResult scan = await trust.scan(
        session: account,
        operation: describeOperation('POST', '/v1/demo/transfer', body),
      );
      Future<Map<String, dynamic>> transfer(String? reportId) async =>
          trust.send(
            await trust.signRequest(
              method: 'POST',
              path: '/v1/demo/transfer',
              bearer: account,
              body: body,
              reportId: reportId,
            ),
          );
      await expectLater(transfer(null), _refused('needs_scan'));
      expect(
        await transfer(scan.reportId),
        containsPair('done', '/v1/demo/transfer'),
      );
      await expectLater(transfer(scan.reportId), _refused('needs_scan'));
    });

    test('a scan for one action approves it only when the backend allows '
        'it: the contract judges a report before anything else', () async {
      const String body = '{"amount":25,"to":"payee-7"}';
      for (final (String sample, String next) in <(String, String)>[
        ('android-8-complete', 'allow'),
        ('android-8-incomplete', 'scan_again'),
        ('android-8-invalid', 'review'),
      ]) {
        final DeviceTrust trust = _trust(collector: _SampleCollector(sample));
        await trust.start();
        final String account = await _signIn(trust);
        final ScanResult scan = await trust.scan(
          session: account,
          operation: describeOperation('POST', '/v1/demo/transfer', body),
        );
        expect(
          (scan.answer['integrity'] as Map<String, dynamic>)['next'],
          next,
          reason: sample,
        );
        final Future<Map<String, dynamic>> transfer = trust.send(
          await trust.signRequest(
            method: 'POST',
            path: '/v1/demo/transfer',
            bearer: account,
            body: body,
            reportId: scan.reportId,
          ),
        );
        if (next == 'allow') {
          expect(
            await transfer,
            containsPair('done', '/v1/demo/transfer'),
            reason: sample,
          );
        } else {
          await expectLater(transfer, _refused('needs_scan'), reason: sample);
        }
      }
      // A collector older than the contract is refused, never read.
      final DeviceTrust old = _trust(
        collector: _SampleCollector('android-8-complete', 7),
      );
      await old.start();
      await expectLater(old.scan(), _refused('report_not_accepted'));
    });

    test('every sample of the contract is judged as it says, under its own '
        'plan', () async {
      final List<File> samples =
          repositoryDirectory(_samples).listSync().whereType<File>().where((
            File file,
          ) {
            return file.path.endsWith('.json');
          }).toList()..sort((File a, File b) => a.path.compareTo(b.path));
      expect(samples, hasLength(11));
      for (final File file in samples) {
        final Map<String, dynamic> sample =
            jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
        final Map<String, dynamic> answer =
            await _control('/test/judge', <String, dynamic>{
              'report': sample['report'],
              'required_probes':
                  (sample['plan'] as Map<String, dynamic>)['required_probes'],
            });
        expect(answer['judged'], sample['expect'], reason: file.path);
      }
    }, skip: _testToken == null ? 'NECESSARY_TEST_TOKEN is not set' : false);

    test("a sensitive request needs the person's approval: step-up, the app "
        'PIN, or both', () async {
      final DeviceTrust trust = _trust(
        stepUp: const StepUpOptions(),
        appPin: const AppPinOptions(),
      );
      await trust.start();
      final String account = await _signIn(trust, password: 'pin owner');
      Future<Map<String, dynamic>> sensitive({
        bool stepUp = false,
        String? pin,
      }) async => trust.send(
        await trust.signRequest(
          method: 'POST',
          path: '/v1/demo/sensitive',
          bearer: account,
          body: '{"payee":"payee-7"}',
          stepUp: stepUp,
          appPin: pin,
        ),
      );
      await expectLater(sensitive(), _refused('needs_approval'));
      expect(
        await sensitive(stepUp: true),
        containsPair('done', '/v1/demo/sensitive'),
      );
      await expectLater(sensitive(pin: '135790'), _refused('app_pin_not_set'));
      expect(
        await trust.setAppPin(
          session: account,
          pin: '135790',
          reauthentication: <String, dynamic>{'password': 'pin owner'},
        ),
        containsPair('app_pin_set', true),
      );
      await expectLater(sensitive(pin: '000000'), _refused('app_pin_invalid'));
      expect(
        await sensitive(pin: '135790'),
        containsPair('done', '/v1/demo/sensitive'),
      );
      expect(
        await sensitive(stepUp: true, pin: '135790'),
        containsPair('done', '/v1/demo/sensitive'),
      );
    });

    test('a request proof is refused for another body, path or time, and '
        "under another phone's key", () async {
      final DeviceTrust trust = _trust();
      await trust.start();
      final String account = await _signIn(trust);
      const String body = '{"amount":25}';
      Future<RequestProof> echo() => trust.signRequest(
        method: 'POST',
        path: '/v1/demo/echo',
        bearer: account,
        body: body,
      );
      await expectLater(
        trust.client.sendSigned(await echo(), encodedBody: '{"amount":2500}'),
        _refused('proof_not_accepted'),
      );
      await expectLater(
        trust.client.sendSigned(await echo(), path: '/v1/demo/sensitive'),
        _refused('proof_not_accepted'),
      );
      await expectLater(
        trust.send(
          await signRequest(
            identity: trust.identity!,
            method: 'POST',
            path: '/v1/demo/echo',
            bearerToken: account,
            encodedBody: body,
            timestamp: DateTime.now().millisecondsSinceEpoch ~/ 1000 - 600,
          ),
        ),
        _refused('proof_not_accepted'),
      );
      // The session copied to another phone: its key cannot sign for this
      // installation, even naming it.
      final DeviceTrust other = _trust();
      await other.start();
      await expectLater(
        other.send(
          await signRequest(
            identity: other.identity!,
            method: 'POST',
            path: '/v1/demo/echo',
            bearerToken: account,
            encodedBody: body,
            installationId: trust.identity!.installationId,
          ),
        ),
        _refused('invalid_installation_signature'),
      );
    });

    test('re-enrolment: a dead step-up key replaced with the password, for '
        'that account alone', () async {
      final _StepUpKey stepUpKey = _StepUpKey();
      final DeviceTrust trust = _trust(
        stepUp: const StepUpOptions(),
        stepUpKey: stepUpKey,
      );
      await trust.start();
      final String account = await _signIn(trust, password: 'key owner');
      Future<Map<String, dynamic>> sensitive(String session) async =>
          trust.send(
            await trust.signRequest(
              method: 'POST',
              path: '/v1/demo/sensitive',
              bearer: session,
              body: '{"payee":"payee-7"}',
              stepUp: true,
            ),
          );
      expect(
        await sensitive(account),
        containsPair('done', '/v1/demo/sensitive'),
      );
      // The screen lock removed: the key the backend holds cannot sign.
      stepUpKey.dead = true;
      await expectLater(
        sensitive(account),
        throwsA(
          isA<NativeKeyException>().having(
            (NativeKeyException e) => e.code,
            'code',
            'STEPUP_KEY_INVALIDATED',
          ),
        ),
      );
      await expectLater(
        trust.reenrolStepUp(
          session: account,
          reauthentication: <String, dynamic>{'password': 'wrong password'},
        ),
        _refused('reauthentication_failed'),
      );
      expect(
        await trust.reenrolStepUp(
          session: account,
          reauthentication: <String, dynamic>{'password': 'key owner'},
        ),
        containsPair('stepup_key_registered', true),
      );
      expect(
        await sensitive(account),
        containsPair('done', '/v1/demo/sensitive'),
      );
      // Another account on the same phone gains no step-up from it.
      await expectLater(
        sensitive(await _signIn(trust)),
        _refused('step_up_not_accepted'),
      );
    });

    test('an app PIN check settles against the PIN it compared: a PIN set '
        'meanwhile is left alone, and the proofs made before it no longer '
        'serve', () async {
      final DeviceTrust trust = _trust(appPin: const AppPinOptions());
      await trust.start();
      final String account = await _signIn(trust, password: 'pin owner');
      Future<void> setPin(String pin) => trust.setAppPin(
        session: account,
        pin: pin,
        reauthentication: <String, dynamic>{'password': 'pin owner'},
      );
      Future<RequestProof> unlock(String pin) => trust.signRequest(
        method: 'POST',
        path: '/v1/demo/sensitive',
        bearer: account,
        body: '{"payee":"payee-7"}',
        appPin: pin,
      );
      Future<Map<String, dynamic>> sensitive(String pin) async =>
          trust.send(await unlock(pin));
      final Matcher done = containsPair('done', '/v1/demo/sensitive');
      await setPin('111111');

      // A right PIN still being checked when a new one is set unlocks
      // nothing; asked now, the old PIN is simply wrong. (Each check held is
      // expected at once, so that its refusal never goes unheard.)
      await _holdPinChecks();
      final Future<void> right = expectLater(
        unlock('111111'),
        _refused('app_pin_invalid'),
      );
      await _pinChecksHeld(1);
      await setPin('222222');
      await _releasePinChecks();
      await right;
      await expectLater(sensitive('111111'), _refused('app_pin_invalid'));
      expect(await sensitive('222222'), done);

      // Five wrong PINs being checked hold every attempt, so a sixth waits;
      // when a new PIN is set meanwhile they neither count against it nor
      // lock it.
      await _holdPinChecks();
      final List<Future<void>> wrong = <Future<void>>[
        for (int i = 0; i < 5; i++)
          expectLater(unlock('99999$i'), _refused('app_pin_invalid')),
      ];
      await _pinChecksHeld(5);
      await expectLater(unlock('999995'), _refused('pin_busy'));
      await setPin('333333');
      await _releasePinChecks();
      await Future.wait(wrong);
      expect(await sensitive('333333'), done);

      // A proof made before a new PIN no longer serves.
      final RequestProof made = await unlock('333333');
      await setPin('444444');
      await expectLater(trust.send(made), _refused('app_pin_not_accepted'));
      expect(await sensitive('444444'), done);

      // A check that could not run gives its attempt back: four wrong PINs
      // after it still leave the last attempt, which two checks at once
      // cannot both take.
      await _holdPinChecks();
      final Future<void> broken = expectLater(
        unlock('444444'),
        _refused('pin_unavailable'),
      );
      await _pinChecksHeld(1);
      await _releasePinChecks(fail: true);
      await broken;
      for (int i = 0; i < 4; i++) {
        await expectLater(sensitive('00000$i'), _refused('app_pin_invalid'));
      }
      await _holdPinChecks();
      final Future<RequestProof> last = unlock('444444');
      await _pinChecksHeld(1);
      await expectLater(unlock('444444'), _refused('pin_busy'));
      await _releasePinChecks();
      expect(await trust.send(await last), done);
    }, skip: _testToken == null ? 'NECESSARY_TEST_TOKEN is not set' : false);

    test('a screen lock set only after the installation was registered: its '
        'step-up key waits for re-enrolment, then approves', () async {
      final _StepUpKey stepUpKey = _StepUpKey()..locked = false;
      final DeviceTrust trust = _trust(
        stepUp: const StepUpOptions(),
        stepUpKey: stepUpKey,
      );
      await trust.start();
      expect(trust.stepUpUnavailable?.code, 'STEPUP_NO_DEVICE_CREDENTIAL');
      final String account = await _signIn(trust, password: 'lock owner');
      // The lock set again, the app started again: the key it makes now is
      // not one the backend took.
      stepUpKey.locked = true;
      await trust.start();
      expect(trust.stepUpUnavailable?.code, 'STEPUP_REENROL_PENDING');
      Future<Map<String, dynamic>> sensitive() async => trust.send(
        await trust.signRequest(
          method: 'POST',
          path: '/v1/demo/sensitive',
          bearer: account,
          body: '{"payee":"payee-7"}',
          stepUp: true,
        ),
      );
      await expectLater(
        sensitive(),
        throwsA(
          isA<NativeKeyException>().having(
            (NativeKeyException e) => e.code,
            'code',
            'STEPUP_REENROL_PENDING',
          ),
        ),
      );
      expect(
        await trust.reenrolStepUp(
          session: account,
          reauthentication: <String, dynamic>{'password': 'lock owner'},
        ),
        containsPair('stepup_key_registered', true),
      );
      expect(await sensitive(), containsPair('done', '/v1/demo/sensitive'));
    });

    test("the guide's protocol errors, each acted on once", () async {
      final DeviceTrust trust = _trust();
      await trust.start();
      // The installation session expired: the key is proved again.
      await _control('/test/expire-sessions', <String, dynamic>{});
      expect((await trust.scan()).reportId, isNotEmpty);
      // The backend lost the installation: registered again with the same key.
      await _control('/test/forget', <String, dynamic>{
        'installation_id': trust.identity!.installationId,
      });
      expect((await trust.scan()).reportId, isNotEmpty);
      // A key challenge expired before its answer: a new one, once.
      await _control('/test/refuse-next', <String, dynamic>{
        'path': '/v1/installations/verify',
        'status': 401,
        'code': 'challenge_expired',
      });
      expect(await trust.prove(), isNotEmpty);
      // A scan's challenge expired before its report: a new scan, once.
      await _control('/test/refuse-next', <String, dynamic>{
        'path': '/v1/integrity/report',
        'status': 401,
        'code': 'integrity_challenge_expired',
      });
      expect((await trust.scan()).reportId, isNotEmpty);
      // A short wait is waited out, once.
      await _control('/test/refuse-next', <String, dynamic>{
        'path': '/v1/integrity/challenge',
        'status': 429,
        'code': 'busy',
        'details': <String, dynamic>{'retry_after_seconds': 1},
      });
      expect((await trust.scan()).reportId, isNotEmpty);
      // Any other refusal reaches the app as it came.
      await _control('/test/refuse-next', <String, dynamic>{
        'path': '/v1/integrity/challenge',
        'status': 403,
        'code': 'installation_inactive',
      });
      await expectLater(trust.scan(), _refused('installation_inactive'));
    }, skip: _testToken == null ? 'NECESSARY_TEST_TOKEN is not set' : false);
  }, skip: _backend == null ? 'NECESSARY_BACKEND_URL is not set' : false);
}
