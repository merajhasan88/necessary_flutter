// The plugin end to end against a sample backend (backend/), over real HTTP
// with real P-256 signatures: only the phone's keystore and collector are
// replaced, by a software key and the contract's complete Android sample.
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
}

class _StepUpKey extends NativeStepUpKey {
  final _SoftwareKey key = _SoftwareKey();

  @override
  Future<StepUpKeyMetadata> getOrCreateKey({
    required String factor,
    required String mode,
    required int windowSeconds,
  }) async => StepUpKeyMetadata(
    publicKey: key.jwk,
    factor: factor,
    mode: mode,
    windowSeconds: windowSeconds,
    securityLevel: 'software',
    hardwareBacked: false,
    created: false,
  );

  @override
  Future<String> sign(
    String payloadBase64Url, {
    required String reason,
  }) async => key.sign(payloadBase64Url);
}

/// Answers with the contract's complete Android sample, whatever is asked.
class _SampleCollector extends NativeIntegrityCollector {
  static final Map<String, dynamic> _probes =
      ((jsonDecode(
                    repositoryFile(
                      'contract/report-1/android-8-ios-5/samples/android-8-complete.json',
                    ).readAsStringSync(),
                  )
                  as Map<String, dynamic>)['report']
              as Map<String, dynamic>)['probe_results']
          as Map<String, dynamic>;

  @override
  Future<Map<String, dynamic>> collect({
    required List<String> requiredProbes,
    required String challengeNonce,
    required List<String> enabledMeasurements,
    List<String> optionalProbes = const <String>[],
  }) async => <String, dynamic>{
    'platform': 'android',
    'challenge_nonce_echo': challengeNonce,
    'collector_version': 8,
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

DeviceTrust _trust({StepUpOptions? stepUp, AppPinOptions? appPin}) =>
    DeviceTrust.over(
      HttpTransport(_backend!),
      stepUp: stepUp,
      appPin: appPin,
      store: _MemoryStore(),
      collector: _SampleCollector(),
      hintReader: _Hint(),
      stepUpKey: _StepUpKey(),
    );

Future<void> _control(String path, Map<String, dynamic> body) async {
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

Matcher _refused(String code) => throwsA(
  isA<ApiException>().having((ApiException e) => e.code, 'code', code),
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
