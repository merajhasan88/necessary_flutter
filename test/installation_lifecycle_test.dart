// The installation across a phone's life: the first start, a restart, a key
// the platform lost (an Android reinstall), and an iOS reinstall that kept the
// key but not the app's other data -- and two of the plugin's calls at once.
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:necessary/necessary.dart';

/// A platform keystore holding, or not holding, the installation key.
class _Keystore implements NativeInstallationKey {
  _Keystore({required this.holds});

  bool holds;

  @override
  Future<NativeKeyMetadata> getOrCreateKey() async {
    final bool created = !holds;
    holds = true;
    return NativeKeyMetadata(
      publicKey: const <String, dynamic>{
        'kty': 'EC',
        'crv': 'P-256',
        'alg': 'ES256',
        'x': 'x',
        'y': 'y',
      },
      algorithm: 'ES256',
      keyAlias: 'test',
      provider: 'AndroidKeyStore',
      securityLevel: 'trusted_execution_environment',
      hardwareBacked: true,
      privateKeyExportable: false,
      signatureFormat: 'der',
      created: created,
    );
  }

  @override
  Future<String> signPayload(String payloadBase64Url) async => 'signed';

  @override
  Future<void> deleteKey() async => holds = false;
}

const String _stored = 'recognition.installation_id.v2';

Future<String?> _storedId() => const FlutterSecureStorage().read(key: _stored);

/// Answers as the guide says; counts what it was asked.
class _Backend implements DeviceTrustTransport {
  final List<String> paths = <String>[];

  @override
  Future<Map<String, dynamic>> send(
    String method,
    String path, {
    String? encodedBody,
    String? bearerToken,
    Map<String, String> headers = const <String, String>{},
  }) async {
    paths.add(path);
    await Future<void>.delayed(Duration.zero);
    return switch (path) {
      '/v1/installations/register' => <String, dynamic>{
        'installation_id': 'held',
      },
      '/v1/installations/challenge' => <String, dynamic>{
        'challenge_id': 'k',
        'payload': 'cA',
      },
      '/v1/installations/verify' => <String, dynamic>{
        'device_token': 'session',
      },
      '/v1/integrity/challenge' => <String, dynamic>{
        'challenge_id': 's',
        'nonce': 'bg',
        'platform': 'android',
        'required_probes': <String>['app_identity'],
      },
      _ => <String, dynamic>{
        'integrity': <String, dynamic>{'report_id': 'r'},
      },
    };
  }

  @override
  void close() {}
}

class _Collector extends NativeIntegrityCollector {
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
    'probes': <String, dynamic>{
      'app_identity': <String, dynamic>{'status': 'ok'},
    },
  };
}

class _NoHint extends ReinstallHintReader {
  @override
  Future<ReinstallHint?> read() async => null;
}

void main() {
  setUp(() {
    FlutterSecureStorage.setMockInitialValues(<String, String>{});
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
  });
  tearDown(() => debugDefaultTargetPlatformOverride = null);

  test(
    'the first start makes the key and an installation ID; a restart finds both',
    () async {
      final _Keystore keystore = _Keystore(holds: false);
      final InstallationIdentity first = await InstallationStore(
        key: keystore,
      ).loadOrCreate();
      expect(first.createdThisLaunch, isTrue);
      expect(await _storedId(), first.installationId);
      final InstallationIdentity restarted = await InstallationStore(
        key: keystore,
      ).loadOrCreate();
      expect(restarted.createdThisLaunch, isFalse);
      expect(restarted.installationId, first.installationId);
    },
  );

  test(
    'a key the platform lost is a new installation, under a new ID',
    () async {
      FlutterSecureStorage.setMockInitialValues(<String, String>{
        _stored: 'old-installation',
      });
      final InstallationIdentity identity = await InstallationStore(
        key: _Keystore(holds: false),
      ).loadOrCreate();
      expect(identity.createdThisLaunch, isTrue);
      expect(identity.installationId, isNot('old-installation'));
      expect(await _storedId(), identity.installationId);
    },
  );

  test('a key kept without its ID proposes a new one, and keeps the one the '
      'backend holds for the key', () async {
    final InstallationStore store = InstallationStore(
      key: _Keystore(holds: true),
    );
    final InstallationIdentity proposed = await store.loadOrCreate();
    expect(proposed.createdThisLaunch, isFalse);
    final DeviceTrust trust = DeviceTrust.over(
      _Backend(),
      store: store,
      collector: _Collector(),
      hintReader: _NoHint(),
    );
    await trust.start();
    expect(trust.identity!.installationId, 'held');
    expect(await _storedId(), 'held');
  });

  test(
    'reset deletes the key and the ID: the next start is a new installation',
    () async {
      final _Keystore keystore = _Keystore(holds: false);
      final DeviceTrust trust = DeviceTrust.over(
        _Backend(),
        store: InstallationStore(key: keystore),
        collector: _Collector(),
        hintReader: _NoHint(),
      );
      await trust.start();
      await trust.reset();
      expect(keystore.holds, isFalse);
      expect(await _storedId(), isNull);
      expect(trust.identity, isNull);
      expect(trust.installationSession, isNull);
      expect((await trust.loadIdentity()).createdThisLaunch, isTrue);
    },
  );

  test(
    'two calls of one kind at once share one run; other scans run apart',
    () async {
      final _Backend backend = _Backend();
      final DeviceTrust trust = DeviceTrust.over(
        backend,
        store: InstallationStore(key: _Keystore(holds: false)),
        collector: _Collector(),
        hintReader: _NoHint(),
      );
      final List<InstallationIdentity> started = await Future.wait(
        <Future<InstallationIdentity>>[trust.start(), trust.start()],
      );
      expect(identical(started[0], started[1]), isTrue);
      expect(
        backend.paths.where((String p) => p == '/v1/installations/register'),
        hasLength(1),
      );
      expect(
        backend.paths.where((String p) => p == '/v1/installations/verify'),
        hasLength(1),
      );

      backend.paths.clear();
      final Map<String, dynamic> pay = describeOperation(
        'POST',
        '/v1/pay',
        '{}',
      );
      final Map<String, dynamic> payee = describeOperation(
        'POST',
        '/v1/payee',
        '{}',
      );
      final List<ScanResult> scans = await Future.wait(<Future<ScanResult>>[
        trust.scan(),
        trust.scan(),
        trust.scan(session: 'account', operation: pay),
        trust.scan(session: 'account', operation: payee),
      ]);
      expect(identical(scans[0], scans[1]), isTrue);
      expect(
        backend.paths.where((String p) => p == '/v1/integrity/challenge'),
        hasLength(3),
      );
      expect(
        backend.paths.where((String p) => p == '/v1/integrity/report'),
        hasLength(3),
      );
    },
  );
}
