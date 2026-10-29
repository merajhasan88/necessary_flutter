// DeviceTrust against a backend that answers as the public guide says, with
// the phone's native side replaced: what it sends, under which session, and
// what it does about each of the guide's protocol errors.
import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:necessary/necessary.dart';

import 'repository_files.dart';

class _Call {
  _Call(this.method, this.path, this.body, this.bearer, this.headers);

  final String method;
  final String path;
  final Map<String, dynamic> body;
  final String? bearer;
  final Map<String, String> headers;
}

/// Answers each path from its queue, the last answer repeating; an
/// ApiException in the queue is thrown.
class _Backend implements DeviceTrustTransport {
  _Backend([Map<String, List<Object>>? answers])
    : answers = <String, List<Object>>{
        '/v1/installations/register': <Object>[
          <String, dynamic>{'installation_id': 'proposed-id'},
        ],
        '/v1/installations/challenge': <Object>[
          <String, dynamic>{'challenge_id': 'key-challenge', 'payload': 'cGF5'},
        ],
        '/v1/installations/verify': <Object>[
          <String, dynamic>{'device_token': 'installation-session'},
        ],
        '/v1/integrity/challenge': <Object>[
          <String, dynamic>{
            'challenge_id': 'scan-challenge',
            'nonce': 'bm9uY2U',
            'platform': 'android',
            'required_probes': <String>['app_identity'],
            'optional_probes': <String>['location'],
          },
        ],
        '/v1/integrity/report': <Object>[
          <String, dynamic>{
            'integrity': <String, dynamic>{'report_id': 'report-1'},
          },
        ],
        '/v1/account/app-pin': <Object>[
          <String, dynamic>{'app_pin_set': true},
        ],
        '/v1/account/app-pin/proof': <Object>[
          <String, dynamic>{'app_pin_proof': 'pin-proof'},
        ],
        '/v1/installations/stepup-key': <Object>[
          <String, dynamic>{'stepup_key_registered': true},
        ],
        ...?answers,
      };

  final Map<String, List<Object>> answers;
  final List<_Call> calls = <_Call>[];

  List<String> get paths => <String>[for (final _Call call in calls) call.path];

  @override
  Future<Map<String, dynamic>> send(
    String method,
    String path, {
    String? encodedBody,
    String? bearerToken,
    Map<String, String> headers = const <String, String>{},
  }) async {
    calls.add(
      _Call(
        method,
        path,
        encodedBody == null || encodedBody.isEmpty
            ? <String, dynamic>{}
            : jsonDecode(encodedBody) as Map<String, dynamic>,
        bearerToken,
        headers,
      ),
    );
    final List<Object> queue = answers[path]!;
    final Object next = queue.length > 1 ? queue.removeAt(0) : queue.first;
    if (next is ApiException) {
      throw next;
    }
    return Map<String, dynamic>.from(next as Map);
  }

  @override
  void close() {}
}

NativeKeyMetadata _metadata({bool created = false}) => NativeKeyMetadata(
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

class _Key implements NativeInstallationKey {
  @override
  Future<NativeKeyMetadata> getOrCreateKey() async => _metadata();

  @override
  Future<String> signPayload(String payloadBase64Url) async => 'signed';

  @override
  Future<void> deleteKey() async {}
}

class _Store extends InstallationStore {
  _Store() : super(key: _Key());

  String? saved;

  @override
  Future<InstallationIdentity> loadOrCreate() async => InstallationIdentity(
    installationId: 'proposed-id',
    nativeKey: key,
    metadata: _metadata(),
  );

  @override
  Future<void> saveInstallationId(String installationId) async {
    saved = installationId;
  }

  bool reenrolPending = false;

  @override
  Future<bool> stepUpReenrolPending() async => reenrolPending;

  @override
  Future<void> setStepUpReenrolPending(bool pending) async =>
      reenrolPending = pending;

  @override
  Future<void> clear() async {
    saved = null;
    reenrolPending = false;
  }
}

class _Collector extends NativeIntegrityCollector {
  List<String>? enabled;

  @override
  Future<Map<String, dynamic>> collect({
    required List<String> requiredProbes,
    required String challengeNonce,
    required List<String> enabledMeasurements,
    List<String> optionalProbes = const <String>[],
  }) async {
    enabled = enabledMeasurements;
    return <String, dynamic>{
      'platform': 'android',
      'challenge_nonce_echo': challengeNonce,
      'collector_version': 8,
      'probes': <String, dynamic>{
        for (final String probe in requiredProbes)
          probe: <String, dynamic>{'status': 'ok'},
      },
    };
  }
}

class _Hints extends ReinstallHintReader {
  @override
  Future<ReinstallHint?> read() async =>
      const ReinstallHint(kind: 'android_id_sha256', value: 'hint');
}

class _StepUpKey extends NativeStepUpKey {
  _StepUpKey({this.refuse});

  final NativeKeyException? refuse;
  String? reason;

  @override
  Future<StepUpKeyMetadata> getOrCreateKey({
    required String factor,
    required String mode,
    required int windowSeconds,
  }) async {
    if (refuse != null) {
      throw refuse!;
    }
    return StepUpKeyMetadata(
      publicKey: const <String, dynamic>{
        'kty': 'EC',
        'crv': 'P-256',
        'alg': 'ES256',
        'x': 'sx',
        'y': 'sy',
      },
      factor: factor,
      mode: mode,
      windowSeconds: windowSeconds,
      securityLevel: 'trusted_execution_environment',
      hardwareBacked: true,
      created: true,
    );
  }

  @override
  Future<String> sign(String payloadBase64Url, {required String reason}) async {
    this.reason = reason;
    return 'approved';
  }
}

/// A key that died with the screen lock: its first signature fails, and a
/// new one is made once it is deleted.
class _DyingStepUpKey extends _StepUpKey {
  int deleted = 0;

  @override
  Future<String> sign(String payloadBase64Url, {required String reason}) async {
    if (deleted == 0) {
      throw NativeKeyException(
        'STEPUP_KEY_INVALIDATED',
        'the lock was removed',
      );
    }
    return super.sign(payloadBase64Url, reason: reason);
  }

  @override
  Future<void> deleteKey() async => deleted += 1;
}

/// A dying key whose first prompt after its replacement is cancelled.
class _CancelledStepUpKey extends _DyingStepUpKey {
  bool cancelled = false;

  @override
  Future<String> sign(String payloadBase64Url, {required String reason}) async {
    if (deleted > 0 && !cancelled) {
      cancelled = true;
      throw NativeKeyException('STEPUP_CANCELLED', 'the person cancelled');
    }
    return super.sign(payloadBase64Url, reason: reason);
  }
}

/// Refuses the first key it is asked for, then makes one.
class _FlakyStepUpKey extends _StepUpKey {
  int attempts = 0;

  @override
  Future<StepUpKeyMetadata> getOrCreateKey({
    required String factor,
    required String mode,
    required int windowSeconds,
  }) async {
    attempts += 1;
    if (attempts == 1) {
      throw NativeKeyException(
        'STEPUP_NO_DEVICE_CREDENTIAL',
        'no screen lock yet',
      );
    }
    return super.getOrCreateKey(
      factor: factor,
      mode: mode,
      windowSeconds: windowSeconds,
    );
  }
}

DeviceTrust _trust(
  _Backend backend, {
  _Store? store,
  _Collector? collector,
  _StepUpKey? stepUpKey,
  Set<PersonalMeasurement> personal = const <PersonalMeasurement>{},
  StepUpOptions? stepUp,
  AppPinOptions? appPin,
  void Function(Map<String, dynamic>)? onRegistered,
}) => DeviceTrust.over(
  backend,
  personalMeasurements: personal,
  stepUp: stepUp,
  appPin: appPin,
  onRegistered: onRegistered,
  store: store ?? _Store(),
  collector: collector ?? _Collector(),
  hintReader: _Hints(),
  stepUpKey: stepUpKey ?? _StepUpKey(),
);

Map<String, dynamic> _decoded(String payload) =>
    jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(payload))))
        as Map<String, dynamic>;

ApiException _refusal(
  String code,
  int status, [
  Map<String, dynamic>? details,
]) => ApiException(code, statusCode: status, code: code, details: details);

/// One approval with the step-up key, for a payment.
Future<RequestProof> _approve(DeviceTrust trust) => trust.signRequest(
  method: 'POST',
  path: '/v1/pay',
  bearer: 'account-session',
  stepUp: true,
);

final Matcher _reenrolPending = throwsA(
  isA<NativeKeyException>().having(
    (NativeKeyException e) => e.code,
    'code',
    'STEPUP_REENROL_PENDING',
  ),
);

void main() {
  setUp(() => debugDefaultTargetPlatformOverride = TargetPlatform.android);
  tearDown(() => debugDefaultTargetPlatformOverride = null);

  test(
    'start registers the key -- with the step-up key -- and proves it',
    () async {
      final _Backend backend = _Backend();
      final DeviceTrust trust = _trust(backend, stepUp: const StepUpOptions());
      await trust.start();
      expect(backend.paths, <String>[
        '/v1/installations/register',
        '/v1/installations/challenge',
        '/v1/installations/verify',
      ]);
      final Map<String, dynamic> registration = backend.calls.first.body;
      expect(registration['installation_id'], 'proposed-id');
      expect(registration['platform'], 'android');
      expect(registration['public_key'], containsPair('kty', 'EC'));
      expect(registration['reinstall_hint'], <String, dynamic>{
        'kind': 'android_id_sha256',
        'value': 'hint',
      });
      expect(
        registration['key_security'],
        containsPair('hardware_backed', true),
      );
      expect(registration['stepup_public_key'], containsPair('x', 'sx'));
      expect(registration['stepup_key_auth'], <String, dynamic>{
        'factor': 'passcode',
        'mode': 'per_use',
        'window_seconds': 0,
      });
      expect(backend.calls[2].body['signature'], 'signed');
      expect(trust.installationSession, 'installation-session');
    },
  );

  test('the installation the backend holds for the key is kept', () async {
    final _Store store = _Store();
    final List<Map<String, dynamic>> answers = <Map<String, dynamic>>[];
    final _Backend backend = _Backend(<String, List<Object>>{
      '/v1/installations/register': <Object>[
        <String, dynamic>{'installation_id': 'held-id', 'more': 1},
      ],
    });
    final DeviceTrust trust = _trust(
      backend,
      store: store,
      onRegistered: answers.add,
    );
    await trust.start();
    expect(trust.identity!.installationId, 'held-id');
    expect(store.saved, 'held-id');
    expect(backend.calls[1].body['installation_id'], 'held-id');
    expect(answers.single, containsPair('more', 1));
  });

  test('a scan: under the installation session, the enabled measurements in '
      "the guide's order, the report id from integrity", () async {
    final _Backend backend = _Backend();
    final _Collector collector = _Collector();
    final DeviceTrust trust = _trust(
      backend,
      collector: collector,
      personal: <PersonalMeasurement>{
        PersonalMeasurement.mockLocation,
        PersonalMeasurement.localAddresses,
      },
    );
    await trust.start();
    final ScanResult scan = await trust.scan();
    expect(collector.enabled, <String>['local_addresses', 'mock_location']);
    final _Call challenge = backend.calls[3];
    expect(challenge.path, '/v1/integrity/challenge');
    expect(challenge.bearer, 'installation-session');
    expect(challenge.body, isEmpty);
    expect(challenge.headers.keys, contains('X-Access-Proof'));
    final _Call report = backend.calls[4];
    expect(report.bearer, 'installation-session');
    final Map<String, dynamic> signed = _decoded(
      report.body['report_payload'] as String,
    );
    expect(signed['challenge_id'], 'scan-challenge');
    expect(signed['enabled_measurements'], <String>[
      'local_addresses',
      'mock_location',
    ]);
    expect(scan.reportId, 'report-1');
  });

  test('the personal measurements change with the app: the next scan '
      'follows, the installation and its step-up key stay', () async {
    final _Backend backend = _Backend();
    final _Collector collector = _Collector();
    final DeviceTrust trust = _trust(
      backend,
      collector: collector,
      stepUp: const StepUpOptions(),
    );
    await trust.start();
    await trust.scan();
    expect(collector.enabled, isEmpty);
    trust.personalMeasurements = <PersonalMeasurement>{
      PersonalMeasurement.location,
      PersonalMeasurement.accessibility,
    };
    await trust.scan();
    expect(collector.enabled, <String>['accessibility', 'location']);
    expect(trust.stepUpKey, isNotNull);
    expect(
      backend.paths.where(
        (String path) => path.startsWith('/v1/installations'),
      ),
      hasLength(3),
    );
  });

  test('re-enrolment: a dead step-up key replaced, its proof bound to the '
      "request proof's nonce, and approvals from then on", () async {
    final _Backend backend = _Backend();
    final _DyingStepUpKey key = _DyingStepUpKey();
    final DeviceTrust trust = _trust(
      backend,
      stepUpKey: key,
      stepUp: const StepUpOptions(),
    );
    await trust.start();
    expect(
      await trust.reenrolStepUp(
        session: 'account-session',
        reauthentication: <String, dynamic>{'password': 'pw'},
      ),
      containsPair('stepup_key_registered', true),
    );
    expect(key.deleted, 1);
    final _Call call = backend.calls.last;
    expect(call.path, '/v1/installations/stepup-key');
    expect(call.bearer, 'account-session');
    expect(call.body['password'], 'pw');
    expect(call.body['stepup_public_key'], containsPair('x', 'sx'));
    expect(call.body['stepup_key_auth'], containsPair('factor', 'passcode'));
    expect(call.body['stepup_key_signature'], 'approved');
    final Map<String, dynamic> proof = _decoded(
      call.body['stepup_key_proof'] as String,
    );
    expect(proof['version'], 1);
    expect(proof['purpose'], 'stepup_reenrol');
    expect(proof['installation_id'], 'proposed-id');
    expect(proof['nonce'], _decoded(call.headers['X-Access-Proof']!)['nonce']);
    final RequestProof approval = await trust.signRequest(
      method: 'POST',
      path: '/v1/pay',
      bearer: 'account-session',
      stepUp: true,
    );
    expect(approval.headers.keys, contains('X-Step-Up-Proof'));
  });

  test('a re-enrolment the backend refused leaves approvals waiting for it, '
      'across a restart too, until a second one succeeds', () async {
    final _Backend backend = _Backend(<String, List<Object>>{
      '/v1/installations/stepup-key': <Object>[
        _refusal('reauthentication_failed', 401),
        <String, dynamic>{'stepup_key_registered': true},
      ],
    });
    final _Store store = _Store();
    final _DyingStepUpKey key = _DyingStepUpKey();
    DeviceTrust started() => _trust(
      backend,
      store: store,
      stepUpKey: key,
      stepUp: const StepUpOptions(),
    );
    final DeviceTrust trust = started();
    await trust.start();
    await expectLater(
      trust.reenrolStepUp(
        session: 'account-session',
        reauthentication: <String, dynamic>{'password': 'wrong'},
      ),
      throwsA(isA<ApiException>()),
    );
    // The dead key is gone and the new one not taken: approvals wait.
    await expectLater(_approve(trust), _reenrolPending);
    expect(trust.stepUpUnavailable?.code, 'STEPUP_REENROL_PENDING');
    final DeviceTrust restarted = started();
    await restarted.start();
    await expectLater(_approve(restarted), _reenrolPending);
    expect(
      await restarted.reenrolStepUp(
        session: 'account-session',
        reauthentication: <String, dynamic>{'password': 'pw'},
      ),
      containsPair('stepup_key_registered', true),
    );
    expect(store.reenrolPending, isFalse);
    expect(restarted.stepUpUnavailable, isNull);
    expect(
      (await _approve(restarted)).headers.keys,
      contains('X-Step-Up-Proof'),
    );
  });

  test('a re-enrolment whose prompt was cancelled, then whose answer was '
      'lost, is finished by the next one', () async {
    final _Backend backend = _Backend(<String, List<Object>>{
      '/v1/installations/stepup-key': <Object>[
        _refusal('bad_gateway', 502),
        <String, dynamic>{'stepup_key_registered': true},
      ],
    });
    final _Store store = _Store();
    final DeviceTrust trust = _trust(
      backend,
      store: store,
      stepUpKey: _CancelledStepUpKey(),
      stepUp: const StepUpOptions(),
    );
    await trust.start();
    Future<Map<String, dynamic>> reenrol() => trust.reenrolStepUp(
      session: 'account-session',
      reauthentication: <String, dynamic>{'password': 'pw'},
    );
    await expectLater(
      reenrol(),
      throwsA(
        isA<NativeKeyException>().having(
          (NativeKeyException e) => e.code,
          'code',
          'STEPUP_CANCELLED',
        ),
      ),
    );
    await expectLater(_approve(trust), _reenrolPending);
    await expectLater(reenrol(), throwsA(isA<ApiException>()));
    await expectLater(_approve(trust), _reenrolPending);
    expect(store.reenrolPending, isTrue);
    expect(await reenrol(), containsPair('stepup_key_registered', true));
    expect(store.reenrolPending, isFalse);
    expect((await _approve(trust)).headers.keys, contains('X-Step-Up-Proof'));
  });

  test(
    'a backend that says it does not hold the step-up key offered leaves '
    'approvals waiting for re-enrolment; one that says it does clears that',
    () async {
      final _Backend backend = _Backend(<String, List<Object>>{
        '/v1/installations/register': <Object>[
          <String, dynamic>{
            'installation_id': 'proposed-id',
            'stepup_key_registered': false,
            'stepup_key_matches': false,
          },
          <String, dynamic>{
            'installation_id': 'proposed-id',
            'stepup_key_registered': true,
            'stepup_key_matches': true,
          },
        ],
      });
      final _Store store = _Store();
      final DeviceTrust trust = _trust(
        backend,
        store: store,
        stepUp: const StepUpOptions(),
      );
      await trust.start();
      expect(trust.stepUpUnavailable?.code, 'STEPUP_REENROL_PENDING');
      await expectLater(_approve(trust), _reenrolPending);
      expect(store.reenrolPending, isTrue);
      await trust.start();
      expect(trust.stepUpUnavailable, isNull);
      expect(store.reenrolPending, isFalse);
      expect((await _approve(trust)).headers.keys, contains('X-Step-Up-Proof'));
    },
  );

  test(
    'a step-up key the phone could not make at registration, made at the '
    'next start, waits for re-enrolment even where the backend says nothing',
    () async {
      final _Backend backend = _Backend();
      final _Store store = _Store();
      final DeviceTrust trust = _trust(
        backend,
        store: store,
        stepUp: const StepUpOptions(),
        stepUpKey: _FlakyStepUpKey(),
      );
      await trust.start();
      expect(trust.stepUpUnavailable?.code, 'STEPUP_NO_DEVICE_CREDENTIAL');
      await trust.start();
      expect(trust.stepUpUnavailable?.code, 'STEPUP_REENROL_PENDING');
      await expectLater(_approve(trust), _reenrolPending);
      expect(
        await trust.reenrolStepUp(
          session: 'account-session',
          reauthentication: <String, dynamic>{'password': 'pw'},
        ),
        containsPair('stepup_key_registered', true),
      );
      expect((await _approve(trust)).headers.keys, contains('X-Step-Up-Proof'));
    },
  );

  test('reset deletes the step-up key with the installation: nothing links '
      'the next installation to this one', () async {
    final _DyingStepUpKey key = _DyingStepUpKey();
    final DeviceTrust trust = _trust(
      _Backend(),
      stepUpKey: key,
      stepUp: const StepUpOptions(),
    );
    await trust.start();
    await trust.reset();
    expect(key.deleted, 1);
    expect(trust.stepUpKey, isNull);
  });

  test('re-enrolment with step-up off refuses before sending', () async {
    final _Backend backend = _Backend();
    final DeviceTrust trust = _trust(backend);
    await trust.start();
    await expectLater(
      trust.reenrolStepUp(session: 'account-session'),
      throwsA(
        isA<NativeKeyException>().having(
          (NativeKeyException e) => e.code,
          'code',
          'STEPUP_OFF',
        ),
      ),
    );
    expect(backend.paths, isNot(contains('/v1/installations/stepup-key')));
  });

  test('a scan for one operation is asked under the account session', () async {
    final _Backend backend = _Backend();
    final DeviceTrust trust = _trust(backend);
    await trust.start();
    final Map<String, dynamic> operation = describeOperation(
      'POST',
      '/v1/pay',
      '{"amount":5}',
    );
    expect(
      () => trust.scan(operation: operation),
      throwsA(isA<ArgumentError>()),
    );
    await trust.scan(session: 'account-session', operation: operation);
    final _Call challenge = backend.calls[3];
    expect(challenge.bearer, 'account-session');
    expect(challenge.body['operation'], operation);
    expect(backend.calls[4].bearer, 'account-session');
  });

  test('an expired installation session is proved again, once; an expired '
      'account session goes to the app', () async {
    final _Backend backend = _Backend(<String, List<Object>>{
      '/v1/integrity/challenge': <Object>[
        _refusal('expired_token', 401),
        <String, dynamic>{
          'challenge_id': 'scan-challenge',
          'nonce': 'bm9uY2U',
          'platform': 'android',
          'required_probes': <String>['app_identity'],
        },
      ],
    });
    final DeviceTrust trust = _trust(backend);
    await trust.start();
    await trust.scan();
    expect(backend.paths.sublist(3), <String>[
      '/v1/integrity/challenge',
      '/v1/installations/challenge',
      '/v1/installations/verify',
      '/v1/integrity/challenge',
      '/v1/integrity/report',
    ]);

    final _Backend account = _Backend(<String, List<Object>>{
      '/v1/integrity/challenge': <Object>[_refusal('expired_token', 401)],
    });
    final DeviceTrust other = _trust(account);
    await other.start();
    await expectLater(
      other.scan(session: 'account-session', operation: <String, dynamic>{}),
      throwsA(
        isA<ApiException>().having(
          (ApiException e) => e.code,
          'code',
          'expired_token',
        ),
      ),
    );
    expect(
      account.paths.where((String p) => p == '/v1/installations/verify'),
      hasLength(1),
    );
  });

  test('a lost installation registers again under the installation session, '
      'never under an account session', () async {
    final _Backend backend = _Backend(<String, List<Object>>{
      '/v1/integrity/challenge': <Object>[
        _refusal('installation_not_found', 404),
        <String, dynamic>{
          'challenge_id': 'scan-challenge',
          'nonce': 'bm9uY2U',
          'platform': 'android',
          'required_probes': <String>['app_identity'],
        },
      ],
    });
    final DeviceTrust trust = _trust(backend);
    await trust.start();
    await trust.scan();
    expect(backend.paths.sublist(3, 7), <String>[
      '/v1/integrity/challenge',
      '/v1/installations/register',
      '/v1/installations/challenge',
      '/v1/installations/verify',
    ]);

    final _Backend account = _Backend(<String, List<Object>>{
      '/v1/integrity/challenge': <Object>[
        _refusal('installation_not_found', 404),
      ],
    });
    final DeviceTrust other = _trust(account);
    await other.start();
    await expectLater(
      other.scan(session: 'account-session', operation: <String, dynamic>{}),
      throwsA(isA<ApiException>()),
    );
    expect(
      account.paths.where((String p) => p == '/v1/installations/register'),
      hasLength(1),
    );
  });

  test('a short wait is waited out once; a long one goes to the app', () async {
    final _Backend backend = _Backend(<String, List<Object>>{
      '/v1/integrity/report': <Object>[
        _refusal('too_many', 429, <String, dynamic>{'retry_after_seconds': 0}),
        <String, dynamic>{
          'integrity': <String, dynamic>{'report_id': 'report-2'},
        },
      ],
    });
    final DeviceTrust trust = _trust(backend);
    await trust.start();
    expect((await trust.scan()).reportId, 'report-2');

    final _Backend slow = _Backend(<String, List<Object>>{
      '/v1/integrity/report': <Object>[
        _refusal('too_many', 429, <String, dynamic>{'retry_after_seconds': 30}),
      ],
    });
    final DeviceTrust other = _trust(slow);
    await other.start();
    await expectLater(other.scan(), throwsA(isA<ApiException>()));
    expect(
      slow.paths.where((String p) => p == '/v1/integrity/report'),
      hasLength(1),
    );
  });

  test('a refusal outside the guide goes to the app as it came', () async {
    final _Backend backend = _Backend(<String, List<Object>>{
      '/v1/installations/register': <Object>[_refusal('try_again_later', 409)],
    });
    await expectLater(
      _trust(backend).start(),
      throwsA(
        isA<ApiException>().having(
          (ApiException e) => e.code,
          'code',
          'try_again_later',
        ),
      ),
    );
    expect(backend.paths, <String>['/v1/installations/register']);
  });

  test(
    'a signed request: the person approves first, the request proof '
    "after on the same nonce; the PIN's proof and the report join it",
    () async {
      final _Backend backend = _Backend(<String, List<Object>>{
        '/v1/pay': <Object>[
          <String, dynamic>{'paid': true},
        ],
      });
      final _StepUpKey key = _StepUpKey();
      final DeviceTrust trust = _trust(
        backend,
        stepUpKey: key,
        stepUp: const StepUpOptions(),
        appPin: const AppPinOptions(),
      );
      await trust.start();
      final RequestProof proof = await trust.signRequest(
        method: 'post',
        path: '/v1/pay',
        bearer: 'account-session',
        body: '{"amount":5}',
        stepUp: true,
        reason: 'Approve the payment',
        appPin: '246810',
        reportId: 'report-1',
      );
      final Map<String, dynamic> access = _decoded(
        proof.headers['X-Access-Proof']!,
      );
      final Map<String, dynamic> stepUp = _decoded(
        proof.headers['X-Step-Up-Proof']!,
      );
      expect(stepUp['nonce'], access['nonce']);
      expect(stepUp['method'], 'POST');
      expect(stepUp['factor'], 'passcode');
      expect(proof.headers['X-Step-Up-Signature'], 'approved');
      expect(key.reason, 'Approve the payment');
      expect(proof.headers['X-App-PIN-Proof'], 'pin-proof');
      expect(proof.headers['X-Integrity-Report'], 'report-1');
      final _Call pin = backend.calls.last;
      expect(pin.path, '/v1/account/app-pin/proof');
      expect(pin.bearer, 'account-session');
      expect(pin.body, <String, dynamic>{
        'pin': '246810',
        'request': <String, dynamic>{
          'method': 'POST',
          'path': '/v1/pay',
          'query': '',
          'body_sha256': crypto.sha256
              .convert(utf8.encode('{"amount":5}'))
              .toString(),
          'nonce': access['nonce'],
        },
      });
      await trust.send(proof);
      expect(backend.calls.last.path, '/v1/pay');
      expect(backend.calls.last.headers, proof.headers);
    },
  );

  test('step-up and the app PIN are options: off, they refuse', () async {
    final DeviceTrust trust = _trust(_Backend());
    await trust.start();
    await expectLater(
      trust.signRequest(method: 'POST', path: '/p', bearer: 'b', stepUp: true),
      throwsA(isA<NativeKeyException>()),
    );
    await expectLater(
      trust.signRequest(method: 'POST', path: '/p', bearer: 'b', appPin: '1'),
      throwsA(isA<StateError>()),
    );
    await expectLater(
      trust.setAppPin(session: 'b', pin: '1'),
      throwsA(isA<StateError>()),
    );
  });

  test('the app PIN is set with the re-authentication the app gives', () async {
    final _Backend backend = _Backend();
    final DeviceTrust trust = _trust(backend, appPin: const AppPinOptions());
    await trust.start();
    await trust.setAppPin(
      session: 'account-session',
      pin: '246810',
      reauthentication: <String, dynamic>{'password': 'secret'},
    );
    expect(backend.calls.last.path, '/v1/account/app-pin');
    expect(backend.calls.last.bearer, 'account-session');
    expect(backend.calls.last.body, <String, dynamic>{
      'password': 'secret',
      'pin': '246810',
    });
  });

  test(
    'a phone that cannot make the step-up key registers without it',
    () async {
      final _Backend backend = _Backend();
      final DeviceTrust trust = _trust(
        backend,
        stepUp: const StepUpOptions(),
        stepUpKey: _StepUpKey(
          refuse: NativeKeyException(
            'STEPUP_NO_DEVICE_CREDENTIAL',
            'no screen lock',
          ),
        ),
      );
      await trust.start();
      expect(
        backend.calls.first.body.containsKey('stepup_public_key'),
        isFalse,
      );
      expect(trust.stepUpUnavailable?.code, 'STEPUP_NO_DEVICE_CREDENTIAL');
      expect(trust.installationSession, 'installation-session');
    },
  );

  test('a step-up key the phone could not make at registration is not made '
      'later for a request, which the backend could not check', () async {
    final _Backend backend = _Backend();
    final _FlakyStepUpKey key = _FlakyStepUpKey();
    final DeviceTrust trust = _trust(
      backend,
      stepUp: const StepUpOptions(),
      stepUpKey: key,
    );
    await trust.start();
    expect(backend.calls.first.body.containsKey('stepup_public_key'), isFalse);
    await expectLater(
      trust.signRequest(method: 'POST', path: '/p', bearer: 'b', stepUp: true),
      throwsA(
        isA<NativeKeyException>().having(
          (NativeKeyException e) => e.code,
          'code',
          'STEPUP_NO_DEVICE_CREDENTIAL',
        ),
      ),
    );
    expect(key.attempts, 1);
  });

  test("the personal measurements are the published contract's", () {
    final Map<String, dynamic> schema =
        jsonDecode(
              repositoryFile(
                'contract/report-1/android-8-ios-5/report.schema.json',
              ).readAsStringSync(),
            )
            as Map<String, dynamic>;
    final Map<String, dynamic> enabled =
        (schema['properties'] as Map<String, dynamic>)['enabled_measurements']
            as Map<String, dynamic>;
    expect(<String>[
      for (final PersonalMeasurement m in PersonalMeasurement.values)
        m.wireName,
    ], (enabled['items'] as Map<String, dynamic>)['enum']);
  });
}
