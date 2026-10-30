/// DeviceTrust: the one object an app configures -- its backend, the
/// personal measurements it enables, step-up and the app PIN -- and what it
/// asks of it: start, scan, and sign a request (the public guide).
library;

import 'dart:async';
import 'dart:convert';

import 'client.dart';
import 'collector.dart';
import 'errors.dart';
import 'installation_key.dart';
import 'installation_store.dart';
import 'protocol.dart';
import 'reinstall_hint.dart';
import 'report.dart';
import 'request_proof.dart';
import 'request_proof.dart' as proofs show signRequest;
import 'step_up_key.dart';
import 'transport.dart';

/// The personal measurements an app may enable (the public guide, section
/// 8). Each is collected only when the backend asks for it as well -- the
/// location only with the person's permission too.
enum PersonalMeasurement {
  localAddresses('local_addresses'),
  accessibility('accessibility'),
  notificationAccess('notification_access'),
  otherAccess('other_access'),
  screenCapture('screen_capture'),
  location('location'),
  mockLocation('mock_location');

  const PersonalMeasurement(this.wireName);

  /// The name the report and the backend use.
  final String wireName;
}

/// Where the backend takes the app PIN's two calls (the public guide,
/// section 4).
class AppPinOptions {
  const AppPinOptions({
    this.path = DeviceTrustClient.appPinPath,
    this.proofPath = DeviceTrustClient.appPinProofPath,
  });

  final String path;
  final String proofPath;
}

/// One scan: the challenge it answered, the report as signed, and the
/// backend's answer, whole.
class ScanResult {
  const ScanResult({
    required this.challenge,
    required this.report,
    required this.answer,
  });

  final ScanChallenge challenge;
  final SignedReport report;
  final Map<String, dynamic> answer;

  /// The stored report (`integrity.report_id`), which a scan made for one
  /// request sends back with that request.
  String? get reportId {
    final Object? integrity = answer['integrity'];
    final Object? id = integrity is Map ? integrity['report_id'] : null;
    return id is String ? id : null;
  }
}

class DeviceTrust {
  /// Talks to your backend over JSON and HTTPS under [baseUrl], the plugin's
  /// default API (the public guide, section 4).
  DeviceTrust({
    required String baseUrl,
    Set<PersonalMeasurement> personalMeasurements =
        const <PersonalMeasurement>{},
    StepUpOptions? stepUp,
    AppPinOptions? appPin,
    FutureOr<void> Function(Map<String, dynamic> answer)? onRegistered,
  }) : this.over(
         HttpTransport(baseUrl),
         personalMeasurements: personalMeasurements,
         stepUp: stepUp,
         appPin: appPin,
         onRegistered: onRegistered,
       );

  /// The same over the app's own [transport]; [store], [collector],
  /// [hintReader] and [stepUpKey] replace the native ones in tests.
  DeviceTrust.over(
    DeviceTrustTransport transport, {
    this.personalMeasurements = const <PersonalMeasurement>{},
    this.stepUp,
    this.appPin,
    this.onRegistered,
    InstallationStore? store,
    NativeIntegrityCollector? collector,
    ReinstallHintReader? hintReader,
    NativeStepUpKey? stepUpKey,
  }) : client = DeviceTrustClient(transport),
       _store = store ?? InstallationStore(),
       _collector = collector ?? NativeIntegrityCollector(),
       _hintReader = hintReader ?? ReinstallHintReader(),
       _stepUpKey = stepUpKey ?? NativeStepUpKey();

  /// The guide's calls, for an app that makes them itself.
  final DeviceTrustClient client;

  /// What this app enables; the backend asks for what it needs of them. The
  /// app may change it whenever the person does -- in a privacy setting, say:
  /// the next scan measures what it holds then, and the installation, its
  /// session and its step-up key stay as they are.
  Set<PersonalMeasurement> personalMeasurements;

  /// How the step-up key is made, or null for no step-up. An app that takes
  /// these from its backend sets them before [start].
  StepUpOptions? stepUp;

  /// The app PIN's calls, or null for no app PIN.
  final AppPinOptions? appPin;

  /// Every registration's answer, whole -- also those made again inside a
  /// scan, when the backend had lost the installation -- awaited before the
  /// installation goes on.
  final FutureOr<void> Function(Map<String, dynamic> answer)? onRegistered;

  final InstallationStore _store;
  final NativeIntegrityCollector _collector;
  final ReinstallHintReader _hintReader;
  final NativeStepUpKey _stepUpKey;

  InstallationIdentity? _identity;
  String? _session;

  // One call of each kind in flight; a second waits for the first's result.
  Future<InstallationIdentity>? _loading;
  Future<InstallationIdentity>? _starting;
  Future<String>? _proving;
  final Map<String, Future<ScanResult>> _scanning =
      <String, Future<ScanResult>>{};

  // Which installation the calls running now belong to: reset() and close()
  // move on to the next, and a call of an earlier one keeps nothing it finds.
  int _generation = 0;
  // A reset's deletion, which every later load waits for; and the
  // installation ID being saved and a re-enrolment, which a reset waits for.
  Future<void>? _resetting;
  Future<void>? _saving;
  Future<void>? _reenrolling;
  StepUpKeyMetadata? _offeredStepUpKey;
  ReinstallHint? _hint;
  bool _hintRead = false;

  /// Why step-up is off on this phone although the app turned it on -- no
  /// screen lock, say -- or null.
  NativeKeyException? stepUpUnavailable;

  InstallationIdentity? get identity => _identity;

  /// The installation session from proving the key, or null before [start].
  String? get installationSession => _session;

  /// The step-up key offered at the last registration.
  StepUpKeyMetadata? get stepUpKey => _offeredStepUpKey;

  /// The wire names of [personalMeasurements], in the guide's order.
  List<String> get enabledMeasurements => <String>[
    for (final PersonalMeasurement measurement in PersonalMeasurement.values)
      if (personalMeasurements.contains(measurement)) measurement.wireName,
  ];

  /// The installation: its key, made on first use, and its ID. A key made
  /// now is a new installation ([InstallationIdentity.createdThisLaunch]):
  /// whatever the app kept for the one before belongs to that one. Calls at
  /// once share one load, so one key gets one ID.
  Future<InstallationIdentity> loadIdentity() {
    final InstallationIdentity? known = _identity;
    if (known != null) {
      return Future<InstallationIdentity>.value(known);
    }
    final Future<InstallationIdentity>? running = _loading;
    if (running != null) {
      return running;
    }
    late final Future<InstallationIdentity> loading;
    loading = _load().whenComplete(() {
      if (identical(_loading, loading)) {
        _loading = null;
      }
    });
    return _loading = loading;
  }

  Future<InstallationIdentity> _load() async {
    // A reset's deletion first, so that nothing loads the key it deletes.
    await _resetting;
    final int generation = _generation;
    final InstallationIdentity loaded = await _store.loadOrCreate();
    _current(generation);
    return _identity ??= loaded;
  }

  /// Throws when reset() or close() ended the installation [generation]
  /// belongs to: a call keeps nothing of one that is gone.
  void _current(int generation) {
    if (generation != _generation) {
      throw InterruptedCallException(
        'The installation was reset, or the client closed, while this call '
        'ran: nothing it found was kept.',
      );
    }
  }

  /// Loads or makes the key, registers it -- with the step-up key, when
  /// step-up is on -- and proves the installation holds it: the
  /// installation session. A refusal outside the guide's protocol errors
  /// goes to the app as it came. A second call while one runs gets its
  /// result.
  Future<InstallationIdentity> start() {
    final Future<InstallationIdentity>? running = _starting;
    if (running != null) {
      return running;
    }
    late final Future<InstallationIdentity> starting;
    starting = _start().whenComplete(() {
      if (identical(_starting, starting)) {
        _starting = null;
      }
    });
    return _starting = starting;
  }

  Future<InstallationIdentity> _start() async {
    final int generation = _generation;
    await loadIdentity();
    await _register(generation);
    await prove();
    _current(generation);
    return _identity!;
  }

  /// A new installation session: the key's challenge, answered. A second
  /// call while one runs gets its result.
  Future<String> prove() {
    final Future<String>? running = _proving;
    if (running != null) {
      return running;
    }
    late final Future<String> proving;
    proving = _prove(_generation, retried: false).whenComplete(() {
      if (identical(_proving, proving)) {
        _proving = null;
      }
    });
    return _proving = proving;
  }

  /// Deletes the key, the installation ID (InstallationStore.clear) and the
  /// step-up key, and forgets the session: the next start is a new
  /// installation, linked to this one by nothing it holds. Calls still
  /// running end with InterruptedCallException and keep nothing; calls made
  /// from now on wait for the deletion, and never join one made before.
  Future<void> reset() {
    final Future<InstallationIdentity>? loading = _loading;
    final Future<void>? saving = _saving;
    final Future<void>? reenrolling = _reenrolling;
    final Future<void>? earlier = _resetting;
    _endCalls();
    _offeredStepUpKey = null;
    _hint = null;
    _hintRead = false;
    final Future<void> deleting = () async {
      await earlier;
      // A load or a save still running finishes first, so that nothing it
      // writes outlives the deletion.
      // So does a re-enrolment: its key, which a backend may already have
      // taken, is deleted after it, and the marker it writes is cleared.
      await Future.wait(<Future<void>>[
        if (loading != null) loading.then<void>((_) {}, onError: (_) {}),
        if (saving != null) saving.then<void>((_) {}, onError: (_) {}),
        ?reenrolling,
      ]);
      await _store.clear();
      // The step-up key goes with the installation, as on a reinstall: kept,
      // it would link the next installation to this one.
      try {
        await _stepUpKey.deleteKey();
      } catch (_) {
        // Best effort: none to delete, none this phone can make, or no
        // native side at all; the installation itself is gone either way.
      }
    }();
    // Later loads wait for the deletion, whatever came of it; the caller of
    // reset hears what did.
    _resetting = deleting.then<void>((_) {}, onError: (_) {});
    return deleting;
  }

  /// Moves on to the next installation: the calls running now keep nothing,
  /// and the next ones start afresh.
  void _endCalls() {
    _generation++;
    _identity = null;
    _session = null;
    _loading = null;
    _starting = null;
    _proving = null;
    _scanning.clear();
  }

  Future<String> _prove(int generation, {required bool retried}) async {
    final InstallationIdentity identity = await loadIdentity();
    _current(generation);
    try {
      final Map<String, dynamic> challenge = await client
          .createInstallationChallenge(identity.installationId);
      final String payload = challenge['payload'] as String;
      final Map<String, dynamic> verified = await client.verifyInstallation(
        installationId: identity.installationId,
        challengeId: challenge['challenge_id'] as String,
        payload: payload,
        signature: await identity.signPayload(payload),
      );
      _current(generation);
      return _session = verified['device_token'] as String;
    } on ApiException catch (error) {
      if (retried) {
        rethrow;
      }
      switch (protocolStepFor(error, deviceSession: true)) {
        case ProtocolStep.askAgain:
          break;
        case ProtocolStep.registerAgain:
          await _register(generation);
        case ProtocolStep.waitThenRetry:
          await Future<void>.delayed(protocolWait(error)!);
        case ProtocolStep.proveAgain:
        case ProtocolStep.stop:
          rethrow;
      }
      return _prove(generation, retried: true);
    }
  }

  Future<void> _register(int generation) async {
    final InstallationIdentity identity = await loadIdentity();
    _current(generation);
    if (!_hintRead) {
      final ReinstallHint? hint = await _hintReader.read();
      _current(generation);
      _hint = hint;
      _hintRead = true;
    }
    final StepUpKeyMetadata? offered = await _prepareStepUpKey(generation);
    final Map<String, dynamic> answer = await client.registerInstallation(
      identity,
      _hint,
      stepUpKey: offered,
    );
    _current(generation);
    // The key is the installation's identity: a backend that holds it under
    // another ID answers with that one, which is kept.
    final Object? held = answer['installation_id'];
    if (held is String && held.isNotEmpty && held != identity.installationId) {
      _identity = identity.withInstallationId(held);
      final Future<void> saving = _store.saveInstallationId(held);
      _saving = saving;
      await saving;
    }
    await _settleStepUpKey(answer, offered, generation);
    await onRegistered?.call(answer);
  }

  /// Whether the backend holds the step-up key offered: it takes one only
  /// when it first registers an installation, so a key made later -- after the
  /// screen lock was removed and set again, say -- it takes by re-enrolment
  /// alone. Its answer says so (`stepup_key_matches`, or for an installation
  /// new to it `stepup_key_registered`); until it holds this key, approvals
  /// wait for reenrolStepUp, across restarts too. A registration without a
  /// key, the phone unable to make one, leaves any key made later waiting the
  /// same way. A backend whose answer says nothing is taken at its word unless
  /// a re-enrolment is pending.
  Future<void> _settleStepUpKey(
    Map<String, dynamic> answer,
    StepUpKeyMetadata? offered,
    int generation,
  ) async {
    if (stepUp == null) {
      return;
    }
    final Object? matches = answer['stepup_key_matches'];
    final Object? registered = answer['stepup_key_registered'];
    final bool? bound = offered == null
        ? null
        : matches is bool
        ? matches
        : registered is bool
        ? registered
        : null;
    if (offered == null || bound == false) {
      await _store.setStepUpReenrolPending(true);
    } else if (bound == true) {
      await _store.setStepUpReenrolPending(false);
    }
    final bool pending =
        offered != null && bound != true && await _store.stepUpReenrolPending();
    _current(generation);
    if (pending) {
      _offeredStepUpKey = null;
      stepUpUnavailable = _reenrolPending();
    }
  }

  /// The step-up key as [stepUp] asks: an existing key is kept as it is.
  /// Step-up is optional, so a key the phone cannot make leaves it off. Its
  /// use waits for the backend's answer (_settleStepUpKey).
  Future<StepUpKeyMetadata?> _prepareStepUpKey(int generation) async {
    final StepUpOptions? options = stepUp;
    if (options == null) {
      stepUpUnavailable = null;
      return _offeredStepUpKey = null;
    }
    _stepUpKey.configuredMode = options.mode;
    StepUpKeyMetadata? key;
    NativeKeyException? unavailable;
    try {
      key = await _stepUpKey.getOrCreateKey(
        factor: options.factor,
        mode: options.mode,
        windowSeconds: options.windowSeconds,
      );
    } on NativeKeyException catch (error) {
      unavailable = error;
    }
    _current(generation);
    stepUpUnavailable = unavailable;
    return _offeredStepUpKey = key;
  }

  /// What approvals answer while the backend does not hold the step-up key.
  static NativeKeyException _reenrolPending() => NativeKeyException(
    'STEPUP_REENROL_PENDING',
    'The backend does not hold this step-up key -- a re-enrolment unfinished, '
        'or a key made after the installation was registered: '
        'reenrolStepUp() first.',
  );

  /// A scan: under the installation session -- or, for a scan that approves
  /// one [operation] ([describeOperation]), under the app's account
  /// [session] for this installation, the one that will send that request.
  /// The guide's protocol errors are acted on once; an account session is
  /// the app's to renew. A second call for the same scan while one runs gets
  /// its result; a scan whose answer was lost is simply asked for again.
  Future<ScanResult> scan({String? session, Map<String, dynamic>? operation}) {
    if (operation != null && session == null) {
      throw ArgumentError.value(
        session,
        'session',
        'a scan for one operation is asked under the account session that '
            'will send it',
      );
    }
    // The personal measurements enabled now are part of the scan: one asked
    // for after the person changed them never joins one asked for before.
    final List<String> enabled = enabledMeasurements;
    final String kind = jsonEncode(<Object?>[session, operation, enabled]);
    final Future<ScanResult>? running = _scanning[kind];
    if (running != null) {
      return running;
    }
    late final Future<ScanResult> scanning;
    scanning = _scan(_generation, session, operation, enabled).whenComplete(() {
      if (identical(_scanning[kind], scanning)) {
        _scanning.remove(kind);
      }
    });
    return _scanning[kind] = scanning;
  }

  Future<ScanResult> _scan(
    int generation,
    String? session,
    Map<String, dynamic>? operation,
    List<String> enabled,
  ) async {
    try {
      return await _scanOnce(generation, session, operation, enabled);
    } on ApiException catch (error) {
      final bool installationSession = session == null;
      switch (protocolStepFor(error, deviceSession: installationSession)) {
        case ProtocolStep.askAgain:
          break;
        case ProtocolStep.proveAgain:
          await prove();
        case ProtocolStep.registerAgain:
          // An account session belongs to the installation the backend lost:
          // the app signs in again.
          if (!installationSession) {
            rethrow;
          }
          await _register(generation);
          await prove();
        case ProtocolStep.waitThenRetry:
          await Future<void>.delayed(protocolWait(error)!);
        case ProtocolStep.stop:
          rethrow;
      }
      return _scanOnce(generation, session, operation, enabled);
    }
  }

  Future<ScanResult> _scanOnce(
    int generation,
    String? session,
    Map<String, dynamic>? operation,
    List<String> enabled,
  ) async {
    final InstallationIdentity identity = await loadIdentity();
    final String bearer = session ?? _session ?? await prove();
    _current(generation);
    final ScanChallenge challenge = await client.integrityChallenge(
      session: bearer,
      identity: identity,
      operation: operation,
    );
    final SignedReport report = await collectReport(
      challenge: challenge,
      identity: identity,
      collector: _collector,
      enabledMeasurements: enabled,
    );
    // A report of an installation reset meanwhile is never sent.
    _current(generation);
    final Map<String, dynamic> answer = await client.submitIntegrityReport(
      session: bearer,
      identity: identity,
      report: report,
    );
    _current(generation);
    return ScanResult(challenge: challenge, report: report, answer: answer);
  }

  /// Signs one request to your backend under [bearer], your account session:
  /// [body] is sent exactly as given. With [stepUp] the person approves it
  /// with the step-up key -- the phone asks, saying [reason]; with [appPin]
  /// the backend checks the PIN for it first; [reportId] names the scan made
  /// for it alone. Send it with RequestProof.headers beside
  /// `Authorization: Bearer`, or with [send]; each proof serves this request
  /// once.
  Future<RequestProof> signRequest({
    required String method,
    required String path,
    required String bearer,
    String body = '',
    bool stepUp = false,
    String reason = 'Approve this request',
    String? appPin,
    String? reportId,
  }) async {
    final InstallationIdentity identity = await loadIdentity();
    StepUpApproval? approval;
    if (stepUp) {
      // Only the key the backend received at registration: a key made later
      // would sign approvals the backend cannot check.
      final StepUpKeyMetadata? key = _offeredStepUpKey;
      if (key == null) {
        throw stepUpUnavailable ??
            NativeKeyException(
              'STEPUP_OFF',
              this.stepUp == null
                  ? 'Step-up is off: DeviceTrust(stepUp: StepUpOptions(...)).'
                  : 'No step-up key was registered: start() first.',
            );
      }
      approval = StepUpApproval(
        factor: key.factor,
        sign: (String payload) => _stepUpKey.sign(payload, reason: reason),
      );
    }
    RequestProof proof = await proofs.signRequest(
      identity: identity,
      method: method,
      path: path,
      bearerToken: bearer,
      encodedBody: body,
      stepUp: approval,
    );
    if (appPin != null) {
      final AppPinOptions? options = this.appPin;
      if (options == null) {
        throw StateError(
          'The app PIN is off: DeviceTrust(appPin: const AppPinOptions()).',
        );
      }
      proof = await client.proveAppPin(
        session: bearer,
        identity: identity,
        pin: appPin,
        request: proof,
        path: options.proofPath,
      );
    }
    return reportId == null ? proof : proof.withIntegrityReport(reportId);
  }

  /// Re-enrols the step-up key under the account [session], with the
  /// person's own [reauthentication] -- the account's password, say:
  /// `{'password': ...}`. For a key the phone has lost or can no longer use
  /// -- the screen lock removed (`STEPUP_KEY_INVALIDATED`) -- or one made for
  /// other options: the person unlocks the new key to sign its proof, the
  /// phone showing [reason], and the backend takes it for that account alone
  /// (the public guide, section 3). Approvals use it from then on. A key
  /// replaced before the backend took the new one -- the person cancelled,
  /// the password was wrong, the answer was lost -- leaves step-up waiting:
  /// approvals answer `STEPUP_REENROL_PENDING`, across restarts too, until a
  /// call of this succeeds.
  Future<Map<String, dynamic>> reenrolStepUp({
    required String session,
    Map<String, dynamic> reauthentication = const <String, dynamic>{},
    String reason = 'Confirm your new step-up key',
  }) {
    final Future<Map<String, dynamic>> running = _reenrolStepUp(
      session,
      reauthentication,
      reason,
    );
    // reset() waits for it, whatever comes of it.
    _reenrolling = running.then<void>((_) {}, onError: (_) {});
    return running;
  }

  Future<Map<String, dynamic>> _reenrolStepUp(
    String session,
    Map<String, dynamic> reauthentication,
    String reason,
  ) async {
    final StepUpOptions? options = stepUp;
    if (options == null) {
      throw NativeKeyException(
        'STEPUP_OFF',
        'Step-up is off: DeviceTrust(stepUp: StepUpOptions(...)).',
      );
    }
    final int generation = _generation;
    final InstallationIdentity identity = await loadIdentity();
    _current(generation);
    _stepUpKey.configuredMode = options.mode;
    Future<StepUpKeyMetadata> newKey({required bool replace}) async {
      if (replace) {
        // From here the phone's key and the backend's differ until the
        // backend takes the new one: approvals wait for that.
        _current(generation);
        await _store.setStepUpReenrolPending(true);
        _current(generation);
        _offeredStepUpKey = null;
        stepUpUnavailable = _reenrolPending();
        await _stepUpKey.deleteKey();
      }
      return _stepUpKey.getOrCreateKey(
        factor: options.factor,
        mode: options.mode,
        windowSeconds: options.windowSeconds,
      );
    }

    StepUpKeyMetadata key = await newKey(replace: false);
    if (!key.created && !options.accepts(key)) {
      key = await newKey(replace: true);
    }
    // The new key signs a proof bound to this request's own nonce, which the
    // request proof then signs too.
    final List<int> nonce = freshNonce();
    Future<Map<String, String>> proveWith(StepUpKeyMetadata current) async {
      final String payload = stepUpReenrolProof(
        installationId: identity.installationId,
        stepUpKeyThumbprint: current.thumbprint,
        nonce: base64UrlNoPadding(nonce),
        timestamp: DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
      );
      return <String, String>{
        'stepup_key_proof': payload,
        'stepup_key_signature': await _stepUpKey.sign(payload, reason: reason),
      };
    }

    Map<String, String> keyProof;
    try {
      keyProof = await proveWith(key);
    } on NativeKeyException catch (error) {
      // A key that died with the screen lock is found only when it signs.
      if (error.code != 'STEPUP_KEY_INVALIDATED' &&
          error.code != 'STEPUP_KEY_NOT_FOUND') {
        rethrow;
      }
      key = await newKey(replace: true);
      keyProof = await proveWith(key);
    }
    final RequestProof proof = await proofs.signRequest(
      identity: identity,
      method: 'POST',
      path: options.reenrolPath,
      bearerToken: session,
      encodedBody: jsonEncode(<String, dynamic>{
        ...reauthentication,
        'stepup_public_key': key.publicKey,
        'stepup_key_auth': key.authJson,
        ...keyProof,
      }),
      nonce: nonce,
    );
    final Map<String, dynamic> answer = await send(proof);
    _current(generation);
    await _store.setStepUpReenrolPending(false);
    _current(generation);
    _offeredStepUpKey = key;
    stepUpUnavailable = null;
    return answer;
  }

  /// Sends [proof]'s request through the plugin's transport.
  Future<Map<String, dynamic>> send(RequestProof proof) =>
      client.sendSigned(proof);

  /// Sets the account's app PIN under the account [session], with the
  /// person's own [reauthentication] -- the account's password, say:
  /// `{'password': ...}`.
  Future<Map<String, dynamic>> setAppPin({
    required String session,
    required String pin,
    Map<String, dynamic> reauthentication = const <String, dynamic>{},
  }) async {
    final AppPinOptions? options = appPin;
    if (options == null) {
      throw StateError(
        'The app PIN is off: DeviceTrust(appPin: const AppPinOptions()).',
      );
    }
    return client.setAppPin(
      session: session,
      identity: await loadIdentity(),
      pin: pin,
      reauthentication: reauthentication,
      path: options.path,
    );
  }

  /// Asks the person for the location permission, for the location
  /// measurements: from a button on the app's own screen, since a scan never
  /// asks. Answers `precise`, `approximate` or `none`.
  Future<String> requestLocationPermission() =>
      _collector.requestLocationPermission();

  /// Closes the transport. Calls still running end with
  /// InterruptedCallException, or with the transport's own failure, and keep
  /// nothing; the key and the installation stay as they are.
  void close() {
    _endCalls();
    client.close();
  }
}
