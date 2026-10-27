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
  /// Device trust over JSON and HTTPS under [baseUrl], the plugin's default
  /// API (the public guide, section 4).
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

  /// What this app enables; the backend asks for what it needs of them.
  final Set<PersonalMeasurement> personalMeasurements;

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
  Future<InstallationIdentity>? _starting;
  Future<String>? _proving;
  final Map<String, Future<ScanResult>> _scanning =
      <String, Future<ScanResult>>{};
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
  /// whatever the app kept for the one before belongs to that one.
  Future<InstallationIdentity> loadIdentity() async =>
      _identity ??= await _store.loadOrCreate();

  /// Loads or makes the key, registers it -- with the step-up key, when
  /// step-up is on -- and proves the installation holds it: the
  /// installation session. A refusal outside the guide's protocol errors
  /// goes to the app as it came. A second call while one runs gets its
  /// result.
  Future<InstallationIdentity> start() =>
      _starting ??= _start().whenComplete(() => _starting = null);

  Future<InstallationIdentity> _start() async {
    await loadIdentity();
    await _register();
    await prove();
    return _identity!;
  }

  /// A new installation session: the key's challenge, answered. A second
  /// call while one runs gets its result.
  Future<String> prove() =>
      _proving ??= _prove(retried: false).whenComplete(() => _proving = null);

  /// Deletes the key and the installation ID (InstallationStore.clear) and
  /// forgets the session: the next start is a new installation.
  Future<void> reset() async {
    await _store.clear();
    _identity = null;
    _session = null;
    _offeredStepUpKey = null;
    _hint = null;
    _hintRead = false;
  }

  Future<String> _prove({required bool retried}) async {
    final InstallationIdentity identity = await loadIdentity();
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
      return _session = verified['device_token'] as String;
    } on ApiException catch (error) {
      if (retried) {
        rethrow;
      }
      switch (protocolStepFor(error, deviceSession: true)) {
        case ProtocolStep.askAgain:
          break;
        case ProtocolStep.registerAgain:
          await _register();
        case ProtocolStep.waitThenRetry:
          await Future<void>.delayed(protocolWait(error)!);
        case ProtocolStep.proveAgain:
        case ProtocolStep.stop:
          rethrow;
      }
      return _prove(retried: true);
    }
  }

  Future<void> _register() async {
    final InstallationIdentity identity = await loadIdentity();
    if (!_hintRead) {
      _hint = await _hintReader.read();
      _hintRead = true;
    }
    final Map<String, dynamic> answer = await client.registerInstallation(
      identity,
      _hint,
      stepUpKey: await _prepareStepUpKey(),
    );
    // The key is the installation's identity: a backend that holds it under
    // another ID answers with that one, which is kept.
    final Object? held = answer['installation_id'];
    if (held is String && held.isNotEmpty && held != identity.installationId) {
      _identity = identity.withInstallationId(held);
      await _store.saveInstallationId(held);
    }
    await onRegistered?.call(answer);
  }

  /// The step-up key as [stepUp] asks: an existing key is kept as it is.
  /// Step-up is optional, so a key the phone cannot make leaves it off.
  Future<StepUpKeyMetadata?> _prepareStepUpKey() async {
    final StepUpOptions? options = stepUp;
    stepUpUnavailable = null;
    if (options == null) {
      return _offeredStepUpKey = null;
    }
    _stepUpKey.configuredMode = options.mode;
    try {
      return _offeredStepUpKey = await _stepUpKey.getOrCreateKey(
        factor: options.factor,
        mode: options.mode,
        windowSeconds: options.windowSeconds,
      );
    } on NativeKeyException catch (error) {
      stepUpUnavailable = error;
      return _offeredStepUpKey = null;
    }
  }

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
    final String kind = jsonEncode(<Object?>[session, operation]);
    // A block, not an arrow: remove() answers the very future whenComplete
    // would then wait for.
    return _scanning[kind] ??= _scan(session, operation).whenComplete(() {
      _scanning.remove(kind);
    });
  }

  Future<ScanResult> _scan(
    String? session,
    Map<String, dynamic>? operation,
  ) async {
    try {
      return await _scanOnce(session, operation);
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
          await _register();
          await prove();
        case ProtocolStep.waitThenRetry:
          await Future<void>.delayed(protocolWait(error)!);
        case ProtocolStep.stop:
          rethrow;
      }
      return _scanOnce(session, operation);
    }
  }

  Future<ScanResult> _scanOnce(
    String? session,
    Map<String, dynamic>? operation,
  ) async {
    final InstallationIdentity identity = await loadIdentity();
    final String bearer = session ?? _session ?? await prove();
    final ScanChallenge challenge = await client.integrityChallenge(
      session: bearer,
      identity: identity,
      operation: operation,
    );
    final SignedReport report = await collectReport(
      challenge: challenge,
      identity: identity,
      collector: _collector,
      enabledMeasurements: enabledMeasurements,
    );
    return ScanResult(
      challenge: challenge,
      report: report,
      answer: await client.submitIntegrityReport(
        session: bearer,
        identity: identity,
        report: report,
      ),
    );
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

  void close() => client.close();
}
