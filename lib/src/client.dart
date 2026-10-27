/// The public guide's five calls (section 4) over a [DeviceTrustTransport],
/// the two scan calls each with its request proof (section 3), and the app
/// PIN's two calls.
library;

import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'errors.dart';
import 'installation_key.dart';
import 'reinstall_hint.dart';
import 'report.dart';
import 'request_proof.dart';
import 'step_up_key.dart';
import 'transport.dart';

class DeviceTrustClient {
  DeviceTrustClient(this.transport);

  final DeviceTrustTransport transport;

  /// The app PIN's default paths (the public guide, section 4).
  static const String appPinPath = '/v1/account/app-pin';
  static const String appPinProofPath = '/v1/account/app-pin/proof';

  /// The fields of the guide's registration, which [registerInstallation]'s
  /// `extra` cannot replace.
  static const Set<String> registrationFields = <String>{
    'installation_id',
    'platform',
    'public_key',
    'reinstall_hint',
    'key_security',
    'stepup_public_key',
    'stepup_key_auth',
  };

  /// Sends [proof]'s request. [method], [path] and [encodedBody] replace what
  /// the proof was signed for -- only to test that a backend refuses them.
  Future<Map<String, dynamic>> sendSigned(
    RequestProof proof, {
    String? method,
    String? path,
    String? encodedBody,
  }) {
    final String sentMethod = (method ?? proof.method).toUpperCase();
    return transport.send(
      sentMethod,
      path ?? proof.path,
      bearerToken: proof.bearerToken,
      encodedBody: sentMethod == 'GET'
          ? null
          : (encodedBody ?? proof.encodedBody),
      headers: proof.headers,
    );
  }

  /// Signs and sends one request under [bearerToken], its [body] as JSON.
  /// [installationId] replaces the installation the proof names, only to test
  /// that a backend refuses it.
  Future<Map<String, dynamic>> signAndSend(
    String method,
    String path, {
    required String bearerToken,
    required InstallationIdentity identity,
    Map<String, dynamic>? body,
    String? installationId,
  }) async {
    return sendSigned(
      await signRequest(
        identity: identity,
        method: method,
        path: path,
        bearerToken: bearerToken,
        encodedBody: jsonEncode(body ?? <String, dynamic>{}),
        installationId: installationId,
      ),
    );
  }

  /// Registers the installation's key, and with [stepUpKey] the step-up key.
  /// The answer's `installation_id` is the installation your backend holds
  /// for this key, which may not be the one proposed. [extra] adds fields of
  /// your backend's own.
  Future<Map<String, dynamic>> registerInstallation(
    InstallationIdentity identity,
    ReinstallHint? hint, {
    StepUpKeyMetadata? stepUpKey,
    Map<String, dynamic> extra = const <String, dynamic>{},
  }) {
    final Iterable<String> replaced = extra.keys.where(
      registrationFields.contains,
    );
    if (replaced.isNotEmpty) {
      throw ArgumentError.value(
        extra,
        'extra',
        'replaces the registration fields ${replaced.join(', ')}',
      );
    }
    return transport.send(
      'POST',
      '/v1/installations/register',
      encodedBody: jsonEncode(<String, dynamic>{
        'installation_id': identity.installationId,
        'platform': defaultTargetPlatform == TargetPlatform.android
            ? 'android'
            : 'ios',
        'public_key': identity.publicKeyJson,
        'reinstall_hint': hint?.toJson(),
        // What the platform's keystore says about how the key is protected:
        // a claim, not proof. Its value is comparative -- a non-exportable
        // hardware key cannot move into software, so the same key later
        // claiming a weaker level contradicts itself.
        'key_security': <String, dynamic>{
          'security_level': identity.securityLevel,
          'hardware_backed': identity.hardwareBacked,
          'provider': identity.provider,
        },
        // The step-up key, and how the phone says it is unlocked: also a
        // claim, recorded and compared with what the backend requires.
        if (stepUpKey != null) 'stepup_public_key': stepUpKey.publicKey,
        if (stepUpKey != null) 'stepup_key_auth': stepUpKey.authJson,
        ...extra,
      }),
    );
  }

  /// Asks for a key challenge: `challenge_id` and the `payload` to sign.
  Future<Map<String, dynamic>> createInstallationChallenge(
    String installationId,
  ) {
    return transport.send(
      'POST',
      '/v1/installations/challenge',
      encodedBody: jsonEncode(<String, dynamic>{
        'installation_id': installationId,
      }),
    );
  }

  /// Answers a key challenge; the answer carries `device_token`, your
  /// backend's session for this installation.
  Future<Map<String, dynamic>> verifyInstallation({
    required String installationId,
    required String challengeId,
    required String payload,
    required String signature,
  }) {
    return transport.send(
      'POST',
      '/v1/installations/verify',
      encodedBody: jsonEncode(<String, dynamic>{
        'installation_id': installationId,
        'challenge_id': challengeId,
        'payload': payload,
        'signature': signature,
      }),
    );
  }

  /// Asks for a scan under [session]: the installation's session, from
  /// [verifyInstallation] -- or, for a scan that approves one [operation]
  /// ([describeOperation]), your account session for this installation.
  Future<ScanChallenge> integrityChallenge({
    required String session,
    required InstallationIdentity identity,
    Map<String, dynamic>? operation,
  }) async {
    return ScanChallenge.fromJson(
      await signAndSend(
        'POST',
        '/v1/integrity/challenge',
        bearerToken: session,
        identity: identity,
        body: <String, dynamic>{'operation': ?operation},
      ),
    );
  }

  /// Sends [report] under the [session] that asked for its scan. The answer
  /// is your backend's own; for a scan that approves one request it carries
  /// `report_id`, sent with that request as `X-Integrity-Report`.
  Future<Map<String, dynamic>> submitIntegrityReport({
    required String session,
    required InstallationIdentity identity,
    required SignedReport report,
  }) {
    return signAndSend(
      'POST',
      '/v1/integrity/report',
      bearerToken: session,
      identity: identity,
      body: report.toJson(),
    );
  }

  /// Sets the account's app PIN under its account [session]. The backend
  /// requires the person's own re-authentication with it -- [reauthentication]
  /// carries it, the account's password for example: `{'password': ...}`.
  Future<Map<String, dynamic>> setAppPin({
    required String session,
    required InstallationIdentity identity,
    required String pin,
    Map<String, dynamic> reauthentication = const <String, dynamic>{},
    String path = appPinPath,
  }) {
    return signAndSend(
      'POST',
      path,
      bearerToken: session,
      identity: identity,
      body: <String, dynamic>{...reauthentication, 'pin': pin},
    );
  }

  /// Has the backend check the app [pin] for the one signed [request] -- sent
  /// once, in a signed body, never in a header -- and answers that request
  /// unlocked by its proof, valid for that request alone.
  Future<RequestProof> proveAppPin({
    required String session,
    required InstallationIdentity identity,
    required String pin,
    required RequestProof request,
    String path = appPinProofPath,
  }) async {
    final Map<String, dynamic> answer = await signAndSend(
      'POST',
      path,
      bearerToken: session,
      identity: identity,
      body: appPinProofRequest(
        pin: pin,
        method: request.method,
        path: request.path,
        encodedBody: request.encodedBody,
        nonce: request.nonce,
      ),
    );
    final Object? proof = answer['app_pin_proof'];
    if (proof is! String || proof.isEmpty) {
      throw ApiException(
        'The backend answered no app PIN proof.',
        code: 'app_pin_proof_missing',
      );
    }
    return request.withAppPinProof(proof);
  }

  void close() => transport.close();
}
