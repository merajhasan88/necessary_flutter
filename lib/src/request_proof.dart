/// Request proofs (the public guide, section 3): the installation key signs
/// each request, so a copied session token is useless without the key; with
/// step-up on the person approves one request with the step-up key, and with
/// the app PIN on a request carries the backend's proof of the PIN. Also the
/// description of the one request a scan is to approve (section 2).
library;

import 'dart:convert';
import 'dart:math' as math;

import 'package:crypto/crypto.dart' as crypto;

import 'installation_key.dart';

/// Base64url without padding: how every binary value travels.
String base64UrlNoPadding(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// 32 random bytes from the platform's secure source.
List<int> freshNonce() {
  final math.Random random = math.Random.secure();
  return List<int>.generate(32, (_) => random.nextInt(256));
}

String _sha256Hex(String text) =>
    crypto.sha256.convert(utf8.encode(text)).toString();

/// The person's approval of one request: the step-up key's [factor], and
/// [sign], which has the step-up key sign a payload -- the phone asks the
/// person (NativeStepUpKey.sign).
class StepUpApproval {
  const StepUpApproval({required this.factor, required this.sign});

  final String factor;
  final Future<String> Function(String payload) sign;
}

/// What the installation key signed for one request -- with step-up, what
/// the step-up key signed; with the app PIN, the backend's proof of it; for a
/// request a scan approves, that scan's report -- and the headers that carry
/// them beside `Authorization: Bearer`.
class RequestProof {
  const RequestProof({
    required this.bearerToken,
    required this.method,
    required this.path,
    required this.encodedBody,
    required this.payload,
    required this.signature,
    required this.timestamp,
    required this.nonce,
    this.stepUpPayload,
    this.stepUpSignature,
    this.appPinProof,
    this.integrityReport,
  });

  final String bearerToken;

  /// The request the proof was signed for: its method, its path with the
  /// query, and the exact body.
  final String method;
  final String path;
  final String encodedBody;

  /// `X-Access-Proof`: the base64url of the proof's JSON bytes.
  final String payload;

  /// `X-Access-Signature`.
  final String signature;
  final int timestamp;
  final String nonce;

  /// `X-Step-Up-Proof` and `X-Step-Up-Signature`, for a request the person
  /// approved.
  final String? stepUpPayload;
  final String? stepUpSignature;

  /// `X-App-PIN-Proof`: the backend's proof that the person entered the app
  /// PIN for this request (DeviceTrustClient.proveAppPin).
  final String? appPinProof;

  /// `X-Integrity-Report`: the report of the scan made for this request
  /// alone (the public guide, section 2).
  final String? integrityReport;

  Map<String, String> get headers => <String, String>{
    'X-Access-Proof': payload,
    'X-Access-Signature': signature,
    'X-Step-Up-Proof': ?stepUpPayload,
    'X-Step-Up-Signature': ?stepUpSignature,
    'X-App-PIN-Proof': ?appPinProof,
    'X-Integrity-Report': ?integrityReport,
  };

  /// This request, unlocked by the backend's [proof] of the app PIN.
  RequestProof withAppPinProof(String proof) =>
      _with(appPinProof: proof, integrityReport: integrityReport);

  /// This request, naming [reportId], the scan made for it alone.
  RequestProof withIntegrityReport(String reportId) =>
      _with(appPinProof: appPinProof, integrityReport: reportId);

  RequestProof _with({String? appPinProof, String? integrityReport}) =>
      RequestProof(
        bearerToken: bearerToken,
        method: method,
        path: path,
        encodedBody: encodedBody,
        payload: payload,
        signature: signature,
        timestamp: timestamp,
        nonce: nonce,
        stepUpPayload: stepUpPayload,
        stepUpSignature: stepUpSignature,
        appPinProof: appPinProof,
        integrityReport: integrityReport,
      );
}

/// What the app sends to have its backend check the app PIN for one request:
/// the PIN, and that request as its request proof signs it -- method, path,
/// query, the hash of the body sent and the request proof's nonce.
Map<String, dynamic> appPinProofRequest({
  required String pin,
  required String method,
  required String path,
  required String encodedBody,
  required String nonce,
}) {
  final Uri target = Uri.parse(path);
  return <String, dynamic>{
    'pin': pin,
    'request': <String, dynamic>{
      'method': method.toUpperCase(),
      'path': target.path,
      'query': target.query,
      'body_sha256': _sha256Hex(encodedBody),
      'nonce': nonce,
    },
  };
}

/// The step-up proof, version 2, that the step-up key signs for one request:
/// the base64url of its JSON, the members in this order. [nonce] is the
/// request proof's nonce for the same request, so the approval is used up
/// with it.
String stepUpProof({
  required String installationId,
  required String accessToken,
  required String method,
  required String path,
  required String encodedBody,
  required String factor,
  required String nonce,
  required int timestamp,
}) {
  final Uri target = Uri.parse(path);
  return base64UrlNoPadding(
    utf8.encode(
      jsonEncode(<String, dynamic>{
        'version': 2,
        'purpose': 'stepup',
        'installation_id': installationId,
        'access_token_sha256': _sha256Hex(accessToken),
        'method': method.toUpperCase(),
        'path': target.path,
        'query': target.query,
        'body_sha256': _sha256Hex(encodedBody),
        'factor': factor,
        'nonce': nonce,
        'timestamp': timestamp,
      }),
    ),
  );
}

/// Signs [method] [path] with [encodedBody] under [bearerToken]: proof
/// version 2, which signs the query string too, exactly as sent. A GET signs
/// an empty body. With [stepUp], the step-up key signs first -- the phone asks
/// the person -- and the request proof after, with the same nonce, so the
/// time the person takes does not count against the request proof's clock
/// window. [installationId], [timestamp] and [nonce] replace what the request
/// proof would otherwise carry, for the shared test vectors and for testing a
/// backend's refusals.
Future<RequestProof> signRequest({
  required InstallationIdentity identity,
  required String method,
  required String path,
  required String bearerToken,
  String encodedBody = '',
  StepUpApproval? stepUp,
  String? installationId,
  int? timestamp,
  List<int>? nonce,
}) async {
  final String normalizedMethod = method.toUpperCase();
  final String body = normalizedMethod == 'GET' ? '' : encodedBody;
  final String nonceText = base64UrlNoPadding(nonce ?? freshNonce());
  String? stepUpPayload;
  String? stepUpSignature;
  if (stepUp != null) {
    stepUpPayload = stepUpProof(
      installationId: identity.installationId,
      accessToken: bearerToken,
      method: normalizedMethod,
      path: path,
      encodedBody: body,
      factor: stepUp.factor,
      nonce: nonceText,
      timestamp: DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
    );
    stepUpSignature = await stepUp.sign(stepUpPayload);
  }
  final int signedAt =
      timestamp ?? DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
  final Uri target = Uri.parse(path);
  // The members in this order: the backend checks each against the request
  // it received, and the shared vectors hold both sides to these bytes.
  final Map<String, dynamic> proof = <String, dynamic>{
    'access_token_sha256': _sha256Hex(bearerToken),
    'body_sha256': _sha256Hex(body),
    'installation_id': installationId ?? identity.installationId,
    'method': normalizedMethod,
    'nonce': nonceText,
    'path': target.path,
    'query': target.query,
    'timestamp': signedAt,
    'version': 2,
  };

  // The key signs the exact JSON bytes this base64url value carries; the
  // private key never leaves Android Keystore or the iOS Keychain.
  final String payload = base64UrlNoPadding(utf8.encode(jsonEncode(proof)));
  return RequestProof(
    bearerToken: bearerToken,
    method: normalizedMethod,
    path: path,
    encodedBody: body,
    payload: payload,
    signature: await identity.signPayload(payload),
    timestamp: signedAt,
    nonce: nonceText,
    stepUpPayload: stepUpPayload,
    stepUpSignature: stepUpSignature,
  );
}

/// The one request a scan is to approve, described exactly as it will be
/// sent: what the challenge names as its `operation`.
Map<String, dynamic> describeOperation(
  String method,
  String path,
  String encodedBody,
) {
  final Uri target = Uri.parse(path);
  return <String, dynamic>{
    'method': method.toUpperCase(),
    'path': target.path,
    'query': target.query,
    'body_sha256': _sha256Hex(encodedBody),
  };
}
