// The sample backend's own API (../backend/README.md): how an app signs what
// it sends to its own backend -- a request proof on every request, and the
// person's approval on a sensitive one -- and requests made wrong on purpose,
// which a backend must refuse.
import 'dart:convert';

import 'package:necessary/necessary.dart';

class SampleApi {
  SampleApi(this.trust);

  final DeviceTrust trust;

  /// The sample's account session for this installation, after [signIn].
  String? account;

  static const String _echo = '/v1/demo/echo';
  static const String _sensitive = '/v1/demo/sensitive';
  static const String _echoBody = '{"hello":"backend"}';
  static const String _payeeBody = '{"payee":"payee-7"}';

  String get _session {
    final String? session = account;
    if (session == null) {
      throw StateError('Sign in first.');
    }
    return session;
  }

  /// The sample's sign-in, under the installation session from start(): an
  /// account session for this installation. The sample makes the account at
  /// its first sign-in.
  Future<void> signIn(String handle, String password) async {
    final RequestProof proof = await trust.signRequest(
      method: 'POST',
      path: '/v1/demo/sign-in',
      bearer: trust.installationSession!,
      body: jsonEncode(<String, String>{
        'handle': handle,
        'password': password,
      }),
    );
    account = (await trust.send(proof))['account_session'] as String;
  }

  /// A request with its request proof alone: only this installation's key
  /// can sign it, so the session is useless on another phone.
  Future<Map<String, dynamic>> protectedRequest() async => trust.send(
    await trust.signRequest(
      method: 'POST',
      path: _echo,
      bearer: _session,
      body: _echoBody,
    ),
  );

  /// The sensitive request. With [stepUp] the person approves it with the
  /// screen lock -- the phone asks, showing the reason; with [appPin] the
  /// backend checks the PIN for this request first. With neither the
  /// backend refuses it.
  Future<Map<String, dynamic>> sensitive({
    bool stepUp = false,
    String? appPin,
  }) async => trust.send(
    await trust.signRequest(
      method: 'POST',
      path: _sensitive,
      bearer: _session,
      body: _payeeBody,
      stepUp: stepUp,
      reason: 'Approve the new payee',
      appPin: appPin,
    ),
  );

  /// A new step-up key, with the person's password: after the screen lock
  /// was removed, say, when approvals fail with STEPUP_KEY_INVALIDATED.
  Future<Map<String, dynamic>> reenrolStepUp(String password) =>
      trust.reenrolStepUp(
        session: _session,
        reauthentication: <String, dynamic>{'password': password},
      );

  /// Sets the account's app PIN, with the person's password.
  Future<Map<String, dynamic>> setAppPin(String pin, String password) =>
      trust.setAppPin(
        session: _session,
        pin: pin,
        reauthentication: <String, dynamic>{'password': password},
      );

  // --- Requests a backend must refuse.

  Future<RequestProof> _signedEcho() => trust.signRequest(
    method: 'POST',
    path: _echo,
    bearer: _session,
    body: _echoBody,
  );

  /// One signed request sent twice: the second is a replay.
  Future<Map<String, dynamic>> replay() async {
    final RequestProof proof = await _signedEcho();
    try {
      await trust.send(proof);
    } on ApiException catch (error) {
      // The first must go through, or the second tests nothing.
      throw StateError(
        'The first send was refused: ${error.statusCode} ${error.code}.',
      );
    }
    return trust.send(proof);
  }

  /// A signed request whose body is changed on the way.
  Future<Map<String, dynamic>> changedBody() async => trust.client.sendSigned(
    await _signedEcho(),
    encodedBody: '{"hello":"changed"}',
  );

  /// A signed request sent to another path.
  Future<Map<String, dynamic>> otherPath() async =>
      trust.client.sendSigned(await _signedEcho(), path: _sensitive);

  /// A request proof signed ten minutes ago.
  Future<Map<String, dynamic>> staleProof() async => trust.send(
    await signRequest(
      identity: await trust.loadIdentity(),
      method: 'POST',
      path: _echo,
      bearerToken: _session,
      encodedBody: _echoBody,
      timestamp: DateTime.now().millisecondsSinceEpoch ~/ 1000 - 600,
    ),
  );

  /// This phone's account session and installation, to try on another
  /// phone.
  String shareSession() => jsonEncode(<String, String>{
    'session': _session,
    'installation_id': trust.identity!.installationId,
  });

  /// A session [shared] from another phone, used here: this phone's key
  /// signs a request naming that phone's installation.
  Future<Map<String, dynamic>> sessionFromAnotherPhone(String shared) async {
    final Map<String, dynamic> copied =
        jsonDecode(shared.trim()) as Map<String, dynamic>;
    return trust.send(
      await signRequest(
        identity: await trust.loadIdentity(),
        method: 'POST',
        path: _echo,
        bearerToken: copied['session'] as String,
        encodedBody: _echoBody,
        installationId: copied['installation_id'] as String,
      ),
    );
  }
}
