/// What the client does about the protocol errors of the public guide's
/// section 4.
library;

import 'errors.dart';

/// What the client does about a refusal from the device-trust API: the
/// protocol errors of the integration guide's section 4, each acted on
/// once. Any other refusal goes to the app as it came.
enum ProtocolStep { askAgain, proveAgain, registerAgain, waitThenRetry, stop }

/// The longest wait the client sits through before it retries a 429 itself;
/// a longer one goes to the app.
const int protocolMaxWaitSeconds = 10;

/// [deviceSession]: the request ran under the session from
/// /v1/installations/verify, which the client can renew by proving its key
/// again; an account session is the app's to renew.
ProtocolStep protocolStepFor(
  ApiException error, {
  required bool deviceSession,
}) {
  switch (error.code) {
    case 'challenge_expired':
    case 'challenge_used':
    case 'integrity_challenge_expired':
    case 'integrity_challenge_replay':
      return ProtocolStep.askAgain;
    case 'expired_token':
      return deviceSession ? ProtocolStep.proveAgain : ProtocolStep.stop;
    case 'installation_not_found':
      return ProtocolStep.registerAgain;
  }
  return protocolWait(error) == null
      ? ProtocolStep.stop
      : ProtocolStep.waitThenRetry;
}

/// How long a 429 asks the client to wait, when that is short enough to wait.
Duration? protocolWait(ApiException error) {
  final Object? seconds = error.details?['retry_after_seconds'];
  if (error.statusCode != 429 ||
      seconds is! num ||
      seconds < 0 ||
      seconds > protocolMaxWaitSeconds) {
    return null;
  }
  return Duration(milliseconds: (seconds * 1000).round());
}
