/// The failures the plugin reports.
library;

/// A failure of the phone's keystore or of a prompt: [code] says which --
/// `KEY_UNAVAILABLE` (Android's keystore could not be reached for the
/// installation key; no key was made over it: try again, or reset()),
/// `STEPUP_KEY_INVALIDATED` (the key can never sign again: re-enrol),
/// `STEPUP_KEY_UNAVAILABLE` (the keystore could not say whether the key is
/// usable, or could not be reached; it was kept: try again, or re-enrol),
/// `STEPUP_CANCELLED`, `STEPUP_REENROL_PENDING` and the like -- and [message]
/// says it in words: on Android followed by everything that failed beneath it
/// (`[cause: ...]`), down to the keystore's own answer.
class NativeKeyException implements Exception {
  NativeKeyException(this.code, this.message);

  /// What failed, for the app to act on.
  final String code;

  /// The same, in words.
  final String message;

  @override
  String toString() => '$message [$code]';
}

/// A refusal from your backend, or a request that did not reach it: the
/// backend's `{"error": {"code", "message", "details"}}` (the guide, section
/// 4), with the HTTP status.
class ApiException implements Exception {
  ApiException(this.message, {this.statusCode, this.code, this.details});

  /// The backend's message, or what went wrong on the way.
  final String message;

  /// The HTTP status, when the backend answered.
  final int? statusCode;

  /// The backend's `code`: what the app acts on.
  final String? code;

  /// The backend's `details`, such as `retry_after_seconds`.
  final Map<String, dynamic>? details;

  @override
  String toString() => message;
}

/// A call that DeviceTrust.reset or DeviceTrust.close ended while it ran:
/// what it found belongs to an installation that is gone, or to a client that
/// is closed, so nothing of it was kept. After a reset, call again.
class InterruptedCallException implements Exception {
  InterruptedCallException(this.message);

  final String message;

  @override
  String toString() => message;
}
