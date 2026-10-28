/// The failures the plugin reports.
library;

class NativeKeyException implements Exception {
  NativeKeyException(this.code, this.message);

  final String code;
  final String message;

  @override
  String toString() => '$message [$code]';
}

class ApiException implements Exception {
  ApiException(this.message, {this.statusCode, this.code, this.details});

  final String message;
  final int? statusCode;
  final String? code;
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
