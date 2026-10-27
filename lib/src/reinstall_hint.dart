/// The reinstall hint: a SHA-256 of the platform's per-app device identifier,
/// which the backend keys before storing. Client input, never proof.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

class ReinstallHint {
  const ReinstallHint({required this.kind, required this.value});

  final String kind;
  final String value;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'kind': kind,
    'value': value,
  };
}

class ReinstallHintReader {
  static const MethodChannel _channel = MethodChannel(
    'necessary/installation_key_v2',
  );

  Future<ReinstallHint?> read() async {
    // ANDROID_ID on Android, the identifier for vendor on iOS.
    final String kind;
    switch (kIsWeb ? null : defaultTargetPlatform) {
      case TargetPlatform.android:
        kind = 'android_id';
      case TargetPlatform.iOS:
        kind = 'idfv';
      default:
        return null;
    }
    try {
      final String value =
          (await _channel.invokeMethod<String>('reinstallHintIdentifier') ?? '')
              .trim()
              .toLowerCase();
      if (value.isEmpty) {
        return null;
      }
      final String digest = crypto.sha256
          .convert(utf8.encode('device-recognition-hint-v1|$kind|$value'))
          .toString();
      return ReinstallHint(kind: '${kind}_sha256', value: digest);
    } catch (_) {
      // A missing hint must never stop cryptographic installation identity.
    }
    return null;
  }
}
