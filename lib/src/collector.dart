/// The native integrity collector: measures what a challenge asks for and the
/// app enabled, and nothing else.
library;

import 'package:flutter/services.dart';

import 'errors.dart';

class NativeIntegrityCollector {
  static const MethodChannel _channel = MethodChannel('necessary/integrity_v1');

  /// [enabledMeasurements]: the personal measurements this app's developers
  /// allow; with [optionalProbes], what the backend asks for, the collector
  /// measures only what is in both.
  Future<Map<String, dynamic>> collect({
    required List<String> requiredProbes,
    required String challengeNonce,
    required List<String> enabledMeasurements,
    List<String> optionalProbes = const <String>[],
  }) async {
    try {
      final Map<String, dynamic>? value = await _channel
          .invokeMapMethod<String, dynamic>('collect', <String, dynamic>{
            'required_probes': requiredProbes,
            'challenge_nonce': challengeNonce,
            // What the server asks for and what this app allows; the native
            // collector measures only what is in both.
            'optional_probes': optionalProbes,
            'enabled_measurements': enabledMeasurements,
          });
      if (value == null) {
        throw NativeKeyException(
          'EMPTY_INTEGRITY_RESPONSE',
          'The native integrity collector returned no measurements.',
        );
      }
      return value;
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_INTEGRITY_PLUGIN_MISSING',
        "The necessary plugin's integrity channel is not registered: perform a full rebuild.",
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The native integrity collector failed.',
      );
    }
  }

  /// Asks the person for the OS location permission and
  /// returns what the app now holds: precise, approximate or none. Only the
  /// app asks, from its own screen; a scan never prompts.
  Future<String> requestLocationPermission() async {
    try {
      return await _channel.invokeMethod<String>('requestLocationPermission') ??
          'none';
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The location permission request failed.',
      );
    }
  }
}
