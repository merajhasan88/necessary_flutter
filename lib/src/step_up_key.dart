/// The step-up key (the public guide, section 3): a second key that the
/// person must unlock, the options it is made with, and its re-enrolment
/// proof.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter/services.dart';

import 'errors.dart';

/// The optional step-up key as the native side reports it. [factor], [mode]
/// and [windowSeconds] describe what the platform keystore actually enforces
/// (read back from KeyInfo on Android, from the key's label on iOS), which on
/// Android 9/10 is a short hardware window rather than per-use.
class StepUpKeyMetadata {
  StepUpKeyMetadata({
    required this.publicKey,
    required this.factor,
    required this.mode,
    required this.windowSeconds,
    required this.securityLevel,
    required this.hardwareBacked,
    required this.created,
  });

  final Map<String, dynamic> publicKey;
  final String factor;
  final String mode;
  final int windowSeconds;
  final String securityLevel;
  final bool hardwareBacked;
  final bool created;

  Map<String, dynamic> get authJson => <String, dynamic>{
    'factor': factor,
    'mode': mode,
    'window_seconds': windowSeconds,
  };

  String get description => mode == 'per_use'
      ? '$factor, per-use'
      : '$factor, ${windowSeconds}s hardware window';

  /// RFC 7638 thumbprint, the same form the server derives from the JWK.
  String get thumbprint => crypto.sha256
      .convert(
        utf8.encode(
          jsonEncode(<String, dynamic>{
            'crv': publicKey['crv'],
            'kty': 'EC',
            'x': publicKey['x'],
            'y': publicKey['y'],
          }),
        ),
      )
      .toString();

  factory StepUpKeyMetadata.fromPlatform(Map<String, dynamic> value) {
    final Object? rawPublicKey = value['public_key'];
    final Object? rawAuth = value['auth'];
    if (rawPublicKey is! Map || rawAuth is! Map) {
      throw const FormatException(
        'The native step-up key provider returned no public key or auth.',
      );
    }
    final Map<String, dynamic> publicKey = Map<String, dynamic>.from(
      rawPublicKey,
    );
    final Map<String, dynamic> auth = Map<String, dynamic>.from(rawAuth);
    if (publicKey['kty'] != 'EC' ||
        publicKey['crv'] != 'P-256' ||
        publicKey['alg'] != 'ES256' ||
        publicKey['x'] is! String ||
        publicKey['y'] is! String) {
      throw const FormatException(
        'The native step-up key provider did not return an EC P-256 public JWK.',
      );
    }
    final Object? factor = auth['factor'];
    final Object? mode = auth['mode'];
    final Object? window = auth['window_seconds'];
    if (factor is! String || mode is! String || window is! int) {
      throw const FormatException(
        'The native step-up key provider returned an invalid auth description.',
      );
    }
    return StepUpKeyMetadata(
      publicKey: publicKey,
      factor: factor,
      mode: mode,
      windowSeconds: window,
      securityLevel: value['security_level'] as String? ?? 'unknown',
      hardwareBacked: value['hardware_backed'] == true,
      created: value['created'] == true,
    );
  }
}

/// Where a backend takes a re-enrolled step-up key by default (the public
/// guide, section 4).
const String stepUpReenrolPath = '/v1/installations/stepup-key';

/// How the app wants its step-up key made (the public guide, section 3):
/// [factor] `passcode` or `biometric`; [mode] `per_use`, or `windowed` with
/// [windowSeconds] from 1. Android 9 and 10 cannot make a per-use passcode
/// key and make a windowed one; iOS makes per-use keys only. [reenrolPath]
/// is where the backend takes a new key (DeviceTrust.reenrolStepUp).
class StepUpOptions {
  const StepUpOptions({
    this.factor = 'passcode',
    this.mode = 'per_use',
    this.windowSeconds = 0,
    this.reenrolPath = stepUpReenrolPath,
  });

  final String factor;
  final String mode;
  final int windowSeconds;
  final String reenrolPath;

  /// A key made with other values, or already made: whether it satisfies
  /// these options -- the same factor (a backend refuses any other), and a
  /// per-use key or a window no longer than this one. A per-use key
  /// satisfies windowed options.
  bool accepts(StepUpKeyMetadata key) =>
      key.factor == factor &&
      (key.mode == 'per_use' ||
          (mode == 'windowed' && key.windowSeconds <= windowSeconds));

  String get description =>
      '$factor, ${mode == 'per_use' ? 'per-use' : '${windowSeconds}s window'}';
}

/// The proof a new step-up key signs at re-enrolment: the base64url of its
/// JSON, the members in this order. [nonce] is the request proof's nonce of
/// the re-enrolment request.
String stepUpReenrolProof({
  required String installationId,
  required String stepUpKeyThumbprint,
  required String nonce,
  required int timestamp,
}) {
  return base64Url
      .encode(
        utf8.encode(
          jsonEncode(<String, dynamic>{
            'version': 1,
            'purpose': 'stepup_reenrol',
            'installation_id': installationId,
            'stepup_key_thumbprint': stepUpKeyThumbprint,
            'nonce': nonce,
            'timestamp': timestamp,
          }),
        ),
      )
      .replaceAll('=', '');
}

/// Whether a step-up key [options] do not accept is replaced before the
/// next registration: only where the new key can then be bound -- by a
/// re-enrolment ([replaceMismatched]), which binds it with the person's
/// re-authentication, or by this installation's first registration, which
/// binds the key it is offered. A known installation's registration never binds an offered key;
/// it only says whether it matches, so replacing the key there orphans the
/// one the server holds: on a phone that cannot make the key the options ask
/// for (Android 9 makes no per-use passcode key), the registration that
/// follows every re-enrolment would replace the key the server had just
/// bound, and step-up would stay unavailable.
bool replacesStepUpKey(
  StepUpKeyMetadata key,
  StepUpOptions options, {
  required bool replaceMismatched,
  required bool knownInstallation,
}) =>
    !key.created &&
    !options.accepts(key) &&
    (replaceMismatched || !knownInstallation);

class NativeStepUpKey {
  NativeStepUpKey({this.configuredMode = 'per_use'});

  static const MethodChannel _channel = MethodChannel(
    'necessary/stepup_key_v1',
  );

  /// The mode the app asks for, which decides whether a windowed key first
  /// tries to sign inside an open hardware window.
  String configuredMode;

  /// Returns the existing key as the keystore enforces it, or creates one
  /// with these values: an existing key is never changed, so a caller that
  /// needs other values deletes it first.
  Future<StepUpKeyMetadata> getOrCreateKey({
    required String factor,
    required String mode,
    required int windowSeconds,
  }) async {
    try {
      final Map<String, dynamic>? value = await _channel
          .invokeMapMethod<String, dynamic>('getOrCreateKey', <String, dynamic>{
            'factor': factor,
            'mode': mode,
            'window_seconds': windowSeconds,
          });
      if (value == null) {
        throw NativeKeyException(
          'EMPTY_NATIVE_RESPONSE',
          'The native step-up key provider returned no key metadata.',
        );
      }
      return StepUpKeyMetadata.fromPlatform(value);
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_STEPUP_PLUGIN_MISSING',
        'The step-up key channel is not registered in this native build.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The native step-up key provider failed.',
      );
    }
  }

  /// Shows the system passcode (or biometric) prompt and completes when the
  /// user answers it. A cancelled prompt is STEPUP_CANCELLED.
  Future<String> sign(String payloadBase64Url, {required String reason}) async {
    try {
      final String? signature = await _channel.invokeMethod<String>(
        'sign',
        <String, dynamic>{
          'payload': payloadBase64Url,
          'reason': reason,
          'mode': configuredMode,
        },
      );
      if (signature == null || signature.isEmpty) {
        throw NativeKeyException(
          'EMPTY_NATIVE_SIGNATURE',
          'The step-up key returned no signature.',
        );
      }
      return signature;
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_STEPUP_PLUGIN_MISSING',
        'The step-up key channel is not registered in this native build.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The step-up key could not sign.',
      );
    }
  }

  Future<void> deleteKey() async {
    try {
      await _channel.invokeMethod<bool>('deleteKey');
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_STEPUP_PLUGIN_MISSING',
        'The step-up key channel is not registered in this native build.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The step-up key could not be deleted.',
      );
    }
  }
}
