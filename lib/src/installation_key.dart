/// The installation key: one non-exportable P-256 key per installation, made
/// and held by Android Keystore or the iOS Secure Enclave (or, where that
/// refuses, the Keychain).
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter/services.dart';

import 'errors.dart';

class NativeKeyMetadata {
  NativeKeyMetadata({
    required this.publicKey,
    required this.algorithm,
    required this.keyAlias,
    required this.provider,
    required this.securityLevel,
    required this.hardwareBacked,
    required this.privateKeyExportable,
    required this.signatureFormat,
    required this.created,
  });

  final Map<String, dynamic> publicKey;
  final String algorithm;
  final String keyAlias;
  final String provider;
  final String securityLevel;
  final bool hardwareBacked;
  final bool privateKeyExportable;
  final String signatureFormat;
  final bool created;

  factory NativeKeyMetadata.fromPlatform(Map<String, dynamic> value) {
    final Object? rawPublicKey = value['public_key'];
    if (rawPublicKey is! Map) {
      throw const FormatException(
        'The native key provider returned no public key.',
      );
    }
    final Map<String, dynamic> publicKey = Map<String, dynamic>.from(
      rawPublicKey,
    );

    String requiredString(String field) {
      final Object? item = value[field];
      if (item is! String || item.isEmpty) {
        throw FormatException(
          'The native key provider returned an invalid $field.',
        );
      }
      return item;
    }

    bool requiredBool(String field) {
      final Object? item = value[field];
      if (item is! bool) {
        throw FormatException(
          'The native key provider returned an invalid $field.',
        );
      }
      return item;
    }

    if (publicKey['kty'] != 'EC' ||
        publicKey['crv'] != 'P-256' ||
        publicKey['alg'] != 'ES256' ||
        publicKey['x'] is! String ||
        publicKey['y'] is! String) {
      throw const FormatException(
        'The native key provider did not return an EC P-256 public JWK.',
      );
    }

    return NativeKeyMetadata(
      publicKey: publicKey,
      algorithm: requiredString('algorithm'),
      keyAlias: requiredString('key_alias'),
      provider: requiredString('provider'),
      securityLevel: requiredString('security_level'),
      hardwareBacked: requiredBool('hardware_backed'),
      privateKeyExportable: requiredBool('private_key_exportable'),
      signatureFormat: requiredString('signature_format'),
      created: requiredBool('created'),
    );
  }
}

class NativeInstallationKey {
  static const MethodChannel _channel = MethodChannel(
    'necessary/installation_key_v2',
  );

  Future<NativeKeyMetadata> getOrCreateKey() async {
    try {
      final Map<String, dynamic>? value = await _channel
          .invokeMapMethod<String, dynamic>('getOrCreateKey');
      if (value == null) {
        throw NativeKeyException(
          'EMPTY_NATIVE_RESPONSE',
          'The native key provider returned no key metadata.',
        );
      }
      return NativeKeyMetadata.fromPlatform(value);
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_KEY_PLUGIN_MISSING',
        "The necessary plugin's installation-key channel is not registered: "
            'perform a full rebuild.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The native key provider failed.',
      );
    }
  }

  Future<String> signPayload(String payloadBase64Url) async {
    try {
      final String? signature = await _channel.invokeMethod<String>(
        'sign',
        <String, dynamic>{'payload': payloadBase64Url},
      );
      if (signature == null || signature.isEmpty) {
        throw NativeKeyException(
          'EMPTY_NATIVE_SIGNATURE',
          'The native key provider returned no signature.',
        );
      }
      return signature;
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_KEY_PLUGIN_MISSING',
        'The Android/iOS installation-key channel is not registered.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ??
            'The native key provider could not sign the challenge.',
      );
    }
  }

  Future<void> deleteKey() async {
    try {
      await _channel.invokeMethod<bool>('deleteKey');
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_KEY_PLUGIN_MISSING',
        'The Android/iOS installation-key channel is not registered.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The native installation key could not be deleted.',
      );
    }
  }
}

class InstallationIdentity {
  InstallationIdentity({
    required this.installationId,
    required this.nativeKey,
    required this.metadata,
  });

  final String installationId;
  final NativeInstallationKey nativeKey;
  final NativeKeyMetadata metadata;

  Map<String, dynamic> get publicKeyJson => metadata.publicKey;
  String get algorithm => metadata.algorithm;
  String get keyAlias => metadata.keyAlias;
  String get provider => metadata.provider;
  String get securityLevel => metadata.securityLevel;
  bool get hardwareBacked => metadata.hardwareBacked;
  bool get privateKeyExportable => metadata.privateKeyExportable;
  String get signatureFormat => metadata.signatureFormat;
  bool get createdThisLaunch => metadata.created;

  String get keyThumbprint {
    // RFC 7638 canonical member order for an EC public JWK.
    final String canonical = jsonEncode(<String, dynamic>{
      'crv': publicKeyJson['crv'],
      'kty': 'EC',
      'x': publicKeyJson['x'],
      'y': publicKeyJson['y'],
    });
    return crypto.sha256.convert(utf8.encode(canonical)).toString();
  }

  Future<String> signPayload(String payloadBase64Url) {
    return nativeKey.signPayload(payloadBase64Url);
  }

  InstallationIdentity withInstallationId(String canonicalInstallationId) {
    return InstallationIdentity(
      installationId: canonicalInstallationId,
      nativeKey: nativeKey,
      metadata: metadata,
    );
  }
}
