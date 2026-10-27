// The shared client-server vectors, test/vectors/client_server.json: the
// plugin must produce, byte for byte, the request proof it signs, the
// operation a scan names, its key's thumbprint, the step-up proofs and the
// app PIN's request -- the integration guide's sections 1 to 3. A backend can
// test itself against the same file.
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:necessary/necessary.dart';

import 'repository_files.dart';

/// Signs nothing: the vectors fix what is signed, and ECDSA signatures are
/// randomized, so the signature is the backend's own check.
class _VectorKey implements NativeInstallationKey {
  @override
  Future<NativeKeyMetadata> getOrCreateKey() => throw UnimplementedError();

  @override
  Future<String> signPayload(String payloadBase64Url) async => 'unsigned';

  @override
  Future<void> deleteKey() async {}
}

InstallationIdentity _identity(
  String installationId,
  Map<String, dynamic> jwk,
) {
  return InstallationIdentity(
    installationId: installationId,
    nativeKey: _VectorKey(),
    metadata: NativeKeyMetadata(
      publicKey: jwk,
      algorithm: 'ES256',
      keyAlias: 'vector',
      provider: 'vector',
      securityLevel: 'software',
      hardwareBacked: false,
      privateKeyExportable: false,
      signatureFormat: 'der',
      created: false,
    ),
  );
}

List<int> _unpadded(String value) =>
    base64Url.decode(base64Url.normalize(value));

void main() {
  final Map<String, dynamic> vectors =
      jsonDecode(
            repositoryFile(
              'test/vectors/client_server.json',
            ).readAsStringSync(),
          )
          as Map<String, dynamic>;
  final Map<String, dynamic> someKey = Map<String, dynamic>.from(
    ((vectors['thumbprint'] as List<dynamic>).first
            as Map<String, dynamic>)['jwk']
        as Map,
  );

  group('access proof', () {
    for (final dynamic raw in vectors['access_proof'] as List<dynamic>) {
      final Map<String, dynamic> vector = raw as Map<String, dynamic>;
      test(vector['name'] as String, () async {
        final Object? body = vector['body'];
        final RequestProof proof = await signRequest(
          identity: _identity(vector['installation_id'] as String, someKey),
          method: vector['method'] as String,
          path: vector['path'] as String,
          bearerToken: vector['bearer'] as String,
          encodedBody: body == null ? '' : jsonEncode(body),
          timestamp: vector['timestamp'] as int,
          nonce: _unpadded(vector['nonce'] as String),
        );
        expect(proof.encodedBody, vector['sent_body'], reason: 'the body sent');
        expect(
          utf8.decode(_unpadded(proof.payload)),
          vector['proof_json'],
          reason: 'the proof, as JSON',
        );
        expect(proof.payload, vector['proof'], reason: 'the proof, as sent');
      });
    }
  });

  group('operation a scan names', () {
    for (final dynamic raw in vectors['operation'] as List<dynamic>) {
      final Map<String, dynamic> vector = raw as Map<String, dynamic>;
      test(vector['name'] as String, () {
        expect(
          jsonEncode(vector['body']),
          vector['sent_body'],
          reason: 'the body sent',
        );
        expect(
          describeOperation(
            vector['method'] as String,
            vector['path'] as String,
            jsonEncode(vector['body']),
          ),
          equals(vector['operation']),
        );
      });
    }
  });

  group('key thumbprint', () {
    for (final dynamic raw in vectors['thumbprint'] as List<dynamic>) {
      final Map<String, dynamic> vector = raw as Map<String, dynamic>;
      test(vector['name'] as String, () {
        final InstallationIdentity identity = _identity(
          '00000000-0000-4000-8000-000000000000',
          Map<String, dynamic>.from(vector['jwk'] as Map),
        );
        expect(identity.keyThumbprint, vector['thumbprint']);
      });
    }
  });

  // The step-up proofs (the public guide, section 3): what the step-up key
  // signs for one request, and what a new step-up key signs at re-enrolment.
  group('step-up proof v2', () {
    for (final dynamic raw in vectors['step_up_proof'] as List<dynamic>) {
      final Map<String, dynamic> vector = raw as Map<String, dynamic>;
      test(vector['name'] as String, () {
        final String sent = jsonEncode(vector['body']);
        expect(sent, vector['sent_body'], reason: 'the body sent');
        final String payload = stepUpProof(
          installationId: vector['installation_id'] as String,
          accessToken: vector['bearer'] as String,
          method: 'POST',
          path: vector['path'] as String,
          encodedBody: sent,
          factor: vector['factor'] as String,
          nonce: vector['nonce'] as String,
          timestamp: vector['timestamp'] as int,
        );
        expect(
          utf8.decode(_unpadded(payload)),
          vector['proof_json'],
          reason: 'the proof, as JSON',
        );
        expect(payload, vector['proof'], reason: 'the proof, as sent');
      });
    }
  });

  group('step-up key re-enrolment proof', () {
    for (final dynamic raw
        in vectors['step_up_reenrol_proof'] as List<dynamic>) {
      final Map<String, dynamic> vector = raw as Map<String, dynamic>;
      test(vector['name'] as String, () {
        final String payload = stepUpReenrolProof(
          installationId: vector['installation_id'] as String,
          stepUpKeyThumbprint: vector['stepup_key_thumbprint'] as String,
          nonce: vector['nonce'] as String,
          timestamp: vector['timestamp'] as int,
        );
        expect(
          utf8.decode(_unpadded(payload)),
          vector['proof_json'],
          reason: 'the proof, as JSON',
        );
        expect(payload, vector['proof'], reason: 'the proof, as sent');
      });
    }
  });

  // What the app sends to have its backend check the app PIN for one request
  // (the public guide, section 3).
  group('app PIN proof request', () {
    for (final dynamic raw
        in vectors['app_pin_proof_request'] as List<dynamic>) {
      final Map<String, dynamic> vector = raw as Map<String, dynamic>;
      test(vector['name'] as String, () {
        final String sent = jsonEncode(vector['body']);
        expect(
          sent,
          vector['sent_body'],
          reason: 'the body of the request it unlocks',
        );
        expect(
          jsonEncode(
            appPinProofRequest(
              pin: vector['pin'] as String,
              method: 'POST',
              path: vector['path'] as String,
              encodedBody: sent,
              nonce: vector['nonce'] as String,
            ),
          ),
          vector['asked_body'],
        );
      });
    }
  });
}
