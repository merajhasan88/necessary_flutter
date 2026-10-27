// The plugin's reports against the published measurement contract: from the
// collector answer in each sample of contract/report-1/android-8-ios-5/, the
// plugin builds that sample's report -- every member but the phone's clock.
// The plugin judges nothing: an invalid or refused sample is built just as
// faithfully.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:necessary/necessary.dart';

import 'repository_files.dart';

class _Key implements NativeInstallationKey {
  @override
  Future<NativeKeyMetadata> getOrCreateKey() => throw UnimplementedError();

  @override
  Future<String> signPayload(String payloadBase64Url) async => 'signed';

  @override
  Future<void> deleteKey() async {}
}

/// Answers what the sample's collector answered.
class _Recorded extends NativeIntegrityCollector {
  _Recorded(this.report);

  final Map<String, dynamic> report;

  @override
  Future<Map<String, dynamic>> collect({
    required List<String> requiredProbes,
    required String challengeNonce,
    required List<String> enabledMeasurements,
    List<String> optionalProbes = const <String>[],
  }) async => <String, dynamic>{
    'platform': report['platform'],
    'challenge_nonce_echo': challengeNonce,
    'collector_version': report['collector_version'],
    'probes': report['probe_results'],
  };
}

void main() {
  final List<File> samples =
      repositoryDirectory('contract/report-1/android-8-ios-5/samples')
          .listSync()
          .whereType<File>()
          .where((File file) => file.path.endsWith('.json'))
          .toList()
        ..sort((File a, File b) => a.path.compareTo(b.path));

  test('the contract has its samples', () => expect(samples.length, 11));

  for (final File file in samples) {
    final Map<String, dynamic> sample =
        jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    final Map<String, dynamic> expected =
        sample['report'] as Map<String, dynamic>;
    final Map<String, dynamic> plan = sample['plan'] as Map<String, dynamic>;
    test(file.uri.pathSegments.last, () async {
      final SignedReport built = await collectReport(
        challenge: ScanChallenge.fromJson(<String, dynamic>{
          'challenge_id': expected['challenge_id'],
          'nonce': expected['challenge_nonce'],
          'platform': expected['platform'],
          'required_probes': plan['required_probes'],
          'optional_probes': plan['optional_probes'],
        }),
        identity: InstallationIdentity(
          installationId: expected['installation_id'] as String,
          nativeKey: _Key(),
          metadata: NativeKeyMetadata(
            publicKey: const <String, dynamic>{},
            algorithm: 'ES256',
            keyAlias: 'sample',
            provider: 'sample',
            securityLevel: 'software',
            hardwareBacked: false,
            privateKeyExportable: false,
            signatureFormat: 'der',
            created: false,
          ),
        ),
        collector: _Recorded(expected),
        enabledMeasurements: List<String>.from(
          expected['enabled_measurements'] as List,
        ),
      );
      expect(built.report['collected_at'], isA<int>());
      expect(<String, dynamic>{
        ...built.report,
        'collected_at': expected['collected_at'],
      }, expected);
      expect(
        jsonDecode(
          utf8.decode(base64Url.decode(base64Url.normalize(built.payload))),
        ),
        built.report,
        reason: 'the payload is the report, as signed',
      );
    });
  }
}
