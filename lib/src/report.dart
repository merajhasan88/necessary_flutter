/// The scan (the public guide, section 2): your backend's challenge, the
/// measurements it asks for, and the report the installation key signs.
library;

import 'dart:convert';

import 'collector.dart';
import 'errors.dart';
import 'installation_key.dart';
import 'request_proof.dart';

/// The most a backend takes: a report of 65,536 bytes of JSON (the
/// measurement contract, section 1).
const int reportByteLimit = 65536;

/// The lists a report may shorten, by measurement -- each beside the
/// `truncated` flag that says the phone had more (the measurement contract,
/// section 6).
const Map<String, List<String>> shortenableLists = <String, List<String>>{
  'accessibility': <String>['services', 'settings_only'],
  'notification_access': <String>['listeners'],
  'other_access': <String>['device_admins', 'remote_access_apps'],
};

/// [report] made to fit [reportByteLimit]: the longest list it may shorten is
/// halved, and marked `truncated`, until it fits. A report that cannot fit is
/// never cut anywhere else: the answer is an error naming the limit.
Map<String, dynamic> fitReport(Map<String, dynamic> report) {
  final Map<String, dynamic> probes = Map<String, dynamic>.from(
    report['probe_results'] as Map,
  );
  final Map<String, dynamic> fitted = <String, dynamic>{
    ...report,
    'probe_results': probes,
  };
  int size() => utf8.encode(jsonEncode(fitted)).length;
  for (int bytes = size(); bytes > reportByteLimit; bytes = size()) {
    String? probe;
    String? field;
    int longest = 0;
    shortenableLists.forEach((String name, List<String> fields) {
      final Object? result = probes[name];
      for (final String list in fields) {
        final Object? items = result is Map ? result[list] : null;
        if (items is List && items.length > longest) {
          probe = name;
          field = list;
          longest = items.length;
        }
      }
    });
    if (probe == null) {
      throw ApiException(
        'The report would be $bytes bytes; a backend takes at most '
        '$reportByteLimit.',
        code: 'report_too_large',
        details: <String, dynamic>{'bytes': bytes, 'limit': reportByteLimit},
      );
    }
    final Map<String, dynamic> shortened = Map<String, dynamic>.from(
      probes[probe] as Map,
    );
    shortened[field!] = (shortened[field] as List).sublist(0, longest ~/ 2);
    shortened['truncated'] = true;
    probes[probe!] = shortened;
  }
  return fitted;
}

/// A challenge for a scan, as your backend sent it.
class ScanChallenge {
  ScanChallenge({
    required this.challengeId,
    required this.nonce,
    required this.platform,
    required this.requiredProbes,
    required this.optionalProbes,
    required this.answer,
  });

  factory ScanChallenge.fromJson(Map<String, dynamic> value) {
    List<String> names(Object? list) => list is List
        ? list.map((Object? item) => item.toString()).toList(growable: false)
        : const <String>[];
    return ScanChallenge(
      challengeId: value['challenge_id'] as String,
      nonce: value['nonce'] as String,
      platform: value['platform'] as String,
      requiredProbes: names(value['required_probes']),
      optionalProbes: names(value['optional_probes']),
      answer: value,
    );
  }

  final String challengeId;
  final String nonce;
  final String platform;

  /// The measurements the report must answer.
  final List<String> requiredProbes;

  /// The personal measurements asked for, answered only where the app
  /// enabled them; none from a backend that names none.
  final List<String> optionalProbes;

  /// The challenge whole.
  final Map<String, dynamic> answer;
}

/// A report as the installation key signed it.
class SignedReport {
  const SignedReport({
    required this.report,
    required this.payload,
    required this.signature,
  });

  /// The report, as signed.
  final Map<String, dynamic> report;

  /// `report_payload`: the base64url of the report's JSON bytes.
  final String payload;

  /// `report_signature`.
  final String signature;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'report_payload': payload,
    'report_signature': signature,
  };
}

/// Measures what [challenge] asks for -- and, of the personal measurements it
/// asks for, those in [enabledMeasurements] -- and signs the report with
/// [identity]'s key.
Future<SignedReport> collectReport({
  required ScanChallenge challenge,
  required InstallationIdentity identity,
  required NativeIntegrityCollector collector,
  required List<String> enabledMeasurements,
}) async {
  final Map<String, dynamic> native = await collector.collect(
    requiredProbes: challenge.requiredProbes,
    challengeNonce: challenge.nonce,
    enabledMeasurements: enabledMeasurements,
    optionalProbes: challenge.optionalProbes,
  );
  if (native['probes'] is! Map) {
    throw ApiException(
      'The native collector returned no probe map.',
      code: 'invalid_native_integrity_result',
    );
  }
  if (native['platform'] != challenge.platform ||
      native['challenge_nonce_echo'] != challenge.nonce) {
    throw ApiException(
      'The native integrity response did not match the server challenge.',
      code: 'integrity_challenge_binding_failed',
    );
  }

  final Map<String, dynamic> report = fitReport(<String, dynamic>{
    'challenge_id': challenge.challengeId,
    'challenge_nonce': challenge.nonce,
    'installation_id': identity.installationId,
    'platform': challenge.platform,
    'collector_version': (native['collector_version'] as num?)?.toInt() ?? 1,
    'collected_at': DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
    'probe_results': Map<String, dynamic>.from(native['probes'] as Map),
    // The personal measurements this app enabled, whether or not this scan
    // asked for them.
    'enabled_measurements': enabledMeasurements,
    'version': 1,
  });
  final String payload = base64UrlNoPadding(utf8.encode(jsonEncode(report)));
  return SignedReport(
    report: report,
    payload: payload,
    signature: await identity.signPayload(payload),
  );
}
