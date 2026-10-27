// The report-size rule: a report a backend would refuse for its size is never
// sent. The lists the contract lets a collector shorten are halved, and say
// truncated, until it fits; anything else is an error naming the limit --
// nothing is cut silently.
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:necessary/necessary.dart';

Map<String, dynamic> _report(Map<String, dynamic> probes) => <String, dynamic>{
  'challenge_id': 'c',
  'challenge_nonce': 'n',
  'installation_id': 'i',
  'platform': 'android',
  'collector_version': 8,
  'collected_at': 1,
  'probe_results': probes,
  'enabled_measurements': <String>['accessibility'],
  'version': 1,
};

int _bytes(Map<String, dynamic> report) =>
    utf8.encode(jsonEncode(report)).length;

Map<String, dynamic> _service(int i) => <String, dynamic>{
  'package': 'com.example.service.with.a.long.name.number$i',
  'service': 'com.example.service.with.a.long.name.number$i.Service',
  'system': false,
  'installer': 'com.android.vending',
};

void main() {
  test('a report that fits is sent as it is', () {
    final Map<String, dynamic> report = _report(<String, dynamic>{
      'accessibility': <String, dynamic>{
        'status': 'ok',
        'services': <Map<String, dynamic>>[_service(1)],
        'truncated': false,
      },
    });
    expect(fitReport(report), report);
  });

  test(
    "a list the contract lets shorten is halved, and says so, until it fits",
    () {
      final Map<String, dynamic> report = _report(<String, dynamic>{
        'accessibility': <String, dynamic>{
          'status': 'ok',
          'services': <Map<String, dynamic>>[
            for (int i = 0; i < 2000; i++) _service(i),
          ],
          'settings_only': <String>[],
          'truncated': false,
        },
        'device': <String, dynamic>{'status': 'ok', 'model': 'm'},
      });
      expect(_bytes(report), greaterThan(reportByteLimit));
      final Map<String, dynamic> fitted = fitReport(report);
      expect(_bytes(fitted), lessThanOrEqualTo(reportByteLimit));
      final Map<String, dynamic> accessibility =
          (fitted['probe_results'] as Map<String, dynamic>)['accessibility']
              as Map<String, dynamic>;
      expect(accessibility['truncated'], isTrue);
      expect(
        (accessibility['services'] as List<dynamic>).length,
        lessThan(2000),
      );
      expect(
        (fitted['probe_results'] as Map<String, dynamic>)['device'],
        <String, dynamic>{'status': 'ok', 'model': 'm'},
      );
      expect(
        ((report['probe_results'] as Map<String, dynamic>)['accessibility']
            as Map<String, dynamic>)['services'],
        hasLength(2000),
        reason: 'the collector answer itself is left as it came',
      );
    },
  );

  test('anything else too large is an error naming the limit', () {
    final Map<String, dynamic> report = _report(<String, dynamic>{
      'device': <String, dynamic>{
        'status': 'ok',
        'model': 'x' * (reportByteLimit + 1),
      },
    });
    expect(
      () => fitReport(report),
      throwsA(
        isA<ApiException>()
            .having((ApiException e) => e.code, 'code', 'report_too_large')
            .having(
              (ApiException e) => e.details?['limit'],
              'limit',
              reportByteLimit,
            ),
      ),
    );
  });
}
