// The measurements view against the published contract's samples: every
// measurement each sample report carries is listed with its status, the
// hooks, gadgets and memory changes first, and each opens to its fields.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:necessary_example/measurements.dart';

/// The contract's samples, in the nearest folder from here up that holds
/// them.
List<File> _samples() {
  const String path = 'contract/report-1/android-8-ios-5/samples';
  Directory folder = Directory.current.absolute;
  while (!Directory('${folder.path}/$path').existsSync()) {
    if (folder.parent.path == folder.path) {
      throw StateError('$path: in no folder from ${Directory.current.path} up');
    }
    folder = folder.parent;
  }
  return Directory('${folder.path}/$path')
      .listSync()
      .whereType<File>()
      .where((File file) => file.path.endsWith('.json'))
      .toList()
    ..sort((File a, File b) => a.path.compareTo(b.path));
}

void main() {
  final List<File> samples = _samples();

  test('the contract has its samples', () => expect(samples, hasLength(11)));

  for (final File file in samples) {
    testWidgets(file.uri.pathSegments.last, (WidgetTester tester) async {
      final Map<String, dynamic> sample =
          jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
      final Map<String, dynamic> plan = sample['plan'] as Map<String, dynamic>;
      final Map<String, dynamic> report =
          sample['report'] as Map<String, dynamic>;
      final Map<String, dynamic> results =
          report['probe_results'] as Map<String, dynamic>;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: ListView(
              children: <Widget>[
                ScanView(
                  platform: report['platform'] as String,
                  required: List<String>.from(plan['required_probes'] as List),
                  optional: List<String>.from(plan['optional_probes'] as List),
                  results: results,
                  enabled: List<String>.from(
                    report['enabled_measurements'] as List,
                  ),
                ),
              ],
            ),
          ),
        ),
      );
      for (final String name in results.keys) {
        expect(find.text(name), findsOneWidget, reason: name);
      }
      // The hooks, gadgets and memory changes come first, and every one of
      // them is shown, asked for or not.
      expect(
        tester.getTopLeft(find.text(MeasurementGroup.hooks.title)).dy,
        lessThan(tester.getTopLeft(find.text(MeasurementGroup.app.title)).dy),
      );
      for (final MeasurementInfo info
          in (report['platform'] == 'ios'
              ? iosMeasurements
              : androidMeasurements)) {
        if (info.group == MeasurementGroup.hooks) {
          expect(find.text(info.name), findsOneWidget, reason: info.name);
        }
      }
      // Each opens, by its name, to its fields.
      for (final String name in results.keys) {
        final Finder label = find.text(name);
        await tester.ensureVisible(label);
        await tester.pumpAndSettle();
        await tester.tap(label);
        await tester.pumpAndSettle();
        final List<String> fields = <String>[
          for (final String field
              in (results[name] as Map<String, dynamic>).keys)
            if (field != 'status') field,
        ];
        if (fields.isNotEmpty) {
          expect(find.text(fields.first), findsWidgets, reason: name);
        }
      }
      expect(tester.takeException(), isNull);
    });
  }
}
