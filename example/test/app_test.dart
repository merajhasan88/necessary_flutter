// The example's screen before it talks to a backend: its sections, and the
// personal measurements switched on and shown as the code that does it.
import 'package:flutter_test/flutter_test.dart';
import 'package:necessary_example/main.dart';

void main() {
  testWidgets('the sections, and the personal measurements as code', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const ExampleApp());
    expect(find.text('Necessary'), findsOneWidget);
    for (final String section in <String>[
      'Installation',
      'Measurements',
      'Account',
      'Requests',
      'Requests a backend must refuse',
      'Log',
    ]) {
      expect(find.text(section), findsOneWidget, reason: section);
    }
    await tester.tap(find.text('Measurements'));
    await tester.pumpAndSettle();
    expect(find.text('trust.personalMeasurements = {};'), findsOneWidget);
    await tester.ensureVisible(find.text('All of them'));
    await tester.tap(find.text('All of them'));
    await tester.pumpAndSettle();
    expect(
      find.textContaining('PersonalMeasurement.mockLocation,'),
      findsOneWidget,
    );
    expect(find.text('Ask for the location permission'), findsOneWidget);
  });
}
