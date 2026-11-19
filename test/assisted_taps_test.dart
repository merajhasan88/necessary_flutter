import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:necessary/src/assisted_taps.dart';

void main() {
  const MethodChannel channel = MethodChannel('necessary/integrity_v1');
  late List<String> told;
  late List<ui.SemanticsActionEvent> handled;
  late ui.SemanticsActionEventCallback? binding;

  ui.SemanticsActionEvent event(ui.SemanticsAction type) =>
      ui.SemanticsActionEvent(type: type, viewId: 0, nodeId: 1);

  setUp(() {
    told = <String>[];
    handled = <ui.SemanticsActionEvent>[];
    binding = ui.PlatformDispatcher.instance.onSemanticsActionEvent;
    // The app's own handler, as the binding sets it.
    ui.PlatformDispatcher.instance.onSemanticsActionEvent = handled.add;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (MethodCall call) async {
          told.add(call.method);
          return null;
        });
  });

  tearDown(() {
    ui.PlatformDispatcher.instance.onSemanticsActionEvent = binding;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  testWidgets('taps and long presses are told, every action still handled, '
      'and the handler changes in the frames\' zone, not the caller\'s', (
    WidgetTester tester,
  ) async {
    runZoned(
      () => AssistedTaps.watch(on: true),
      zoneValues: <Object, Object>{#caller: true},
    );
    await tester.pump();
    expect(AssistedTaps.changedIn![#caller], isNull);
    final ui.SemanticsActionEventCallback ours =
        ui.PlatformDispatcher.instance.onSemanticsActionEvent!;
    ours(event(ui.SemanticsAction.tap));
    ours(event(ui.SemanticsAction.scrollUp));
    ours(event(ui.SemanticsAction.longPress));
    await tester.pump();
    expect(told, <String>['clickPerformed', 'clickPerformed']);
    expect(
      handled.map((ui.SemanticsActionEvent e) => e.type),
      <ui.SemanticsAction>[
        ui.SemanticsAction.tap,
        ui.SemanticsAction.scrollUp,
        ui.SemanticsAction.longPress,
      ],
    );
    // A second caller does not wrap twice.
    AssistedTaps.watch(on: true);
    await tester.pump();
    expect(
      identical(ui.PlatformDispatcher.instance.onSemanticsActionEvent, ours),
      isTrue,
    );
    // Off: the app's handler is back.
    AssistedTaps.watch(on: false);
    await tester.pump();
    ui.PlatformDispatcher.instance.onSemanticsActionEvent!(
      event(ui.SemanticsAction.tap),
    );
    expect(told, hasLength(2));
    expect(handled, hasLength(4));
  });

  testWidgets(
    'wrapped over by something else, it stays in the chain and counts none',
    (WidgetTester tester) async {
      AssistedTaps.watch(on: true);
      await tester.pump();
      final ui.SemanticsActionEventCallback ours =
          ui.PlatformDispatcher.instance.onSemanticsActionEvent!;
      final List<ui.SemanticsAction> outer = <ui.SemanticsAction>[];
      ui.PlatformDispatcher.instance.onSemanticsActionEvent =
          (ui.SemanticsActionEvent e) {
            outer.add(e.type);
            ours(e);
          };
      AssistedTaps.watch(on: false);
      await tester.pump();
      ui.PlatformDispatcher.instance.onSemanticsActionEvent!(
        event(ui.SemanticsAction.tap),
      );
      expect(outer, <ui.SemanticsAction>[ui.SemanticsAction.tap]);
      expect(handled, hasLength(1));
      expect(told, isEmpty);
    },
  );

  testWidgets(
    'a tap the plugin could not be told of is reported once as lost',
    (WidgetTester tester) async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
            throw PlatformException(code: 'DETACHED');
          });
      AssistedTaps.watch(on: true);
      await tester.pump();
      ui.PlatformDispatcher.instance.onSemanticsActionEvent!(
        event(ui.SemanticsAction.tap),
      );
      await tester.pump();
      expect(AssistedTaps.takeLost(), isTrue);
      expect(AssistedTaps.takeLost(), isFalse);
      AssistedTaps.watch(on: false);
      await tester.pump();
    },
  );
}
