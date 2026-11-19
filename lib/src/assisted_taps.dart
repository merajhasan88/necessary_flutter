/// The taps and long presses an assistive service asks this app's own
/// widgets to perform (Android collector 13), for the accessibility
/// measurement's `clicks_without_touch`.
///
/// A click a service performs makes no touch, and a Flutter screen reports it
/// to Android only for widgets that send tap feedback (Material's ink, toggles,
/// Cupertino's buttons): a plain gesture detector, or a button with its
/// feedback off, reports nothing. Every such click reaches Dart as a semantics
/// action, which only an assistive service sends, so the plugin is told of
/// each one here; the native side counts a click told both ways once.
library;

import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/foundation.dart';
import 'package:flutter/scheduler.dart';
import 'package:flutter/services.dart';

/// Watches the semantics actions while the app enables the accessibility
/// measurement; Android only.
class AssistedTaps {
  AssistedTaps._();

  static const MethodChannel _channel = MethodChannel('necessary/integrity_v1');

  static bool _wanted = false;
  static ui.SemanticsActionEventCallback? _ours;
  static ui.SemanticsActionEventCallback? _inner;
  static bool _lost = false;

  /// The zone the watch was last put in or taken out from, for tests.
  @visibleForTesting
  static Zone? changedIn;

  /// Starts or stops watching. The handler is changed from a frame callback,
  /// so in the zone the binding's frames run in, where it set its own: the
  /// app's handler keeps its zone, whichever zone asks.
  static void watch({required bool on}) {
    if (defaultTargetPlatform != TargetPlatform.android) {
      return;
    }
    _wanted = on;
    if (on == (_ours != null)) {
      return;
    }
    final SchedulerBinding binding;
    try {
      binding = SchedulerBinding.instance;
    } on FlutterError {
      // No binding: nothing handles semantics actions, so none can arrive.
      return;
    }
    binding.addPostFrameCallback(
      (_) => _change(),
      debugLabel: 'necessary assisted taps',
    );
    binding.scheduleFrame();
  }

  static void _change() {
    changedIn = Zone.current;
    final ui.PlatformDispatcher dispatcher = ui.PlatformDispatcher.instance;
    if (_wanted && _ours == null) {
      final ui.SemanticsActionEventCallback? inner =
          dispatcher.onSemanticsActionEvent;
      if (inner == null) {
        return;
      }
      late final ui.SemanticsActionEventCallback ours;
      ours = (ui.SemanticsActionEvent event) {
        if (identical(_ours, ours) &&
            (event.type == ui.SemanticsAction.tap ||
                event.type == ui.SemanticsAction.longPress)) {
          _report();
        }
        inner(event);
      };
      _inner = inner;
      _ours = ours;
      dispatcher.onSemanticsActionEvent = ours;
    } else if (!_wanted && _ours != null) {
      // Put back only where nothing wrapped over it since; otherwise it stays
      // in the chain, handing every action on and counting none.
      if (identical(dispatcher.onSemanticsActionEvent, _ours)) {
        dispatcher.onSemanticsActionEvent = _inner;
      }
      _ours = null;
      _inner = null;
    }
  }

  static void _report() {
    _channel
        .invokeMethod<void>('clickPerformed')
        .then<void>(
          (_) {},
          // Never an error in the app's zone: the scan's clicks are left out
          // instead (takeLost).
          onError: (Object _) => _lost = true,
        );
  }

  /// Whether a tap could not be told to the plugin since the last call.
  static bool takeLost() {
    final bool lost = _lost;
    _lost = false;
    return lost;
  }
}
