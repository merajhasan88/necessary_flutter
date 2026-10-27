/// Protection of the app's window while a secret is typed.
library;

import 'package:flutter/services.dart';

/// Protects the app's window while a secret is typed. Android: no
/// screenshots, recordings or casts of the window, other apps' windows not
/// drawn over it (Android 12 and later), and touches that passed through
/// another app's window dropped. iOS cannot block screenshots; it covers the
/// window while the screen is recorded or mirrored.
///
/// Calls nest: each `protect(true)` needs its `protect(false)`, and the
/// window is put back as it was -- a window the app keeps secure itself stays
/// secure -- when the last one ends. Other apps' overlays, which no public
/// call reads, are shown again then. Returns what the window has now; an
/// older native host answers nothing, and the entry stays usable.
class SecureScreen {
  static const MethodChannel _channel = MethodChannel(
    'necessary/secure_screen_v1',
  );

  static Future<Map<String, dynamic>> protect(bool on) async {
    try {
      return await _channel.invokeMapMethod<String, dynamic>(
            'protect',
            <String, dynamic>{'on': on},
          ) ??
          const <String, dynamic>{};
    } on MissingPluginException {
      return const <String, dynamic>{};
    } on PlatformException {
      return const <String, dynamic>{};
    }
  }
}
