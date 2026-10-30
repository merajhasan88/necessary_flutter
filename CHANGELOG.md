## 0.1.0

- First release: an installation key the plugin never exports (Android Keystore, StrongBox where the
  phone has it; the Secure Enclave on iOS; a software key where the secure hardware declines, and
  `key_security` reports where, as the phone says), registration and proof of possession, a signed proof
  on every request, signed scans answering the measurement contract (report format 1, Android
  collector 8, iOS collector 5), a scan made for one request, and, when turned on, step-up approval
  with a second key and the app PIN.
- Sample backends in Python, TypeScript and C#, and the integration guide they are written from.
- A call that `reset()` or `close()` ends while it runs throws `InterruptedCallException` and keeps
  nothing; step-up waits for `reenrolStepUp` (`STEPUP_REENROL_PENDING`) whenever your backend does not
  hold the phone's step-up key.
- Needs Flutter 3.44 and Dart 3.12 or later: the Android build uses the Kotlin Gradle plugin's
  `kotlin.compilerOptions`, which Flutter supports from 3.44 (AGP 9, built-in Kotlin off). The example
  app needs Flutter 3.47.
