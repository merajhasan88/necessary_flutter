## Unreleased

- iOS (collector 7): an app image whose code the App Store encrypted on disk is no longer compared with
  its file — the file holds encrypted bytes and memory the decrypted ones, so a genuine App Store
  install would have differed in every encrypted byte. Such an image is skipped with its `__text`
  bytes and named in `app_images_not_compared`, so `app_complete` is false; builds stored in the clear
  are compared as before.
- `doc/measurements.md` is the same for every Necessary SDK: it says "the SDK" where it said "the
  plugin", and leaves what differs between SDKs — the collector versions, the Android and iOS versions,
  how an app turns on a personal measurement — to each SDK's README.
- `doc/measurements.md` says what the status `ok` means: measured, never "all clear" — the example
  app's badge already says *measured*. The report's value stays `ok`.
- The measurements and the integration guide, checked against the code: `root_shell` tries `command -v
  su`, then `which su`; Android's `app` region is what is mapped from the APK plus the libraries the SDK
  names beside it; the iOS jailbreak paths are listed in full; the guide cites `RULES.md` sections 2
  and 7, and `RULES.md` says `ok` means measured.

## 0.1.2

- The product is named Necessary: the package's description, the README, the integration guide and the
  measurement contract's titles say "Necessary" or "device integrity" where they said "device trust".
  No change to the code, the API (the class is still `DeviceTrust`), the report or the contract's rules;
  the schema's `$id` stays as it was.

## 0.1.1

- iOS: the collector, now version 6, sends the memory page size with `device`, and asks screen capture
  of the screen showing the app: with no window of the app's in the foreground, `recording` is left out
  and `recording_status` says `unavailable`, as on Android.
- `doc/measurements.md`: every measurement the plugin sends, field by field.
- The README, like the example's, says how to install the example app, test it step by step, and watch
  each measurement change one at a time.
- The README opens with links to the integration guide, the measurements and the measurement contract;
  it and the guide explain the contract folder's name, `android-8-ios-5`: the lowest collector versions
  the contract accepts, not the Android and iOS versions.

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
