# necessary

Device integrity for Flutter apps on Android and iOS. The plugin gives your app a key it never exports — made
in the phone's keystore, in secure hardware where the phone has it and in software where it does not —
signed measurements of the phone and of the app running on it, and a proof on each request your app
sends — and, if you turn them on, a second key the person must unlock to approve a request, and a
PIN your backend checks. **It never scores and never decides: your backend does.**

Android 7.0 (API 24) and later; iOS 15 and later; Flutter 3.44 (Dart 3.12) and later — the example app
needs Flutter 3.47.

## Documentation

- [The integration guide](https://github.com/merajhasan88/necessary_flutter/blob/main/doc/integration_guide.md)
  (`doc/integration_guide.md`) — the protocol: what the plugin sends, and how your backend checks it.
- [The measurements](https://github.com/merajhasan88/necessary_flutter/blob/main/doc/measurements.md)
  (`doc/measurements.md`) — everything the plugin measures on the phone, field by field: what each
  measurement is, how it is taken, and what a complete answer holds.
- [The measurement contract](https://github.com/merajhasan88/necessary_flutter/tree/main/contract/report-1/android-8-ios-5)
  (`contract/report-1/android-8-ios-5/`) — the report's schema, its rules and sample reports. The
  folder's name is two versions: `report-1` is the report's format, and `android-8-ios-5` the lowest
  versions of the measuring code, the collector, that the contract accepts — 8 on Android and 5 on iOS
  (`collector_version`; this plugin's are 9 and 7). They are not the Android or iOS versions the plugin
  runs on, which are above.
- [The example app](https://github.com/merajhasan88/necessary_flutter/tree/main/example)
  (`example/`) puts every piece below in a working app, against the
  [sample backends](https://github.com/merajhasan88/necessary_flutter/tree/main/backend)
  (in the repository, not the package). [Try the example app](#try-the-example-app), below, installs it
  and tests it step by step, measurement by measurement.

## Install

```yaml
dependencies:
  necessary: ^0.1.3
```

The plugin declares what its own features need. Your app adds only what you choose to use:

- **Location measurements**: on Android `ACCESS_COARSE_LOCATION` (and `ACCESS_FINE_LOCATION` for a
  precise location) in your manifest; on iOS `NSLocationWhenInUseUsageDescription` in `Info.plist`.
  The plugin never asks by itself: call `trust.requestLocationPermission()` from your own screen.
- **Biometric step-up on iOS**: `NSFaceIDUsageDescription` in `Info.plist`.

## Start

```dart
import 'package:necessary/necessary.dart';

final trust = DeviceTrust(
  baseUrl: 'https://api.example.com',
  // The personal measurements your app allows; your backend asks for what it needs of them.
  personalMeasurements: {PersonalMeasurement.screenCapture},
);

await trust.start(); // loads or makes the key, registers it, proves it holds it
```

`start()` makes the guide's first three calls under `baseUrl`: register the installation, ask for a key
challenge, answer it. Your backend answers each as the guide says. A new key is a new installation:
`trust.identity!.createdThisLaunch` tells your app to forget what it kept for the old one.

## Scan

```dart
final ScanResult scan = await trust.scan();
final answer = scan.answer; // your backend's answer, whole
```

The plugin measures what your backend's challenge asks for — and, of the personal measurements it asks
for, the ones your app enabled — signs the report with the installation key and sends it. It acts on the
guide's protocol errors once (a challenge expired, the installation session expired, the backend lost
the installation, a short wait); any other refusal reaches your app as an `ApiException`.

## Personal measurements

Seven measurements identify a person's phone, network or habits. Each is collected only when your app
enables it **and** your backend's challenge asks for it (`optional_probes`); otherwise the report says
`not_enabled`. None is on unless your app turns it on:

```dart
trust.personalMeasurements = {
  PersonalMeasurement.screenCapture, // the screen recorded, mirrored or cast
  PersonalMeasurement.location, // the last location the phone already knows
};
```

Set them in the constructor, or change them whenever the person does — in a privacy setting: the next
scan follows, and the installation and its step-up key stay as they are.

| `PersonalMeasurement` | What it reports | Platforms |
|---|---|---|
| `localAddresses` | the phone's own IP addresses, link-local ones left out | both |
| `accessibility` | the Accessibility services that are on, and the keyboard in use | Android |
| `notificationAccess` | the apps allowed to read notifications | Android |
| `otherAccess` | device-administrator apps, and known remote-control apps installed | Android |
| `screenCapture` | the screen being recorded, mirrored or cast | both |
| `location` | the last location the phone already knows — never a fresh fix, never a prompt | both |
| `mockLocation` | whether that location was faked | both |

The location needs the person's permission as well: declare it (Install, above) and ask from your own
screen with `await trust.requestLocationPermission()`, which answers `precise`, `approximate` or
`none`. On iOS the three Android-only measurements answer `unsupported`.

## Prove your own requests

Every request your app sends to your own API can carry a proof that this installation's key signed it,
so a copied session token is useless on another phone:

```dart
final body = jsonEncode({'amount': 25, 'to': 'payee-7'});
final proof = await trust.signRequest(
  method: 'POST',
  path: '/v1/transfer',
  bearer: accountSession, // your backend's session for this installation
  body: body, // sent exactly as signed
);
await http.post(
  Uri.parse('https://api.example.com/v1/transfer'),
  headers: {
    'Authorization': 'Bearer $accountSession',
    'Content-Type': 'application/json',
    ...proof.headers, // X-Access-Proof, X-Access-Signature
  },
  body: body,
);
```

Each proof serves its request once. `trust.send(proof)` sends it through the plugin's transport instead.

## A scan for one action

For a request that matters — a payment, a new payee — have the scan name it, under the account session
that will send it, and send the scan's report with the request:

```dart
final operation = describeOperation('POST', '/v1/transfer', body);
final scan = await trust.scan(session: accountSession, operation: operation);
final proof = await trust.signRequest(
  method: 'POST',
  path: '/v1/transfer',
  bearer: accountSession,
  body: body,
  reportId: scan.reportId, // X-Integrity-Report
);
```

## Step-up: the person approves one request

Turn it on, and choose how the key is unlocked:

```dart
final trust = DeviceTrust(
  baseUrl: 'https://api.example.com',
  stepUp: const StepUpOptions(factor: 'passcode', mode: 'per_use'),
);
await trust.start(); // registers the step-up key with the installation

if (trust.stepUpUnavailable != null) {
  // This phone cannot make the key -- no screen lock, say. Step-up is off here.
}

final proof = await trust.signRequest(
  method: 'POST',
  path: '/v1/transfer',
  bearer: accountSession,
  body: body,
  stepUp: true,
  reason: 'Approve the transfer of 25', // what the phone shows the person
);
```

| Option | Values |
|---|---|
| `factor` | `passcode` (the phone's PIN, pattern or password) or `biometric` (a fingerprint or face enrolled now) |
| `mode` | `per_use` (unlocked for every signature) or `windowed` with `windowSeconds` (one unlock for a while; Android only) |

Android 9 and 10 cannot ask for the passcode at every signature: there a passcode key is windowed, and
says so to your backend. iOS makes per-use keys only. An app whose backend sets the policy assigns
`trust.stepUp` before `start()`.

Removing the screen lock, or enrolling another biometric for a biometric key, makes the key unusable:
an approval then fails with `NativeKeyException` `STEPUP_KEY_INVALIDATED`. On Android the plugin
deletes the key only when Android itself says so; when the keystore cannot establish whether the key is
usable — a failure it may recover from — the approval fails with `STEPUP_KEY_UNAVAILABLE` and the key
is kept: try again later. The person re-enrols a new key with their own re-authentication, which also
replaces a key that stays unavailable:

```dart
await trust.reenrolStepUp(
  session: accountSession,
  reauthentication: {'password': password}, // as your backend requires
);
```

A new key is made, the person unlocks it to sign its proof, and your backend takes it for that account
alone; approvals use it from then on. The call goes to `/v1/installations/stepup-key`, or to your API's
own path: `StepUpOptions(reenrolPath: ...)`. Until your backend has taken the new key — the person
cancelled the prompt, the password was wrong, the answer was lost — approvals fail with
`STEPUP_REENROL_PENDING`, across restarts too: call `reenrolStepUp` again. The same holds for a key the
phone made after the installation was registered — the screen lock was off at the first `start()` and
set later, say — since your backend takes a step-up key only at an installation's first registration:
`start()` reports `stepUpUnavailable` `STEPUP_REENROL_PENDING`, and re-enrolment registers the key.

## The app PIN: the person's PIN for one request

Turn it on; the two paths default to the guide's and can be your API's own:

```dart
final trust = DeviceTrust(
  baseUrl: 'https://api.example.com',
  appPin: const AppPinOptions(), // path: '/v1/account/app-pin', proofPath: '/v1/account/app-pin/proof'
);

// Setting it: with the person's own re-authentication, as your backend requires.
await trust.setAppPin(
  session: accountSession,
  pin: pin,
  reauthentication: {'password': password},
);

// Using it: your backend checks the PIN for this one request, and the request carries its proof.
final proof = await trust.signRequest(
  method: 'POST',
  path: '/v1/transfer',
  bearer: accountSession,
  body: body,
  appPin: pin,
);
```

The PIN travels once, in a signed body, never in a header, and the plugin never stores it. Protect the
screen while it is typed:

```dart
await SecureScreen.protect(true); // Android: no screenshots or recording; iOS: covered while captured
// ... the PIN is typed ...
await SecureScreen.protect(false);
```

Calls nest — each `protect(true)` needs its `protect(false)` — and when the last one ends the window gets
back what it had: a window your app keeps secure itself stays secure. On iOS the cover is over your app's
window, not the system keyboard; on the iPhone it was tested on (iOS 15), the keyboard's key presses did
not show in a recording. Opening Control Center to start a recording closes the keyboard, so protect
whenever the field has focus, as the example does.

Your backend's refusals reach your app as `ApiException` with the guide's codes: `app_pin_not_set`,
`app_pin_invalid` (it counts), `app_pin_locked` (a new PIN, set with the re-authentication, unlocks it).
Step-up and the app PIN combine: your backend decides which requests need which.

## What happens when

| When | What the plugin does |
|---|---|
| The key is lost — an Android reinstall, a cleared keystore | `start()` makes a new key and a new installation ID; `trust.identity!.createdThisLaunch` is true, so forget what you kept for the old installation. Your backend links the two only provisionally, by the reinstall hint |
| iOS keeps the key across a reinstall | with its ID, the same installation comes back; without it, the plugin proposes a new ID, your backend answers with the one it holds for the key, and the plugin keeps that one |
| The app's process restarts | nothing is kept in memory: `start()` again finds the same key and installation, and proves it for a new installation session |
| The activity, a scene or a window is replaced | screen protection follows: Android sets it on each new window; on iOS the cover is placed again, on the window the person sees in each scene, whenever a window becomes key, visible or hidden or a scene comes to the foreground — and protection asked for before any window exists covers the first one. A step-up prompt the recreation cancelled answers `STEPUP_CANCELLED`: ask again |
| The Flutter engine is torn down | iOS drops the protection, its covers and its observers with the engine |
| Two calls at once | `start()`, `prove()`, `loadIdentity()` and the same `scan()` run once, and the second caller gets the first's result; scans for different operations, or asked after the personal measurements changed, run apart |
| A step-up prompt is open | on iOS the plugin's other calls — a scan, a request's signature — wait until the person answers it; Android runs them meanwhile |
| `reset()` or `close()` while calls run | the calls end with `InterruptedCallException` and keep nothing — no session, no installation ID, no report sent, no request proof or app PIN answer handed out; a reset first waits for every write and key change still running, so none outlives it; after a reset, new calls wait for the deletion and never join one made before. A proof handed out before the reset, or a request already sent, is beyond it: reset is local |
| The step-up key cannot be deleted | `reset()` fails with that `NativeKeyException` (`KEY_DELETE_FAILED`), the installation itself gone: call it again. None to delete, or no step-up on the phone, is no failure |
| A call abandoned, or its answer lost | a scan is simply asked for again — a challenge serves once; the plugin never sends a signed request twice: sign it again, and let your backend decide whether the first one reached it |
| A report over 65,536 bytes | it is never sent: the app lists the contract lets a collector shorten are shortened, and say `truncated`; anything else answers an `ApiException` `report_too_large` |

## Your own transport

```dart
final trust = DeviceTrust.over(MyTransport()); // implements DeviceTrustTransport
```

A transport sends each message the plugin builds and answers your backend's JSON object, or throws an
`ApiException` with its `code`, `message` and `details`. To carry the messages over an API of your own
shape instead, use the pieces directly — `trust.client`, `collectReport`, `signRequest` — and make the
guide's checks in your backend.

## What the plugin never does

It never scores, decides, or tells your app a score; never stores your account session; never sends the
PIN in a header; and uses no platform attestation (Play Integrity, SafetyNet, App Attest, DeviceCheck).
It never exports a private key, but it cannot prove to your backend where a key is kept: the
registration's `key_security` is the phone's own word, and where the secure hardware declines — the iOS
Simulator, some configurations — the key is a software key, which a compromised phone can copy. A fully
compromised phone can falsify what it measures and can use a genuine key to sign what it likes: the
measurements raise the cost of fraud, and your backend weighs them with its own business logic.

## Try the example app

The example app (`example/`) puts every piece above in a working app, against a sample backend.
Its own README carries the same steps.

### Install it

The sample backends live in the repository, not in the package, so start from a clone.

1. Clone the repository:

   ```sh
   git clone https://github.com/merajhasan88/necessary_flutter.git
   cd necessary_flutter
   ```

2. Start a sample backend on your computer. It answers on `127.0.0.1` only. In Python 3.10 or later:

   ```sh
   pip install --require-hashes -r backend/python/requirements.txt
   python3 backend/python/server.py --port 8787 --schema contract/report-1/android-8-ios-5/report.schema.json
   ```

   The TypeScript and C# samples run the same way; their commands are in
   [`backend/README.md`](https://github.com/merajhasan88/necessary_flutter/blob/main/backend/README.md).
3. Run the example app, which needs Flutter 3.47, from `example/`:
   - **On an Android emulator**, a debug build reaches your computer at `10.0.2.2`:

     ```sh
     flutter run --dart-define=NECESSARY_BACKEND_URL=http://10.0.2.2:8787
     ```

   - **On an Android phone** connected by USB with USB debugging on, forward the port first:

     ```sh
     adb reverse tcp:8787 tcp:8787
     flutter run --dart-define=NECESSARY_BACKEND_URL=http://127.0.0.1:8787
     ```

   - **A release build**, on Android or iOS, talks only HTTPS: the plugin refuses an `http://` address in
     a release build. Put the sample behind an HTTPS proxy on a name the phone can resolve, with a
     certificate the phone trusts, and give that address:

     ```sh
     flutter run --release --dart-define=NECESSARY_BACKEND_URL=https://backend.example.com
     ```

   - **On an iPhone**, open `example/ios/Runner.xcworkspace` in Xcode on a Mac, choose your team under
     Signing & Capabilities, and run as above with the iPhone connected. An iPhone reaches your computer
     over your network, so give the address of the HTTPS proxy.

   To offer several backends, name each:
   `--dart-define='NECESSARY_BACKENDS=Python=https://…;TypeScript=https://…'`. A debug build measures
   itself as one — `debuggable` in `app_identity` — so judge the measurements on a release build.

### Test it on a phone, step by step

With several backends (`NECESSARY_BACKENDS`), tap one at the top and run the steps once for each. Every
result line carries a ✓ when the backend did what it should, a red ✗ when it did not.

1. **Installation → Start.** Expect: `Installation …, proved; step-up on.` On a phone without a screen
   lock, step-up is off: `step-up off here (…)`, and step 7 cannot pass.
2. **Measurements:** switch on **All of them**, tap **Ask for the location permission** and allow it.
   Once is enough; the switches reset when the app restarts.
3. **Scan.** Expect: `The backend answered next: allow, report …` — the sample backends answer
   `scan_again` when a measurement could not be read, and `review` when its figures contradict each
   other. Under **Hooks, gadgets and memory changes** every row reads `measured`, none `not asked`. Open
   any row for the fields the phone sent.
4. **Account → Sign in.** Expect: `An account session for this installation.`
5. **Requests → Protected request.** Expect: ✓ `{"done":"/v1/demo/echo"}`.
6. **Sensitive, without approval.** Expect: ✓ `Refused, as it should be: 403 needs_approval`.
7. **Sensitive, with step-up**, then unlock with the phone's passcode. Expect: ✓
   `{"done":"/v1/demo/sensitive"}`.
8. Type 6 digits in **App PIN**, then **Set the app PIN**. Expect: ✓ `Set, with the account password.`
9. **Sensitive, with the app PIN.** Expect: ✓ `{"done":"/v1/demo/sensitive"}`.
10. **Requests a backend must refuse:** tap each of the four. Expect a ✓ on each: `Refused, as it should
    be: 401 proof_reused` for the request sent twice, `401 proof_not_accepted` for the other three.

If the phone's screen lock is removed and set again, the step-up key dies: step 7 then shows `The phone
said STEPUP_KEY_INVALIDATED`. Tap **Re-enrol the step-up key** and unlock with the passcode — expect ✓
`{"stepup_key_registered":true}` — and step 7 passes again. The new key is that account's alone. If the
lock was off at step 1 and set afterwards, **Start again** says `step-up off here
(STEPUP_REENROL_PENDING)`: the backend took the installation without a step-up key, so re-enrol the same
way after step 4.

The app PIN belongs to the account, not to the phone. Phones signed in with the same handle share it: a
PIN set on one unlocks requests on the other, and before any is set, step 9 answers `app_pin_not_set`.
Sign in with another handle for an account of its own.

### A session copied to another phone

A session token copied off one phone must be useless on another. You need two phones running the
example against the same backend.

1. **Phone A:** steps 1 and 4 above, then **Requests a backend must refuse → Copy this phone's session**.
   Expect: `Copied this phone's session`.
2. Get the copied text to phone B, for example in a note or a message to yourself. It holds phone A's
   session and installation ID; the sample's sessions last ten minutes.
3. **Phone B:** step 1 above, on the same backend.
4. **Phone B:** paste the text into **A session from another phone**, then tap **Use it here**. Expect: ✓
   `Refused, as it should be: 401 invalid_installation_signature`. Phone B's key cannot sign for phone A's
   installation, even when the request names it.

If step 4 reads `The session is no longer valid: sign in again`, phone A's session has expired: sign in
again on phone A and copy it again.

### Measurement by measurement

What each measurement is and every field it carries:
[`doc/measurements.md`](https://github.com/merajhasan88/necessary_flutter/blob/main/doc/measurements.md).
On a phone of your own you can watch these change, one at a time: make the change, tap **Scan**, open the
measurement's row, and change it back afterwards.

| Measurement | Change | The row then shows |
|---|---|---|
| `developer_settings` (Android) | Settings → About phone → tap Build number seven times; then Developer options → USB debugging | `developer_options_enabled`, then `adb_enabled`, true |
| `network` | turn on a VPN app; or set a manual proxy on your Wi-Fi network | `vpn_active` true, the tunnel's interface in `interfaces` (Android) or `scoped_interfaces` (iOS); `http_proxy_configured` true |
| `local_addresses` | switch between Wi-Fi and mobile data | the phone's own addresses, per interface |
| `screen_capture` | start the screen recorder (Android 15 and later; on iOS from Control Center); connect an external display | `recording` true; `external_displays` 1 |
| `location` | tap **Ask for the location permission** and allow it | the `permission`, the coordinates and their `age_seconds` |
| `mock_location` | Android: Developer options → Select mock location app, and run a mock-location app; iOS: simulate a location from Xcode while the app runs from it | `mock` true |
| `accessibility` (Android) | Settings → Accessibility → turn on a service such as Select to Speak; or choose another keyboard | the service in `services`; the keyboard in `keyboard` |
| `notification_access` (Android) | Settings → Notification access (under Special app access) → allow an app | the app in `listeners` |
| `other_access` (Android) | install AnyDesk, TeamViewer QuickSupport, RustDesk or AirDroid; or make an app a device administrator | the app in `remote_access_apps`; in `device_admins` |
| `app_identity` | install a build of the example made with other code | other hashes; a debug build reads `debuggable` true |
| `debug_state` (Android) | in Android Studio, Run → Attach Debugger to Android Process, on a debug build | `debugger_connected` true |
| `code_signing` (iOS) | run a development build from Xcode | `get_task_allow` true |

The rest — root and jailbreak traces, Frida and other hooking tools, code changed in memory, an emulator
or the Simulator — needs a device you are allowed to change: never a phone you depend on. On an Android
emulator `emulator.suspected` is true, and a `userdebug` image shows a debuggable, test-keys build in
`system_properties` and `root_files`; on the iOS Simulator `simulator.is_simulator` is true. Frida on a
test device shows in `runtime_maps`, `frida_ports`, `instrumentation_threads`, `exec_mappings` and
`code_integrity` on Android, and in `dyld_images` and `code_integrity` on iOS.

## Licence

Copyright 2026 Meraj Hasan. Licensed under the Apache License, Version 2.0 (`LICENSE`, `NOTICE`).
