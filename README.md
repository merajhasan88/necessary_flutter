# necessary

Device trust for Flutter apps on Android and iOS. The plugin gives your app a key that cannot leave the
phone, signed measurements of the phone and of the app running on it, and a proof on each request your
app sends — and, if you turn them on, a second key the person must unlock to approve a request, and a
PIN your backend checks. **It never scores and never decides: your backend does.** The integration guide
(`doc/integration_guide.md`) is the protocol: what the plugin sends and how your backend checks it.

Android 7.0 (API 24) and later; iOS 15 and later. Status: 0.1.0, not yet published.

## Install

```yaml
dependencies:
  necessary: ^0.1.0
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
says so to your backend. iOS makes per-use keys only. Removing the screen lock, or enrolling another
biometric for a biometric key, makes the key unusable; the person then re-enrols a new one with their
own re-authentication — `stepUpReenrolProof` builds the proof the new key signs, as the guide's step-up
section describes. An app whose backend sets the policy assigns `trust.stepUp` before `start()`.

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
back what it had: a window your app keeps secure itself stays secure.

Your backend's refusals reach your app as `ApiException` with the guide's codes: `app_pin_not_set`,
`app_pin_invalid` (it counts), `app_pin_locked` (a new PIN, set with the re-authentication, unlocks it).
Step-up and the app PIN combine: your backend decides which requests need which.

## What happens when

| When | What the plugin does |
|---|---|
| The key is lost — an Android reinstall, a cleared keystore | `start()` makes a new key and a new installation ID; `trust.identity!.createdThisLaunch` is true, so forget what you kept for the old installation. Your backend links the two only provisionally, by the reinstall hint |
| iOS keeps the key across a reinstall | with its ID, the same installation comes back; without it, the plugin proposes a new ID, your backend answers with the one it holds for the key, and the plugin keeps that one |
| The app's process restarts | nothing is kept in memory: `start()` again finds the same key and installation, and proves it for a new installation session |
| The activity or scene is recreated | screen protection stays on the new window; a step-up prompt the recreation cancelled answers `STEPUP_CANCELLED`: ask again |
| Two calls at once | `start()`, `prove()` and the same `scan()` run once, and the second caller gets the first's result; scans for different operations run apart |
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
A fully compromised phone can falsify what it measures and can use a genuine key to sign what it likes:
the measurements raise the cost of fraud, and your backend weighs them with its own business logic.

## Licence

Copyright 2026 Meraj Hasan. Licensed under the Apache License, Version 2.0 (`LICENSE`, `NOTICE`).
