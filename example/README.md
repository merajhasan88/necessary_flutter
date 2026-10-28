# Necessary example

The `necessary` plugin in a working app, against one of its sample backends (`../backend`): the app side
of device trust, in code. The integration guide (`../doc/integration_guide.md`) is the backend side, in
words.

## Run it

Start a sample backend on your development machine (see `../backend/README.md`), then run the app on an
Android emulator, which reaches the machine at `10.0.2.2`:

```sh
flutter run --dart-define=NECESSARY_BACKEND_URL=http://10.0.2.2:8787
```

On a phone, give the backend's address on your network. Plain HTTP serves a debug build against a local
sample only; a release build talks HTTPS. To offer several backends, name each:
`--dart-define='NECESSARY_BACKENDS=Python=https://…;TypeScript=https://…'`.

## What the screen shows

Each section opens and closes; each result says whether the backend did what it should.

| Section | What you do | What a backend that makes the guide's checks answers |
|---|---|---|
| Installation | **Start**: the key is made in the phone's keystore, registered and proved. **Prove again**. **New installation** deletes the key, as a reinstall would | the installation, its key, and the step-up key the phone made |
| Measurements | turn each personal measurement on or off, and see the code for your choice; ask for the location permission; **Scan** | every measurement the signed report carried, each opening to its fields, grouped by what it catches: the hooks, gadgets and changes in memory first. One the backend did not ask for shows as not asked |
| Account | **Sign in** (the sample makes the account at its first sign-in) | an account session for this installation |
| Requests | **Protected request**; **Sensitive, without approval**; **Sensitive, with step-up**; set the app PIN, then **Sensitive, with the app PIN** | accepted; refused, `403 needs_approval`; accepted once the person unlocks the screen lock; accepted |
| Requests a backend must refuse | one request sent twice; its body changed after signing; sent to another path; a proof ten minutes old; a session copied from another phone | each refused |

A request that a backend must refuse but that is accepted shows as a failure, so the app doubles as a check
of your own backend.

## Test it on a phone, step by step

Run a sample backend where the phone can reach it (HTTPS for a release build), and build the example
with its address: `flutter run --release --dart-define=NECESSARY_BACKEND_URL=https://…`. With several
backends (`NECESSARY_BACKENDS`), tap one at the top and run the steps once for each. Every result line
carries a ✓ when the backend did what it should, a red ✗ when it did not.

1. **Installation → Start.** Expect: `Installation …, proved; step-up on.` On a phone without a screen
   lock, step-up is off: `step-up off here (…)`, and step 7 cannot pass.
2. **Measurements:** switch on **All of them**, tap **Ask for the location permission** and allow it.
   Once is enough; the switches reset when the app restarts.
3. **Scan.** Expect: `The backend answered next: allow, report …`. Under **Hooks, gadgets and memory
   changes** every row reads `ok`, none `not asked`. Open any row for the fields the phone sent.
4. **Account → Sign in.** Expect: `An account session for this installation.`
5. **Requests → Protected request.** Expect: ✓ `{"done":"/v1/demo/echo"}`.
6. **Sensitive, without approval.** Expect: ✓ `Refused, as it should be: 403 needs_approval`.
7. **Sensitive, with step-up**, then unlock with the phone's passcode. Expect: ✓
   `{"done":"/v1/demo/sensitive"}`.
8. Type 6 digits in **App PIN**, then **Set the app PIN**. Expect: ✓ `Set, with the account password.`
9. **Sensitive, with the app PIN.** Expect: ✓ `{"done":"/v1/demo/sensitive"}`.
10. **Requests a backend must refuse:** tap each of the four. Expect a ✓ on each: `Refused, as it should
    be: 401 proof_reused` for the request sent twice, `401 proof_not_accepted` for the other three.

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

## The app side, file by file

- `lib/setup.dart`: the `DeviceTrust`, with its backend, the personal measurements, step-up and the app
  PIN, each option commented.
- `lib/sample_api.dart`: what the app sends to its own backend. The sign-in, a request with its proof, the
  sensitive request with step-up or the app PIN, setting the PIN; and the requests made wrong on purpose.
- `lib/measurements.dart`: reading a scan. Every measurement the report carried, with its status (`ok`,
  `error`, `unsupported` or `not_enabled`) and its fields, grouped by what it catches.
- `lib/main.dart`: the screen. The switches that change `trust.personalMeasurements` while the app runs, the
  location permission, and `SecureScreen` while the password or the PIN is typed.

The platform files declare what the app uses: the location permissions in
`android/app/src/main/AndroidManifest.xml`; `NSLocationWhenInUseUsageDescription` and
`NSFaceIDUsageDescription` in `ios/Runner/Info.plist`.
