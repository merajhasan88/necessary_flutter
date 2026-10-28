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
| Measurements | turn each personal measurement on or off, and see the code for your choice; ask for the location permission; **Scan** | every measurement the signed report carried, grouped as the backend asked for them, each opening to its fields |
| Account | **Sign in** (the sample makes the account at its first sign-in) | an account session for this installation |
| Requests | **Protected request**; **Sensitive, without approval**; **Sensitive, with step-up**; set the app PIN, then **Sensitive, with the app PIN** | accepted; refused, `403 needs_approval`; accepted once the person unlocks the screen lock; accepted |
| Requests a backend must refuse | one request sent twice; its body changed after signing; sent to another path; a proof ten minutes old; a session copied from another phone | each refused |

A request that a backend must refuse but that is accepted shows as a failure, so the app doubles as a check
of your own backend.

## The app side, file by file

- `lib/setup.dart`: the `DeviceTrust`, with its backend, the personal measurements, step-up and the app
  PIN, each option commented.
- `lib/sample_api.dart`: what the app sends to its own backend. The sign-in, a request with its proof, the
  sensitive request with step-up or the app PIN, setting the PIN; and the requests made wrong on purpose.
- `lib/measurements.dart`: reading a scan. What the backend asked for, and every measurement the report
  carried, with its status (`ok`, `error`, `unsupported` or `not_enabled`) and its fields.
- `lib/main.dart`: the screen. The switches that change `trust.personalMeasurements` while the app runs, the
  location permission, and `SecureScreen` while the password or the PIN is typed.

The platform files declare what the app uses: the location permissions in
`android/app/src/main/AndroidManifest.xml`; `NSLocationWhenInUseUsageDescription` and
`NSFaceIDUsageDescription` in `ios/Runner/Info.plist`.
