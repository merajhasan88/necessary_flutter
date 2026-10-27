# necessary example

The `necessary` plugin against one of its sample backends (`../backend`): start, a scan, and the
sample's own calls, each carrying the proofs the plugin adds — a request proof on every call, a scan made
for one transfer, the person's step-up approval, and the app PIN.

Start a sample backend on your development machine (see `../backend/README.md`), then run the app on an
Android emulator, which reaches the machine at `10.0.2.2`:

```sh
flutter run --dart-define=NECESSARY_BACKEND_URL=http://10.0.2.2:8787
```

On a phone, give the machine's address on your network. Plain HTTP serves a debug build against a local
sample only; a release build talks HTTPS.

Tap **Start**, then **Scan** and **Sign in**; then **Transfer**, **Approve (step-up)**, and, with a
six-digit PIN typed, **Set PIN** and **Unlock with PIN**. Each answer — or the backend's refusal, with its
code — is shown below the buttons.
