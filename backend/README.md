# Sample backends

Three small backends for the `necessary` plugin — in Python, TypeScript and C# — written from the
integration guide (`doc/integration_guide.md`) and the measurement contract alone. Each implements the
guide's API (its section 4) and the checks its sections 1 to 3 describe, in the guide's order, with
the section numbers in the code:

- **Registration** (section 1): an EC P-256 key whose point is on the curve; the key's thumbprint as the
  installation's identity, so the same key gets back the installation it has; a known ID under another
  key refused; the reinstall hint keyed before it is kept; `key_security` recorded, never relied on; the
  step-up key taken only with a new installation, never the installation key itself.
- **Proof of possession** (section 1): a key challenge that stores nothing — its payload carries an HMAC
  under a key of the backend's — answered once, consumed only after the signature verifies, for an
  installation session of ten minutes.
- **The scan** (section 2): a challenge asking on every scan for every measurement that would catch
  tampering — the hooks, gadgets and changes to the app's code in memory among them — varying only the
  emulator's (or simulator's) build values; and for every personal measurement (section 8), so that the
  example app can show each one it enables — a production backend asks only for those it uses; the
  report's ten checks in order; then
  the report against the contract's schema; the answer `{"integrity": {"report_id": …, "next":
  "allow"}}` — what to do next, never a score.
- **A scan for one action** (section 2): named only under an account session; its report approves that
  one request, once, sent back as `X-Integrity-Report`.
- **Request proofs** (section 3): every field against the request received, the clock window, the
  signature, then the nonce stored once — a proof sent twice is refused.
- **Step-up and the app PIN** (section 3): the person's approval checked against the request and its
  proof's nonce; a new step-up key taken by re-enrolment only with the person's password and the new
  key's proof bound to the request proof's nonce, every check of the key before the password, and kept
  for that account alone; the PIN set with the person's password and kept as a slow keyed verifier, its
  attempts claimed before comparing, the last wrong one locking it, and the backend's own short-lived
  proof for one request.

They are **samples**: one process, everything in memory, secrets made at start, no rate limits and no
account system beyond a demonstration sign-in. A production backend keeps its records in a database,
its secrets in a vault, limits how often each call may be made, and decides with its own business
logic.

## This sample's own API

Beside the guide's calls, a few of the sample's own, to show the plugin's proofs in use — each under the
session and request proof the guide describes:

| Call | Session | Needs |
|---|---|---|
| `POST /v1/demo/sign-in` `{"handle", "password"}` → `{"account_session"}` | the installation session | — |
| `POST /v1/demo/echo` | an account session | a request proof |
| `POST /v1/demo/transfer` | an account session | a scan made for this request (`X-Integrity-Report`) |
| `POST /v1/demo/sensitive` | an account session | the person's approval: step-up, the app PIN's proof, or both — each one sent must hold; with neither, `403 needs_approval` |

With `--test-controls`, and only for requests carrying `X-Test-Token: $SAMPLE_TEST_TOKEN` (16
characters or more), `POST /test/expire-sessions`, `POST /test/forget` `{"installation_id"}` and
`POST /test/refuse-next` `{"path", "status", "code", "details"}` let a test reach each of the guide's
protocol errors. A deployed sample runs without them.

Each sample logs one line per call — its method, path, status and any refusal's code — and never a
body or a header, which hold PINs and tokens.

## Run

```sh
# Python 3.10 or later
pip install --require-hashes -r python/requirements.txt
python3 python/server.py --port 8787 --schema <contract>/report.schema.json

# TypeScript, on Node 22 or later
cd typescript && npm ci && npm run build
node dist/server.js --port 8787 --schema <contract>/report.schema.json

# C#, on .NET 10
cd csharp && dotnet restore --locked-mode && dotnet build -c Release --no-restore
dotnet bin/Release/net10.0/SampleBackend.dll --port 8787 --schema <contract>/report.schema.json
```

## The plugin end to end

`run_e2e.sh` starts a sample with its test controls and a token of its own, runs the plugin's
`test/backend_e2e_test.dart` against it — real HTTP, real P-256 signatures, the contract's complete
Android sample as the phone's measurements — and stops it. Against a deployed sample, set
`NECESSARY_BACKEND_URL` alone and run the test: the protocol-error test, which needs the controls, is
skipped.


```sh
backend/run_e2e.sh python
backend/run_e2e.sh typescript
backend/run_e2e.sh csharp
```
