# Device Trust — what the app sends, and how your backend checks it

The Device Trust plugins (Android, iOS, Flutter, React Native, .NET) are open source. They give your app
a key that cannot leave the phone, measurements of the phone and of the app running on it, and — if
you turn them on — a second key that the person must unlock, and a PIN your backend checks, to approve
a request. **They never decide
anything: your backend does.** This guide is the protocol the plugins follow — what they
send, how your backend checks that a report was signed by the key an installation registered and proved
it holds, and how to weigh what it says with your own business logic. It describes no particular server.
A valid signature proves possession of that key and that the bytes you verify are the ones it signed; on
its own it does not prove which phone or which app produced them, or that the plugin ran unmodified
(section 9).

There are two ways to connect, and the choice is yours. **By default the plugin calls the API in
section 4**, under a base URL your app sets, and your backend implements it. Or your app calls the
plugin's functions and carries the messages over its own API. The checks are the same either way.
Binary values travel as base64url without padding, hashes are lower-case hex SHA-256, times are UTC.

---

## 1. The installation key

On first use the plugin creates an **installation key**: ECDSA P-256 (ES256), never exportable by the
app. On Android it is generated inside Android Keystore — in StrongBox where the phone has one, otherwise
wherever that phone's Keystore keeps keys, its secure hardware or, on some phones, software. On iOS the
plugin asks the Secure Enclave first; where it refuses — the Simulator, or a configuration that declines
the key — the plugin falls back to a Keychain key marked not extractable: a software key, which a
compromised phone can copy. `key_security` (below) is what the phone says about where its key is. Your
backend only ever sees the public key.

Every signature works the same way: the phone base64url-decodes the payload it is given, signs those
bytes with ECDSA over SHA-256, and returns the signature in ASN.1 DER, base64url. **Verify over the bytes
that were signed — never over JSON you encoded again yourself.**

### Registration (the app to your backend)

| Field | Meaning |
|---|---|
| `installation_id` | a UUID the app proposes |
| `platform` | `android` or `ios` |
| `public_key` | a JWK: `kty` `EC`, `crv` `P-256`, `alg` `ES256`, `x`, `y` |
| `reinstall_hint` | `kind` (`android_id_sha256` or `idfv_sha256`) and `value`, a SHA-256 of the platform's per-app device identifier; or `null` |
| `key_security` | `security_level`, `hardware_backed`, `provider`: what the phone says about its own key |

Your backend:

1. Accepts only an EC P-256 key whose `x` and `y` are 32 bytes each and whose point is on the curve.
2. Computes the **thumbprint**: the lower-case hex SHA-256 of `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`
   — members in that order, no spaces, `x` and `y` as 32-byte big-endian values in base64url without
   padding. **The thumbprint is the installation's identity**, not the proposed `installation_id`: a
   registration whose thumbprint you already hold is the same installation (an app that lost its stored
   ID), so answer with the one you have. A proposed `installation_id` you already hold under another key
   is not that installation: refuse it. The plugin never sends one — when its key is gone it makes a new
   ID as well.
3. Keys the reinstall hint with a secret of its own (HMAC-SHA256) before storing it. **The hint is what
   the app says**: a modified app can send another phone's hint, or a new one every time, and keying it
   does not make its origin genuine. It links reinstalls on one phone provisionally; it never
   authenticates anyone. On Android it changes when the app's signing key changes.
4. Records `key_security` but never relies on it: the phone cannot prove it.
5. Trusts nothing about the installation until it has proved that it holds the key.

### Installations and phones

An installation is one key — its thumbprint, exact within this protocol. What becomes of the key when
the app is removed depends on the platform:

- **Android** deletes the key with the app. A reinstall makes a new key, so a new installation, while the
  reinstall hint stays the same until the phone is reset or the app's signing key changes.
- **iOS** keeps the key, and the installation ID the plugin stores beside it, in the Keychain — and
  Apple does not promise whether Keychain items outlive the app. A reinstall may come back with the same
  key, so the same installation (step 2 above); with the key but without the app's other data; or with
  neither, so a new key. The hint stays the same until every app from your company has been removed.
  Handle all three: the same thumbprint is the same installation, whatever else the app forgot, and a
  session your app kept in the Keychain may come back with it.

So **a phone, as far as the hint can tell, is every installation that shares a reinstall hint**: count
accounts, reinstalls and limits per phone (section 7) — knowing that a fraudster who sends fresh hints
looks like many phones, and one who copies a hint looks like someone else's.

- **Key identities are exact; matches by hint are provisional.**
- **A match by hint alone never carries a block, a ban or trust from one installation to another.** Act
  on it only with other evidence — the same account signing in on both, the same network, the same
  payees — and even then it links two installations; it does not prove one phone.
- An account signing in on an installation whose key it has used before strengthens a link; it still
  does not make the hint a hardware identity.

### Proof of possession

Your backend sends a challenge: a `challenge_id` (a UUID) and a `payload` — base64url bytes of your
choosing. We suggest JSON naming the `challenge_id`, the `installation_id`, a `purpose`, a `nonce` of 32
random bytes and an `expires_at` two minutes ahead, either stored or carrying an HMAC under a key of yours
so that you need not store it. The app answers with `installation_id`, `challenge_id`, `payload`
(unchanged) and `signature`. Your backend:

1. Checks that the payload is one it issued (stored, or its HMAC verifies), for this `challenge_id`,
   this `installation_id` and this purpose.
2. Checks that it has not expired.
3. Verifies the signature over the decoded payload bytes with the installation's registered key.
4. Consumes the challenge atomically — inserting its ID under a unique key is the single-use check, so a
   second answer fails however the two requests interleave. Consume only after the signature verifies, so
   nobody can use up another phone's challenges.
5. Issues its own short-lived session for this installation; ten minutes is a sound choice.

---

## 2. The scan

### The challenge (your backend to the app)

| Field | Meaning |
|---|---|
| `challenge_id` | a UUID |
| `nonce` | 32 random bytes; store its SHA-256, not the nonce |
| `platform` | the installation's platform, as registered |
| `required_probes` | the measurements this scan must answer (section 6) |
| `optional_probes` | the personal measurements you ask for, answered only where the app enables them (section 8) |
| `expires_at` | 60 seconds ahead |

Ask for every measurement you rely on every time, and vary the others from scan to scan, so that a
tampered app cannot prepare its answers. **Rely on every measurement that would catch tampering** — the
hooks, gadgets and changes to the app's code in memory among them: on Android `runtime_maps`,
`frida_ports`, `instrumentation_threads`, `exec_mappings` and `code_integrity`; on iOS `dyld_images`,
`environment` and `code_integrity`. One left to chance is one a tampered app waits out, scanning again
until it is not asked for. Ask for iOS `code_integrity` too, although every report carries it: only a
report that lacks a measurement you asked for is refused. Issue a challenge only to a session that has
proved its key, and limit how often one installation may ask.

### The report (the app to your backend)

The app sends `report_payload` — the base64url of these UTF-8 JSON bytes — and `report_signature`:

| Field | Meaning |
|---|---|
| `challenge_id`, `challenge_nonce` | the challenge it answers |
| `installation_id` | the installation whose key signs it |
| `platform` | `android` or `ios` |
| `collector_version` | the plugin's measurement version, an integer |
| `collected_at` | the phone's clock, in Unix seconds |
| `probe_results` | one object per measurement (section 6) |
| `enabled_measurements` | the personal measurements this app's developers enabled (section 8) |
| `version` | the report format: `1` |

Your backend, in this order, refusing at the first failure:

1. Decodes the payload (a report is far below 64 KiB; refuse larger): a JSON object with `version` 1.
2. Its `installation_id` is the session's installation.
3. Finds the challenge by `challenge_id`, locking it: it belongs to this installation, and `platform`
   matches it.
4. The challenge is unused and has not expired.
5. The SHA-256 of the decoded `challenge_nonce` equals the stored hash.
6. `collected_at` is within 90 seconds of your clock.
7. `collector_version` is one you support — refuse plugins too old to measure what you need.
8. Every probe in `required_probes` is in `probe_results`. **A report that lacks a measurement you asked
   for is refused, never read.**
9. The signature verifies over the decoded payload bytes with the installation's key.
10. Marks the challenge used, in the same transaction.

Only then read the measurements — and keep the signed bytes, or their SHA-256, with what you decided.

### A scan for one action

When the app asks for the challenge, it may name the one request the scan is to approve — a payment, a
change of payee — as `operation`: that request's `method`, `path`, `query` (as sent, empty when none)
and `body_sha256` (the SHA-256 of its exact body).

- **Such a scan is the account's, not the installation's.** The app asks for it under your **account
  session** — the one that will send the request — never under the installation session of section 1;
  refuse an operation named under that one. Your account session must itself belong to this
  installation: issue it only to an installation that has proved its key, carry the installation in it,
  and require its request proofs (section 3).
- Read the account and the session from your own verified token, never from anything the app says, and
  store a SHA-256 of the description, joined to them, with the challenge.
- Your answer to the report carries `report_id`, inside its `integrity` object, which names the stored
  report; the app sends it back with the request, in the header `X-Integrity-Report`.
- When the request arrives, accept it only if that report answered a challenge naming exactly this
  request — same method, path, query and body — under the same account session, within a couple of
  minutes; and mark the report used in the same transaction, so that it approves one request, once.

---

## 3. Binding each request to the phone (recommended)

A copied session token is useless without the installation key when every sensitive request carries a
proof signed by that key. The plugin adds two headers to the request, beside `Authorization: Bearer`:
`X-Access-Proof`, the base64url of these JSON bytes, and `X-Access-Signature`.

| Field | Meaning |
|---|---|
| `access_token_sha256` | SHA-256 of the bearer token, as sent |
| `body_sha256` | SHA-256 of the exact body bytes sent (of nothing, for a GET) |
| `installation_id` | the installation |
| `method` | upper case |
| `path` | the path, without the query |
| `query` | the query string exactly as sent, without `?`; empty when there is none |
| `nonce` | 32 random bytes |
| `timestamp` | Unix seconds |
| `version` | `2` |

Your backend checks every field against the request it actually received — the installation (from the
session), method, path, query, body hash and token hash — then that the timestamp is within 120 seconds,
then the signature; and only after the signature verifies does it store the nonce's hash under a unique
key, so that a repeated request is refused as a replay. Keep nonces for at least ten minutes, longer than
the clock window on either side.

### Step-up: the person approves one request (optional)

For a request where you want the person and not only the phone — a payment, a new payee, a changed
password — the plugin can hold a second key, the **step-up key**: ECDSA P-256 like the installation key,
never exportable, and usable only after the person unlocks it. A step-up proof shows that someone able to
unlock this phone approved this one request; it does not show who. The app turns step-up on and chooses
how the key is unlocked; your backend decides which requests need it.

| How it is unlocked | |
|---|---|
| factor `passcode` | the phone's passcode: its PIN, pattern or password |
| factor `biometric` | a biometric enrolled now, such as a fingerprint or a face |
| mode `per_use` | the person unlocks the key for every signature |
| mode `windowed` | one unlock lets the key sign for `window_seconds` — Android only. Android 9 and 10 cannot ask for the passcode at every signature, so there a passcode key is windowed, and says so |

Removing the screen lock — or, for a biometric key, enrolling another biometric — makes the key
unusable. The app then makes a new one, which your backend takes only by re-enrolment (below).

**At registration**, with step-up on, the registration (section 1) also carries:

| Field | Meaning |
|---|---|
| `stepup_public_key` | the step-up key's JWK, as `public_key` |
| `stepup_key_auth` | `factor`, `mode` and `window_seconds` (0 for `per_use`): what the phone says about how the key is unlocked |

Your backend:

1. Takes a step-up key only with an installation it does not yet hold. A step-up key arriving with a
   later registration of a known installation is not taken: otherwise whoever holds the installation
   key could put a key of their own in its place.
2. Refuses a step-up key whose thumbprint is the installation key's: it would add nothing.
3. Records `stepup_key_auth` and, like `key_security`, never treats it as proof. Compare it with what
   you require, and decide whether to accept a weaker key — a windowed one where you want every signature
   unlocked; refusing it shuts out the owners of Android 9 and 10 phones.

**The proof.** A request that needs step-up carries, beside its request proof, `X-Step-Up-Proof` — the
base64url of these JSON bytes — and `X-Step-Up-Signature`, the step-up key's signature over them:

| Field | Meaning |
|---|---|
| `version` | `2` |
| `purpose` | `stepup` |
| `installation_id` | the installation |
| `access_token_sha256` | SHA-256 of the bearer token, as sent |
| `method`, `path`, `query`, `body_sha256` | the request, as its request proof states them |
| `factor` | the step-up key's factor |
| `nonce` | the request proof's nonce — the same value |
| `timestamp` | Unix seconds |

The plugin has the step-up key sign first — the phone asks the person — and the request proof after, so
the time the person takes does not count against the request proof's clock window.

Your backend, for a request that needs step-up, after the request proof's checks:

1. Refuses the request without both headers, telling the app that step-up is needed.
2. Verifies the signature over the decoded bytes with the step-up key it holds for this installation.
3. Checks `version` 2, `purpose` `stepup`, the installation, and every request field against the request
   it received — the token hash, method, path, query and body hash — and that `nonce` is this request's
   request-proof nonce. That nonce is stored once, so one approval approves one request, once.
4. Checks that the timestamp is within 120 seconds of its clock.
5. Checks the factor: both the proof's and the one recorded with the key are the factor you require.

Which requests need step-up, and which factor, is yours to decide. Limit failed step-ups per
installation and per account.

**Re-enrolment.** An unusable key, or one with a factor you no longer accept, is replaced only with the
person's own re-authentication — your account's password, for example — and a proof from the new key.
The request, with its request proof, carries the new `stepup_public_key` and `stepup_key_auth`, and the
new key's signature over the base64url of this JSON:

```text
{"version":1,"purpose":"stepup_reenrol","installation_id":"…","stepup_key_thumbprint":"…",
 "nonce":"…","timestamp":…}
```

`stepup_key_thumbprint` is the new key's thumbprint (section 1); `nonce` is the request proof's. Your
backend checks the re-authentication, that the new key is not the installation key, the signature with
the new key, each field and the timestamp. Then the new key replaces the old one for that account alone:
a second account on the same phone, which needs only the installation key, must not gain step-up for the
first.

### The app PIN: the person's PIN for one request (optional)

A PIN of the person's account, which your backend checks: something the person knows, where the
step-up key is something only someone able to unlock the phone can use. It works on any phone, one
without a screen lock included. The app turns it on; your backend decides which requests need the
step-up key, the PIN, or both. The plugin never stores the PIN, and sends it only inside a signed
request body — never in a header, which proxies and monitoring tools record.

**Setting it.** Under your account session, with a request proof, the app sends the PIN with the
person's own re-authentication — your account's password, for example (section 4). Your backend:

1. Requires that re-authentication, and counts a wrong one as it counts a failed sign-in.
2. Takes only digits, of the length you chose.
3. Stores only a slow verifier — bcrypt, scrypt or PBKDF2 with a high work factor — over an HMAC of the
   account and the PIN, keyed by a secret your database never holds, so that a copy of the database
   checks nothing. Never log the PIN.
4. Clears the count of wrong PINs and any lock: a new PIN is how a person who forgot or locked theirs
   gets back in.

**Unlocking one request.** The app signs the request that needs the PIN first, which fixes its request
proof's nonce. Then, under the same account session and with a request proof of its own, it sends the
PIN with a description of that request — its `method`, `path`, `query`, `body_sha256` and that
`nonce` (section 4). Your backend:

1. Refuses an incomplete description before it checks the PIN.
2. Claims one attempt before comparing, so that PINs sent at the same moment cannot pass your limit, and
   counts a wrong PIN; the last wrong one you allow locks the PIN until a new one is set. While the PIN
   is being checked for another request, it answers 429 with a short wait and counts nothing.
3. Answers a proof it makes itself — an HMAC, under a key of its own, over the account, the
   installation, the session, the request described and an expiry about two minutes ahead.

The request then carries that proof in `X-App-PIN-Proof`. Your backend checks that it made the proof,
that it has not expired, that the account, installation and session are this request's, and that the
method, path, query, body hash and nonce are this request's. That nonce is stored once with the request
proof, so one PIN entry unlocks one request, once.

---

## 4. The API — the plugin's default

Unless your app carries the messages itself, the plugin makes these five calls under the HTTPS base URL
your app sets — and, with the app PIN on, two more, at paths your app can change. Your backend
implements them by sections 1 to 3.

| Call | Method and path | Authorization |
|---|---|---|
| Register the installation | `POST /v1/installations/register` | none |
| Ask for a key challenge | `POST /v1/installations/challenge` | none |
| Answer it | `POST /v1/installations/verify` | none |
| Ask for a scan | `POST /v1/integrity/challenge` | the session from *Answer it* — or, for a scan that approves one request, your account session for this installation (section 2) — with a request proof (section 3) |
| Send the report | `POST /v1/integrity/report` | the session that asked for the scan, with a request proof |
| Set the app PIN | `POST /v1/account/app-pin` | your account session, with a request proof |
| Prove the app PIN for one request | `POST /v1/account/app-pin/proof` | your account session, with a request proof |

Requests and answers, in JSON. An answer may carry more fields; the plugin passes them to your app.

```text
POST /v1/installations/register
  {"installation_id": "0f1d…", "platform": "android",
   "public_key": {"kty": "EC", "crv": "P-256", "alg": "ES256", "x": "…", "y": "…"},
   "reinstall_hint": {"kind": "android_id_sha256", "value": "9c1e…"},
   "key_security": {"security_level": "strongbox", "hardware_backed": true,
                    "provider": "AndroidKeyStore"}}
→ {"installation_id": "0f1d…"}                       the installation you hold for this key

POST /v1/installations/challenge
  {"installation_id": "0f1d…"}
→ {"challenge_id": "5b2a…", "payload": "eyJ…", "expires_at": "2026-10-20T12:02:00Z"}

POST /v1/installations/verify
  {"installation_id": "0f1d…", "challenge_id": "5b2a…", "payload": "eyJ…", "signature": "MEUCIQ…"}
→ {"device_token": "…"}                              your session for this installation

POST /v1/integrity/challenge
  {}   or, under the account session, for a scan that approves one request (section 2),
  {"operation": {"method": "POST", "path": "/v1/account/transfer", "query": "",
                 "body_sha256": "98ab…"}}
→ {"challenge_id": "7c5e…", "nonce": "q3Vn…", "platform": "android",
   "required_probes": ["app_identity", "debug_state", …], "optional_probes": [],
   "expires_at": "2026-10-20T12:01:00Z"}

POST /v1/integrity/report
  {"report_payload": "eyJ…", "report_signature": "MEUCIQ…"}
→ {"integrity": {"report_id": "3e9d…", …}}           the stored report; the plugin hands the
                                                    whole answer to your app, and for a scan
                                                    that approves one request sends report_id
                                                    with that request as X-Integrity-Report

POST /v1/account/app-pin                             with the app PIN on (section 3)
  {"password": "…", "pin": "246810"}                your own re-authentication, and the PIN
→ {"app_pin_set": true, …}

POST /v1/account/app-pin/proof
  {"pin": "246810", "request": {"method": "POST", "path": "/v1/account/transfer", "query": "",
                                "body_sha256": "98ab…", "nonce": "yMnK…"}}
→ {"app_pin_proof": "eyJ…", "expires_at": "2026-10-20T12:02:00Z"}   sent with that request as
                                                                   X-App-PIN-Proof
```

- `security_level` is `strongbox`, `trusted_execution_environment`, `secure_hardware`, `software` or
  `unknown` on Android, and `secure_enclave` or `software` on iOS; `provider` is `AndroidKeyStore`,
  `SecureEnclave` or `Keychain`.
- Prefer key challenges that store nothing — a payload carrying your HMAC — so that asking for one
  cannot fill a table, and limit registrations and challenges per network address.
- The rest of a report's answer is yours, in the same `integrity` object: tell the app what to do next,
  never the score or the reasons (section 7).
- With step-up on (section 3), the registration also carries `stepup_public_key` and `stepup_key_auth`,
  and the requests your backend chooses carry the person's approval.

### Errors

Refuse with an HTTP status and `{"error": {"code": "…", "message": "…", "details": {…}}}`. The plugin
acts on the codes below; any other refusal it hands to your app as it came.

| Status | `code` | When | The plugin |
|---|---|---|---|
| 401 | `challenge_expired`, `challenge_used` | a key challenge expired, or was answered already | asks for a new one, once |
| 401 | `integrity_challenge_expired`, `integrity_challenge_replay` | the same, for a scan | asks for a new scan, once |
| 401 | `expired_token` | the session from *Answer it* has expired | proves the key again, then retries |
| 404 | `installation_not_found` | you do not know this installation | registers again with the same key, then retries |
| 429 | any, with `details.retry_after_seconds` | too many requests | waits, if that is ten seconds or less, then retries once; a longer wait goes to your app |
| 403 | `installation_inactive`, `device_inactive` | you have switched this installation or this phone off | stops, and tells your app |
| 400, 401 | `invalid_installation_signature`, `integrity_report_stale`, `integrity_probe_missing` (with `details.missing_probes`) | a signature that does not verify, a phone clock far off, a measurement left out | stops, and tells your app |
| 400 | `invalid_operation` | an `operation` you cannot read, or one named under the installation session rather than an account session | stops, and tells your app |
| 403 | `app_pin_not_set` | the account has no app PIN | tells your app, which asks the person to set one |
| 403 | `app_pin_invalid` | a wrong app PIN, which counts | tells your app, which asks for the PIN again |
| 403 | `app_pin_locked` | too many wrong app PINs | tells your app: a new PIN, set with the person's re-authentication, unlocks it |

### Carrying the messages yourself

Each call is built from plugin functions your app can call directly: load or create the key (its public
JWK and thumbprint), sign a payload, collect and sign a report for a challenge, sign a request (the
two headers of section 3) and, with step-up on, have the person approve one (two more headers) or sign a
new step-up key's re-enrolment proof. Send their results over your own API, and make the same checks.

---

## 5. Reference code

Python with `cryptography`, checked against the plugins' shared test vectors:

```python
import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64url_decode(text):
    return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_key(jwk):
    """The installation's key, from the JWK the app registered."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("only EC P-256 keys are accepted")
    x, y = b64url_decode(jwk["x"]), b64url_decode(jwk["y"])
    if len(x) != 32 or len(y) != 32:
        raise ValueError("P-256 coordinates are 32 bytes each")
    # Raises ValueError for a point that is not on the curve.
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()


def thumbprint(jwk):
    """The installation's identity: lower-case hex SHA-256 of the canonical key."""
    x, y = b64url_decode(jwk["x"]), b64url_decode(jwk["y"])
    canonical = json.dumps({"crv": "P-256", "kty": "EC",
                            "x": b64url_encode(x), "y": b64url_encode(y)},
                           sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def signed_bytes(jwk, payload_b64, signature_b64):
    """The bytes the phone signed, or InvalidSignature. Parse these bytes -
    never JSON you encoded again yourself."""
    payload = b64url_decode(payload_b64)
    public_key(jwk).verify(b64url_decode(signature_b64), payload, ec.ECDSA(hashes.SHA256()))
    return payload
```

---

## 6. What the app measures

**The full contract is published with this guide**, in `contract/report-1/android-8-ios-5/`: the
report's schema (`report.schema.json`: every measurement's fields with their types, units and bounds),
the rules a schema cannot state (`RULES.md`: when a measurement is complete, how its figures add up,
what contradicts itself, how versions change), and sample reports judged each way (`samples/`). The
tables below summarise it.

Each entry in `probe_results` has a `status`: `ok`, `error` (with `error`, and on Android `error_type`),
`unsupported` (with `reason`), or `not_enabled` for a personal measurement this app does not collect.
**A measurement counts only when its status is `ok` and its fields are there** — a status on its own is a
claim. A field a plugin version does not know is absent; read absent as not measured. Besides what you
ask for, every report carries `device` and `network`, and on iOS `code_integrity`.

**An `ok` probe may carry `unread`**: the parts it could not read, each with why —
`{"adb_enabled": "SecurityException", "/sbin/su": "SecurityException"}`. An unread part is not
measured: never read it as a clean "no", and take a probe you required that carries one as not
measured. A probe that could read nothing answers `error`. From plugin versions Android 8 and iOS 5
(`collector_version`) no failed read is reported as a clean value; an older Android plugin could report
one, and an older iOS plugin a partial comparison of the app's code as complete — refuse those versions,
or keep their scans apart as older evidence.

### Android

| Probe | What it tells you | Fields |
|---|---|---|
| `app_identity` | the installed app: package, the base APK's hash, the signing certificates, flags, install source; from version 8 the split APKs apart | `package_name`, `apk_sha256` (the base APK alone, never its splits), `cert_sha256` (list), `debuggable`, `allow_backup`, `version_name`, `version_code`, `installer_package`, `source_dir`, `current_signers`, `signing_lineage`, `split_apks` (each `name` and `sha256`, sorted by name; empty without splits) |
| `debug_state` | a Java debugger attached or awaited | `debugger_connected`, `waiting_for_debugger` |
| `tracer` | another process tracing the app | `tracer_pid`, `seccomp`, `no_new_privs` |
| `root_files` | known root, su and framework paths that exist; a test-keys build | `found_paths`, `test_keys`, `build_tags` |
| `root_shell` | whether `su` resolves from the app's shell | `su_found`, `su_path` |
| `system_properties` | build and boot-security properties | `properties`: `ro.secure`, `ro.debuggable`, `ro.build.type`, `ro.build.tags`, `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`, `ro.boot.vbmeta.device_state`, `ro.boot.veritymode` |
| `selinux` | the SELinux mode, read two ways | `mode` (`enforcing`, `permissive`, `disabled`, `unknown`), `getenforce`, `enforce_value` |
| `mounts` | system partitions mounted writable | `protected_rw_mounts` |
| `runtime_maps` | instrumentation and hooking frameworks named in the app's memory map | `suspicious_tokens`, `suspicious_line_count`, `maps_lines` |
| `frida_ports` | Frida's default local ports accepting connections | `open_ports` |
| `instrumentation_threads` | threads an instrumentation runtime creates, even renamed | `frida_threads`, `glib_threads`, `token_threads`, `thread_count` |
| `exec_mappings` | memory both writable and executable, executable memory from deleted files, unlabelled executable regions | `wx_mappings`, `wx_bytes`, `wx_size_classes`, `wx_smallest_bytes`, `wx_largest_bytes`, `deleted_exec_mappings`, `deleted_exec_own_code`, `deleted_exec_jit`, `anon_exec_labeled`, `anon_exec_unlabeled`, `anon_exec_unlabeled_bytes`, `maps_lines`, `samples` |
| `code_integrity` | the app's native code and system libraries in memory compared with their files — an inline hook changes bytes | `checked`, `diff_bytes`, and for each region — the core system libraries, the extended ones, the app's own — its bytes compared, differing, expected, skipped and unreadable, and whether it is complete (`core_compared_bytes` to `app_complete`); `ext_libs_diff`, `app_libs_diff`, `diffed_libs`, `protect_restore_failures`, `elapsed_ms` |
| `developer_settings` | developer options and USB debugging | `developer_options_enabled`, `adb_enabled` |
| `emulator` | build values typical of an emulator | `suspected`, `reasons`, `model`, `manufacturer`, `product`, `hardware` |
| `device` | the OS version, the security patch level, model, build, the app's ABI, memory page size | `release`, `sdk_int`, `security_patch`, `manufacturer`, `brand`, `model`, `device`, `build_id`, `fingerprint`, `abi`, `page_size` |
| `network` | a VPN up on any network; an HTTP proxy set | `vpn_active`, `http_proxy_configured`, `transports`, `interfaces` (names only) |

### iOS

| Probe | What it tells you | Fields |
|---|---|---|
| `app_identity` | the installed app and its executable's hash | `bundle_id`, `executable_sha256`, `version_name`, `version_code`, `executable_bytes` |
| `code_signing` | the executable's own code signature | `signing_identifier`, `team_identifier`, `get_task_allow`, `signed`, `signature_absent`, `signature_parse_error`, `code_directory_flags`, `entitlement_count` |
| `debugger` | a debugger tracing the process | `traced` |
| `jailbreak_files` | known jailbreak paths that exist | `found_paths`, `checked_count` |
| `sandbox` | whether the app can write outside its sandbox | `write_outside_sandbox_succeeded`, `probe_path` |
| `dyld_images` | instrumentation and jailbreak names among the loaded libraries | `suspicious_tokens`, `suspicious_image_count`, `image_count` |
| `environment` | libraries injected through the environment | `dyld_insert_libraries` |
| `simulator` | the simulator, and the hardware model | `is_simulator`, `model` |
| `code_integrity` | the app's code in memory compared with its file, image by image | `checked`, `app_compared_bytes`, `app_diff_bytes`, `app_libs_diff`, `diffed_libs`; from version 5 the coverage: `app_images_expected` (the app's images loaded), `app_images_compared`, `app_images_unreadable`, `app_images_skipped`, `app_expected_bytes`, `app_unreadable_bytes`, `app_skipped_bytes`, `app_complete`, `main_executable_compared`, `app_images_not_compared` (each image not compared, by its path in the app, with why); `system_images_unreadable` |
| `device` | the OS version and build, and the model | `os_version`, `os_build`, `model_identifier` |
| `network` | a VPN, inferred from the interfaces the proxy settings are scoped to — a heuristic, so the names come with it; an HTTP proxy | `vpn_active`, `http_proxy_configured`, `scoped_interfaces` |

- **`apk_sha256` is the base APK's alone.** Installs of one release with different feature, ABI or
  density splits share it; the splits are in `split_apks`. Pin and compare builds by the base hash, and
  read the splits as what this install added.
- **On iOS only the app's own code can be compared.** The system libraries live in a shared cache that
  no app can read: `system_images_unreadable` counts them, and their figures stay 0 — not measured, never
  clean. The app's coverage adds up — expected = compared + unreadable + skipped, for images and for
  bytes — and `app_complete` is true only when every image was compared, the main executable among them.
  A comparison short of complete measured part of the app's code; figures that do not add up are a
  report to distrust.

---

## 7. Deciding: the measurements, and fraud on clean phones

The plugin tells you about the phone. Most fraud does not need a tampered one: it uses genuine,
unmodified phones — bought by the dozen, borrowed from a victim, handed to a mule — and those pass every
measurement. What catches it is what only your backend can see: the same phones and accounts over time,
what your own server observed, where the requests come from, and what happened afterwards.

### 7.1 The measurements are evidence

- **The phone never sends a score or a verdict. You decide, on your server.**
- **Weigh each measurement by how rare it is on genuine phones, and by what is at stake.** Developer
  options, USB debugging and a VPN are common on honest phones; an instrumentation framework in memory, a
  debugger attached, code changed in memory, or an app that is not your own signed build are not.
- **Compare the app with your release** — its files, its code and its size, as section 7.2 describes. A
  modified app is the most direct attack on everything else here: it holds a genuine key.
- **Compare a phone with itself.** A sudden change between one phone's reports — another signing
  certificate, an older OS than before — matters more than any single value.
- **A missing or failed measurement is not proof of an attack.** Phones differ, people refuse
  permissions, and OS versions hide things: ask again rather than punish the person. (A measurement you
  required that is absent from the report is different: step 8 of section 2 refuses that report.)

### 7.2 Your app as you built it: its files, its code, its size

An app taken apart and rebuilt — with a hook, a cheat or an injected library — changes in size and in
content from the app you released, and the plugin measures it three ways, each against what it should
be. Nothing on the phone can prove that the app is yours (section 9); what you can do is know exactly
what each release looks like, and refuse what does not look like it.

**Write down each release as your customers install it.** At every release, run the build on your
reference phones — each OS version, processor and memory page size you support, through its main
features — and record what the plugin reports. Record from the installed build, not from what you
uploaded: a store may re-sign or slim the app for each kind of phone, so keep one record per kind. And
record only from your own runs, never from the field, where the first modified copy would set what
normal looks like.

1. **The installed files** (`app_identity`). A single changed byte changes a hash.
   - Android: the base APK's SHA-256 (`apk_sha256`); your signing certificate (`cert_sha256`,
     `current_signers`) — a rebuilt app must be signed again, with a key that is not yours; each split
     APK you ship and its hash (`split_apks`); and, where you distribute through a store, that store as
     `installer_package`.
   - iOS: the main executable's SHA-256 and its **size in bytes** (`executable_sha256`,
     `executable_bytes`) — an executable with code added is larger; and your team identifier
     (`team_identifier`, in `code_signing`).

   A report whose files match no release of yours is not your app as you built it.
2. **The code in memory** (`code_integrity`). The plugin compares the app's code as it runs with the
   code in its installed files: every byte that differs (`app_diff_bytes`, and on Android the system
   libraries' too) is code changed while running, which should never happen. Its **size** tells you
   what was loaded: on iOS `app_images_expected` counts the app's own images in memory and
   `app_expected_bytes` their code — an injected library is one image more and its code more than your
   release ever loads; on Android `app_expected_bytes` is the app's own native code in memory. Compare
   both with your release's record. A comparison short of complete measured only part of the code.
3. **The memory around it** (`exec_mappings`, on Android). Code loaded at run time needs executable
   memory: memory both writable and executable (`wx_bytes`, `wx_size_classes`, `wx_largest_bytes`) and
   executable regions with no file behind them (`anon_exec_unlabeled_bytes`). Some runtimes compile
   code as they run and map some of each — in amounts and sizes your own release runs show. Record the
   most of each your release maps, per OS version, processor and page size; **more than your app ever
   maps, or in sizes it never uses, is code in it that you did not ship.**

Compare a phone with itself too: the same installation reporting other hashes without an update, or an
older build than before, is an app that changed under it.

### 7.3 Clean phones, fraudulent people

Keep three kinds of evidence that the phone does not get to decide.

1. **Who uses which phone, over time.** Link every account to every installation it signs in from, and
   through the reinstall hint to the phone it suggests (section 1), and **never delete a link** — mark it
   ended, so the history stays. From the links:
   - accounts per phone — one phone, many accounts: farms, bonus abuse, mule herding;
   - phones per account — one account, many phones: shared, sold or taken-over accounts;
   - installations per phone — reinstalling again and again to look new (a fraudster who also sends a
     fresh hint each time looks like new phones instead, which the addresses and speed below still show);
   - how long you have known the phone, and the account — a new phone on an old account is the shape of
     a takeover.
2. **What your own server saw.** Wrong passwords and failed second factors, counted per account, per
   phone and per network address; request proofs signed by the wrong phone (a copied token); requests
   sent twice; scans refused. These come from your logs, not from the phone.
3. **Where the requests come from, and how fast.** The network address of each request: data-centre and
   VPN exits, many accounts behind one address, an address far from where the account lives. And speed:
   registrations, sign-ins, scans and requests per phone, per account and per address in a minute, an
   hour and a day, and the time from sign-up to the first payout. People are slow and irregular; scripts
   are fast and regular.

**Measure what is normal for your genuine customers** — accounts per phone, sign-ins per hour, the time
to a first payout — **and set each limit just beyond it.** Numbers borrowed from elsewhere either let
fraud through or stop your customers.

How the common patterns show up:

| Pattern | How it shows up | What helps |
|---|---|---|
| A farm of real phones | many accounts per phone over time; reinstalls between sign-ups; phones arriving in batches — same model and build, minutes apart, one network address; accounts acting on a schedule | limits per phone, counted by reinstall hint, and per network address, since a hint can be made up; first payouts held; risk shared along links made by keys and accounts |
| Takeover, on the fraudster's own clean phone | an old account on a phone you have never seen; wrong passwords or a reset just before; a new payee and a large amount soon after | a new phone starts limited until a phone the account already trusts approves it, or a waiting period passes |
| A scam on the victim's own phone | the account's own, known phone; an unusual payee or amount; the screen shared or mirrored, a remote-control app, an Accessibility service not from a store — where you collect them | pause the payment and confirm another way; delay new payees |
| Mule accounts | new accounts receiving from many senders and paying out fast; several on one phone; phones shared with accounts later confirmed as fraud | limits on what new accounts send; outcomes fed back along links |
| Bonus and promotion abuse | many new accounts per phone or per address, each claiming once; a reinstall between them | one bonus per phone, by reinstall hint, not per account — and per address, since a hint can be made up |
| Credential stuffing through real phones | many accounts tried from few phones or addresses; wrong passwords spread across accounts | failures counted per phone and per address, not only per account |
| Automation on real phones | perfectly regular timing; steps faster than a person can read; the same steps in the same order across many accounts | speed and regularity per phone and per address; a second factor that needs the person |
| Shared or sold accounts | one account on many phones, in different places, at the same time | phones per account; each new phone approved from a trusted one |

### 7.4 What to do about it

- **Bind a sensitive action to a fresh scan** made for it (section 2, *A scan for one action*) and to its
  request proof (section 3).
- **A new phone on an old account starts limited.** It can read, but not move money or change who
  receives it, until a phone the account already trusts approves it — show a code on the new phone and
  have the person type it on the trusted one — or until a waiting period has passed.
- **Cool off whatever is new**: new accounts, new payees and new phones get lower limits at first.
- **Spread risk along links you can stand behind.** When an account is confirmed as fraud, mark every
  installation it used, and look again at every other account on those installations. A phone joined to
  them by reinstall hint alone is a lead to review, never a ban to copy (section 1).
- **Feed outcomes back.** Chargebacks, disputes, refunds, complaints and confirmed fraud belong beside
  the phones and accounts they involved: fraud found later is your best teacher.
- **Answer in proportion**: allow, ask for a second factor, hold for review, or block — and keep blocking
  for strong evidence on actions that matter.
- **Tell the phone only what to do next** — scan again, confirm with a second factor, contact support —
  never the score or which signal mattered. That tells an attacker what to hide.

### 7.5 An example: a payout request

1. **Is it signed by the phone that holds this session?** The request proof (section 3) verifies, or the
   request is refused.
2. **Is there a fresh scan for exactly this payout?** If not, ask for one (section 2).
3. **Did the scan find strong evidence of tampering?** Hold the payout for review, or refuse it.
4. **What do the phone and the account say over time?** A phone first seen today, a password that failed
   this morning, a payee added an hour ago, an amount far above this account's usual, a VPN exit, other
   accounts on this phone that took money from strangers this week — each raises what you ask for: a
   second factor, approval from a trusted phone, a review.
5. **Record the decision with its evidence** — the report's SHA-256, the links and counts you read, what
   you asked for — so that a chargeback next month can be traced back to it.

### 7.6 Observe before you enforce

Run every new rule silently first: record what it would have done, measure how many genuine customers it
would have stopped, and only then turn it on, with a review queue for what it holds. Check your rules
against your outcomes regularly — fraud adapts to them.

---

## 8. Personal measurements and privacy

These identify a person's phone, network or habits, so they need two keys: your backend lists them in
`optional_probes`, **and** the app's developers enable them in the plugin. Anything else answers
`not_enabled`. The location needs the person's permission as well, which the plugin asks for only when
your app asks.

| Probe | What it tells you | Fields | Platforms |
|---|---|---|---|
| `local_addresses` | the phone's own IP addresses, link-local ones left out | `addresses` (`interface`, `address`) | both |
| `accessibility` | the Accessibility services that are on, and the keyboard in use | `services`, `keyboard`, `settings_only`, `truncated` | Android |
| `notification_access` | the apps allowed to read notifications, one-time codes among them | `listeners`, `truncated` | Android |
| `other_access` | device-administrator apps, and known remote-control apps installed | `device_admins`, `remote_access_apps`, `truncated` | Android |
| `screen_capture` | the screen being recorded, mirrored or cast | `recording`, `external_displays`; Android also `recording_status` | both |
| `location` | the last location the phone already knows — never a fresh fix, never a prompt | `permission` (`precise`, `approximate`, `none`), `latitude`, `longitude`, `accuracy_m`, `age_seconds`, `fix_time`; Android also `provider` | both |
| `mock_location` | whether that location was faked | `permission`, `mock`, `age_seconds`, `fix_time`; iOS also `accessory` | both |

- A list of apps holds at most 32, each with `package` and `service`, and with `system` and `installer`
  where Android lets the app see them; `truncated` is true when the phone had more.
- On Android, `recording` exists from Android 15; when it is missing, `recording_status` says why
  (`unsupported`, `no_permission`, `unavailable`).
- iOS shows an app no other app: `accessibility`, `notification_access` and `other_access` answer
  `unsupported` there.
- From plugin versions Android 8 and iOS 5 both location answers describe one fix, read once per scan,
  and carry its time, `fix_time` (Unix seconds): two different times are two observations, not one.
  Asking for `mock_location` alone never sends coordinates. On Android a location source the plugin
  could not read is in `unread`: then no coordinates do not mean that the phone knows no location.
- On iOS, `mock` is Apple's own flag. On an iPhone with iOS 15.8, a location faked with Apple's
  developer tools was flagged on the first scan; third-party spoofing apps have not been tested, and Apple
  does not promise to flag them. `accessory` marks a location from an external GPS accessory.
- **Drop any personal measurement you did not ask for** before you store or read a report — after the
  signature has been checked over the bytes as sent.
- **Treat `probe_results` as personal data.** They identify a phone — its model, OS build, installed
  tools, install source. Keep them only as long as you need them, and never store a name, e-mail address
  or phone number beside them.

---

## 9. What no app can prove

- A fully compromised phone can report anything, and can use a genuine key to sign what it likes: the
  key proves that a report came from that installation, not that the phone is honest — nor that the app
  is your own unmodified build, or that the plugin measured what it reports. A modified app that holds a
  registered key signs whatever it is given.
- The plugin cannot prove to your backend that its key is hardware-backed; `key_security` is the phone's
  own word.
- Measurements raise the cost of fraud, and together with your own business logic they make it
  expensive. On their own they are never proof.
