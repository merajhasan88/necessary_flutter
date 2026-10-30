# The measurement contract: report format 1, Android collector 8, iOS collector 5

What a Necessary collector sends in its signed integrity report, and how to read it. Three parts,
all in this folder:

- `report.schema.json` — the report's shape (JSON Schema 2020-12): every measurement, field, type,
  unit and bound. It says what is well-formed, nothing more.
- this file — what a schema cannot say: when a measurement is complete, how its figures add up, what
  contradicts itself, and how versions change.
- `samples/` — reports as a collector signs them, for each platform, each with the plan it answers and
  how it is judged.

The thresholds and the decisions are yours: which measurements to ask for, what each one costs, how
old a location may be, when to refuse. Nothing here scores anything.

## 1. The report

- The app sends `report_payload`, the base64url (without padding) of the report's UTF-8 JSON bytes,
  and `report_signature`: ECDSA P-256 over SHA-256 of exactly those bytes, ASN.1 DER, base64url.
  Verify over the bytes as sent, never over JSON you encoded again. The plugins' shared test vectors
  (`client_server.json`) pin the encoding.
- At most 65,536 bytes decoded: refuse larger.
- `version` is 1. `challenge_nonce` is the challenge's 32-byte nonce exactly as issued (43
  characters). `collected_at` is the phone's clock in Unix seconds, to be within 90 seconds of yours.
  `collector_version` is the collector's version on its platform. `probe_results` holds one object per
  measurement; `enabled_measurements` names the personal measurements this app's developers enabled.
- Numbers the schema types as integers are written without a fraction or an exponent, and a number is
  never `true` or `false`.

## 2. What counts as a measurement

- Each measurement has a `status`: `ok`; `error`, with `error` saying why (Android may add
  `error_type`); `unsupported`, with `reason`; or `not_enabled`, a personal measurement this app does
  not collect.
- **`ok` is a claim, not a measurement.** A measurement is complete when it answered `ok` and carries
  every field its `x-complete-when-ok` lists — for `code_integrity` with `checked` true, every field of
  `x-complete-when-checked` too, and for a personal measurement every one of its `x-parts`.
- **`unread`** names the parts an `ok` measurement could not read, each with why: at most 64, a name
  of at most 128 characters, a reason of at most 160. An unread part is not measured — never read it
  as a clean "no". A measurement that could read nothing answers `error`.
- A field a collector version does not know is absent: read absent as not measured.
- A report that lacks a measurement you asked for is refused, not read. A failed or incomplete one
  tells you something could not be measured; it is not proof of an attack. Ask again rather than
  punish the person.

## 3. When each measurement comes

Each measurement's `x-answered` says it:

- **when the backend requests it** — ask, in the challenge, for every measurement you rely on, every
  time, and vary the others from scan to scan;
- **volunteered on every scan** — `device`, `network`, and on iOS `code_integrity`. Rely on one only
  if you decide to; until you ask for it, its absence or failure does not make a report incomplete;
- **personal** — only when the backend asks for it and the app's developers enabled it, and the
  location only with the person's permission as well. Drop any personal measurement you did not ask
  for before you store or read the report, after checking the signature over the bytes as sent.

## 4. Comparing code in memory with its files

**Android** compares three regions: `core` (the C library and the runtime), `ext` (the other system
libraries the app has mapped) and `app` (the app's own native code). In each region the expected bytes
are the compared, skipped and unreadable bytes together, and `<region>_complete` is true exactly when
some code was expected and all of it was compared. `checked` false: the comparison did not run.
`checked` true with nothing compared in a region that always holds code: nothing was measured there.

**iOS** can compare only the app's own code. The system libraries live in a shared cache no app can
read: `system_images_unreadable` counts them, and their figures are always 0 — not measured, never
clean. Every app image the loader has mapped is expected, and each is compared, unreadable (its file
could not be read in full) or skipped (no usable `__text`, a `__TEXT` too large, no live address);
`app_images_not_compared` names each one not compared, by its path in the app, with why. Images and
bytes both add up: expected = compared + unreadable + skipped. `app_complete` is true exactly when every
image was compared — the images decide, since an image whose `__text` size could not be read adds no
bytes — and then the main executable is among them (`main_executable_compared`).

On both, a comparison short of complete compared part of the code: never a complete clean comparison.
Any differing byte in compared code is a change in code that should never change.

## 5. Location

- Without the permission (`permission` `none`) no coordinates are sent.
- The location is the one the phone already holds — never a fresh fix, never a prompt — and
  `age_seconds` says how old it is. How old is too old is yours to decide.
- With the permission and no coordinates, the phone holds no location — but only when every location
  source was read: with a source in `unread`, the location may be there.
- Both answers describe one fix, read once per scan, and carry its time (`fix_time`, Unix seconds):
  two different times are two observations presented as one.
- `mock_location` never carries coordinates, so asking for it alone never sends them. On iOS `mock` is
  Apple's flag, from iOS 15; `accessory` marks a location from an external GPS accessory.

## 6. Lists

- **Apps** (`services`, `listeners`, `device_admins`, `remote_access_apps`): at most 32 from a
  collector, each with `package`, and `service`, `system` and `installer` where Android shows them;
  `truncated` is true when the phone had more. A list is complete only when `truncated` is false.
- **`split_apks`**: each installed split's file `name` and `sha256`, at most 64, **sorted by name, none
  twice** — the one rule the schema cannot state. Empty without splits. `apk_sha256` is the base APK's
  alone, so installs of one release with different splits share it.
- **`current_signers`, `signing_lineage`**: at most 8 lower-case hex SHA-256 digests each.
- **`addresses`** (`local_addresses`): at most 64, each an `interface` and an `address` of at most 64
  characters.

## 7. Figures that cannot all be true

A report whose figures contradict each other is one to distrust: not a measurement, clean or
otherwise.

- code-comparison coverage that does not add up, or a `complete` flag that does not follow from it
  (section 4);
- no writable-and-executable mapping, with the sizes of such mappings listed;
- screen recording `unsupported` on a platform version that measures it (iOS; Android 15 and later);
- two different `fix_time`s for the location and the mock-location answers.

These, by contrast, are failed reads — incomplete, not contradictions: a process map read as empty
(`maps_lines` 0), no thread found in a running process (`thread_count` 0), a code comparison that did
not run or compared nothing in a region that always holds code.

## 8. Versions

- `collector_version` counts per platform. This contract: Android 8, iOS 5 — the schema allows no
  lower version on either, since an older collector's report is not this contract's.
- Before these versions a collector could report a failed read as a clean value (Android before 8) or
  a partial comparison of the app's code as complete (iOS before 5). Refuse those versions, or keep
  their scans apart as older evidence.
- Fields are only ever added; a field's meaning never changes. A new measurement is volunteered before
  any backend asks for it, so that older apps keep working. Unknown fields and unknown measurements
  are ignored.
- A new contract gets a folder of its own beside this one.

## 9. The samples

Each sample holds the report as a collector signs it (`report`), the plan it answers
(`required_probes`, and the personal `optional_probes`), and how a backend following these rules
judges it (`expect`, with `why`). The envelope's `installation_id`, `challenge_id`, `challenge_nonce`
and `collected_at` are placeholders a test replaces before signing. Each is checked, as published,
against the reference backend's judgment.

| Sample | Judged | What it shows |
|---|---|---|
| `android-8-complete` | complete | a clean phone, every requested measurement whole, one split APK listed apart |
| `android-8-incomplete` | incomplete | a setting in `unread`, a probe in `error` |
| `android-8-invalid` | invalid | coverage that does not add up |
| `android-8-location-one-fix` | complete | both location answers with one `fix_time` |
| `android-8-location-two-fixes` | invalid | the mock flag of another fix than the coordinates |
| `android-8-refused` | refused | an `unread` that is not an object |
| `ios-5-complete` | complete | a clean iPhone, every app image compared |
| `ios-5-incomplete` | incomplete | an `ok` without its fields |
| `ios-5-partial` | partial | the app-code comparison requested, one image unreadable |
| `ios-5-invalid` | invalid | images that do not add up |
| `ios-5-refused` | refused | an `app_images_not_compared` that is not an object |
