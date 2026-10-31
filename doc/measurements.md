# Measurements — what the SDKs measure on the phone

Every measurement a Necessary SDK can put in a signed report, field by field: what it is, how the
SDK measures it, and what a complete answer holds. Every SDK sends the same report, whatever framework
your app is built with, and none sends a score or a verdict;
what a measurement means for a request is your backend's decision. The integration guide
(`integration_guide.md`, beside this file) is the protocol — how your backend asks for a scan and checks
the report — and its section 7 is about deciding with these measurements.

## The contract

Every SDK follows the measurement contract published in `contract/report-1/android-8-ios-5/`: the
report's schema (`report.schema.json`), the rules a schema cannot state (`RULES.md`), and sample reports
judged each way (`samples/`). The folder's name is two versions:

- `report-1` is the report's format, version 1 — `version` in every report;
- `android-8-ios-5` names the lowest versions of the measuring code, the collector, that the contract
  accepts: 8 on Android and 5 on iOS — `collector_version` in every report. These are not Android or iOS versions; your
  SDK's README says which collector versions it sends and which Android and iOS versions it runs on.

This file describes that contract as the SDKs send it: each heading below is one of its
measurements — a probe — and each row of a table one of its fields.

## Reading a measurement

- **Every probe has a `status`**: `ok`, measured; `error`, with `error` saying why (on Android also
  `error_type`); `unsupported`, with `reason`; or `not_enabled`, a personal measurement your app does
  not collect. **`ok` means measured, never "all clear"**: the phone took the measurement, and what it
  found is in the fields — the example app shows it as *measured*.
- **`ok` says measured; the fields say how much.** A probe is complete when it answered `ok` and carries every
  field marked *yes* below — for `code_integrity` with `checked` true, every field marked *when checked*
  as well, and for a list of apps `truncated` present and false (*yes, false*).
- **`unread`** names the parts of an `ok` probe that could not be read, each with why:
  `{"adb_enabled": "SecurityException"}`. An unread part is not measured: never read it as a clean "no".
  A probe that could read nothing answers `error`.
- **A field that is absent was not measured.** Fields are only ever added, and a field's meaning never
  changes; ignore fields and probes you do not know.
- **A report that lacks a measurement your backend asked for is refused, never read** (integration
  guide, section 2). A failed or incomplete measurement says that something could not be measured, not
  that the phone is attacked: ask again rather than punish the person.
- **Figures that contradict each other** — code-comparison coverage that does not add up, two different
  times for one location fix — make a report one to distrust (`RULES.md`, section 7).

Each probe says when it comes:

- **your backend asks for it**, in the challenge's `required_probes`. Ask every time for each
  measurement you rely on, and vary the others from scan to scan;
- **every scan**, whether or not your backend asks. Rely on one only by asking for it: until you do, its
  absence or failure does not make a report incomplete;
- **a personal measurement**, only when your backend lists it in `optional_probes` and your app enables
  it in its SDK (the SDK's README says how) — the location only with the person's permission as well.
  These identify a person's phone, network or habits (integration guide, section 8).

The columns: *Type* — `true/false`, an integer or a number with its unit, text, a list or a map;
*Needed* — *yes*, a complete answer carries it; *when checked*, needed when `checked` is true; *yes,
false*, present and false; empty, sent when the SDK has it.

## Apps in a list

An app in `services`, `keyboard`, `listeners`, `device_admins` or `remote_access_apps` (Android) is an
object: `package`, its package name; `service`, the component the list is about, where there is one;
`system`, true for an app that is part of the phone's system; and `installer`, the package that installed
it, empty for none. `system` and `installer` are left out where Android hides the app from this one —
unknown, never evidence. A list holds at most 32 apps, and `truncated` is true when the phone had more.

## Android

Your backend may ask for `app_identity`, `debug_state`, `tracer`, `root_files`, `root_shell`,
`system_properties`, `selinux`, `mounts`, `runtime_maps`, `frida_ports`, `instrumentation_threads`,
`exec_mappings`, `code_integrity`, `developer_settings` and `emulator`. Every scan carries `device` and
`network`. The personal measurements are `local_addresses`, `accessibility`, `notification_access`,
`other_access`, `screen_capture`, `location` and `mock_location`.

### `app_identity`

The installed app as Android reports it: its package, the hashes of its installed files, its signing
certificates, its flags and what installed it. A rebuilt app must be signed again, with a key that is
not yours, and one changed byte changes a hash: compare these with each release of yours (integration
guide, section 7.2). A lookup that failed is in `unread`: the installer as `installer_package`, a split
APK that could not be hashed as `split_apks:<file name>`.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `package_name` | text | yes | the app's package name |
| `apk_sha256` | text | yes | the SHA-256 of the base APK alone, never its splits: installs of one release with different feature, ABI or density splits share it |
| `cert_sha256` | list | yes | the SHA-256 of each certificate signing the app, sorted; after a signing key rotation, each certificate of its history |
| `debuggable` | true/false | yes | the app is built debuggable |
| `allow_backup` | true/false | yes | the app allows Android's backup (`allowBackup`) |
| `current_signers` | list |  | the SHA-256 of the certificates signing the APK now, sorted, at most 8 |
| `signing_lineage` | list |  | after a signing key rotation, the SHA-256 of each certificate of the lineage, oldest first, at most 8; empty without one |
| `split_apks` | list |  | the installed split APKs, apart from the base APK: each its file `name` and its `sha256`, sorted by name, at most 64; empty for an install without splits |
| `version_name` | text |  | the app's version name |
| `version_code` | integer |  | the app's version code |
| `installer_package` | text, or null |  | the package that installed the app; null when none is named — installed with adb, or by an installer that names none |
| `source_dir` | text |  | the base APK's path on the phone |

### `debug_state`

Whether a Java debugger is attached to the app, or the app waits for one, as Android's `Debug` says.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `debugger_connected` | true/false | yes | a Java debugger is attached |
| `waiting_for_debugger` | true/false | yes | the app waits for a debugger to attach |

### `tracer`

Another process tracing the app — a native debugger, or a tool attached to the app's process — from the
app's own `/proc/self/status`. A status file that cannot be read, or without a tracer line, answers
`error`: never a tracer of 0.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `tracer_pid` | integer, process ID | yes | the process tracing the app; 0 when none |
| `seccomp` | integer |  | the app's `Seccomp` mode from the same file; -1 when the line is absent |
| `no_new_privs` | integer |  | the app's `NoNewPrivs` flag from the same file; -1 when the line is absent |

### `root_files`

Whether 15 known root paths exist — `su` in the usual places, the Superuser and SuperSU apps, and the
folders of Magisk, KernelSU and APatch — and whether the build is signed with test keys. A path the app
is not allowed to see reads as absent; a check that failed is in `unread`, by its path.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `found_paths` | list | yes | the listed paths that exist |
| `test_keys` | true/false | yes | the build's tags include `test-keys` |
| `build_tags` | text |  | the build's tags, for example `release-keys` |

### `root_shell`

Whether `su` resolves from the app's own shell (`command -v su`, then `which su`). A lookup that could not run, or did
not finish, answers `error`: never "no su".

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `su_found` | true/false | yes | `su` resolved |
| `su_path` | text |  | where it resolved; empty when it did not |

### `system_properties`

Build and boot-security properties, each read with `getprop`: whether the build is secure and not
debuggable, its type and tags, the verified-boot state, the bootloader's lock, and the vbmeta and
dm-verity states. A property that could not be read is in `unread`, by its name; when none could, the
probe answers `error`.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `properties` | map | yes | each property read, by name — `ro.secure`, `ro.debuggable`, `ro.build.type`, `ro.build.tags`, `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`, `ro.boot.vbmeta.device_state`, `ro.boot.veritymode` — with the text `getprop` printed, empty when the phone does not set it |

### `selinux`

The SELinux mode, read two ways: the `getenforce` command, and the kernel's own
`/sys/fs/selinux/enforce`. Many phones let an app read neither; then the mode is `unknown`, which is no
evidence of anything.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `mode` | one of `enforcing`, `permissive`, `disabled`, `unknown` | yes | the mode: from `getenforce` when it answered, else from the kernel's value (`1` enforcing, `0` permissive); `unknown` when neither could be read |
| `getenforce` | text | yes | what `getenforce` printed; empty when it printed nothing |
| `enforce_value` | text | yes | the kernel's value, `1` or `0`; empty when it could not be read |

### `mounts`

System partitions mounted writable — `/system`, `/vendor`, `/product`, `/odm`, `/system_ext` and
anything below them — from `/proc/mounts`. On a phone as it is sold they are read-only. A mounts file
that cannot be read answers `error`.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `protected_rw_mounts` | list | yes | each of those mounted read-write, as `<mount point>:<options>`, at most 32 |

### `runtime_maps`

Instrumentation and hooking frameworks named in the app's own memory map, `/proc/self/maps`: Frida and
its Gadget, Objection, Xposed, LSPosed, Substrate, Cydia, Zygisk, Riru, Magisk, KernelSU and APatch. It
matches names, so a renamed library escapes it; `instrumentation_threads`, `exec_mappings` and
`code_integrity` look at structure instead. A map that cannot be read, or reads as empty, answers
`error`.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `suspicious_tokens` | list | yes | the listed names found |
| `maps_lines` | integer, count | yes | lines read from the memory map |
| `suspicious_line_count` | integer, count |  | lines that named one |

### `frida_ports`

Whether Frida's default ports, 27042 and 27043, accept a connection on the phone itself. A refused
connection is a measured "closed"; any other failure is in `unread`, by its port.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `open_ports` | list | yes | the ports that accepted a connection |

### `instrumentation_threads`

The names of the app's own threads, from `/proc/self/task`. Frida's runtime starts threads whose names
are compiled into it, so a renamed library still shows here. A thread whose name could not be read is in
`unread` as `thread_names`, since a renamed instrumentation thread could be that one; a thread that
ended while the list was read is simply gone.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `frida_threads` | list | yes | the Frida runtime's thread names found: `gum-js-loop`, `gum-js`, `pool-frida` |
| `glib_threads` | list | yes | the GLib thread names found — `gmain`, `gdbus`, `pool-spawner` — which Frida brings into an app and apps seldom bring themselves |
| `token_threads` | list | yes | the names `runtime_maps` looks for, found in a thread's name |
| `thread_count` | integer, count | yes | the threads whose names were read; a running app always has some, so 0 is a failed read |

### `exec_mappings`

The shape of the app's executable memory, from `/proc/self/maps`. A clean app's code is read-only and
backed by its files; memory both writable and executable, executable memory whose file was deleted, and
executable memory with neither a file nor a label are the shapes that injected code leaves. Some
runtimes compile code as they run and map some of each: compare with the most your own release maps
(integration guide, section 7.2).

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `wx_mappings` | integer, count | yes | mappings both writable and executable |
| `deleted_exec_mappings` | integer, count | yes | executable mappings whose file was deleted, the runtime's code cache and the app's own compiled code left out |
| `deleted_exec_own_code` | integer, count | yes | executable mappings of the app's own compiled code (`.odex`, `.vdex`, `.art`, `.oat` under its install folder) whose file was deleted |
| `maps_lines` | integer, count | yes | lines read from the memory map |
| `wx_bytes` | integer, bytes |  | the size of all the writable-and-executable mappings |
| `wx_size_classes` | text |  | each size of writable-and-executable mapping with how many there are, largest first, as `<bytes>:<count>`, comma-separated |
| `wx_smallest_bytes` | integer, bytes |  | the smallest writable-and-executable mapping; 0 when none |
| `wx_largest_bytes` | integer, bytes |  | the largest writable-and-executable mapping; 0 when none |
| `deleted_exec_jit` | integer, count |  | executable mappings of the runtime's code cache, which shows as deleted on every phone |
| `anon_exec_labeled` | integer, count |  | executable mappings with no file but a label (`[anon:…]`), such as the runtime's code cache |
| `anon_exec_unlabeled` | integer, count |  | executable mappings with neither a file nor a label |
| `anon_exec_unlabeled_bytes` | integer, bytes |  | their size |
| `samples` | list |  | up to 8 of the memory-map lines counted above — writable and executable, or deleted — each cut to 160 characters |

### `code_integrity`

The app's native code, and the system libraries it uses, compared in memory with their files: a hook
that patches code in memory changes bytes there, whatever the tool is called. Three regions: `core` —
the C library and the Android runtime (`libc.so`, `libart.so`); `ext` — other system libraries that
hooks aim at (`libc++.so`, `libssl.so`, `libcrypto.so`, `libandroid_runtime.so`, `libbinder.so`); `app`
— the app's own native code: what is mapped from the APKs the app was installed from (its base APK and
its split APKs, by their exact paths — never another package's APK the app has loaded code from, such
as the WebView's), and the libraries the SDK names wherever they are (the Flutter SDK: the Flutter
engine, `libflutter.so`, and the compiled Dart, `libapp.so`). That is a selection, and it depends on
how the app is packaged: a build that keeps its native libraries in its APKs (the default) has all of
them measured; one that extracts them leaves those under other names — another plugin's, say — outside
`app`. The report says what it leaves out: every executable file of the app's own that is mapped but
not in `app` — an extracted library, the app's Java and Kotlin compiled by Android — is counted in
`app_outside_count` and named in `app_outside_files`. Code compiled as the app runs has no file to be
compared with, and is in neither.
In each region expected = compared + skipped + unreadable, and `<region>_complete` is true exactly when
some code was expected and all of it was compared. Any differing byte is code changed while the app
runs, which should never happen. Memory that Android 10 and later maps execute-only is made readable for
the copy and restored. The memory map is read once, whole, and every region taken from that one
snapshot: complete means every target mapping in the snapshot compared. One comparison runs at a time
in the app's process. `checked` false: the comparison did not run, and `reason` says why —
`maps_unreadable` or `maps_empty` when the memory map could not be read, `no_target_mapped` when it
names no target; every region is then incomplete.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `checked` | true/false | yes | the comparison ran |
| `diff_bytes` | integer, bytes | yes | bytes that differ in `core` (the same as `core_diff_bytes`) |
| `core_compared_bytes` | integer, bytes | yes | `core` bytes compared |
| `ext_compared_bytes` | integer, bytes | yes | `ext` bytes compared |
| `ext_diff_bytes` | integer, bytes | yes | `ext` bytes that differ |
| `app_compared_bytes` | integer, bytes | yes | `app` bytes compared |
| `app_diff_bytes` | integer, bytes | yes | `app` bytes that differ |
| `core_expected_bytes` | integer, bytes | when checked | `core` code found in memory, in bytes |
| `ext_expected_bytes` | integer, bytes | when checked | `ext` code found in memory, in bytes |
| `app_expected_bytes` | integer, bytes | when checked | `app` code found in memory, in bytes |
| `core_skipped_bytes` | integer, bytes |  | `core` bytes not compared, past the comparison's budget of 256 MiB a region |
| `ext_skipped_bytes` | integer, bytes |  | `ext` bytes not compared, past the budget |
| `app_skipped_bytes` | integer, bytes |  | `app` bytes not compared, past the budget |
| `core_unreadable_bytes` | integer, bytes |  | `core` bytes not compared because they could not be read: memory that could not be made readable, a file that could not be opened, a short read |
| `ext_unreadable_bytes` | integer, bytes |  | `ext` bytes that could not be read |
| `app_unreadable_bytes` | integer, bytes |  | `app` bytes that could not be read |
| `core_complete` | true/false |  | every `core` byte expected was compared |
| `ext_complete` | true/false |  | every `ext` byte expected was compared |
| `app_complete` | true/false |  | every `app` byte expected was compared: complete over the selected mappings of the snapshot, not over all of the app's code |
| `core_diff_bytes` | integer, bytes |  | `core` bytes that differ |
| `ext_libs_diff` | integer, count |  | `ext` libraries with a difference |
| `app_libs_diff` | integer, count |  | `app` files with a difference |
| `diffed_libs` | text |  | the files with a difference, comma-separated |
| `protect_restore_failures` | integer, count |  | execute-only memory whose protection could not be put back after the copy |
| `xom_regions_unlocked` | integer, count |  | execute-only regions made readable for the comparison |
| `xom_regions_unreadable` | integer, count |  | execute-only regions that could not be made readable: their bytes count as unreadable |
| `app_outside_count` | integer, count |  | executable files of the app's own (in its install or data directories) mapped but not in `app`, so not compared (collector 10) |
| `app_outside_files` | list |  | their file names, sorted, at most 32 (collector 10) |
| `elapsed_ms` | integer, milliseconds |  | how long the comparison took |

### `developer_settings`

Whether developer options and USB debugging are on. Both are common on honest phones (integration guide,
section 7.1). A setting that could not be read is in `unread`, never "off"; when neither could, the
probe answers `error`.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `developer_options_enabled` | true/false | yes | developer options are on |
| `adb_enabled` | true/false | yes | USB debugging is on |

### `emulator`

Build values typical of an Android emulator: the fingerprint, model, manufacturer, product, hardware and
board names of the common emulators.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `suspected` | true/false | yes | a build value looked like an emulator's |
| `reasons` | list |  | which: `fingerprint`, `model`, `manufacturer`, `product`, `hardware`, `board` |
| `model` | text |  | the build's model |
| `manufacturer` | text |  | the build's manufacturer |
| `product` | text |  | the build's product |
| `hardware` | text |  | the build's hardware |

### `device`

The phone and its software: the Android version and API level, the security patch level — how current
the phone's patches are — the maker and model, the build, the processor ABI the app runs as, and the
memory page size.

**When:** every scan, whether or not your backend asks.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `sdk_int` | integer, Android API level | yes | the Android API level, for example 34 |
| `release` | text |  | the Android version, for example `14` |
| `security_patch` | text |  | the security patch level, a date (`YYYY-MM-DD`) |
| `manufacturer` | text |  | the phone's maker |
| `brand` | text |  | its brand |
| `model` | text |  | its model |
| `device` | text |  | its device name |
| `build_id` | text |  | the build's ID |
| `fingerprint` | text |  | the build's fingerprint, at most 256 characters |
| `abi` | text |  | the ABI the app's process runs as — `arm64-v8a`, `armeabi-v7a`, `x86_64` — since a 32-bit app on a 64-bit phone maps other code |
| `page_size` | integer, bytes |  | the memory page size: 4096, or 16384 on phones built for 16 KB pages |

### `network`

Whether a VPN is up and an HTTP proxy is set, as Android's connectivity service says: every network is
asked, not only the default one, since a VPN is a network of its own. Interface names only, never an
address. The proxy says how the phone is set, not which way the report came: whether an app's own
requests follow it depends on how the app makes them (a Flutter app's do not). A listing of the
interfaces that failed, whole or for one interface, is in `unread` as `interfaces`: the list is then
not all of them.

**When:** every scan, whether or not your backend asks.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `vpn_active` | true/false | yes | a VPN network is up |
| `http_proxy_configured` | true/false |  | an HTTP proxy is set |
| `transports` | list |  | what carries the default network: `wifi`, `cellular`, `ethernet`, `vpn` |
| `interfaces` | list |  | the names of the network interfaces that are up, loopback left out — `wlan0`, `rmnet0`, `tun0` — at most 32 |

### `local_addresses`

The phone's own IP addresses, per network interface. Loopback and link-local addresses are left out: a
link-local address can carry the hardware address, which Android hides from apps.

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `addresses` | list | yes | each an `interface` (its name) and an `address` (IPv4 or IPv6), at most 32 |
| `truncated` | true/false |  | the phone had more than the 32 addresses a list holds (Android collector 10, iOS collector 8) |

### `accessibility`

Every Accessibility service that is on, and the keyboard in use: the two ways an app reads what the
person types. The Accessibility manager's list is compared with the system setting it is built from — a
service the setting names that the manager does not report was hiding, as an Android bug allowed until
the December 2022 security patch.

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `services` | list of apps | yes | the Accessibility services that are on, each an app with its `service` |
| `settings_only` | list | yes | services the system setting names that the Accessibility manager does not report, as component names |
| `truncated` | true/false | yes, false | the phone had more than the 32 a list holds |
| `keyboard` | an app |  | the keyboard in use — the default input method — with its `service` |

### `notification_access`

Every app allowed to read the phone's notifications — one-time codes among them.

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `listeners` | list of apps | yes | the apps allowed to read notifications, each with its `service` |
| `truncated` | true/false | yes, false | the phone had more than the 32 a list holds |

### `other_access`

The device-administrator apps that are active, and which of four known remote-control apps are
installed: AnyDesk, TeamViewer QuickSupport, RustDesk and AirDroid — a list compiled into the SDK,
which Android lets an app check without seeing other apps.

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `device_admins` | list of apps | yes | the active device administrators, each with its `service` |
| `remote_access_apps` | list of apps | yes | the remote-control apps installed, of the four |
| `truncated` | true/false | yes, false | the phone had more device administrators than the 32 a list holds |

### `screen_capture`

Whether the app's window is being recorded (Android 15 and later), and how many displays besides the
phone's own are on: casting, mirroring or an external screen, which it cannot tell apart. A display that
is off, or private to another app, is not counted. Recording needs `DETECT_SCREEN_RECORDING`, a
permission the SDK declares for your app; when it cannot be measured it is left out — unknown, not
"no".

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `recording` | true/false | yes | the app's window is being recorded |
| `external_displays` | integer, count | yes | displays besides the phone's own that are on and public |
| `recording_status` | one of `unsupported`, `no_permission`, `unavailable` |  | why `recording` is absent: `unsupported` below Android 15, `no_permission` without `DETECT_SCREEN_RECORDING`, `unavailable` with no app window to ask |

### `location`

The last location the phone already knows — never a fresh fix, never a prompt: the newest fix any
enabled provider holds, read once per scan, so that both location answers describe the same fix.
Coordinates come only with the location permission, which your app asks for itself (your SDK's README says how). With the
permission and no coordinates the phone holds no location — unless a provider could not be read: it is
then in `unread`, by its name, and the location may be there.

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `permission` | one of `none`, `approximate`, `precise` | yes | the app's location permission |
| `latitude` | number, degrees, WGS 84 | yes | the fix's latitude; absent without the permission or without a fix |
| `longitude` | number, degrees, WGS 84 | yes | the fix's longitude; absent likewise |
| `age_seconds` | integer, seconds | yes | how old the fix is |
| `accuracy_m` | number, metres |  | its accuracy, when the provider gives one |
| `provider` | text |  | the provider that made it, for example `gps` or `network` |
| `fix_time` | integer, Unix seconds, UTC |  | when it was made |

### `mock_location`

Whether that same fix came from a mock-location app, by Android's own flag. It never carries
coordinates, so asking for it alone never sends a location.

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `permission` | one of `none`, `approximate`, `precise` | yes | the app's location permission |
| `mock` | true/false | yes | the fix came from a mock-location app |
| `age_seconds` | integer, seconds | yes | how old the fix is |
| `fix_time` | integer, Unix seconds, UTC |  | when it was made: the same as `location`'s in one report |

## iOS

Your backend may ask for `app_identity`, `code_signing`, `debugger`, `jailbreak_files`, `sandbox`,
`dyld_images`, `environment` and `simulator`. Every scan carries `code_integrity`, `device` and
`network`. The personal measurements are `local_addresses`, `screen_capture`, `location` and
`mock_location`; `accessibility`, `notification_access` and `other_access` exist on iOS only to say that
iOS cannot measure them.

### `app_identity`

The installed app: its bundle identifier and version, and the SHA-256 and size of its main executable.
An executable with code added is larger, and one changed byte changes the hash: compare these with each
release of yours (integration guide, section 7.2).

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `bundle_id` | text | yes | the app's bundle identifier |
| `executable_sha256` | text | yes | the SHA-256 of the main executable; empty when it could not be read |
| `version_name` | text |  | the app's version (`CFBundleShortVersionString`) |
| `version_code` | text |  | the app's build number (`CFBundleVersion`) |
| `executable_bytes` | integer, bytes |  | the main executable's size |

### `code_signing`

The main executable's own code signature, read from the file: its signing identifier, your team
identifier, and whether the app lets a debugger attach (`get-task-allow`, set on development builds). An
executable that carries no signature says so: `signed` false, never taken for a signed app.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `signing_identifier` | text | yes | the signature's identifier; empty without one |
| `team_identifier` | text | yes | the team identifier its entitlements name; empty without one |
| `get_task_allow` | true/false | yes | its entitlements let a debugger attach |
| `signed` | true/false |  | the executable carries a signature |
| `signature_absent` | true/false |  | true when it carries none |
| `signature_parse_error` | text |  | why a signature that is there could not be read |
| `code_directory_flags` | integer |  | the code directory's flags, as a number |
| `entitlement_count` | integer, count |  | how many entitlements the signature grants |

### `debugger`

A debugger tracing the app's process: the kernel's `P_TRACED` flag.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `traced` | true/false | yes | a debugger traces the process |

### `jailbreak_files`

Whether 20 known jailbreak paths exist: the package managers (Cydia, Sileo, Zebra), Substrate and
ElleKit, a shell and SSH, apt's and Cydia's folders, `/private/var/stash`, the marker files of the
Electra, Taurine and unc0ver jailbreaks, and the rootless `/var/jb` layout of current jailbreaks. A
clean phone's sandbox hides most of them, so a path the app cannot see reads as absent. On the
Simulator, whose files are the Mac's, it answers `unsupported`.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `found_paths` | list | yes | the listed paths that exist |
| `checked_count` | integer, count |  | how many paths were checked |

### `sandbox`

Whether the app can write outside its sandbox: a phone that enforces the sandbox refuses it. A file that
was written is removed at once.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `write_outside_sandbox_succeeded` | true/false | yes | the write succeeded |
| `probe_path` | text |  | the path the app tried to write |

### `dyld_images`

Instrumentation and jailbreak names among the libraries loaded into the app: Frida and its Gadget,
Objection, Cynject, Cycript, Substrate and MobileSubstrate, Substitute, libhooker, ElleKit, Cydia,
Shadow, FLEX and libSparkAppList. It matches names, so a renamed library escapes it; `code_integrity`
compares the code itself. A library whose name the loader did not give (one unloading as the list is
read) is in `unread` as `image_names`, since it could be one of those.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `suspicious_tokens` | list | yes | the listed names found, sorted |
| `suspicious_image_count` | integer, count |  | loaded libraries with a listed name |
| `image_count` | integer, count |  | libraries loaded |

### `environment`

Libraries injected through the environment: `DYLD_INSERT_LIBRARIES`, which loads a library into the app
as it starts.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `dyld_insert_libraries` | text | yes | the variable's value, at most 8,192 characters; empty when it is not set |

### `simulator`

Whether the app runs in the iOS Simulator, and the hardware model.

**When:** your backend asks for it.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `is_simulator` | true/false | yes | the app runs in the Simulator |
| `model` | text |  | the hardware model identifier, for example `iPhone15,2` |

### `code_integrity`

The app's own code compared in memory with its files, image by image: every image the loader mapped from
the app — the main executable and its frameworks — has its `__text` compared. iOS keeps its system
libraries in a shared cache that no app can read, so only the app's own code can be compared: the system
figures are always 0 — not measured, never clean — and `system_images_unreadable` counts those
libraries. Each app image is compared, unreadable (its file could not be read in full) or skipped (no
usable `__text`, a `__TEXT` over 64 MiB, no live address, or code encrypted on disk); images and bytes
both add up, expected = compared + unreadable + skipped. An app installed from the App Store has its
code encrypted in its files and decrypted only in memory, so the two differ in every encrypted byte of a
genuine app: such an image is skipped and named in `app_images_not_compared`, never compared — a
development, ad hoc or enterprise build is stored in the clear and is compared. `app_complete` is true
exactly when every image was compared, the main executable among them. It comes with every scan; ask for it too, since a report that lacks it is refused
only when you asked for it.

**When:** every scan, whether or not your backend asks.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `checked` | true/false | yes | the comparison ran: at least one image was compared |
| `app_diff_bytes` | integer, bytes | yes | bytes that differ in the app's compared code |
| `app_compared_bytes` | integer, bytes | yes | the app's code compared, in bytes |
| `app_images_expected` | integer, count | when checked | the app's images the loader mapped |
| `app_images_compared` | integer, count | when checked | of those, the images compared |
| `app_images_unreadable` | integer, count | when checked | the images whose file could not be read in full |
| `app_images_skipped` | integer, count | when checked | the images skipped |
| `app_expected_bytes` | integer, bytes | when checked | the `__text` bytes of the app's images |
| `app_unreadable_bytes` | integer, bytes | when checked | those of the unreadable images |
| `app_skipped_bytes` | integer, bytes | when checked | those of the skipped images |
| `app_complete` | true/false | when checked | every app image was compared |
| `main_executable_compared` | true/false | when checked | the main executable was among the compared |
| `app_images_not_compared` | map |  | each app image not compared, by its path in the app, with why |
| `system_images_unreadable` | integer, count |  | the system libraries loaded, which no app can read |
| `app_libs_diff` | integer, count |  | app images with a difference |
| `diffed_libs` | text |  | the images with a difference, comma-separated |
| `diff_bytes` | integer |  | always 0: iOS's system libraries cannot be read |
| `core_compared_bytes` | integer |  | always 0, likewise |
| `core_diff_bytes` | integer |  | always 0, likewise |
| `ext_compared_bytes` | integer |  | always 0, likewise |
| `ext_diff_bytes` | integer |  | always 0, likewise |
| `ext_libs_diff` | integer |  | always 0, likewise |
| `system_bucket_reason` | text |  | why the system figures are 0: `dyld_shared_cache_has_no_backing_files` |
| `app_segment_compared_bytes` | integer, bytes |  | the whole `__TEXT` segments compared, beyond `__text`, in bytes: telemetry |
| `app_segment_diff_bytes` | integer, bytes |  | bytes that differ across those segments: telemetry |

### `device`

The iOS version and build, the hardware model, and the memory page size. iOS has no separate security
patch level: its security fixes ship as iOS versions, and the build tells a Rapid Security Response
apart.

**When:** every scan, whether or not your backend asks.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `os_version` | text | yes | the iOS version, for example `17.6.1` |
| `os_build` | text |  | the build, for example `21G93` |
| `model_identifier` | text |  | the hardware model identifier, for example `iPhone15,2` |
| `page_size` | integer, bytes |  | the memory page size: 16384 on Apple's 64-bit phones |

### `network`

Whether a VPN or an HTTP proxy is in use. iOS gives apps no way to ask about a VPN, so a VPN is inferred
from the network interfaces the system proxy settings are scoped to (`utun`, `ipsec`, `ppp`, `tun`,
`tap`): a heuristic, so the names come with it. The proxy is read from the system proxy settings;
whether an app's own requests follow it depends on how the app makes them (a Flutter app's do not).

**When:** every scan, whether or not your backend asks.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `vpn_active` | true/false | yes | an interface the proxy settings are scoped to is a VPN's kind |
| `http_proxy_configured` | true/false |  | an HTTP, HTTPS or automatic proxy is set |
| `scoped_interfaces` | list |  | the interfaces the proxy settings are scoped to, sorted, at most 32 — `en0` Wi-Fi, `pdp_ip0` cellular, `utun3` a tunnel |

### `local_addresses`

The phone's own IP addresses, per network interface. Loopback and link-local (`fe80`, `169.254`)
addresses are left out.

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `addresses` | list | yes | each an `interface` (its name) and an `address` (IPv4 or IPv6), at most 32 |
| `truncated` | true/false |  | the phone had more than the 32 addresses a list holds (Android collector 10, iOS collector 8) |

### `screen_capture`

Whether the screen showing the app is being recorded, mirrored or sent to AirPlay
(`UIScreen.isCaptured`, asked of the screen of each of the app's windows in the foreground), and how
many other screens are attached. With no window of the app's in the foreground — the app in the
background, or before its first window — recording is not measured: it is left out, unknown rather than
"no", and `recording_status` says why.

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `recording` | true/false | yes | the screen showing the app is being captured |
| `external_displays` | integer, count | yes | other screens attached |
| `recording_status` | one of `unsupported`, `no_permission`, `unavailable` |  | why `recording` is absent: `unavailable`, no window of the app's in the foreground to ask. iOS has measured recording since iOS 11, so `unsupported` never comes from iOS |

### `location`

The last location the phone already holds — never a fresh fix, never a prompt — read once per scan, so
that both location answers describe the same fix. Coordinates come only with the location permission,
which your app asks for itself (your SDK's README says how).

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `permission` | one of `none`, `approximate`, `precise` | yes | the app's location permission: `approximate` when the person allowed an approximate location only |
| `latitude` | number, degrees, WGS 84 | yes | the fix's latitude; absent without the permission or without a fix |
| `longitude` | number, degrees, WGS 84 | yes | the fix's longitude; absent likewise |
| `age_seconds` | integer, seconds | yes | how old the fix is |
| `accuracy_m` | number, metres |  | its horizontal accuracy |
| `fix_time` | integer, Unix seconds, UTC |  | when it was made |

### `mock_location`

Whether that same fix was simulated by software, by Apple's own flag, or produced by an external
accessory. Apple's flag catches the simulation of its own developer tools; Apple does not promise it for
other spoofing apps. It never carries coordinates.

**When:** your backend asks for it and your app enables it — a personal measurement.

| Field | Type | Needed | Meaning |
|---|---|---|---|
| `permission` | one of `none`, `approximate`, `precise` | yes | the app's location permission |
| `mock` | true/false | yes | iOS says the fix was simulated by software; absent when iOS did not say |
| `age_seconds` | integer, seconds | yes | how old the fix is |
| `accessory` | true/false |  | the fix came from an external accessory, such as a GPS receiver |
| `fix_time` | integer, Unix seconds, UTC |  | when it was made: the same as `location`'s in one report |

### `accessibility`

iOS shows an app no other app, so there is nothing to list: this answers `unsupported` when your app
enables it, and `not_enabled` when it does not. No fields.

**When:** your backend asks for it and your app enables it — a personal measurement.

### `notification_access`

iOS shows an app no other app, so there is nothing to list: this answers `unsupported` when your app
enables it, and `not_enabled` when it does not. No fields.

**When:** your backend asks for it and your app enables it — a personal measurement.

### `other_access`

iOS shows an app no other app, so there is nothing to list: this answers `unsupported` when your app
enables it, and `not_enabled` when it does not. No fields.

**When:** your backend asks for it and your app enables it — a personal measurement.

## What no measurement can prove

A fully compromised phone can report anything, and a modified app that holds a registered key signs
whatever it is given: the signature proves which installation sent a report, not that the phone is
honest or that the SDK measured what it reports (integration guide, section 9). The measurements raise
the cost of fraud; your backend weighs them with its own business logic.
