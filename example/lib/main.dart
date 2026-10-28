// The necessary plugin against its sample backends (../backend), section by
// section: the installation, the scan with every measurement it sent, an
// account, requests with and without the person's approval, and requests a
// backend must refuse. setup.dart makes the DeviceTrust, sample_api.dart signs
// what the app sends, measurements.dart reads a scan; this file is the screen.
//
// Start a sample backend, then:
//
//     flutter run --dart-define=NECESSARY_BACKEND_URL=http://10.0.2.2:8787
//
// (10.0.2.2 is the development machine as the Android emulator sees it.) To
// choose among several, name each:
//
//     --dart-define='NECESSARY_BACKENDS=Python=https://…;TypeScript=https://…'
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:necessary/necessary.dart';

import 'measurements.dart';
import 'sample_api.dart';
import 'setup.dart';

void main() => runApp(const ExampleApp());

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Necessary',
    theme: ThemeData(colorSchemeSeed: Colors.teal),
    home: const TrustPage(),
  );
}

/// What a backend that makes the guide's checks does with a request.
enum Expect { accepted, refused }

/// One action's result as shown: [asExpected] when the backend did what
/// [Expect] says.
class Outcome {
  const Outcome(this.action, this.text, {required this.asExpected});

  final String action;
  final String text;
  final bool asExpected;
}

class TrustPage extends StatefulWidget {
  const TrustPage({super.key});

  @override
  State<TrustPage> createState() => _TrustPageState();
}

class _TrustPageState extends State<TrustPage> {
  String _backend = backends.keys.first;
  late DeviceTrust _trust = setUpDeviceTrust(backends[_backend]!);
  late SampleApi _api = SampleApi(_trust);

  ScanResult? _scan;
  String? _locationPermission;
  bool _busy = false;
  final Map<String, Outcome> _latest = <String, Outcome>{};
  final List<Outcome> _log = <Outcome>[];

  final TextEditingController _handle = TextEditingController(text: 'example');
  final TextEditingController _password = TextEditingController(
    text: 'example password',
  );
  final TextEditingController _pin = TextEditingController();
  final TextEditingController _shared = TextEditingController();
  final FocusNode _passwordFocus = FocusNode();
  final FocusNode _pinFocus = FocusNode();
  bool _screenProtected = false;

  @override
  void initState() {
    super.initState();
    _passwordFocus.addListener(_protectSecrets);
    _pinFocus.addListener(_protectSecrets);
  }

  /// No screenshots or recordings of the window while a secret is typed.
  void _protectSecrets() {
    final bool typing = _passwordFocus.hasFocus || _pinFocus.hasFocus;
    if (typing != _screenProtected) {
      _screenProtected = typing;
      SecureScreen.protect(typing);
    }
  }

  @override
  void dispose() {
    if (_screenProtected) {
      SecureScreen.protect(false);
    }
    for (final TextEditingController controller in <TextEditingController>[
      _handle,
      _password,
      _pin,
      _shared,
    ]) {
      controller.dispose();
    }
    _passwordFocus.dispose();
    _pinFocus.dispose();
    _trust.close();
    super.dispose();
  }

  /// Another backend: the same key, an installation of its own there, and
  /// the same personal measurements.
  void _choose(String name) {
    final Set<PersonalMeasurement> enabled = _trust.personalMeasurements;
    _trust.close();
    setState(() {
      _backend = name;
      _trust = setUpDeviceTrust(backends[name]!, personalMeasurements: enabled);
      _api = SampleApi(_trust);
      _scan = null;
      _latest.clear();
    });
  }

  /// Runs one action of [section] and shows how the backend answered it.
  Future<void> _run(
    String section,
    String action,
    Future<String> Function() step, {
    Expect expect = Expect.accepted,
  }) async {
    setState(() => _busy = true);
    Outcome outcome;
    try {
      final String answer = await step();
      outcome = expect == Expect.accepted
          ? Outcome(action, answer, asExpected: true)
          : Outcome(
              action,
              'Accepted, but a backend should refuse this: $answer',
              asExpected: false,
            );
    } on ApiException catch (error) {
      final String refusal = '${error.statusCode ?? ''} ${error.code ?? ''}'
          .trim();
      // A session the backend no longer takes says nothing of the check a
      // request was made wrong to test: the sample's session lasts ten
      // minutes.
      final bool sessionGone =
          error.code == 'expired_token' || error.code == 'not_signed_in';
      outcome = expect == Expect.refused && !sessionGone
          ? Outcome(
              action,
              'Refused, as it should be: $refusal',
              asExpected: true,
            )
          : Outcome(
              action,
              sessionGone
                  ? 'Refused: $refusal. The session is no longer valid: '
                        'sign in again.'
                  : 'Refused: $refusal. ${error.message}',
              asExpected: false,
            );
    } on NativeKeyException catch (error) {
      outcome = Outcome(
        action,
        'The phone said ${error.code}: ${error.message}',
        asExpected: false,
      );
    } catch (error) {
      outcome = Outcome(action, '$error', asExpected: false);
    }
    // Also to the device log (logcat on Android), for whoever runs a test.
    debugPrint('EXAMPLE: [$_backend] $action — ${outcome.text}');
    if (mounted) {
      setState(() {
        _busy = false;
        _latest[section] = outcome;
        _log.insert(0, outcome);
      });
    }
  }

  // --- The installation.

  Future<String> _start() async {
    final InstallationIdentity identity = await _trust.start();
    final NativeKeyException? stepUpOff = _trust.stepUpUnavailable;
    return 'Installation ${identity.installationId}, proved; step-up '
        '${stepUpOff == null ? 'on' : 'off here (${stepUpOff.code})'}.';
  }

  Future<String> _prove() async {
    await _trust.prove();
    return 'A new installation session.';
  }

  Future<void> _newInstallation() async {
    final bool? confirmed = await showDialog<bool>(
      context: context,
      builder: (BuildContext dialog) => AlertDialog(
        title: const Text('A new installation?'),
        content: const Text(
          'This deletes the installation key and its ID, as a reinstall '
          'would, and starts again with a new key.',
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.pop(dialog, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialog, true),
            child: const Text('Start again'),
          ),
        ],
      ),
    );
    if (confirmed != true) {
      return;
    }
    await _run('Installation', 'New installation', () async {
      await _trust.reset();
      _api.account = null;
      _scan = null;
      return _start();
    });
  }

  // --- The scan.

  void _setPersonal(Set<PersonalMeasurement> enabled) =>
      setState(() => _trust.personalMeasurements = enabled);

  Future<String> _askLocation() async {
    final String permission = await _trust.requestLocationPermission();
    setState(() => _locationPermission = permission);
    return 'The app holds: $permission.';
  }

  Future<String> _doScan() async {
    final ScanResult scan = await _trust.scan();
    setState(() => _scan = scan);
    final Object? integrity = scan.answer['integrity'];
    final Object? next = integrity is Map ? integrity['next'] : null;
    return 'The backend answered next: ${next ?? 'not said'}, '
        'report ${scan.reportId ?? 'not named'}.';
  }

  // --- The screen.

  @override
  Widget build(BuildContext context) {
    final bool started = _trust.installationSession != null;
    final bool signedIn = _api.account != null;
    final ScanResult? scan = _scan;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Necessary'),
        bottom: _busy
            ? const PreferredSize(
                preferredSize: Size.fromHeight(4),
                child: LinearProgressIndicator(),
              )
            : null,
      ),
      // A column, not a list: every section stays built, so each keeps what
      // it shows while scrolled away.
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 32),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            if (backends.length > 1) ...<Widget>[
              SegmentedButton<String>(
                segments: <ButtonSegment<String>>[
                  for (final String name in backends.keys)
                    ButtonSegment<String>(value: name, label: Text(name)),
                ],
                selected: <String>{_backend},
                onSelectionChanged: _busy
                    ? null
                    : (Set<String> chosen) => _choose(chosen.single),
              ),
              const SizedBox(height: 4),
            ],
            Text(
              'Backend: ${backends[_backend]}',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            _section(
              'Installation',
              started
                  ? 'Its key made, registered and proved'
                  : 'Start: make the key, register it, prove it',
              _installation(started),
              initiallyExpanded: true,
            ),
            _section(
              'Measurements',
              scan == null
                  ? 'What the phone measures, signed with its key'
                  : '${(scan.report.report['probe_results'] as Map).length} '
                        'sent in the last scan',
              _measurements(started),
            ),
            _section(
              'Account',
              signedIn ? 'Signed in' : 'Sign in to the sample backend',
              _account(started, signedIn),
            ),
            _section(
              'Requests',
              "A proof on each; the person's approval on a sensitive one",
              _requests(signedIn),
            ),
            _section(
              'Requests a backend must refuse',
              'Made wrong on purpose',
              _refusals(started, signedIn),
            ),
            _section(
              'Log',
              '${_log.length} results, the latest first',
              <Widget>[
                for (final Outcome outcome in _log) _outcomeLine(outcome),
              ],
            ),
          ],
        ),
      ),
    );
  }

  List<Widget> _installation(bool started) {
    final InstallationIdentity? identity = _trust.identity;
    final StepUpKeyMetadata? stepUp = _trust.stepUpKey;
    final NativeKeyException? stepUpOff = _trust.stepUpUnavailable;
    return <Widget>[
      _actions(<Widget>[
        _button(
          'Installation',
          started ? 'Start again' : 'Start',
          _start,
          primary: true,
        ),
        _button('Installation', 'Prove again', _prove, enabled: started),
        OutlinedButton(
          onPressed: _busy || identity == null ? null : _newInstallation,
          child: const Text('New installation'),
        ),
      ]),
      _latestLine('Installation'),
      if (identity != null) ...<Widget>[
        _field('Installation ID', identity.installationId),
        _field('Key thumbprint', identity.keyThumbprint),
        _field(
          'Key',
          '${identity.algorithm}, ${identity.provider}, '
              '${identity.securityLevel}',
        ),
        _field('Hardware-backed', identity.hardwareBacked ? 'yes' : 'no'),
        _field(
          'Can leave the phone',
          identity.privateKeyExportable ? 'yes' : 'no',
        ),
        _field('New this launch', identity.createdThisLaunch ? 'yes' : 'no'),
        _field(
          'Step-up key',
          stepUp != null
              ? '${stepUp.description}, ${stepUp.securityLevel}'
              : stepUpOff != null
              ? 'off on this phone: ${stepUpOff.code}'
              : 'made at start',
        ),
      ],
    ];
  }

  List<Widget> _measurements(bool started) {
    final Set<PersonalMeasurement> enabled = _trust.personalMeasurements;
    final ScanResult? scan = _scan;
    final bool locationOn =
        enabled.contains(PersonalMeasurement.location) ||
        enabled.contains(PersonalMeasurement.mockLocation);
    return <Widget>[
      Text(
        'Personal measurements',
        style: Theme.of(context).textTheme.titleSmall,
      ),
      _note(
        'Measured only when this app turns one on and the backend asks for '
        'it. None is on until the app says so.',
      ),
      SwitchListTile(
        dense: true,
        contentPadding: EdgeInsets.zero,
        title: const Text('All of them'),
        value: enabled.length == PersonalMeasurement.values.length,
        onChanged: _busy
            ? null
            : (bool on) => _setPersonal(
                on
                    ? PersonalMeasurement.values.toSet()
                    : <PersonalMeasurement>{},
              ),
      ),
      for (final PersonalMeasurement measurement in PersonalMeasurement.values)
        SwitchListTile(
          dense: true,
          contentPadding: EdgeInsets.zero,
          title: Text(personalInfo(measurement).title),
          subtitle: Text(personalInfo(measurement).about),
          value: enabled.contains(measurement),
          onChanged: _busy
              ? null
              : (bool on) => _setPersonal(
                  on
                      ? <PersonalMeasurement>{...enabled, measurement}
                      : (<PersonalMeasurement>{...enabled}
                          ..remove(measurement)),
                ),
        ),
      _code(_personalCode(enabled)),
      if (locationOn)
        _actions(<Widget>[
          _button(
            'Measurements',
            _locationPermission == null
                ? 'Ask for the location permission'
                : 'Location permission: $_locationPermission',
            _askLocation,
          ),
        ]),
      _actions(<Widget>[
        _button(
          'Measurements',
          'Scan',
          _doScan,
          enabled: started,
          primary: true,
        ),
      ]),
      _latestLine('Measurements'),
      if (scan != null)
        ScanView(
          platform: scan.challenge.platform,
          required: scan.challenge.requiredProbes,
          optional: scan.challenge.optionalProbes,
          results: Map<String, dynamic>.from(
            scan.report.report['probe_results'] as Map,
          ),
          enabled: List<String>.from(
            scan.report.report['enabled_measurements'] as List,
          ),
        ),
    ];
  }

  /// The code for the personal measurements chosen above.
  String _personalCode(Set<PersonalMeasurement> enabled) => enabled.isEmpty
      ? 'trust.personalMeasurements = {};'
      : <String>[
          'trust.personalMeasurements = {',
          for (final PersonalMeasurement measurement
              in PersonalMeasurement.values)
            if (enabled.contains(measurement))
              '  PersonalMeasurement.${measurement.name},',
          '};',
        ].join('\n');

  List<Widget> _account(bool started, bool signedIn) => <Widget>[
    TextField(
      controller: _handle,
      autocorrect: false,
      decoration: const InputDecoration(labelText: 'Handle'),
    ),
    TextField(
      controller: _password,
      focusNode: _passwordFocus,
      obscureText: true,
      autocorrect: false,
      enableSuggestions: false,
      enableIMEPersonalizedLearning: false,
      decoration: const InputDecoration(
        labelText: 'Password',
        helperText: 'The sample makes the account at its first sign-in',
      ),
    ),
    _actions(<Widget>[
      _button(
        'Account',
        'Sign in',
        () async {
          await _api.signIn(_handle.text, _password.text);
          return 'An account session for this installation.';
        },
        enabled: started,
        primary: true,
      ),
      OutlinedButton(
        onPressed: _busy || !signedIn
            ? null
            : () => setState(() => _api.account = null),
        child: const Text('Sign out'),
      ),
    ]),
    _latestLine('Account'),
  ];

  List<Widget> _requests(bool signedIn) => <Widget>[
    _note(
      "Each request carries a proof signed by this installation's key. The "
      "sensitive one also needs the person's approval: the step-up key, "
      'unlocked with the screen lock, or the app PIN.',
    ),
    _actions(<Widget>[
      _button(
        'Requests',
        'Protected request',
        () async => jsonEncode(await _api.protectedRequest()),
        enabled: signedIn,
      ),
      _button(
        'Requests',
        'Sensitive, without approval',
        () async => jsonEncode(await _api.sensitive()),
        enabled: signedIn,
        expect: Expect.refused,
      ),
      _button(
        'Requests',
        'Sensitive, with step-up',
        () async => jsonEncode(await _api.sensitive(stepUp: true)),
        enabled: signedIn,
      ),
    ]),
    TextField(
      controller: _pin,
      focusNode: _pinFocus,
      obscureText: true,
      keyboardType: TextInputType.number,
      maxLength: 6,
      autocorrect: false,
      enableSuggestions: false,
      enableIMEPersonalizedLearning: false,
      decoration: const InputDecoration(
        labelText: 'App PIN (6 digits)',
        helperText: 'The screen is protected while it is typed',
      ),
    ),
    _actions(<Widget>[
      _button('Requests', 'Set the app PIN', () async {
        await _api.setAppPin(_pin.text, _password.text);
        return 'Set, with the account password.';
      }, enabled: signedIn),
      _button(
        'Requests',
        'Sensitive, with the app PIN',
        () async => jsonEncode(await _api.sensitive(appPin: _pin.text)),
        enabled: signedIn,
      ),
    ]),
    _latestLine('Requests'),
  ];

  List<Widget> _refusals(bool started, bool signedIn) => <Widget>[
    _note(
      'Each of these is a request made wrong on purpose. A backend that '
      "makes the guide's checks refuses every one.",
    ),
    _actions(<Widget>[
      _refusal('Send one request twice', _api.replay, signedIn),
      _refusal('Change the body after signing', _api.changedBody, signedIn),
      _refusal('Send it to another path', _api.otherPath, signedIn),
      _refusal('A proof ten minutes old', _api.staleProof, signedIn),
    ]),
    const SizedBox(height: 8),
    Text(
      'A session copied to another phone',
      style: Theme.of(context).textTheme.titleSmall,
    ),
    _note(
      "Copy this phone's session, get it to another phone running this "
      "example, paste it there and use it: that phone's key cannot sign for "
      'this installation.',
    ),
    _actions(<Widget>[
      OutlinedButton(
        onPressed: _busy || !signedIn ? null : _copySession,
        child: const Text("Copy this phone's session"),
      ),
    ]),
    TextField(
      controller: _shared,
      minLines: 1,
      maxLines: 3,
      onChanged: (_) => setState(() {}),
      decoration: const InputDecoration(
        labelText: 'A session from another phone',
      ),
    ),
    _actions(<Widget>[
      _refusal(
        'Use it here',
        () => _api.sessionFromAnotherPhone(_shared.text),
        started && _shared.text.trim().isNotEmpty,
      ),
    ]),
    _latestLine('Refusals'),
  ];

  Future<void> _copySession() async {
    await Clipboard.setData(ClipboardData(text: _api.shareSession()));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text("Copied this phone's session")),
      );
    }
  }

  // --- Pieces of the screen.

  Widget _section(
    String title,
    String subtitle,
    List<Widget> children, {
    bool initiallyExpanded = false,
  }) => Card(
    clipBehavior: Clip.antiAlias,
    child: ExpansionTile(
      initiallyExpanded: initiallyExpanded,
      maintainState: true,
      shape: const Border(),
      collapsedShape: const Border(),
      title: Text(title, style: Theme.of(context).textTheme.titleMedium),
      subtitle: Text(subtitle),
      expandedCrossAxisAlignment: CrossAxisAlignment.stretch,
      childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
      children: children,
    ),
  );

  Widget _button(
    String section,
    String label,
    Future<String> Function() step, {
    bool enabled = true,
    bool primary = false,
    Expect expect = Expect.accepted,
  }) {
    final VoidCallback? onPressed = _busy || !enabled
        ? null
        : () => _run(section, label, step, expect: expect);
    if (expect == Expect.refused) {
      return OutlinedButton(onPressed: onPressed, child: Text(label));
    }
    return primary
        ? FilledButton(onPressed: onPressed, child: Text(label))
        : FilledButton.tonal(onPressed: onPressed, child: Text(label));
  }

  Widget _refusal(
    String label,
    Future<Map<String, dynamic>> Function() step,
    bool enabled,
  ) => _button(
    'Refusals',
    label,
    () async => jsonEncode(await step()),
    enabled: enabled,
    expect: Expect.refused,
  );

  Widget _actions(List<Widget> buttons) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 8),
    child: Wrap(spacing: 8, runSpacing: 8, children: buttons),
  );

  Widget _latestLine(String section) {
    final Outcome? outcome = _latest[section];
    return outcome == null ? const SizedBox.shrink() : _outcomeLine(outcome);
  }

  Widget _outcomeLine(Outcome outcome) {
    final ColorScheme colors = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Icon(
            outcome.asExpected
                ? Icons.check_circle_outline
                : Icons.error_outline,
            size: 18,
            color: outcome.asExpected ? colors.primary : colors.error,
          ),
          const SizedBox(width: 8),
          Expanded(child: SelectableText('${outcome.action}: ${outcome.text}')),
        ],
      ),
    );
  }

  Widget _field(String label, String value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 2),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        Expanded(
          flex: 2,
          child: Text(
            label,
            style: const TextStyle(fontWeight: FontWeight.w600),
          ),
        ),
        Expanded(flex: 3, child: SelectableText(value)),
      ],
    ),
  );

  Widget _note(String text) => Padding(
    padding: const EdgeInsets.only(bottom: 4),
    child: Text(text, style: Theme.of(context).textTheme.bodySmall),
  );

  Widget _code(String code) => Container(
    width: double.infinity,
    margin: const EdgeInsets.symmetric(vertical: 8),
    padding: const EdgeInsets.all(10),
    decoration: BoxDecoration(
      color: Theme.of(context).colorScheme.surfaceContainerHighest,
      borderRadius: BorderRadius.circular(8),
    ),
    child: SelectableText(
      code,
      style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
    ),
  );
}
