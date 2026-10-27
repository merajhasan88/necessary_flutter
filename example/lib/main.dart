// The necessary plugin against its sample backends (../backend): start, a
// scan, and the sample's own calls, each carrying the proofs the plugin adds.
// Start a sample, then:
//
//     flutter run --dart-define=NECESSARY_BACKEND_URL=http://10.0.2.2:8787
//
// (10.0.2.2 is the development machine as the Android emulator sees it.) To
// choose among several, name each:
//
//     --dart-define='NECESSARY_BACKENDS=Python=https://…;TypeScript=https://…'
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:necessary/necessary.dart';

const String backendUrl = String.fromEnvironment(
  'NECESSARY_BACKEND_URL',
  defaultValue: 'http://10.0.2.2:8787',
);
const String backendList = String.fromEnvironment('NECESSARY_BACKENDS');

/// The backends to choose among, by name: NECESSARY_BACKENDS, or the one URL.
final Map<String, String> backends = backendList.isEmpty
    ? <String, String>{'Sample': backendUrl}
    : <String, String>{
        for (final String entry in backendList.split(';'))
          if (entry.contains('='))
            entry.substring(0, entry.indexOf('=')).trim(): entry
                .substring(entry.indexOf('=') + 1)
                .trim(),
      };

/// The sample backend's demonstration account.
const String _handle = 'example';
const String _password = 'example password';

void main() => runApp(const ExampleApp());

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'necessary',
    theme: ThemeData(colorSchemeSeed: Colors.teal),
    home: const TrustPage(),
  );
}

class TrustPage extends StatefulWidget {
  const TrustPage({super.key});

  @override
  State<TrustPage> createState() => _TrustPageState();
}

class _TrustPageState extends State<TrustPage> {
  String _backend = backends.keys.first;
  late DeviceTrust _trust = _trustFor(_backend);

  DeviceTrust _trustFor(String name) => DeviceTrust(
    baseUrl: backends[name]!,
    // Step-up and the app PIN, turned on; the personal measurements, none.
    stepUp: const StepUpOptions(factor: 'passcode', mode: 'per_use'),
    appPin: const AppPinOptions(),
  );

  /// Another backend: the same key, an installation of its own there.
  void _choose(String name) {
    _trust.close();
    setState(() {
      _backend = name;
      _trust = _trustFor(name);
      _account = null;
      _log.insert(0, 'Backend: $name, ${backends[name]}');
    });
  }

  final TextEditingController _pin = TextEditingController();
  final FocusNode _pinFocus = FocusNode();
  final List<String> _log = <String>[];
  String? _account;
  bool _busy = false;
  bool _screenProtected = false;

  @override
  void initState() {
    super.initState();
    _pinFocus.addListener(_protectWhilePinTyped);
  }

  /// No screenshots or recording of the window while the PIN is typed.
  void _protectWhilePinTyped() {
    if (_pinFocus.hasFocus != _screenProtected) {
      _screenProtected = _pinFocus.hasFocus;
      SecureScreen.protect(_screenProtected);
    }
  }

  @override
  void dispose() {
    if (_screenProtected) {
      SecureScreen.protect(false);
    }
    _pinFocus.dispose();
    _pin.dispose();
    _trust.close();
    super.dispose();
  }

  Future<void> _run(String label, Future<String> Function() step) async {
    setState(() => _busy = true);
    String line;
    try {
      line = await step();
    } on ApiException catch (error) {
      line = 'refused, ${error.statusCode} ${error.code}: ${error.message}';
    } on NativeKeyException catch (error) {
      line = 'the phone said ${error.code}: ${error.message}';
    } catch (error) {
      line = '$error';
    }
    // Also to the device log (logcat on Android), for whoever runs a test.
    debugPrint('EXAMPLE: [$_backend] $label — $line');
    if (mounted) {
      setState(() {
        _busy = false;
        _log.insert(0, '$label — $line');
      });
    }
  }

  Future<String> _start() async {
    final InstallationIdentity identity = await _trust.start();
    final NativeKeyException? stepUp = _trust.stepUpUnavailable;
    return 'installation ${identity.installationId}, key ${identity.securityLevel}, '
        '${stepUp == null ? 'step-up on' : 'step-up off (${stepUp.code})'}';
  }

  Future<String> _scan() async {
    final ScanResult scan = await _trust.scan();
    return 'report ${scan.reportId}: ${jsonEncode(scan.answer)}';
  }

  /// The sample's own sign-in, under the installation session.
  Future<String> _signIn() async {
    final RequestProof proof = await _trust.signRequest(
      method: 'POST',
      path: '/v1/demo/sign-in',
      bearer: _trust.installationSession!,
      body: jsonEncode(<String, String>{
        'handle': _handle,
        'password': _password,
      }),
    );
    _account = (await _trust.send(proof))['account_session'] as String;
    return 'an account session for this installation';
  }

  /// A transfer, which the sample takes only with a scan made for it.
  Future<String> _transfer() async {
    const String body = '{"amount":25,"to":"payee-7"}';
    final ScanResult scan = await _trust.scan(
      session: _account!,
      operation: describeOperation('POST', '/v1/demo/transfer', body),
    );
    final RequestProof proof = await _trust.signRequest(
      method: 'POST',
      path: '/v1/demo/transfer',
      bearer: _account!,
      body: body,
      reportId: scan.reportId,
    );
    return jsonEncode(await _trust.send(proof));
  }

  /// An approval, which the sample takes only with the person's step-up.
  Future<String> _approve() async {
    final RequestProof proof = await _trust.signRequest(
      method: 'POST',
      path: '/v1/demo/approve',
      bearer: _account!,
      body: '{"payee":"payee-7"}',
      stepUp: true,
      reason: 'Approve the new payee',
    );
    return jsonEncode(await _trust.send(proof));
  }

  Future<String> _setPin() async {
    await _trust.setAppPin(
      session: _account!,
      pin: _pin.text,
      reauthentication: <String, String>{'password': _password},
    );
    return 'PIN set';
  }

  /// A request the sample takes only with the app PIN's proof.
  Future<String> _unlock() async {
    final RequestProof proof = await _trust.signRequest(
      method: 'POST',
      path: '/v1/demo/unlock',
      bearer: _account!,
      appPin: _pin.text,
    );
    return jsonEncode(await _trust.send(proof));
  }

  @override
  Widget build(BuildContext context) {
    final bool started = _trust.installationSession != null;
    final bool signedIn = _account != null;
    Widget action(String label, Future<String> Function() step, bool enabled) =>
        FilledButton.tonal(
          onPressed: _busy || !enabled ? null : () => _run(label, step),
          child: Text(label),
        );
    return Scaffold(
      appBar: AppBar(title: const Text('necessary')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: <Widget>[
          if (backends.length > 1)
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
          Text('Backend: ${backends[_backend]}'),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: <Widget>[
              action('Start', _start, true),
              action('Scan', _scan, started),
              action('Sign in', _signIn, started),
              action('Transfer', _transfer, signedIn),
              action('Approve (step-up)', _approve, signedIn),
            ],
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _pin,
            focusNode: _pinFocus,
            obscureText: true,
            keyboardType: TextInputType.number,
            maxLength: 6,
            decoration: const InputDecoration(labelText: 'App PIN (6 digits)'),
          ),
          Wrap(
            spacing: 8,
            children: <Widget>[
              action('Set PIN', _setPin, signedIn),
              action('Unlock with PIN', _unlock, signedIn),
            ],
          ),
          const Divider(height: 32),
          for (final String line in _log)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: SelectableText(line),
            ),
        ],
      ),
    );
  }
}
