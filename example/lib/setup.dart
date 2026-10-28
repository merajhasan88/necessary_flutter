// How an app sets up the plugin: one DeviceTrust for its backend, with the
// options it chooses. Everything else in the example uses what is made here.
import 'package:necessary/necessary.dart';

const String _backendUrl = String.fromEnvironment(
  'NECESSARY_BACKEND_URL',
  defaultValue: 'http://10.0.2.2:8787',
);
const String _backendList = String.fromEnvironment('NECESSARY_BACKENDS');

/// The backends to choose among, by name: NECESSARY_BACKENDS
/// (`Name=https://…;Other=https://…`), or the one NECESSARY_BACKEND_URL.
final Map<String, String> backends = _backendList.isEmpty
    ? <String, String>{'Sample': _backendUrl}
    : <String, String>{
        for (final String entry in _backendList.split(';'))
          if (entry.contains('='))
            entry.substring(0, entry.indexOf('=')).trim(): entry
                .substring(entry.indexOf('=') + 1)
                .trim(),
      };

/// Device trust against the backend at [baseUrl].
DeviceTrust setUpDeviceTrust(
  String baseUrl, {
  Set<PersonalMeasurement> personalMeasurements = const <PersonalMeasurement>{},
}) => DeviceTrust(
  baseUrl: baseUrl,
  // The personal measurements this app allows -- none unless it names them.
  // The backend asks for those it needs, and only what both name is measured.
  // They can change while the app runs: trust.personalMeasurements = {...}.
  personalMeasurements: personalMeasurements,
  // Step-up: a second key, which the person unlocks to approve one request.
  // factor 'passcode' (the phone's PIN, pattern or password) or 'biometric';
  // mode 'per_use', or 'windowed' with windowSeconds (Android only). Leave it
  // out for no step-up.
  stepUp: const StepUpOptions(factor: 'passcode', mode: 'per_use'),
  // The app PIN, which the backend checks for one request. Its two calls
  // default to the guide's paths. Leave it out for no app PIN.
  appPin: const AppPinOptions(),
);
