/// Where the plugin keeps the installation ID: in the platform's secure
/// storage beside the key -- on iOS in the Keychain, on this device only,
/// readable after the first unlock.
library;

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:uuid/uuid.dart';

import 'installation_key.dart';

class InstallationStore {
  InstallationStore({NativeInstallationKey? key, FlutterSecureStorage? storage})
    : key = key ?? NativeInstallationKey(),
      _storage = storage ?? const FlutterSecureStorage();

  static const String _installationIdKey = 'recognition.installation_id.v2';
  static const String _stepUpReenrolKey =
      'recognition.stepup_reenrol_pending.v1';

  static const IOSOptions _iosOptions = IOSOptions(
    accessibility: KeychainAccessibility.first_unlock_this_device,
    synchronizable: false,
  );

  final NativeInstallationKey key;
  final FlutterSecureStorage _storage;

  /// The installation: its key, made on first use, and its ID. A key made
  /// now ([InstallationIdentity.createdThisLaunch]) is a new installation, so
  /// it gets a new ID even where one was stored: that ID belongs to the key
  /// that was lost, and a backend refuses a known ID under another key.
  Future<InstallationIdentity> loadOrCreate() async {
    final String? stored = await _storage.read(
      key: _installationIdKey,
      iOptions: _iosOptions,
    );
    final NativeKeyMetadata metadata = await key.getOrCreateKey();
    String installationId = stored ?? '';
    if (installationId.isEmpty || metadata.created) {
      installationId = const Uuid().v4();
      await saveInstallationId(installationId);
    }
    return InstallationIdentity(
      installationId: installationId,
      nativeKey: key,
      metadata: metadata,
    );
  }

  /// Keeps the installation your backend answered for this key, which may
  /// not be the ID proposed. Only this opaque ID is stored here; the private
  /// key never leaves the platform's keystore.
  Future<void> saveInstallationId(String installationId) {
    return _storage.write(
      key: _installationIdKey,
      value: installationId,
      iOptions: _iosOptions,
    );
  }

  /// Whether a step-up key was replaced and the backend has not yet taken
  /// the new one (DeviceTrust.reenrolStepUp) -- kept across restarts.
  Future<bool> stepUpReenrolPending() async =>
      await _storage.read(key: _stepUpReenrolKey, iOptions: _iosOptions) !=
      null;

  Future<void> setStepUpReenrolPending(bool pending) => pending
      ? _storage.write(
          key: _stepUpReenrolKey,
          value: '1',
          iOptions: _iosOptions,
        )
      : _storage.delete(key: _stepUpReenrolKey, iOptions: _iosOptions);

  /// Deletes the key and the installation ID: the next start is a new
  /// installation.
  Future<void> clear() async {
    await key.deleteKey();
    await _storage.delete(key: _installationIdKey, iOptions: _iosOptions);
    await _storage.delete(key: _stepUpReenrolKey, iOptions: _iosOptions);
  }
}
