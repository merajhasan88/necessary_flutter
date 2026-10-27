import CoreLocation
import Flutter
import UIKit

/// The plugin's entry point on iOS: the installation key, the step-up key, the
/// integrity collector and screen protection, each on its method channel.
/// Keychain, Secure Enclave and collection work runs off the platform thread;
/// every result is delivered back on the main thread.
public class NecessaryPlugin: NSObject, FlutterPlugin, CLLocationManagerDelegate {
    /// The same names on both platforms: the Dart side is platform-agnostic.
    private static let keyChannelName = "necessary/installation_key_v2"
    private static let integrityChannelName = "necessary/integrity_v1"
    private static let stepUpChannelName = "necessary/stepup_key_v1"
    private static let secureScreenChannelName = "necessary/secure_screen_v1"

    private let installationKeys: InstallationKeyManager
    private let stepUpKeys: StepUpKeyManager
    private let integrityProbes = IntegrityProbeManager()
    /// The app's own request for the location permission,
    /// answered when the person chooses; a scan never asks.
    private var locationManager: CLLocationManager?
    private var pendingLocationResult: FlutterResult?
    /// While the app PIN is typed: iOS lets no app block
    /// screenshots, so the window is covered whenever the screen is recorded,
    /// mirrored or sent to AirPlay.
    private var screenProtected = false
    /// Callers holding the protection: it lasts until the last one is done.
    private var screenHolders = 0
    private var captureCover: UIView?
    private let worker = DispatchQueue(label: "necessary.native", qos: .userInitiated)

    init(bundleIdentifier: String) {
        installationKeys = InstallationKeyManager(bundleIdentifier: bundleIdentifier)
        stepUpKeys = StepUpKeyManager(bundleIdentifier: bundleIdentifier)
        super.init()
    }

    public static func register(with registrar: FlutterPluginRegistrar) {
        // The keys' aliases are built from the host app's bundle identifier.
        let plugin = NecessaryPlugin(bundleIdentifier: Bundle.main.bundleIdentifier ?? "necessary")
        let messenger = registrar.messenger()
        let handlers: [(String, (FlutterMethodCall, @escaping FlutterResult) -> Void)] = [
            (keyChannelName, plugin.onKeyCall),
            (integrityChannelName, plugin.onIntegrityCall),
            (stepUpChannelName, plugin.onStepUpCall),
            (secureScreenChannelName, plugin.onSecureScreenCall),
        ]
        for (name, handler) in handlers {
            // Each handler holds the plugin, which lives as long as the engine.
            FlutterMethodChannel(name: name, binaryMessenger: messenger).setMethodCallHandler(handler)
        }
    }

    private func onKeyCall(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let manager = installationKeys
        switch call.method {
        case "getOrCreateKey":
            runOffPlatformThread(result) { try manager.getOrCreateKey() }
        case "sign":
            guard let payload = (call.arguments as? [String: Any])?["payload"] as? String else {
                result(FlutterError(code: "INVALID_ARGUMENT",
                                    message: "payload must be a base64url string.", details: nil))
                return
            }
            runOffPlatformThread(result) { try manager.signPayload(payload) }
        case "deleteKey":
            runOffPlatformThread(result) { try manager.deleteKey() }
        case "reinstallHintIdentifier":
            // The reinstall hint's source, the identifier for vendor: the
            // same for every app of this vendor on the phone. The Dart side
            // hashes it before it leaves the phone.
            result(UIDevice.current.identifierForVendor?.uuidString ?? "")
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func onIntegrityCall(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let collector = integrityProbes
        switch call.method {
        case "collect":
            guard
                let arguments = call.arguments as? [String: Any],
                let nonce = arguments["challenge_nonce"] as? String,
                let required = arguments["required_probes"] as? [String]
            else {
                result(FlutterError(
                    code: "INVALID_ARGUMENT",
                    message: "challenge_nonce must be a string and required_probes a list of strings.",
                    details: nil))
                return
            }
            // Absent from an older Dart client: then nothing optional is
            // collected.
            let optional = arguments["optional_probes"] as? [String] ?? []
            let enabled = Set(arguments["enabled_measurements"] as? [String] ?? [])
            runOffPlatformThread(result) {
                collector.collect(requiredProbes: required, challengeNonce: nonce,
                                  optionalProbes: optional, enabledMeasurements: enabled)
            }
        case "requestLocationPermission":
            requestLocationPermission(result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func onStepUpCall(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let manager = stepUpKeys
        let arguments = call.arguments as? [String: Any] ?? [:]
        switch call.method {
        case "getOrCreateKey":
            guard let factor = arguments["factor"] as? String else {
                result(FlutterError(code: "INVALID_ARGUMENT", message: "factor must be a string.",
                                    details: nil))
                return
            }
            runOffPlatformThread(result) { try manager.getOrCreateKey(factor: factor) }
        case "sign":
            guard let payload = arguments["payload"] as? String else {
                result(FlutterError(code: "INVALID_ARGUMENT",
                                    message: "payload must be a base64url string.", details: nil))
                return
            }
            let reason = arguments["reason"] as? String ?? "Approve this operation"
            // Off the platform thread: the call blocks while the system prompt is up.
            runOffPlatformThread(result) { try manager.signPayload(payload, reason: reason) }
        case "deleteKey":
            runOffPlatformThread(result) { try manager.deleteKey() }
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func onSecureScreenCall(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        switch call.method {
        case "protect":
            let on = (call.arguments as? [String: Any])?["on"] as? Bool ?? false
            if on {
                screenHolders += 1
            } else if screenHolders > 0 {
                screenHolders -= 1
            }
            setScreenProtection(screenHolders > 0)
            result(["held": screenHolders > 0, "secure": false,
                    "covered_while_captured": screenHolders > 0])
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func setScreenProtection(_ on: Bool) {
        screenProtected = on
        NotificationCenter.default.removeObserver(
            self, name: UIScreen.capturedDidChangeNotification, object: nil)
        if on {
            NotificationCenter.default.addObserver(
                self, selector: #selector(screenCaptureChanged),
                name: UIScreen.capturedDidChangeNotification, object: nil)
        }
        updateCaptureCover()
    }

    @objc private func screenCaptureChanged() {
        updateCaptureCover()
    }

    private func updateCaptureCover() {
        let cover = screenProtected && UIScreen.main.isCaptured
        if !cover {
            captureCover?.removeFromSuperview()
            captureCover = nil
            return
        }
        guard captureCover == nil, let window = activeWindow() else { return }
        let view = UIView(frame: window.bounds)
        view.backgroundColor = .black
        view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        window.addSubview(view)
        captureCover = view
    }

    private func activeWindow() -> UIWindow? {
        return UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
    }

    private func locationState(_ manager: CLLocationManager) -> String {
        switch manager.authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways:
            return manager.accuracyAuthorization == .reducedAccuracy ? "approximate" : "precise"
        case .notDetermined:
            return "undetermined"
        default:
            return "none"
        }
    }

    private func requestLocationPermission(_ result: @escaping FlutterResult) {
        let manager = locationManager ?? CLLocationManager()
        locationManager = manager
        let state = locationState(manager)
        guard state == "undetermined", pendingLocationResult == nil else {
            result(state == "undetermined" ? "none" : state)
            return
        }
        pendingLocationResult = result
        manager.delegate = self
        manager.requestWhenInUseAuthorization()
    }

    public func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let state = locationState(manager)
        guard state != "undetermined", let pending = pendingLocationResult else { return }
        pendingLocationResult = nil
        pending(state)
    }

    private func runOffPlatformThread(_ result: @escaping FlutterResult,
                                      _ operation: @escaping () throws -> Any) {
        worker.async {
            do {
                let value = try operation()
                DispatchQueue.main.async { result(value) }
            } catch let failure as InstallationKeyFailure {
                DispatchQueue.main.async {
                    result(FlutterError(code: failure.code, message: failure.message, details: nil))
                }
            } catch {
                DispatchQueue.main.async {
                    result(FlutterError(code: "NATIVE_KEY_ERROR", message: error.localizedDescription,
                                        details: nil))
                }
            }
        }
    }
}
