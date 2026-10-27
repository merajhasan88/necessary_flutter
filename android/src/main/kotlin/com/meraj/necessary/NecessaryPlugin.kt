package com.meraj.necessary

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.WindowManager
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.PluginRegistry
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * The plugin's entry point on Android: the installation key, the step-up key,
 * the integrity collector and screen protection, each on its method channel.
 * Blocking work runs on one worker thread; the step-up prompt, the location
 * prompt and the window are the current activity's, on the main thread.
 */
class NecessaryPlugin :
    FlutterPlugin,
    ActivityAware,
    PluginRegistry.ActivityResultListener,
    PluginRegistry.RequestPermissionsResultListener {

    companion object {
        private const val KEY_CHANNEL = "necessary/installation_key_v2"
        private const val INTEGRITY_CHANNEL = "necessary/integrity_v1"
        private const val STEPUP_CHANNEL = "necessary/stepup_key_v1"
        private const val SECURE_SCREEN_CHANNEL = "necessary/secure_screen_v1"
        private const val LOCATION_REQUEST = 4721
    }

    private var channels: List<MethodChannel> = emptyList()
    private var worker: ExecutorService? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var context: Context
    private lateinit var installationKeys: InstallationKeyManager
    private lateinit var integrityProbes: IntegrityProbeManager
    private lateinit var stepUpKeys: StepUpKeyManager
    private var activityBinding: ActivityPluginBinding? = null
    private val screenGuard = ScreenGuard()
    // The app's own request for the location permission, answered when the
    // person chooses; the collector itself never asks.
    private var pendingLocationResult: MethodChannel.Result? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        worker = Executors.newSingleThreadExecutor()
        installationKeys = InstallationKeyManager(context)
        integrityProbes = IntegrityProbeManager(context) { activityBinding?.activity }
        stepUpKeys = StepUpKeyManager(context)
        val messenger = binding.binaryMessenger
        channels = listOf(
            MethodChannel(messenger, KEY_CHANNEL).apply { setMethodCallHandler(::onKeyCall) },
            MethodChannel(messenger, INTEGRITY_CHANNEL).apply { setMethodCallHandler(::onIntegrityCall) },
            MethodChannel(messenger, STEPUP_CHANNEL).apply { setMethodCallHandler(::onStepUpCall) },
            MethodChannel(messenger, SECURE_SCREEN_CHANNEL).apply { setMethodCallHandler(::onSecureScreenCall) },
        )
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channels.forEach { it.setMethodCallHandler(null) }
        channels = emptyList()
        worker?.shutdown()
        worker = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
        binding.addActivityResultListener(this)
        binding.addRequestPermissionsResultListener(this)
        // A window recreated while the screen is protected is protected too.
        screenGuard.reattach(windowState(binding.activity))?.let { applyScreen(binding.activity, it) }
    }

    override fun onDetachedFromActivityForConfigChanges() = onDetachedFromActivity()

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) =
        onAttachedToActivity(binding)

    override fun onDetachedFromActivity() {
        activityBinding?.removeActivityResultListener(this)
        activityBinding?.removeRequestPermissionsResultListener(this)
        activityBinding = null
    }

    // Delivers the confirm-credential result the step-up key uses on API < 30.
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean =
        ::stepUpKeys.isInitialized && stepUpKeys.onActivityResult(requestCode, resultCode)

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<String>,
        grantResults: IntArray,
    ): Boolean {
        if (requestCode != LOCATION_REQUEST) return false
        pendingLocationResult?.success(locationState())
        pendingLocationResult = null
        return true
    }

    private fun onKeyCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "getOrCreateKey" -> runOffMainThread(result) { installationKeys.getOrCreateKey() }
            "sign" -> runOffMainThread(result) {
                installationKeys.signPayload(requiredString(call, "payload"))
            }
            "deleteKey" -> runOffMainThread(result) { installationKeys.deleteKey() }
            // The reinstall hint's source, ANDROID_ID: scoped to the phone, the
            // user and the app's signing key. The Dart side hashes it before
            // it leaves the phone; empty when the platform gives none.
            "reinstallHintIdentifier" -> runOffMainThread(result) {
                Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: ""
            }
            else -> result.notImplemented()
        }
    }

    private fun onIntegrityCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "collect" -> runOffMainThread(result) {
                val nonce = requiredString(call, "challenge_nonce")
                val required = call.argument<List<String>>("required_probes")
                    ?: throw InstallationKeyFailure(
                        "INVALID_ARGUMENT",
                        "required_probes must be a list of strings.",
                    )
                // Absent from an older Dart client: then nothing optional is
                // collected.
                val optional = call.argument<List<String>>("optional_probes") ?: emptyList()
                val enabled = call.argument<List<String>>("enabled_measurements")?.toSet() ?: emptySet()
                integrityProbes.collect(required, nonce, optional, enabled)
            }
            // For the location and mock_location measurements: asks the person
            // once, from a button on the app's own screen.
            "requestLocationPermission" -> requestLocationPermission(result)
            else -> result.notImplemented()
        }
    }

    private fun onStepUpCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "getOrCreateKey" -> runOffMainThread(result) {
                stepUpKeys.getOrCreateKey(
                    requiredString(call, "factor"),
                    requiredString(call, "mode"),
                    call.argument<Int>("window_seconds") ?: 0,
                )
            }
            // Stays on the main thread: it shows the system prompt, and the
            // keystore signs inside the prompt's callback.
            "sign" -> {
                val activity = activityBinding?.activity
                    ?: return result.error("NO_ACTIVITY", "The step-up prompt needs a visible activity.", null)
                try {
                    stepUpKeys.sign(
                        activity,
                        requiredString(call, "payload"),
                        call.argument<String>("reason") ?: "Approve this operation",
                        call.argument<String>("mode") ?: StepUpKeyManager.MODE_PER_USE,
                    ) { outcome ->
                        outcome.fold(
                            { signature -> result.success(signature) },
                            { error ->
                                val failure = error as? InstallationKeyFailure
                                result.error(
                                    failure?.errorCode ?: "NATIVE_STEPUP_ERROR",
                                    error.message ?: "The step-up signature failed.",
                                    null,
                                )
                            },
                        )
                    }
                } catch (error: InstallationKeyFailure) {
                    result.error(error.errorCode, error.message, null)
                }
            }
            "deleteKey" -> runOffMainThread(result) { stepUpKeys.deleteKey() }
            else -> result.notImplemented()
        }
    }

    private fun onSecureScreenCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            // On the main thread: it changes the window.
            "protect" -> {
                val activity = activityBinding?.activity
                if (call.argument<Boolean>("on") == true) {
                    if (activity == null) {
                        return result.error("NO_ACTIVITY", "Screen protection needs a visible activity.", null)
                    }
                    screenGuard.acquire(windowState(activity))?.let { applyScreen(activity, it) }
                } else {
                    // Counted even without a window, so a release is never lost.
                    val change = screenGuard.release()
                    if (activity != null && change != null) applyScreen(activity, change)
                }
                result.success(screenState(activity))
            }
            else -> result.notImplemented()
        }
    }

    private fun locationState(): String = when {
        context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED -> "precise"
        context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED -> "approximate"
        else -> "none"
    }

    private fun requestLocationPermission(result: MethodChannel.Result) {
        val activity = activityBinding?.activity
        if (locationState() == "precise" || pendingLocationResult != null || activity == null) {
            result.success(locationState())
            return
        }
        pendingLocationResult = result
        activity.requestPermissions(
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION),
            LOCATION_REQUEST,
        )
    }

    /**
     * While a secret is typed: the window cannot be captured in screenshots,
     * recordings or casts (FLAG_SECURE); other apps' windows are not drawn
     * over it (Android 12 and later, HIDE_OVERLAY_WINDOWS, a normal
     * permission); and a touch that passed through another app's window is
     * dropped. ScreenGuard decides when, and what the window gets back. The
     * phone's own screen-lock prompt is the system's window and needs none of
     * this from the app.
     */
    private fun applyScreen(activity: Activity, change: ScreenGuard.Change) {
        val window = activity.window
        if (change.secure) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        if (overlaysHideable()) window.setHideOverlayWindows(change.hideOverlays)
        window.decorView.filterTouchesWhenObscured = change.dropsObscuredTouches
    }

    private fun overlaysHideable(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            context.checkSelfPermission("android.permission.HIDE_OVERLAY_WINDOWS") ==
            PackageManager.PERMISSION_GRANTED

    private fun windowState(activity: Activity) = ScreenGuard.WindowState(
        secure = (activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0,
        dropsObscuredTouches = activity.window.decorView.filterTouchesWhenObscured,
    )

    /** What the window has now, and whether the plugin holds it. */
    private fun screenState(activity: Activity?): Map<String, Any> = mapOf(
        "held" to screenGuard.held,
        "secure" to (activity?.let { windowState(it).secure } ?: false),
        "overlays_hidden" to (screenGuard.held && overlaysHideable()),
        "obscured_touches_dropped" to (activity?.let { windowState(it).dropsObscuredTouches } ?: false),
    )

    private fun requiredString(call: MethodCall, field: String): String =
        call.argument<String>(field)
            ?: throw InstallationKeyFailure("INVALID_ARGUMENT", "$field must be a string.")

    private fun runOffMainThread(result: MethodChannel.Result, operation: () -> Any) {
        val executor = worker
            ?: return result.error("DETACHED", "The plugin is detached from its engine.", null)
        executor.execute {
            try {
                val value = operation()
                mainHandler.post { result.success(value) }
            } catch (error: InstallationKeyFailure) {
                mainHandler.post { result.error(error.errorCode, error.message, null) }
            } catch (error: Throwable) {
                // Name the exception and its cause: a release build's log output
                // is suppressed on some phones, so the message shown in the app
                // is the only diagnostic there is.
                val detail = buildString {
                    append("The Android native operation failed: ")
                    append(error.javaClass.name)
                    error.message?.let { append(": ").append(it) }
                    error.cause?.let { cause ->
                        append(" (cause ").append(cause.javaClass.name)
                        cause.message?.let { append(": ").append(it) }
                        append(")")
                    }
                    append(" at ")
                    append(error.stackTrace.take(6).joinToString(" < ") {
                        "${it.className.substringAfterLast('.')}.${it.methodName}:${it.lineNumber}"
                    })
                }
                mainHandler.post { result.error("NATIVE_INTEGRITY_ERROR", detail, null) }
            }
        }
    }
}
