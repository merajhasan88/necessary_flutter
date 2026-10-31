package com.meraj.necessary

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class InstallationKeyFailure(
    val errorCode: String,
    override val message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * Owns one non-exportable P-256 signing key in AndroidKeyStore.
 *
 * The private key object is only a handle. Android performs signing through the
 * keystore provider, and this class returns only the public EC coordinates and
 * DER-encoded ECDSA signatures to Flutter.
 */
class InstallationKeyManager(private val context: Context) {
    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val CURVE_NAME = "secp256r1"
        private const val CHANNEL_KEY_VERSION = 2
        private const val MAX_PAYLOAD_BYTES = 65536

        // Making and deleting the key run one at a time in the process,
        // whichever engine asks: two first starts at once would otherwise each
        // find no key, and the second would generate over the first's.
        private val keyLock = Any()
    }

    private val keyAlias: String =
        "${context.packageName}.device_recognition.installation_key.v2"

    // Never holds a key: deleting it says whether the keystore answers
    // (KeyPresence).
    private val probeAlias: String = "$keyAlias.probe"

    fun getOrCreateKey(): Map<String, Any> = synchronized(keyLock) { loadOrMakeKey() }

    private fun loadOrMakeKey(): Map<String, Any> {
        requireSupportedAndroid()
        val keyStore = loadKeyStore()
        var created = false

        // A key is made only where the keystore, answering, holds none: a
        // lookup that failed reads as "no key", and generating would replace
        // the installation's key with a new one.
        val found = presence(keyStore)
        when (found.answer) {
            KeyPresence.Answer.PRESENT -> {}
            KeyPresence.Answer.ABSENT -> {
                generateKeyPair(keyStore)
                created = true
            }
            KeyPresence.Answer.UNAVAILABLE -> throw keyUnavailable(found.cause)
        }

        var entry = privateKeyEntry(keyStore)
        if (!isExpectedP256Key(entry)) {
            // An interrupted development build may have left a different key
            // under the alias. Replace it and tell Dart that a new key exists so
            // Dart also rotates the installation UUID.
            keyStore.deleteEntry(keyAlias)
            generateKeyPair(keyStore)
            created = true
            entry = privateKeyEntry(keyStore)
        }

        val publicKey = entry.certificate.publicKey as? ECPublicKey
            ?: throw InstallationKeyFailure(
                "INVALID_PUBLIC_KEY",
                "AndroidKeyStore did not return an EC public key.",
            )
        val x = unsignedFixed(publicKey.w.affineX, 32)
        val y = unsignedFixed(publicKey.w.affineY, 32)
        val security = describeSecurity(entry)

        return mapOf(
            "version" to CHANNEL_KEY_VERSION,
            "key_alias" to keyAlias,
            "algorithm" to "ES256",
            "signature_format" to "asn1_der",
            "provider" to ANDROID_KEY_STORE,
            "security_level" to security.first,
            "hardware_backed" to security.second,
            "private_key_exportable" to false,
            "created" to created,
            "public_key" to mapOf(
                "kty" to "EC",
                "crv" to "P-256",
                "alg" to "ES256",
                "x" to base64Url(x),
                "y" to base64Url(y),
            ),
        )
    }

    fun signPayload(payloadBase64Url: String): String {
        requireSupportedAndroid()
        val payload = decodeBase64Url(payloadBase64Url)
        if (payload.size > MAX_PAYLOAD_BYTES) {
            throw InstallationKeyFailure(
                "PAYLOAD_TOO_LARGE",
                "The challenge payload is larger than $MAX_PAYLOAD_BYTES bytes.",
            )
        }

        val keyStore = loadKeyStore()
        val found = presence(keyStore)
        when (found.answer) {
            KeyPresence.Answer.PRESENT -> {}
            KeyPresence.Answer.ABSENT -> throw InstallationKeyFailure(
                "KEY_NOT_FOUND",
                "The Android installation key is missing. Restart the app to create a fresh installation identity.",
            )
            KeyPresence.Answer.UNAVAILABLE -> throw keyUnavailable(found.cause)
        }
        val entry = privateKeyEntry(keyStore)

        try {
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(entry.privateKey)
            signer.update(payload)
            // The JCA SHA256withECDSA signature format is ASN.1 DER.
            return base64Url(signer.sign())
        } catch (error: GeneralSecurityException) {
            throw InstallationKeyFailure(
                "SIGNING_FAILED",
                "AndroidKeyStore could not sign the installation challenge.",
                error,
            )
        }
    }

    /**
     * Deletes the key, whatever a lookup says: a lookup that failed reads as
     * "no key", and skipping the deletion then would leave the key in place
     * after a reset. Whether one was there is for the answer only.
     */
    fun deleteKey(): Boolean = synchronized(keyLock) {
        requireSupportedAndroid()
        val keyStore = loadKeyStore()
        try {
            val existed = keyStore.containsAlias(keyAlias)
            keyStore.deleteEntry(keyAlias)
            if (keyStore.containsAlias(keyAlias)) {
                throw InstallationKeyFailure(
                    "KEY_DELETE_FAILED",
                    "AndroidKeyStore did not delete the installation key: it is still present.",
                )
            }
            existed
        } catch (error: GeneralSecurityException) {
            throw InstallationKeyFailure(
                "KEY_DELETE_FAILED",
                "AndroidKeyStore could not delete the installation key.",
                error,
            )
        }
    }

    private fun presence(keyStore: KeyStore): KeyPresence.Found =
        KeyPresence.of(object : KeyPresence.Keystore {
            override fun containsKey() = keyStore.containsAlias(keyAlias)
            override fun deleteProbe() = keyStore.deleteEntry(probeAlias)
        })

    private fun keyUnavailable(cause: Throwable?) = InstallationKeyFailure(
        "KEY_UNAVAILABLE",
        "AndroidKeyStore could not be reached for the installation key" +
            (cause?.let { " (${it.javaClass.simpleName}: ${it.message})" } ?: "") +
            "; the key was kept, never replaced. Try again; if this persists, reset() starts a new installation.",
        cause,
    )

    private fun requireSupportedAndroid() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            throw InstallationKeyFailure(
                "UNSUPPORTED_ANDROID_VERSION",
                "This prototype requires Android 6.0 (API 23) or newer.",
            )
        }
    }

    private fun loadKeyStore(): KeyStore {
        try {
            return KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        } catch (error: GeneralSecurityException) {
            throw InstallationKeyFailure(
                "KEYSTORE_UNAVAILABLE",
                "AndroidKeyStore is unavailable.",
                error,
            )
        }
    }

    private fun generateKeyPair(keyStore: KeyStore) {
        val canTryStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE,
            )

        if (canTryStrongBox) {
            try {
                generateKeyPair(preferStrongBox = true)
                return
            } catch (error: Exception) {
                // Some devices advertise StrongBox but cannot satisfy a
                // particular algorithm/digest combination. Remove any partial
                // alias and retry with the regular AndroidKeyStore provider.
                try {
                    if (keyStore.containsAlias(keyAlias)) {
                        keyStore.deleteEntry(keyAlias)
                    }
                } catch (_: Exception) {
                    // The normal generation attempt below will produce the
                    // actionable error if the keystore is genuinely unusable.
                }
            }
        }

        generateKeyPair(preferStrongBox = false)
    }

    private fun generateKeyPair(preferStrongBox: Boolean) {
        try {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEY_STORE,
            )
            val builder = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_SIGN,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE_NAME))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && preferStrongBox) {
                builder.setIsStrongBoxBacked(true)
            }

            generator.initialize(builder.build())
            generator.generateKeyPair()
        } catch (error: GeneralSecurityException) {
            throw InstallationKeyFailure(
                "KEY_GENERATION_FAILED",
                if (preferStrongBox) {
                    "StrongBox could not create the P-256 installation key."
                } else {
                    "AndroidKeyStore could not create the P-256 installation key."
                },
                error,
            )
        } catch (error: ProviderException) {
            throw InstallationKeyFailure(
                "KEY_GENERATION_FAILED",
                if (preferStrongBox) {
                    "StrongBox could not create the P-256 installation key."
                } else {
                    "AndroidKeyStore could not create the P-256 installation key."
                },
                error,
            )
        }
    }

    private fun privateKeyEntry(keyStore: KeyStore): KeyStore.PrivateKeyEntry {
        try {
            // getEntry answers null when its own lookup fails (the keystore
            // just reported the key), and an UnsupportedOperationException
            // when the alias holds no key entry -- on Android 7 to 11 also when
            // that lookup fails: both may pass, so the key is kept.
            val entry = keyStore.getEntry(keyAlias, null)
                ?: throw keyUnavailable(null)
            return entry as? KeyStore.PrivateKeyEntry
                ?: throw InstallationKeyFailure(
                    "KEY_NOT_FOUND",
                    "The Android installation key entry has the wrong type.",
                )
        } catch (error: UnsupportedOperationException) {
            throw keyUnavailable(error)
        } catch (error: GeneralSecurityException) {
            throw InstallationKeyFailure(
                "KEY_LOOKUP_FAILED",
                "AndroidKeyStore could not load the installation key.",
                error,
            )
        }
    }

    private fun isExpectedP256Key(entry: KeyStore.PrivateKeyEntry): Boolean {
        val publicKey = entry.certificate.publicKey as? ECPublicKey ?: return false
        return publicKey.params.curve.field.fieldSize == 256
    }

    private fun describeSecurity(
        entry: KeyStore.PrivateKeyEntry,
    ): Pair<String, Boolean> {
        return try {
            val keyFactory = KeyFactory.getInstance(
                entry.privateKey.algorithm,
                ANDROID_KEY_STORE,
            )
            val keyInfo = keyFactory.getKeySpec(entry.privateKey, KeyInfo::class.java)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox" to true
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                        "trusted_execution_environment" to true
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software" to false
                    else -> "unknown" to false
                }
            } else {
                if (keyInfo.isInsideSecureHardware) {
                    "secure_hardware" to true
                } else {
                    "software" to false
                }
            }
        } catch (_: Exception) {
            "unknown" to false
        }
    }

    private fun unsignedFixed(value: BigInteger, size: Int): ByteArray {
        var raw = value.toByteArray()
        if (raw.size == size + 1 && raw[0] == 0.toByte()) {
            raw = raw.copyOfRange(1, raw.size)
        }
        if (raw.size > size) {
            throw InstallationKeyFailure(
                "INVALID_PUBLIC_KEY",
                "The EC coordinate is larger than P-256 permits.",
            )
        }
        return ByteArray(size).also { output ->
            System.arraycopy(raw, 0, output, size - raw.size, raw.size)
        }
    }

    private fun base64Url(value: ByteArray): String {
        return Base64.encodeToString(
            value,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
    }

    private fun decodeBase64Url(value: String): ByteArray {
        if (value.isBlank()) {
            throw InstallationKeyFailure(
                "INVALID_PAYLOAD",
                "The challenge payload is empty.",
            )
        }
        return try {
            Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        } catch (error: IllegalArgumentException) {
            throw InstallationKeyFailure(
                "INVALID_PAYLOAD",
                "The challenge payload is not valid base64url.",
                error,
            )
        }
    }
}
