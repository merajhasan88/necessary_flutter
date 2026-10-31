package com.meraj.necessary

/**
 * Whether a key is in AndroidKeyStore, when its absence matters: a key is
 * made only where there is none, and generating one replaces whatever the
 * alias holds.
 *
 * `KeyStore.containsAlias` cannot say "absent" on its own. It answers false
 * also when the keystore cannot be reached: on Android 7 to 11
 * `android.security.KeyStore.contains` returns false on a binder failure, and
 * on Android 12 and later `AndroidKeyStoreSpi.getKeyMetadata` returns null on
 * every keystore error, a lost connection included. Deleting an alias that
 * never holds a key does say whether the keystore answered: one that answers
 * reports it not found, which `deleteEntry` takes as done, while one that
 * cannot be reached makes `deleteEntry` throw (`KeyStore.delete` returns false
 * and `engineDeleteEntry` throws on 7 to 11; keystore2's `deleteKey` throws
 * `SYSTEM_ERROR` on 12 and later). So a "no" is believed only when the
 * keystore answered the probe and then said "no" again.
 *
 * The limit: two outages, one over each lookup and neither over the probe
 * between them, still read as absent. A pure decision, so a JVM test holds it.
 */
internal object KeyPresence {
    /** The two keystore calls the answer rests on. */
    interface Keystore {
        /** `containsAlias` for the key: false also when the keystore could not be reached. */
        fun containsKey(): Boolean

        /**
         * `deleteEntry` of an alias that never holds a key: returns when the
         * keystore answered, throws when it could not be reached.
         */
        fun deleteProbe()
    }

    enum class Answer {
        /** The keystore holds the key. */
        PRESENT,

        /** The keystore answered, and holds no key: one may be made. */
        ABSENT,

        /** The keystore could not be reached: no key may be made over one it may hold. */
        UNAVAILABLE,
    }

    class Found(val answer: Answer, val cause: Exception? = null)

    fun of(keystore: Keystore): Found {
        if (keystore.containsKey()) {
            return Found(Answer.PRESENT)
        }
        try {
            keystore.deleteProbe()
        } catch (error: Exception) {
            return Found(Answer.UNAVAILABLE, error)
        }
        // The keystore answers now: its "no" may have been an outage that has
        // passed, so it is asked again.
        return Found(if (keystore.containsKey()) Answer.PRESENT else Answer.ABSENT)
    }
}
