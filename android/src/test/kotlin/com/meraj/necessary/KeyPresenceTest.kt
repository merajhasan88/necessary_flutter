package com.meraj.necessary

import com.meraj.necessary.KeyPresence.Answer
import java.security.KeyStoreException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * A key is made only where the keystore, answering, holds none: a lookup that
 * failed never replaces the key (the release review of 2026-10-31's
 * acceptance: "transient binder/keymaster error followed by recovery
 * preserves the same public key").
 */
class KeyPresenceTest {
    /** AndroidKeyStore as KeyPresence sees it, with an outage over chosen calls. */
    private class Keystore(var key: String?) : KeyPresence.Keystore {
        /** The calls, counted from 1, that the keystore cannot answer. */
        var outage: Set<Int> = emptySet()
        var calls = 0
        private var made = 0

        override fun containsKey(): Boolean {
            calls += 1
            return calls !in outage && key != null
        }

        override fun deleteProbe() {
            calls += 1
            if (calls in outage) {
                throw KeyStoreException("Failed to delete entry")
            }
        }

        /** What a key manager does with the answer: load, make, or refuse. */
        fun start(): String {
            calls = 0
            return when (KeyPresence.of(this).answer) {
                Answer.PRESENT -> key!!
                Answer.ABSENT -> "made-${++made}".also { key = it }
                Answer.UNAVAILABLE -> throw IllegalStateException("KEY_UNAVAILABLE")
            }
        }
    }

    @Test
    fun aKeyTheKeystoreReportsIsPresentAndNothingElseIsAsked() {
        val keystore = Keystore("held")
        assertEquals(Answer.PRESENT, KeyPresence.of(keystore).answer)
        assertEquals(1, keystore.calls)
    }

    @Test
    fun noKeyWithTheKeystoreAnsweringIsAbsent() {
        val found = KeyPresence.of(Keystore(null))
        assertEquals(Answer.ABSENT, found.answer)
        assertNull(found.cause)
    }

    @Test
    fun anOutageOverTheLookupAndTheProbeIsUnavailableWithItsCause() {
        val keystore = Keystore("held").apply { outage = setOf(1, 2) }
        val found = KeyPresence.of(keystore)
        assertEquals(Answer.UNAVAILABLE, found.answer)
        assertTrue(found.cause is KeyStoreException)
    }

    @Test
    fun aProbeThatFailsAnyOtherWayIsUnavailableToo() {
        // A keystore with no service behind it fails with a NullPointerException.
        val keystore = object : KeyPresence.Keystore {
            override fun containsKey() = false
            override fun deleteProbe() = throw NullPointerException("no keystore service")
        }
        assertEquals(Answer.UNAVAILABLE, KeyPresence.of(keystore).answer)
    }

    @Test
    fun aLookupThatFailedOnceIsAskedAgainOnceTheKeystoreAnswers() {
        val keystore = Keystore("held").apply { outage = setOf(1) }
        assertEquals(Answer.PRESENT, KeyPresence.of(keystore).answer)
    }

    @Test
    fun anOutageAtStartThenRecoveryKeepsTheSameKey() {
        val keystore = Keystore("registered").apply { outage = setOf(1, 2) }
        try {
            keystore.start()
            fail("a start during the outage made or loaded a key")
        } catch (refused: IllegalStateException) {
            assertEquals("KEY_UNAVAILABLE", refused.message)
        }
        assertEquals("registered", keystore.key)
        keystore.outage = emptySet()
        assertEquals("registered", keystore.start())
    }

    @Test
    fun theFirstStartMakesTheKeyAndTheNextFindsIt() {
        val keystore = Keystore(null)
        val made = keystore.start()
        assertEquals(made, keystore.start())
    }

    @Test
    fun theLimitTwoOutagesAroundAnAnsweredProbeReadAsAbsent() {
        // Stated, not hidden: one outage over each lookup, none over the probe.
        val keystore = Keystore("held").apply { outage = setOf(1, 3) }
        assertEquals(Answer.ABSENT, KeyPresence.of(keystore).answer)
    }
}
