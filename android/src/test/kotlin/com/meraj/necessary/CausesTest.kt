package com.meraj.necessary

import java.security.KeyStoreException
import java.security.UnrecoverableKeyException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every failure the plugin reports says what failed beneath it (the release
 * review of 2026-10-31, item 4: "preserve the original cause chain and
 * available error codes").
 */
class CausesTest {
    /** Android 9's failed key lookup: the keystore's answer is only in the cause. */
    private fun android9Lookup(): UnrecoverableKeyException =
        UnrecoverableKeyException("Failed to obtain information about key").apply {
            initCause(KeyStoreException("Key blob corrupted"))
        }

    @Test
    fun noFailureSaysNothing() {
        assertEquals("", Causes.chain(null))
        assertEquals("the message", Causes.withCauses("the message", null))
    }

    @Test
    fun theKeystoresAnswerBeneathAFailedLookupIsSaid() {
        assertEquals(
            "UnrecoverableKeyException: Failed to obtain information about key < KeyStoreException: Key blob corrupted",
            Causes.chain(android9Lookup()),
        )
    }

    @Test
    fun everyCauseIsSaidOutermostFirst() {
        val failure = IllegalStateException("outer", RuntimeException("middle", IllegalArgumentException("inner")))
        assertEquals(
            "IllegalStateException: outer < RuntimeException: middle < IllegalArgumentException: inner",
            Causes.chain(failure),
        )
    }

    @Test
    fun aFailureWithoutWordsIsNamedByItsKind() {
        assertEquals("UnsupportedOperationException", Causes.chain(UnsupportedOperationException()))
    }

    @Test
    fun theDetailAddsTheKeystoresCode() {
        val chain = Causes.chain(android9Lookup()) { error ->
            if (error is KeyStoreException) "code -33" else null
        }
        assertEquals(
            "UnrecoverableKeyException: Failed to obtain information about key < " +
                "KeyStoreException: Key blob corrupted (code -33)",
            chain,
        )
    }

    @Test
    fun aCauseThatLoopsIsSaidOnce() {
        val first = RuntimeException("first")
        val second = RuntimeException("second", first)
        first.initCause(second)
        assertEquals("RuntimeException: first < RuntimeException: second", Causes.chain(first))
    }

    @Test
    fun aChainDeeperThanItsLimitSaysSo() {
        var failure: Throwable = RuntimeException("0")
        for (depth in 1..20) {
            failure = RuntimeException("$depth", failure)
        }
        val links = Causes.chain(failure).split(" < ")
        assertEquals(Causes.MAX_LINKS + 1, links.size)
        assertEquals("…", links.last())
    }

    @Test
    fun aKeyFailureReportsItsWordsThenItsCauses() {
        val failure = InstallationKeyFailure(
            "STEPUP_KEY_UNAVAILABLE",
            "AndroidKeyStore could not establish whether the step-up key is usable (lookup: unrecoverable).",
            android9Lookup(),
        )
        assertEquals(
            "AndroidKeyStore could not establish whether the step-up key is usable (lookup: unrecoverable). " +
                "[cause: UnrecoverableKeyException: Failed to obtain information about key < " +
                "KeyStoreException: Key blob corrupted]",
            failure.report(),
        )
        assertEquals("No cause.", InstallationKeyFailure("X", "No cause.").report())
    }

    @Test
    fun anUnreadPartSaysItsCausesWithinTheContractsLimit() {
        assertEquals(
            "UnrecoverableKeyException: Failed to obtain information about key < KeyStoreException: Key blob corrupted",
            ProbeReads.why(android9Lookup()),
        )
        val long = RuntimeException("x".repeat(300))
        assertTrue(ProbeReads.why(long).length <= 160)
        assertEquals("unknown", ProbeReads.why(null))
    }
}
