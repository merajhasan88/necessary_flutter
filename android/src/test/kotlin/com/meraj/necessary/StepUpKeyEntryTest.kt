package com.meraj.necessary

import com.meraj.necessary.StepUpKeyEntry.Lookup
import com.meraj.necessary.StepUpKeyEntry.SignStart
import com.meraj.necessary.StepUpKeyEntry.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

/** The step-up key is deleted only when Android says it is dead (review of 2026-10-31, item 4). */
class StepUpKeyEntryTest {
    @Test
    fun aLoadedKeySigns() {
        assertEquals(Verdict.USABLE, StepUpKeyEntry.verdict(Lookup.PRIVATE_KEY, SignStart.STARTED))
    }

    @Test
    fun aWindowedKeyOutsideItsWindowOnlyNeedsThePerson() {
        assertEquals(Verdict.USABLE, StepUpKeyEntry.verdict(Lookup.PRIVATE_KEY, SignStart.NEEDS_AUTHENTICATION))
    }

    @Test
    fun aPermanentlyInvalidatedKeyIsTheOnlyOneDeleted() {
        assertEquals(Verdict.INVALIDATED, StepUpKeyEntry.verdict(Lookup.PRIVATE_KEY, SignStart.PERMANENTLY_INVALIDATED))
        for (lookup in Lookup.values().filter { it != Lookup.PRIVATE_KEY }) {
            for (start in SignStart.values()) {
                assertEquals("$lookup/$start", false, StepUpKeyEntry.verdict(lookup, start) == Verdict.INVALIDATED)
            }
        }
    }

    @Test
    fun anAmbiguousLookupKeepsTheKey() {
        // Android 9 answers isKeyEntry false on a binder error; a failed
        // key-characteristics query surfaces as UnrecoverableKeyException.
        for (lookup in listOf(Lookup.NOT_KEY_ENTRY, Lookup.UNRECOVERABLE, Lookup.NOT_PRIVATE_KEY)) {
            assertEquals(lookup.name, Verdict.UNAVAILABLE, StepUpKeyEntry.verdict(lookup, SignStart.NOT_TRIED))
        }
    }

    @Test
    fun theAndroid9OrphanedAliasIsKeptToo() {
        // Seen on an Android 9 phone: containsAlias true, isKeyEntry false, and
        // getEntry throwing UnsupportedOperationException. Kept, retryable;
        // replacing it is the app's explicit re-enrolment.
        assertEquals(Verdict.UNAVAILABLE, StepUpKeyEntry.verdict(Lookup.UNSUPPORTED, SignStart.NOT_TRIED))
        assertEquals(Verdict.UNAVAILABLE, StepUpKeyEntry.verdict(Lookup.NOT_KEY_ENTRY, SignStart.NOT_TRIED))
    }

    @Test
    fun theSameFailureTwiceIsStillNoProofOfPermanence() {
        repeat(3) {
            assertEquals(Verdict.UNAVAILABLE, StepUpKeyEntry.verdict(Lookup.UNRECOVERABLE, SignStart.NOT_TRIED))
        }
    }

    @Test
    fun anotherKeystoreFailureIsReportedAndTheKeyKept() {
        assertEquals(Verdict.LOOKUP_FAILED, StepUpKeyEntry.verdict(Lookup.OTHER_FAILURE, SignStart.NOT_TRIED))
    }
}
