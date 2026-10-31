package com.meraj.necessary

/**
 * What the step-up key's lookups found, and what that means for the key: a
 * pure decision, so a JVM test holds it (the release review of 2026-10-31,
 * item 4).
 *
 * Only a permanent invalidation that Android itself reports
 * (KeyPermanentlyInvalidatedException when a signature starts) deletes the
 * key. Every other failure is ambiguous -- on Android 9, KeyStore.contains
 * answers false on a binder error, and an unsuccessful key-characteristics
 * query surfaces as UnrecoverableKeyException -- so the key is kept and the
 * app hears STEPUP_KEY_UNAVAILABLE, which it may retry; replacing the key is
 * an explicit re-enrolment. Nothing here counts failures: two alike are no
 * proof of permanence either.
 */
internal object StepUpKeyEntry {
    /** What looking the key up found. */
    enum class Lookup {
        /** A private-key entry, loaded. */
        PRIVATE_KEY,
        /** isKeyEntry false: no key, or a keystore that could not say. */
        NOT_KEY_ENTRY,
        /** getEntry threw UnrecoverableKeyException. */
        UNRECOVERABLE,
        /** getEntry threw UnsupportedOperationException (the Android 9 orphaned alias). */
        UNSUPPORTED,
        /** getEntry returned an entry that is not a private key's. */
        NOT_PRIVATE_KEY,
        /** getEntry threw another GeneralSecurityException. */
        OTHER_FAILURE,
    }

    /** What starting a signature with the loaded key found. */
    enum class SignStart { STARTED, NEEDS_AUTHENTICATION, PERMANENTLY_INVALIDATED, NOT_TRIED }

    enum class Verdict {
        /** Sign with it; a windowed key outside its window only needs the person. */
        USABLE,
        /** Android says it can never sign again: delete it, re-enrol. */
        INVALIDATED,
        /** Could not establish whether it is usable: keep it, STEPUP_KEY_UNAVAILABLE. */
        UNAVAILABLE,
        /** Another keystore failure: keep it, KEY_LOOKUP_FAILED. */
        LOOKUP_FAILED,
    }

    fun verdict(lookup: Lookup, start: SignStart): Verdict = when (lookup) {
        Lookup.PRIVATE_KEY -> when (start) {
            SignStart.PERMANENTLY_INVALIDATED -> Verdict.INVALIDATED
            else -> Verdict.USABLE
        }
        Lookup.OTHER_FAILURE -> Verdict.LOOKUP_FAILED
        Lookup.NOT_KEY_ENTRY, Lookup.UNRECOVERABLE, Lookup.UNSUPPORTED,
        Lookup.NOT_PRIVATE_KEY -> Verdict.UNAVAILABLE
    }
}
