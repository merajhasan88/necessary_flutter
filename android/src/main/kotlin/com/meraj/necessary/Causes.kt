package com.meraj.necessary

/**
 * What failed, and everything beneath it: a failure and each of its causes,
 * outermost first, as "Class: message < Class: message". Every failure the
 * plugin reports carries it, so a key that reads as unavailable or dead says
 * what the keystore itself answered -- on Android 9 an
 * UnrecoverableKeyException's message is always "Failed to obtain information
 * about key", and only the KeyStoreException beneath it says which failure it
 * was (the release review of 2026-10-31, item 4: "preserve the original cause
 * chain and available error codes").
 *
 * Class names and messages only: never a stack trace, a key or a value of the
 * app's. A pure function, so a JVM test holds it.
 */
internal object Causes {
    /** How many failures a chain names: deeper ones are the same failure rewrapped. */
    const val MAX_LINKS = 8

    /**
     * [error] and its causes. [detail] adds what a failure's message leaves
     * out -- AndroidKeyStore's numeric error code -- or null. Empty for no error.
     */
    fun chain(error: Throwable?, detail: (Throwable) -> String? = { null }): String {
        val links = mutableListOf<String>()
        val seen = mutableSetOf<Throwable>()
        var current = error
        while (current != null && links.size < MAX_LINKS && seen.add(current)) {
            val message = current.message?.trim().orEmpty()
            val extra = detail(current)
            links.add(
                current.javaClass.simpleName +
                    (if (message.isEmpty()) "" else ": $message") +
                    (if (extra.isNullOrEmpty()) "" else " ($extra)"),
            )
            current = current.cause
        }
        if (current != null && current !in seen) {
            links.add("…")
        }
        return links.joinToString(" < ")
    }

    /** [message], then what failed beneath it when anything did. */
    fun withCauses(message: String, cause: Throwable?, detail: (Throwable) -> String? = { null }): String {
        val beneath = chain(cause, detail)
        return if (beneath.isEmpty()) message else "$message [cause: $beneath]"
    }
}
