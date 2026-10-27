package com.meraj.necessary

/**
 * What a probe makes of what it read: pure functions over the raw reads, with
 * no Android API in them, so the JVM unit tests can hand them every way a
 * read fails.
 *
 * The rule: a failed read is never a clean negative. A probe that could read
 * nothing answers status "error"; one that read some parts answers "ok" with
 * those parts and names the rest in "unread", each with why. The server takes
 * either as missing evidence, never as a measured "no".
 */
object ProbeReads {

    /** One command's run: started at all, finished in time, its exit code and output. */
    data class CommandResult(
        val started: Boolean,
        val finished: Boolean,
        val exitCode: Int?,
        val output: String,
        val failure: String? = null,
    ) {
        /** Why the command gave no answer, or null when it ran to the end. */
        val problem: String?
            get() = when {
                !started -> "could not start" + (failure?.let { ": $it" } ?: "")
                !finished -> "did not finish in time"
                else -> null
            }
    }

    /** How one attempt to reach a local port ended. */
    sealed class PortResult {
        object Open : PortResult()
        /** Refused: nothing listens there - a measured "closed". */
        object Refused : PortResult()
        /** Anything else: the test could not be made. */
        data class Failed(val why: String) : PortResult()
    }

    fun ok(vararg pairs: Pair<String, Any?>): MutableMap<String, Any> {
        val result = linkedMapOf<String, Any>("status" to "ok")
        for ((key, value) in pairs) if (value != null) result[key] = value
        return result
    }

    fun error(reason: String): Map<String, Any> =
        linkedMapOf("status" to "error", "error" to reason.take(240))

    private fun withUnread(result: MutableMap<String, Any>, unread: Map<String, String>): Map<String, Any> {
        if (unread.isNotEmpty()) {
            result["unread"] = LinkedHashMap(unread.entries.take(64).associate { (part, why) ->
                part.take(128) to why.take(160)
            })
        }
        return result
    }

    /** /proc/mounts: lines, or null when the file could not be read. */
    fun mounts(lines: List<String>?): Map<String, Any> {
        if (lines == null) return error("/proc/mounts is not readable")
        if (lines.isEmpty()) return error("/proc/mounts returned no lines")
        val protectedPrefixes = listOf("/system", "/vendor", "/product", "/odm", "/system_ext")
        val writable = mutableListOf<String>()
        for (line in lines) {
            val parts = line.split(' ')
            if (parts.size < 4) continue
            val mountPoint = parts[1]
            val options = parts[3].split(',')
            if (protectedPrefixes.any { mountPoint == it || mountPoint.startsWith("$it/") } &&
                options.contains("rw")) {
                writable.add("$mountPoint:${parts[3]}")
            }
        }
        return ok("protected_rw_mounts" to writable.distinct().take(32))
    }

    /**
     * /proc/self/status: lines, or null when unreadable. TracerPid is the
     * measurement: missing or unparsable, nothing was measured - it is never
     * taken as 0. Seccomp and NoNewPrivs are context, -1 when absent.
     */
    fun tracer(lines: List<String>?): Map<String, Any> {
        if (lines == null) return error("/proc/self/status is not readable")
        var tracerPid: Int? = null
        var tracerSeen = false
        var seccomp = -1
        var noNewPrivs = -1
        for (line in lines) {
            when {
                line.startsWith("TracerPid:") -> {
                    tracerSeen = true
                    tracerPid = line.substringAfter(':').trim().toIntOrNull()
                }
                line.startsWith("Seccomp:") -> seccomp = line.substringAfter(':').trim().toIntOrNull() ?: -1
                line.startsWith("NoNewPrivs:") -> noNewPrivs = line.substringAfter(':').trim().toIntOrNull() ?: -1
            }
        }
        if (!tracerSeen) return error("TracerPid is missing from /proc/self/status")
        val pid = tracerPid ?: return error("TracerPid is not a number")
        return ok("tracer_pid" to pid, "seccomp" to seccomp, "no_new_privs" to noNewPrivs)
    }

    /** The two developer settings, each read on its own: a read that threw is unread, not "off". */
    fun developerSettings(adb: Result<Boolean>, developer: Result<Boolean>): Map<String, Any> {
        if (adb.isFailure && developer.isFailure) {
            return error("neither developer setting could be read: " + why(adb.exceptionOrNull()))
        }
        val unread = linkedMapOf<String, String>()
        adb.exceptionOrNull()?.let { unread["adb_enabled"] = why(it) }
        developer.exceptionOrNull()?.let { unread["developer_options_enabled"] = why(it) }
        return withUnread(
            ok("adb_enabled" to adb.getOrNull(), "developer_options_enabled" to developer.getOrNull()),
            unread
        )
    }

    /** `command -v su`: a lookup that could not run, or never finished, is not "no su". */
    fun rootShell(lookup: CommandResult): Map<String, Any> {
        lookup.problem?.let { return error("su lookup $it") }
        val path = lookup.output.trim()
        return ok("su_path" to path.take(512), "su_found" to path.isNotEmpty())
    }

    /** One getprop run per property: a property not read is unread, never "". */
    fun systemProperties(results: Map<String, CommandResult>): Map<String, Any> {
        val values = linkedMapOf<String, String>()
        val unread = linkedMapOf<String, String>()
        for ((name, result) in results) {
            val problem = result.problem
            if (problem != null) unread[name] = "getprop $problem" else values[name] = result.output.trim().take(256)
        }
        if (values.isEmpty()) return error("no property could be read: " + unread.values.firstOrNull().orEmpty())
        return withUnread(ok("properties" to values), unread)
    }

    /** Whether each root path exists: a check that threw is unread, never "absent". */
    fun rootFiles(checks: Map<String, Result<Boolean>>, buildTags: String): Map<String, Any> {
        if (checks.isNotEmpty() && checks.values.all { it.isFailure }) {
            return error("no root path could be checked: " + why(checks.values.first().exceptionOrNull()))
        }
        val found = checks.filter { it.value.getOrNull() == true }.keys.toList()
        val unread = linkedMapOf<String, String>()
        for ((path, result) in checks) result.exceptionOrNull()?.let { unread[path] = why(it) }
        return withUnread(
            ok(
                "found_paths" to found,
                "build_tags" to buildTags,
                "test_keys" to buildTags.lowercase(java.util.Locale.US).contains("test-keys")
            ),
            unread
        )
    }

    /** Local ports: refused is a measured "closed"; any other failure is unread. */
    fun fridaPorts(results: Map<Int, PortResult>): Map<String, Any> {
        if (results.isNotEmpty() && results.values.all { it is PortResult.Failed }) {
            return error("no port could be tested: " + (results.values.first() as PortResult.Failed).why)
        }
        val open = results.filter { it.value is PortResult.Open }.keys.toList()
        val unread = linkedMapOf<String, String>()
        for ((port, result) in results) if (result is PortResult.Failed) unread[port.toString()] = result.why
        return withUnread(ok("open_ports" to open), unread)
    }

    /**
     * This process's thread names. A thread that ended between listing and
     * reading is gone, not unread; one whose name could not be read is
     * unread, since a renamed instrumentation thread could be that one.
     */
    fun threads(
        names: List<String>,
        unreadable: Int,
        fridaThreads: List<String>,
        glibThreads: List<String>,
        tokens: List<String>,
    ): Map<String, Any> {
        val named = names.filter { it.isNotEmpty() }
        if (named.isEmpty()) return error("no thread of this process could be enumerated")
        val fridaHits = linkedSetOf<String>()
        val glibHits = linkedSetOf<String>()
        val tokenHits = linkedSetOf<String>()
        for (name in named) {
            val lower = name.lowercase(java.util.Locale.US)
            for (t in fridaThreads) if (lower == t || lower.startsWith(t)) fridaHits.add(t)
            for (t in glibThreads) if (lower == t) glibHits.add(t)
            for (t in tokens) if (lower.contains(t)) tokenHits.add(t)
        }
        val unread = if (unreadable > 0) {
            mapOf("thread_names" to "$unreadable of ${named.size + unreadable} could not be read")
        } else {
            emptyMap()
        }
        return withUnread(
            ok(
                "frida_threads" to fridaHits.toList(),
                "glib_threads" to glibHits.toList(),
                "token_threads" to tokenHits.toList(),
                "thread_count" to named.size
            ),
            unread
        )
    }

    /** Split APKs listed, at most: the server's bound for any list. */
    const val MAX_SPLITS = 64

    /**
     * The installed split APKs, apart from the base APK: apk_sha256 stays the base APK's alone, so pins
     * and baselines keep their meaning. Each split by file name with its
     * SHA-256, sorted by name; a split that could not be hashed is unread,
     * never left out. No splits is an empty list, a measurement of its own.
     */
    fun splitApks(hashes: Map<String, Result<String>>): Pair<List<Map<String, String>>, Map<String, String>> {
        val listed = hashes.entries.filter { it.value.isSuccess }
            .sortedBy { it.key }
            .take(MAX_SPLITS)
            .map { (name, hash) -> linkedMapOf("name" to name.take(128), "sha256" to hash.getOrThrow()) }
        val unread = linkedMapOf<String, String>()
        for ((name, hash) in hashes.entries.sortedBy { it.key }) {
            hash.exceptionOrNull()?.let { unread["split_apks:" + name.take(116)] = why(it) }
        }
        return listed to unread
    }

    /** One last-known fix as the collection captured it, with no Android type in it. */
    data class Fix(
        val latitude: Double,
        val longitude: Double,
        val accuracyM: Double?,
        val ageSeconds: Long,
        val elapsedNanos: Long,
        val provider: String,
        val timeMillis: Long,
        val mock: Boolean,
    )

    /**
     * The one location read of a collection: the permission the app held, the
     * newest fix the providers gave (null: none held one), the providers that
     * could not be read, with why - or why nothing could be read at all, when
     * the permission is not reported either.
     */
    data class FixRead(
        val permission: String?,
        val fix: Fix? = null,
        val unread: Map<String, String> = emptyMap(),
        val failure: String? = null,
    )

    /**
     * The location and mock-location measurements answer from one read, so the coordinates and the mock flag
     * describe one fix. Read on first use and never again; a read that threw
     * is a failed read, not retried. Each collection makes its own.
     */
    class LocationCapture(read: () -> FixRead) {
        val value: FixRead by lazy {
            try {
                read()
            } catch (error: Throwable) {
                FixRead(null, failure = "location read failed: " + why(error))
            }
        }
    }

    /**
     * The newest fix the providers gave, each read once: a provider that threw
     * is unread, never "no fix"; when none could be read, the read failed.
     */
    fun newestFix(permission: String, providers: Map<String, Result<Fix?>>): FixRead {
        if (permission == "none") return FixRead(permission)
        val unread = linkedMapOf<String, String>()
        for ((provider, result) in providers) result.exceptionOrNull()?.let { unread[provider] = why(it) }
        if (providers.isNotEmpty() && unread.size == providers.size) {
            return FixRead(permission, failure = "no location provider could be read: " + unread.values.first())
        }
        val fix = providers.values.mapNotNull { it.getOrNull() }.maxByOrNull { it.elapsedNanos }
        return FixRead(permission, fix, unread)
    }

    /** The last known location: the coordinates of the captured fix. */
    fun location(read: FixRead): Map<String, Any> {
        read.failure?.let { return error(it) }
        val result = ok("permission" to read.permission)
        read.fix?.let { fix ->
            result["latitude"] = fix.latitude
            result["longitude"] = fix.longitude
            fix.accuracyM?.let { result["accuracy_m"] = it }
            result["age_seconds"] = fix.ageSeconds
            result["provider"] = fix.provider.take(32)
            result["fix_time"] = fix.timeMillis / 1000
        }
        return withUnread(result, read.unread)
    }

    /** Whether the captured fix came from a mock-location app: never its coordinates. */
    fun mockLocation(read: FixRead): Map<String, Any> {
        read.failure?.let { return error(it) }
        val result = ok("permission" to read.permission)
        read.fix?.let { fix ->
            result["mock"] = fix.mock
            result["age_seconds"] = fix.ageSeconds
            result["fix_time"] = fix.timeMillis / 1000
        }
        return withUnread(result, read.unread)
    }

    private fun why(error: Throwable?): String =
        error?.let { it.javaClass.simpleName + (it.message?.let { m -> ": $m" } ?: "") }?.take(160)
            ?: "unknown"
}
