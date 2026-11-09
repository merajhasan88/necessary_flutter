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
                // Every command run here exits 0 when it ran, so another exit is a
                // command that did not run as asked -- one the system's linker
                // could not start, say -- and what it printed is why, not an answer.
                exitCode != null && exitCode != 0 -> "exited with $exitCode" +
                    (output.trim().lineSequence().firstOrNull()?.takeIf { it.isNotEmpty() }?.let { ": $it" } ?: "")
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

    /**
     * The listed names in one line of the memory map, in any case. The app's
     * own folders and package name are taken out of the line first: Android
     * names those folders after the package, with random text beside it, and
     * neither names a tool. What lies inside those folders is still read, so a
     * library the app was rebuilt with is found by its own name.
     */
    fun namesIn(line: String, ownFolders: List<String>, packageName: String, tokens: List<String>): List<String> {
        var text = line
        for (folder in ownFolders) text = text.replace(folder, "/")
        val lower = text.replace(packageName, "").lowercase(java.util.Locale.US)
        return tokens.filter { lower.contains(it) }
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
     * unread, since a renamed instrumentation thread could be that one. A
     * thread named for the app itself - Android gives the main thread part of
     * the package's name, 15 characters at most - names no tool.
     */
    fun threads(
        names: List<String>,
        unreadable: Int,
        fridaThreads: List<String>,
        glibThreads: List<String>,
        tokens: List<String>,
        packageName: String = "",
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
            if (!packageName.contains(name)) {
                for (t in tokens) if (lower.contains(t)) tokenHits.add(t)
            }
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

    /**
     * The runtime's debugger thread among this process's thread names
     * (collector 11): JDWP, through which a debugger attaches to the app's
     * code. Android starts it only in an app built debuggable, or on a system
     * that is (ro.debuggable 1): "JDWP" before Android 9, "ADB-JDWP Connection
     * Control Thread" since (15 characters of it), and "JDWP ..." threads while
     * a debugger is attached. With a thread name unread, a "no" could be
     * wrong, so it is unread instead.
     */
    fun jdwpThread(names: List<String>, unreadable: Int): Map<String, Any> {
        val named = names.filter { it.isNotEmpty() }
        return when {
            named.any { isJdwpThread(it) } -> mapOf("jdwp_thread" to true)
            named.isEmpty() -> mapOf("unread" to mapOf("jdwp_thread" to "no thread of this process could be listed"))
            unreadable > 0 -> mapOf(
                "unread" to mapOf("jdwp_thread" to "$unreadable of ${named.size + unreadable} thread names could not be read")
            )
            else -> mapOf("jdwp_thread" to false)
        }
    }

    fun isJdwpThread(name: String): Boolean = name.startsWith("JDWP") || name.startsWith("ADB-JDWP")

    /** Where a file lies, and in whose private folder when it is in one. */
    data class Place(val kind: String, val owner: String? = null)

    private val installedApps = listOf(Regex("^/data/app/"), Regex("^/mnt/expand/[^/]+/app/"))
    private val systemPartitions = listOf("/system/", "/system_ext/", "/product/", "/vendor/", "/odm/", "/oem/", "/apex/")
    private val appData = listOf(
        Regex("^/data/data/([^/]+)/"),
        Regex("^/data/user(?:_de)?/\\d+/([^/]+)/"),
        Regex("^/mnt/expand/[^/]+/user(?:_de)?/\\d+/([^/]+)/"),
    )

    /**
     * installed: where the package manager puts installed apps; system: a
     * system partition; app_data: an app's private folder, owner naming the
     * app; elsewhere: anywhere else.
     */
    fun place(path: String): Place {
        if (installedApps.any { it.containsMatchIn(path) }) return Place("installed")
        if (systemPartitions.any { path.startsWith(it) }) return Place("system")
        for (pattern in appData) pattern.find(path)?.let { return Place("app_data", it.groupValues[1]) }
        return Place("elsewhere")
    }

    // What a process maps to run code: fonts, databases and other data files are not counted.
    private val codeFiles = listOf(".apk", ".dex", ".odex", ".vdex", ".oat", ".art", ".so", ".jar")
    // Apps load Google Play services' code by design (its dynamite modules), from its own folder.
    private const val PLAY_SERVICES = "com.google.android.gms"
    private val appHostParts = listOf("loaded_from", "data_folder", "uid_matches", "uid_other_apps", "other_app_code")

    /**
     * Whether Android runs the app itself, or another app runs it inside its
     * own (collector 11). An app that does keeps this one's data, and may keep
     * its package file, in its own private folder, and runs its own code in
     * this process. The readings: where Android says the package file and the
     * data are, the process's user ID against the app's, the other apps
     * Android names for that user ID, and the code files mapped in from other
     * apps' private folders. A host can answer the app's questions to Android
     * for it, so one part reading clean clears nothing another part shows.
     * A part not read is unread, never a clean answer.
     */
    fun appHost(
        packageName: String,
        sourceDir: String?,
        dataDir: String?,
        processUid: Int,
        appUid: Int,
        packagesForUid: Result<List<String>?>,
        mapsLines: Result<List<String>>,
        maxApps: Int,
    ): Map<String, Any> {
        val result = ok()
        val unread = linkedMapOf<String, String>()
        if (sourceDir.isNullOrEmpty()) {
            unread["loaded_from"] = "the app's package file is not named"
        } else {
            val where = place(sourceDir)
            result["loaded_from"] = when {
                where.kind == "app_data" && where.owner != packageName -> "another_app"
                where.kind == "installed" || where.kind == "system" -> where.kind
                else -> "elsewhere"
            }
        }
        if (dataDir.isNullOrEmpty()) {
            unread["data_folder"] = "the app's data folder is not named"
        } else {
            val where = place(dataDir.trimEnd('/') + "/")
            result["data_folder"] = when {
                where.kind != "app_data" -> "elsewhere"
                where.owner == packageName -> "own"
                else -> "another_app"
            }
        }
        var truncated: Boolean? = null
        val failed = packagesForUid.exceptionOrNull()
        if (failed != null) {
            unread["uid_matches"] = why(failed)
            unread["uid_other_apps"] = why(failed)
        } else {
            val packages = packagesForUid.getOrNull()
            result["uid_matches"] = processUid == appUid && packages != null && packageName in packages
            // Android lets only apps signed with this app's own key share its
            // user ID (sharedUserId), so any other name is either such an app
            // or an answer that did not come from Android.
            val others = (packages ?: emptyList()).filter { it != packageName }.toSortedSet()
            result["uid_other_apps"] = others.take(maxApps).map { it.take(128) }
            truncated = others.size > maxApps
        }
        val lines = mapsLines.getOrNull()
        if (lines.isNullOrEmpty()) {
            unread["other_app_code"] = mapsLines.exceptionOrNull()?.let { why(it) } ?: "/proc/self/maps returned no lines"
        } else {
            val owners = sortedSetOf<String>()
            for (line in lines) {
                val fields = line.trim().split(Regex("\\s+"), limit = 6)
                if (fields.size < 6) continue
                val path = fields[5].removeSuffix(" (deleted)")
                if ('x' !in fields[1] && codeFiles.none { path.endsWith(it) }) continue
                val where = place(path)
                val owner = where.owner
                if (where.kind == "app_data" && owner != null && owner != packageName && owner != PLAY_SERVICES) {
                    owners.add(owner)
                }
            }
            result["other_app_code"] = owners.take(maxApps).map { it.take(128) }
            truncated = (truncated ?: false) || owners.size > maxApps
        }
        // One flag for both lists: a list read held more apps than it can.
        if (truncated != null) result["truncated"] = truncated
        if (unread.keys.containsAll(appHostParts)) {
            return error("nothing of where the app runs could be read: " + unread.values.first())
        }
        return withUnread(result, unread)
    }

    /** The processor as /proc/cpuinfo names it: an x86 vendor, ARM implementers, a model, a hypervisor. */
    data class Cpu(val vendor: String?, val implementers: List<String>, val model: String?, val hypervisor: Boolean?)

    /**
     * x86 names its vendor (vendor_id) and lists its flags, hypervisor among
     * them under a virtual machine; ARM names each core's implementer, 0x41
     * for Arm's own designs. The model is x86's "model name" or ARM's
     * "Hardware". hypervisor is null where there are no x86 flags to read.
     */
    fun cpu(lines: List<String>): Cpu {
        var vendor: String? = null
        var model: String? = null
        var hypervisor: Boolean? = null
        val implementers = sortedSetOf<String>()
        for (line in lines) {
            val colon = line.indexOf(':')
            if (colon < 0) continue
            val value = line.substring(colon + 1).trim()
            when (line.substring(0, colon).trim().lowercase(java.util.Locale.US)) {
                "vendor_id" -> if (vendor == null && value.isNotEmpty()) vendor = value
                "cpu implementer" -> if (value.isNotEmpty()) implementers.add(value.lowercase(java.util.Locale.US))
                "model name", "hardware" -> if (model == null && value.isNotEmpty()) model = value
                "flags" -> hypervisor = (hypervisor == true) || value.split(' ').contains("hypervisor")
            }
        }
        return Cpu(vendor, implementers.toList(), model, hypervisor)
    }

    /**
     * What the device is, by the features its system declares: a Chromebook,
     * a PC, a car or a TV runs Android apps on hardware no phone has, so its
     * processor is no sign of an emulator.
     */
    fun formFactor(features: Set<String>): String = when {
        "org.chromium.arc" in features || "org.chromium.arc.device_management" in features -> "chromebook"
        "android.hardware.type.pc" in features -> "pc"
        "android.hardware.type.automotive" in features -> "car"
        "android.software.leanback" in features -> "tv"
        "android.hardware.type.watch" in features -> "watch"
        else -> "phone_or_tablet"
    }

    val formFactorFeatures = listOf(
        "org.chromium.arc", "org.chromium.arc.device_management", "android.hardware.type.pc",
        "android.hardware.type.automotive", "android.software.leanback", "android.hardware.type.watch",
    )

    /** The hardware readings of the emulator measurement, and the reasons they give. */
    data class EmulatorHardware(
        val fields: Map<String, Any>,
        val reasons: List<String>,
        val unread: Map<String, String>,
    )

    /**
     * The processor, the ABIs the system offers and the kernel's machine
     * (collector 11). Apps that hide an emulator rewrite its build values but
     * not its processor; no phone running a current Android has an x86 one,
     * runs under a hypervisor, or has Apple's cores (0x61, an emulator on a
     * Mac). These count as reasons only on a phone or tablet: a Chromebook, a
     * PC, a car or a TV may have such hardware, and form_factor says which.
     */
    fun emulatorHardware(
        cpuLines: Result<List<String>>,
        abis: List<String>,
        machine: String?,
        features: Set<String>,
    ): EmulatorHardware {
        val fields = linkedMapOf<String, Any>()
        val reasons = mutableListOf<String>()
        val unread = linkedMapOf<String, String>()
        val form = formFactor(features)
        fields["form_factor"] = form
        fields["abis"] = abis.take(8).map { it.take(32) }
        machine?.takeIf { it.isNotEmpty() }?.let { fields["machine"] = it.take(32) }
        val lines = cpuLines.getOrNull()
        val cpu = if (lines.isNullOrEmpty()) null else cpu(lines)
        if (cpu == null || (cpu.vendor == null && cpu.implementers.isEmpty())) {
            unread["cpu"] = cpuLines.exceptionOrNull()?.let { why(it) } ?: "/proc/cpuinfo names no processor"
        }
        cpu?.vendor?.let { fields["cpu_vendor"] = it.take(64) }
        cpu?.implementers?.takeIf { it.isNotEmpty() }?.let { found -> fields["cpu_implementers"] = found.take(8).map { it.take(8) } }
        cpu?.model?.let { fields["cpu_model"] = it.take(128) }
        cpu?.hypervisor?.let { fields["hypervisor"] = it }
        if (form == "phone_or_tablet") {
            if (cpu != null && (cpu.vendor != null || "0x61" in cpu.implementers)) reasons.add("cpu")
            if (cpu?.hypervisor == true) reasons.add("hypervisor")
            if (abis.isEmpty() || abis.any { it.startsWith("x86") }) reasons.add("abi")
        }
        return EmulatorHardware(fields, reasons, unread)
    }

    /**
     * Why a read failed, for `unread` and a probe's `error`: the failure and
     * every cause beneath it (Causes), within the contract's 160 characters.
     */
    internal fun why(error: Throwable?): String =
        Causes.chain(error).ifEmpty { "unknown" }.take(160)
}
