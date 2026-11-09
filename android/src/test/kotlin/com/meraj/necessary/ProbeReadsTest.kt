package com.meraj.necessary

import com.meraj.necessary.ProbeReads.CommandResult
import com.meraj.necessary.ProbeReads.PortResult
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * No failed read may become a clean
 * negative. Each probe is handed an unreadable source, empty or malformed
 * content, a command that did not start, did not finish, or whose output
 * could not be read, and a check that threw; none answers a clean "no".
 */
class ProbeReadsTest {

    private val ran = CommandResult(started = true, finished = true, exitCode = 0, output = "")
    private val notStarted = CommandResult(false, false, null, "", "IOException")
    private val timedOut = CommandResult(true, false, null, "")
    private val unreadOutput = CommandResult(true, false, 0, "", "output: IOException")

    private fun isError(result: Map<String, Any>) = result["status"] == "error"

    @Suppress("UNCHECKED_CAST")
    private fun unread(result: Map<String, Any>) = result["unread"] as Map<String, String>?

    @Test fun mountsUnreadableOrEmptyIsNoMeasurement() {
        assertTrue(isError(ProbeReads.mounts(null)))
        assertTrue(isError(ProbeReads.mounts(emptyList())))
    }

    @Test fun mountsReadAreMeasured() {
        val clean = ProbeReads.mounts(listOf("/dev/block/dm-0 /system ext4 ro,seclabel 0 0"))
        assertEquals("ok", clean["status"])
        assertEquals(emptyList<String>(), clean["protected_rw_mounts"])
        val writable = ProbeReads.mounts(listOf("/dev/block/dm-0 /system ext4 rw,seclabel 0 0", "garbage"))
        assertEquals(listOf("/system:rw,seclabel"), writable["protected_rw_mounts"])
    }

    @Test fun tracerNeverDefaultsToZero() {
        assertTrue(isError(ProbeReads.tracer(null)))
        assertTrue(isError(ProbeReads.tracer(emptyList())))
        assertTrue(isError(ProbeReads.tracer(listOf("Name:\tapp", "State:\tR"))))
        assertTrue(isError(ProbeReads.tracer(listOf("TracerPid:\tnot-a-number"))))
        assertTrue(isError(ProbeReads.tracer(listOf("TracerPid:"))))
    }

    @Test fun tracerReadIsMeasured() {
        val clean = ProbeReads.tracer(listOf("TracerPid:\t0", "Seccomp:\t2"))
        assertEquals(0, clean["tracer_pid"])
        assertEquals(2, clean["seccomp"])
        assertEquals(-1, clean["no_new_privs"])
        assertEquals(4242, ProbeReads.tracer(listOf("TracerPid:\t4242"))["tracer_pid"])
    }

    @Test fun aSettingThatThrewIsUnreadNotOff() {
        val failure = Result.failure<Boolean>(SecurityException("denied"))
        val oneLost = ProbeReads.developerSettings(failure, Result.success(false))
        assertEquals("ok", oneLost["status"])
        assertFalse(oneLost.containsKey("adb_enabled"))
        assertEquals(false, oneLost["developer_options_enabled"])
        assertTrue(unread(oneLost)!!.getValue("adb_enabled").startsWith("SecurityException"))
        assertTrue(isError(ProbeReads.developerSettings(failure, failure)))
        val both = ProbeReads.developerSettings(Result.success(true), Result.success(false))
        assertNull(unread(both))
        assertEquals(true, both["adb_enabled"])
    }

    @Test fun anUnansweredSuLookupIsNotNoSu() {
        assertTrue(isError(ProbeReads.rootShell(notStarted)))
        assertTrue(isError(ProbeReads.rootShell(timedOut)))
        assertTrue(isError(ProbeReads.rootShell(unreadOutput)))
        assertEquals(false, ProbeReads.rootShell(ran)["su_found"])
        assertEquals(true, ProbeReads.rootShell(ran.copy(output = "/system/xbin/su\n"))["su_found"])
    }

    @Test fun aPropertyNotReadIsUnreadNotEmpty() {
        val some = ProbeReads.systemProperties(
            linkedMapOf("ro.secure" to ran.copy(output = "1\n"), "ro.debuggable" to notStarted)
        )
        @Suppress("UNCHECKED_CAST")
        val values = some["properties"] as Map<String, String>
        assertEquals(mapOf("ro.secure" to "1"), values)
        assertTrue(unread(some)!!.containsKey("ro.debuggable"))
        assertTrue(isError(ProbeReads.systemProperties(mapOf("ro.secure" to timedOut))))
    }

    @Test fun aRootPathThatThrewIsUnreadNotAbsent() {
        val some = ProbeReads.rootFiles(
            linkedMapOf(
                "/system/xbin/su" to Result.success(true),
                "/sbin/su" to Result.failure(SecurityException("denied")),
                "/data/adb/magisk" to Result.success(false)
            ),
            "release-keys"
        )
        assertEquals(listOf("/system/xbin/su"), some["found_paths"])
        assertEquals(setOf("/sbin/su"), unread(some)!!.keys)
        assertTrue(isError(ProbeReads.rootFiles(mapOf("/sbin/su" to Result.failure(IOException())), "")))
    }

    @Test fun aPortThatCouldNotBeTestedIsUnreadNotClosed() {
        val some = ProbeReads.fridaPorts(
            linkedMapOf(27042 to PortResult.Refused, 27043 to PortResult.Failed("SecurityException"))
        )
        assertEquals(emptyList<Int>(), some["open_ports"])
        assertEquals(setOf("27043"), unread(some)!!.keys)
        assertTrue(isError(ProbeReads.fridaPorts(mapOf(27042 to PortResult.Failed("SocketTimeoutException")))))
        val open = ProbeReads.fridaPorts(linkedMapOf(27042 to PortResult.Open, 27043 to PortResult.Refused))
        assertEquals(listOf(27042), open["open_ports"])
        assertNull(unread(open))
    }

    @Test fun threadNamesNotReadAreUnread() {
        val frida = listOf("gum-js-loop")
        val glib = listOf("gmain")
        assertTrue(isError(ProbeReads.threads(emptyList(), 3, frida, glib, emptyList())))
        val some = ProbeReads.threads(listOf("main", "RenderThread"), 2, frida, glib, emptyList())
        assertEquals(2, some["thread_count"])
        assertTrue(unread(some)!!.containsKey("thread_names"))
        val all = ProbeReads.threads(listOf("main", "gum-js-loop"), 0, frida, glib, emptyList())
        assertEquals(listOf("gum-js-loop"), all["frida_threads"])
        assertNull(unread(all))
    }

    @Test fun theAppsOwnNamesAreNoTools() {
        val tokens = listOf("tool", "gadget")
        val name = "com.example.toolbox"
        val install = "/data/app/~~Ztool==/$name-Qgadget==/"
        val own = listOf(install, "/data/user/0/$name/")
        fun line(path: String) = "7a0000-7b0000 r-xp 00000000 fd:00 123  $path"
        fun names(text: String) = ProbeReads.namesIn(text, own, name, tokens)
        assertEquals(emptyList<String>(), names(line("${install}base.apk")))
        assertEquals(emptyList<String>(), names(line("/data/user/0/$name/app_flutter/plugin.so")))
        assertEquals(emptyList<String>(), names("[anon:dalvik-classes.dex extracted in memory from ${install}base.apk]"))
        assertEquals(emptyList<String>(), names(line("/storage/emulated/0/Android/data/$name/files/plugin.so")))
        // What lies inside the app's folders, and anything elsewhere, is read.
        assertEquals(tokens, names(line("${install}lib/arm64/libtool-gadget.so")))
        assertEquals(listOf("tool"), names(line("/data/local/tmp/TOOL-agent.so")))
    }

    @Test fun aThreadNamedForTheAppNamesNoTool() {
        val tokens = listOf("tool")
        val name = "com.example.toolbox"
        val main = ProbeReads.threads(listOf("example.toolbox"), 0, emptyList(), emptyList(), tokens, name)
        assertEquals(emptyList<String>(), main["token_threads"])
        val tool = ProbeReads.threads(listOf("example.toolbox", "tool-worker"), 0, emptyList(), emptyList(), tokens, name)
        assertEquals(tokens, tool["token_threads"])
    }

    @Test fun splitsAreListedApartSortedAndNeverDropped() {
        val hash = "ab".repeat(32)
        val (none, noneUnread) = ProbeReads.splitApks(emptyMap())
        assertEquals(emptyList<Map<String, String>>(), none)
        assertTrue(noneUnread.isEmpty())
        val (listed, unread) = ProbeReads.splitApks(
            linkedMapOf(
                "split_config.xxhdpi.apk" to Result.success(hash),
                "split_config.arm64_v8a.apk" to Result.success("cd".repeat(32)),
                "split_feature.apk" to Result.failure(java.io.IOException("EACCES"))
            )
        )
        assertEquals(listOf("split_config.arm64_v8a.apk", "split_config.xxhdpi.apk"), listed.map { it["name"] })
        assertEquals(hash, listed[1]["sha256"])
        assertEquals(setOf("split_apks:split_feature.apk"), unread.keys)
    }

    // The location and mock-location measurements are one observation.

    private val coordinates = setOf("latitude", "longitude", "accuracy_m", "provider")

    private fun fix(seconds: Long, mock: Boolean, latitude: Double, provider: String = "fused", age: Long = 5) =
        ProbeReads.Fix(latitude, 67.0, 12.0, age, seconds * 1_000_000_000L, provider, seconds * 1000, mock)

    @Test fun bothLocationMeasurementsDescribeTheOneCapturedFix() {
        val real = fix(1_761_300_000, mock = false, latitude = 24.86)
        val mocked = fix(1_761_300_001, mock = true, latitude = 51.5)
        var reads = 0
        // The provider alternates a real and a mocked fix on every read.
        val source = { reads++; ProbeReads.FixRead("precise", if (reads % 2 == 1) real else mocked) }
        val scan = ProbeReads.LocationCapture(source)
        val location = ProbeReads.location(scan.value)
        val mock = ProbeReads.mockLocation(scan.value)
        assertEquals(1, reads)
        assertEquals(24.86, location["latitude"])
        assertEquals(false, mock["mock"])
        assertEquals(1_761_300_000L, location["fix_time"])
        assertEquals(location["fix_time"], mock["fix_time"])
        assertEquals(location["age_seconds"], mock["age_seconds"])
        assertTrue(mock.keys.none { it in coordinates })
        // The next scan reads again, in either order, and gets one fix again.
        val next = ProbeReads.LocationCapture(source)
        assertEquals(true, ProbeReads.mockLocation(next.value)["mock"])
        assertEquals(51.5, ProbeReads.location(next.value)["latitude"])
        assertEquals(2, reads)
    }

    @Test fun theNewestFixOfChangingProvidersIsTheOneDescribed() {
        val read = ProbeReads.newestFix(
            "precise",
            linkedMapOf(
                "gps" to Result.success(fix(1_761_300_000, mock = false, latitude = 24.86, provider = "gps")),
                "network" to Result.success(fix(1_761_300_009, mock = true, latitude = 51.5, provider = "network")),
                "passive" to Result.success(null)
            )
        )
        val location = ProbeReads.location(read)
        val mock = ProbeReads.mockLocation(read)
        assertEquals("network", location["provider"])
        assertEquals(51.5, location["latitude"])
        assertEquals(true, mock["mock"])
        assertEquals(location["fix_time"], mock["fix_time"])
    }

    @Test fun noPermissionReadsNothing() {
        val read = ProbeReads.newestFix(
            "none", mapOf("gps" to Result.success(fix(1_761_300_000, mock = true, latitude = 24.86)))
        )
        for (result in listOf(ProbeReads.location(read), ProbeReads.mockLocation(read))) {
            assertEquals(mapOf("status" to "ok", "permission" to "none"), result)
        }
    }

    @Test fun noFixIsMeasuredOnlyWhenEveryProviderWasRead() {
        val none = ProbeReads.newestFix("approximate", mapOf("network" to Result.success(null)))
        assertEquals(mapOf("status" to "ok", "permission" to "approximate"), ProbeReads.mockLocation(none))
        assertEquals(mapOf("status" to "ok", "permission" to "approximate"), ProbeReads.location(none))
        // A provider that threw - the permission revoked mid-read - is unread, not "no fix".
        val revoked = ProbeReads.newestFix(
            "precise",
            linkedMapOf("gps" to Result.failure(SecurityException("revoked")), "network" to Result.success(null))
        )
        assertEquals(setOf("gps"), unread(ProbeReads.mockLocation(revoked))!!.keys)
        assertFalse(ProbeReads.mockLocation(revoked).containsKey("mock"))
        val some = ProbeReads.newestFix(
            "precise",
            linkedMapOf(
                "gps" to Result.failure(SecurityException("revoked")),
                "network" to Result.success(fix(1_761_300_000, mock = false, latitude = 24.86))
            )
        )
        assertEquals(false, ProbeReads.mockLocation(some)["mock"])
        assertEquals(setOf("gps"), unread(ProbeReads.location(some))!!.keys)
        val all = ProbeReads.newestFix("precise", mapOf("gps" to Result.failure(SecurityException("revoked"))))
        assertTrue(isError(ProbeReads.location(all)))
        assertTrue(isError(ProbeReads.mockLocation(all)))
    }

    @Test fun aStaleFixIsOneAgeInBoth() {
        val read = ProbeReads.FixRead("precise", fix(1_761_296_400, mock = false, latitude = 24.86, age = 3600))
        assertEquals(3600L, ProbeReads.location(read)["age_seconds"])
        assertEquals(3600L, ProbeReads.mockLocation(read)["age_seconds"])
    }

    @Test fun aReadThatThrewFailsBothAndIsNotRetried() {
        var reads = 0
        val scan = ProbeReads.LocationCapture {
            reads++
            if (reads == 1) throw IllegalStateException("provider gone")
            ProbeReads.FixRead("precise", fix(1_761_300_000, mock = false, latitude = 24.86))
        }
        assertTrue(isError(ProbeReads.location(scan.value)))
        assertTrue(isError(ProbeReads.mockLocation(scan.value)))
        assertEquals(1, reads)
    }

    @Test fun theDebuggerThreadIsNamedOrUnread() {
        assertEquals(true, ProbeReads.jdwpThread(listOf("main", "ADB-JDWP Connec"), 0)["jdwp_thread"])
        assertEquals(true, ProbeReads.jdwpThread(listOf("main", "JDWP"), 0)["jdwp_thread"])
        assertEquals(false, ProbeReads.jdwpThread(listOf("main", "RenderThread", "Jit thread pool"), 0)["jdwp_thread"])
        // A name not read could be the one: unread, never false.
        val some = ProbeReads.jdwpThread(listOf("main"), 2)
        assertNull(some["jdwp_thread"])
        assertEquals(setOf("jdwp_thread"), unread(some)!!.keys)
        val none = ProbeReads.jdwpThread(emptyList(), 0)
        assertNull(none["jdwp_thread"])
        assertEquals(setOf("jdwp_thread"), unread(none)!!.keys)
    }

    @Test fun anAppRunByAnotherAppIsNamedByWhereItsFilesAre() {
        val pkg = "com.example.bank"
        val maps = listOf(
            "7000-8000 r--p 00000000 fd:00 1   /data/app/~~a==/com.example.bank-b==/base.apk",
            "8000-9000 r-xp 00000000 fd:00 2   /data/app/~~a==/com.example.bank-b==/oat/arm64/base.odex",
            "9000-a000 r--p 00000000 fd:00 3   /data/user_de/0/com.google.android.gms/app_chimera/m/0000001/MapsDynamite.apk",
            "a000-b000 r--p 00000000 fd:00 4   /data/user/0/com.example.bank/files/fonts/a.ttf",
            "b000-c000 r--p 00000000 fd:00 5   /data/user/0/com.other.provider/files/shared.ttf",
            "c000-d000 rw-p 00000000 00:00 0   [anon:dalvik-main space]",
        )
        val own = ProbeReads.appHost(
            pkg, "/data/app/~~a==/com.example.bank-b==/base.apk", "/data/user/0/com.example.bank",
            10123, 10123, Result.success(listOf(pkg)), Result.success(maps), 32
        )
        assertEquals("installed", own["loaded_from"])
        assertEquals("own", own["data_folder"])
        assertEquals(true, own["uid_matches"])
        assertEquals(emptyList<String>(), own["other_app_code"])
        assertEquals(false, own["truncated"])
        assertNull(unread(own))
        // A second user (a work profile, a phone maker's dual apps): still the app's own.
        val secondUser = ProbeReads.appHost(
            pkg, "/data/app/x/base.apk", "/data/user/999/com.example.bank/",
            99910123, 99910123, Result.success(listOf(pkg)), Result.success(maps), 32
        )
        assertEquals("own", secondUser["data_folder"])
        assertEquals("system", ProbeReads.appHost(
            pkg, "/product/app/Bank/Bank.apk", "/data/user/0/$pkg", 1, 1,
            Result.success(listOf(pkg)), Result.success(maps), 32
        )["loaded_from"])
        // Run inside another app: its package file, data and code are in that app's folder.
        val host = "io.va.exposed"
        val hosted = ProbeReads.appHost(
            pkg, "/data/user/0/$host/virtual/data/app/$pkg/base.apk",
            "/data/user/0/$host/virtual/data/user/0/$pkg", 10200, 10200, Result.success(listOf(host)),
            Result.success(listOf("1000-2000 r--p 00000000 fd:00 9   /data/user/0/$host/virtual/data/app/$pkg/base.apk")), 32
        )
        assertEquals("another_app", hosted["loaded_from"])
        assertEquals("another_app", hosted["data_folder"])
        assertEquals(false, hosted["uid_matches"])
        assertEquals(listOf(host), hosted["other_app_code"])
        assertEquals(false, ProbeReads.appHost(
            pkg, "/data/app/x/base.apk", "/data/user/0/$pkg", 10200, 10123,
            Result.success(listOf(pkg)), Result.success(maps), 32
        )["uid_matches"])
        // Nothing read is an error; a part not read is unread, never a clean answer.
        assertTrue(isError(ProbeReads.appHost(
            pkg, null, null, 1, 1, Result.failure(SecurityException("refused")), Result.failure(IOException("denied")), 32
        )))
        val partial = ProbeReads.appHost(
            pkg, "/data/app/x/base.apk", "/data/user/0/$pkg", 1, 1,
            Result.success(listOf(pkg)), Result.failure(IOException("denied")), 32
        )
        assertNull(partial["other_app_code"])
        assertEquals(setOf("other_app_code"), unread(partial)!!.keys)
    }

    private val emulatorCpu = listOf(
        "processor\t: 0", "vendor_id\t: GenuineIntel", "model name\t: Android virtual processor",
        "flags\t\t: fpu de pse tsc msr pae sse sse2 ht syscall nx lm hypervisor lahf_lm", "",
        "processor\t: 1", "vendor_id\t: GenuineIntel", "flags\t\t: fpu de pse hypervisor",
    )
    private val kirinCpu = listOf(
        "Processor\t: AArch64 Processor rev 4 (aarch64)", "processor\t: 0",
        "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 cpuid", "CPU implementer\t: 0x41",
        "CPU part\t: 0xd03", "", "processor\t: 4", "CPU implementer\t: 0x41", "CPU part\t: 0xd09",
        "Hardware\t: vendor Kirin710",
    )

    @Test fun anEmulatorIsToldByItsProcessorWhateverItsBuildSays() {
        val avd = ProbeReads.emulatorHardware(Result.success(emulatorCpu), listOf("x86_64"), "x86_64", emptySet())
        assertEquals(listOf("cpu", "hypervisor", "abi"), avd.reasons)
        assertEquals("GenuineIntel", avd.fields["cpu_vendor"])
        assertEquals("Android virtual processor", avd.fields["cpu_model"])
        assertEquals(true, avd.fields["hypervisor"])
        assertEquals("phone_or_tablet", avd.fields["form_factor"])
        // A phone: Arm's cores, no x86 flags to read, no reason.
        val phone = ProbeReads.emulatorHardware(
            Result.success(kirinCpu), listOf("arm64-v8a", "armeabi-v7a", "armeabi"), "aarch64", emptySet()
        )
        assertEquals(emptyList<String>(), phone.reasons)
        assertEquals(listOf("0x41"), phone.fields["cpu_implementers"])
        assertEquals("vendor Kirin710", phone.fields["cpu_model"])
        assertNull(phone.fields["hypervisor"])
        assertNull(phone.fields["cpu_vendor"])
        // An emulator on a Mac: Apple's cores.
        val mac = ProbeReads.emulatorHardware(
            Result.success(listOf("CPU implementer\t: 0x61")), listOf("arm64-v8a"), "aarch64", emptySet()
        )
        assertEquals(listOf("cpu"), mac.reasons)
        // Translation that answers aarch64 changes nothing: the processor still says x86.
        val translated = ProbeReads.emulatorHardware(Result.success(emulatorCpu), emptyList(), "aarch64", emptySet())
        assertEquals(listOf("cpu", "hypervisor", "abi"), translated.reasons)
        // A Chromebook has the same hardware and says what it is: no reason, the readings kept.
        val chromebook = ProbeReads.emulatorHardware(
            Result.success(emulatorCpu), listOf("x86_64", "x86"), "x86_64", setOf("org.chromium.arc")
        )
        assertEquals(emptyList<String>(), chromebook.reasons)
        assertEquals("chromebook", chromebook.fields["form_factor"])
        assertEquals("GenuineIntel", chromebook.fields["cpu_vendor"])
        // An unreadable processor is unread, never a phone's.
        val unreadable = ProbeReads.emulatorHardware(Result.failure(IOException("denied")), listOf("arm64-v8a"), "aarch64", emptySet())
        assertEquals(setOf("cpu"), unreadable.unread.keys)
        assertEquals(emptyList<String>(), unreadable.reasons)
    }
}
