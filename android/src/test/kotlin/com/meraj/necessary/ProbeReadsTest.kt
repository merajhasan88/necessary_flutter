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
}
