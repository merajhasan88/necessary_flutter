package com.meraj.necessary

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class TouchCountsTest {
    private var now = 1_000_000L
    private val finger = 1
    private val unknown = TouchCounts.TOOL_TYPE_UNKNOWN
    private val marked = TouchCounts.FLAG_IS_ACCESSIBILITY_EVENT
    private val down = TouchCounts.ACTION_DOWN
    private val up = 1

    private fun counts(sdk: Int = 36) = TouchCounts(sdk) { now }

    private fun tap(counts: TouchCounts, flags: Int, tool: Int) {
        counts.onTouch(down, flags, tool)
        now += 60
        counts.onTouch(up, flags, tool)
    }

    @Test
    fun nothingWatchedIsNoReading() {
        val counts = counts()
        tap(counts, 0, finger)
        assertNull(counts.take())
    }

    @Test
    fun aServicesGestureIsCountedAndAFingersIsNot() {
        val counts = counts()
        counts.watchStarted(clicks = true)
        tap(counts, 0, finger)
        // Android 12 to 15 mark a finger's touches too while a service that can perform gestures is on.
        tap(counts, marked, finger)
        tap(counts, marked, unknown)
        now += 5_000
        val read = counts.take()!!
        assertEquals(3, read["touches"])
        assertEquals(1, read["touches_injected"])
        assertEquals(0, read["clicks_without_touch"])
        assertEquals(5, read["counted_seconds"])
    }

    @Test
    fun beforeAndroid12TheToolAloneTells() {
        val counts = counts(sdk = 29)
        counts.watchStarted(clicks = true)
        tap(counts, 0, unknown)
        tap(counts, 0, finger)
        assertEquals(1, counts.take()!!["touches_injected"])
        // From Android 12 an unmarked touch of no tool is not a service's.
        val newer = counts(sdk = 31)
        newer.watchStarted(clicks = true)
        tap(newer, 0, unknown)
        assertEquals(0, newer.take()!!["touches_injected"])
    }

    @Test
    fun aClickWithNoTouchOrKeyBeforeItIsCounted() {
        val counts = counts()
        counts.watchStarted(clicks = true)
        counts.onClick()                       // nothing before it
        tap(counts, 0, finger)
        now += 300
        counts.onClick()                       // the tap's
        now += TouchCounts.CLICK_AFTER_INPUT_MS
        counts.onClick()                       // long after it
        counts.onKey(0)
        now += 100
        counts.onClick()                       // a key the person pressed
        now += TouchCounts.CLICK_AFTER_INPUT_MS + 1
        counts.onKey(marked)
        counts.onClick()                       // a key a service sent explains nothing
        assertEquals(3, counts.take()!!["clicks_without_touch"])
    }

    @Test
    fun clicksNotWatchedAllTheTimeAreLeftOut() {
        val counts = counts()
        counts.watchStarted(clicks = false)
        counts.onClick()
        val read = counts.take()!!
        assertFalse(read.containsKey("clicks_without_touch"))
        assertEquals(0, read["touches"])
    }

    @Test
    fun eachReadStartsAfreshAndCountsOnlyWatchedTime() {
        val counts = counts()
        counts.watchStarted(clicks = true)
        tap(counts, marked, unknown)
        now += 2_000
        counts.watchStopped()
        now += 60_000
        val first = counts.take()!!
        assertEquals(1, first["touches_injected"])
        assertEquals(2, first["counted_seconds"])
        // Not watched since: no reading.
        assertNull(counts.take())
        counts.watchStarted(clicks = true)
        now += 3_000
        val second = counts.take()!!
        assertEquals(0, second["touches"])
        assertEquals(3, second["counted_seconds"])
    }

    @Test
    fun aPerformedClickAndItsReportAreOneClickInEitherOrder() {
        val counts = counts()
        counts.watchStarted(clicks = true)
        counts.onPerformedClick()   // a Material button: Dart first, then its report
        now += 50
        counts.onClick()
        now += 3_000
        counts.onClick()            // a Cupertino button reports first...
        now += 50
        counts.onPerformedClick()   // ...and Dart's word comes after
        now += 3_000
        counts.onPerformedClick()   // a widget that reports nothing
        now += 3_000
        assertEquals(3, counts.take()!!["clicks_without_touch"])
    }

    @Test
    fun aPerformedClickJustAfterAFingerIsStillOne() {
        val counts = counts()
        counts.watchStarted(clicks = true)
        tap(counts, 0, finger)
        now += 500
        counts.onPerformedClick()
        now += 50
        counts.onClick()            // its report, within 2 s of the finger
        assertEquals(1, counts.take()!!["clicks_without_touch"])
        // A finger's own tap and its report: none.
        tap(counts, 0, finger)
        now += 100
        counts.onClick()
        assertEquals(0, counts.take()!!["clicks_without_touch"])
    }

    @Test
    fun aReportLongAfterAPerformedClickIsAnotherClick() {
        val counts = counts()
        counts.watchStarted(clicks = true)
        counts.onPerformedClick()
        now += TouchCounts.PAIR_MS + 1
        counts.onClick()
        assertEquals(2, counts.take()!!["clicks_without_touch"])
    }

    @Test
    fun aLostPerformedClickLeavesTheClicksOut() {
        val counts = counts()
        counts.watchStarted(clicks = true)
        counts.clicksLost()
        assertFalse(counts.take()!!.containsKey("clicks_without_touch"))
        // Not watched: a performed click counts nothing.
        val idle = counts()
        idle.onPerformedClick()
        assertNull(idle.take())
    }

    @Test
    fun discardDropsWhatWasCounted() {
        val counts = counts()
        counts.watchStarted(clicks = true)
        tap(counts, marked, unknown)
        counts.watchStopped()
        counts.discard()
        assertNull(counts.take())
    }
}
