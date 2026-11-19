package com.meraj.necessary

/**
 * How the app's screen was touched since the accessibility measurement last read it (Android
 * collectors 12 and 13): the touches, those an Accessibility service made, and the clicks a service
 * performed itself.
 * Counts only: no position, no view and no text is kept, and nothing is counted unless the app
 * enabled the accessibility measurement.
 *
 * A touch an Accessibility service makes (a gesture it dispatches) comes from no finger, stylus,
 * mouse or eraser: Android gives its pointer the unknown tool type. From Android 12 Android also
 * marks it as an Accessibility event (input flag 0x800, not a public constant), and both are
 * required there; on Android 12 to 15 the mark alone is not enough, as Android also puts it on a
 * finger's touches while a service that can perform gestures is on. Before Android 12 the tool
 * alone tells, and it also counts the touches adb or root sends through Android's input command,
 * which there come from no tool either.
 *
 * A click a service performs makes no touch at all. Android's views report it to Accessibility
 * after the click, a Flutter screen only for widgets that send tap feedback; and a Flutter screen
 * hands every tap a service asks for to Dart, which tells the plugin (collector 13). One click can
 * arrive both ways, in either order: within a second, the two are one.
 */
class TouchCounts(private val sdkInt: Int, private val clock: () -> Long) {
    private var touches = 0
    private var injected = 0
    private var untouchedClicks = 0
    private var lastInput: Long? = null
    // The clicks counted from one signal, waiting for the other (each a time).
    private val performedUnpaired = ArrayDeque<Long>()
    private val reportedUnpaired = ArrayDeque<Long>()
    private var watchingSince: Long? = null
    private var watchedMs = 0L
    private var watched = false
    // The clicks were not watched for some of the time: their count is left out.
    private var clicksMissed = false
    private var watchingClicks = false

    /** A window of the app's is watched from now; [clicks]: its clicks too. */
    @Synchronized
    fun watchStarted(clicks: Boolean) {
        if (watchingSince == null) watchingSince = clock()
        watched = true
        watchingClicks = clicks
        if (!clicks) clicksMissed = true
    }

    /** No window of the app's is watched from now. */
    @Synchronized
    fun watchStopped() {
        watchingSince?.let { watchedMs += clock() - it }
        watchingSince = null
    }

    /** The app no longer counts: what was counted is dropped. */
    @Synchronized
    fun discard() {
        reset()
        performedUnpaired.clear()
        reportedUnpaired.clear()
        watchedMs = 0
        watched = watchingSince != null
        if (watched) watchingSince = clock()
        clicksMissed = watched && !watchingClicks
    }

    /** A touch event on the app's window: its masked action, its flags, its first pointer's tool. */
    @Synchronized
    fun onTouch(action: Int, flags: Int, toolType: Int) {
        if (action == ACTION_DOWN) {
            touches++
            val marked = sdkInt < MARKED_FROM_SDK || flags and FLAG_IS_ACCESSIBILITY_EVENT != 0
            if (toolType == TOOL_TYPE_UNKNOWN && marked) injected++
        }
        lastInput = clock()
    }

    /** A key event on the app's window: a key the person pressed explains a click after it. */
    @Synchronized
    fun onKey(flags: Int) {
        if (flags and FLAG_IS_ACCESSIBILITY_EVENT == 0) lastInput = clock()
    }

    /** A click the app's screen reported to Accessibility. */
    @Synchronized
    fun onClick() {
        val now = clock()
        prune(now)
        // The report of a click a service performed, counted when it was asked for.
        if (performedUnpaired.isNotEmpty()) {
            performedUnpaired.removeFirst()
            return
        }
        val last = lastInput
        if (last == null || now - last > CLICK_AFTER_INPUT_MS) {
            untouchedClicks++
            reportedUnpaired.addLast(now)
        }
    }

    /** A tap or long press an assistive service asked the app's own widgets to perform. */
    @Synchronized
    fun onPerformedClick() {
        if (watchingSince == null) return
        val now = clock()
        prune(now)
        // Its report came first and was counted.
        if (reportedUnpaired.isNotEmpty()) {
            reportedUnpaired.removeFirst()
            return
        }
        untouchedClicks++
        performedUnpaired.addLast(now)
    }

    /** A performed click the plugin could not be told of: the clicks are left out this time. */
    @Synchronized
    fun clicksLost() {
        if (watched) clicksMissed = true
    }

    private fun prune(now: Long) {
        while (performedUnpaired.isNotEmpty() && now - performedUnpaired.first() > PAIR_MS) performedUnpaired.removeFirst()
        while (reportedUnpaired.isNotEmpty() && now - reportedUnpaired.first() > PAIR_MS) reportedUnpaired.removeFirst()
    }

    /**
     * The counts since the last call, and the seconds a window was watched in that time; null when
     * none was. The clicks are left out when they were not watched all that time. The next count
     * starts now.
     */
    @Synchronized
    fun take(): Map<String, Any>? {
        if (!watched) return null
        val now = clock()
        val ms = watchedMs + (watchingSince?.let { now - it } ?: 0L)
        val counts = linkedMapOf<String, Any>(
            "touches" to touches,
            "touches_injected" to injected,
        )
        if (!clicksMissed) counts["clicks_without_touch"] = untouchedClicks
        counts["counted_seconds"] = (ms.coerceAtLeast(0) / 1000).toInt()
        reset()
        watchedMs = 0
        if (watchingSince != null) watchingSince = now
        watched = watchingSince != null
        clicksMissed = watched && !watchingClicks
        return counts
    }

    private fun reset() {
        touches = 0
        injected = 0
        untouchedClicks = 0
    }

    companion object {
        const val ACTION_DOWN = 0
        const val TOOL_TYPE_UNKNOWN = 0
        /** Android's mark on input an Accessibility service made or passed on (not a public constant). */
        const val FLAG_IS_ACCESSIBILITY_EVENT = 0x800
        /** Android 12, the first to mark it. */
        const val MARKED_FROM_SDK = 31
        /** A click within this long after a touch or a key is theirs. */
        const val CLICK_AFTER_INPUT_MS = 2000L
        /** A performed click and its report this close together are one click. */
        const val PAIR_MS = 1000L
    }
}
