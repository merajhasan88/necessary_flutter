package com.meraj.necessary

/**
 * Screen protection that respects its host. The first caller records what the
 * window has -- FLAG_SECURE, and whether it drops touches that passed through
 * another app's window -- and protects it; later callers only count; the last
 * one to finish puts back exactly what was recorded, so a host that keeps its
 * window secure itself stays secure. Other apps' overlays, whose state no
 * public call reads, are hidden while protected and shown again after. Kept
 * apart from the window so that it runs on the JVM.
 */
internal class ScreenGuard {
    /** What a window has, of what screen protection changes and can read. */
    data class WindowState(val secure: Boolean, val dropsObscuredTouches: Boolean)

    /** What to make of the window. */
    data class Change(
        val secure: Boolean,
        val dropsObscuredTouches: Boolean,
        val hideOverlays: Boolean,
    )

    private var holders = 0
    private var before: WindowState? = null

    val held: Boolean get() = holders > 0

    /** A caller protects the window; only the first changes it. */
    fun acquire(current: WindowState): Change? {
        holders += 1
        if (holders > 1) return null
        before = current
        return PROTECTED
    }

    /** A caller is done; the last puts the window back. An extra release does nothing. */
    fun release(): Change? {
        if (holders == 0) return null
        holders -= 1
        if (holders > 0) return null
        val saved = before ?: return null
        before = null
        return Change(saved.secure, saved.dropsObscuredTouches, hideOverlays = false)
    }

    /** A new window for the screen -- the activity was recreated -- while protected. */
    fun reattach(current: WindowState): Change? {
        if (holders == 0) return null
        before = current
        return PROTECTED
    }

    companion object {
        val PROTECTED = Change(secure = true, dropsObscuredTouches = true, hideOverlays = true)
    }
}
