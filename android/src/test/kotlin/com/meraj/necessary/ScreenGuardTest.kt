package com.meraj.necessary

import com.meraj.necessary.ScreenGuard.Change
import com.meraj.necessary.ScreenGuard.WindowState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Screen protection respects its host (the plugin proposal's section 4): it
 * records the window before changing it, counts overlapping callers, and puts
 * back only what it found when the last one finishes.
 */
class ScreenGuardTest {

    private val plain = WindowState(secure = false, dropsObscuredTouches = false)
    private val hostSecure = WindowState(secure = true, dropsObscuredTouches = false)

    @Test fun theLastReleasePutsBackWhatTheHostHad() {
        val guard = ScreenGuard()
        assertEquals(ScreenGuard.PROTECTED, guard.acquire(hostSecure))
        assertEquals(Change(secure = true, dropsObscuredTouches = false, hideOverlays = false), guard.release())
        assertFalse(guard.held)
    }

    @Test fun overlappingCallersAreCounted() {
        val guard = ScreenGuard()
        assertEquals(ScreenGuard.PROTECTED, guard.acquire(plain))
        assertNull(guard.acquire(plain))
        assertNull(guard.release())
        assertTrue(guard.held)
        assertEquals(Change(secure = false, dropsObscuredTouches = false, hideOverlays = false), guard.release())
        assertFalse(guard.held)
    }

    @Test fun anExtraReleaseChangesNothing() {
        val guard = ScreenGuard()
        assertNull(guard.release())
        guard.acquire(plain)
        guard.release()
        assertNull(guard.release())
        assertEquals(ScreenGuard.PROTECTED, guard.acquire(plain))
    }

    @Test fun aRecreatedWindowIsProtectedAndPutBackAsItCame() {
        val guard = ScreenGuard()
        assertNull(guard.reattach(plain))
        guard.acquire(plain)
        assertEquals(ScreenGuard.PROTECTED, guard.reattach(hostSecure))
        assertEquals(Change(secure = true, dropsObscuredTouches = false, hideOverlays = false), guard.release())
    }
}
