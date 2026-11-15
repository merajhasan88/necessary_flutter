package com.meraj.necessary

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.view.KeyEvent
import android.view.KeyboardShortcutGroup
import android.view.Menu
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityNodeProvider

/**
 * Watches one activity for TouchCounts: every touch and key passes through the window's callback,
 * and every click its screen reports to Accessibility through the content view's delegate. Both
 * hand every call on, unchanged, to what was there before, and are put back on detach; one that
 * something else has since wrapped stays in place and stops counting.
 */
internal class TouchWatch private constructor(
    private val window: Window,
    private val callback: CountingCallback,
    private val content: ViewGroup?,
    private val delegate: CountingDelegate?,
    private val counts: TouchCounts,
) {
    fun detach() {
        callback.counting = false
        if (window.callback === callback) window.callback = callback.inner
        if (content != null && delegate != null) {
            delegate.counting = false
            if (readDelegate(content).getOrNull()?.value === delegate) content.accessibilityDelegate = delegate.inner
        }
        counts.watchStopped()
    }

    companion object {
        /**
         * Starts watching [activity]. The clicks are watched only where the content view's own
         * delegate can be read, so that it is kept; TouchCounts then leaves them out.
         */
        fun attach(activity: Activity, counts: TouchCounts): TouchWatch? {
            val window = activity.window ?: return null
            val original = window.callback ?: return null
            val callback = CountingCallback(original, counts)
            window.callback = callback
            val content = activity.findViewById<ViewGroup>(android.R.id.content)
            val delegate = content?.let { view ->
                readDelegate(view).getOrNull()?.let { CountingDelegate(it.value, counts) }
            }
            if (content != null && delegate != null) content.accessibilityDelegate = delegate
            counts.watchStarted(clicks = delegate != null)
            return TouchWatch(window, callback, content, delegate, counts)
        }

        private class Held(val value: View.AccessibilityDelegate?)

        /**
         * The view's own delegate, which a view gives from Android 10; before, read from its
         * field as AndroidX does. A failure to read it is a failure: no delegate is set over one
         * that might be there.
         */
        private fun readDelegate(view: View): Result<Held> = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                Held(view.accessibilityDelegate)
            } else {
                val field = View::class.java.getDeclaredField("mAccessibilityDelegate")
                field.isAccessible = true
                Held(field.get(view) as View.AccessibilityDelegate?)
            }
        }
    }

    class CountingCallback(val inner: Window.Callback, private val counts: TouchCounts) :
        Window.Callback by inner {
        @Volatile var counting = true

        override fun dispatchTouchEvent(event: MotionEvent?): Boolean {
            if (counting && event != null) {
                counts.onTouch(event.actionMasked, event.flags, event.getToolType(0))
            }
            return inner.dispatchTouchEvent(event)
        }

        override fun dispatchKeyEvent(event: KeyEvent?): Boolean {
            if (counting && event != null) counts.onKey(event.flags)
            return inner.dispatchKeyEvent(event)
        }

        // The interface's two default methods, handed on as every other is.
        override fun onProvideKeyboardShortcuts(data: MutableList<KeyboardShortcutGroup>?, menu: Menu?, deviceId: Int) =
            inner.onProvideKeyboardShortcuts(data, menu, deviceId)

        override fun onPointerCaptureChanged(hasCapture: Boolean) = inner.onPointerCaptureChanged(hasCapture)
    }

    /** Counts the clicks; every call goes on to the delegate that was there, or to the view's own. */
    class CountingDelegate(val inner: View.AccessibilityDelegate?, private val counts: TouchCounts) :
        View.AccessibilityDelegate() {
        @Volatile var counting = true

        override fun onRequestSendAccessibilityEvent(host: ViewGroup, child: View, event: AccessibilityEvent): Boolean {
            val type = event.eventType
            if (counting && (type == AccessibilityEvent.TYPE_VIEW_CLICKED ||
                    type == AccessibilityEvent.TYPE_VIEW_LONG_CLICKED)) {
                counts.onClick()
            }
            return inner?.onRequestSendAccessibilityEvent(host, child, event)
                ?: super.onRequestSendAccessibilityEvent(host, child, event)
        }

        override fun sendAccessibilityEvent(host: View, eventType: Int) {
            inner?.sendAccessibilityEvent(host, eventType) ?: super.sendAccessibilityEvent(host, eventType)
        }

        override fun sendAccessibilityEventUnchecked(host: View, event: AccessibilityEvent) {
            inner?.sendAccessibilityEventUnchecked(host, event) ?: super.sendAccessibilityEventUnchecked(host, event)
        }

        override fun dispatchPopulateAccessibilityEvent(host: View, event: AccessibilityEvent): Boolean =
            inner?.dispatchPopulateAccessibilityEvent(host, event)
                ?: super.dispatchPopulateAccessibilityEvent(host, event)

        override fun onPopulateAccessibilityEvent(host: View, event: AccessibilityEvent) {
            inner?.onPopulateAccessibilityEvent(host, event) ?: super.onPopulateAccessibilityEvent(host, event)
        }

        override fun onInitializeAccessibilityEvent(host: View, event: AccessibilityEvent) {
            inner?.onInitializeAccessibilityEvent(host, event) ?: super.onInitializeAccessibilityEvent(host, event)
        }

        override fun onInitializeAccessibilityNodeInfo(host: View, info: AccessibilityNodeInfo) {
            inner?.onInitializeAccessibilityNodeInfo(host, info) ?: super.onInitializeAccessibilityNodeInfo(host, info)
        }

        override fun addExtraDataToAccessibilityNodeInfo(
            host: View, info: AccessibilityNodeInfo, extraDataKey: String, arguments: Bundle?,
        ) {
            inner?.addExtraDataToAccessibilityNodeInfo(host, info, extraDataKey, arguments)
                ?: super.addExtraDataToAccessibilityNodeInfo(host, info, extraDataKey, arguments)
        }

        override fun getAccessibilityNodeProvider(host: View): AccessibilityNodeProvider? =
            if (inner != null) inner.getAccessibilityNodeProvider(host) else super.getAccessibilityNodeProvider(host)

        override fun performAccessibilityAction(host: View, action: Int, args: Bundle?): Boolean =
            inner?.performAccessibilityAction(host, action, args) ?: super.performAccessibilityAction(host, action, args)
    }
}
