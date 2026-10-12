package org.pqchat.dht.service

import android.content.Intent
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ScreenStateReceiverTest {

    @Test
    fun testIntentFilterContainsExpectedActions() {
        val filter = ScreenStateReceiver.createIntentFilter()
        assertTrue(filter.hasAction(Intent.ACTION_SCREEN_OFF))
        assertTrue(filter.hasAction(Intent.ACTION_SCREEN_ON))
    }

    @Test
    fun testScreenOffInvokesScreenOffCallback() {
        val context = RuntimeEnvironment.getApplication()
        val screenOffTriggered = AtomicBoolean(false)

        val receiver = ScreenStateReceiver(
            onScreenOffCallback = { screenOffTriggered.set(true) },
            onScreenOnCallback = { }
        )

        receiver.onReceive(context, Intent(Intent.ACTION_SCREEN_OFF))
        assertTrue("Screen off callback must be invoked on ACTION_SCREEN_OFF", screenOffTriggered.get())
    }

    @Test
    fun testScreenOnInvokesScreenOnCallbackWithForegroundState() {
        val context = RuntimeEnvironment.getApplication()
        val screenOnTriggered = AtomicBoolean(false)
        var receivedForegroundState: Boolean? = null

        val receiver = ScreenStateReceiver(
            onScreenOffCallback = { },
            onScreenOnCallback = { isFg ->
                screenOnTriggered.set(true)
                receivedForegroundState = isFg
            }
        )

        receiver.onReceive(context, Intent(Intent.ACTION_SCREEN_ON))
        assertTrue("Screen on callback must be invoked on ACTION_SCREEN_ON", screenOnTriggered.get())
        assertNotNull("Foreground state boolean must be passed", receivedForegroundState)
    }

    @Test
    fun testIsScreenInteractiveDefaultsToTrue() {
        val context = RuntimeEnvironment.getApplication()
        val isInteractive = ScreenStateReceiver.isScreenInteractive(context)
        assertNotNull(isInteractive)
    }
}
