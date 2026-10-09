package org.pqchat.dht.traffic

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdaptivePollingManagerTest {

    private var manager: AdaptivePollingManager? = null

    @After
    fun tearDown() {
        manager?.stop()
    }

    @Test
    fun testInitialState_isSyncingIsTrue() {
        val pollGate = CompletableDeferred<Unit>()
        manager = AdaptivePollingManager {
            pollGate.await()
        }

        // Before any event or while first poll is ongoing, isSyncing must be true
        assertTrue("isSyncing should initially be true", manager!!.isSyncing.value)
    }

    @Test
    fun testSyncFinishes_isSyncingBecomesFalseAndCountdownStarts() = runBlocking {
        val pollGate = CompletableDeferred<Unit>()
        manager = AdaptivePollingManager {
            pollGate.await()
        }

        manager!!.onAppForegrounded()
        assertTrue("isSyncing should be true while poll is ongoing", manager!!.isSyncing.value)

        // Allow poll to finish
        pollGate.complete(Unit)

        // Wait briefly for finally block to execute
        var waited = 0
        while (manager!!.isSyncing.value && waited < 2000) {
            delay(50)
            waited += 50
        }

        assertFalse("isSyncing should become false after poll finishes", manager!!.isSyncing.value)
        assertTrue("nextPollInMs should be > 0", manager!!.nextPollInMs.value > 0L)
    }

    @Test
    fun testUpdateIntervals_doesNotCancelInFlightSync() = runBlocking {
        val pollGate = CompletableDeferred<Unit>()
        var pollCallCount = 0

        manager = AdaptivePollingManager {
            pollCallCount++
            pollGate.await()
        }

        manager!!.onAppForegrounded()
        // Immediately update intervals (as happens in ChatViewModel.init)
        manager!!.updateIntervals(
            foreground = 5_000L,
            appActive = 30_000L,
            bgIdle = 100_000L,
            doze = 500_000L
        )

        delay(100)
        // isSyncing should STILL be true! It must not have been cancelled and set to false!
        assertTrue("isSyncing should remain true during in-flight poll despite updateIntervals", manager!!.isSyncing.value)
        assertEquals("Poll should have been called once and not restarted", 1, pollCallCount)

        // Complete the poll
        pollGate.complete(Unit)
        var waited = 0
        while (manager!!.isSyncing.value && waited < 2000) {
            delay(50)
            waited += 50
        }
        assertFalse("isSyncing should become false after poll finishes", manager!!.isSyncing.value)
    }

    @Test
    fun testTriggerImmediatePoll_forcesSync() = runBlocking {
        var pollCallCount = 0
        val gate1 = CompletableDeferred<Unit>()
        val gate2 = CompletableDeferred<Unit>()

        manager = AdaptivePollingManager {
            pollCallCount++
            if (pollCallCount == 1) {
                gate1.await()
            } else {
                gate2.await()
            }
        }

        manager!!.onAppForegrounded()
        gate1.complete(Unit)

        var waited = 0
        while (manager!!.isSyncing.value && waited < 2000) {
            delay(50)
            waited += 50
        }
        assertFalse(manager!!.isSyncing.value)

        // Trigger immediate poll
        manager!!.triggerImmediatePoll()
        assertTrue("isSyncing should be true immediately after triggerImmediatePoll", manager!!.isSyncing.value)

        gate2.complete(Unit)
        waited = 0
        while (manager!!.isSyncing.value && waited < 2000) {
            delay(50)
            waited += 50
        }
        assertFalse(manager!!.isSyncing.value)
        assertEquals(2, pollCallCount)
    }

    @Test
    fun testScreenChangeRecalculatesIntervalWithoutImmediateSync() = runBlocking {
        var pollCallCount = 0
        val gate1 = CompletableDeferred<Unit>()

        manager = AdaptivePollingManager {
            pollCallCount++
            if (pollCallCount == 1) {
                gate1.await()
            }
        }
        manager!!.intervalForegroundChatMs = 10_000L
        manager!!.intervalAppActiveMs = 60_000L

        manager!!.onAppForegrounded()
        var waited = 0
        while (pollCallCount == 0 && waited < 2000) {
            delay(20)
            waited += 20
        }
        assertEquals(1, pollCallCount)

        // Complete the first poll (in App Active, interval 60s)
        gate1.complete(Unit)
        waited = 0
        while (manager!!.isSyncing.value && waited < 2000) {
            delay(50)
            waited += 50
        }
        assertFalse(manager!!.isSyncing.value)

        // User opens chat right after poll finished (time elapsed < 10s foreground interval)
        manager!!.onChatOpened("contact_bob")

        delay(100)
        // Should NOT trigger immediate poll because elapsed time is well below 10s!
        assertEquals("Changing screen should NOT immediately sync if time hasn't elapsed", 1, pollCallCount)
        assertTrue("Countdown should be adjusted to new interval", manager!!.nextPollInMs.value in 1L..(10_000L * (1.0 + manager!!.jitterRatio)).toLong())
    }

    @Test
    fun testTriggerImmediatePoll_inDozeSleep_executesPollAndResetsIsSyncing() = runBlocking {
        var pollCallCount = 0
        val gate = CompletableDeferred<Unit>()

        manager = AdaptivePollingManager {
            pollCallCount++
            gate.await()
        }

        manager!!.onDeviceScreenOff()
        assertEquals(AdaptivePollingManager.PollingState.DOZE_SLEEP, manager!!.currentState.value)
        assertFalse("isSyncing should be false in DOZE_SLEEP", manager!!.isSyncing.value)

        // Trigger immediate poll while in DOZE_SLEEP
        manager!!.triggerImmediatePoll()
        assertTrue("isSyncing should be true after triggering immediate poll in Doze", manager!!.isSyncing.value)

        // Complete the poll
        gate.complete(Unit)

        var waited = 0
        while (manager!!.isSyncing.value && waited < 2000) {
            delay(50)
            waited += 50
        }

        assertFalse("isSyncing must be reset to false after Doze poll finishes", manager!!.isSyncing.value)
        assertEquals("Poll should have been executed once", 1, pollCallCount)
    }

    @Test
    fun testTriggerImmediatePoll_inDozeSleep_unresponsiveNetworkTimesOutAndResetsIsSyncing() = runBlocking {
        manager = AdaptivePollingManager {
            // Simulate unresponsive network that never responds
            delay(10_000L)
        }
        manager!!.immediatePollTimeoutMs = 150L // short timeout for test

        manager!!.onDeviceScreenOff()
        assertEquals(AdaptivePollingManager.PollingState.DOZE_SLEEP, manager!!.currentState.value)
        assertFalse(manager!!.isSyncing.value)

        manager!!.triggerImmediatePoll()
        assertTrue("isSyncing should be true immediately after trigger", manager!!.isSyncing.value)

        // Wait for timeout to fire (150ms + margin)
        var waited = 0
        while (manager!!.isSyncing.value && waited < 2000) {
            delay(50)
            waited += 50
        }

        assertFalse("isSyncing must be reset to false after timeout, preventing infinite spinner hang", manager!!.isSyncing.value)
    }
}
