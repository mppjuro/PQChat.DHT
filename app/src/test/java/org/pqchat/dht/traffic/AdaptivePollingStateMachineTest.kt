package org.pqchat.dht.traffic

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.pqchat.dht.traffic.AdaptivePollingManager.PollingState

/**
 * Pure state machine unit tests for AdaptivePollingManager.
 *
 * Requirements:
 * - Deterministic, instantaneous transitions without Thread.sleep or delay() calls.
 * - Full verification of the 4-state lifecycle model defined in AGENTS.md Section 6.
 * - Verification that minimizing an Activity (ON_STOP) while the device screen is ON
 *   maps strictly to BACKGROUND_IDLE (5m), NOT DOZE_SLEEP (15m).
 * - Verification that device screen off maps strictly to DOZE_SLEEP (15m).
 */
class AdaptivePollingStateMachineTest {

    private var manager: AdaptivePollingManager? = null

    @Before
    fun setUp() {
        manager = AdaptivePollingManager(onPollRequested = {})
    }

    @After
    fun tearDown() {
        manager?.stop()
    }

    @Test
    fun testResolvePollingState_truthTable() {
        // 1. Screen OFF (!isScreenInteractive) -> ALWAYS DOZE_SLEEP
        assertEquals(
            PollingState.DOZE_SLEEP,
            AdaptivePollingManager.resolvePollingState(isScreenInteractive = false, isAppForeground = false, activeChatContactId = null)
        )
        assertEquals(
            PollingState.DOZE_SLEEP,
            AdaptivePollingManager.resolvePollingState(isScreenInteractive = false, isAppForeground = false, activeChatContactId = "alice")
        )
        assertEquals(
            PollingState.DOZE_SLEEP,
            AdaptivePollingManager.resolvePollingState(isScreenInteractive = false, isAppForeground = true, activeChatContactId = null)
        )
        assertEquals(
            PollingState.DOZE_SLEEP,
            AdaptivePollingManager.resolvePollingState(isScreenInteractive = false, isAppForeground = true, activeChatContactId = "alice")
        )

        // 2. Screen ON, App in background (!isAppForeground) -> ALWAYS BACKGROUND_IDLE (5 min)
        assertEquals(
            PollingState.BACKGROUND_IDLE,
            AdaptivePollingManager.resolvePollingState(isScreenInteractive = true, isAppForeground = false, activeChatContactId = null)
        )
        assertEquals(
            PollingState.BACKGROUND_IDLE,
            AdaptivePollingManager.resolvePollingState(isScreenInteractive = true, isAppForeground = false, activeChatContactId = "alice")
        )

        // 3. Screen ON, App in foreground, No active chat -> APP_ACTIVE_OTHER (1 min)
        assertEquals(
            PollingState.APP_ACTIVE_OTHER,
            AdaptivePollingManager.resolvePollingState(isScreenInteractive = true, isAppForeground = true, activeChatContactId = null)
        )

        // 4. Screen ON, App in foreground, Active chat -> FOREGROUND_CHAT (10 sec)
        assertEquals(
            PollingState.FOREGROUND_CHAT,
            AdaptivePollingManager.resolvePollingState(isScreenInteractive = true, isAppForeground = true, activeChatContactId = "alice")
        )
    }

    @Test
    fun testInitialStateIsAppActiveOther() {
        val m = manager!!
        assertTrue("Initial screen interactive state must be true", m.isScreenInteractive)
        assertTrue("Initial app foreground state must be true", m.isAppForeground)
        assertNull("Initial active chat must be null", m.activeChatContactId)
        assertEquals("Initial polling state must be APP_ACTIVE_OTHER", PollingState.APP_ACTIVE_OTHER, m.currentState.value)
    }

    @Test
    fun testActiveChatOpenAndCloseTransitions() {
        val m = manager!!

        // Open chat with Bob
        m.onChatOpened("bob")
        assertEquals(PollingState.FOREGROUND_CHAT, m.currentState.value)
        assertEquals("bob", m.activeChatContactId)

        // Switch to Charlie
        m.onChatOpened("charlie")
        assertEquals(PollingState.FOREGROUND_CHAT, m.currentState.value)
        assertEquals("charlie", m.activeChatContactId)

        // Close chat
        m.onChatClosed()
        assertEquals(PollingState.APP_ACTIVE_OTHER, m.currentState.value)
        assertNull(m.activeChatContactId)
    }

    @Test
    fun testAppMinimizationWithScreenOnMapsToBackgroundIdleNotDozeSleep() {
        val m = manager!!

        // App is minimized (e.g. user taps Home button or switches app while screen is ON)
        m.onAppMinimized()

        assertTrue("Screen should remain interactive", m.isScreenInteractive)
        assertEquals("State must be BACKGROUND_IDLE, NEVER DOZE_SLEEP", PollingState.BACKGROUND_IDLE, m.currentState.value)

        // Return to foreground
        m.onAppForegrounded()
        assertEquals("Returning to foreground must transition to APP_ACTIVE_OTHER", PollingState.APP_ACTIVE_OTHER, m.currentState.value)
    }

    @Test
    fun testAppMinimizationWhileInActiveChatPreservesChatTargetOnReturn() {
        val m = manager!!

        m.onChatOpened("alice")
        assertEquals(PollingState.FOREGROUND_CHAT, m.currentState.value)

        // User leaves app to home screen (screen stays on)
        m.onAppMinimized()
        assertEquals(PollingState.BACKGROUND_IDLE, m.currentState.value)
        assertEquals("alice", m.activeChatContactId)

        // User switches back to PQChat
        m.onAppForegrounded()
        assertEquals("Must return directly to FOREGROUND_CHAT because Alice was active", PollingState.FOREGROUND_CHAT, m.currentState.value)
        assertEquals("alice", m.activeChatContactId)
    }

    @Test
    fun testScreenOffWhileInActiveChatTransitionsToDozeSleepAndRestoresOnScreenOn() {
        val m = manager!!

        m.onChatOpened("alice")
        assertEquals(PollingState.FOREGROUND_CHAT, m.currentState.value)

        // User locks phone while looking at chat
        m.onDeviceScreenOff()
        assertEquals(PollingState.DOZE_SLEEP, m.currentState.value)
        assertEquals("alice", m.activeChatContactId)

        // User turns screen back on
        m.onDeviceScreenOn()
        assertEquals(PollingState.FOREGROUND_CHAT, m.currentState.value)
        assertEquals("alice", m.activeChatContactId)
    }

    @Test
    fun testScreenOffWhileMinimizedTransitionsToDozeSleepAndRestoresToBackgroundIdle() {
        val m = manager!!

        m.onAppMinimized()
        assertEquals(PollingState.BACKGROUND_IDLE, m.currentState.value)

        // Screen turns off while in background
        m.onDeviceScreenOff()
        assertEquals(PollingState.DOZE_SLEEP, m.currentState.value)

        // Screen turns on, but user did not reopen app (still on lockscreen/other app)
        m.onDeviceScreenOn()
        assertEquals("Must transition to BACKGROUND_IDLE because app is still minimized", PollingState.BACKGROUND_IDLE, m.currentState.value)

        // Now user reopens app
        m.onAppForegrounded()
        assertEquals(PollingState.APP_ACTIVE_OTHER, m.currentState.value)
    }

    @Test
    fun testSetScreenInteractiveAndSetAppForegroundDirectly() {
        val m = manager!!

        m.setScreenInteractive(false)
        assertEquals(PollingState.DOZE_SLEEP, m.currentState.value)

        m.setAppForeground(false)
        assertEquals(PollingState.DOZE_SLEEP, m.currentState.value)

        m.setScreenInteractive(true)
        assertEquals(PollingState.BACKGROUND_IDLE, m.currentState.value)

        m.setAppForeground(true)
        assertEquals(PollingState.APP_ACTIVE_OTHER, m.currentState.value)
    }

    @Test
    fun testUpdateInputsAtomically() {
        val m = manager!!

        val state1 = m.updateInputs(
            isScreenInteractive = false,
            isAppForeground = false,
            activeChatContactId = "bob"
        )
        assertEquals(PollingState.DOZE_SLEEP, state1)
        assertEquals(PollingState.DOZE_SLEEP, m.currentState.value)

        val state2 = m.updateInputs(
            isScreenInteractive = true,
            isAppForeground = false,
            activeChatContactId = "bob"
        )
        assertEquals(PollingState.BACKGROUND_IDLE, state2)
        assertEquals(PollingState.BACKGROUND_IDLE, m.currentState.value)

        val state3 = m.updateInputs(
            isScreenInteractive = true,
            isAppForeground = true,
            activeChatContactId = "bob"
        )
        assertEquals(PollingState.FOREGROUND_CHAT, state3)
        assertEquals(PollingState.FOREGROUND_CHAT, m.currentState.value)

        val state4 = m.updateInputs(
            isScreenInteractive = true,
            isAppForeground = true,
            activeChatContactId = null
        )
        assertEquals(PollingState.APP_ACTIVE_OTHER, state4)
        assertEquals(PollingState.APP_ACTIVE_OTHER, m.currentState.value)
    }

    @Test(timeout = 1000)
    fun testRapidTransitionsExecuteWithoutDelaysOrBlocking() {
        val m = manager!!
        val start = System.currentTimeMillis()

        repeat(500) {
            m.onChatOpened("user_$it")
            m.onAppMinimized()
            m.onDeviceScreenOff()
            m.onDeviceScreenOn()
            m.onAppForegrounded()
            m.onChatClosed()
        }

        val elapsed = System.currentTimeMillis() - start
        assertTrue("500 full state transition cycles should execute instantaneously (< 500ms), took ${elapsed}ms", elapsed < 500)
    }
}
