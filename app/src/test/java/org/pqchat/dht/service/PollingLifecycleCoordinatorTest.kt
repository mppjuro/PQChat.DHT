package org.pqchat.dht.service

import android.content.Intent
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import androidx.room.Room
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.pqchat.dht.data.db.AppDatabase
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.traffic.AdaptivePollingManager.PollingState
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.security.Security

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PollingLifecycleCoordinatorTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupClass() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private class TestLifecycleOwner(initialState: Lifecycle.State = Lifecycle.State.STARTED) : LifecycleOwner {
        val registry = LifecycleRegistry(this)
        init {
            registry.currentState = initialState
        }
        override val lifecycle: Lifecycle get() = registry
    }

    private var db: AppDatabase? = null
    private var dhtLeafNode: org.pqchat.dht.dht.leaf.DhtLeafNode? = null
    private var scheduler: PollingScheduler? = null
    private var coordinator: PollingLifecycleCoordinator? = null

    @Before
    fun setUp() {
        val context = RuntimeEnvironment.getApplication()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dhtLeafNode = org.pqchat.dht.dht.leaf.DhtLeafNode()
        val repo = ChatRepository(db!!, dhtLeafNode!!)
        val settings = AppSettingsManager(context)
        scheduler = PollingScheduler(context, repo, dhtLeafNode, settings)
    }

    @After
    fun tearDown() {
        coordinator?.stop()
        scheduler?.stop()
        dhtLeafNode?.stop()
        db?.close()
    }

    @Test
    fun testInitialStartEvaluatesForegroundState() {
        val context = RuntimeEnvironment.getApplication()
        val testOwner = TestLifecycleOwner(Lifecycle.State.STARTED)

        coordinator = PollingLifecycleCoordinator(context, scheduler!!, testOwner)
        coordinator!!.start()

        assertTrue("App foreground input should be true when started in STARTED state", scheduler!!.pollingManager.isAppForeground)
        assertEquals("Initial state should be APP_ACTIVE_OTHER", PollingState.APP_ACTIVE_OTHER, scheduler!!.pollingManager.currentState.value)
    }

    @Test
    fun testLifecycleTransitionsBetweenForegroundAndBackground() {
        val context = RuntimeEnvironment.getApplication()
        val testOwner = TestLifecycleOwner(Lifecycle.State.STARTED)

        coordinator = PollingLifecycleCoordinator(context, scheduler!!, testOwner)
        coordinator!!.start()
        assertEquals(PollingState.APP_ACTIVE_OTHER, scheduler!!.pollingManager.currentState.value)

        // Process moves to background (onStop)
        testOwner.registry.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
        assertFalse("App foreground input must become false on ON_STOP", scheduler!!.pollingManager.isAppForeground)
        assertEquals("State must become BACKGROUND_IDLE on ON_STOP (screen ON)", PollingState.BACKGROUND_IDLE, scheduler!!.pollingManager.currentState.value)

        // Process returns to foreground (onStart)
        testOwner.registry.handleLifecycleEvent(Lifecycle.Event.ON_START)
        assertTrue("App foreground input must become true on ON_START", scheduler!!.pollingManager.isAppForeground)
        assertEquals("State must return to APP_ACTIVE_OTHER on ON_START", PollingState.APP_ACTIVE_OTHER, scheduler!!.pollingManager.currentState.value)
    }

    @Test
    fun testLifecycleTransitionsPreserveActiveChat() {
        val context = RuntimeEnvironment.getApplication()
        val testOwner = TestLifecycleOwner(Lifecycle.State.STARTED)

        coordinator = PollingLifecycleCoordinator(context, scheduler!!, testOwner)
        coordinator!!.start()

        // User opens chat
        scheduler!!.onChatOpened("alice")
        assertEquals(PollingState.FOREGROUND_CHAT, scheduler!!.pollingManager.currentState.value)

        // User minimizes app
        testOwner.registry.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
        assertEquals(PollingState.BACKGROUND_IDLE, scheduler!!.pollingManager.currentState.value)
        assertEquals("alice", scheduler!!.pollingManager.activeChatContactId)

        // User restores app
        testOwner.registry.handleLifecycleEvent(Lifecycle.Event.ON_START)
        assertEquals(PollingState.FOREGROUND_CHAT, scheduler!!.pollingManager.currentState.value)
        assertEquals("alice", scheduler!!.pollingManager.activeChatContactId)
    }

    @Test
    fun testScreenOffAndOnEventsDriveStateTransitions() {
        val context = RuntimeEnvironment.getApplication()
        val testOwner = TestLifecycleOwner(Lifecycle.State.STARTED)

        coordinator = PollingLifecycleCoordinator(context, scheduler!!, testOwner)
        coordinator!!.start()
        scheduler!!.onChatOpened("bob")
        assertEquals(PollingState.FOREGROUND_CHAT, scheduler!!.pollingManager.currentState.value)

        // Screen turned off
        coordinator!!.notifyScreenOff()
        assertEquals(PollingState.DOZE_SLEEP, scheduler!!.pollingManager.currentState.value)
        assertFalse("isScreenInteractive must be false", scheduler!!.pollingManager.isScreenInteractive)

        // Screen turned on
        coordinator!!.notifyScreenOn()
        assertTrue("isScreenInteractive must be true", scheduler!!.pollingManager.isScreenInteractive)
        assertEquals(PollingState.FOREGROUND_CHAT, scheduler!!.pollingManager.currentState.value)
    }

    @Test
    fun testScreenOffWhileMinimizedTransitionsToDozeSleep() {
        val context = RuntimeEnvironment.getApplication()
        val testOwner = TestLifecycleOwner(Lifecycle.State.STARTED)

        coordinator = PollingLifecycleCoordinator(context, scheduler!!, testOwner)
        coordinator!!.start()

        // App minimized
        testOwner.registry.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
        assertEquals(PollingState.BACKGROUND_IDLE, scheduler!!.pollingManager.currentState.value)

        // Screen turned off
        coordinator!!.notifyScreenOff()
        assertEquals(PollingState.DOZE_SLEEP, scheduler!!.pollingManager.currentState.value)

        // Screen turned on while app is still minimized
        coordinator!!.notifyScreenOn()
        assertEquals(PollingState.BACKGROUND_IDLE, scheduler!!.pollingManager.currentState.value)
    }
}
