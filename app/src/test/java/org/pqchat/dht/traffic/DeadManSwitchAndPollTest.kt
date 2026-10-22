package org.pqchat.dht.traffic

import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.FakeDht
import java.security.Security

class DeadManSwitchAndPollTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupProviders() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private lateinit var fakeDht: FakeDht

    @Before
    fun setUp() {
        fakeDht = FakeDht()
        fakeDht.start()
        PollingWorker.clearRepublishTasks()
        BlindRepublishPool.defaultInstance.clear()
        DecoyTargetPool.defaultInstance.clear()
    }

    @After
    fun tearDown() {
        fakeDht.stop()
        PollingWorker.clearRepublishTasks()
    }

    @Test
    fun testDeadManSwitchExpirationAndCheckInLogic() = runBlocking {
        val settings = AppSettingsManager(context = null, sharedPreferences = null)

        // 1. By default, disabled
        assertFalse(settings.isDeadManSwitchEnabled.value)
        assertFalse("Disabled switch must never report expired", settings.isDeadManSwitchExpired())

        // 2. Enable Dead Man's Switch with 24h timeout
        settings.setDeadManSwitchEnabled(true)
        settings.setDeadManSwitchTimeoutHours(24)
        assertEquals(24, settings.deadManSwitchTimeoutHours.value)
        assertTrue(settings.isDeadManSwitchEnabled.value)

        // Initially, activity is set to currentTimeMillis, so not expired
        assertFalse(settings.isDeadManSwitchExpired())

        // 3. User check-in records activity
        settings.recordUserActivity()
        val activityTime = settings.lastUserActivityTimestamp.value
        assertTrue("Activity time should be recent", activityTime > 0L)
        assertFalse(settings.isDeadManSwitchExpired())

        // 4. Test trusted contacts management
        val contactA = "contact-alice-123"
        val contactB = "contact-bob-456"

        settings.addDeadManTrustedContactId(contactA)
        assertTrue(settings.deadManTrustedContactIds.value.contains(contactA))

        settings.addDeadManTrustedContactId(contactB)
        assertEquals(2, settings.deadManTrustedContactIds.value.size)

        settings.removeDeadManTrustedContactId(contactA)
        assertFalse(settings.deadManTrustedContactIds.value.contains(contactA))
        assertTrue(settings.deadManTrustedContactIds.value.contains(contactB))

        // 5. Test emergency note
        val customNote = "Severe emergency - unlock secure vault"
        settings.setDeadManEmergencyNote(customNote)
        assertEquals(customNote, settings.deadManEmergencyNote.value)

        // 6. Test canary triggered flag
        assertFalse(settings.isCanaryTriggered.value)
        settings.setCanaryTriggered(true)
        assertTrue(settings.isCanaryTriggered.value)
        settings.setCanaryTriggered(false)
        assertFalse(settings.isCanaryTriggered.value)
    }

    @Test
    fun testPoissonTrafficGeneratorSubstitutesCanaryForDummyCover() = runBlocking {
        val generator = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            pendingAckQueue = PendingAckQueue(),
            blindRepublishPool = BlindRepublishPool(maxCapacity = 10),
            crowdsourcedRepublishEnabledProvider = { false }
        )

        val target = CryptoUtils.secureRandomBytes(20)
        val canaryPayload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.TOTAL_FRAME_SIZE) // 900 bytes
        val sk = CryptoUtils.secureRandomBytes(32)

        var canaryDelivered = false
        val canaryFrame = OutboundPoissonFrame(
            target = target,
            payload = canaryPayload,
            seq = 1L,
            salt = null,
            sk = sk,
            skipLocalStore = false,
            seqNum = 7,
            contactId = "trusted-partner",
            timestamp = System.currentTimeMillis(),
            packetClass = PacketClass.URGENT_CONTROL,
            onSent = { ok ->
                canaryDelivered = ok
            }
        )

        // Hook safety canary provider that returns the canary frame on first pull, then null
        var frameConsumed = false
        generator.safetyCanaryProvider = {
            if (!frameConsumed) {
                frameConsumed = true
                canaryFrame
            } else {
                null
            }
        }

        // Execute cover traffic tick: with no ACKs and crowdsourced disabled, it calls emitDummyCover
        val event = generator.processCoverTrafficTick(delayMs = 3000L)

        // Verify that the packet put to the DHT was the exact canary frame!
        assertEquals(1, fakeDht.putCalls.get())
        assertEquals(0, fakeDht.coverTrafficCalls.get())
        assertTrue("Callback onSent must be called", canaryDelivered)

        val stored = fakeDht.getMutable(target)
        assertNotNull("Canary frame must be stored in DHT", stored)
        assertArrayEquals("Payload in DHT must match canary payload", canaryPayload, stored!!.v)
        assertEquals(1L, stored.seq)

        assertEquals(CryptoUtils.toHex(target), event.targetHex)
        assertFalse("Must not be labeled as ACK", event.isAck)
        assertFalse("Must not be labeled as blind republish", event.isBlindRepublish)
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, event.payloadSize)

        // Next tick: canary has been consumed, so generator emits synthetic CSPRNG noise
        val nextEvent = generator.processCoverTrafficTick(delayMs = 4000L)
        assertEquals(1, fakeDht.coverTrafficCalls.get())
        assertEquals(BinaryFrameCodec.TOTAL_FRAME_SIZE, nextEvent.payloadSize)
    }
}
