package org.pqchat.dht.ui

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.bouncycastle.jce.provider.BouncyCastleProvider
import androidx.room.Room
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.jupiter.api.Tag
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.crypto.KeystoreCrypto
import org.pqchat.dht.data.db.AppDatabase
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.bencode.Bencode
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.HandshakeManager
import org.pqchat.dht.ui.viewmodel.BobHandshakeStatus
import org.pqchat.dht.ui.viewmodel.ChatViewModel
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.security.Security
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import javax.crypto.spec.SecretKeySpec

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
@Tag("slow")
class BobHandshakeStatusTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private val testMasterKey = SecretKeySpec(ByteArray(32) { (it * 13 + 5).toByte() }, "AES")
    private var testDb: AppDatabase? = null

    @Before
    fun setUp() {
        KeystoreCrypto.setTestSecretKey(testMasterKey)
        val context = RuntimeEnvironment.getApplication()
        testDb = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
    }

    @After
    fun tearDown() {
        testDb?.close()
        testDb = null
        KeystoreCrypto.resetForTesting()
    }

    private class FakeDhtLeafNode(
        var dropProbability: Double = 0.0
    ) : DhtLeafNode(autoBootstrap = false) {
        val networkStorage = ConcurrentHashMap<String, MutableItem>()
        var putCallCount = 0
        var getCallCount = 0

        override fun start() {}
        override fun stop() {}
        override suspend fun preWarmTarget(target: ByteArray): List<DhtPeer> = emptyList()
        override fun setAdaptiveK(isMobileOrCgnat: Boolean) {}

        override suspend fun putMutable(
            target: ByteArray,
            v: ByteArray,
            seq: Long,
            salt: ByteArray?,
            sk: ByteArray,
            skipLocalStore: Boolean
        ): Boolean {
            putCallCount++
            if (dropProbability >= 1.0) return false
            val targetHex = CryptoUtils.toHex(target)
            val keyPair = Ed25519Engine.generateKeyPairFromSeed(sk)
            val signData = Bencode.encodeBep44SignData(v, seq, salt)
            val sig = Ed25519Engine.sign(sk, signData)
            networkStorage[targetHex] = MutableItem(
                v = v.copyOf(),
                seq = seq,
                k = keyPair.publicKey,
                sig = sig,
                salt = salt,
                token = null,
                responder = null
            )
            return true
        }

        override suspend fun getMutable(
            target: ByteArray,
            salt: ByteArray?,
            skipLocalStore: Boolean,
            timeoutMs: Long,
            probeAllReplicas: Boolean
        ): MutableItem? {
            getCallCount++
            val targetHex = CryptoUtils.toHex(target)
            return networkStorage[targetHex]
        }
    }

    private fun createTestViewModel(fakeDht: FakeDhtLeafNode): Pair<ChatViewModel, ChatRepository> {
        val app = RuntimeEnvironment.getApplication()
        val settings = AppSettingsManager(app)
        val repo = ChatRepository(testDb!!, fakeDht, settingsManager = settings)
        val viewModel = ChatViewModel(app, customDhtLeafNode = fakeDht, customRepository = repo)
        return Pair(viewModel, repo)
    }

    @Test
    fun testSuccessfulBobHandshakeFlowTransitions() = runBlocking {
        val fakeDht = FakeDhtLeafNode(dropProbability = 0.0)
        val (viewModel, _) = createTestViewModel(fakeDht)

        val recordedStatuses = CopyOnWriteArrayList<BobHandshakeStatus>()
        recordedStatuses.add(viewModel.bobHandshakeStatus.value)
        viewModel.onBobStatusChangedForTesting = { recordedStatuses.add(it) }

        val aliceInit = HandshakeManager.aliceCreateHandshake()
        assertNotNull(aliceInit.qrBytes)
        assertEquals(HandshakeManager.QR_DATA_SIZE, aliceInit.qrBytes.size)

        viewModel.processBobHandshake(aliceInit.qrBytes, "Alice")

        withTimeout(10_000L) {
            while (viewModel.bobHandshakeStatus.value != BobHandshakeStatus.AWAITING_ALICE) {
                delay(20L)
            }
        }

        assertEquals(BobHandshakeStatus.AWAITING_ALICE, viewModel.bobHandshakeStatus.value)
        assertNotNull("handshakeCompleted must not be null after placement in DHT", viewModel.handshakeCompleted.value)
        assertEquals("Alice", viewModel.handshakeCompleted.value?.contactName)

        // Verify sequential progress through the state machine
        val expectedSequence = listOf(
            BobHandshakeStatus.IDLE,
            BobHandshakeStatus.SCANNING_QR,
            BobHandshakeStatus.ENCAPSULATING,
            BobHandshakeStatus.SENDING_DHT,
            BobHandshakeStatus.DHT_SENT_UNVERIFIED,
            BobHandshakeStatus.VERIFYING_DHT,
            BobHandshakeStatus.PLACED_IN_DHT,
            BobHandshakeStatus.AWAITING_ALICE
        )

        var lastIdx = -1
        for (expected in expectedSequence) {
            val foundIdx = recordedStatuses.indexOf(expected)
            assertTrue("Expected status $expected in recorded transitions: $recordedStatuses", foundIdx >= 0)
            assertTrue("Status $expected must appear after previous status in sequence", foundIdx >= lastIdx)
            lastIdx = foundIdx
        }
    }

    @Test
    fun testFirstPutFailsThenRepublishSucceeds() = runBlocking {
        val fakeDht = FakeDhtLeafNode(dropProbability = 1.0)
        val (viewModel, _) = createTestViewModel(fakeDht)

        val recordedStatuses = CopyOnWriteArrayList<BobHandshakeStatus>()
        recordedStatuses.add(viewModel.bobHandshakeStatus.value)
        viewModel.onBobStatusChangedForTesting = { recordedStatuses.add(it) }

        val aliceInit = HandshakeManager.aliceCreateHandshake()
        viewModel.processBobHandshake(aliceInit.qrBytes, "Alice", intervalMs = 25L)

        // Wait until initial put fails and enters retry loop
        withTimeout(5_000L) {
            while (viewModel.bobHandshakeStatus.value != BobHandshakeStatus.PUT_FAILED_RETRYING) {
                delay(20L)
            }
        }
        assertEquals(BobHandshakeStatus.PUT_FAILED_RETRYING, viewModel.bobHandshakeStatus.value)
        assertNull("handshakeCompleted must be null while retrying", viewModel.handshakeCompleted.value)

        // Network recovers: drop probability becomes 0.0
        fakeDht.dropProbability = 0.0

        withTimeout(10_000L) {
            while (viewModel.bobHandshakeStatus.value != BobHandshakeStatus.AWAITING_ALICE) {
                delay(20L)
            }
        }

        assertTrue("Must have recorded PUT_FAILED_RETRYING", recordedStatuses.contains(BobHandshakeStatus.PUT_FAILED_RETRYING))
        assertTrue("Must have recorded PLACED_IN_DHT", recordedStatuses.contains(BobHandshakeStatus.PLACED_IN_DHT))
        assertTrue("Must have recorded AWAITING_ALICE", recordedStatuses.contains(BobHandshakeStatus.AWAITING_ALICE))
        assertNotNull(viewModel.handshakeCompleted.value)
    }

    @Test
    fun testPutAlwaysFailsReachesTimeout() = runBlocking {
        val fakeDht = FakeDhtLeafNode(dropProbability = 1.0)
        val (viewModel, _) = createTestViewModel(fakeDht)

        val aliceInit = HandshakeManager.aliceCreateHandshake()
        // Fast interval to complete 40 iterations quickly in test
        viewModel.processBobHandshake(aliceInit.qrBytes, "Alice", intervalMs = 2L)

        withTimeout(15_000L) {
            while (viewModel.bobHandshakeStatus.value != BobHandshakeStatus.TIMEOUT) {
                delay(20L)
            }
        }

        assertEquals(BobHandshakeStatus.TIMEOUT, viewModel.bobHandshakeStatus.value)
        assertNull("handshakeCompleted must remain null on timeout", viewModel.handshakeCompleted.value)
    }

    @Test
    fun testCryptographicFailureTransitionsToFailed() = runBlocking {
        val fakeDht = FakeDhtLeafNode(dropProbability = 0.0)
        val (viewModel, _) = createTestViewModel(fakeDht)

        // Corrupted payload of invalid length (100 bytes != 864 bytes)
        val invalidPayload = ByteArray(100) { 0x55.toByte() }
        viewModel.processBobHandshake(invalidPayload, "Alice")

        delay(50L)
        assertEquals(BobHandshakeStatus.FAILED, viewModel.bobHandshakeStatus.value)
        assertNull("handshakeCompleted must be null on failure", viewModel.handshakeCompleted.value)
    }

    @Test
    fun testHandshakeCompletedRemainsNullBeforePlacedInDht() = runBlocking {
        val fakeDht = FakeDhtLeafNode(dropProbability = 1.0)
        val (viewModel, _) = createTestViewModel(fakeDht)

        val observedCompletedBeforePlaced = CopyOnWriteArrayList<ChatViewModel.HandshakeCompletedState?>()
        observedCompletedBeforePlaced.add(viewModel.handshakeCompleted.value)
        viewModel.onBobStatusChangedForTesting = { status ->
            if (status != BobHandshakeStatus.PLACED_IN_DHT && status != BobHandshakeStatus.AWAITING_ALICE) {
                observedCompletedBeforePlaced.add(viewModel.handshakeCompleted.value)
            }
        }

        val aliceInit = HandshakeManager.aliceCreateHandshake()
        viewModel.processBobHandshake(aliceInit.qrBytes, "Alice", intervalMs = 10L)

        withTimeout(5_000L) {
            while (viewModel.bobHandshakeStatus.value != BobHandshakeStatus.PUT_FAILED_RETRYING) {
                delay(20L)
            }
        }

        assertTrue("Observed states must not be empty", observedCompletedBeforePlaced.isNotEmpty())
        assertTrue(
            "handshakeCompleted must remain strictly null before PLACED_IN_DHT",
            observedCompletedBeforePlaced.all { it == null }
        )
    }
}
