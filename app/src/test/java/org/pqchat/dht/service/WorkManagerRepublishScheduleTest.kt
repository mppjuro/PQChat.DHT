package org.pqchat.dht.service

import androidx.work.BackoffPolicy
import androidx.work.NetworkType
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.data.settings.DefaultRepublishConfig
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.traffic.*
import java.security.Security
import java.util.concurrent.TimeUnit

class WorkManagerRepublishScheduleTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupClass() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private var scheduler: PollingScheduler? = null
    private val fakeContactDao = FakeContactDao()
    private val fakeMessageDao = FakeMessageDao()
    private val fakeChunkDao = FakeChunkDao()
    private val fakeDht = org.pqchat.dht.dht.FakeDht()
    private lateinit var repository: ChatRepository
    private lateinit var settingsManager: AppSettingsManager

    @Before
    fun setUp() {
        fakeDht.start()
        PollingWorker.clearRepublishTasks()
        fakeMessageDao.messages.clear()
        repository = ChatRepository(fakeContactDao, fakeMessageDao, fakeChunkDao, fakeDht)
        settingsManager = AppSettingsManager(null)
        scheduler = PollingScheduler(
            context = null,
            repository = repository,
            dhtLeafNode = null,
            settingsManager = settingsManager
        )
    }

    @After
    fun tearDown() {
        fakeDht.stop()
        scheduler?.stop()
        PollingWorker.clearRepublishTasks()
    }

    // =========================================================================
    // 1. RepublishPolicy Unit Tests
    // =========================================================================

    @Test
    fun testRepublishPolicyTiersAndIntervals() {
        val policy = RepublishPolicy()

        // Tier 1: 0 to 2h (15 min interval)
        assertEquals(RepublishTier.TIER1_INITIAL, policy.getTier(0L))
        assertEquals(RepublishTier.TIER1_INITIAL, policy.getTier(30 * 60 * 1000L))
        assertEquals(RepublishTier.TIER1_INITIAL, policy.getTier(2 * 60 * 60 * 1000L - 1))
        assertEquals(15 * 60 * 1000L, policy.getIntervalForAge(30 * 60 * 1000L))
        assertFalse(policy.isExpired(30 * 60 * 1000L))

        // Tier 2: 2h to 12h (1h interval)
        assertEquals(RepublishTier.TIER2_EXTENDED, policy.getTier(2 * 60 * 60 * 1000L))
        assertEquals(RepublishTier.TIER2_EXTENDED, policy.getTier(6 * 60 * 60 * 1000L))
        assertEquals(RepublishTier.TIER2_EXTENDED, policy.getTier(12 * 60 * 60 * 1000L - 1))
        assertEquals(60 * 60 * 1000L, policy.getIntervalForAge(6 * 60 * 60 * 1000L))
        assertFalse(policy.isExpired(6 * 60 * 60 * 1000L))

        // Tier 3: 12h to 48h (6h interval)
        assertEquals(RepublishTier.TIER3_LONG_TERM, policy.getTier(12 * 60 * 60 * 1000L))
        assertEquals(RepublishTier.TIER3_LONG_TERM, policy.getTier(24 * 60 * 60 * 1000L))
        assertEquals(RepublishTier.TIER3_LONG_TERM, policy.getTier(48 * 60 * 60 * 1000L - 1))
        assertEquals(6 * 60 * 60 * 1000L, policy.getIntervalForAge(24 * 60 * 60 * 1000L))
        assertFalse(policy.isExpired(24 * 60 * 60 * 1000L))

        // TTL Expiration: >= 48h
        assertEquals(RepublishTier.EXPIRED, policy.getTier(48 * 60 * 60 * 1000L))
        assertEquals(RepublishTier.EXPIRED, policy.getTier(72 * 60 * 60 * 1000L))
        assertEquals(-1L, policy.getIntervalForAge(48 * 60 * 60 * 1000L))
        assertTrue(policy.isExpired(48 * 60 * 60 * 1000L))
        assertTrue(policy.isExpired(50 * 60 * 60 * 1000L))
    }

    // =========================================================================
    // 2. WorkManager WorkRequest Builder Tests
    // =========================================================================

    @Test
    fun testBuildPeriodicWorkRequestAttributes() {
        // Tier 1: 15 minutes
        val req15 = PollingWorker.buildPeriodicWorkRequest(15L)
        assertEquals(TimeUnit.MINUTES.toMillis(15L), req15.workSpec.intervalDuration)
        assertEquals(NetworkType.CONNECTED, req15.workSpec.constraints.requiredNetworkType)
        assertEquals(BackoffPolicy.EXPONENTIAL, req15.workSpec.backoffPolicy)
        assertTrue(req15.tags.contains(PollingWorker.TAG_REPUBLISH))

        // Tier 2: 60 minutes
        val req60 = PollingWorker.buildPeriodicWorkRequest(60L)
        assertEquals(TimeUnit.MINUTES.toMillis(60L), req60.workSpec.intervalDuration)

        // Tier 3: 360 minutes (6 hours)
        val req360 = PollingWorker.buildPeriodicWorkRequest(360L)
        assertEquals(TimeUnit.MINUTES.toMillis(360L), req360.workSpec.intervalDuration)

        // Constraint coercion: WorkManager enforces minimum 15 minutes
        val req5 = PollingWorker.buildPeriodicWorkRequest(5L)
        assertEquals(TimeUnit.MINUTES.toMillis(15L), req5.workSpec.intervalDuration)
    }

    // =========================================================================
    // 3. WorkManager Schedule Evaluation Across Backoff Tiers
    // =========================================================================

    @Test
    fun testScheduleEvaluationTier1() {
        val now = 1_000_000_000L
        val task = PollingWorker.RepublishTask(
            messageId = 101L,
            contactId = "alice",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.MINUTES.toMillis(30) // 30 min old
        )

        val decision = scheduler!!.evaluateRepublishSchedule(
            currentTimeMs = now,
            tasks = listOf(task)
        )

        assertTrue(decision.shouldSchedule)
        assertEquals(15L, decision.intervalMinutes)
        assertEquals(RepublishTier.TIER1_INITIAL, decision.tier)
        assertEquals(1, decision.activeTaskCount)
        assertTrue(decision.expiredTaskIds.isEmpty())
    }

    @Test
    fun testScheduleEvaluationTier2() {
        val now = 1_000_000_000L
        val task = PollingWorker.RepublishTask(
            messageId = 102L,
            contactId = "alice",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.HOURS.toMillis(4) // 4 hours old (Tier 2)
        )

        val decision = scheduler!!.evaluateRepublishSchedule(
            currentTimeMs = now,
            tasks = listOf(task)
        )

        assertTrue(decision.shouldSchedule)
        assertEquals(60L, decision.intervalMinutes)
        assertEquals(RepublishTier.TIER2_EXTENDED, decision.tier)
        assertEquals(1, decision.activeTaskCount)
        assertTrue(decision.expiredTaskIds.isEmpty())
    }

    @Test
    fun testScheduleEvaluationTier3() {
        val now = 1_000_000_000L
        val task = PollingWorker.RepublishTask(
            messageId = 103L,
            contactId = "alice",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.HOURS.toMillis(20) // 20 hours old (Tier 3)
        )

        val decision = scheduler!!.evaluateRepublishSchedule(
            currentTimeMs = now,
            tasks = listOf(task)
        )

        assertTrue(decision.shouldSchedule)
        assertEquals(360L, decision.intervalMinutes)
        assertEquals(RepublishTier.TIER3_LONG_TERM, decision.tier)
        assertEquals(1, decision.activeTaskCount)
        assertTrue(decision.expiredTaskIds.isEmpty())
    }

    @Test
    fun testScheduleEvaluationTtlExpiredStopsRadioWakeup() {
        val now = 1_000_000_000L
        val expiredTask = PollingWorker.RepublishTask(
            messageId = 104L,
            contactId = "alice",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.HOURS.toMillis(49) // 49 hours old (> 48h TTL)
        )

        val decision = scheduler!!.evaluateRepublishSchedule(
            currentTimeMs = now,
            tasks = listOf(expiredTask)
        )

        // Radio wakeups must be stopped: shouldSchedule = false
        assertFalse("Expired message must not schedule WorkManager", decision.shouldSchedule)
        assertEquals(0, decision.activeTaskCount)
        assertEquals(listOf(104L), decision.expiredTaskIds)
    }

    @Test
    fun testScheduleEvaluationMultipleMessagesSelectsEarliestInterval() {
        val now = 1_000_000_000L
        val taskTier1 = PollingWorker.RepublishTask(
            messageId = 1L,
            contactId = "alice",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.MINUTES.toMillis(40) // 40 min -> Tier 1 (15m)
        )
        val taskTier2 = PollingWorker.RepublishTask(
            messageId = 2L,
            contactId = "bob",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.HOURS.toMillis(5) // 5h -> Tier 2 (1h)
        )
        val taskTier3 = PollingWorker.RepublishTask(
            messageId = 3L,
            contactId = "charlie",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.HOURS.toMillis(30) // 30h -> Tier 3 (6h)
        )
        val taskExpired = PollingWorker.RepublishTask(
            messageId = 4L,
            contactId = "dave",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.HOURS.toMillis(55) // 55h -> Expired
        )

        // With all tasks: earliest is Tier 1 (15m)
        val decision1 = scheduler!!.evaluateRepublishSchedule(
            currentTimeMs = now,
            tasks = listOf(taskTier1, taskTier2, taskTier3, taskExpired)
        )
        assertTrue(decision1.shouldSchedule)
        assertEquals(15L, decision1.intervalMinutes)
        assertEquals(RepublishTier.TIER1_INITIAL, decision1.tier)
        assertEquals(3, decision1.activeTaskCount)
        assertEquals(listOf(4L), decision1.expiredTaskIds)

        // Once taskTier1 is ACKed/removed: earliest is Tier 2 (60m)
        val decision2 = scheduler!!.evaluateRepublishSchedule(
            currentTimeMs = now,
            tasks = listOf(taskTier2, taskTier3)
        )
        assertTrue(decision2.shouldSchedule)
        assertEquals(60L, decision2.intervalMinutes)
        assertEquals(RepublishTier.TIER2_EXTENDED, decision2.tier)
        assertEquals(2, decision2.activeTaskCount)

        // Once taskTier2 is ACKed/removed: earliest is Tier 3 (360m)
        val decision3 = scheduler!!.evaluateRepublishSchedule(
            currentTimeMs = now,
            tasks = listOf(taskTier3)
        )
        assertTrue(decision3.shouldSchedule)
        assertEquals(360L, decision3.intervalMinutes)
        assertEquals(RepublishTier.TIER3_LONG_TERM, decision3.tier)
        assertEquals(1, decision3.activeTaskCount)

        // Once taskTier3 is also ACKed/removed: no active tasks remain, stop WorkManager!
        val decision4 = scheduler!!.evaluateRepublishSchedule(
            currentTimeMs = now,
            tasks = emptyList()
        )
        assertFalse(decision4.shouldSchedule)
        assertEquals(0, decision4.activeTaskCount)
    }

    // =========================================================================
    // 4. Apply Republish Schedule & Room DB Status Updates
    // =========================================================================

    @Test
    fun testApplyRepublishScheduleMarksExpiredMessagesInDb() = runBlocking {
        val now = System.currentTimeMillis()

        // Insert message awaiting delivery in DB
        val msgId = fakeMessageDao.insertMessage(
            MessageEntity(
                contactId = "alice",
                isOutgoing = true,
                seqNum = 1,
                timestamp = now - TimeUnit.HOURS.toMillis(50), // 50 hours old (> 48h TTL)
                status = "PENDING_DELIVERY"
            )
        )

        val expiredTask = PollingWorker.RepublishTask(
            messageId = msgId,
            contactId = "alice",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.HOURS.toMillis(50)
        )
        PollingWorker.registerRepublishTask(expiredTask)
        assertTrue(PollingWorker.isRepublishTaskRegistered(msgId))

        // Apply schedule
        val decision = scheduler!!.applyRepublishSchedule(currentTimeMs = now)

        // Verify task unregistered
        assertFalse("Expired task must be unregistered from PollingWorker",
            PollingWorker.isRepublishTaskRegistered(msgId))

        // Verify Room DB status updated to EXPIRED_OFFLINE
        val dbMsg = fakeMessageDao.messages.first { it.id == msgId }
        assertEquals("EXPIRED_OFFLINE", dbMsg.status)

        // Verify WorkManager is not scheduled (stops waking radio)
        assertFalse(decision.shouldSchedule)
    }

    @Test
    fun testOfflineExpiredMessagesInDbAreDetectedAndMarked() = runBlocking {
        val now = System.currentTimeMillis()

        // Message stored in DB that expired while the phone was offline (no in-memory task)
        val msgId = fakeMessageDao.insertMessage(
            MessageEntity(
                contactId = "bob",
                isOutgoing = true,
                seqNum = 2,
                timestamp = now - TimeUnit.HOURS.toMillis(60), // 60h old
                status = "SENT_DHT"
            )
        )

        val expiredList = repository.expireOutdatedPendingMessages(
            maxTtlMs = DefaultRepublishConfig.MAX_TTL,
            currentTimeMs = now
        )

        assertEquals(listOf(msgId), expiredList)
        val dbMsg = fakeMessageDao.messages.first { it.id == msgId }
        assertEquals("EXPIRED_OFFLINE", dbMsg.status)
    }

    // =========================================================================
    // 5. Configurable Settings in AppSettingsManager
    // =========================================================================

    @Test
    fun testConfigurableSettingsAlterPolicyAndSchedule() {
        val now = 1_000_000_000L

        // Change settings
        settingsManager.setIntervalRepublishTier1(10 * 60 * 1000L) // 10 min
        settingsManager.setIntervalRepublishTier2(30 * 60 * 1000L) // 30 min
        settingsManager.setIntervalRepublishTier3(2 * 60 * 60 * 1000L) // 2 hours
        settingsManager.setRepublishMaxTtl(24 * 60 * 60 * 1000L) // 24 hours TTL

        val customPolicy = settingsManager.getRepublishPolicy()
        assertEquals(10 * 60 * 1000L, customPolicy.tier1IntervalMs)
        assertEquals(30 * 60 * 1000L, customPolicy.tier2IntervalMs)
        assertEquals(2 * 60 * 60 * 1000L, customPolicy.tier3IntervalMs)
        assertEquals(24 * 60 * 60 * 1000L, customPolicy.maxTtlMs)

        // Message age 25 hours is expired under 24h TTL
        val task25h = PollingWorker.RepublishTask(
            messageId = 5L,
            contactId = "alice",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.HOURS.toMillis(25)
        )

        val decision = scheduler!!.evaluateRepublishSchedule(
            currentTimeMs = now,
            policy = customPolicy,
            tasks = listOf(task25h)
        )
        assertFalse("Message at 25h must be expired with 24h TTL", decision.shouldSchedule)
        assertEquals(listOf(5L), decision.expiredTaskIds)

        // Message age 5 hours uses custom Tier 2 interval (30 min)
        val task5h = PollingWorker.RepublishTask(
            messageId = 6L,
            contactId = "alice",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.HOURS.toMillis(5)
        )
        val decision5h = scheduler!!.evaluateRepublishSchedule(
            currentTimeMs = now,
            policy = customPolicy,
            tasks = listOf(task5h)
        )
        assertTrue(decision5h.shouldSchedule)
        assertEquals(30L, decision5h.intervalMinutes)
    }

    // =========================================================================
    // 6. PollingWorker.executeRepublishPass with Exponential Backoff
    // =========================================================================

    @Test
    fun testExecuteRepublishPassRespectsIntervalsAndTtl() = runBlocking {
        val now = 10_000_000L
        val policy = RepublishPolicy()

        // Task 1: Tier 1, interval elapsed (last republished 20 min ago > 15 min interval)
        val task1 = PollingWorker.RepublishTask(
            messageId = 1L,
            contactId = "alice",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.MINUTES.toMillis(30),
            lastRepublishedTimestamp = now - TimeUnit.MINUTES.toMillis(20)
        )

        // Task 2: Tier 1, interval NOT elapsed (last republished 5 min ago < 15 min interval)
        val task2 = PollingWorker.RepublishTask(
            messageId = 2L,
            contactId = "bob",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.MINUTES.toMillis(30),
            lastRepublishedTimestamp = now - TimeUnit.MINUTES.toMillis(5)
        )

        // Task 3: TTL expired (50 hours old)
        val task3 = PollingWorker.RepublishTask(
            messageId = 3L,
            contactId = "charlie",
            target = ByteArray(20),
            payload = ByteArray(100),
            edPrivateKeySeed = ByteArray(32),
            initialSentTimestamp = now - TimeUnit.HOURS.toMillis(50),
            lastRepublishedTimestamp = now - TimeUnit.HOURS.toMillis(10)
        )

        PollingWorker.registerRepublishTask(task1)
        PollingWorker.registerRepublishTask(task2)
        PollingWorker.registerRepublishTask(task3)

        val expiredCallbackIds = mutableListOf<Long>()
        val count = PollingWorker.executeRepublishPass(
            dhtClient = fakeDht,
            policy = policy,
            currentTimeMs = now,
            onMessageExpired = { expiredCallbackIds.add(it) }
        )

        // Only Task 1 was due for republishing
        assertEquals(1, count)
        assertEquals(1, task1.currentAttempts)
        assertEquals(now, task1.lastRepublishedTimestamp)
        assertEquals(0, task2.currentAttempts)

        // Task 3 must be expired and removed from tasks
        assertEquals(listOf(3L), expiredCallbackIds)
        assertFalse(PollingWorker.isRepublishTaskRegistered(3L))
        assertTrue(PollingWorker.isRepublishTaskRegistered(1L))
        assertTrue(PollingWorker.isRepublishTaskRegistered(2L))
    }

    // =========================================================================
    // Fake DAOs for test isolation
    // =========================================================================

    private class FakeContactDao : ContactDao {
        val contacts = mutableMapOf<String, ContactEntity>()
        val flow = MutableStateFlow<List<ContactEntity>>(emptyList())
        override fun getAllContactsFlow(): Flow<List<ContactEntity>> = flow
        override suspend fun getContactById(id: String): ContactEntity? = contacts[id]
        override suspend fun insertOrUpdate(contact: ContactEntity) { contacts[contact.id] = contact }
        override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob) {}
        override suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: EncryptedBlob, rekeyEpoch: Long) {}
        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {}
        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {}
        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {}
        override suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {}
        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {}
        override suspend fun deleteContact(id: String) {}
    }

    private class FakeMessageDao : MessageDao {
        val messages = mutableListOf<MessageEntity>()
        private var idGen = 1L
        override fun getMessagesForContactFlow(contactId: String): Flow<List<MessageEntity>> =
            MutableStateFlow(messages.filter { it.contactId == contactId })
        override suspend fun insertMessage(message: MessageEntity): Long {
            val id = if (message.id != 0L) message.id else idGen++
            messages.add(message.copy(id = id))
            return id
        }
        override suspend fun updateStatus(id: Long, status: String) {
            val idx = messages.indexOfFirst { it.id == id }
            if (idx >= 0) messages[idx] = messages[idx].copy(status = status)
        }
        override suspend fun updateMessageStatusAndSeq(id: Long, status: String, seqNum: Int) {
            val idx = messages.indexOfFirst { it.id == id }
            if (idx >= 0) messages[idx] = messages[idx].copy(status = status, seqNum = seqNum)
        }
        override suspend fun updateMessageRetry(id: Long, status: String, retryCount: Int, timestamp: Long) {}
        override suspend fun getQueuedMessagesForContact(contactId: String): List<MessageEntity> = emptyList()
        override suspend fun getAllQueuedMessages(): List<MessageEntity> = emptyList()
        override suspend fun updateStatusForSeq(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String) {}
        override suspend fun updateMessageStatusAndDirection(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String) {}
        override suspend fun normalizeConfirmedSelfNotes(contactId: String) {}
        override suspend fun deleteMessagesForContact(contactId: String) {}
        override suspend fun existsMessageWithEpoch(contactId: String, seqEpoch: Int, seqNum: Int, isOutgoing: Boolean): Boolean = false
        override suspend fun existsMessage(contactId: String, seqNum: Int, isOutgoing: Boolean): Boolean = false
        override suspend fun getPendingDeliveryMessagesForContact(contactId: String): List<MessageEntity> =
            messages.filter { it.contactId == contactId && it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }
        override suspend fun getAllPendingDeliveryMessages(): List<MessageEntity> =
            messages.filter { it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }
    }

    private class FakeChunkDao : ChunkDao {
        override suspend fun insertChunk(chunk: ChunkEntity) {}
        override suspend fun getChunksForTransfer(transferId: String): List<ChunkEntity> = emptyList()
        override suspend fun countChunks(transferId: String): Int = 0
        override suspend fun deleteChunks(transferId: String) {}
    }
}
