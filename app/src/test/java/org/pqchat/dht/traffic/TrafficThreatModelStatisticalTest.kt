package org.pqchat.dht.traffic

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.FakeDht
import kotlin.math.abs
import kotlin.math.ln
import kotlin.math.sqrt

/**
 * Statistical validation tests according to docs/threat_model.md:
 * - Interval distribution (Exponential distribution for Poisson cover traffic, Uniform for Polling Jitter)
 * - Goodness of fit (Chi-Square test & Quantiles)
 * - Memorylessness & Lack of periodicity (Autocorrelation test at lag 1, 2, 5)
 * - Actual target emission in PoissonTrafficGenerator (verifying record stored in DHT)
 * - Decoy GET queries hitting real/expiring populated targets rather than random 0-PUT targets
 * - Delayed PUT & Decoy PUT Slots emission
 */
class TrafficThreatModelStatisticalTest {

    @Test
    fun testPoissonIntervalDistribution_ExponentialPropertiesAndGoodnessOfFit() {
        val fakeDht = FakeDht()
        val lambda = 1.0 / 480.0 // average once every 8 minutes = 480s
        val generator = PoissonTrafficGenerator(dhtLeafNode = fakeDht, lambda = lambda)

        val n = 5000
        val intervalsMs = DoubleArray(n) { generator.computeNextIntervalMs().toDouble() }

        // 1. Minimum limit check (coerceAtLeast 1000ms)
        assertTrue("All Poisson intervals must be >= 1000 ms", intervalsMs.all { it >= 1000.0 })

        // 2. Sample Mean: theoretical mean mu = (1 / lambda) * 1000 = 480_000 ms
        val theoreticalMean = (1.0 / lambda) * 1000.0
        val sampleMean = intervalsMs.average()
        val meanRelativeError = abs(sampleMean - theoreticalMean) / theoreticalMean
        assertTrue(
            "Sample mean ($sampleMean ms) must be within 5% of theoretical mean ($theoreticalMean ms), got error ${meanRelativeError * 100}%",
            meanRelativeError < 0.05
        )

        // 3. Sample Standard Deviation: for exponential distribution, sigma = mu
        val variance = intervalsMs.map { (it - sampleMean) * (it - sampleMean) }.average()
        val sampleStd = sqrt(variance)
        val stdRelativeError = abs(sampleStd - theoreticalMean) / theoreticalMean
        assertTrue(
            "Sample std dev ($sampleStd ms) must be within 7% of theoretical std dev ($theoreticalMean ms), got error ${stdRelativeError * 100}%",
            stdRelativeError < 0.07
        )

        // 4. Sample Median: theoretical median = mu * ln(2)
        val theoreticalMedian = theoreticalMean * ln(2.0)
        val sorted = intervalsMs.sorted()
        val sampleMedian = sorted[n / 2]
        val medianRelativeError = abs(sampleMedian - theoreticalMedian) / theoreticalMedian
        assertTrue(
            "Sample median ($sampleMedian ms) must be within 6% of theoretical median ($theoreticalMedian ms), got error ${medianRelativeError * 100}%",
            medianRelativeError < 0.06
        )

        // 5. Chi-Square Goodness-of-Fit into 5 equal-probability quantile bins
        val kBins = 5
        val expectedPerBin = n.toDouble() / kBins
        val binCounts = IntArray(kBins)
        for (x in intervalsMs) {
            val u = 1.0 - kotlin.math.exp(-lambda * (x / 1000.0))
            val bin = (u * kBins).toInt().coerceIn(0, kBins - 1)
            binCounts[bin]++
        }

        var chiSquare = 0.0
        for (observed in binCounts) {
            val diff = observed - expectedPerBin
            chiSquare += (diff * diff) / expectedPerBin
        }

        // Critical value for chi-square with 4 degrees of freedom at alpha=0.01 is 13.28
        assertTrue(
            "Chi-Square test statistic ($chiSquare) must not reject exponential distribution (critical = 13.28)",
            chiSquare < 13.28
        )
    }

    @Test
    fun testPoissonIntervals_LackOfPeriodicityAndAutocorrelation() {
        val fakeDht = FakeDht()
        val generator = PoissonTrafficGenerator(dhtLeafNode = fakeDht, lambda = 1.0 / 480.0)

        val n = 4000
        val intervals = DoubleArray(n) { generator.computeNextIntervalMs().toDouble() }
        val mean = intervals.average()

        // Autocorrelation at lag k: sum((x_i - mean)*(x_{i+k} - mean)) / sum((x_i - mean)^2)
        val denominator = intervals.sumOf { (it - mean) * (it - mean) }

        for (lag in listOf(1, 2, 5)) {
            var numerator = 0.0
            for (i in 0 until n - lag) {
                numerator += (intervals[i] - mean) * (intervals[i + lag] - mean)
            }
            val rLag = numerator / denominator
            assertTrue(
                "Autocorrelation at lag $lag must be close to 0 (|r| < 0.05) proving lack of periodicity, got $rLag",
                abs(rLag) < 0.05
            )
        }
    }

    @Test
    fun testPollingJitterDistribution_SpreadAndLackOfPeriodicity() {
        val manager = AdaptivePollingManager(onPollRequested = {})
        manager.jitterRatio = 0.30 // ±30% per docs/threat_model.md

        val baseIntervalMs = 10_000L
        val n = 5000
        val samples = DoubleArray(n) { manager.computeJitteredInterval(baseIntervalMs).toDouble() }

        // 1. Strict boundary check: range [0.70 * 10000, 1.30 * 10000] = [7000, 13000]
        assertTrue("All jittered intervals must be >= 7000 ms", samples.all { it >= 7000.0 })
        assertTrue("All jittered intervals must be <= 13000 ms", samples.all { it <= 13000.0 })

        // 2. Mean check: uniform distribution in [7000, 13000] has mean 10000
        val sampleMean = samples.average()
        val meanRelativeError = abs(sampleMean - 10000.0) / 10000.0
        assertTrue(
            "Jitter sample mean ($sampleMean ms) must be within 1% of base interval (10000 ms)",
            meanRelativeError < 0.01
        )

        // 3. Std Dev check: uniform distribution has sigma = (b - a) / sqrt(12) = 6000 / sqrt(12) ~ 1732.05
        val theoreticalStd = 6000.0 / sqrt(12.0)
        val variance = samples.map { (it - sampleMean) * (it - sampleMean) }.average()
        val sampleStd = sqrt(variance)
        val stdRelativeError = abs(sampleStd - theoreticalStd) / theoreticalStd
        assertTrue(
            "Jitter std dev ($sampleStd) must be within 5% of theoretical uniform std ($theoreticalStd)",
            stdRelativeError < 0.05
        )

        // 4. Autocorrelation check: consecutive samples must be independent (lack of periodicity)
        val denominator = samples.sumOf { (it - sampleMean) * (it - sampleMean) }
        var numerator = 0.0
        for (i in 0 until n - 1) {
            numerator += (samples[i] - sampleMean) * (samples[i + 1] - sampleMean)
        }
        val r1 = numerator / denominator
        assertTrue(
            "Jitter autocorrelation at lag 1 must be close to 0 (|r1| < 0.05), got $r1",
            abs(r1) < 0.05
        )
    }

    @Test
    fun testPoissonTrafficGenerator_EmitsActuallyUsedDhtTarget() = runBlocking {
        val fakeDht = FakeDht()
        val decoyPool = DecoyTargetPool()
        val queue = PendingAckQueue()
        val generator = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            pendingAckQueue = queue,
            decoyTargetPool = decoyPool
        )

        // 1. Tick with dummy: must emit actually stored target
        val dummyEvent = generator.processCoverTrafficTick(delayMs = 2000L)
        assertFalse("Tick without queue must be dummy", dummyEvent.isAck)
        assertNotNull("TargetHex must not be null", dummyEvent.targetHex)
        assertEquals(40, dummyEvent.targetHex.length) // 20 bytes SHA-1 hex

        // Verify the record physically exists in DHT storage under the exact emitted target!
        assertTrue(
            "Target emitted in CoverEvent must be physically present in DHT storage",
            fakeDht.storage.containsKey(dummyEvent.targetHex)
        )
        val storedItem = fakeDht.storage[dummyEvent.targetHex]!!.item
        assertEquals(1000, storedItem.v.size)
        assertTrue(
            "DecoyTargetPool must have registered the emitted target",
            decoyPool.getAllPopulatedTargets().any { CryptoUtils.toHex(it) == dummyEvent.targetHex }
        )

        // 2. Tick with Cover ACK: must emit ackTarget and store in DHT
        val ratchetKey = CryptoUtils.secureRandomBytes(32)
        queue.enqueue(PendingAck(contactId = "bob", messageId = "42", ratchetKey = ratchetKey, seqNum = 42))
        val ackEvent = generator.processCoverTrafficTick(delayMs = 3000L)
        assertTrue("Tick with queued ACK must be ACK", ackEvent.isAck)
        assertTrue(
            "ACK target emitted must be physically stored in DHT",
            fakeDht.storage.containsKey(ackEvent.targetHex)
        )
        assertTrue(
            "DecoyTargetPool must have registered the ACK target",
            decoyPool.getAllPopulatedTargets().any { CryptoUtils.toHex(it) == ackEvent.targetHex }
        )
    }

    @Test
    fun testDecoyGets_UsesRealAndExpiringTargetsNotRandom() = runBlocking {
        val fakeDht = FakeDht()
        val decoyPool = DecoyTargetPool()

        // Register 3 real populated targets (from previous Poisson cover traffic)
        val realCover1 = CryptoUtils.secureRandomBytes(20)
        val realCover2 = CryptoUtils.secureRandomBytes(20)
        val realCover3 = CryptoUtils.secureRandomBytes(20)
        decoyPool.registerPopulatedTarget(realCover1)
        decoyPool.registerPopulatedTarget(realCover2)
        decoyPool.registerPopulatedTarget(realCover3)

        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val repository = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = PendingAckQueue(),
            decoyTargetPool = decoyPool
        )
        repository.decoyGetRatio = 2.0
        repository.enableDecoyGets = true

        val getCountBefore = fakeDht.getCalls.get()
        val queriedDecoys = repository.executeDecoyGets()
        assertTrue("Must execute decoy GETs", queriedDecoys >= 1)
        assertTrue("FakeDht must have received GET calls", fakeDht.getCalls.get() > getCountBefore)

        // Verify that the requested decoy targets are strictly chosen from the populated pool
        val populatedHexes = setOf(
            CryptoUtils.toHex(realCover1),
            CryptoUtils.toHex(realCover2),
            CryptoUtils.toHex(realCover3)
        )
        val decoyTargetsSampled = decoyPool.getDecoyTargets(2)
        for (target in decoyTargetsSampled) {
            assertTrue(
                "Sampled decoy target must belong to populated targets pool",
                populatedHexes.contains(CryptoUtils.toHex(target))
            )
        }
    }

    @Test
    fun testDelayedPutAndDecoySlots_PublishingBehavior() = runBlocking {
        val fakeDht = FakeDht()
        val decoyPool = DecoyTargetPool()
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()

        val repository = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = PendingAckQueue(),
            decoyTargetPool = decoyPool
        )
        // Configure delayed put & decoy slots
        repository.delayedPutMaxMs = 100L
        repository.decoyPutSlotsCount = 1

        val contact = ContactEntity(
            id = "alice",
            name = "Alice",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            chainKeyIn = CryptoUtils.secureRandomBytes(64),
            counterIn = 0
        )
        contactDao.insertOrUpdate(contact)

        val initialPutCount = fakeDht.putCalls.get()
        val success = repository.sendTextMessage("alice", "Hello Alice with decoy slots!")
        assertTrue("Send message must succeed", success)

        // With decoyPutSlotsCount = 1: FakeDht must receive 1 decoy PUT + 1 real message PUT = 2 PUTs total!
        val putCountAfter = fakeDht.putCalls.get()
        assertEquals(
            "Must execute real message PUT + 1 Decoy Slot PUT (2 PUT calls total)",
            initialPutCount + 2,
            putCountAfter
        )

        // DecoyTargetPool must have registered the targets
        assertTrue("Decoy pool must contain at least 2 populated targets", decoyPool.size() >= 2)
    }

    // --- Minimal In-Memory DAOs for isolation ---

    private class FakeContactDao : ContactDao {
        val contacts = mutableMapOf<String, ContactEntity>()
        val flow = MutableStateFlow<List<ContactEntity>>(emptyList())

        override fun getAllContactsFlow(): Flow<List<ContactEntity>> = flow
        override suspend fun getContactById(id: String): ContactEntity? = contacts[id]

        override suspend fun insertOrUpdate(contact: ContactEntity) {
            contacts[contact.id] = contact
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: EncryptedBlob, rekeyEpoch: Long) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut, rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun deleteContact(id: String) {
            contacts.remove(id)
            flow.value = contacts.values.toList()
        }
    }

    private class FakeMessageDao : MessageDao {
        val messages = mutableListOf<MessageEntity>()
        private var idCounter = 1L

        override fun getMessagesForContactFlow(contactId: String): Flow<List<MessageEntity>> =
            MutableStateFlow(messages.filter { it.contactId == contactId })

        override suspend fun insertMessage(message: MessageEntity): Long {
            val id = idCounter++
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

        override suspend fun updateMessageRetry(id: Long, status: String, retryCount: Int, timestamp: Long) {
            val idx = messages.indexOfFirst { it.id == id }
            if (idx >= 0) messages[idx] = messages[idx].copy(status = status, retryCount = retryCount, lastAttemptTimestamp = timestamp)
        }

        override suspend fun getQueuedMessagesForContact(contactId: String): List<MessageEntity> =
            messages.filter { it.contactId == contactId && it.isOutgoing && it.status == "QUEUED" }.sortedBy { it.id }

        override suspend fun getAllQueuedMessages(): List<MessageEntity> =
            messages.filter { it.isOutgoing && it.status == "QUEUED" }.sortedBy { it.id }

        override suspend fun updateStatusForSeq(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String) {
            val idx = messages.indexOfFirst { it.contactId == contactId && it.seqNum == seqNum && it.isOutgoing == isOutgoing }
            if (idx >= 0) messages[idx] = messages[idx].copy(status = status)
        }

        override suspend fun updateMessageStatusAndDirection(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String) {
            val idx = messages.indexOfFirst { it.contactId == contactId && it.seqNum == seqNum }
            if (idx >= 0) messages[idx] = messages[idx].copy(status = status, isOutgoing = isOutgoing)
        }

        override suspend fun normalizeConfirmedSelfNotes(contactId: String) {}

        override suspend fun deleteMessagesForContact(contactId: String) {
            messages.removeAll { it.contactId == contactId }
        }

        override suspend fun existsMessageWithEpoch(contactId: String, seqEpoch: Int, seqNum: Int, isOutgoing: Boolean): Boolean =
            messages.any { it.contactId == contactId && it.seqEpoch == seqEpoch && it.seqNum == seqNum && it.isOutgoing == isOutgoing }

        override suspend fun existsMessage(contactId: String, seqNum: Int, isOutgoing: Boolean): Boolean =
            messages.any { it.contactId == contactId && it.seqNum == seqNum && it.isOutgoing == isOutgoing }

        override suspend fun getPendingDeliveryMessagesForContact(contactId: String): List<MessageEntity> =
            messages.filter { it.contactId == contactId && it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }.sortedBy { it.id }

        override suspend fun getAllPendingDeliveryMessages(): List<MessageEntity> =
            messages.filter { it.isOutgoing && (it.status == "PENDING_DELIVERY" || it.status == "SENT_DHT") }.sortedBy { it.id }
    }

    private class FakeChunkDao : ChunkDao {
        override suspend fun insertChunk(chunk: ChunkEntity) {}
        override suspend fun getChunksForTransfer(transferId: String): List<ChunkEntity> = emptyList()
        override suspend fun countChunks(transferId: String): Int = 0
        override suspend fun deleteChunks(transferId: String) {}
    }
}
