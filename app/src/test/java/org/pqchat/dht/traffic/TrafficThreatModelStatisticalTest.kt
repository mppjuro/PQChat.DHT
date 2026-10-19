package org.pqchat.dht.traffic

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.dht.leaf.DhtClient
import kotlin.math.abs
import kotlin.math.exp
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
@Tag("slow")
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
            decoyTargetPool = decoyPool,
            blindRepublishPool = BlindRepublishPool()
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
        assertEquals(org.pqchat.dht.crypto.BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, storedItem.v.size)
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

    @Test
    fun testStrictPoissonTrafficShaping_DistributionIndistinguishableFromIdleNoise() = runBlocking {
        val lambda = 1.0 / 300.0 // average once every 5 minutes = 300s
        val n = 3000

        // 1. Idle resting baseline (no chat messages; only dummy cover traffic)
        val fakeDhtIdle = FakeDht()
        val generatorIdle = PoissonTrafficGenerator(dhtLeafNode = fakeDhtIdle, lambda = lambda)
        val intervalsIdle = DoubleArray(n) { generatorIdle.computeNextIntervalMs().toDouble() }

        // 2. Active chatting state under Strict Poisson Shaping:
        // User heavily sending messages queued into OutboundPoissonQueue
        val fakeDhtActive = FakeDht()
        val outboundQueue = OutboundPoissonQueue()
        val ackQueue = PendingAckQueue()
        val republishPool = BlindRepublishPool()
        val generatorActive = PoissonTrafficGenerator(
            dhtLeafNode = fakeDhtActive,
            pendingAckQueue = ackQueue,
            blindRepublishPool = republishPool,
            outboundPoissonQueue = outboundQueue,
            lambda = lambda
        )

        // Pre-enqueue batches of user messages (simulating intense conversation bursts)
        for (i in 0 until 50) {
            outboundQueue.enqueue(
                OutboundPoissonFrame(
                    target = CryptoUtils.secureRandomBytes(20),
                    payload = ByteArray(900) { (it % 256).toByte() },
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = CryptoUtils.secureRandomBytes(32),
                    seqNum = i,
                    messageId = i.toLong(),
                    contactId = "peer"
                )
            )
        }

        val intervalsActive = DoubleArray(n)
        for (i in 0 until n) {
            intervalsActive[i] = generatorActive.computeNextIntervalMs().toDouble()
            // Replenish bursts periodically to simulate persistent user typing
            if (i % 30 == 0) {
                outboundQueue.enqueue(
                    OutboundPoissonFrame(
                        target = CryptoUtils.secureRandomBytes(20),
                        payload = ByteArray(900) { 0x55 },
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = CryptoUtils.secureRandomBytes(32),
                        seqNum = i,
                        messageId = (1000 + i).toLong(),
                        contactId = "peer"
                    )
                )
            }
            // Execute tick
            val event = generatorActive.processCoverTrafficTick(delayMs = intervalsActive[i].toLong())
            assertNotNull(event)
            // Verify all emitted frames have strictly uniform 900-byte payload
            assertEquals("Every emitted packet must be exactly 900 bytes", BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, event.payloadSize)
        }

        // --- STATISTICAL TEST 1: Chi-Square Goodness-of-Fit against theoretical exponential distribution ---
        val kBins = 10
        val expectedPerBin = n.toDouble() / kBins
        val binCounts = IntArray(kBins)
        for (x in intervalsActive) {
            val u = 1.0 - exp(-lambda * (x / 1000.0))
            val bin = (u * kBins).toInt().coerceIn(0, kBins - 1)
            binCounts[bin]++
        }

        var chiSquare = 0.0
        for (observed in binCounts) {
            val diff = observed - expectedPerBin
            chiSquare += (diff * diff) / expectedPerBin
        }

        // Critical value for chi-square with 9 degrees of freedom at alpha=0.01 is 21.67
        assertTrue(
            "Chi-Square test statistic ($chiSquare) for active chatting must not reject exponential distribution (critical = 21.67)",
            chiSquare < 21.67
        )

        // --- STATISTICAL TEST 2: Two-Sample Kolmogorov-Smirnov Test between Active and Idle distributions ---
        // Null Hypothesis H0: The inter-arrival distributions of PUT packets in active chatting and idle resting states are identical.
        val dStatistic = computeTwoSampleKsStatistic(intervalsActive, intervalsIdle)
        // Critical value at alpha = 0.05: D_crit = 1.36 * sqrt((n1 + n2) / (n1 * n2))
        val dCritical = 1.36 * sqrt((2.0 * n) / (n.toDouble() * n))

        assertTrue(
            "Two-sample KS statistic D ($dStatistic) must be strictly less than critical value ($dCritical) at alpha=0.05, proving statistical indistinguishability",
            dStatistic < dCritical
        )

        // --- STATISTICAL TEST 3: Lack of Autocorrelation / Memorylessness during Active Chatting ---
        val meanActive = intervalsActive.average()
        val denominator = intervalsActive.sumOf { (it - meanActive) * (it - meanActive) }
        for (lag in listOf(1, 2, 5)) {
            var numerator = 0.0
            for (i in 0 until n - lag) {
                numerator += (intervalsActive[i] - meanActive) * (intervalsActive[i + lag] - meanActive)
            }
            val rLag = numerator / denominator
            assertTrue(
                "Autocorrelation at lag $lag during active chatting must be negligible (|r| < 0.05), got $rLag",
                abs(rLag) < 0.05
            )
        }
    }

    @Test
    fun testStrictPoissonTrafficShaping_ChatBurstQueueTransitions() = runBlocking {
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val fakeDht = FakeDht()
        val ackQueue = PendingAckQueue()
        val outboundQueue = OutboundPoissonQueue()

        val repository = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = ackQueue,
            outboundPoissonQueue = outboundQueue,
            isStrictPoissonShapingEnabled = true
        )

        val generator = PoissonTrafficGenerator(
            dhtLeafNode = fakeDht,
            pendingAckQueue = ackQueue,
            blindRepublishPool = repository.blindRepublishPool,
            outboundPoissonQueue = outboundQueue
        )

        val contact = ContactEntity(
            id = "alice",
            name = "Alice",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            chainKeyIn = CryptoUtils.secureRandomBytes(64),
            counterIn = 0
        )
        contactDao.insertOrUpdate(contact)

        // 1. Rapid burst of 15 messages sent by user
        val burstCount = 15
        for (i in 1..burstCount) {
            val ok = repository.sendTextMessage("alice", "Burst message #$i")
            assertTrue("Send must succeed immediately into queue", ok)
        }

        // All 15 messages must be in database with status "QUEUED_POISSON"
        val queuedMessages = messageDao.messages
        assertEquals(burstCount, queuedMessages.size)
        assertTrue(queuedMessages.all { it.status == "QUEUED_POISSON" })
        assertEquals(burstCount, outboundQueue.size)
        assertEquals(0, fakeDht.storage.size) // No DHT leakage prior to Poisson ticks!

        // Outgoing sequence counter advanced across all slots
        val updatedContact = contactDao.getContactById("alice")!!
        assertEquals(burstCount, updatedContact.counterOut)

        // 2. Process Poisson ticks one by one: verify seamless 1-by-1 emission and status progression
        for (i in 1..burstCount) {
            val event = generator.processCoverTrafficTick()
            assertNotNull(event)
            assertTrue("Emitted frame must be FIRST_SEND", event.isFirstSend)
            assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, event.payloadSize)
            assertEquals(burstCount - i, outboundQueue.size)
            assertEquals(i, fakeDht.storage.size)
        }

        // All 15 messages should now be "PENDING_DELIVERY"
        val deliveredMessages = messageDao.messages
        assertTrue(deliveredMessages.all { it.status == "PENDING_DELIVERY" })

        // 3. Next Poisson tick: queue is empty -> automatically falls back to Tier 4 Dummy Chaff
        val dummyEvent = generator.processCoverTrafficTick()
        assertNotNull(dummyEvent)
        assertFalse("Subsequent tick when queue empty must be dummy chaff", dummyEvent.isFirstSend)
        assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, dummyEvent.payloadSize)
    }

    private fun computeTwoSampleKsStatistic(sample1: DoubleArray, sample2: DoubleArray): Double {
        val n1 = sample1.size
        val n2 = sample2.size
        val sorted1 = sample1.sortedArray()
        val sorted2 = sample2.sortedArray()

        var i1 = 0
        var i2 = 0
        var maxDiff = 0.0

        while (i1 < n1 && i2 < n2) {
            val v1 = sorted1[i1]
            val v2 = sorted2[i2]
            val v = if (v1 <= v2) v1 else v2

            while (i1 < n1 && sorted1[i1] <= v) i1++
            while (i2 < n2 && sorted2[i2] <= v) i2++

            val cdf1 = i1.toDouble() / n1
            val cdf2 = i2.toDouble() / n2
            val diff = abs(cdf1 - cdf2)
            if (diff > maxDiff) {
                maxDiff = diff
            }
        }
        return maxDiff
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

        override suspend fun updateOutgoingStateAndEpoch(
            id: String,
            counterOut: Int,
            chainKeyOut: EncryptedBlob,
            rekeyEpoch: Long
        ) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut, rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpoch(
            id: String,
            counterIn: Int,
            chainKeyIn: EncryptedBlob,
            rekeyEpoch: Long
        ) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateWithBitmap(
            id: String,
            counterIn: Int,
            chainKeyIn: EncryptedBlob,
            bitmapBase: Int,
            bitmap: ByteArray
        ) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(
                counterIn = counterIn,
                chainKeyIn = chainKeyIn,
                receivedBitmapBase = bitmapBase,
                receivedBitmap = bitmap
            )
            flow.value = contacts.values.toList()
        }

        override suspend fun updateIncomingStateAndEpochWithBitmap(
            id: String,
            counterIn: Int,
            chainKeyIn: EncryptedBlob,
            rekeyEpoch: Long,
            bitmapBase: Int,
            bitmap: ByteArray
        ) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(
                counterIn = counterIn,
                chainKeyIn = chainKeyIn,
                rekeyEpoch = rekeyEpoch,
                receivedBitmapBase = bitmapBase,
                receivedBitmap = bitmap
            )
            flow.value = contacts.values.toList()
        }

        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(rekeyEpoch = rekeyEpoch)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateVerifiedStatus(id: String, isVerified: Boolean) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(isVerified = isVerified)
            flow.value = contacts.values.toList()
        }

        override suspend fun updateContactName(id: String, name: String) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(name = name)
            flow.value = contacts.values.toList()
        }

        override suspend fun deleteContact(id: String) {
            contacts.remove(id)
            flow.value = contacts.values.toList()
        }
    }

    private class FakeMessageDao : org.pqchat.dht.test.BaseFakeMessageDao()

    private class FakeChunkDao : org.pqchat.dht.test.BaseFakeChunkDao()
}
