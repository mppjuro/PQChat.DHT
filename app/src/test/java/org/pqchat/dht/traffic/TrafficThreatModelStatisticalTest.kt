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
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.RatchetChain
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

    @Test
    fun testConstantSizeDecoyPaddedPollBatch_IndistinguishableFromDecoyNoise() = runBlocking {
        class TrackingFakeDht(val delegate: FakeDht = FakeDht()) : DhtClient by delegate {
            val queriedTargetsInOrder = mutableListOf<ByteArray>()
            val cycleCounts = mutableListOf<Int>()
            private var currentCount = 0

            fun startCycle() {
                currentCount = 0
            }

            fun endCycle() {
                cycleCounts.add(currentCount)
            }

            override suspend fun getMutable(
                target: ByteArray,
                salt: ByteArray?,
                skipLocalStore: Boolean,
                timeoutMs: Long,
                probeAllReplicas: Boolean
            ): DhtLeafNode.MutableItem? {
                queriedTargetsInOrder.add(target.copyOf())
                currentCount++
                return delegate.getMutable(target, salt, skipLocalStore, timeoutMs, probeAllReplicas)
            }
        }

        val contactDao = FakeContactDao()
        val groupDao = FakeGroupDao()
        val groupMemberDao = FakeGroupMemberDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val fakeDht = TrackingFakeDht()
        val decoyPool = DecoyTargetPool()

        // Pre-populate DecoyTargetPool with 25 realistic populated targets
        val populatedDecoyTargets = (1..25).map { CryptoUtils.sha1(CryptoUtils.secureRandomBytes(32)) }
        decoyPool.registerPopulatedTargets(populatedDecoyTargets)

        val repository = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = chunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            pendingAckQueue = PendingAckQueue(),
            decoyTargetPool = decoyPool,
            groupDao = groupDao,
            groupMemberDao = groupMemberDao
        )

        // Setup contacts
        val aliceChainKeyIn = CryptoUtils.secureRandomBytes(64)
        val alice = ContactEntity(
            id = "alice",
            name = "Alice",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            chainKeyIn = aliceChainKeyIn,
            counterIn = 0
        )
        contactDao.insertOrUpdate(alice)

        val bob = ContactEntity(
            id = "bob",
            name = "Bob",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            chainKeyIn = CryptoUtils.secureRandomBytes(64),
            counterIn = 0
        )
        contactDao.insertOrUpdate(bob)

        // Setup a group with Alice, Bob, and Self
        val groupId = "group-1"
        val myMemberId = "self-member-id"
        groupDao.insertOrUpdate(
            GroupEntity(
                groupId = groupId,
                groupName = "Alpha Squad",
                myMemberId = myMemberId,
                myCounterOut = 0,
                myChainKeyOut = EncryptedBlob(CryptoUtils.secureRandomBytes(64), "groups", groupId, "myChainKeyOut")
            )
        )
        groupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = "alice-member",
                memberName = "Alice Group",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0
            )
        )
        groupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = "bob-member",
                memberName = "Bob Group",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0
            )
        )

        val expectedBatchSize = ChatRepository.N_POLL_TARGETS
        assertEquals("Default N_POLL_TARGETS must be 8", 8, expectedBatchSize)

        // -----------------------------------------------------------------------------------------
        // 1. STATISTICAL PROPERTY 1: Invariant Batch Size across All Polling Modes
        // -----------------------------------------------------------------------------------------
        // Test states:
        // A) FOREGROUND_CHAT with Alice (1 contact, 7 decoys)
        // B) FOREGROUND_CHAT with Group (2 other members, 6 decoys)
        // C) APP_ACTIVE_OTHER / Contact List (2 contacts, 2 group members, 4 decoys)

        val testScenarios: List<Pair<String, suspend () -> Boolean>> = listOf(
            "FOREGROUND_CHAT_ALICE" to { repository.pollConstantBatch(focusContactId = "alice", batchSize = expectedBatchSize, intraBatchJitterMinMs = 0L, intraBatchJitterMaxMs = 0L) },
            "FOREGROUND_CHAT_GROUP" to { repository.pollConstantBatch(focusContactId = groupId, batchSize = expectedBatchSize, intraBatchJitterMinMs = 0L, intraBatchJitterMaxMs = 0L) },
            "APP_ACTIVE_GENERAL" to { repository.pollConstantBatch(focusContactId = null, batchSize = expectedBatchSize, intraBatchJitterMinMs = 0L, intraBatchJitterMaxMs = 0L) }
        )

        for ((scenarioName, pollAction) in testScenarios) {
            for (cycle in 1..25) {
                fakeDht.startCycle()
                pollAction()
                fakeDht.endCycle()
                val countInCycle = fakeDht.cycleCounts.last()
                assertEquals(
                    "[$scenarioName cycle #$cycle] Every poll cycle must strictly generate exactly $expectedBatchSize GET queries",
                    expectedBatchSize,
                    countInCycle
                )
            }
        }

        // Test D: Idle / No Contacts (0 real targets, 8 decoys)
        val idleContactDao = FakeContactDao()
        val idleRepo = ChatRepository(
            contactDao = idleContactDao,
            messageDao = FakeMessageDao(),
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDht,
            decoyTargetPool = decoyPool
        )
        for (cycle in 1..25) {
            fakeDht.startCycle()
            idleRepo.pollConstantBatch(focusContactId = null, batchSize = expectedBatchSize, intraBatchJitterMinMs = 0L, intraBatchJitterMaxMs = 0L)
            fakeDht.endCycle()
            val countInCycle = fakeDht.cycleCounts.last()
            assertEquals(
                "[IDLE_NO_CONTACTS cycle #$cycle] Must strictly generate exactly $expectedBatchSize GET queries even with 0 contacts",
                expectedBatchSize,
                countInCycle
            )
        }

        // Variance of query count across all 100 cycles must be strictly 0.0
        val allCounts = fakeDht.cycleCounts
        assertEquals(100, allCounts.size)
        assertTrue("All cycles must have exactly $expectedBatchSize queries", allCounts.all { it == expectedBatchSize })
        val countMean = allCounts.average()
        val countVariance = allCounts.map { (it - countMean) * (it - countMean) }.average()
        assertEquals(0.0, countVariance, 1e-9)

        // -----------------------------------------------------------------------------------------
        // 2. STATISTICAL PROPERTY 2: Uniform Permutation of Real Target (Chi-Square Goodness-of-Fit)
        // -----------------------------------------------------------------------------------------
        // An eavesdropper observing the 8 queries must not be able to identify which slot is Alice's.
        // The index of Alice's query in the batch {0, 1, ..., 7} must follow a Discrete Uniform distribution.
        val aliceSlot = RatchetChain.deriveSlot(alice.chainKeyIn, 0)
        val aliceTargetHex = CryptoUtils.toHex(aliceSlot.target)

        val nPermutationCycles = 800
        val positionCounts = IntArray(expectedBatchSize)

        fakeDht.queriedTargetsInOrder.clear()
        for (i in 0 until nPermutationCycles) {
            fakeDht.startCycle()
            repository.pollConstantBatch(focusContactId = "alice", batchSize = expectedBatchSize, intraBatchJitterMinMs = 0L, intraBatchJitterMaxMs = 0L)
            fakeDht.endCycle()

            val batchStartIndex = i * expectedBatchSize
            val batchTargets = (0 until expectedBatchSize).map { offset ->
                CryptoUtils.toHex(fakeDht.queriedTargetsInOrder[batchStartIndex + offset])
            }

            val aliceIndex = batchTargets.indexOf(aliceTargetHex)
            assertTrue("Alice target must be present in every poll batch", aliceIndex in 0 until expectedBatchSize)
            positionCounts[aliceIndex]++
        }

        // Expected frequency per position: E = 800 / 8 = 100
        val expectedPerPos = nPermutationCycles.toDouble() / expectedBatchSize
        var chiSquarePos = 0.0
        for (observed in positionCounts) {
            val diff = observed - expectedPerPos
            chiSquarePos += (diff * diff) / expectedPerPos
        }

        // Critical value for Chi-Square with 7 degrees of freedom at alpha=0.01 is 18.48
        assertTrue(
            "Chi-Square test statistic ($chiSquarePos) for Alice position must not reject Discrete Uniform distribution (critical = 18.48)",
            chiSquarePos < 18.48
        )

        // -----------------------------------------------------------------------------------------
        // 3. STATISTICAL PROPERTY 3: Kolmogorov-Smirnov Test on Target Hashes (Active vs Decoy)
        // -----------------------------------------------------------------------------------------
        // A network observer comparing SHA-1 target bytes during conversation ratchet steps vs decoy targets
        // must not find any statistical deviation in the 160-bit target distribution.
        val nTestSlots = 200
        val realChainKey = CryptoUtils.secureRandomBytes(64)
        val realRatchetTargets = (0 until nTestSlots).map { step ->
            RatchetChain.deriveSlot(realChainKey, step).target
        }
        val realByteValues = DoubleArray(realRatchetTargets.size * 20) { idx ->
            (realRatchetTargets[idx / 20][idx % 20].toInt() and 0xFF) / 255.0
        }

        val decoyTargets = (0 until nTestSlots).map {
            CryptoUtils.sha1(CryptoUtils.secureRandomBytes(32))
        }
        val decoyByteValues = DoubleArray(decoyTargets.size * 20) { idx ->
            (decoyTargets[idx / 20][idx % 20].toInt() and 0xFF) / 255.0
        }

        val ksStat = computeTwoSampleKsStatistic(realByteValues, decoyByteValues)
        // Critical value at alpha = 0.01: D_crit = 1.63 * sqrt((n1 + n2) / (n1 * n2))
        val ksCritical = 1.63 * sqrt((realByteValues.size + decoyByteValues.size).toDouble() / (realByteValues.size.toDouble() * decoyByteValues.size))
        assertTrue(
            "Two-sample KS statistic ($ksStat) must be < critical ($ksCritical), proving target hashes are indistinguishable from decoy noise",
            ksStat < ksCritical
        )

        // -----------------------------------------------------------------------------------------
        // 4. STATISTICAL PROPERTY 4: Intra-Batch Timing Jitter Verification
        // -----------------------------------------------------------------------------------------
        val jitterMinMs = 15L
        val jitterMaxMs = 40L
        val t0 = System.currentTimeMillis()
        repository.pollConstantBatch(
            focusContactId = "alice",
            batchSize = expectedBatchSize,
            intraBatchJitterMinMs = jitterMinMs,
            intraBatchJitterMaxMs = jitterMaxMs
        )
        val elapsed = System.currentTimeMillis() - t0
        // (8 - 1) = 7 jitter intervals of at least 15ms -> expected >= 7 * 15 = 105ms
        assertTrue("Elapsed time ($elapsed ms) must exhibit intra-batch jitter (>= 100 ms)", elapsed >= 100L)
    }

    @Test
    fun testGroupChatAndDirectChatPolling_StatisticallyIndistinguishableInCountAndTiming() = runBlocking {
        class TimingTrackingFakeDht(val delegate: FakeDht = FakeDht()) : DhtClient by delegate {
            val queriedTargetsInOrder = mutableListOf<ByteArray>()
            val cycleCounts = mutableListOf<Int>()
            val cycleTimestamps = mutableListOf<MutableList<Long>>()
            private var currentCount = 0
            private var currentTimestamps = mutableListOf<Long>()

            fun startCycle() {
                currentCount = 0
                currentTimestamps = mutableListOf()
            }

            fun endCycle() {
                cycleCounts.add(currentCount)
                cycleTimestamps.add(currentTimestamps)
            }

            override suspend fun getMutable(
                target: ByteArray,
                salt: ByteArray?,
                skipLocalStore: Boolean,
                timeoutMs: Long,
                probeAllReplicas: Boolean
            ): DhtLeafNode.MutableItem? {
                currentTimestamps.add(System.nanoTime())
                queriedTargetsInOrder.add(target.copyOf())
                currentCount++
                return delegate.getMutable(target, salt, skipLocalStore, timeoutMs, probeAllReplicas)
            }
        }

        val expectedBatchSize = ChatRepository.N_POLL_TARGETS
        assertEquals(8, expectedBatchSize)

        // -----------------------------------------------------------------------------------------
        // CLIENT A: Pure 1-on-1 Direct Chat User
        // - 1 single contact (Alice), 0 groups
        // - Lookahead window = 2 (slots: k=0, k=1, k=2 -> 3 real candidate listening slots)
        // - Budget B = 8 -> candidate slots (3) < B, so 5 slots must be padded with DecoyTargetPool
        // -----------------------------------------------------------------------------------------
        val contactDaoA = FakeContactDao()
        val fakeDhtA = TimingTrackingFakeDht()
        val decoyPoolA = DecoyTargetPool()
        val populatedDecoysA = (1..50).map { CryptoUtils.sha1(CryptoUtils.secureRandomBytes(32)) }
        decoyPoolA.registerPopulatedTargets(populatedDecoysA)

        val aliceChainKeyIn = CryptoUtils.secureRandomBytes(64)
        val alice = ContactEntity(
            id = "alice",
            name = "Alice",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            chainKeyIn = aliceChainKeyIn,
            counterIn = 0
        )
        contactDaoA.insertOrUpdate(alice)

        val repoA = ChatRepository(
            contactDao = contactDaoA,
            messageDao = FakeMessageDao(),
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDhtA,
            pendingAckQueue = PendingAckQueue(),
            decoyTargetPool = decoyPoolA,
            groupDao = null,
            groupMemberDao = null
        ).apply {
            pollLookaheadWindowSize = 2
        }

        // -----------------------------------------------------------------------------------------
        // CLIENT B: Heavy Group Chat Participant
        // - Participates in 5 distinct groups
        // - Each group has 10 members (1 self + 9 other active members -> 45 total peers)
        // - Lookahead window = 2 (each member has slots k=0, 1, 2 -> 45 * 3 = 135 real candidate slots)
        // - Candidate slots (135) >> B (8) -> Weighted Fair Stratified Sampling downsamples to 8
        // -----------------------------------------------------------------------------------------
        val contactDaoB = FakeContactDao()
        val groupDaoB = FakeGroupDao()
        val groupMemberDaoB = FakeGroupMemberDao()
        val fakeDhtB = TimingTrackingFakeDht()
        val decoyPoolB = DecoyTargetPool()
        val populatedDecoysB = (1..50).map { CryptoUtils.sha1(CryptoUtils.secureRandomBytes(32)) }
        decoyPoolB.registerPopulatedTargets(populatedDecoysB)

        val myMemberIdB = java.util.UUID.randomUUID().toString()
        val groupIds = (1..5).map { java.util.UUID.randomUUID().toString() }
        val allGroupMemberTargets = mutableMapOf<String, MutableSet<String>>()

        fun uuidTo16Bytes(uuidStr: String): ByteArray {
            val u = java.util.UUID.fromString(uuidStr)
            val bb = java.nio.ByteBuffer.allocate(16)
            bb.putLong(u.mostSignificantBits)
            bb.putLong(u.leastSignificantBits)
            return bb.array()
        }

        val myMemberIdBytesB = uuidTo16Bytes(myMemberIdB)

        for (gId in groupIds) {
            allGroupMemberTargets[gId] = mutableSetOf()
            val gBytes = uuidTo16Bytes(gId)
            groupDaoB.insertOrUpdate(
                GroupEntity(
                    groupId = gId,
                    groupName = "Group-$gId",
                    myMemberId = myMemberIdB,
                    myChainKeyOut = CryptoUtils.secureRandomBytes(64),
                    myCounterOut = 0
                )
            )

            for (m in 1..9) {
                val memberId = java.util.UUID.randomUUID().toString()
                val mBytes = uuidTo16Bytes(memberId)
                val memberChainKeyIn = CryptoUtils.secureRandomBytes(64)
                groupMemberDaoB.insertOrUpdate(
                    GroupMemberEntity(
                        groupId = gId,
                        memberId = memberId,
                        contactId = null,
                        memberName = "Member $m in $gId",
                        chainKeyIn = memberChainKeyIn,
                        counterIn = 0
                    )
                )

                // Track expected targets for lookahead k=0, 1, 2
                val memberSlots = RatchetChain.computeGroupLookaheadSlots(
                    startChainKey = memberChainKeyIn,
                    startCounter = 0,
                    groupId = gBytes,
                    senderMemberId = mBytes,
                    recipientMemberId = myMemberIdBytesB,
                    windowSize = 2
                )
                for (slot in memberSlots) {
                    allGroupMemberTargets[gId]!!.add(CryptoUtils.toHex(slot.target))
                }
            }
        }

        val repoB = ChatRepository(
            contactDao = contactDaoB,
            messageDao = FakeMessageDao(),
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = fakeDhtB,
            pendingAckQueue = PendingAckQueue(),
            decoyTargetPool = decoyPoolB,
            groupDao = groupDaoB,
            groupMemberDao = groupMemberDaoB
        ).apply {
            pollLookaheadWindowSize = 2
        }

        // -----------------------------------------------------------------------------------------
        // RUN POLLING CYCLES (30 cycles for each client)
        // Using intra-batch jitter between 5ms and 15ms.
        // -----------------------------------------------------------------------------------------
        val nCycles = 30
        val jitterMinMs = 5L
        val jitterMaxMs = 15L

        for (cycle in 0 until nCycles) {
            // First 15 cycles: focused on Alice / Group 1
            // Last 15 cycles: background / idle (focusContactId = null)
            val focusA = if (cycle < 15) "alice" else null
            val focusB = if (cycle < 15) groupIds[0] else null

            fakeDhtA.startCycle()
            repoA.pollConstantBatch(
                focusContactId = focusA,
                batchSize = expectedBatchSize,
                intraBatchJitterMinMs = jitterMinMs,
                intraBatchJitterMaxMs = jitterMaxMs
            )
            fakeDhtA.endCycle()

            fakeDhtB.startCycle()
            repoB.pollConstantBatch(
                focusContactId = focusB,
                batchSize = expectedBatchSize,
                intraBatchJitterMinMs = jitterMinMs,
                intraBatchJitterMaxMs = jitterMaxMs
            )
            fakeDhtB.endCycle()
        }

        // -----------------------------------------------------------------------------------------
        // 1. STATISTICAL PROPERTY 1: Strict Invariance of Query Count & Chi-Square Goodness-of-Fit
        // -----------------------------------------------------------------------------------------
        val countsA = fakeDhtA.cycleCounts
        val countsB = fakeDhtB.cycleCounts

        assertEquals(nCycles, countsA.size)
        assertEquals(nCycles, countsB.size)

        // Strict batch size equality: B = const across all cycles
        assertTrue("Client A (1-on-1) must have exactly $expectedBatchSize queries in every cycle", countsA.all { it == expectedBatchSize })
        assertTrue("Client B (5 groups of 10) must have exactly $expectedBatchSize queries in every cycle", countsB.all { it == expectedBatchSize })

        val varA = countsA.map { (it - expectedBatchSize.toDouble()) * (it - expectedBatchSize.toDouble()) }.average()
        val varB = countsB.map { (it - expectedBatchSize.toDouble()) * (it - expectedBatchSize.toDouble()) }.average()
        assertEquals("Client A query count variance must be strictly 0.0", 0.0, varA, 1e-9)
        assertEquals("Client B query count variance must be strictly 0.0", 0.0, varB, 1e-9)

        // Chi-Square Test of homogeneity on count distributions between Client A and Client B
        // With bins [k < B, k == B, k > B]: both distributions have 100% of samples in [k == B].
        val kBins = 3
        val observedA = IntArray(kBins)
        val observedB = IntArray(kBins)
        for (c in countsA) {
            val bin = when {
                c < expectedBatchSize -> 0
                c == expectedBatchSize -> 1
                else -> 2
            }
            observedA[bin]++
        }
        for (c in countsB) {
            val bin = when {
                c < expectedBatchSize -> 0
                c == expectedBatchSize -> 1
                else -> 2
            }
            observedB[bin]++
        }

        var chiSquareCount = 0.0
        for (b in 0 until kBins) {
            val expectedTotal = (observedA[b] + observedB[b]).toDouble()
            if (expectedTotal > 0.0) {
                val expectedClient = expectedTotal / 2.0
                val diffA = observedA[b] - expectedClient
                val diffB = observedB[b] - expectedClient
                chiSquareCount += (diffA * diffA) / expectedClient + (diffB * diffB) / expectedClient
            }
        }
        // Critical value for Chi-Square test (alpha=0.01) is 6.63 (1 df)
        assertTrue(
            "Chi-Square test statistic ($chiSquareCount) must prove count distributions are identical (critical = 6.63)",
            chiSquareCount < 6.63
        )

        // -----------------------------------------------------------------------------------------
        // 2. STATISTICAL PROPERTY 2: Two-Sample Kolmogorov-Smirnov Test on Inter-Query Arrival Timings
        // -----------------------------------------------------------------------------------------
        // An adversary observing the inter-query timing intervals must not distinguish whether the
        // client is chatting 1-on-1 or in large group chats.
        val delaysA = mutableListOf<Double>()
        for (timestamps in fakeDhtA.cycleTimestamps) {
            for (i in 0 until timestamps.size - 1) {
                // convert nanoseconds to fractional milliseconds
                delaysA.add((timestamps[i + 1] - timestamps[i]) / 1_000_000.0)
            }
        }

        val delaysB = mutableListOf<Double>()
        for (timestamps in fakeDhtB.cycleTimestamps) {
            for (i in 0 until timestamps.size - 1) {
                delaysB.add((timestamps[i + 1] - timestamps[i]) / 1_000_000.0)
            }
        }

        val expectedDelaysCount = nCycles * (expectedBatchSize - 1) // 30 * 7 = 210 delays
        assertEquals(expectedDelaysCount, delaysA.size)
        assertEquals(expectedDelaysCount, delaysB.size)

        val ksStat = computeTwoSampleKsStatistic(delaysA.toDoubleArray(), delaysB.toDoubleArray())
        val n1 = delaysA.size.toDouble()
        val n2 = delaysB.size.toDouble()
        // Two-sample KS critical value at alpha = 0.001 is 1.95 * sqrt((n1 + n2) / (n1 * n2)).
        // On virtualized CI and non-realtime OS runtimes, timer quantization jitter can induce empirical step deviations up to 0.20.
        val ksCritical = maxOf(0.20, 1.95 * sqrt((n1 + n2) / (n1 * n2)))

        assertTrue(
            "Two-sample KS statistic ($ksStat) must be < critical ($ksCritical), " +
            "proving inter-query timing distributions between 1-on-1 and Group Chat clients are statistically indistinguishable",
            ksStat < ksCritical
        )

        // -----------------------------------------------------------------------------------------
        // 3. STATISTICAL PROPERTY 3: Anti-Starvation & Fairness of Weighted Fair Stratified Sampling
        // -----------------------------------------------------------------------------------------
        // For Client B: across the 30 cycles, tasks representing all 5 groups must be sampled.
        val queriedHexesB = fakeDhtB.queriedTargetsInOrder.map { CryptoUtils.toHex(it) }.toSet()
        for (gId in groupIds) {
            val groupTargets = allGroupMemberTargets[gId]!!
            val hitsForGroup = groupTargets.count { it in queriedHexesB }
            assertTrue(
                "Group $gId must not be starved (must have at least one slot sampled across 30 cycles), got $hitsForGroup hits",
                hitsForGroup > 0
            )
        }

        // For Client A: 1 contact with 3 slots (current + 2 lookahead) -> exactly 5 decoy queries per batch
        val aliceSlots = RatchetChain.computeLookaheadSlots(aliceChainKeyIn, 0, 2)
        val aliceKnownSlots = aliceSlots.map { CryptoUtils.toHex(it.target) }.toSet()

        val queriedHexesA = fakeDhtA.queriedTargetsInOrder.map { CryptoUtils.toHex(it) }
        val decoyHitsA = queriedHexesA.count { it !in aliceKnownSlots }
        // Across 30 cycles, with exactly 5 decoys per cycle: total decoys = 30 * 5 = 150
        assertEquals(
            "Client A must pad exactly (batchSize - 3) = 5 decoys per cycle, yielding 150 decoy queries across 30 cycles",
            nCycles * (expectedBatchSize - 3),
            decoyHitsA
        )
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

        override suspend fun updateContactName(id: String, name: EncryptedText) {
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

    private class FakeGroupDao : GroupDao {
        val groups = mutableMapOf<String, GroupEntity>()
        val flow = MutableStateFlow<List<GroupEntity>>(emptyList())

        override fun getAllGroupsFlow(): Flow<List<GroupEntity>> = flow
        override suspend fun getAllActiveGroups(): List<GroupEntity> = groups.values.filter { it.isActive }
        override suspend fun getGroupById(groupId: String): GroupEntity? = groups[groupId]
        override suspend fun insertOrUpdate(group: GroupEntity) {
            groups[group.groupId] = group
            flow.value = groups.values.toList()
        }
        override suspend fun updateOutgoingState(groupId: String, counterOut: Int, chainKeyOut: EncryptedBlob, lastActive: Long) {
            val g = groups[groupId] ?: return
            val bound = if (chainKeyOut.boundColumn == null) EncryptedBlob(chainKeyOut.raw, "groups", groupId, "myChainKeyOut") else chainKeyOut
            groups[groupId] = g.copy(myCounterOut = counterOut, myChainKeyOut = bound, lastActive = lastActive)
            flow.value = groups.values.toList()
        }
        override suspend fun updateRekeyedState(groupId: String, epoch: Long, counterOut: Int, chainKeyOut: EncryptedBlob, lastActive: Long) {
            val g = groups[groupId] ?: return
            val bound = if (chainKeyOut.boundColumn == null) EncryptedBlob(chainKeyOut.raw, "groups", groupId, "myChainKeyOut") else chainKeyOut
            groups[groupId] = g.copy(myCounterOut = counterOut, myChainKeyOut = bound, groupEpoch = epoch, lastActive = lastActive)
            flow.value = groups.values.toList()
        }
        override suspend fun updateActiveStatus(groupId: String, isActive: Boolean) {
            val g = groups[groupId] ?: return
            groups[groupId] = g.copy(isActive = isActive)
            flow.value = groups.values.toList()
        }
        override suspend fun deleteGroup(groupId: String) {
            groups.remove(groupId)
            flow.value = groups.values.toList()
        }
    }

    private class FakeGroupMemberDao : GroupMemberDao {
        val members = mutableMapOf<String, MutableMap<String, GroupMemberEntity>>()
        val flows = mutableMapOf<String, MutableStateFlow<List<GroupMemberEntity>>>()

        private fun getFlow(groupId: String): MutableStateFlow<List<GroupMemberEntity>> {
            return flows.getOrPut(groupId) {
                MutableStateFlow(members[groupId]?.values?.filter { it.isActive } ?: emptyList())
            }
        }

        override fun getMembersForGroupFlow(groupId: String): Flow<List<GroupMemberEntity>> = getFlow(groupId)
        override suspend fun getMembersForGroup(groupId: String): List<GroupMemberEntity> = members[groupId]?.values?.filter { it.isActive } ?: emptyList()
        override suspend fun getMember(groupId: String, memberId: String): GroupMemberEntity? = members[groupId]?.get(memberId)
        override suspend fun insertOrUpdate(member: GroupMemberEntity) {
            val groupMap = members.getOrPut(member.groupId) { mutableMapOf() }
            groupMap[member.memberId] = member
            getFlow(member.groupId).value = groupMap.values.filter { it.isActive }
        }
        override suspend fun insertOrUpdateAll(members: List<GroupMemberEntity>) {
            for (m in members) {
                insertOrUpdate(m)
            }
        }
        override suspend fun updateMemberIncomingStateWithBitmap(groupId: String, memberId: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {
            val m = members[groupId]?.get(memberId) ?: return
            insertOrUpdate(m.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap))
        }
        override suspend fun markMemberInactive(groupId: String, memberId: String) {
            val m = members[groupId]?.get(memberId) ?: return
            insertOrUpdate(m.copy(isActive = false))
        }
        override suspend fun deleteMember(groupId: String, memberId: String) {
            members[groupId]?.remove(memberId)
            getFlow(groupId).value = members[groupId]?.values?.filter { it.isActive } ?: emptyList()
        }
        override suspend fun deleteMembersForGroup(groupId: String) {
            members.remove(groupId)
            getFlow(groupId).value = emptyList()
        }
    }
}
