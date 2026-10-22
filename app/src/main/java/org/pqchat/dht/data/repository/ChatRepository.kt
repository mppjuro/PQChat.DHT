package org.pqchat.dht.data.repository

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.crypto.MLKemEngine
import org.pqchat.dht.data.db.*
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.ChunkingEngine
import org.pqchat.dht.protocol.RatchetChain
import org.pqchat.dht.protocol.RekeyCoordinator
import org.pqchat.dht.protocol.SlidingWindowBitmap
import org.pqchat.dht.traffic.PollingWorker
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class ChatRepository(
    val contactDao: ContactDao,
    val messageDao: MessageDao,
    val chunkDao: ChunkDao,
    val pendingRekeyOfferDao: PendingRekeyOfferDao?,
    val skippedKeyDao: SkippedKeyDao? = null,
    val dhtLeafNode: org.pqchat.dht.dht.leaf.DhtClient,
    val pendingAckQueue: org.pqchat.dht.traffic.PendingAckQueue = org.pqchat.dht.traffic.PendingAckQueue(),
    val decoyTargetPool: org.pqchat.dht.traffic.DecoyTargetPool = org.pqchat.dht.traffic.DecoyTargetPool.defaultInstance,
    val blindRepublishPool: org.pqchat.dht.traffic.BlindRepublishPool = org.pqchat.dht.traffic.BlindRepublishPool.defaultInstance,
    val outboundPoissonQueue: org.pqchat.dht.traffic.OutboundPoissonQueue = org.pqchat.dht.traffic.OutboundPoissonQueue(),
    var isStrictPoissonShapingEnabled: Boolean = false,
    var strictPoissonShapingEnabledProvider: (() -> Boolean)? = null,
    var researchTelemetryProvider: (() -> org.pqchat.dht.research.ResearchTelemetryManager?)? = {
        try {
            org.pqchat.dht.PQChatApplication.instance.researchTelemetryManager
        } catch (_: Throwable) {
            null
        }
    },
    val groupDao: GroupDao? = null,
    val groupMemberDao: GroupMemberDao? = null,
    val pollDao: PollDao? = null,
    var settingsManager: org.pqchat.dht.data.settings.AppSettingsManager? = null
) {
    val researchTelemetry: org.pqchat.dht.research.ResearchTelemetryManager?
        get() = researchTelemetryProvider?.invoke()

    fun isStrictPoissonShaping(): Boolean =
        strictPoissonShapingEnabledProvider?.invoke() ?: isStrictPoissonShapingEnabled

    val canaryQueue = java.util.concurrent.ConcurrentLinkedQueue<org.pqchat.dht.traffic.OutboundPoissonFrame>()

    fun pollPendingSafetyCanary(): org.pqchat.dht.traffic.OutboundPoissonFrame? {
        return canaryQueue.poll()
    }

    constructor(
        contactDao: ContactDao,
        messageDao: MessageDao,
        chunkDao: ChunkDao,
        dhtLeafNode: org.pqchat.dht.dht.leaf.DhtClient
    ) : this(contactDao, messageDao, chunkDao, null, null, dhtLeafNode, org.pqchat.dht.traffic.PendingAckQueue())

    constructor(
        contactDao: ContactDao,
        messageDao: MessageDao,
        chunkDao: ChunkDao,
        pendingRekeyOfferDao: PendingRekeyOfferDao?,
        dhtLeafNode: org.pqchat.dht.dht.leaf.DhtClient
    ) : this(contactDao, messageDao, chunkDao, pendingRekeyOfferDao, null, dhtLeafNode, org.pqchat.dht.traffic.PendingAckQueue())

    constructor(
        contactDao: ContactDao,
        messageDao: MessageDao,
        chunkDao: ChunkDao,
        dhtLeafNode: org.pqchat.dht.dht.leaf.DhtClient,
        pendingAckQueue: org.pqchat.dht.traffic.PendingAckQueue
    ) : this(contactDao, messageDao, chunkDao, null, null, dhtLeafNode, pendingAckQueue)

    constructor(
        database: AppDatabase,
        dhtLeafNode: org.pqchat.dht.dht.leaf.DhtClient,
        pendingAckQueue: org.pqchat.dht.traffic.PendingAckQueue = org.pqchat.dht.traffic.PendingAckQueue(),
        decoyTargetPool: org.pqchat.dht.traffic.DecoyTargetPool = org.pqchat.dht.traffic.DecoyTargetPool.defaultInstance,
        blindRepublishPool: org.pqchat.dht.traffic.BlindRepublishPool = org.pqchat.dht.traffic.BlindRepublishPool.defaultInstance,
        outboundPoissonQueue: org.pqchat.dht.traffic.OutboundPoissonQueue = org.pqchat.dht.traffic.OutboundPoissonQueue(),
        isStrictPoissonShapingEnabled: Boolean = false,
        strictPoissonShapingEnabledProvider: (() -> Boolean)? = null,
        settingsManager: org.pqchat.dht.data.settings.AppSettingsManager? = null
    ) : this(
        database.contactDao(),
        database.messageDao(),
        database.chunkDao(),
        database.pendingRekeyOfferDao(),
        database.skippedKeyDao(),
        dhtLeafNode,
        pendingAckQueue,
        decoyTargetPool,
        blindRepublishPool,
        outboundPoissonQueue,
        isStrictPoissonShapingEnabled,
        strictPoissonShapingEnabledProvider,
        groupDao = database.groupDao(),
        groupMemberDao = database.groupMemberDao(),
        pollDao = database.pollDao(),
        settingsManager = settingsManager
    )

    /**
     * Average number of decoy GET queries executed per polling pass (docs/threat_model.md Section 5.1).
     */
    @Volatile
    var decoyGetRatio: Double = 1.5

    @Volatile
    var enableDecoyGets: Boolean = true

    /**
     * Maximum randomized hold delay in ms for outgoing PUT operations (Delayed PUT).
     * Breaks temporal correlation between chat interaction and DHT emission.
     */
    @Volatile
    var delayedPutMaxMs: Long = 2000L

    /**
     * Number of parallel dummy decoy PUT slots published per outgoing message.
     * Blurs sender emissions across multiple populated targets.
     */
    @Volatile
    var decoyPutSlotsCount: Int = 1

    /**
     * Constant budget of GET queries executed in each polling batch (docs/threat_model.md).
     * Padded with DecoyTargetPool queries to guarantee constant size and target anonymity.
     */
    @Volatile
    var pollBatchSize: Int = N_POLL_TARGETS

    /**
     * Lookahead window size for pre-polling out-of-order slots in constant polling batches.
     */
    @Volatile
    var pollLookaheadWindowSize: Int = 2

    @Volatile
    var intraBatchJitterMinMs: Long = 20L

    @Volatile
    var intraBatchJitterMaxMs: Long = 80L

    private val repositoryScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val contactMutexes = ConcurrentHashMap<String, Mutex>()
    private val _rekeyInProgressContacts = MutableStateFlow<Set<String>>(emptySet())
    val rekeyInProgressContacts: StateFlow<Set<String>> = _rekeyInProgressContacts.asStateFlow()
    val voiceSegmentAssembler = org.pqchat.dht.media.voice.VoiceSegmentAssembler()

    data class ImageDownloadProgress(
        val transferId: String,
        val contactId: String,
        val seqNum: Int,
        val receivedChunks: Int,
        val totalChunks: Int
    ) {
        val progressFraction: Float get() = if (totalChunks > 0) receivedChunks.toFloat() / totalChunks else 0f
        val progressPercent: Int get() = (progressFraction * 100).toInt()
    }

    private val _imageDownloadProgress = MutableStateFlow<Map<String, ImageDownloadProgress>>(emptyMap())
    val imageDownloadProgress: StateFlow<Map<String, ImageDownloadProgress>> = _imageDownloadProgress.asStateFlow()

    init {
        repositoryScope.launch {
            loadPendingTransfersProgress()
        }
    }

    suspend fun loadPendingTransfersProgress() {
        try {
            val pending = chunkDao.getAllPendingTransfers()
            val map = mutableMapOf<String, ImageDownloadProgress>()
            for (p in pending) {
                val count = chunkDao.countChunks(p.transferId)
                map[p.transferId] = ImageDownloadProgress(
                    transferId = p.transferId,
                    contactId = p.contactId,
                    seqNum = p.seqNum,
                    receivedChunks = count,
                    totalChunks = p.totalChunks
                )
            }
            _imageDownloadProgress.value = map
        } catch (_: Exception) {}
    }

    fun isRekeyPendingFlow(contactId: String): Flow<Boolean> {
        val dbFlow = pendingRekeyOfferDao?.isRekeyPendingFlow(contactId) ?: flowOf(false)
        return combine(dbFlow, _rekeyInProgressContacts) { inDb, inMem ->
            inDb || inMem.contains(contactId)
        }
    }

    suspend fun initiateRekey(contactId: String): Boolean = withContext(Dispatchers.IO) {
        getContactMutex(contactId).withLock {
            val contact = contactDao.getContactById(contactId) ?: return@withLock false
            if (pendingRekeyOfferDao?.getPendingOffer(contactId) != null) {
                return@withLock false
            }
            sendRekeyOfferInternal(contact)
        }
    }

    var onIncomingMessageDelivered: ((contactId: String, textContent: String, isImage: Boolean) -> Unit)? = null
    var onRepublishTaskUpdated: (() -> Unit)? = null

    suspend fun markMessageExpiredOffline(messageId: Long) = withContext(Dispatchers.IO) {
        messageDao.updateStatus(messageId, "EXPIRED_OFFLINE")
        org.pqchat.dht.service.DhtWorker.unregisterRepublishTask(messageId)
        onRepublishTaskUpdated?.invoke()
    }

    suspend fun expireOutdatedPendingMessages(
        maxTtlMs: Long,
        currentTimeMs: Long = System.currentTimeMillis()
    ): List<Long> = withContext(Dispatchers.IO) {
        val pending = messageDao.getAllPendingDeliveryMessages()
        val expiredIds = mutableListOf<Long>()
        for (msg in pending) {
            val age = (currentTimeMs - msg.timestamp).coerceAtLeast(0L)
            if (age >= maxTtlMs) {
                messageDao.updateStatus(msg.id, "EXPIRED_OFFLINE")
                org.pqchat.dht.service.DhtWorker.unregisterRepublishTask(msg.id)
                expiredIds.add(msg.id)
            }
        }
        if (expiredIds.isNotEmpty()) {
            onRepublishTaskUpdated?.invoke()
        }
        expiredIds
    }

    fun getContactMutex(contactId: String): Mutex =
        contactMutexes.computeIfAbsent(contactId) { Mutex() }

    private val groupMutexes = ConcurrentHashMap<String, Mutex>()
    fun getGroupMutex(groupId: String): Mutex =
        groupMutexes.computeIfAbsent(groupId) { Mutex() }

    fun getAllGroupsFlow(): Flow<List<GroupEntity>> =
        (groupDao?.getAllGroupsFlow() ?: flowOf(emptyList())).catch { emit(emptyList()) }

    fun getGroupMembersFlow(groupId: String): Flow<List<GroupMemberEntity>> =
        (groupMemberDao?.getMembersForGroupFlow(groupId) ?: flowOf(emptyList())).catch { emit(emptyList()) }

    suspend fun getGroup(groupId: String): GroupEntity? = withContext(Dispatchers.IO) {
        groupDao?.getGroupById(groupId)
    }

    fun getPollFlow(pollId: String): Flow<PollEntity?> =
        pollDao?.getPollFlow(pollId) ?: flowOf(null)

    fun getPollVotesFlow(pollId: String): Flow<List<PollVoteEntity>> =
        pollDao?.getVotesForPollFlow(pollId) ?: flowOf(emptyList())

    fun getPollsForGroupFlow(groupId: String): Flow<List<PollEntity>> =
        pollDao?.getPollsForGroupFlow(groupId) ?: flowOf(emptyList())

    suspend fun getPoll(pollId: String): PollEntity? = withContext(Dispatchers.IO) {
        pollDao?.getPoll(pollId)
    }

    suspend fun getVotesForPoll(pollId: String): List<PollVoteEntity> = withContext(Dispatchers.IO) {
        pollDao?.getVotesForPoll(pollId) ?: emptyList()
    }

    suspend fun triggerSafetyCanary(
        triggerReason: Byte,
        latitude: Double = 0.0,
        longitude: Double = 0.0,
        customNote: String? = null
    ): Int = withContext(Dispatchers.IO) {
        val sm = settingsManager
        val configuredIds = sm?.deadManTrustedContactIds?.value ?: emptySet()
        val trustedIds = if (configuredIds.isNotEmpty()) {
            configuredIds
        } else if (triggerReason == BinaryFrameCodec.CANARY_REASON_DURESS_PIN || triggerReason == BinaryFrameCodec.CANARY_REASON_MANUAL_SOS) {
            contactDao.getAllContactsFlow().first().map { it.id }.toSet()
        } else {
            emptySet()
        }
        if (trustedIds.isEmpty()) return@withContext 0

        val note = customNote ?: sm?.deadManEmergencyNote?.value ?: "Safety canary emergency alarm"
        var queuedCount = 0

        for (contactId in trustedIds) {
            getContactMutex(contactId).withLock {
                val contact = contactDao.getContactById(contactId) ?: return@withLock
                val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)
                val canaryUuid = UUID.randomUUID()
                val canaryIdBytes = uuidStringToBytes(canaryUuid.toString())
                val now = System.currentTimeMillis()

                val plaintext = BinaryFrameCodec.encodeSafetyCanary(
                    seqNum = contact.counterOut and 0xFFFF,
                    ackNum = contact.counterIn and 0xFFFF,
                    timestampUTC = now,
                    triggerReason = triggerReason,
                    canaryId = canaryIdBytes,
                    triggerTimestamp = now,
                    latitude = latitude,
                    longitude = longitude,
                    note = note
                )

                val ciphertext = BinaryFrameCodec.packAeadFrame(
                    key = slot.msgKey,
                    plaintext = plaintext,
                    target = slot.target,
                    direction = "A_TO_B"
                )

                val frame = org.pqchat.dht.traffic.OutboundPoissonFrame(
                    target = slot.target,
                    payload = ciphertext,
                    seq = org.pqchat.dht.dht.leaf.DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = false,
                    seqNum = contact.counterOut,
                    contactId = contactId,
                    timestamp = now,
                    packetClass = org.pqchat.dht.traffic.PacketClass.URGENT_CONTROL
                )

                contactDao.updateOutgoingState(
                    id = contact.id,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )

                canaryQueue.add(frame)
                queuedCount++
            }
        }
        queuedCount
    }

    suspend fun checkAndTriggerDeadManSwitch(): Boolean = withContext(Dispatchers.IO) {
        val sm = settingsManager ?: return@withContext false
        if (sm.isDeadManSwitchExpired()) {
            sm.setCanaryTriggered(true)
            val queued = triggerSafetyCanary(BinaryFrameCodec.CANARY_REASON_DEAD_MAN_TIMEOUT)
            queued > 0
        } else {
            false
        }
    }

    private fun uuidStringToBytes(uuidStr: String): ByteArray {
        return try {
            val u = java.util.UUID.fromString(uuidStr)
            val bb = java.nio.ByteBuffer.allocate(16)
            bb.putLong(u.mostSignificantBits)
            bb.putLong(u.leastSignificantBits)
            bb.array()
        } catch (_: Exception) {
            val hash = CryptoUtils.sha256(uuidStr.toByteArray(Charsets.UTF_8))
            hash.copyOf(16)
        }
    }

    private fun bytesToUuidString(bytes: ByteArray): String {
        return try {
            val bb = java.nio.ByteBuffer.wrap(bytes)
            java.util.UUID(bb.long, bb.long).toString()
        } catch (_: Exception) {
            CryptoUtils.toHex(bytes)
        }
    }

    fun getAllContactsFlow(): Flow<List<ContactEntity>> =
        contactDao.getAllContactsFlow().catch { emit(emptyList()) }

    fun getMessagesFlow(contactId: String): Flow<List<MessageEntity>> =
        messageDao.getMessagesForContactFlow(contactId).catch { emit(emptyList()) }

    suspend fun addContact(contact: ContactEntity) = withContext(Dispatchers.IO) {
        contactDao.insertOrUpdate(contact)
    }

    /**
     * Publishes parallel dummy decoy PUT slots to the DHT.
     * Generates a 900-byte CSPRNG packet signed by an ephemeral Ed25519 key,
     * blurs sender emission and registers the target in DecoyTargetPool.
     */
    internal suspend fun publishDecoyPutSlots(count: Int) {
        if (count <= 0) return
        for (i in 0 until count) {
            val dummySeed = CryptoUtils.secureRandomBytes(32)
            val dummyKeyPair = org.pqchat.dht.crypto.Ed25519Engine.generateKeyPairFromSeed(dummySeed)
            val decoyTarget = org.pqchat.dht.crypto.Ed25519Engine.computeTarget(dummyKeyPair.publicKey)
            val dummyPayload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES)

            val ok = dhtLeafNode.putMutable(
                target = decoyTarget,
                v = dummyPayload,
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                salt = null,
                sk = dummySeed,
                skipLocalStore = false
            )
            if (ok) {
                decoyTargetPool.registerPopulatedTarget(decoyTarget)
            }
        }
    }

    /**
     * Computes the number of decoy GET queries to issue for this polling cycle,
     * given the configured decoyGetRatio (e.g. 1.5 means 50% chance of 1, 50% chance of 2).
     */
    internal fun computeDecoyGetCount(ratio: Double): Int {
        if (ratio <= 0.0) return 0
        val base = ratio.toInt()
        val remainder = ratio - base
        val extra = if (CryptoUtils.secureRandom.nextDouble() < remainder) 1 else 0
        return base + extra
    }

    /**
     * Collects real, past, and expiring targets associated with existing contacts.
     * Used to ensure decoy GETs query populated targets rather than unpopulated hashes.
     */
    internal suspend fun collectExpiringAndPastTargets(contactId: String?): List<ByteArray> {
        val targets = mutableListOf<ByteArray>()
        val contacts = if (contactId != null) {
            val c = contactDao.getContactById(contactId)
            if (c != null) listOf(c) else emptyList()
        } else {
            contactDao.getAllContactsFlow().firstOrNull() ?: emptyList()
        }

        for (c in contacts) {
            if (c.counterIn > 0) {
                val pastSlot1 = RatchetChain.deriveSlot(c.chainKeyIn, c.counterIn - 1)
                targets.add(pastSlot1.target)
            }
            if (c.counterIn > 1) {
                val pastSlot2 = RatchetChain.deriveSlot(c.chainKeyIn, c.counterIn - 2)
                targets.add(pastSlot2.target)
            }
            val lookahead = RatchetChain.computeLookaheadSlots(c.chainKeyIn, c.counterIn, windowSize = 2)
            for (s in lookahead) {
                targets.add(s.target)
            }
        }
        return targets
    }

    /**
     * Executes decoy GET queries directed to real / expiring populated targets.
     * In accordance with docs/threat_model.md Section 3.2, queries target populated slots
     * (from Poisson cover traffic, decoy PUT slots, or past contact slots) to survive 0-PUT filtering.
     */
    suspend fun executeDecoyGets(contactId: String? = null): Int = withContext(Dispatchers.IO) {
        if (!enableDecoyGets) return@withContext 0
        val count = computeDecoyGetCount(decoyGetRatio)
        if (count <= 0) return@withContext 0

        val targets = decoyTargetPool.getDecoyTargets(count) {
            runBlocking { collectExpiringAndPastTargets(contactId) }
        }

        var queried = 0
        for (target in targets) {
            try {
                val item = dhtLeafNode.getMutable(target, skipLocalStore = true)
                if (item != null) {
                    harvestUndecryptableItem(target, item)
                }
                queried++
            } catch (_: Exception) {}
        }
        queried
    }

    /**
     * Caches third-party authentic BEP 44 mutable records into BlindRepublishPool
     * when they cannot be decrypted by this node (e.g. from decoy queries or unmatched slots).
     */
    fun harvestUndecryptableItem(target: ByteArray, item: DhtLeafNode.MutableItem) {
        blindRepublishPool.verifyAndAdd(
            target = target,
            publicKey = item.k,
            seq = item.seq,
            v = item.v,
            sig = item.sig,
            salt = item.salt
        )
    }

    companion object {
        const val N_POLL_TARGETS = 8
        const val DEFAULT_POLL_BATCH_SIZE = N_POLL_TARGETS
        const val SELF_CONTACT_ID = "self_notes_loopback"
        const val MAX_SKIPPED_KEYS_PER_CONTACT = 100

        fun getBackoffDelayMs(retryCount: Int): Long {
            val baseDelay = 1000L
            val maxDelay = 60000L
            val exponential = baseDelay * (1L shl minOf(retryCount, 5))
            return minOf(exponential, maxDelay)
        }
    }

    suspend fun ensureSelfNotesContactExists() = withContext(Dispatchers.IO) {
        val existing = try {
            contactDao.getContactById(SELF_CONTACT_ID)
        } catch (_: Throwable) {
            null
        }
        if (existing == null || existing.chainKeyOut.size != 64 || (existing.counterIn == 0 && existing.counterOut > 0)) {
            val symmetricSeed = CryptoUtils.secureRandomBytes(64)
            try {
                messageDao.deleteMessagesForContact(SELF_CONTACT_ID)
            } catch (_: Throwable) {}
            contactDao.insertOrUpdate(
                ContactEntity(
                    id = SELF_CONTACT_ID,
                    name = "🔒 Moje Notatki (Test DHT)",
                    chainKeyOut = symmetricSeed,
                    counterOut = 0,
                    chainKeyIn = symmetricSeed,
                    counterIn = 0,
                    rekeyEpoch = 0
                )
            )
        } else {
            messageDao.normalizeConfirmedSelfNotes(SELF_CONTACT_ID)
        }
    }

    suspend fun getContact(contactId: String): ContactEntity? = withContext(Dispatchers.IO) {
        contactDao.getContactById(contactId)
    }

    suspend fun setContactVerified(contactId: String, isVerified: Boolean) = withContext(Dispatchers.IO) {
        contactDao.updateVerifiedStatus(contactId, isVerified)
    }

    suspend fun updateContactName(contactId: String, newName: String) = withContext(Dispatchers.IO) {
        contactDao.updateContactName(contactId, newName)
    }

    /**
     * Sends a text message to contact via DHT with key hopping and 900-byte frame.
     * Protected by per-contact Mutex and backed by Room outbox queue.
     */
    suspend fun sendTextMessage(
        contactId: String,
        text: String,
        ephemeralTtlSeconds: Long = 0L
    ): Boolean = withContext(Dispatchers.IO) {
        getContactMutex(contactId).withLock {
            val contact = contactDao.getContactById(contactId) ?: return@withLock false
            val expiresAt = if (ephemeralTtlSeconds > 0L) System.currentTimeMillis() + ephemeralTtlSeconds * 1000L else null

            // 1. Drain existing outbox if any messages are queued
            val queued = messageDao.getQueuedMessagesForContact(contactId)
            if (queued.isNotEmpty()) {
                drainOutboxInternal(contactId, force = false)
                val remaining = messageDao.getQueuedMessagesForContact(contactId)
                if (remaining.isNotEmpty()) {
                    val fullSeq = contact.counterOut + remaining.size
                    messageDao.insertMessage(
                        MessageEntity(
                            contactId = contactId,
                            isOutgoing = true,
                            seqEpoch = fullSeq / 65536,
                            seqNum = fullSeq,
                            ackNum = contact.counterIn,
                            timestamp = System.currentTimeMillis(),
                            textContent = text,
                            status = "QUEUED",
                            ephemeralTtlSeconds = ephemeralTtlSeconds,
                            expiresAtTimestamp = expiresAt
                        )
                    )
                    return@withLock false
                }
            }

            // 2. Check if a PQC rekey offer is currently pending awaiting response
            if (pendingRekeyOfferDao?.getPendingOffer(contactId) != null) {
                messageDao.insertMessage(
                    MessageEntity(
                        contactId = contactId,
                        isOutgoing = true,
                        seqEpoch = contact.counterOut / 65536,
                        seqNum = contact.counterOut,
                        ackNum = contact.counterIn,
                        timestamp = System.currentTimeMillis(),
                        textContent = text,
                        status = "QUEUED",
                        ephemeralTtlSeconds = ephemeralTtlSeconds,
                        expiresAtTimestamp = expiresAt
                    )
                )
                return@withLock false
            }

            // 3. Check if PQC rekey offer is due (every 50 messages)
            if (RekeyCoordinator.shouldOfferRekey(contact.counterOut)) {
                sendRekeyOfferInternal(contact)
                val updatedContact = contactDao.getContactById(contactId) ?: contact
                messageDao.insertMessage(
                    MessageEntity(
                        contactId = contactId,
                        isOutgoing = true,
                        seqEpoch = updatedContact.counterOut / 65536,
                        seqNum = updatedContact.counterOut,
                        ackNum = updatedContact.counterIn,
                        timestamp = System.currentTimeMillis(),
                        textContent = text,
                        status = "QUEUED",
                        ephemeralTtlSeconds = ephemeralTtlSeconds,
                        expiresAtTimestamp = expiresAt
                    )
                )
                return@withLock false
            }

            // 4. Derive slot parameters for current counter
            val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)

            // 5. Encode Type 0x02 message (wire seqNum is 16-bit)
            val plaintext = BinaryFrameCodec.encodeTextMessage(
                seqNum = contact.counterOut and 0xFFFF,
                ackNum = contact.counterIn and 0xFFFF,
                timestampUTC = System.currentTimeMillis(),
                text = text,
                ephemeralTtlSeconds = ephemeralTtlSeconds
            )
            val frame = BinaryFrameCodec.packAeadFrame(
                key = slot.msgKey,
                plaintext = plaintext,
                target = slot.target,
                direction = contact.outboundDirection
            )

            org.pqchat.dht.debug.MessageDebugLogger.logOutgoingTextMessage(
                contactId = contactId,
                textLength = text.toByteArray(Charsets.UTF_8).size,
                slot = slot,
                seqNum = contact.counterOut,
                ackNum = contact.counterIn,
                frame = frame
            )

            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot.msgKey, "${contact.counterOut}")

            val isSelf = contactId == SELF_CONTACT_ID

            if (isStrictPoissonShaping()) {
                val msgId = messageDao.insertMessage(
                    MessageEntity(
                        contactId = contactId,
                        isOutgoing = true,
                        seqEpoch = contact.counterOut / 65536,
                        seqNum = contact.counterOut,
                        ackNum = contact.counterIn,
                        timestamp = System.currentTimeMillis(),
                        textContent = text,
                        status = "QUEUED_POISSON",
                        ackTarget = targetAck,
                        ackRatchetKey = slot.msgKey,
                        slotTarget = slot.target,
                        slotEdSeed = slot.edPrivateKeySeed,
                        ephemeralTtlSeconds = ephemeralTtlSeconds,
                        expiresAtTimestamp = expiresAt
                    )
                )

                // Piggybacking ACK: Clear pending cover ACK queue for this contact
                pendingAckQueue.removeForContact(contactId, contact.counterIn)

                // Advance outgoing chain state immediately so subsequent messages get next sequence slot
                contactDao.updateOutgoingState(
                    id = contactId,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )

                outboundPoissonQueue.enqueue(
                    org.pqchat.dht.traffic.OutboundPoissonFrame(
                        target = slot.target,
                        payload = frame,
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = slot.edPrivateKeySeed,
                        skipLocalStore = isSelf,
                        seqNum = contact.counterOut,
                        messageId = msgId,
                        contactId = contactId,
                        onSent = { success ->
                            if (success) {
                                decoyTargetPool.registerPopulatedTarget(slot.target)
                                val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                                messageDao.updateStatus(msgId, newStatus)
                                if (!isSelf) {
                                    org.pqchat.dht.service.DhtWorker.registerRepublishTask(
                                        org.pqchat.dht.traffic.PollingWorker.RepublishTask(
                                            messageId = msgId,
                                            contactId = contactId,
                                            target = slot.target,
                                            payload = frame,
                                            edPrivateKeySeed = slot.edPrivateKeySeed,
                                            initialSentTimestamp = System.currentTimeMillis()
                                        )
                                    )
                                    onRepublishTaskUpdated?.invoke()
                                }
                            } else {
                                messageDao.updateStatus(msgId, "EXPIRED_DHT")
                            }
                        }
                    )
                )
                return@withLock true
            }

            // 6. Store message in database with seqEpoch and ACK metadata
            val msgId = messageDao.insertMessage(
                MessageEntity(
                    contactId = contactId,
                    isOutgoing = true,
                    seqEpoch = contact.counterOut / 65536,
                    seqNum = contact.counterOut,
                    ackNum = contact.counterIn,
                    timestamp = System.currentTimeMillis(),
                    textContent = text,
                    status = "SENDING",
                    ackTarget = targetAck,
                    ackRatchetKey = slot.msgKey,
                    slotTarget = slot.target,
                    slotEdSeed = slot.edPrivateKeySeed,
                    ephemeralTtlSeconds = ephemeralTtlSeconds,
                    expiresAtTimestamp = expiresAt
                )
            )

            // Piggybacking ACK: Clear pending cover ACK queue for this contact
            pendingAckQueue.removeForContact(contactId, contact.counterIn)

            // Delayed PUT: randomized hold delay (docs/threat_model.md Section 4 & 5.1)
            if (delayedPutMaxMs > 0L && !isSelf) {
                val delayMs = (CryptoUtils.secureRandom.nextDouble() * delayedPutMaxMs).toLong().coerceAtLeast(0L)
                if (delayMs > 0L) {
                    delay(delayMs)
                }
            }

            // Decoy PUT Slots: publish parallel decoy record(s) to blur sender emission
            if (decoyPutSlotsCount > 0 && !isSelf) {
                publishDecoyPutSlots(decoyPutSlotsCount)
            }

            // 7. Put to DHT under Target_i
            val tStart = System.currentTimeMillis()
            val success = dhtLeafNode.putMutable(
                target = slot.target,
                v = frame,
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                salt = null,
                sk = slot.edPrivateKeySeed,
                skipLocalStore = isSelf
            )
            val rttMs = System.currentTimeMillis() - tStart
            researchTelemetry?.recordPacketEvent(
                role = org.pqchat.dht.research.PacketRole.FIRST_SEND,
                target = slot.target,
                seqNum = contact.counterOut.toLong(),
                payloadBytes = frame.size,
                rttMs = rttMs,
                nodesQueried = dhtLeafNode.lastNodesQueried,
                nodesResponded = dhtLeafNode.lastNodesResponded,
                lookupHops = dhtLeafNode.lastLookupHops,
                success = success,
                republishAttempt = 0
            )

            if (success) {
                decoyTargetPool.registerPopulatedTarget(slot.target)
                val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                messageDao.updateStatus(msgId, newStatus)
                if (!isSelf) {
                    org.pqchat.dht.service.DhtWorker.registerRepublishTask(
                        org.pqchat.dht.traffic.PollingWorker.RepublishTask(
                            messageId = msgId,
                            contactId = contactId,
                            target = slot.target,
                            payload = frame,
                            edPrivateKeySeed = slot.edPrivateKeySeed,
                            initialSentTimestamp = System.currentTimeMillis()
                        )
                    )
                    onRepublishTaskUpdated?.invoke()
                }
                // Advance outgoing chain state ONLY on success
                contactDao.updateOutgoingState(
                    id = contactId,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )

                if (isSelf) {
                    delay(2000L)
                    pollContactIncomingInternal(contactId)
                    val c = contactDao.getContactById(contactId)
                    if (c != null && c.counterIn <= contact.counterIn) {
                        delay(3000L)
                        pollContactIncomingInternal(contactId)
                    }
                }
                true
            } else {
                messageDao.updateMessageRetry(msgId, "QUEUED", retryCount = 1, timestamp = System.currentTimeMillis())
                false
            }
        }
    }

    suspend fun sendReaction(
        contactId: String,
        targetMessage: MessageEntity,
        emoji: String
    ): Boolean = sendReaction(contactId, targetMessage.seqEpoch, targetMessage.seqNum, emoji)

    suspend fun sendReaction(
        contactId: String,
        targetSeqEpoch: Int,
        targetSeqNum: Int,
        emoji: String
    ): Boolean = withContext(Dispatchers.IO) {
        getContactMutex(contactId).withLock {
            val isSelf = (contactId == SELF_CONTACT_ID)
            messageDao.updateMessageReactionAnyDirection(contactId, targetSeqEpoch, targetSeqNum, emoji)
            if (isSelf) {
                return@withLock true
            }

            val contact = contactDao.getContactById(contactId) ?: return@withLock false
            val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)

            val plaintext = BinaryFrameCodec.encodeReaction(
                seqNum = contact.counterOut and 0xFFFF,
                ackNum = contact.counterIn and 0xFFFF,
                timestampUTC = System.currentTimeMillis(),
                targetSeqEpoch = targetSeqEpoch,
                targetSeqNum = targetSeqNum,
                emoji = emoji
            )
            val frame = BinaryFrameCodec.packAeadFrame(
                key = slot.msgKey,
                plaintext = plaintext,
                target = slot.target,
                direction = contact.outboundDirection
            )

            contactDao.updateOutgoingState(
                id = contactId,
                counterOut = contact.counterOut + 1,
                chainKeyOut = slot.nextChainKey
            )

            if (isStrictPoissonShaping()) {
                outboundPoissonQueue.enqueue(
                    org.pqchat.dht.traffic.OutboundPoissonFrame(
                        target = slot.target,
                        payload = frame,
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = slot.edPrivateKeySeed,
                        skipLocalStore = false,
                        seqNum = contact.counterOut,
                        messageId = -1L,
                        contactId = contactId,
                        onSent = { success ->
                            if (success) {
                                decoyTargetPool.registerPopulatedTarget(slot.target)
                            }
                        }
                    )
                )
                true
            } else {
                val success = dhtLeafNode.putMutable(
                    target = slot.target,
                    v = frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = false
                )
                if (success) {
                    decoyTargetPool.registerPopulatedTarget(slot.target)
                }
                success
            }
        }
    }

    suspend fun sendLocationPin(
        contactId: String,
        latitude: Double,
        longitude: Double,
        altitude: Double = 0.0,
        accuracy: Float = 0.0f,
        note: String = "",
        ephemeralTtlSeconds: Long = 0L
    ): Boolean = withContext(Dispatchers.IO) {
        val locText = org.pqchat.dht.protocol.LocationPinData(
            latitude = latitude,
            longitude = longitude,
            altitude = altitude,
            accuracy = accuracy,
            note = note
        ).toPayloadText()

        getContactMutex(contactId).withLock {
            val isSelf = contactId == SELF_CONTACT_ID
            val expiresAt = if (ephemeralTtlSeconds > 0L) System.currentTimeMillis() + ephemeralTtlSeconds * 1000L else null

            if (isSelf) {
                val currentContact = contactDao.getContactById(contactId)
                val seqNum = currentContact?.counterOut ?: 0
                val seqEpoch = seqNum / 65536
                messageDao.insertMessage(
                    MessageEntity(
                        contactId = contactId,
                        isOutgoing = true,
                        seqEpoch = seqEpoch,
                        seqNum = seqNum,
                        ackNum = 0,
                        timestamp = System.currentTimeMillis(),
                        textContent = locText,
                        status = "SENT_DHT",
                        ackTarget = null,
                        ackRatchetKey = null,
                        slotTarget = null,
                        slotEdSeed = null,
                        ephemeralTtlSeconds = ephemeralTtlSeconds,
                        expiresAtTimestamp = expiresAt
                    )
                )
                if (currentContact != null) {
                    contactDao.updateOutgoingState(
                        id = contactId,
                        counterOut = seqNum + 1,
                        chainKeyOut = currentContact.chainKeyOut
                    )
                }
                return@withLock true
            }

            val contact = contactDao.getContactById(contactId) ?: return@withLock false
            val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)

            val plaintext = BinaryFrameCodec.encodeLocationPin(
                seqNum = contact.counterOut and 0xFFFF,
                ackNum = contact.counterIn and 0xFFFF,
                timestampUTC = System.currentTimeMillis(),
                latitude = latitude,
                longitude = longitude,
                altitude = altitude,
                accuracy = accuracy,
                note = note,
                ephemeralTtlSeconds = ephemeralTtlSeconds
            )
            val frame = BinaryFrameCodec.packAeadFrame(
                key = slot.msgKey,
                plaintext = plaintext,
                target = slot.target,
                direction = contact.outboundDirection
            )

            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot.msgKey, "${contact.counterOut}")

            val msgId = messageDao.insertMessage(
                MessageEntity(
                    contactId = contactId,
                    isOutgoing = true,
                    seqEpoch = contact.counterOut / 65536,
                    seqNum = contact.counterOut,
                    ackNum = contact.counterIn,
                    timestamp = System.currentTimeMillis(),
                    textContent = locText,
                    status = if (isStrictPoissonShaping()) "QUEUED_POISSON" else "SENDING",
                    ackTarget = targetAck,
                    ackRatchetKey = slot.msgKey,
                    slotTarget = slot.target,
                    slotEdSeed = slot.edPrivateKeySeed,
                    ephemeralTtlSeconds = ephemeralTtlSeconds,
                    expiresAtTimestamp = expiresAt
                )
            )

            contactDao.updateOutgoingState(
                id = contactId,
                counterOut = contact.counterOut + 1,
                chainKeyOut = slot.nextChainKey
            )

            if (isStrictPoissonShaping() && !isSelf) {
                outboundPoissonQueue.enqueue(
                    org.pqchat.dht.traffic.OutboundPoissonFrame(
                        target = slot.target,
                        payload = frame,
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = slot.edPrivateKeySeed,
                        skipLocalStore = isSelf,
                        seqNum = contact.counterOut,
                        messageId = msgId,
                        contactId = contactId,
                        onSent = { success ->
                            if (success) {
                                decoyTargetPool.registerPopulatedTarget(slot.target)
                                val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                                messageDao.updateStatus(msgId, newStatus)
                            } else {
                                messageDao.updateStatus(msgId, "EXPIRED_DHT")
                            }
                        }
                    )
                )
                true
            } else {
                val success = dhtLeafNode.putMutable(
                    target = slot.target,
                    v = frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = isSelf
                )
                if (success) {
                    messageDao.updateStatus(msgId, if (isSelf) "SENT_DHT" else "PENDING_DELIVERY")
                } else {
                    messageDao.updateStatus(msgId, "EXPIRED_DHT")
                }
                success
            }
        }
    }

    /**
     * Sends an ultra-low-bitrate micro-voice note over DHT fitting in 1 to 3 BEP 44 frames (900 B).
     */
    suspend fun sendVoiceNote(
        contactId: String,
        pcm16Samples: ShortArray,
        ephemeralTtlSeconds: Long = 0L
    ): Boolean = withContext(Dispatchers.IO) {
        val durationMs = (pcm16Samples.size * 1000L / org.pqchat.dht.media.voice.VoiceCodec.SAMPLE_RATE).toInt()
        val voiceBytes = org.pqchat.dht.media.voice.VoiceCodec.encode(pcm16Samples)
        sendVoiceNote(contactId, voiceBytes, durationMs, ephemeralTtlSeconds)
    }

    suspend fun sendVoiceNote(
        contactId: String,
        voiceBytes: ByteArray,
        durationMs: Int,
        ephemeralTtlSeconds: Long = 0L
    ): Boolean = withContext(Dispatchers.IO) {
        if (voiceBytes.isEmpty()) return@withContext false
        val totalSegments = ((voiceBytes.size + BinaryFrameCodec.T9_MAX_VOICE_SIZE - 1) / BinaryFrameCodec.T9_MAX_VOICE_SIZE).coerceIn(1, 3)
        val voiceClipId = CryptoUtils.secureRandom.nextLong()

        getContactMutex(contactId).withLock {
            val contact = contactDao.getContactById(contactId) ?: return@withLock false
            val expiresAt = if (ephemeralTtlSeconds > 0L) System.currentTimeMillis() + ephemeralTtlSeconds * 1000L else null
            val isSelf = contactId == SELF_CONTACT_ID

            val initialCounter = contact.counterOut
            val seqEpoch = initialCounter / 65536
            val slot0 = RatchetChain.deriveSlot(contact.chainKeyOut, initialCounter)
            val targetAck0 = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot0.msgKey, "$initialCounter")

            val msgId = messageDao.insertMessage(
                MessageEntity(
                    contactId = contactId,
                    isOutgoing = true,
                    seqEpoch = seqEpoch,
                    seqNum = initialCounter,
                    ackNum = contact.counterIn,
                    timestamp = System.currentTimeMillis(),
                    voiceBytes = voiceBytes,
                    voiceDurationMs = durationMs,
                    status = if (isStrictPoissonShaping()) "QUEUED_POISSON" else "SENDING",
                    ackTarget = targetAck0,
                    ackRatchetKey = slot0.msgKey,
                    slotTarget = slot0.target,
                    slotEdSeed = slot0.edPrivateKeySeed,
                    ephemeralTtlSeconds = ephemeralTtlSeconds,
                    expiresAtTimestamp = expiresAt
                )
            )

            var currentCounter = initialCounter
            var currentChainKey: ByteArray = contact.rawChainKeyOut
            var allSucceeded = true
            val segmentDurationMs = (durationMs / totalSegments).coerceAtLeast(1)

            for (segIdx in 0 until totalSegments) {
                val offset = segIdx * BinaryFrameCodec.T9_MAX_VOICE_SIZE
                val len = (voiceBytes.size - offset).coerceAtMost(BinaryFrameCodec.T9_MAX_VOICE_SIZE)
                val segBytes = voiceBytes.copyOfRange(offset, offset + len)
                val thisSegDuration = if (segIdx == totalSegments - 1) {
                    durationMs - segmentDurationMs * (totalSegments - 1)
                } else {
                    segmentDurationMs
                }

                val slot = RatchetChain.deriveSlot(currentChainKey, currentCounter)
                val plaintext = BinaryFrameCodec.encodeVoiceNote(
                    seqNum = currentCounter and 0xFFFF,
                    ackNum = contact.counterIn and 0xFFFF,
                    timestampUTC = System.currentTimeMillis(),
                    voiceClipId = voiceClipId,
                    segmentIndex = segIdx,
                    totalSegments = totalSegments,
                    durationMs = thisSegDuration,
                    codecMode = org.pqchat.dht.media.voice.VoiceCodec.CODEC_MODE_LPC10_COMPACT,
                    ephemeralTtlSeconds = ephemeralTtlSeconds,
                    voiceBytes = segBytes
                )
                val frame = BinaryFrameCodec.packAeadFrame(
                    key = slot.msgKey,
                    plaintext = plaintext,
                    target = slot.target,
                    direction = contact.outboundDirection
                )

                currentCounter++
                currentChainKey = slot.nextChainKey

                if (isStrictPoissonShaping() && !isSelf) {
                    outboundPoissonQueue.enqueue(
                        org.pqchat.dht.traffic.OutboundPoissonFrame(
                            target = slot.target,
                            payload = frame,
                            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                            salt = null,
                            sk = slot.edPrivateKeySeed,
                            skipLocalStore = isSelf,
                            seqNum = currentCounter - 1,
                            messageId = msgId,
                            contactId = contactId,
                            onSent = { success ->
                                if (success) {
                                    decoyTargetPool.registerPopulatedTarget(slot.target)
                                    val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                                    messageDao.updateStatus(msgId, newStatus)
                                } else {
                                    messageDao.updateStatus(msgId, "EXPIRED_DHT")
                                }
                            }
                        )
                    )
                } else {
                    val ok = dhtLeafNode.putMutable(
                        target = slot.target,
                        v = frame,
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = slot.edPrivateKeySeed,
                        skipLocalStore = isSelf
                    )
                    if (!ok) allSucceeded = false
                }
            }

            contactDao.updateOutgoingState(
                id = contactId,
                counterOut = currentCounter,
                chainKeyOut = currentChainKey
            )

            if (!isStrictPoissonShaping() || isSelf) {
                if (allSucceeded) {
                    messageDao.updateStatus(msgId, if (isSelf) "SENT_DHT" else "PENDING_DELIVERY")
                } else {
                    messageDao.updateStatus(msgId, "EXPIRED_DHT")
                }
            }

            allSucceeded
        }
    }

    /**
     * Sends an image payload over DHT with chunking.
     * Protected by per-contact Mutex and Room outbox queue.
     */
    suspend fun sendImagePayload(contactId: String, rawBytes: ByteArray): Boolean = withContext(Dispatchers.IO) {
        getContactMutex(contactId).withLock {
            val contact = contactDao.getContactById(contactId) ?: return@withLock false

            // 1. Drain existing outbox first
            val queued = messageDao.getQueuedMessagesForContact(contactId)
            if (queued.isNotEmpty()) {
                drainOutboxInternal(contactId, force = false)
                val remaining = messageDao.getQueuedMessagesForContact(contactId)
                if (remaining.isNotEmpty()) {
                    val fullSeq = contact.counterOut + remaining.size
                    messageDao.insertMessage(
                        MessageEntity(
                            contactId = contactId,
                            isOutgoing = true,
                            seqEpoch = fullSeq / 65536,
                            seqNum = fullSeq,
                            ackNum = contact.counterIn,
                            timestamp = System.currentTimeMillis(),
                            textContent = "[Image: ${rawBytes.size / 1024} KB]",
                            imageBytes = rawBytes,
                            status = "QUEUED"
                        )
                    )
                    return@withLock false
                }
            }

            // 2. Check if a PQC rekey offer is currently pending
            if (pendingRekeyOfferDao?.getPendingOffer(contactId) != null) {
                messageDao.insertMessage(
                    MessageEntity(
                        contactId = contactId,
                        isOutgoing = true,
                        seqEpoch = contact.counterOut / 65536,
                        seqNum = contact.counterOut,
                        ackNum = contact.counterIn,
                        timestamp = System.currentTimeMillis(),
                        textContent = "[Image: ${rawBytes.size / 1024} KB]",
                        imageBytes = rawBytes,
                        status = "QUEUED"
                    )
                )
                return@withLock false
            }

            // 3. Check if PQC rekey offer is due
            if (RekeyCoordinator.shouldOfferRekey(contact.counterOut)) {
                sendRekeyOfferInternal(contact)
                val updatedContact = contactDao.getContactById(contactId) ?: contact
                messageDao.insertMessage(
                    MessageEntity(
                        contactId = contactId,
                        isOutgoing = true,
                        seqEpoch = updatedContact.counterOut / 65536,
                        seqNum = updatedContact.counterOut,
                        ackNum = updatedContact.counterIn,
                        timestamp = System.currentTimeMillis(),
                        textContent = "[Image: ${rawBytes.size / 1024} KB]",
                        imageBytes = rawBytes,
                        status = "QUEUED"
                    )
                )
                return@withLock false
            }

            val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)
            val chunks = ChunkingEngine.splitData(
                data = rawBytes,
                currentEdSeed = slot.edPrivateKeySeed,
                currentMsgKey = slot.msgKey,
                seqNum = contact.counterOut and 0xFFFF,
                ackNum = contact.counterIn and 0xFFFF,
                direction = contact.outboundDirection
            )

            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot.msgKey, "${contact.counterOut}")

            val isSelf = contactId == SELF_CONTACT_ID

            if (isStrictPoissonShaping()) {
                val msgId = messageDao.insertMessage(
                    MessageEntity(
                        contactId = contactId,
                        isOutgoing = true,
                        seqEpoch = contact.counterOut / 65536,
                        seqNum = contact.counterOut,
                        ackNum = contact.counterIn,
                        timestamp = System.currentTimeMillis(),
                        textContent = "[Image: ${rawBytes.size / 1024} KB (${chunks.size} chunks)]",
                        imageBytes = rawBytes,
                        status = "QUEUED_POISSON",
                        ackTarget = targetAck,
                        ackRatchetKey = slot.msgKey,
                        slotTarget = slot.target,
                        slotEdSeed = slot.edPrivateKeySeed
                    )
                )

                // Piggybacking ACK: Clear pending cover ACK queue for this contact
                pendingAckQueue.removeForContact(contactId, contact.counterIn)

                // Advance outgoing chain state immediately
                contactDao.updateOutgoingState(
                    id = contactId,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )

                val chunksRemaining = java.util.concurrent.atomic.AtomicInteger(chunks.size)
                val anyFailed = java.util.concurrent.atomic.AtomicBoolean(false)
                for (c in chunks) {
                    outboundPoissonQueue.enqueue(
                        org.pqchat.dht.traffic.OutboundPoissonFrame(
                            target = c.target,
                            payload = c.frame,
                            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                            salt = null,
                            sk = c.edPrivateKeySeed,
                            skipLocalStore = isSelf,
                            seqNum = contact.counterOut,
                            messageId = msgId,
                            contactId = contactId,
                            onSent = { success ->
                                decoyTargetPool.registerPopulatedTarget(c.target)
                                if (!success) {
                                    anyFailed.set(true)
                                }
                                if (chunksRemaining.decrementAndGet() == 0) {
                                    if (!anyFailed.get()) {
                                        val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                                        messageDao.updateStatus(msgId, newStatus)
                                        if (!isSelf && chunks.isNotEmpty()) {
                                            val firstChunk = chunks[0]
                                            org.pqchat.dht.service.DhtWorker.registerRepublishTask(
                                                org.pqchat.dht.traffic.PollingWorker.RepublishTask(
                                                    messageId = msgId,
                                                    contactId = contactId,
                                                    target = firstChunk.target,
                                                    payload = firstChunk.frame,
                                                    edPrivateKeySeed = firstChunk.edPrivateKeySeed,
                                                    initialSentTimestamp = System.currentTimeMillis()
                                                )
                                            )
                                            onRepublishTaskUpdated?.invoke()
                                        }
                                    } else {
                                        messageDao.updateStatus(msgId, "EXPIRED_DHT")
                                    }
                                }
                            }
                        )
                    )
                }
                return@withLock true
            }

            val msgId = messageDao.insertMessage(
                MessageEntity(
                    contactId = contactId,
                    isOutgoing = true,
                    seqEpoch = contact.counterOut / 65536,
                    seqNum = contact.counterOut,
                    ackNum = contact.counterIn,
                    timestamp = System.currentTimeMillis(),
                    textContent = "[Image: ${rawBytes.size / 1024} KB (${chunks.size} chunks)]",
                    imageBytes = rawBytes,
                    status = "SENDING",
                    ackTarget = targetAck,
                    ackRatchetKey = slot.msgKey,
                    slotTarget = slot.target,
                    slotEdSeed = slot.edPrivateKeySeed
                )
            )

            // Piggybacking ACK: Clear pending cover ACK queue for this contact
            pendingAckQueue.removeForContact(contactId, contact.counterIn)

            // Delayed PUT: randomized hold delay (docs/threat_model.md Section 4 & 5.1)
            if (delayedPutMaxMs > 0L && !isSelf) {
                val delayMs = (CryptoUtils.secureRandom.nextDouble() * delayedPutMaxMs).toLong().coerceAtLeast(0L)
                if (delayMs > 0L) {
                    delay(delayMs)
                }
            }

            // Decoy PUT Slots: publish parallel decoy record(s) to blur sender emission
            if (decoyPutSlotsCount > 0 && !isSelf) {
                publishDecoyPutSlots(decoyPutSlotsCount)
            }

            var allSuccess = true
            for (c in chunks) {
                org.pqchat.dht.debug.MessageDebugLogger.logOutgoingChunkData(
                    contactId = contactId,
                    transferId = c.transferId,
                    chunkIndex = c.chunkIndex,
                    totalChunks = c.totalChunks,
                    dataSize = c.frame.size,
                    target = c.target,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    frame = c.frame
                )
                val ok = dhtLeafNode.putMutable(
                    target = c.target,
                    v = c.frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    sk = c.edPrivateKeySeed,
                    skipLocalStore = isSelf
                )
                if (!ok) {
                    allSuccess = false
                    break
                }
            }

            if (allSuccess) {
                for (c in chunks) {
                    decoyTargetPool.registerPopulatedTarget(c.target)
                }
                val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                messageDao.updateStatus(msgId, newStatus)
                if (!isSelf && chunks.isNotEmpty()) {
                    val firstChunk = chunks[0]
                    org.pqchat.dht.service.DhtWorker.registerRepublishTask(
                        org.pqchat.dht.traffic.PollingWorker.RepublishTask(
                            messageId = msgId,
                            contactId = contactId,
                            target = firstChunk.target,
                            payload = firstChunk.frame,
                            edPrivateKeySeed = firstChunk.edPrivateKeySeed,
                            initialSentTimestamp = System.currentTimeMillis()
                        )
                    )
                    onRepublishTaskUpdated?.invoke()
                }
                contactDao.updateOutgoingState(
                    id = contactId,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )
                if (isSelf) {
                    delay(1500L)
                    pollContactIncomingInternal(contactId)
                }
                true
            } else {
                messageDao.updateMessageRetry(msgId, "QUEUED", retryCount = 1, timestamp = System.currentTimeMillis())
                false
            }
        }
    }

    /**
     * Drains the Room outbox for a contact, retrying QUEUED messages with exponential backoff.
     */
    suspend fun drainOutbox(contactId: String, force: Boolean = false): Int = withContext(Dispatchers.IO) {
        getContactMutex(contactId).withLock {
            drainOutboxInternal(contactId, force)
        }
    }

    private suspend fun drainOutboxInternal(contactId: String, force: Boolean): Int {
        if (contactDao.getContactById(contactId) == null) return 0
        val queued = messageDao.getQueuedMessagesForContact(contactId)
        if (queued.isEmpty()) return 0

        var sentCount = 0
        val now = System.currentTimeMillis()

        for (msg in queued) {
            val backoff = getBackoffDelayMs(msg.retryCount)
            if (!force && (now - msg.lastAttemptTimestamp) < backoff) {
                break
            }

            val currentContact = contactDao.getContactById(contactId) ?: break

            if (pendingRekeyOfferDao?.getPendingOffer(contactId) != null) {
                break
            }

            if (RekeyCoordinator.shouldOfferRekey(currentContact.counterOut)) {
                sendRekeyOfferInternal(currentContact)
                break
            }

            val isSelf = contactId == SELF_CONTACT_ID

            if (msg.imageBytes != null) {
                val slot = RatchetChain.deriveSlot(currentContact.chainKeyOut, currentContact.counterOut)
                val chunks = ChunkingEngine.splitData(
                    data = msg.imageBytes.raw,
                    currentEdSeed = slot.edPrivateKeySeed,
                    currentMsgKey = slot.msgKey,
                    seqNum = currentContact.counterOut and 0xFFFF,
                    ackNum = currentContact.counterIn and 0xFFFF,
                    direction = currentContact.outboundDirection
                )
                if (isStrictPoissonShaping()) {
                    messageDao.updateMessageStatusAndSeq(msg.id, "QUEUED_POISSON", currentContact.counterOut)
                    pendingAckQueue.removeForContact(contactId, currentContact.counterIn)
                    contactDao.updateOutgoingState(
                        id = contactId,
                        counterOut = currentContact.counterOut + 1,
                        chainKeyOut = slot.nextChainKey
                    )
                    val chunksRemaining = java.util.concurrent.atomic.AtomicInteger(chunks.size)
                    val anyFailed = java.util.concurrent.atomic.AtomicBoolean(false)
                    for (c in chunks) {
                        outboundPoissonQueue.enqueue(
                            org.pqchat.dht.traffic.OutboundPoissonFrame(
                                target = c.target,
                                payload = c.frame,
                                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                                salt = null,
                                sk = c.edPrivateKeySeed,
                                skipLocalStore = isSelf,
                                seqNum = currentContact.counterOut,
                                messageId = msg.id,
                                contactId = contactId,
                                packetClass = org.pqchat.dht.traffic.PacketClass.IMAGE_CHUNK,
                                onSent = { success ->
                                    decoyTargetPool.registerPopulatedTarget(c.target)
                                    if (!success) {
                                        anyFailed.set(true)
                                    }
                                    if (chunksRemaining.decrementAndGet() == 0) {
                                        if (!anyFailed.get()) {
                                            val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                                            messageDao.updateStatus(msg.id, newStatus)
                                            if (!isSelf && chunks.isNotEmpty()) {
                                                val firstChunk = chunks[0]
                                                org.pqchat.dht.service.DhtWorker.registerRepublishTask(
                                                    org.pqchat.dht.traffic.PollingWorker.RepublishTask(
                                                        messageId = msg.id,
                                                        contactId = contactId,
                                                        target = firstChunk.target,
                                                        payload = firstChunk.frame,
                                                        edPrivateKeySeed = firstChunk.edPrivateKeySeed,
                                                        initialSentTimestamp = msg.timestamp
                                                    )
                                                )
                                                onRepublishTaskUpdated?.invoke()
                                            }
                                        } else {
                                            messageDao.updateMessageRetry(msg.id, "QUEUED", msg.retryCount + 1, System.currentTimeMillis())
                                        }
                                    }
                                }
                            )
                        )
                    }
                    sentCount++
                } else {
                    var allSuccess = true
                    for (c in chunks) {
                        val tStart = System.currentTimeMillis()
                        val ok = dhtLeafNode.putMutable(
                            target = c.target,
                            v = c.frame,
                            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                            sk = c.edPrivateKeySeed,
                            skipLocalStore = isSelf
                        )
                        val rttMs = System.currentTimeMillis() - tStart
                        researchTelemetry?.recordPacketEvent(
                            role = org.pqchat.dht.research.PacketRole.FIRST_SEND,
                            target = c.target,
                            seqNum = currentContact.counterOut.toLong(),
                            payloadBytes = c.frame.size,
                            rttMs = rttMs,
                            nodesQueried = dhtLeafNode.lastNodesQueried,
                            nodesResponded = dhtLeafNode.lastNodesResponded,
                            lookupHops = dhtLeafNode.lastLookupHops,
                            success = ok,
                            republishAttempt = 0
                        )
                        if (!ok) {
                            allSuccess = false
                            break
                        }
                    }
                    if (allSuccess) {
                        pendingAckQueue.removeForContact(contactId, currentContact.counterIn)
                        val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                        messageDao.updateMessageStatusAndSeq(msg.id, newStatus, currentContact.counterOut)
                        if (!isSelf && chunks.isNotEmpty()) {
                            val firstChunk = chunks[0]
                            org.pqchat.dht.service.DhtWorker.registerRepublishTask(
                                org.pqchat.dht.traffic.PollingWorker.RepublishTask(
                                    messageId = msg.id,
                                    contactId = contactId,
                                    target = firstChunk.target,
                                    payload = firstChunk.frame,
                                    edPrivateKeySeed = firstChunk.edPrivateKeySeed,
                                    initialSentTimestamp = msg.timestamp
                                )
                            )
                            onRepublishTaskUpdated?.invoke()
                        }
                        contactDao.updateOutgoingState(
                            id = contactId,
                            counterOut = currentContact.counterOut + 1,
                            chainKeyOut = slot.nextChainKey
                        )
                        sentCount++
                    } else {
                        messageDao.updateMessageRetry(msg.id, "QUEUED", msg.retryCount + 1, System.currentTimeMillis())
                        break
                    }
                }
            } else if (msg.textContent != null) {
                val slot = RatchetChain.deriveSlot(currentContact.chainKeyOut, currentContact.counterOut)
                val plaintext = BinaryFrameCodec.encodeTextMessage(
                    seqNum = currentContact.counterOut and 0xFFFF,
                    ackNum = currentContact.counterIn and 0xFFFF,
                    timestampUTC = System.currentTimeMillis(),
                    text = msg.textContent.raw,
                    ephemeralTtlSeconds = msg.rawEphemeralTtlSeconds
                )
                val frame = BinaryFrameCodec.packAeadFrame(
                    key = slot.msgKey,
                    plaintext = plaintext,
                    target = slot.target,
                    direction = currentContact.outboundDirection
                )
                if (isStrictPoissonShaping()) {
                    messageDao.updateMessageStatusAndSeq(msg.id, "QUEUED_POISSON", currentContact.counterOut)
                    pendingAckQueue.removeForContact(contactId, currentContact.counterIn)
                    contactDao.updateOutgoingState(
                        id = contactId,
                        counterOut = currentContact.counterOut + 1,
                        chainKeyOut = slot.nextChainKey
                    )
                    outboundPoissonQueue.enqueue(
                        org.pqchat.dht.traffic.OutboundPoissonFrame(
                            target = slot.target,
                            payload = frame,
                            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                            salt = null,
                            sk = slot.edPrivateKeySeed,
                            skipLocalStore = isSelf,
                            seqNum = currentContact.counterOut,
                            messageId = msg.id,
                            contactId = contactId,
                            packetClass = org.pqchat.dht.traffic.PacketClass.IMAGE_CHUNK,
                            onSent = { success ->
                                if (success) {
                                    decoyTargetPool.registerPopulatedTarget(slot.target)
                                    val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                                    messageDao.updateStatus(msg.id, newStatus)
                                    if (!isSelf) {
                                        org.pqchat.dht.service.DhtWorker.registerRepublishTask(
                                            org.pqchat.dht.traffic.PollingWorker.RepublishTask(
                                                messageId = msg.id,
                                                contactId = contactId,
                                                target = slot.target,
                                                payload = frame,
                                                edPrivateKeySeed = slot.edPrivateKeySeed,
                                                initialSentTimestamp = msg.timestamp
                                            )
                                        )
                                        onRepublishTaskUpdated?.invoke()
                                    }
                                } else {
                                    messageDao.updateMessageRetry(msg.id, "QUEUED", msg.retryCount + 1, System.currentTimeMillis())
                                }
                            }
                        )
                    )
                    sentCount++
                } else {
                    val ok = dhtLeafNode.putMutable(
                        target = slot.target,
                        v = frame,
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = slot.edPrivateKeySeed,
                        skipLocalStore = isSelf
                    )
                    if (ok) {
                        pendingAckQueue.removeForContact(contactId, currentContact.counterIn)
                        val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                        messageDao.updateMessageStatusAndSeq(msg.id, newStatus, currentContact.counterOut)
                        if (!isSelf) {
                            org.pqchat.dht.service.DhtWorker.registerRepublishTask(
                                org.pqchat.dht.traffic.PollingWorker.RepublishTask(
                                    messageId = msg.id,
                                    contactId = contactId,
                                    target = slot.target,
                                    payload = frame,
                                    edPrivateKeySeed = slot.edPrivateKeySeed,
                                    initialSentTimestamp = msg.timestamp
                                )
                            )
                            onRepublishTaskUpdated?.invoke()
                        }
                        contactDao.updateOutgoingState(
                            id = contactId,
                            counterOut = currentContact.counterOut + 1,
                            chainKeyOut = slot.nextChainKey
                        )
                        sentCount++
                    } else {
                        messageDao.updateMessageRetry(msg.id, "QUEUED", msg.retryCount + 1, System.currentTimeMillis())
                        break
                    }
                }
            }
        }
        return sentCount
    }

    private suspend fun sendRekeyOfferInternal(contact: ContactEntity): Boolean {
        _rekeyInProgressContacts.value = _rekeyInProgressContacts.value + contact.id
        val nextTarget = RatchetChain.getNextExpectedTarget(contact.chainKeyOut, contact.counterOut)
        val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)
        val newEpoch = contact.rekeyEpoch + 1
        val (pendingOffer, offerFrame) = RekeyCoordinator.createRekeyOffer(
            epoch = newEpoch,
            seqNum = contact.counterOut and 0xFFFF,
            ackNum = contact.counterIn and 0xFFFF,
            msgKey = slot.msgKey,
            target = nextTarget,
            direction = contact.outboundDirection
        )

        pendingRekeyOfferDao?.insertOrUpdate(
            PendingRekeyOfferEntity(
                contactId = contact.id,
                epoch = newEpoch,
                skNew = pendingOffer.skNew,
                pkNew = pendingOffer.pkNew,
                offerSeqNum = contact.counterOut
            )
        )

        org.pqchat.dht.debug.MessageDebugLogger.logOutgoingRekeyOffer(
            contactId = contact.id,
            epoch = newEpoch,
            slot = slot,
            seqNum = contact.counterOut,
            ackNum = contact.counterIn,
            mlKemPublicKeySize = pendingOffer.pkNew.size,
            frame = offerFrame
        )

        val isSelf = contact.id == SELF_CONTACT_ID
        if (isStrictPoissonShaping()) {
            contactDao.updateOutgoingState(
                id = contact.id,
                counterOut = contact.counterOut + 1,
                chainKeyOut = slot.nextChainKey
            )
            outboundPoissonQueue.enqueue(
                org.pqchat.dht.traffic.OutboundPoissonFrame(
                    target = nextTarget,
                    payload = offerFrame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = isSelf,
                    seqNum = contact.counterOut,
                    contactId = contact.id,
                    packetClass = org.pqchat.dht.traffic.PacketClass.URGENT_CONTROL,
                    onSent = { success ->
                        if (success) {
                            decoyTargetPool.registerPopulatedTarget(nextTarget)
                        } else {
                            pendingRekeyOfferDao?.deletePendingOffer(contact.id)
                            _rekeyInProgressContacts.value = _rekeyInProgressContacts.value - contact.id
                        }
                    }
                )
            )
            return true
        }

        val success = dhtLeafNode.putMutable(
            target = nextTarget,
            v = offerFrame,
            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
            salt = null,
            sk = slot.edPrivateKeySeed,
            skipLocalStore = isSelf
        )

        if (success) {
            contactDao.updateOutgoingState(
                id = contact.id,
                counterOut = contact.counterOut + 1,
                chainKeyOut = slot.nextChainKey
            )
        } else {
            pendingRekeyOfferDao?.deletePendingOffer(contact.id)
            _rekeyInProgressContacts.value = _rekeyInProgressContacts.value - contact.id
        }
        return success
    }

    /**
     * Polls DHT for incoming message for contact.
     * First checks any preserved skipped keys for previously missing slots,
     * then queries the current slot counterIn.
     */
    suspend fun pollContactIncoming(contactId: String): Boolean = withContext(Dispatchers.IO) {
        getContactMutex(contactId).withLock {
            pollContactIncomingInternal(contactId)
        }
    }

    internal suspend fun pollPendingSkippedKeys(contactId: String): Boolean {
        if (skippedKeyDao == null) return false
        skippedKeyDao.deleteExpiredKeys()
        val skipped = skippedKeyDao.getSkippedKeysForContact(contactId)
        if (skipped.isEmpty()) return false

        val isSelf = contactId == SELF_CONTACT_ID
        var anyProcessed = false

        for (sk in skipped) {
            val item = dhtLeafNode.getMutable(sk.target, skipLocalStore = isSelf) ?: continue
            try {
                val contact = contactDao.getContactById(contactId) ?: continue
                val frameMsg = BinaryFrameCodec.unpackAeadFrame(
                    key = sk.rawMsgKey,
                    frame = item.v,
                    target = sk.target,
                    direction = contact.inboundDirection
                )
                val bitmap = SlidingWindowBitmap(contact.receivedBitmapBase, 1024, contact.receivedBitmap)

                when (frameMsg.msgType) {
                    BinaryFrameCodec.TYPE_TEXT_MESSAGE -> {
                        val textPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.TextMessage
                        val seqEpoch = sk.slotIndex / 65536
                        if (!messageDao.existsMessageWithEpoch(contactId, seqEpoch, sk.slotIndex, false)) {
                            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(sk.rawMsgKey, "${sk.slotIndex}")
                            messageDao.insertMessage(
                                MessageEntity(
                                    contactId = contactId,
                                    isOutgoing = false,
                                    seqEpoch = seqEpoch,
                                    seqNum = sk.slotIndex,
                                    ackNum = frameMsg.ackNum,
                                    timestamp = frameMsg.timestampUTC,
                                    textContent = textPayload.text,
                                    status = "DELIVERED",
                                    ackTarget = targetAck,
                                    ackRatchetKey = sk.rawMsgKey,
                                    slotTarget = sk.target,
                                    slotEdSeed = sk.rawEdPrivateKeySeed,
                                    ephemeralTtlSeconds = textPayload.ephemeralTtlSeconds,
                                    expiresAtTimestamp = null
                                )
                            )
                            onIncomingMessageDelivered?.invoke(contactId, textPayload.text, false)
                        }
                        bitmap.markReceived(sk.slotIndex)
                        contactDao.updateIncomingStateWithBitmap(
                            id = contactId,
                            counterIn = contact.counterIn,
                            chainKeyIn = contact.chainKeyIn,
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                        sk.destroy()
                        skippedKeyDao.deleteSkippedKey(contactId, sk.slotIndex)
                        anyProcessed = true
                    }
                    BinaryFrameCodec.TYPE_CHUNK_DATA -> {
                        val chunkPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.ChunkData
                        val transferIdHex = CryptoUtils.toHex(chunkPayload.transferId)
                        chunkDao.insertChunk(
                            ChunkEntity(
                                transferId = transferIdHex,
                                chunkIndex = chunkPayload.chunkIndex,
                                totalChunks = chunkPayload.totalChunks,
                                data = chunkPayload.data
                            )
                        )
                        bitmap.markReceived(sk.slotIndex)
                        contactDao.updateIncomingStateWithBitmap(
                            id = contactId,
                            counterIn = contact.counterIn,
                            chainKeyIn = contact.chainKeyIn,
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                        sk.destroy()
                        skippedKeyDao.deleteSkippedKey(contactId, sk.slotIndex)
                        anyProcessed = true
                    }
                    BinaryFrameCodec.TYPE_REACTION -> {
                        val reactionPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.Reaction
                        messageDao.updateMessageReaction(contactId, reactionPayload.targetSeqEpoch, reactionPayload.targetSeqNum, true, reactionPayload.emoji)
                        messageDao.updateMessageReactionAnyDirection(contactId, reactionPayload.targetSeqEpoch, reactionPayload.targetSeqNum, reactionPayload.emoji)
                        bitmap.markReceived(sk.slotIndex)
                        contactDao.updateIncomingStateWithBitmap(
                            id = contactId,
                            counterIn = contact.counterIn,
                            chainKeyIn = contact.chainKeyIn,
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                        sk.destroy()
                        skippedKeyDao.deleteSkippedKey(contactId, sk.slotIndex)
                        anyProcessed = true
                    }
                    BinaryFrameCodec.TYPE_LOCATION_PIN -> {
                        val locPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.LocationPin
                        val seqEpoch = sk.slotIndex / 65536
                        if (!messageDao.existsMessageWithEpoch(contactId, seqEpoch, sk.slotIndex, false)) {
                            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(sk.rawMsgKey, "${sk.slotIndex}")
                            val locText = org.pqchat.dht.protocol.LocationPinData(
                                locPayload.latitude,
                                locPayload.longitude,
                                locPayload.altitude,
                                locPayload.accuracy,
                                locPayload.note
                            ).toPayloadText()
                            messageDao.insertMessage(
                                MessageEntity(
                                    contactId = contactId,
                                    isOutgoing = false,
                                    seqEpoch = seqEpoch,
                                    seqNum = sk.slotIndex,
                                    ackNum = frameMsg.ackNum,
                                    timestamp = frameMsg.timestampUTC,
                                    textContent = locText,
                                    status = "DELIVERED",
                                    ackTarget = targetAck,
                                    ackRatchetKey = sk.rawMsgKey,
                                    slotTarget = sk.target,
                                    slotEdSeed = sk.rawEdPrivateKeySeed,
                                    ephemeralTtlSeconds = locPayload.ephemeralTtlSeconds,
                                    expiresAtTimestamp = null
                                )
                            )
                            onIncomingMessageDelivered?.invoke(contactId, locText, false)
                        }
                        bitmap.markReceived(sk.slotIndex)
                        contactDao.updateIncomingStateWithBitmap(
                            id = contactId,
                            counterIn = contact.counterIn,
                            chainKeyIn = contact.chainKeyIn,
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                        sk.destroy()
                        skippedKeyDao.deleteSkippedKey(contactId, sk.slotIndex)
                        anyProcessed = true
                    }
                    BinaryFrameCodec.TYPE_VOICE_NOTE -> {
                        val voicePayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.VoiceNote
                        val assembled = voiceSegmentAssembler.ingest(voicePayload)
                        if (assembled != null) {
                            val seqEpoch = sk.slotIndex / 65536
                            if (!messageDao.existsMessageWithEpoch(contactId, seqEpoch, sk.slotIndex, false)) {
                                val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(sk.rawMsgKey, "${sk.slotIndex}")
                                messageDao.insertMessage(
                                    MessageEntity(
                                        contactId = contactId,
                                        isOutgoing = false,
                                        seqEpoch = seqEpoch,
                                        seqNum = sk.slotIndex,
                                        ackNum = frameMsg.ackNum,
                                        timestamp = frameMsg.timestampUTC,
                                        voiceBytes = assembled.voiceBytes,
                                        voiceDurationMs = assembled.totalDurationMs,
                                        status = "DELIVERED",
                                        ackTarget = targetAck,
                                        ackRatchetKey = sk.rawMsgKey,
                                        slotTarget = sk.target,
                                        slotEdSeed = sk.rawEdPrivateKeySeed,
                                        ephemeralTtlSeconds = assembled.ephemeralTtlSeconds,
                                        expiresAtTimestamp = null
                                    )
                                )
                                onIncomingMessageDelivered?.invoke(contactId, "Voice Note (${assembled.totalDurationMs / 1000}s)", false)
                            }
                        }
                        bitmap.markReceived(sk.slotIndex)
                        contactDao.updateIncomingStateWithBitmap(
                            id = contactId,
                            counterIn = contact.counterIn,
                            chainKeyIn = contact.chainKeyIn,
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                        sk.destroy()
                        skippedKeyDao.deleteSkippedKey(contactId, sk.slotIndex)
                        anyProcessed = true
                    }
                    BinaryFrameCodec.TYPE_GROUP_CONTROL -> {
                        val controlPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.GroupControl
                        processIncomingGroupControl(contactId, controlPayload)
                        bitmap.markReceived(sk.slotIndex)
                        contactDao.updateIncomingStateWithBitmap(
                            id = contactId,
                            counterIn = contact.counterIn,
                            chainKeyIn = contact.chainKeyIn,
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                        val rawRatchetKey = sk.rawMsgKey.copyOf()
                        sk.destroy()
                        skippedKeyDao.deleteSkippedKey(contactId, sk.slotIndex)
                        if (!isSelf) {
                            pendingAckQueue.enqueue(
                                org.pqchat.dht.traffic.PendingAck(
                                    contactId = contactId,
                                    messageId = "${sk.slotIndex}",
                                    ratchetKey = rawRatchetKey,
                                    seqNum = sk.slotIndex
                                )
                            )
                        }
                        anyProcessed = true
                    }
                    BinaryFrameCodec.TYPE_SAFETY_CANARY -> {
                        val canaryPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.SafetyCanary
                        val seqEpoch = sk.slotIndex / 65536
                        if (!messageDao.existsMessageWithEpoch(contactId, seqEpoch, sk.slotIndex, false)) {
                            val reasonStr = when (canaryPayload.triggerReason) {
                                BinaryFrameCodec.CANARY_REASON_DEAD_MAN_TIMEOUT -> "Dead Man's Switch timeout"
                                BinaryFrameCodec.CANARY_REASON_DURESS_PIN -> "Duress PIN emergency"
                                BinaryFrameCodec.CANARY_REASON_MANUAL_SOS -> "Manual SOS trigger"
                                else -> "Emergency trigger"
                            }
                            val locPart = if (canaryPayload.latitude != 0.0 || canaryPayload.longitude != 0.0) {
                                " Location: %.5f, %.5f.".format(java.util.Locale.US, canaryPayload.latitude, canaryPayload.longitude)
                            } else ""
                            val alertText = "[SAFETY CANARY ALERT] Reason: $reasonStr.$locPart Note: ${canaryPayload.note}"
                            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(sk.rawMsgKey, "${sk.slotIndex}")
                            messageDao.insertMessage(
                                MessageEntity(
                                    contactId = contactId,
                                    isOutgoing = false,
                                    seqEpoch = seqEpoch,
                                    seqNum = sk.slotIndex,
                                    ackNum = frameMsg.ackNum,
                                    timestamp = frameMsg.timestampUTC,
                                    textContent = alertText,
                                    status = "DELIVERED",
                                    ackTarget = targetAck,
                                    ackRatchetKey = sk.rawMsgKey,
                                    slotTarget = sk.target,
                                    slotEdSeed = sk.rawEdPrivateKeySeed
                                )
                            )
                            onIncomingMessageDelivered?.invoke(contactId, alertText, true)
                        }
                        bitmap.markReceived(sk.slotIndex)
                        contactDao.updateIncomingStateWithBitmap(
                            id = contactId,
                            counterIn = contact.counterIn,
                            chainKeyIn = contact.chainKeyIn,
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                        val rawRatchetKey = sk.rawMsgKey.copyOf()
                        sk.destroy()
                        skippedKeyDao.deleteSkippedKey(contactId, sk.slotIndex)
                        if (!isSelf) {
                            pendingAckQueue.enqueue(
                                org.pqchat.dht.traffic.PendingAck(
                                    contactId = contactId,
                                    messageId = "${sk.slotIndex}",
                                    ratchetKey = rawRatchetKey,
                                    seqNum = sk.slotIndex
                                )
                            )
                        }
                        anyProcessed = true
                    }
                    else -> {}
                }
            } catch (_: Exception) {
                harvestUndecryptableItem(sk.target, item)
            }
        }
        return anyProcessed
    }

    private suspend fun pollContactIncomingInternal(contactId: String): Boolean {
        var contact = contactDao.getContactById(contactId) ?: return false
        val isSelf = contactId == SELF_CONTACT_ID
        var anyProcessed = false

        // Check for Cover-Traffic ACKs for messages pending delivery to this contact
        checkPendingAcks(contactId)

        // Decoy GETs querying populated real / expiring targets (docs/threat_model.md Section 3.2 & 5.1)
        executeDecoyGets(contactId)

        // 1. First, poll any preserved skipped keys for previously out-of-order slots
        if (pollPendingSkippedKeys(contactId)) {
            anyProcessed = true
            contact = contactDao.getContactById(contactId) ?: return true
        }

        // 1b. Check and resume any pending partial chunk transfers for this contact
        if (resumePendingChunkTransfers(contactId)) {
            anyProcessed = true
            contact = contactDao.getContactById(contactId) ?: return true
        }

        // 2. Process all available consecutive messages starting at counterIn
        while (true) {
            val currentSlot = RatchetChain.deriveSlot(contact.chainKeyIn, contact.counterIn)
            val tStart = System.currentTimeMillis()
            var item = dhtLeafNode.getMutable(currentSlot.target, skipLocalStore = isSelf)
            val rttMs = System.currentTimeMillis() - tStart
            if (item != null) {
                researchTelemetry?.recordPacketEvent(
                    role = org.pqchat.dht.research.PacketRole.PACKET_RECEIVED,
                    target = currentSlot.target,
                    seqNum = contact.counterIn.toLong(),
                    payloadBytes = item.v.size,
                    rttMs = rttMs,
                    nodesQueried = item.nodesQueried.takeIf { it > 0 } ?: dhtLeafNode.lastNodesQueried,
                    nodesResponded = item.nodesResponded.takeIf { it > 0 } ?: dhtLeafNode.lastNodesResponded,
                    lookupHops = item.lookupHops.takeIf { it > 0 } ?: dhtLeafNode.lastLookupHops,
                    success = true
                )
            }
            var isChunkTransfer = false
            var initialChunkPayload: BinaryFrameCodec.DecodedPayload.ChunkData? = null
            var initialChunkIndex = -1
            var initialFrameMsg: BinaryFrameCodec.FrameMessage? = null

            if (item == null) {
                // If single message target is empty, probe chunk targets for this slot (probe 0 and 1)
                for (probeIdx in 0..1) {
                    val chunkTarget = ChunkingEngine.deriveChunkTarget(currentSlot.edPrivateKeySeed, probeIdx)
                    val tChunkStart = System.currentTimeMillis()
                    val chunkItem = dhtLeafNode.getMutable(chunkTarget, skipLocalStore = isSelf)
                    val chunkRttMs = System.currentTimeMillis() - tChunkStart
                    if (chunkItem != null) {
                        researchTelemetry?.recordPacketEvent(
                            role = org.pqchat.dht.research.PacketRole.PACKET_RECEIVED,
                            target = chunkTarget,
                            seqNum = contact.counterIn.toLong(),
                            payloadBytes = chunkItem.v.size,
                            rttMs = chunkRttMs,
                            nodesQueried = chunkItem.nodesQueried.takeIf { it > 0 } ?: dhtLeafNode.lastNodesQueried,
                            nodesResponded = chunkItem.nodesResponded.takeIf { it > 0 } ?: dhtLeafNode.lastNodesResponded,
                            lookupHops = chunkItem.lookupHops.takeIf { it > 0 } ?: dhtLeafNode.lastLookupHops,
                            success = true
                        )
                    }
                    if (chunkItem != null) {
                        val chunkKey = ChunkingEngine.deriveChunkMsgKey(currentSlot.msgKey, probeIdx)
                        try {
                            val decoded = BinaryFrameCodec.unpackAeadFrame(
                                key = chunkKey,
                                frame = chunkItem.v,
                                target = chunkTarget,
                                direction = contact.inboundDirection
                            )
                            if (decoded.msgType == BinaryFrameCodec.TYPE_CHUNK_DATA) {
                                item = chunkItem
                                isChunkTransfer = true
                                initialChunkPayload = decoded.payload as BinaryFrameCodec.DecodedPayload.ChunkData
                                initialChunkIndex = probeIdx
                                initialFrameMsg = decoded
                                break
                            }
                        } catch (_: Exception) {}
                    }
                }
            }

            if (item == null) break

            if (isChunkTransfer && initialChunkPayload != null && initialFrameMsg != null) {
                val completed = processIncomingChunkTransfer(
                    contactId = contactId,
                    slot = currentSlot,
                    chunkPayload = initialChunkPayload,
                    initialChunkIndex = initialChunkIndex,
                    frameMsg = initialFrameMsg,
                    isSelf = isSelf,
                    contact = contact
                )
                anyProcessed = true
                if (!completed) {
                    break
                }
            } else {
                val processed = processIncomingItem(contactId, currentSlot, item, isSelf)
                if (!processed) {
                    harvestUndecryptableItem(currentSlot.target, item)
                    break
                }
                anyProcessed = true
            }
            contact = contactDao.getContactById(contactId) ?: break
        }

        if (!anyProcessed) {
            checkLookaheadWindowInternal(contactId)
            val updatedContact = contactDao.getContactById(contactId)
            if (updatedContact != null && updatedContact.counterIn > contact.counterIn) {
                anyProcessed = true
                drainOutboxInternal(contactId, force = true)
            }
        } else {
            drainOutboxInternal(contactId, force = true)
            triggerLookaheadWindowAsync(contactId)
        }

        return anyProcessed
    }

    /**
     * Asynchronously checks subsequent slots in the lookahead window.
     * Launched only after successfully receiving and decrypting a message at counterIn.
     */
    fun triggerLookaheadWindowAsync(contactId: String): Job {
        return repositoryScope.launch {
            checkLookaheadWindow(contactId)
        }
    }

    /**
     * Checks subsequent slots in lookahead window [counterIn .. counterIn + 4].
     * When slot k > n is found, intermediate skipped keys n..k-1 are saved with TTL & limit
     * rather than jumping the counter and permanently losing skipped slot keys.
     */
    suspend fun checkLookaheadWindow(contactId: String) = withContext(Dispatchers.IO) {
        getContactMutex(contactId).withLock {
            checkLookaheadWindowInternal(contactId)
        }
    }

    private suspend fun checkLookaheadWindowInternal(contactId: String) {
        val isSelf = contactId == SELF_CONTACT_ID
        var currentContact = contactDao.getContactById(contactId) ?: return
        var hasMore = true

        while (hasMore) {
            hasMore = false
            val lookaheadSlots = RatchetChain.computeLookaheadSlots(
                startChainKey = currentContact.chainKeyIn,
                startCounter = currentContact.counterIn,
                windowSize = 4
            )

            for (idx in lookaheadSlots.indices) {
                val slot = lookaheadSlots[idx]
                val item = dhtLeafNode.getMutable(slot.target, skipLocalStore = isSelf) ?: continue

                // If slot.counter > currentContact.counterIn, preserve skipped slots n..k-1
                if (slot.counter > currentContact.counterIn) {
                    for (skipIdx in 0 until idx) {
                        val skippedSlot = lookaheadSlots[skipIdx]
                        val bitmap = SlidingWindowBitmap(currentContact.receivedBitmapBase, 1024, currentContact.receivedBitmap)
                        if (!bitmap.isReceived(skippedSlot.counter)) {
                            if (skippedKeyDao != null) {
                                val count = skippedKeyDao.countSkippedKeys(contactId)
                                if (count >= MAX_SKIPPED_KEYS_PER_CONTACT) {
                                    skippedKeyDao.deleteOldestSkippedKeys(contactId, count - MAX_SKIPPED_KEYS_PER_CONTACT + 1)
                                }
                                skippedKeyDao.insertOrUpdate(
                                    SkippedKeyEntity(
                                        contactId = contactId,
                                        slotIndex = skippedSlot.counter,
                                        msgKey = skippedSlot.msgKey,
                                        target = skippedSlot.target,
                                        edPrivateKeySeed = skippedSlot.edPrivateKeySeed
                                    )
                                )
                            }
                        }
                    }
                }

                val success = processIncomingItem(contactId, slot, item, isSelf)
                if (success) {
                    val updated = contactDao.getContactById(contactId)
                    if (updated != null && updated.counterIn > currentContact.counterIn) {
                        currentContact = updated
                        hasMore = true
                        break
                    }
                } else {
                    harvestUndecryptableItem(slot.target, item)
                }
            }
        }

        drainOutboxInternal(contactId, force = true)
    }

    /**
     * Processes and decrypts a received DHT BEP 44 mutable item for a specific slot.
     */
    suspend fun processIncomingItem(
        contactId: String,
        slot: RatchetChain.SlotParameters,
        item: DhtLeafNode.MutableItem,
        isSelf: Boolean
    ): Boolean = withContext(Dispatchers.IO) {
        val contact = contactDao.getContactById(contactId) ?: return@withContext false

        // 1. BEP 44 Sequence Rollback & Tombstone Defense:
        // If the record has seq > DEFAULT_MUTABLE_SEQ (e.g. seq = 2 tombstone),
        // the slot was already consumed and cleaned by receiver or sender.
        // Mark as received in sliding window and advance counter past this slot to avoid stalling outbox.
        if (item.seq > DhtClient.DEFAULT_MUTABLE_SEQ) {
            val bitmap = SlidingWindowBitmap(contact.receivedBitmapBase, 1024, contact.receivedBitmap)
            bitmap.markReceived(slot.counter)
            contactDao.updateIncomingStateWithBitmap(
                id = contactId,
                counterIn = maxOf(contact.counterIn, slot.counter + 1),
                chainKeyIn = slot.nextChainKey,
                bitmapBase = bitmap.windowBase,
                bitmap = bitmap.toByteArray()
            )
            researchTelemetry?.recordAdversarialEvent(
                anomalyType = "TOMBSTONE_SLOT_DETECTED",
                target = slot.target,
                details = "Slot counter=${slot.counter} tombstoned with seq=${item.seq}",
                mitigated = true
            )
            return@withContext true
        }

        try {
            val frameMsg = BinaryFrameCodec.unpackAeadFrame(
                key = slot.msgKey,
                frame = item.v,
                target = slot.target,
                direction = contact.inboundDirection
            )

            // Process Piggybacked ACK: If incoming frame acknowledges our sent sequence, mark as DELIVERED
            processPiggybackedAck(contactId, frameMsg.last_received_seq)

            org.pqchat.dht.debug.MessageDebugLogger.logIncomingMessage(
                contactId = contactId,
                target = slot.target,
                seq = item.seq,
                senderEdPublicKey = item.k,
                senderSignature = item.sig,
                frame = item.v,
                frameMsg = frameMsg
            )

            val bitmap = SlidingWindowBitmap(contact.receivedBitmapBase, 1024, contact.receivedBitmap)

            // Ignore if already marked in sliding window bitmap
            if (!isSelf && bitmap.isReceived(slot.counter)) {
                researchTelemetry?.recordAdversarialEvent(
                    anomalyType = "REPLAY_ATTACK_ATTEMPT",
                    target = slot.target,
                    details = "Blocked duplicate message slot counter=${slot.counter} via sliding window",
                    mitigated = true
                )
                return@withContext true
            }

            when (frameMsg.msgType) {
                BinaryFrameCodec.TYPE_TEXT_MESSAGE -> {
                    val textPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.TextMessage
                    bitmap.markReceived(slot.counter)

                    if (isSelf) {
                        messageDao.updateMessageStatusAndDirection(
                            contactId = contactId,
                            seqNum = slot.counter,
                            isOutgoing = false,
                            status = "CONFIRMED_DHT"
                        )
                        contactDao.updateIncomingStateWithBitmap(
                            id = contactId,
                            counterIn = slot.counter + 1,
                            chainKeyIn = slot.nextChainKey,
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                        preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                    } else {
                        val seqEpoch = slot.counter / 65536
                        val alreadyExists = messageDao.existsMessageWithEpoch(contactId, seqEpoch, slot.counter, false)
                        if (!alreadyExists) {
                            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot.msgKey, "${slot.counter}")
                            messageDao.insertMessage(
                                MessageEntity(
                                    contactId = contactId,
                                    isOutgoing = false,
                                    seqEpoch = seqEpoch,
                                    seqNum = slot.counter,
                                    ackNum = frameMsg.ackNum,
                                    timestamp = frameMsg.timestampUTC,
                                    textContent = textPayload.text,
                                    status = "DELIVERED",
                                    ackTarget = targetAck,
                                    ackRatchetKey = slot.msgKey,
                                    slotTarget = slot.target,
                                    slotEdSeed = slot.edPrivateKeySeed,
                                    ephemeralTtlSeconds = textPayload.ephemeralTtlSeconds,
                                    expiresAtTimestamp = null
                                )
                            )

                            contactDao.updateIncomingStateWithBitmap(
                                id = contactId,
                                counterIn = slot.counter + 1,
                                chainKeyIn = slot.nextChainKey,
                                bitmapBase = bitmap.windowBase,
                                bitmap = bitmap.toByteArray()
                            )
                            preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                            onIncomingMessageDelivered?.invoke(contactId, textPayload.text, false)

                            if (!isSelf) {
                                pendingAckQueue.enqueue(
                                    org.pqchat.dht.traffic.PendingAck(
                                        contactId = contactId,
                                        messageId = "${slot.counter}",
                                        ratchetKey = slot.msgKey,
                                        seqNum = slot.counter
                                    )
                                )
                            }
                        }
                    }
                    true
                }

                BinaryFrameCodec.TYPE_REKEY_OFFER -> {
                    val offerPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.RekeyOffer
                    bitmap.markReceived(slot.counter)

                    val currentContact = contactDao.getContactById(contactId) ?: contact
                    val outSlot = RatchetChain.deriveSlot(currentContact.chainKeyOut, currentContact.counterOut)

                    // 1. Receiver encapsulates SS_rekey and creates Type 0x04 Response frame via RekeyCoordinator
                    val (ssRekey, respFrame) = RekeyCoordinator.processOfferAndCreateResponse(
                        offer = offerPayload,
                        reverseSeqNum = currentContact.counterOut and 0xFFFF,
                        reverseAckNum = frameMsg.seqNum and 0xFFFF,
                        reverseMsgKey = outSlot.msgKey,
                        reverseTarget = outSlot.target,
                        direction = currentContact.outboundDirection
                    )

                    // 2. Inject SS_rekey into receiver's chainKeyIn
                    val rekeyedChainIn = RatchetChain.injectRekeySecret(slot.nextChainKey, ssRekey)
                    contactDao.updateIncomingStateAndEpochWithBitmap(
                        id = contactId,
                        counterIn = slot.counter + 1,
                        chainKeyIn = rekeyedChainIn,
                        rekeyEpoch = offerPayload.rekeyEpoch,
                        bitmapBase = bitmap.windowBase,
                        bitmap = bitmap.toByteArray()
                    )
                    preWarmNextIncomingTarget(rekeyedChainIn, slot.counter + 1)

                    org.pqchat.dht.debug.MessageDebugLogger.logOutgoingRekeyResponse(
                        contactId = contactId,
                        epoch = offerPayload.rekeyEpoch,
                        slot = outSlot,
                        seqNum = currentContact.counterOut,
                        ackNum = frameMsg.seqNum,
                        frame = respFrame
                    )

                    // 3. Publish Type 0x04 Response on receiver's outgoing channel (reverse direction)
                    contactDao.updateOutgoingState(contactId, currentContact.counterOut + 1, outSlot.nextChainKey)
                    if (isStrictPoissonShaping()) {
                        outboundPoissonQueue.enqueue(
                            org.pqchat.dht.traffic.OutboundPoissonFrame(
                                target = outSlot.target,
                                payload = respFrame,
                                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                                salt = null,
                                sk = outSlot.edPrivateKeySeed,
                                skipLocalStore = isSelf,
                                seqNum = currentContact.counterOut,
                                contactId = contactId,
                                packetClass = org.pqchat.dht.traffic.PacketClass.URGENT_CONTROL,
                                onSent = { success ->
                                    if (success) {
                                        decoyTargetPool.registerPopulatedTarget(outSlot.target)
                                    }
                                }
                            )
                        )
                    } else {
                        dhtLeafNode.putMutable(
                            target = outSlot.target,
                            v = respFrame,
                            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                            sk = outSlot.edPrivateKeySeed,
                            skipLocalStore = isSelf
                        )
                    }

                    ssRekey.fill(0)
                    true
                }

                BinaryFrameCodec.TYPE_REKEY_RESPONSE -> {
                    val respPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.RekeyResponse
                    val pendingOfferEntity = pendingRekeyOfferDao?.getPendingOffer(contactId)
                    bitmap.markReceived(slot.counter)

                    if (pendingOfferEntity != null && pendingOfferEntity.epoch == respPayload.rekeyEpoch) {
                        val pendingOffer = RekeyCoordinator.PendingRekeyOffer(
                            epoch = pendingOfferEntity.epoch,
                            skNew = pendingOfferEntity.rawSkNew,
                            pkNew = pendingOfferEntity.pkNew
                        )
                        val ssRekey = RekeyCoordinator.processResponse(respPayload, pendingOffer)
                        pendingOfferEntity.destroy()
                        pendingRekeyOfferDao.deletePendingOffer(contactId)
                        _rekeyInProgressContacts.value = _rekeyInProgressContacts.value - contactId

                        val latestContact = contactDao.getContactById(contactId) ?: contact
                        val rekeyedChainOut = RatchetChain.injectRekeySecret(latestContact.chainKeyOut, ssRekey)
                        contactDao.updateOutgoingStateAndEpoch(contactId, latestContact.counterOut, rekeyedChainOut, respPayload.rekeyEpoch)
                        ssRekey.fill(0)
                    }

                    contactDao.updateIncomingStateWithBitmap(
                        id = contactId,
                        counterIn = slot.counter + 1,
                        chainKeyIn = slot.nextChainKey,
                        bitmapBase = bitmap.windowBase,
                        bitmap = bitmap.toByteArray()
                    )
                    preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                    true
                }

                BinaryFrameCodec.TYPE_CHUNK_DATA -> {
                    val chunkPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.ChunkData
                    processIncomingChunkTransfer(
                        contactId = contactId,
                        slot = slot,
                        chunkPayload = chunkPayload,
                        initialChunkIndex = chunkPayload.chunkIndex,
                        frameMsg = frameMsg,
                        isSelf = isSelf,
                        contact = contact
                    )
                }

                BinaryFrameCodec.TYPE_GROUP_CONTROL -> {
                    val controlPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.GroupControl
                    bitmap.markReceived(slot.counter)
                    processIncomingGroupControl(contactId, controlPayload)
                    contactDao.updateIncomingStateWithBitmap(
                        id = contactId,
                        counterIn = slot.counter + 1,
                        chainKeyIn = slot.nextChainKey,
                        bitmapBase = bitmap.windowBase,
                        bitmap = bitmap.toByteArray()
                    )
                    preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                    if (!isSelf) {
                        pendingAckQueue.enqueue(
                            org.pqchat.dht.traffic.PendingAck(
                                contactId = contactId,
                                messageId = "${slot.counter}",
                                ratchetKey = slot.msgKey,
                                seqNum = slot.counter
                            )
                        )
                    }
                    true
                }
                BinaryFrameCodec.TYPE_REACTION -> {
                    val reactionPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.Reaction
                    bitmap.markReceived(slot.counter)
                    messageDao.updateMessageReaction(contactId, reactionPayload.targetSeqEpoch, reactionPayload.targetSeqNum, true, reactionPayload.emoji)
                    messageDao.updateMessageReactionAnyDirection(contactId, reactionPayload.targetSeqEpoch, reactionPayload.targetSeqNum, reactionPayload.emoji)
                    contactDao.updateIncomingStateWithBitmap(
                        id = contactId,
                        counterIn = slot.counter + 1,
                        chainKeyIn = slot.nextChainKey,
                        bitmapBase = bitmap.windowBase,
                        bitmap = bitmap.toByteArray()
                    )
                    preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                    if (!isSelf) {
                        pendingAckQueue.enqueue(
                            org.pqchat.dht.traffic.PendingAck(
                                contactId = contactId,
                                messageId = "${slot.counter}",
                                ratchetKey = slot.msgKey,
                                seqNum = slot.counter
                            )
                        )
                    }
                    true
                }
                BinaryFrameCodec.TYPE_LOCATION_PIN -> {
                    val locPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.LocationPin
                    bitmap.markReceived(slot.counter)
                    val seqEpoch = slot.counter / 65536
                    val alreadyExists = messageDao.existsMessageWithEpoch(contactId, seqEpoch, slot.counter, false)
                    if (!alreadyExists) {
                        val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot.msgKey, "${slot.counter}")
                        val locText = org.pqchat.dht.protocol.LocationPinData(
                            locPayload.latitude,
                            locPayload.longitude,
                            locPayload.altitude,
                            locPayload.accuracy,
                            locPayload.note
                        ).toPayloadText()
                        messageDao.insertMessage(
                            MessageEntity(
                                contactId = contactId,
                                isOutgoing = false,
                                seqEpoch = seqEpoch,
                                seqNum = slot.counter,
                                ackNum = frameMsg.ackNum,
                                timestamp = frameMsg.timestampUTC,
                                textContent = locText,
                                status = "DELIVERED",
                                ackTarget = targetAck,
                                ackRatchetKey = slot.msgKey,
                                slotTarget = slot.target,
                                slotEdSeed = slot.edPrivateKeySeed,
                                ephemeralTtlSeconds = locPayload.ephemeralTtlSeconds,
                                expiresAtTimestamp = null
                            )
                        )
                        contactDao.updateIncomingStateWithBitmap(
                            id = contactId,
                            counterIn = slot.counter + 1,
                            chainKeyIn = slot.nextChainKey,
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                        preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                        onIncomingMessageDelivered?.invoke(contactId, locText, false)

                        if (!isSelf) {
                            pendingAckQueue.enqueue(
                                org.pqchat.dht.traffic.PendingAck(
                                    contactId = contactId,
                                    messageId = "${slot.counter}",
                                    ratchetKey = slot.msgKey,
                                    seqNum = slot.counter
                                )
                            )
                        }
                    }
                    true
                }
                BinaryFrameCodec.TYPE_VOICE_NOTE -> {
                    val voicePayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.VoiceNote
                    bitmap.markReceived(slot.counter)
                    val assembled = voiceSegmentAssembler.ingest(voicePayload)
                    if (assembled != null) {
                        val seqEpoch = slot.counter / 65536
                        val alreadyExists = messageDao.existsMessageWithEpoch(contactId, seqEpoch, slot.counter, false)
                        if (!alreadyExists) {
                            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot.msgKey, "${slot.counter}")
                            messageDao.insertMessage(
                                MessageEntity(
                                    contactId = contactId,
                                    isOutgoing = false,
                                    seqEpoch = seqEpoch,
                                    seqNum = slot.counter,
                                    ackNum = frameMsg.ackNum,
                                    timestamp = frameMsg.timestampUTC,
                                    voiceBytes = assembled.voiceBytes,
                                    voiceDurationMs = assembled.totalDurationMs,
                                    status = "DELIVERED",
                                    ackTarget = targetAck,
                                    ackRatchetKey = slot.msgKey,
                                    slotTarget = slot.target,
                                    slotEdSeed = slot.edPrivateKeySeed,
                                    ephemeralTtlSeconds = assembled.ephemeralTtlSeconds,
                                    expiresAtTimestamp = null
                                )
                            )
                            onIncomingMessageDelivered?.invoke(contactId, "Voice Note (${assembled.totalDurationMs / 1000}s)", false)
                        }
                    }
                    contactDao.updateIncomingStateWithBitmap(
                        id = contactId,
                        counterIn = slot.counter + 1,
                        chainKeyIn = slot.nextChainKey,
                        bitmapBase = bitmap.windowBase,
                        bitmap = bitmap.toByteArray()
                    )
                    preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                    if (!isSelf) {
                        pendingAckQueue.enqueue(
                            org.pqchat.dht.traffic.PendingAck(
                                contactId = contactId,
                                messageId = "${slot.counter}",
                                ratchetKey = slot.msgKey,
                                seqNum = slot.counter
                            )
                        )
                    }
                    true
                }
                BinaryFrameCodec.TYPE_SAFETY_CANARY -> {
                    val canaryPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.SafetyCanary
                    bitmap.markReceived(slot.counter)
                    val seqEpoch = slot.counter / 65536
                    val alreadyExists = messageDao.existsMessageWithEpoch(contactId, seqEpoch, slot.counter, false)
                    if (!alreadyExists) {
                        val reasonStr = when (canaryPayload.triggerReason) {
                            BinaryFrameCodec.CANARY_REASON_DEAD_MAN_TIMEOUT -> "Dead Man's Switch timeout"
                            BinaryFrameCodec.CANARY_REASON_DURESS_PIN -> "Duress PIN emergency"
                            BinaryFrameCodec.CANARY_REASON_MANUAL_SOS -> "Manual SOS trigger"
                            else -> "Emergency trigger"
                        }
                        val locPart = if (canaryPayload.latitude != 0.0 || canaryPayload.longitude != 0.0) {
                            " Location: %.5f, %.5f.".format(java.util.Locale.US, canaryPayload.latitude, canaryPayload.longitude)
                        } else ""
                        val alertText = "[SAFETY CANARY ALERT] Reason: $reasonStr.$locPart Note: ${canaryPayload.note}"
                        val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot.msgKey, "${slot.counter}")
                        messageDao.insertMessage(
                            MessageEntity(
                                contactId = contactId,
                                isOutgoing = false,
                                seqEpoch = seqEpoch,
                                seqNum = slot.counter,
                                ackNum = frameMsg.ackNum,
                                timestamp = frameMsg.timestampUTC,
                                textContent = alertText,
                                status = "DELIVERED",
                                ackTarget = targetAck,
                                ackRatchetKey = slot.msgKey,
                                slotTarget = slot.target,
                                slotEdSeed = slot.edPrivateKeySeed
                            )
                        )
                        onIncomingMessageDelivered?.invoke(contactId, alertText, true)
                    }
                    contactDao.updateIncomingStateWithBitmap(
                        id = contactId,
                        counterIn = slot.counter + 1,
                        chainKeyIn = slot.nextChainKey,
                        bitmapBase = bitmap.windowBase,
                        bitmap = bitmap.toByteArray()
                    )
                    preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                    if (!isSelf) {
                        pendingAckQueue.enqueue(
                            org.pqchat.dht.traffic.PendingAck(
                                contactId = contactId,
                                messageId = "${slot.counter}",
                                ratchetKey = slot.msgKey,
                                seqNum = slot.counter
                            )
                        )
                    }
                    true
                }
                else -> false
            }
        } catch (e: Exception) {
            researchTelemetry?.recordAdversarialEvent(
                anomalyType = "BAD_AEAD_TAG",
                target = slot.target,
                details = "Corrupted frame, IV, AEAD tag or structure: ${e.message}",
                mitigated = true
            )
            false
        }
    }

    /**
     * Processes an incoming chunked payload (e.g. PNG image), retrieving parallel/remaining chunks,
     * maintaining pending partial transfer state with 72h TTL, and reporting download progress.
     */
    private suspend fun processIncomingChunkTransfer(
        contactId: String,
        slot: RatchetChain.SlotParameters,
        chunkPayload: BinaryFrameCodec.DecodedPayload.ChunkData,
        initialChunkIndex: Int,
        frameMsg: BinaryFrameCodec.FrameMessage,
        isSelf: Boolean,
        contact: ContactEntity
    ): Boolean {
        val transferIdHex = CryptoUtils.toHex(chunkPayload.transferId)
        val bitmap = SlidingWindowBitmap(contact.receivedBitmapBase, 1024, contact.receivedBitmap)

        chunkDao.insertChunk(
            transferId = transferIdHex,
            chunkIndex = chunkPayload.chunkIndex,
            totalChunks = chunkPayload.totalChunks,
            data = chunkPayload.data
        )

        // Query all other chunks 0 until totalChunks
        for (j in 0 until chunkPayload.totalChunks) {
            if (j == initialChunkIndex) continue
            val subTarget = ChunkingEngine.deriveChunkTarget(slot.edPrivateKeySeed, j)
            val subMsgKey = ChunkingEngine.deriveChunkMsgKey(slot.msgKey, j)

            val subItem = dhtLeafNode.getMutable(subTarget, skipLocalStore = isSelf)
            if (subItem != null) {
                try {
                    val subFrame = BinaryFrameCodec.unpackAeadFrame(
                        key = subMsgKey,
                        frame = subItem.v,
                        target = subTarget,
                        direction = contact.inboundDirection
                    )
                    if (subFrame.msgType == BinaryFrameCodec.TYPE_CHUNK_DATA) {
                        val subChunk = subFrame.payload as BinaryFrameCodec.DecodedPayload.ChunkData
                        chunkDao.insertChunk(
                            transferId = transferIdHex,
                            chunkIndex = subChunk.chunkIndex,
                            totalChunks = subChunk.totalChunks,
                            data = subChunk.data
                        )
                    }
                } catch (_: Exception) {}
            }
        }

        val count = chunkDao.countChunks(transferIdHex)
        if (count == chunkPayload.totalChunks) {
            val allChunks = chunkDao.getChunksForTransfer(transferIdHex)
            val decodedList = allChunks.map {
                BinaryFrameCodec.DecodedPayload.ChunkData(
                    transferId = chunkPayload.transferId,
                    chunkIndex = it.chunkIndex,
                    totalChunks = it.totalChunks,
                    data = it.rawData
                )
            }
            val fullData = ChunkingEngine.assembleChunks(decodedList)
            chunkDao.deleteChunks(transferIdHex)
            chunkDao.deletePendingTransfer(transferIdHex)
            _imageDownloadProgress.update { it - transferIdHex }

            bitmap.markReceived(slot.counter)

            if (isSelf) {
                messageDao.updateMessageStatusAndDirection(
                    contactId = contactId,
                    seqNum = slot.counter,
                    isOutgoing = false,
                    status = "CONFIRMED_DHT"
                )
                contactDao.updateIncomingStateWithBitmap(
                    id = contactId,
                    counterIn = slot.counter + 1,
                    chainKeyIn = slot.nextChainKey,
                    bitmapBase = bitmap.windowBase,
                    bitmap = bitmap.toByteArray()
                )
                preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
            } else {
                val seqEpoch = slot.counter / 65536
                messageDao.insertMessage(
                    MessageEntity(
                        contactId = contactId,
                        isOutgoing = false,
                        seqEpoch = seqEpoch,
                        seqNum = slot.counter,
                        ackNum = frameMsg.ackNum,
                        timestamp = frameMsg.timestampUTC,
                        textContent = "[Image File - ${fullData.size} bytes]",
                        imageBytes = fullData,
                        status = "DELIVERED"
                    )
                )

                contactDao.updateIncomingStateWithBitmap(
                    id = contactId,
                    counterIn = slot.counter + 1,
                    chainKeyIn = slot.nextChainKey,
                    bitmapBase = bitmap.windowBase,
                    bitmap = bitmap.toByteArray()
                )
                preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                onIncomingMessageDelivered?.invoke(contactId, "[Image File - ${fullData.size} bytes]", true)

                pendingAckQueue.enqueue(
                    org.pqchat.dht.traffic.PendingAck(
                        contactId = contactId,
                        messageId = "${slot.counter}",
                        ratchetKey = slot.msgKey,
                        seqNum = slot.counter
                    )
                )
            }
            return true
        } else {
            // Partial transfer: record missing chunk indices and save pending state (72h TTL)
            val existingIndices = chunkDao.getExistingChunkIndices(transferIdHex).toSet()
            val missingIndices = (0 until chunkPayload.totalChunks).filter { it !in existingIndices }

            val pendingTransfer = PendingChunkTransferEntity(
                transferId = transferIdHex,
                contactId = contactId,
                seqNum = slot.counter,
                totalChunks = chunkPayload.totalChunks,
                missingIndices = missingIndices,
                baseEdSeed = slot.edPrivateKeySeed,
                baseMsgKey = slot.msgKey,
                direction = contact.inboundDirection,
                isSelf = isSelf,
                ackNum = frameMsg.ackNum,
                timestampUTC = frameMsg.timestampUTC,
                createdAt = System.currentTimeMillis(),
                expiresAt = System.currentTimeMillis() + 72 * 3600 * 1000L
            )
            chunkDao.insertPendingTransfer(pendingTransfer)

            _imageDownloadProgress.update {
                it + (transferIdHex to ImageDownloadProgress(
                    transferId = transferIdHex,
                    contactId = contactId,
                    seqNum = slot.counter,
                    receivedChunks = count,
                    totalChunks = chunkPayload.totalChunks
                ))
            }
            return false
        }
    }

    /**
     * Resumes any in-flight partial chunk transfers for this contact, querying DHT for missing chunks.
     * Enforces a 72h TTL by deleting expired orphaned transfers and chunks.
     */
    suspend fun resumePendingChunkTransfers(contactId: String): Boolean = withContext(Dispatchers.IO) {
        chunkDao.purgeExpiredTransfers()
        val pendingList = chunkDao.getPendingTransfersForContact(contactId)
        if (pendingList.isEmpty()) return@withContext false

        var anyCompleted = false
        val contact = contactDao.getContactById(contactId) ?: return@withContext false
        val bitmap = SlidingWindowBitmap(contact.receivedBitmapBase, 1024, contact.receivedBitmap)

        for (pending in pendingList) {
            val missing = pending.parseMissingIndices()
            if (missing.isEmpty()) continue

            for (chunkIdx in missing) {
                val subTarget = ChunkingEngine.deriveChunkTarget(pending.rawBaseEdSeed, chunkIdx)
                val subKey = ChunkingEngine.deriveChunkMsgKey(pending.rawBaseMsgKey, chunkIdx)
                val subItem = dhtLeafNode.getMutable(subTarget, skipLocalStore = pending.isSelf) ?: continue
                try {
                    val subFrame = BinaryFrameCodec.unpackAeadFrame(
                        key = subKey,
                        frame = subItem.v,
                        target = subTarget,
                        direction = pending.direction
                    )
                    if (subFrame.msgType == BinaryFrameCodec.TYPE_CHUNK_DATA) {
                        val subChunk = subFrame.payload as BinaryFrameCodec.DecodedPayload.ChunkData
                        chunkDao.insertChunk(
                            transferId = pending.transferId,
                            chunkIndex = subChunk.chunkIndex,
                            totalChunks = pending.totalChunks,
                            data = subChunk.data
                        )
                    }
                } catch (_: Exception) {}
            }

            val count = chunkDao.countChunks(pending.transferId)
            if (count == pending.totalChunks) {
                // Completed!
                val allChunks = chunkDao.getChunksForTransfer(pending.transferId)
                val decodedList = allChunks.map {
                    BinaryFrameCodec.DecodedPayload.ChunkData(
                        transferId = CryptoUtils.fromHex(pending.transferId),
                        chunkIndex = it.chunkIndex,
                        totalChunks = it.totalChunks,
                        data = it.rawData
                    )
                }
                val fullData = ChunkingEngine.assembleChunks(decodedList)
                chunkDao.deleteChunks(pending.transferId)
                chunkDao.deletePendingTransfer(pending.transferId)
                _imageDownloadProgress.update { it - pending.transferId }

                bitmap.markReceived(pending.seqNum)

                if (pending.isSelf) {
                    messageDao.updateMessageStatusAndDirection(
                        contactId = contactId,
                        seqNum = pending.seqNum,
                        isOutgoing = false,
                        status = "CONFIRMED_DHT"
                    )
                } else {
                    val seqEpoch = pending.seqNum / 65536
                    messageDao.insertMessage(
                        MessageEntity(
                            contactId = contactId,
                            isOutgoing = false,
                            seqEpoch = seqEpoch,
                            seqNum = pending.seqNum,
                            ackNum = pending.ackNum,
                            timestamp = pending.timestampUTC,
                            textContent = "[Image File - ${fullData.size} bytes]",
                            imageBytes = fullData,
                            status = "DELIVERED"
                        )
                    )
                    onIncomingMessageDelivered?.invoke(contactId, "[Image File - ${fullData.size} bytes]", true)
                    pendingAckQueue.enqueue(
                        org.pqchat.dht.traffic.PendingAck(
                            contactId = contactId,
                            messageId = "${pending.seqNum}",
                            ratchetKey = pending.rawBaseMsgKey,
                            seqNum = pending.seqNum
                        )
                    )
                }

                // If this completed transfer is at counterIn, advance counterIn
                val currentContact = contactDao.getContactById(contactId) ?: contact
                if (pending.seqNum == currentContact.counterIn) {
                    val completedSlot = RatchetChain.deriveSlot(currentContact.chainKeyIn, currentContact.counterIn)
                    contactDao.updateIncomingStateWithBitmap(
                        id = contactId,
                        counterIn = completedSlot.counter + 1,
                        chainKeyIn = completedSlot.nextChainKey,
                        bitmapBase = bitmap.windowBase,
                        bitmap = bitmap.toByteArray()
                    )
                    preWarmNextIncomingTarget(completedSlot.nextChainKey, completedSlot.counter + 1)
                } else {
                    contactDao.updateIncomingStateWithBitmap(
                        id = contactId,
                        counterIn = currentContact.counterIn,
                        chainKeyIn = currentContact.chainKeyIn,
                        bitmapBase = bitmap.windowBase,
                        bitmap = bitmap.toByteArray()
                    )
                }
                anyCompleted = true
            } else {
                // Still incomplete: update missing indices & progress
                val existing = chunkDao.getExistingChunkIndices(pending.transferId).toSet()
                val remaining = (0 until pending.totalChunks).filter { it !in existing }
                chunkDao.updateMissingIndices(pending.transferId, remaining.joinToString(","))
                _imageDownloadProgress.update {
                    it + (pending.transferId to ImageDownloadProgress(
                        transferId = pending.transferId,
                        contactId = contactId,
                        seqNum = pending.seqNum,
                        receivedChunks = count,
                        totalChunks = pending.totalChunks
                    ))
                }
            }
        }
        return@withContext anyCompleted
    }

    data class PendingGroupControlRecord(
        val taskId: Long,
        val groupId: String,
        val contactId: String,
        val controlSubType: Byte,
        val groupEpoch: Long,
        val targetAck: ByteArray,
        val ackRatchetKey: ByteArray,
        val seqNum: Int,
        val slotTarget: ByteArray,
        val slotEdSeed: ByteArray,
        val payload: ByteArray,
        val timestamp: Long = System.currentTimeMillis(),
        var lastRepublishedTimestamp: Long = 0L,
        var currentAttempts: Int = 0
    )

    private val pendingGroupControls = ConcurrentHashMap<Long, PendingGroupControlRecord>()
    private val nextControlTaskId = java.util.concurrent.atomic.AtomicLong(-1000L)

    fun getPendingGroupControls(): List<PendingGroupControlRecord> = pendingGroupControls.values.toList()

    fun getPendingGroupControlCount(): Int = pendingGroupControls.size

    fun clearPendingGroupControls() {
        pendingGroupControls.clear()
    }

    suspend fun checkPendingGroupControlAcks(contactId: String? = null): Int = withContext(Dispatchers.IO) {
        val targets = if (contactId != null) {
            pendingGroupControls.values.filter { it.contactId == contactId }
        } else {
            pendingGroupControls.values.toList()
        }
        if (targets.isEmpty()) return@withContext 0

        var acksFound = 0
        for (record in targets) {
            val isSelf = record.contactId == SELF_CONTACT_ID
            val ackItem = dhtLeafNode.getMutable(record.targetAck, skipLocalStore = isSelf) ?: continue
            val isValid = org.pqchat.dht.protocol.CoverAckProtocol.verifyAckPayload(
                ratchetKey = record.ackRatchetKey,
                frame = ackItem.v,
                expectedMessageId = "${record.seqNum}",
                expectedSeqNum = record.seqNum
            )
            if (isValid) {
                org.pqchat.dht.service.DhtWorker.unregisterRepublishTask(record.taskId)
                pendingGroupControls.remove(record.taskId)
                onRepublishTaskUpdated?.invoke()

                researchTelemetry?.recordDeliveryAck(record.slotTarget)

                try {
                    val tombOk = dhtLeafNode.putMutable(
                        target = record.slotTarget,
                        v = BinaryFrameCodec.createTombstonePayload(),
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ + 1,
                        salt = null,
                        sk = record.slotEdSeed,
                        skipLocalStore = isSelf
                    )
                    researchTelemetry?.recordPacketEvent(
                        role = org.pqchat.dht.research.PacketRole.TOMBSTONE_SENT,
                        target = record.slotTarget,
                        payloadBytes = 900,
                        success = tombOk
                    )
                } catch (_: Exception) {}
                acksFound++
            }
        }
        acksFound
    }

    /**
     * Checks Target_ACK ephemeral slots for messages in PENDING_DELIVERY (or SENT_DHT) status.
     * When a valid Cover-Traffic ACK is detected:
     * - Updates Room DB message status to DELIVERED
     * - Unregisters cyclic republish task in DhtWorker
     * - Optionally emits a BEP 44 tombstone (empty record) on the transmission slot
     */
    suspend fun checkPendingAcks(contactId: String? = null): Int = withContext(Dispatchers.IO) {
        val pending = if (contactId != null) {
            messageDao.getPendingDeliveryMessagesForContact(contactId)
        } else {
            messageDao.getAllPendingDeliveryMessages()
        }
        val controlAcks = checkPendingGroupControlAcks(contactId)
        if (pending.isEmpty()) return@withContext controlAcks

        var acksFound = controlAcks
        for (msg in pending) {
            val targetAck = msg.ackTarget ?: continue
            val ratchetKey = msg.ackRatchetKey?.raw ?: continue
            val msgIdStr = "${msg.seqNum}"
            val isSelf = msg.contactId == SELF_CONTACT_ID

            val ackItem = dhtLeafNode.getMutable(targetAck, skipLocalStore = isSelf) ?: continue
            val isValid = org.pqchat.dht.protocol.CoverAckProtocol.verifyAckPayload(
                ratchetKey = ratchetKey,
                frame = ackItem.v,
                expectedMessageId = msgIdStr,
                expectedSeqNum = msg.seqNum
            )

            if (isValid) {
                messageDao.updateStatus(msg.id, "DELIVERED")
                org.pqchat.dht.service.DhtWorker.unregisterRepublishTask(msg.id)
                onRepublishTaskUpdated?.invoke()

                val slotTarget = msg.slotTarget
                if (slotTarget != null) {
                    researchTelemetry?.recordDeliveryAck(slotTarget)
                }

                val slotEdSeed = msg.slotEdSeed?.raw
                if (slotTarget != null && slotEdSeed != null) {
                    try {
                        val tombOk = dhtLeafNode.putMutable(
                            target = slotTarget,
                            v = org.pqchat.dht.crypto.BinaryFrameCodec.createTombstonePayload(),
                            seq = DhtClient.DEFAULT_MUTABLE_SEQ + 1,
                            salt = null,
                            sk = slotEdSeed,
                            skipLocalStore = isSelf
                        )
                        researchTelemetry?.recordPacketEvent(
                            role = org.pqchat.dht.research.PacketRole.TOMBSTONE_SENT,
                            target = slotTarget,
                            payloadBytes = 900,
                            success = tombOk
                        )
                    } catch (_: Exception) {}
                }
                acksFound++
            }
        }
        acksFound
    }

    /**
     * Processes Piggybacked ACKs: when an incoming frame has last_received_seq > 0,
     * any outgoing messages with seqNum < last_received_seq are marked as DELIVERED,
     * their cyclic republish tasks are unregistered, and tombstones emitted.
     */
    suspend fun processPiggybackedAck(contactId: String, lastReceivedSeq: Int) = withContext(Dispatchers.IO) {
        if (lastReceivedSeq <= 0) return@withContext
        val pending = messageDao.getPendingDeliveryMessagesForContact(contactId)
        val isSelf = contactId == SELF_CONTACT_ID
        for (msg in pending) {
            if (msg.seqNum < lastReceivedSeq) {
                messageDao.updateStatus(msg.id, "DELIVERED")
                org.pqchat.dht.service.DhtWorker.unregisterRepublishTask(msg.id)
                onRepublishTaskUpdated?.invoke()

                val slotTarget = msg.slotTarget
                if (slotTarget != null) {
                    researchTelemetry?.recordDeliveryAck(slotTarget)
                }

                val slotEdSeed = msg.slotEdSeed?.raw
                if (slotTarget != null && slotEdSeed != null) {
                    try {
                        val tombOk = dhtLeafNode.putMutable(
                            target = slotTarget,
                            v = org.pqchat.dht.crypto.BinaryFrameCodec.createTombstonePayload(),
                            seq = DhtClient.DEFAULT_MUTABLE_SEQ + 1,
                            salt = null,
                            sk = slotEdSeed,
                            skipLocalStore = isSelf
                        )
                        researchTelemetry?.recordPacketEvent(
                            role = org.pqchat.dht.research.PacketRole.TOMBSTONE_SENT,
                            target = slotTarget,
                            payloadBytes = 900,
                            success = tombOk
                        )
                    } catch (_: Exception) {}
                }
            }
        }
    }

    /**
     * Starts an active coroutine loop for periodically republishing a message until
     * its task is unregistered (e.g. upon detecting ACK) or max retries/TTL are reached.
     */
    fun startRepublishLoopForMessage(
        task: org.pqchat.dht.traffic.PollingWorker.RepublishTask,
        policy: org.pqchat.dht.traffic.RepublishPolicy? = null
    ): Job {
        org.pqchat.dht.service.DhtWorker.registerRepublishTask(task)
        onRepublishTaskUpdated?.invoke()
        return repositoryScope.launch {
            while (isActive && org.pqchat.dht.service.DhtWorker.isRepublishTaskRegistered(task.messageId)) {
                val effectivePolicy = policy ?: org.pqchat.dht.traffic.RepublishPolicy()
                val now = System.currentTimeMillis()
                val age = (now - task.initialSentTimestamp).coerceAtLeast(0L)
                if (effectivePolicy.isExpired(age)) {
                    markMessageExpiredOffline(task.messageId)
                    break
                }

                val interval = if (policy != null) {
                    effectivePolicy.getIntervalForAge(age)
                } else {
                    task.intervalMs
                }
                delay(interval)
                if (!isActive || !org.pqchat.dht.service.DhtWorker.isRepublishTaskRegistered(task.messageId)) break

                val republishNow = System.currentTimeMillis()
                val republishAge = (republishNow - task.initialSentTimestamp).coerceAtLeast(0L)
                if (effectivePolicy.isExpired(republishAge)) {
                    markMessageExpiredOffline(task.messageId)
                    break
                }

                dhtLeafNode.putMutable(
                    target = task.target,
                    v = task.payload,
                    seq = task.seq,
                    salt = null,
                    sk = task.edPrivateKeySeed
                )
                task.lastRepublishedTimestamp = republishNow
                task.currentAttempts++
                if (task.currentAttempts >= task.maxRetries) {
                    org.pqchat.dht.service.DhtWorker.unregisterRepublishTask(task.messageId)
                    onRepublishTaskUpdated?.invoke()
                    break
                }
            }
        }
    }

    private fun preWarmNextIncomingTarget(chainKeyIn: ByteArray, counterIn: Int) {
        val nextTarget = RatchetChain.getNextExpectedTarget(chainKeyIn, counterIn)
        dhtLeafNode.preWarmTargetAsync(nextTarget)
        val nextSlot = RatchetChain.deriveSlot(chainKeyIn, counterIn)
        val chunk0Target = ChunkingEngine.deriveChunkTarget(nextSlot.edPrivateKeySeed, 0)
        dhtLeafNode.preWarmTargetAsync(chunk0Target)
    }

    private sealed interface PollTask {
        val target: ByteArray
        val isSelf: Boolean
        val seqNum: Long
        val entityId: String
        val isFocused: Boolean
        val priorityWeight: Double
        suspend fun execute(item: DhtLeafNode.MutableItem?): Boolean
    }

    private inner class DecoyPollTask(
        override val target: ByteArray
    ) : PollTask {
        override val isSelf: Boolean = true
        override val seqNum: Long = 0L
        override val entityId: String = "decoy"
        override val isFocused: Boolean = false
        override val priorityWeight: Double = 1.0
        override suspend fun execute(item: DhtLeafNode.MutableItem?): Boolean {
            if (item != null) {
                harvestUndecryptableItem(target, item)
            }
            return false
        }
    }

    private inner class ContactSlotPollTask(
        override val target: ByteArray,
        val contactId: String,
        val slot: RatchetChain.SlotParameters,
        override val isSelf: Boolean,
        override val seqNum: Long,
        override val isFocused: Boolean = false,
        val lookaheadDistance: Int = 0
    ) : PollTask {
        override val entityId: String get() = contactId
        override val priorityWeight: Double
            get() = if (lookaheadDistance == 0) 10.0 else 10.0 / (1.0 + lookaheadDistance)

        override suspend fun execute(item: DhtLeafNode.MutableItem?): Boolean {
            if (item == null) return false
            return getContactMutex(contactId).withLock {
                val contact = contactDao.getContactById(contactId) ?: return@withLock false
                if (slot.counter > contact.counterIn) {
                    val intermediateSlots = RatchetChain.computeLookaheadSlots(
                        startChainKey = contact.chainKeyIn,
                        startCounter = contact.counterIn,
                        windowSize = slot.counter - contact.counterIn
                    )
                    for (interSlot in intermediateSlots) {
                        if (interSlot.counter < slot.counter) {
                            val bitmap = SlidingWindowBitmap(contact.receivedBitmapBase, 1024, contact.receivedBitmap)
                            if (!bitmap.isReceived(interSlot.counter)) {
                                if (skippedKeyDao != null) {
                                    val count = skippedKeyDao.countSkippedKeys(contactId)
                                    if (count >= MAX_SKIPPED_KEYS_PER_CONTACT) {
                                        skippedKeyDao.deleteOldestSkippedKeys(contactId, count - MAX_SKIPPED_KEYS_PER_CONTACT + 1)
                                    }
                                    skippedKeyDao.insertOrUpdate(
                                        SkippedKeyEntity(
                                            contactId = contactId,
                                            slotIndex = interSlot.counter,
                                            msgKey = interSlot.msgKey,
                                            target = interSlot.target,
                                            edPrivateKeySeed = interSlot.edPrivateKeySeed
                                        )
                                    )
                                }
                            }
                        }
                    }
                }
                val processed = processIncomingItem(contactId, slot, item, isSelf)
                if (!processed) {
                    harvestUndecryptableItem(slot.target, item)
                    false
                } else {
                    drainOutboxInternal(contactId, force = true)
                    triggerLookaheadWindowAsync(contactId)
                    true
                }
            }
        }
    }

    private inner class SkippedKeyPollTask(
        override val target: ByteArray,
        val contactId: String,
        val skippedKey: SkippedKeyEntity,
        override val isSelf: Boolean,
        override val seqNum: Long,
        override val isFocused: Boolean = false
    ) : PollTask {
        override val entityId: String get() = contactId
        override val priorityWeight: Double = 12.0

        override suspend fun execute(item: DhtLeafNode.MutableItem?): Boolean {
            if (item == null) return false
            return getContactMutex(contactId).withLock {
                try {
                    val contact = contactDao.getContactById(contactId) ?: return@withLock false
                    val frameMsg = BinaryFrameCodec.unpackAeadFrame(
                        key = skippedKey.rawMsgKey,
                        frame = item.v,
                        target = skippedKey.target,
                        direction = contact.inboundDirection
                    )
                    val bitmap = SlidingWindowBitmap(contact.receivedBitmapBase, 1024, contact.receivedBitmap)
                    when (frameMsg.msgType) {
                        BinaryFrameCodec.TYPE_TEXT_MESSAGE -> {
                            val textPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.TextMessage
                            val seqEpoch = skippedKey.slotIndex / 65536
                            if (!messageDao.existsMessageWithEpoch(contactId, seqEpoch, skippedKey.slotIndex, false)) {
                                messageDao.insertMessage(
                                    MessageEntity(
                                        contactId = contactId,
                                        isOutgoing = false,
                                        seqEpoch = seqEpoch,
                                        seqNum = skippedKey.slotIndex,
                                        ackNum = frameMsg.ackNum,
                                        timestamp = frameMsg.timestampUTC,
                                        textContent = textPayload.text,
                                        status = "DELIVERED"
                                    )
                                )
                                onIncomingMessageDelivered?.invoke(contactId, textPayload.text, false)
                            }
                            bitmap.markReceived(skippedKey.slotIndex)
                            contactDao.updateIncomingStateWithBitmap(
                                id = contactId,
                                counterIn = contact.counterIn,
                                chainKeyIn = contact.chainKeyIn,
                                bitmapBase = bitmap.windowBase,
                                bitmap = bitmap.toByteArray()
                            )
                            skippedKey.destroy()
                            skippedKeyDao?.deleteSkippedKey(contactId, skippedKey.slotIndex)
                            true
                        }
                        BinaryFrameCodec.TYPE_REACTION -> {
                            val reactionPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.Reaction
                            messageDao.updateMessageReaction(contactId, reactionPayload.targetSeqEpoch, reactionPayload.targetSeqNum, true, reactionPayload.emoji)
                            messageDao.updateMessageReactionAnyDirection(contactId, reactionPayload.targetSeqEpoch, reactionPayload.targetSeqNum, reactionPayload.emoji)
                            bitmap.markReceived(skippedKey.slotIndex)
                            contactDao.updateIncomingStateWithBitmap(
                                id = contactId,
                                counterIn = contact.counterIn,
                                chainKeyIn = contact.chainKeyIn,
                                bitmapBase = bitmap.windowBase,
                                bitmap = bitmap.toByteArray()
                            )
                            skippedKey.destroy()
                            skippedKeyDao?.deleteSkippedKey(contactId, skippedKey.slotIndex)
                            true
                        }
                        BinaryFrameCodec.TYPE_LOCATION_PIN -> {
                            val locPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.LocationPin
                            val seqEpoch = skippedKey.slotIndex / 65536
                            if (!messageDao.existsMessageWithEpoch(contactId, seqEpoch, skippedKey.slotIndex, false)) {
                                val locText = org.pqchat.dht.protocol.LocationPinData(
                                    locPayload.latitude,
                                    locPayload.longitude,
                                    locPayload.altitude,
                                    locPayload.accuracy,
                                    locPayload.note
                               ).toPayloadText()
                                messageDao.insertMessage(
                                    MessageEntity(
                                        contactId = contactId,
                                        isOutgoing = false,
                                        seqEpoch = seqEpoch,
                                        seqNum = skippedKey.slotIndex,
                                        ackNum = frameMsg.ackNum,
                                        timestamp = frameMsg.timestampUTC,
                                        textContent = locText,
                                        status = "DELIVERED"
                                    )
                                )
                                onIncomingMessageDelivered?.invoke(contactId, locText, false)
                            }
                            bitmap.markReceived(skippedKey.slotIndex)
                            contactDao.updateIncomingStateWithBitmap(
                                id = contactId,
                                counterIn = contact.counterIn,
                                chainKeyIn = contact.chainKeyIn,
                                bitmapBase = bitmap.windowBase,
                                bitmap = bitmap.toByteArray()
                            )
                            skippedKey.destroy()
                            skippedKeyDao?.deleteSkippedKey(contactId, skippedKey.slotIndex)
                            true
                        }
                        BinaryFrameCodec.TYPE_VOICE_NOTE -> {
                            val voicePayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.VoiceNote
                            val assembled = voiceSegmentAssembler.ingest(voicePayload)
                            if (assembled != null) {
                                val seqEpoch = skippedKey.slotIndex / 65536
                                if (!messageDao.existsMessageWithEpoch(contactId, seqEpoch, skippedKey.slotIndex, false)) {
                                    messageDao.insertMessage(
                                        MessageEntity(
                                            contactId = contactId,
                                            isOutgoing = false,
                                            seqEpoch = seqEpoch,
                                            seqNum = skippedKey.slotIndex,
                                            ackNum = frameMsg.ackNum,
                                            timestamp = frameMsg.timestampUTC,
                                            voiceBytes = assembled.voiceBytes,
                                            voiceDurationMs = assembled.totalDurationMs,
                                            status = "DELIVERED"
                                        )
                                    )
                                    onIncomingMessageDelivered?.invoke(contactId, "Voice Note (${assembled.totalDurationMs / 1000}s)", false)
                                }
                            }
                            bitmap.markReceived(skippedKey.slotIndex)
                            contactDao.updateIncomingStateWithBitmap(
                                id = contactId,
                                counterIn = contact.counterIn,
                                chainKeyIn = contact.chainKeyIn,
                                bitmapBase = bitmap.windowBase,
                                bitmap = bitmap.toByteArray()
                            )
                            skippedKey.destroy()
                            skippedKeyDao?.deleteSkippedKey(contactId, skippedKey.slotIndex)
                            true
                        }
                        else -> {
                            harvestUndecryptableItem(skippedKey.target, item)
                            false
                        }
                    }
                } catch (_: Exception) {
                    harvestUndecryptableItem(skippedKey.target, item)
                    false
                }
            }
        }
    }

    private inner class GroupMemberSlotPollTask(
        override val target: ByteArray,
        val groupId: String,
        val member: GroupMemberEntity,
        val slot: RatchetChain.SlotParameters,
        val baseSlot: RatchetChain.SlotParameters,
        val isIndividualSlot: Boolean,
        val groupIdBytes: ByteArray,
        val memberIdBytes: ByteArray,
        override val seqNum: Long,
        override val isFocused: Boolean = false,
        val lookaheadDistance: Int = 0
    ) : PollTask {
        override val isSelf: Boolean = false
        override val entityId: String get() = groupId
        override val priorityWeight: Double
            get() = if (lookaheadDistance == 0) 10.0 else 10.0 / (1.0 + lookaheadDistance)

        override suspend fun execute(item: DhtLeafNode.MutableItem?): Boolean {
            if (item == null) return false
            return getGroupMutex(groupId).withLock {
                try {
                    val frameMsg = BinaryFrameCodec.unpackGroupAeadFrame(
                        key = slot.msgKey,
                        frame = item.v,
                        target = slot.target,
                        groupId = groupIdBytes,
                        senderMemberId = memberIdBytes
                    )
                    val bitmap = SlidingWindowBitmap(member.receivedBitmapBase, 1024, member.receivedBitmap)
                    if (!bitmap.isReceived(slot.counter)) {
                        bitmap.markReceived(slot.counter)
                        if (frameMsg.msgType == BinaryFrameCodec.TYPE_TEXT_MESSAGE) {
                            val textPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.TextMessage
                            val seqEpoch = slot.counter / 65536
                            if (!messageDao.existsMessageWithEpoch(groupId, seqEpoch, slot.counter, false)) {
                                messageDao.insertMessage(
                                    MessageEntity(
                                        contactId = groupId,
                                        isOutgoing = false,
                                        seqEpoch = seqEpoch,
                                        seqNum = slot.counter,
                                        ackNum = frameMsg.ackNum,
                                        timestamp = frameMsg.timestampUTC,
                                        textContent = textPayload.text,
                                        status = "DELIVERED",
                                        slotTarget = slot.target,
                                        slotEdSeed = slot.edPrivateKeySeed,
                                        senderMemberId = member.memberId,
                                        senderName = member.rawMemberName,
                                        ephemeralTtlSeconds = textPayload.ephemeralTtlSeconds,
                                        expiresAtTimestamp = null
                                    )
                                )
                                onIncomingMessageDelivered?.invoke(groupId, textPayload.text, false)
                            }
                        } else if (frameMsg.msgType == BinaryFrameCodec.TYPE_REACTION) {
                            val reactionPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.Reaction
                            messageDao.updateMessageReactionAnyDirection(groupId, reactionPayload.targetSeqEpoch, reactionPayload.targetSeqNum, reactionPayload.emoji)
                        } else if (frameMsg.msgType == BinaryFrameCodec.TYPE_LOCATION_PIN) {
                            val locPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.LocationPin
                            val seqEpoch = slot.counter / 65536
                            if (!messageDao.existsMessageWithEpoch(groupId, seqEpoch, slot.counter, false)) {
                                val locText = org.pqchat.dht.protocol.LocationPinData(
                                    locPayload.latitude,
                                    locPayload.longitude,
                                    locPayload.altitude,
                                    locPayload.accuracy,
                                    locPayload.note
                                ).toPayloadText()
                                messageDao.insertMessage(
                                    MessageEntity(
                                        contactId = groupId,
                                        isOutgoing = false,
                                        seqEpoch = seqEpoch,
                                        seqNum = slot.counter,
                                        ackNum = frameMsg.ackNum,
                                        timestamp = frameMsg.timestampUTC,
                                        textContent = locText,
                                        status = "DELIVERED",
                                        slotTarget = slot.target,
                                        slotEdSeed = slot.edPrivateKeySeed,
                                        senderMemberId = member.memberId,
                                        senderName = member.rawMemberName,
                                        ephemeralTtlSeconds = locPayload.ephemeralTtlSeconds,
                                        expiresAtTimestamp = null
                                    )
                                )
                                onIncomingMessageDelivered?.invoke(groupId, locText, false)
                            }
                        } else if (frameMsg.msgType == BinaryFrameCodec.TYPE_VOICE_NOTE) {
                            val voicePayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.VoiceNote
                            val assembled = voiceSegmentAssembler.ingest(voicePayload)
                            if (assembled != null) {
                                val seqEpoch = slot.counter / 65536
                                if (!messageDao.existsMessageWithEpoch(groupId, seqEpoch, slot.counter, false)) {
                                    messageDao.insertMessage(
                                        MessageEntity(
                                            contactId = groupId,
                                            isOutgoing = false,
                                            seqEpoch = seqEpoch,
                                            seqNum = slot.counter,
                                            ackNum = frameMsg.ackNum,
                                            timestamp = frameMsg.timestampUTC,
                                            voiceBytes = assembled.voiceBytes,
                                            voiceDurationMs = assembled.totalDurationMs,
                                            status = "DELIVERED",
                                            slotTarget = slot.target,
                                            slotEdSeed = slot.edPrivateKeySeed,
                                            senderMemberId = member.memberId,
                                            senderName = member.rawMemberName,
                                            ephemeralTtlSeconds = assembled.ephemeralTtlSeconds,
                                            expiresAtTimestamp = null
                                        )
                                    )
                                    onIncomingMessageDelivered?.invoke(groupId, "Voice Note (${assembled.totalDurationMs / 1000}s)", false)
                                }
                            }
                        }
                    }

                    if (slot.counter == member.counterIn) {
                        groupMemberDao?.updateMemberIncomingStateWithBitmap(
                            groupId = groupId,
                            memberId = member.memberId,
                            counterIn = slot.counter + 1,
                            chainKeyIn = EncryptedBlob(baseSlot.nextChainKey, "group_members", "${groupId}_${member.memberId}", "chainKeyIn"),
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                    } else {
                        groupMemberDao?.updateMemberIncomingStateWithBitmap(
                            groupId = groupId,
                            memberId = member.memberId,
                            counterIn = member.counterIn,
                            chainKeyIn = member.chainKeyIn,
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )
                    }

                    if (isIndividualSlot) {
                        try {
                            dhtLeafNode.putMutable(
                                target = slot.target,
                                v = BinaryFrameCodec.createTombstonePayload(),
                                seq = item.seq + 1,
                                salt = null,
                                sk = slot.edPrivateKeySeed,
                                skipLocalStore = false
                            )
                        } catch (_: Exception) {}
                    }
                    true
                } catch (_: Exception) {
                    harvestUndecryptableItem(slot.target, item)
                    false
                }
            }
        }
    }

    private inner class PendingAckPollTask(
        override val target: ByteArray,
        val messageId: Long,
        val contactId: String,
        val ratchetKey: ByteArray,
        val seqNumInt: Int,
        val slotTarget: ByteArray?,
        val slotEdSeed: ByteArray?,
        override val isSelf: Boolean,
        override val isFocused: Boolean = false
    ) : PollTask {
        override val entityId: String get() = contactId
        override val seqNum: Long = seqNumInt.toLong()
        override val priorityWeight: Double = 8.0

        override suspend fun execute(item: DhtLeafNode.MutableItem?): Boolean {
            if (item == null) return false
            val isValid = org.pqchat.dht.protocol.CoverAckProtocol.verifyAckPayload(
                ratchetKey = ratchetKey,
                frame = item.v,
                expectedMessageId = "$seqNumInt",
                expectedSeqNum = seqNumInt
            )
            if (isValid) {
                messageDao.updateStatus(messageId, "DELIVERED")
                PollingWorker.unregisterRepublishTask(messageId)
                onRepublishTaskUpdated?.invoke()
                if (slotTarget != null) {
                    researchTelemetry?.recordDeliveryAck(slotTarget)
                    if (slotEdSeed != null) {
                        try {
                            dhtLeafNode.putMutable(
                                target = slotTarget,
                                v = BinaryFrameCodec.createTombstonePayload(),
                                seq = DhtClient.DEFAULT_MUTABLE_SEQ + 1,
                                salt = null,
                                sk = slotEdSeed,
                                skipLocalStore = isSelf
                            )
                        } catch (_: Exception) {}
                    }
                }
                return true
            }
            return false
        }
    }

    private inner class PendingGroupControlAckPollTask(
        override val target: ByteArray,
        val record: PendingGroupControlRecord,
        override val isFocused: Boolean = false
    ) : PollTask {
        override val entityId: String get() = record.contactId
        override val isSelf: Boolean = record.contactId == SELF_CONTACT_ID
        override val seqNum: Long = record.seqNum.toLong()
        override val priorityWeight: Double = 8.0

        override suspend fun execute(item: DhtLeafNode.MutableItem?): Boolean {
            if (item == null) return false
            val isValid = org.pqchat.dht.protocol.CoverAckProtocol.verifyAckPayload(
                ratchetKey = record.ackRatchetKey,
                frame = item.v,
                expectedMessageId = "${record.seqNum}",
                expectedSeqNum = record.seqNum
            )
            if (isValid) {
                PollingWorker.unregisterRepublishTask(record.taskId)
                pendingGroupControls.remove(record.taskId)
                onRepublishTaskUpdated?.invoke()
                researchTelemetry?.recordDeliveryAck(record.slotTarget)
                try {
                    dhtLeafNode.putMutable(
                        target = record.slotTarget,
                        v = BinaryFrameCodec.createTombstonePayload(),
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ + 1,
                        salt = null,
                        sk = record.slotEdSeed,
                        skipLocalStore = isSelf
                    )
                } catch (_: Exception) {}
                return true
            }
            return false
        }
    }

    /**
     * Weighted Fair Stratified Sampling without replacement:
     * - Partitions candidate active listening slots into focus stratum (if focusContactId != null)
     *   and background stratum (other contacts/groups).
     * - Damps entity dominance with sub-linear fairness factor: weight / sqrt(entityCount), ensuring
     *   large 50-person groups do not starve 1-on-1 contacts.
     * - Samples slots without replacement using Efraimidis-Spirakis exponential key sampling.
     */
    private fun sampleWeightedFairStratified(
        candidateTasks: List<PollTask>,
        batchSize: Int,
        focusContactId: String?
    ): List<PollTask> {
        if (candidateTasks.isEmpty() || batchSize <= 0) return emptyList()

        // 1. Deduplicate by target byte equality (keep highest priorityWeight)
        val uniqueByTarget = LinkedHashMap<String, PollTask>()
        for (task in candidateTasks) {
            val hex = CryptoUtils.toHex(task.target)
            val existing = uniqueByTarget[hex]
            if (existing == null || task.priorityWeight > existing.priorityWeight) {
                uniqueByTarget[hex] = task
            }
        }
        val candidates = uniqueByTarget.values.toList()

        if (candidates.size <= batchSize) {
            return candidates
        }

        // Weighted sampling without replacement using Efraimidis-Spirakis algorithm
        // with sublinear entity fairness damping: w_eff = priorityWeight / sqrt(entityCandidateCount)
        fun sampleWithoutReplacement(pool: List<PollTask>, k: Int): List<PollTask> {
            if (pool.size <= k) return pool
            if (k <= 0) return emptyList()

            val entityCounts = pool.groupingBy { it.entityId }.eachCount()
            val scored = pool.map { task ->
                val entityCount = entityCounts[task.entityId] ?: 1
                val fairnessDamping = Math.sqrt(entityCount.toDouble()).coerceAtLeast(1.0)
                val effectiveWeight = (task.priorityWeight / fairnessDamping).coerceAtLeast(1e-4)

                val u = CryptoUtils.secureRandom.nextDouble().coerceIn(1e-12, 1.0 - 1e-12)
                val key = Math.pow(u, 1.0 / effectiveWeight)
                Pair(task, key)
            }

            return scored.sortedByDescending { it.second }.take(k).map { it.first }
        }

        if (focusContactId != null) {
            val focusedPool = candidates.filter { it.isFocused }
            val backgroundPool = candidates.filter { !it.isFocused }

            if (focusedPool.isNotEmpty() && backgroundPool.isNotEmpty()) {
                val bgQuotaDesired = minOf(backgroundPool.size, maxOf(1, batchSize / 4))
                val focusQuota = minOf(focusedPool.size, batchSize - bgQuotaDesired)
                val bgQuota = batchSize - focusQuota

                // In focused pool, guarantee current in-sequence slot (k=0) if it exists
                val focusedCurrent = focusedPool.filter {
                    (it is ContactSlotPollTask && it.lookaheadDistance == 0) ||
                    (it is SkippedKeyPollTask)
                }
                val result = mutableListOf<PollTask>()
                if (focusedCurrent.isNotEmpty() && focusQuota > 0) {
                    val guaranteed = focusedCurrent.take(focusQuota)
                    result.addAll(guaranteed)
                    val remainingFocusPool = focusedPool.filter { t -> guaranteed.none { it.target.contentEquals(t.target) } }
                    val remainingFocusQuota = focusQuota - guaranteed.size
                    if (remainingFocusQuota > 0 && remainingFocusPool.isNotEmpty()) {
                        result.addAll(sampleWithoutReplacement(remainingFocusPool, remainingFocusQuota))
                    }
                } else {
                    result.addAll(sampleWithoutReplacement(focusedPool, focusQuota))
                }

                result.addAll(sampleWithoutReplacement(backgroundPool, bgQuota))
                return result.take(batchSize)
            } else if (focusedPool.isNotEmpty()) {
                val focusedCurrent = focusedPool.filter {
                    (it is ContactSlotPollTask && it.lookaheadDistance == 0) ||
                    (it is SkippedKeyPollTask)
                }
                val result = mutableListOf<PollTask>()
                if (focusedCurrent.isNotEmpty()) {
                    val guaranteed = focusedCurrent.take(batchSize)
                    result.addAll(guaranteed)
                    val remaining = focusedPool.filter { t -> guaranteed.none { it.target.contentEquals(t.target) } }
                    val remainingQuota = batchSize - guaranteed.size
                    if (remainingQuota > 0 && remaining.isNotEmpty()) {
                        result.addAll(sampleWithoutReplacement(remaining, remainingQuota))
                    }
                    return result.take(batchSize)
                } else {
                    return sampleWithoutReplacement(focusedPool, batchSize)
                }
            } else {
                return sampleWithoutReplacement(backgroundPool, batchSize)
            }
        } else {
            // General poll (APP_ACTIVE_OTHER, BACKGROUND_IDLE, DOZE_SLEEP):
            // Sample fairly across all candidate slots
            return sampleWithoutReplacement(candidates, batchSize)
        }
    }

    /**
     * Executes a Constant-Size Decoy-Padded Poll Batch:
     * - Generates a constant budget of [batchSize] (default N_POLL_TARGETS = 8) getMutable queries
     *   across all states (FOREGROUND_CHAT, APP_ACTIVE_OTHER, BACKGROUND_IDLE, DOZE_SLEEP).
     * - Gathers active listening slots across 1-on-1 contacts, active group members, lookahead windows,
     *   and pending ACKs.
     * - When active slots exceed [batchSize], applies Weighted Fair Stratified Sampling without replacement.
     * - Disguises focused contact/group queries within real/expiring decoy targets from [DecoyTargetPool]
     *   when active slots are fewer than [batchSize].
     * - Shuffles all targets in random permutation using CSPRNG.
     * - Applies intra-batch jitter between queries to prevent network observer timing/frequency correlation.
     */
    suspend fun pollConstantBatch(
        focusContactId: String? = null,
        batchSize: Int = pollBatchSize,
        intraBatchJitterMinMs: Long = this.intraBatchJitterMinMs,
        intraBatchJitterMaxMs: Long = this.intraBatchJitterMaxMs
    ): Boolean = withContext(Dispatchers.IO) {
        // 1. Assemble candidate real active listening slots
        val tasks = mutableListOf<PollTask>()

        // 1a. Gather 1-on-1 contact listening slots (current slot, lookahead window, skipped keys)
        val contacts = contactDao.getAllContactsFlow().firstOrNull() ?: emptyList()
        for (contact in contacts) {
            val isSelf = contact.id == SELF_CONTACT_ID
            val isFocusedContact = (contact.id == focusContactId)

            val skipped = skippedKeyDao?.getSkippedKeysForContact(contact.id) ?: emptyList()
            for (sk in skipped) {
                tasks.add(
                    SkippedKeyPollTask(
                        target = sk.target,
                        contactId = contact.id,
                        skippedKey = sk,
                        isSelf = isSelf,
                        seqNum = sk.slotIndex.toLong(),
                        isFocused = isFocusedContact
                    )
                )
            }

            val currentSlot = RatchetChain.deriveSlot(contact.chainKeyIn, contact.counterIn)
            tasks.add(
                ContactSlotPollTask(
                    target = currentSlot.target,
                    contactId = contact.id,
                    slot = currentSlot,
                    isSelf = isSelf,
                    seqNum = contact.counterIn.toLong(),
                    isFocused = isFocusedContact,
                    lookaheadDistance = 0
                )
            )

            if (pollLookaheadWindowSize > 0) {
                val laSlots = RatchetChain.computeLookaheadSlots(
                    startChainKey = contact.chainKeyIn,
                    startCounter = contact.counterIn,
                    windowSize = pollLookaheadWindowSize
                )
                for (k in 1 until laSlots.size) {
                    val laSlot = laSlots[k]
                    tasks.add(
                        ContactSlotPollTask(
                            target = laSlot.target,
                            contactId = contact.id,
                            slot = laSlot,
                            isSelf = isSelf,
                            seqNum = laSlot.counter.toLong(),
                            isFocused = isFocusedContact,
                            lookaheadDistance = k
                        )
                    )
                }
            }
        }

        // 1b. Gather group member active listening slots (current slot, lookahead window)
        val groups = groupDao?.getAllActiveGroups() ?: emptyList()
        for (group in groups) {
            val isFocusedGroup = (group.groupId == focusContactId)
            val members = groupMemberDao?.getMembersForGroup(group.groupId) ?: emptyList()
            val groupIdBytes = uuidStringToBytes(group.groupId)
            val myMemberIdBytes = uuidStringToBytes(group.myMemberId)

            for (member in members) {
                if (member.memberId == group.myMemberId) continue
                if (member.rawChainKeyIn.all { it == 0.toByte() }) continue

                val memberIdBytes = uuidStringToBytes(member.memberId)
                val baseSlot = RatchetChain.deriveSlot(member.rawChainKeyIn, member.counterIn)
                val individualSlot = RatchetChain.deriveGroupRecipientSlot(
                    chainKey = member.rawChainKeyIn,
                    counter = member.counterIn,
                    groupId = groupIdBytes,
                    senderMemberId = memberIdBytes,
                    recipientMemberId = myMemberIdBytes
                )

                tasks.add(
                    GroupMemberSlotPollTask(
                        target = individualSlot.target,
                        groupId = group.groupId,
                        member = member,
                        slot = individualSlot,
                        baseSlot = baseSlot,
                        isIndividualSlot = true,
                        groupIdBytes = groupIdBytes,
                        memberIdBytes = memberIdBytes,
                        seqNum = member.counterIn.toLong(),
                        isFocused = isFocusedGroup,
                        lookaheadDistance = 0
                    )
                )

                if (pollLookaheadWindowSize > 0) {
                    val groupLaSlots = RatchetChain.computeGroupLookaheadSlots(
                        startChainKey = member.rawChainKeyIn,
                        startCounter = member.counterIn,
                        groupId = groupIdBytes,
                        senderMemberId = memberIdBytes,
                        recipientMemberId = myMemberIdBytes,
                        windowSize = pollLookaheadWindowSize
                    )
                    for (k in 1 until groupLaSlots.size) {
                        val laSlot = groupLaSlots[k]
                        tasks.add(
                            GroupMemberSlotPollTask(
                                target = laSlot.target,
                                groupId = group.groupId,
                                member = member,
                                slot = laSlot,
                                baseSlot = laSlot,
                                isIndividualSlot = true,
                                groupIdBytes = groupIdBytes,
                                memberIdBytes = memberIdBytes,
                                seqNum = laSlot.counter.toLong(),
                                isFocused = isFocusedGroup,
                                lookaheadDistance = k
                            )
                        )
                    }
                }
            }
        }

        // 1c. Gather pending ACK slots (1-on-1 delivery ACKs and group control ACKs)
        val pendingMsgs = if (focusContactId != null) {
            messageDao.getPendingDeliveryMessagesForContact(focusContactId)
        } else {
            messageDao.getAllPendingDeliveryMessages()
        }
        for (msg in pendingMsgs) {
            val targetAck = msg.ackTarget ?: continue
            val ratchetKey = msg.ackRatchetKey?.raw ?: continue
            tasks.add(
                PendingAckPollTask(
                    target = targetAck,
                    messageId = msg.id,
                    contactId = msg.contactId,
                    ratchetKey = ratchetKey,
                    seqNumInt = msg.seqNum,
                    slotTarget = msg.slotTarget,
                    slotEdSeed = msg.slotEdSeed?.raw,
                    isSelf = msg.contactId == SELF_CONTACT_ID,
                    isFocused = msg.contactId == focusContactId
                )
            )
        }

        val controlRecords = if (focusContactId != null) {
            pendingGroupControls.values.filter { it.contactId == focusContactId }
        } else {
            pendingGroupControls.values.toList()
        }
        for (rec in controlRecords) {
            tasks.add(
                PendingGroupControlAckPollTask(
                    target = rec.targetAck,
                    record = rec,
                    isFocused = rec.contactId == focusContactId
                )
            )
        }

        // 2. Apply Weighted Fair Stratified Sampling without replacement
        val sampledTasks = sampleWeightedFairStratified(tasks, batchSize, focusContactId).toMutableList()

        // 3. Constant budget adjustment: pad with DecoyTargetPool queries if fewer than batchSize
        val countNeeded = batchSize - sampledTasks.size
        if (countNeeded > 0) {
            val decoyTargets = decoyTargetPool.getDecoyTargets(countNeeded) {
                runBlocking { collectExpiringAndPastTargets(focusContactId) }
            }.toMutableList()

            while (decoyTargets.size < countNeeded) {
                decoyTargets.add(CryptoUtils.sha1(CryptoUtils.secureRandomBytes(32)))
            }

            for (target in decoyTargets.take(countNeeded)) {
                sampledTasks.add(DecoyPollTask(target))
            }
        }

        // 4. Random permutation: Fisher-Yates shuffle with CSPRNG
        val finalTasks = sampledTasks.take(batchSize).shuffled(CryptoUtils.secureRandom)

        // 5. Execute batch sequentially with intra-batch jitter
        var anyReceived = false
        for (i in finalTasks.indices) {
            val task = finalTasks[i]
            try {
                val tStart = System.currentTimeMillis()
                val item = dhtLeafNode.getMutable(task.target, skipLocalStore = task.isSelf)
                val rttMs = System.currentTimeMillis() - tStart
                if (item != null) {
                    researchTelemetry?.recordPacketEvent(
                        role = org.pqchat.dht.research.PacketRole.PACKET_RECEIVED,
                        target = task.target,
                        seqNum = task.seqNum,
                        payloadBytes = item.v.size,
                        rttMs = rttMs,
                        nodesQueried = item.nodesQueried.takeIf { it > 0 } ?: dhtLeafNode.lastNodesQueried,
                        nodesResponded = item.nodesResponded.takeIf { it > 0 } ?: dhtLeafNode.lastNodesResponded,
                        lookupHops = item.lookupHops.takeIf { it > 0 } ?: dhtLeafNode.lastLookupHops,
                        success = true
                    )
                }
                if (task.execute(item)) {
                    anyReceived = true
                }
            } catch (_: Exception) {}

            // Apply intra-batch jitter between queries
            if (i < finalTasks.size - 1 && intraBatchJitterMaxMs > 0L) {
                val span = (intraBatchJitterMaxMs - intraBatchJitterMinMs).coerceAtLeast(1L)
                val jitter = intraBatchJitterMinMs + (CryptoUtils.secureRandom.nextDouble() * span).toLong()
                if (jitter > 0L) {
                    delay(jitter)
                }
            }
        }

        anyReceived
    }

    /**
     * Polls DHT concurrently for all known contacts using coroutineScope and async/awaitAll.
     */
    suspend fun pollAllContactsIncoming(): List<Boolean> = coroutineScope {
        checkPendingAcks(null)
        val contacts = contactDao.getAllContactsFlow().firstOrNull() ?: emptyList()
        if (contacts.isEmpty()) {
            executeDecoyGets(null)
            return@coroutineScope emptyList()
        }
        contacts.map { contact ->
            async {
                pollContactIncoming(contact.id)
            }
        }.awaitAll()
    }

    /**
     * Polls DHT concurrently for specified contacts using coroutineScope and async/awaitAll.
     */
    suspend fun pollContactsIncoming(contactIds: List<String>): List<Boolean> = coroutineScope {
        contactIds.forEach { checkPendingAcks(it) }
        contactIds.map { contactId ->
            async {
                pollContactIncoming(contactId)
            }
        }.awaitAll()
    }

    /**
     * Pre-warms in the background the next expected incoming targets for all known contacts concurrently.
     */
    suspend fun preWarmAllContactsNextTargets() = coroutineScope {
        val contacts = contactDao.getAllContactsFlow().firstOrNull() ?: emptyList()
        contacts.map { contact ->
            async {
                val nextTarget = RatchetChain.getNextExpectedTarget(contact.chainKeyIn, contact.counterIn)
                dhtLeafNode.preWarmTarget(nextTarget)
            }
        }.awaitAll()
    }

    /**
     * Pre-warms in the background the next expected incoming target for a specific contact.
     */
    suspend fun preWarmContactNextTarget(contactId: String) = withContext(Dispatchers.IO) {
        val contact = contactDao.getContactById(contactId) ?: return@withContext
        val nextTarget = RatchetChain.getNextExpectedTarget(contact.chainKeyIn, contact.counterIn)
        dhtLeafNode.preWarmTarget(nextTarget)
    }

    /**
     * Resends an unacknowledged or expired message (status "EXPIRED_OFFLINE" / "EXPIRED_DHT" / "QUEUED").
     * Advances the contact's outgoing chain state to allocate a new cryptographic slot (Target_i)
     * and publishes the re-encrypted payload to DHT.
     */
    suspend fun resendMessage(messageId: Long): Boolean = withContext(Dispatchers.IO) {
        val msg = messageDao.getMessageById(messageId) ?: return@withContext false
        if (!msg.isOutgoing) return@withContext false
        if (msg.status != "EXPIRED_OFFLINE" && msg.status != "EXPIRED_DHT" && msg.status != "QUEUED" && msg.status != "QUEUED_POISSON" && msg.status != "FAILED") {
            return@withContext false
        }
        getContactMutex(msg.contactId).withLock {
            val contact = contactDao.getContactById(msg.contactId) ?: return@withLock false
            val isSelf = msg.contactId == SELF_CONTACT_ID

            val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)
            val text = msg.textContent?.raw
            val image = msg.imageBytes?.raw

            val frame = if (text != null) {
                val plaintext = BinaryFrameCodec.encodeTextMessage(
                    seqNum = contact.counterOut and 0xFFFF,
                    ackNum = contact.counterIn and 0xFFFF,
                    timestampUTC = System.currentTimeMillis(),
                    text = text
                )
                BinaryFrameCodec.packAeadFrame(
                    key = slot.msgKey,
                    plaintext = plaintext,
                    target = slot.target,
                    direction = contact.outboundDirection
                )
            } else if (image != null) {
                val plaintext = BinaryFrameCodec.encodeChunkData(
                    seqNum = contact.counterOut and 0xFFFF,
                    ackNum = contact.counterIn and 0xFFFF,
                    timestampUTC = System.currentTimeMillis(),
                    transferId = CryptoUtils.secureRandomBytes(16),
                    chunkIndex = 0,
                    totalChunks = 1,
                    chunkData = image
                )
                BinaryFrameCodec.packAeadFrame(
                    key = slot.msgKey,
                    plaintext = plaintext,
                    target = slot.target,
                    direction = contact.outboundDirection
                )
            } else {
                return@withLock false
            }

            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot.msgKey, "${contact.counterOut}")

            if (isStrictPoissonShaping()) {
                messageDao.updateMessageRetry(
                    id = msg.id,
                    status = "QUEUED_POISSON",
                    retryCount = msg.retryCount + 1,
                    timestamp = System.currentTimeMillis()
                )
                contactDao.updateOutgoingState(
                    id = contact.id,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )
                outboundPoissonQueue.enqueue(
                    org.pqchat.dht.traffic.OutboundPoissonFrame(
                        target = slot.target,
                        payload = frame,
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = slot.edPrivateKeySeed,
                        skipLocalStore = isSelf,
                        seqNum = contact.counterOut,
                        messageId = msg.id,
                        contactId = msg.contactId,
                        onSent = { success ->
                            if (success) {
                                decoyTargetPool.registerPopulatedTarget(slot.target)
                                val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                                val newRowId = org.pqchat.dht.data.db.MessageEntity.computeMessageRowId(msg.contactId, msg.seqEpoch, contact.counterOut, msg.isOutgoing)
                                messageDao.updateMessageForResend(
                                    id = msg.id,
                                    status = newStatus,
                                    seqNum = contact.counterOut,
                                    ackNum = contact.counterIn,
                                    timestamp = System.currentTimeMillis(),
                                    slotTarget = slot.target,
                                    slotEdSeed = org.pqchat.dht.data.db.EncryptedBlob(
                                        slot.edPrivateKeySeed,
                                        "messages",
                                        newRowId,
                                        "slotEdSeed"
                                    ),
                                    ackTarget = targetAck,
                                    ackRatchetKey = org.pqchat.dht.data.db.EncryptedBlob(
                                        slot.msgKey,
                                        "messages",
                                        newRowId,
                                        "ackRatchetKey"
                                    ),
                                    retryCount = msg.retryCount + 1,
                                    textContent = text?.let { org.pqchat.dht.data.db.EncryptedText(it, "messages", newRowId, "textContent") },
                                    imageBytes = image?.let { org.pqchat.dht.data.db.EncryptedBlob(it, "messages", newRowId, "imageBytes") }
                                )
                                if (!isSelf) {
                                    PollingWorker.registerRepublishTask(
                                        PollingWorker.RepublishTask(
                                            messageId = msg.id,
                                            contactId = msg.contactId,
                                            target = slot.target,
                                            payload = frame,
                                            edPrivateKeySeed = slot.edPrivateKeySeed,
                                            initialSentTimestamp = System.currentTimeMillis()
                                        )
                                    )
                                    onRepublishTaskUpdated?.invoke()
                                }
                            } else {
                                messageDao.updateStatus(msg.id, "EXPIRED_DHT")
                            }
                        }
                    )
                )
                return@withLock true
            }

            messageDao.updateMessageRetry(
                id = msg.id,
                status = "SENDING",
                retryCount = msg.retryCount + 1,
                timestamp = System.currentTimeMillis()
            )

            val success = dhtLeafNode.putMutable(
                target = slot.target,
                v = frame,
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                salt = null,
                sk = slot.edPrivateKeySeed,
                skipLocalStore = isSelf
            )

            if (success) {
                decoyTargetPool.registerPopulatedTarget(slot.target)
                val newStatus = if (isSelf) "SENT_DHT" else "PENDING_DELIVERY"
                val newRowId = org.pqchat.dht.data.db.MessageEntity.computeMessageRowId(msg.contactId, msg.seqEpoch, contact.counterOut, msg.isOutgoing)
                messageDao.updateMessageForResend(
                    id = msg.id,
                    status = newStatus,
                    seqNum = contact.counterOut,
                    ackNum = contact.counterIn,
                    timestamp = System.currentTimeMillis(),
                    slotTarget = slot.target,
                    slotEdSeed = org.pqchat.dht.data.db.EncryptedBlob(
                        slot.edPrivateKeySeed,
                        "messages",
                        newRowId,
                        "slotEdSeed"
                    ),
                    ackTarget = targetAck,
                    ackRatchetKey = org.pqchat.dht.data.db.EncryptedBlob(
                        slot.msgKey,
                        "messages",
                        newRowId,
                        "ackRatchetKey"
                    ),
                    retryCount = msg.retryCount + 1,
                    textContent = text?.let { org.pqchat.dht.data.db.EncryptedText(it, "messages", newRowId, "textContent") },
                    imageBytes = image?.let { org.pqchat.dht.data.db.EncryptedBlob(it, "messages", newRowId, "imageBytes") }
                )

                if (!isSelf) {
                    PollingWorker.registerRepublishTask(
                        PollingWorker.RepublishTask(
                            messageId = msg.id,
                            contactId = msg.contactId,
                            target = slot.target,
                            payload = frame,
                            edPrivateKeySeed = slot.edPrivateKeySeed,
                            initialSentTimestamp = System.currentTimeMillis()
                        )
                    )
                    onRepublishTaskUpdated?.invoke()
                }

                contactDao.updateOutgoingState(
                    id = contact.id,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )
                true
            } else {
                messageDao.updateStatus(msg.id, "EXPIRED_DHT")
                false
            }
        }
    }

    // ==========================================
    // DECENTRALIZED GROUP CHAT (SENDER KEYS OVER BEP 44)
    // ==========================================

    suspend fun createGroup(
        groupName: String,
        invitedContactIds: List<String>
    ): GroupEntity = withContext(Dispatchers.IO) {
        val groupId = UUID.randomUUID().toString()
        val myMemberId = UUID.randomUUID().toString()
        val myChainKeyOut = CryptoUtils.secureRandomBytes(64)
        val group = GroupEntity(
            groupId = groupId,
            groupName = groupName,
            myMemberId = myMemberId,
            myChainKeyOut = myChainKeyOut,
            myCounterOut = 0,
            groupEpoch = 1L,
            createdAt = System.currentTimeMillis(),
            lastActive = System.currentTimeMillis(),
            isActive = true
        )
        groupDao?.insertOrUpdate(group)

        val groupIdBytes = uuidStringToBytes(groupId)
        val myMemberIdBytes = uuidStringToBytes(myMemberId)

        val membersSummary = mutableListOf<BinaryFrameCodec.DecodedPayload.GroupMemberSummary>()
        membersSummary.add(BinaryFrameCodec.DecodedPayload.GroupMemberSummary(myMemberIdBytes, "Ja"))

        val memberEntities = mutableListOf<GroupMemberEntity>()
        memberEntities.add(
            GroupMemberEntity(
                groupId = groupId,
                memberId = myMemberId,
                contactId = null,
                memberName = "Ja",
                chainKeyIn = myChainKeyOut,
                counterIn = 0,
                joinedAt = System.currentTimeMillis(),
                isActive = true
            )
        )
        for (contactId in invitedContactIds) {
            val contact = contactDao.getContactById(contactId) ?: continue
            val memberId = UUID.randomUUID().toString()
            val memberIdBytes = uuidStringToBytes(memberId)
            val memberName = contact.rawName
            membersSummary.add(BinaryFrameCodec.DecodedPayload.GroupMemberSummary(memberIdBytes, memberName))
            memberEntities.add(
                GroupMemberEntity(
                    groupId = groupId,
                    memberId = memberId,
                    contactId = contactId,
                    memberName = memberName,
                    chainKeyIn = ByteArray(64),
                    counterIn = 0,
                    joinedAt = System.currentTimeMillis(),
                    isActive = true
                )
            )
        }
        if (memberEntities.isNotEmpty()) {
            groupMemberDao?.insertOrUpdateAll(memberEntities)
        }

        // Dispatch Group Control invite (Type 0x06, subType = INVITE) to each invited contact with random permutation and interleaved queuing
        val shuffledContactIds = if (invitedContactIds.size > 1) {
            invitedContactIds.shuffled(CryptoUtils.secureRandom)
        } else {
            invitedContactIds
        }
        val inviteFrames = mutableListOf<org.pqchat.dht.traffic.OutboundPoissonFrame>()
        for (contactId in shuffledContactIds) {
            try {
                sendGroupControlInvite(
                    contactId = contactId,
                    groupIdBytes = groupIdBytes,
                    groupEpoch = 1L,
                    myMemberIdBytes = myMemberIdBytes,
                    myChainKeyOut = myChainKeyOut,
                    currentCounter = 0L,
                    groupName = groupName,
                    membersSummary = membersSummary,
                    outboundCollector = if (isStrictPoissonShaping()) inviteFrames else null
                )
            } catch (_: Exception) {}
        }
        if (inviteFrames.isNotEmpty()) {
            outboundPoissonQueue.enqueueInterleaved(inviteFrames)
        }

        group
    }

    private suspend fun sendGroupControlInvite(
        contactId: String,
        groupIdBytes: ByteArray,
        groupEpoch: Long,
        myMemberIdBytes: ByteArray,
        myChainKeyOut: ByteArray,
        currentCounter: Long,
        groupName: String,
        membersSummary: List<BinaryFrameCodec.DecodedPayload.GroupMemberSummary>,
        outboundCollector: MutableList<org.pqchat.dht.traffic.OutboundPoissonFrame>? = null
    ): Boolean {
        return getContactMutex(contactId).withLock {
            val contact = contactDao.getContactById(contactId) ?: return@withLock false
            val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)

            val plaintext = BinaryFrameCodec.encodeGroupControl(
                seqNum = contact.counterOut and 0xFFFF,
                ackNum = contact.counterIn and 0xFFFF,
                timestampUTC = System.currentTimeMillis(),
                controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_INVITE,
                groupId = groupIdBytes,
                groupEpoch = groupEpoch,
                senderMemberId = myMemberIdBytes,
                senderGroupChainKey = myChainKeyOut,
                currentCounter = currentCounter,
                groupName = groupName,
                members = membersSummary
            )

            val frame = BinaryFrameCodec.packAeadFrame(
                key = slot.msgKey,
                plaintext = plaintext,
                target = slot.target,
                direction = contact.outboundDirection
            )

            val isSelf = contactId == SELF_CONTACT_ID
            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot.msgKey, "${contact.counterOut}")
            val controlTaskId = nextControlTaskId.decrementAndGet()

            if (!isSelf) {
                val republishTask = org.pqchat.dht.traffic.PollingWorker.RepublishTask(
                    messageId = controlTaskId,
                    contactId = contactId,
                    target = slot.target,
                    payload = frame,
                    edPrivateKeySeed = slot.edPrivateKeySeed,
                    initialSentTimestamp = System.currentTimeMillis()
                )
                org.pqchat.dht.service.DhtWorker.registerRepublishTask(republishTask)
                pendingGroupControls[controlTaskId] = PendingGroupControlRecord(
                    taskId = controlTaskId,
                    groupId = bytesToUuidString(groupIdBytes),
                    contactId = contactId,
                    controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_INVITE,
                    groupEpoch = groupEpoch,
                    targetAck = targetAck,
                    ackRatchetKey = slot.msgKey,
                    seqNum = contact.counterOut,
                    slotTarget = slot.target,
                    slotEdSeed = slot.edPrivateKeySeed,
                    payload = frame
                )
                onRepublishTaskUpdated?.invoke()
            }

            if (isStrictPoissonShaping()) {
                contactDao.updateOutgoingState(
                    id = contactId,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )
                val outboundFrame = org.pqchat.dht.traffic.OutboundPoissonFrame(
                    target = slot.target,
                    payload = frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = isSelf,
                    seqNum = contact.counterOut,
                    contactId = contactId,
                    packetClass = org.pqchat.dht.traffic.PacketClass.URGENT_CONTROL,
                    onSent = { success ->
                        if (success) {
                            decoyTargetPool.registerPopulatedTarget(slot.target)
                        }
                    }
                )
                if (outboundCollector != null) {
                    outboundCollector.add(outboundFrame)
                } else {
                    outboundPoissonQueue.enqueue(outboundFrame)
                }
                return@withLock true
            }

            val success = dhtLeafNode.putMutable(
                target = slot.target,
                v = frame,
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                salt = null,
                sk = slot.edPrivateKeySeed,
                skipLocalStore = isSelf
            )

            if (success) {
                contactDao.updateOutgoingState(
                    id = contactId,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )
                decoyTargetPool.registerPopulatedTarget(slot.target)
            }
            success
        }
    }

    private suspend fun sendGroupControlRekeyOrInvite(
        contactId: String,
        controlSubType: Byte,
        groupIdBytes: ByteArray,
        groupEpoch: Long,
        myMemberIdBytes: ByteArray,
        myChainKeyOut: ByteArray,
        currentCounter: Long,
        groupName: String,
        outboundCollector: MutableList<org.pqchat.dht.traffic.OutboundPoissonFrame>? = null
    ): Boolean {
        return getContactMutex(contactId).withLock {
            sendGroupControlRekeyOrInviteInternal(
                contactId,
                controlSubType,
                groupIdBytes,
                groupEpoch,
                myMemberIdBytes,
                myChainKeyOut,
                currentCounter,
                groupName,
                outboundCollector
            )
        }
    }

    private suspend fun sendGroupControlRekeyOrInviteInternal(
        contactId: String,
        controlSubType: Byte,
        groupIdBytes: ByteArray,
        groupEpoch: Long,
        myMemberIdBytes: ByteArray,
        myChainKeyOut: ByteArray,
        currentCounter: Long,
        groupName: String,
        outboundCollector: MutableList<org.pqchat.dht.traffic.OutboundPoissonFrame>? = null
    ): Boolean {
        val contact = contactDao.getContactById(contactId) ?: return false
        val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)

            val plaintext = when (controlSubType) {
                BinaryFrameCodec.GROUP_SUBTYPE_REKEY -> BinaryFrameCodec.encodeGroupRekey(
                    seqNum = contact.counterOut and 0xFFFF,
                    ackNum = contact.counterIn and 0xFFFF,
                    timestampUTC = System.currentTimeMillis(),
                    groupId = groupIdBytes,
                    groupEpoch = groupEpoch,
                    senderMemberId = myMemberIdBytes,
                    senderGroupChainKey = myChainKeyOut,
                    currentCounter = currentCounter,
                    groupName = groupName
                )
                BinaryFrameCodec.GROUP_SUBTYPE_LEAVE -> BinaryFrameCodec.encodeGroupLeave(
                    seqNum = contact.counterOut and 0xFFFF,
                    ackNum = contact.counterIn and 0xFFFF,
                    timestampUTC = System.currentTimeMillis(),
                    groupId = groupIdBytes,
                    groupEpoch = groupEpoch,
                    senderMemberId = myMemberIdBytes,
                    groupName = groupName
                )
                else -> BinaryFrameCodec.encodeGroupControl(
                    seqNum = contact.counterOut and 0xFFFF,
                    ackNum = contact.counterIn and 0xFFFF,
                    timestampUTC = System.currentTimeMillis(),
                    controlSubType = controlSubType,
                    groupId = groupIdBytes,
                    groupEpoch = groupEpoch,
                    senderMemberId = myMemberIdBytes,
                    senderGroupChainKey = myChainKeyOut,
                    currentCounter = currentCounter,
                    groupName = groupName,
                    members = emptyList()
                )
            }

            val frame = BinaryFrameCodec.packAeadFrame(
                key = slot.msgKey,
                plaintext = plaintext,
                target = slot.target,
                direction = contact.outboundDirection
            )

            val isSelf = contactId == SELF_CONTACT_ID
            val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(slot.msgKey, "${contact.counterOut}")
            val controlTaskId = nextControlTaskId.decrementAndGet()

            if (!isSelf && controlSubType != BinaryFrameCodec.GROUP_SUBTYPE_LEAVE) {
                val republishTask = org.pqchat.dht.traffic.PollingWorker.RepublishTask(
                    messageId = controlTaskId,
                    contactId = contactId,
                    target = slot.target,
                    payload = frame,
                    edPrivateKeySeed = slot.edPrivateKeySeed,
                    initialSentTimestamp = System.currentTimeMillis()
                )
                org.pqchat.dht.service.DhtWorker.registerRepublishTask(republishTask)
                pendingGroupControls[controlTaskId] = PendingGroupControlRecord(
                    taskId = controlTaskId,
                    groupId = bytesToUuidString(groupIdBytes),
                    contactId = contactId,
                    controlSubType = controlSubType,
                    groupEpoch = groupEpoch,
                    targetAck = targetAck,
                    ackRatchetKey = slot.msgKey,
                    seqNum = contact.counterOut,
                    slotTarget = slot.target,
                    slotEdSeed = slot.edPrivateKeySeed,
                    payload = frame
                )
                onRepublishTaskUpdated?.invoke()
            }

            if (isStrictPoissonShaping()) {
                contactDao.updateOutgoingState(
                    id = contactId,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )
                val outboundFrame = org.pqchat.dht.traffic.OutboundPoissonFrame(
                    target = slot.target,
                    payload = frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = isSelf,
                    seqNum = contact.counterOut,
                    contactId = contactId,
                    packetClass = org.pqchat.dht.traffic.PacketClass.URGENT_CONTROL,
                    onSent = { success ->
                        if (success) {
                            decoyTargetPool.registerPopulatedTarget(slot.target)
                        }
                    }
                )
                if (outboundCollector != null) {
                    outboundCollector.add(outboundFrame)
                } else {
                    outboundPoissonQueue.enqueue(outboundFrame)
                }
                return true
            }

            val success = dhtLeafNode.putMutable(
                target = slot.target,
                v = frame,
                seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                salt = null,
                sk = slot.edPrivateKeySeed,
                skipLocalStore = isSelf
            )

            if (success) {
                contactDao.updateOutgoingState(
                    id = contactId,
                    counterOut = contact.counterOut + 1,
                    chainKeyOut = slot.nextChainKey
                )
                decoyTargetPool.registerPopulatedTarget(slot.target)
            }
            return success
    }

    suspend fun retransmitGroupInviteToOfflineMember(groupId: String, memberContactId: String): Boolean {
        val group = groupDao?.getGroupById(groupId) ?: return false
        val groupIdBytes = uuidStringToBytes(groupId)
        val myMemberIdBytes = uuidStringToBytes(group.myMemberId)
        val allMembers = groupMemberDao?.getMembersForGroup(groupId) ?: emptyList()
        val membersSummary = allMembers.map { m ->
            BinaryFrameCodec.DecodedPayload.GroupMemberSummary(
                uuidStringToBytes(m.memberId),
                m.rawMemberName
            )
        }

        // Cancel previous unconfirmed invite tasks for this member in this group
        val previousTasks = pendingGroupControls.values.filter {
            it.groupId == groupId && it.contactId == memberContactId && it.controlSubType == BinaryFrameCodec.GROUP_SUBTYPE_INVITE
        }
        for (task in previousTasks) {
            org.pqchat.dht.service.DhtWorker.unregisterRepublishTask(task.taskId)
            pendingGroupControls.remove(task.taskId)
        }

        return sendGroupControlInvite(
            contactId = memberContactId,
            groupIdBytes = groupIdBytes,
            groupEpoch = group.groupEpoch,
            myMemberIdBytes = myMemberIdBytes,
            myChainKeyOut = group.rawMyChainKeyOut,
            currentCounter = group.myCounterOut.toLong(),
            groupName = group.rawGroupName,
            membersSummary = membersSummary
        )
    }

    suspend fun retransmitGroupRekeyToOfflineMember(groupId: String, memberContactId: String): Boolean {
        val group = groupDao?.getGroupById(groupId) ?: return false
        val groupIdBytes = uuidStringToBytes(groupId)
        val myMemberIdBytes = uuidStringToBytes(group.myMemberId)

        // Cancel previous unconfirmed rekey tasks for this member in this group
        val previousTasks = pendingGroupControls.values.filter {
            it.groupId == groupId && it.contactId == memberContactId && it.controlSubType == BinaryFrameCodec.GROUP_SUBTYPE_REKEY
        }
        for (task in previousTasks) {
            org.pqchat.dht.service.DhtWorker.unregisterRepublishTask(task.taskId)
            pendingGroupControls.remove(task.taskId)
        }

        return sendGroupControlRekeyOrInvite(
            contactId = memberContactId,
            controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_REKEY,
            groupIdBytes = groupIdBytes,
            groupEpoch = group.groupEpoch,
            myMemberIdBytes = myMemberIdBytes,
            myChainKeyOut = group.rawMyChainKeyOut,
            currentCounter = group.myCounterOut.toLong(),
            groupName = group.rawGroupName
        )
    }

    suspend fun retransmitGroupControlToOfflineMember(groupId: String, memberContactId: String): Boolean {
        val record = pendingGroupControls.values.firstOrNull {
            it.groupId == groupId && it.contactId == memberContactId
        } ?: return false
        return when (record.controlSubType) {
            BinaryFrameCodec.GROUP_SUBTYPE_INVITE -> retransmitGroupInviteToOfflineMember(groupId, memberContactId)
            BinaryFrameCodec.GROUP_SUBTYPE_REKEY -> retransmitGroupRekeyToOfflineMember(groupId, memberContactId)
            else -> false
        }
    }

    suspend fun retransmitUnconfirmedGroupControls(
        policy: org.pqchat.dht.traffic.RepublishPolicy = org.pqchat.dht.traffic.RepublishPolicy(),
        currentTimeMs: Long = System.currentTimeMillis()
    ): Int = withContext(Dispatchers.IO) {
        val unconfirmed = pendingGroupControls.values.toList()
        if (unconfirmed.isEmpty()) return@withContext 0

        var retransmittedCount = 0
        for (record in unconfirmed) {
            val age = (currentTimeMs - record.timestamp).coerceAtLeast(0L)
            if (policy.isExpired(age)) {
                org.pqchat.dht.service.DhtWorker.unregisterRepublishTask(record.taskId)
                pendingGroupControls.remove(record.taskId)
                continue
            }

            if (record.currentAttempts >= 40) {
                org.pqchat.dht.service.DhtWorker.unregisterRepublishTask(record.taskId)
                pendingGroupControls.remove(record.taskId)
                continue
            }

            val interval = policy.getIntervalForAge(age)
            val timeSinceLast = if (record.lastRepublishedTimestamp == 0L) {
                Long.MAX_VALUE
            } else {
                (currentTimeMs - record.lastRepublishedTimestamp).coerceAtLeast(0L)
            }

            if (timeSinceLast >= interval) {
                val success = when (record.controlSubType) {
                    BinaryFrameCodec.GROUP_SUBTYPE_INVITE -> retransmitGroupInviteToOfflineMember(record.groupId, record.contactId)
                    BinaryFrameCodec.GROUP_SUBTYPE_REKEY -> retransmitGroupRekeyToOfflineMember(record.groupId, record.contactId)
                    else -> false
                }
                if (success) {
                    record.lastRepublishedTimestamp = currentTimeMs
                    record.currentAttempts++
                    retransmittedCount++
                }
            }
        }
        retransmittedCount
    }

    suspend fun processIncomingGroupControl(
        contactId: String,
        control: BinaryFrameCodec.DecodedPayload.GroupControl
    ) = withContext(Dispatchers.IO) {
        val groupId = bytesToUuidString(control.groupId)
        val senderMemberId = bytesToUuidString(control.senderMemberId)
        val senderContact = contactDao.getContactById(contactId)
        val senderName = senderContact?.rawName ?: "Uczestnik"

        when (control.controlSubType) {
            BinaryFrameCodec.GROUP_SUBTYPE_INVITE -> {
                var existingGroup = groupDao?.getGroupById(groupId)
                if (existingGroup == null) {
                    val myMemberId = UUID.randomUUID().toString()
                    val myChainKeyOut = CryptoUtils.secureRandomBytes(64)
                    val newGroup = GroupEntity(
                        groupId = groupId,
                        groupName = control.groupName,
                        myMemberId = myMemberId,
                        myChainKeyOut = myChainKeyOut,
                        myCounterOut = 0,
                        groupEpoch = control.groupEpoch,
                        createdAt = System.currentTimeMillis(),
                        lastActive = System.currentTimeMillis(),
                        isActive = true
                    )
                    groupDao?.insertOrUpdate(newGroup)

                    val senderMember = GroupMemberEntity(
                        groupId = groupId,
                        memberId = senderMemberId,
                        contactId = contactId,
                        memberName = senderName,
                        chainKeyIn = control.senderGroupChainKey,
                        counterIn = control.currentCounter.toInt(),
                        joinedAt = System.currentTimeMillis(),
                        isActive = true
                    )
                    groupMemberDao?.insertOrUpdate(senderMember)

                    val myMember = GroupMemberEntity(
                        groupId = groupId,
                        memberId = myMemberId,
                        contactId = null,
                        memberName = "Ja",
                        chainKeyIn = myChainKeyOut,
                        counterIn = 0,
                        joinedAt = System.currentTimeMillis(),
                        isActive = true
                    )
                    groupMemberDao?.insertOrUpdate(myMember)

                    for (m in control.members) {
                        val mId = bytesToUuidString(m.memberId)
                        if (mId != senderMemberId && mId != myMemberId) {
                            val existing = groupMemberDao?.getMember(groupId, mId)
                            if (existing == null) {
                                groupMemberDao?.insertOrUpdate(
                                    GroupMemberEntity(
                                        groupId = groupId,
                                        memberId = mId,
                                        contactId = null,
                                        memberName = m.memberName,
                                        chainKeyIn = ByteArray(64),
                                        counterIn = 0,
                                        joinedAt = System.currentTimeMillis(),
                                        isActive = true
                                    )
                                )
                            }
                        }
                    }

                    // Respond back with our own Sender Key so inviter can receive our group messages
                    val myMemberIdBytes = uuidStringToBytes(myMemberId)
                    val groupIdBytes = control.groupId
                    sendGroupControlRekeyOrInviteInternal(
                        contactId = contactId,
                        controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_REKEY,
                        groupIdBytes = groupIdBytes,
                        groupEpoch = control.groupEpoch,
                        myMemberIdBytes = myMemberIdBytes,
                        myChainKeyOut = myChainKeyOut,
                        currentCounter = 0L,
                        groupName = control.groupName
                    )
                } else {
                    val member = GroupMemberEntity(
                        groupId = groupId,
                        memberId = senderMemberId,
                        contactId = contactId,
                        memberName = senderName,
                        chainKeyIn = control.senderGroupChainKey,
                        counterIn = control.currentCounter.toInt(),
                        joinedAt = System.currentTimeMillis(),
                        isActive = true
                    )
                    groupMemberDao?.insertOrUpdate(member)
                }
            }
            BinaryFrameCodec.GROUP_SUBTYPE_REKEY -> {
                val existingGroup = groupDao?.getGroupById(groupId) ?: return@withContext
                val existingMember = groupMemberDao?.getMember(groupId, senderMemberId)
                val allMembers = groupMemberDao?.getMembersForGroup(groupId) ?: emptyList()
                val placeholderMember = allMembers.firstOrNull { it.contactId == contactId && it.memberId != senderMemberId }

                if (existingMember != null) {
                    val updated = existingMember.copy(
                        contactId = contactId,
                        chainKeyIn = EncryptedBlob(control.senderGroupChainKey, "group_members", "${groupId}_${senderMemberId}", "chainKeyIn"),
                        counterIn = control.currentCounter.toInt(),
                        isActive = true
                    )
                    groupMemberDao.insertOrUpdate(updated)
                } else if (placeholderMember != null) {
                    groupMemberDao?.deleteMember(groupId, placeholderMember.memberId)
                    val updated = placeholderMember.copy(
                        memberId = senderMemberId,
                        chainKeyIn = EncryptedBlob(control.senderGroupChainKey, "group_members", "${groupId}_${senderMemberId}", "chainKeyIn"),
                        counterIn = control.currentCounter.toInt(),
                        isActive = true
                    )
                    groupMemberDao?.insertOrUpdate(updated)
                } else {
                    val newMember = GroupMemberEntity(
                        groupId = groupId,
                        memberId = senderMemberId,
                        contactId = contactId,
                        memberName = senderName,
                        chainKeyIn = control.senderGroupChainKey,
                        counterIn = control.currentCounter.toInt(),
                        joinedAt = System.currentTimeMillis(),
                        isActive = true
                    )
                    groupMemberDao?.insertOrUpdate(newMember)
                }
            }
            BinaryFrameCodec.GROUP_SUBTYPE_LEAVE -> {
                groupMemberDao?.markMemberInactive(groupId, senderMemberId)
                getGroupMutex(groupId).withLock {
                    val existingGroup = groupDao?.getGroupById(groupId)
                    if (existingGroup != null && existingGroup.isActive) {
                        rotateGroupSenderKeyInternal(existingGroup)
                    }
                }
            }
        }
    }

    suspend fun sendGroupMessage(
        groupId: String,
        text: String,
        ephemeralTtlSeconds: Long = 0L
    ): Boolean = withContext(Dispatchers.IO) {
        getGroupMutex(groupId).withLock {
            val group = groupDao?.getGroupById(groupId) ?: return@withLock false
            if (!group.isActive) return@withLock false

            // Auto-rekey every 50 messages
            if (group.myCounterOut > 0 && group.myCounterOut % BinaryFrameCodec.GROUP_REKEY_MESSAGE_INTERVAL == 0) {
                rotateGroupSenderKeyInternal(group)
            }
            val currentGroup = groupDao.getGroupById(groupId) ?: group

            val baseSlot = RatchetChain.deriveSlot(currentGroup.rawMyChainKeyOut, currentGroup.myCounterOut)
            val groupIdBytes = uuidStringToBytes(groupId)
            val myMemberIdBytes = uuidStringToBytes(currentGroup.myMemberId)
            val expiresAt = if (ephemeralTtlSeconds > 0L) System.currentTimeMillis() + ephemeralTtlSeconds * 1000L else null

            val plaintext = BinaryFrameCodec.encodeTextMessage(
                seqNum = currentGroup.myCounterOut and 0xFFFF,
                ackNum = 0,
                timestampUTC = System.currentTimeMillis(),
                text = text,
                ephemeralTtlSeconds = ephemeralTtlSeconds
            )

            val activeMembers = groupMemberDao?.getMembersForGroup(groupId)?.filter {
                it.memberId != currentGroup.myMemberId && it.isActive
            } ?: emptyList()

            // Eliminate Group Fan-Out Burst: randomize recipient order via secure permutation
            val shuffledMembers = if (activeMembers.size > 1) {
                activeMembers.shuffled(CryptoUtils.secureRandom)
            } else {
                activeMembers
            }

            // Same-target for all members allows a DHT observer to correlate N recipients via parallel GETs to the same slot, breaking group destination privacy.
            // Instead of a single target = RatchetChain.deriveSlot(myChainKeyOut, counterOut) used for all members,
            // we derive a unique slot for each member:
            // memberTarget = HKDF-Expand(myChainKeyOut, "group_target:" || groupId || counterOut || memberId, 32)
            // and then RatchetChain.deriveSlot with corresponding msgKey/edSeed per member.
            // We perform separate putMutable under each unique target (N targets for N members).
            val targetSlots = if (shuffledMembers.isNotEmpty()) {
                shuffledMembers.map { member ->
                    val recipientMemberIdBytes = uuidStringToBytes(member.memberId)
                    RatchetChain.deriveGroupRecipientSlot(
                        chainKey = currentGroup.rawMyChainKeyOut,
                        counter = currentGroup.myCounterOut,
                        groupId = groupIdBytes,
                        senderMemberId = myMemberIdBytes,
                        recipientMemberId = recipientMemberIdBytes
                    )
                }
            } else {
                listOf(baseSlot)
            }

            val msgId = messageDao.insertMessage(
                MessageEntity(
                    contactId = groupId,
                    isOutgoing = true,
                    seqEpoch = currentGroup.myCounterOut / 65536,
                    seqNum = currentGroup.myCounterOut,
                    ackNum = 0,
                    timestamp = System.currentTimeMillis(),
                    textContent = text,
                    status = if (isStrictPoissonShaping()) "QUEUED_POISSON" else "SENT_DHT",
                    senderMemberId = currentGroup.myMemberId,
                    senderName = "Ja",
                    ephemeralTtlSeconds = ephemeralTtlSeconds,
                    expiresAtTimestamp = expiresAt
                )
            )

            // Advance sender's ratchet chain using baseSlot.nextChainKey
            groupDao.updateOutgoingState(
                groupId = groupId,
                counterOut = currentGroup.myCounterOut + 1,
                chainKeyOut = EncryptedBlob(baseSlot.nextChainKey, "groups", groupId, "myChainKeyOut"),
                lastActive = System.currentTimeMillis()
            )

            val framesRemaining = java.util.concurrent.atomic.AtomicInteger(targetSlots.size)
            val anySuccess = java.util.concurrent.atomic.AtomicBoolean(false)

            if (isStrictPoissonShaping()) {
                val outboundFrames = targetSlots.map { slot ->
                    val frame = BinaryFrameCodec.packGroupAeadFrame(
                        key = slot.msgKey,
                        plaintext = plaintext,
                        target = slot.target,
                        groupId = groupIdBytes,
                        senderMemberId = myMemberIdBytes
                    )
                    org.pqchat.dht.traffic.OutboundPoissonFrame(
                        target = slot.target,
                        payload = frame,
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = slot.edPrivateKeySeed,
                        skipLocalStore = false,
                        seqNum = currentGroup.myCounterOut,
                        messageId = msgId,
                        contactId = groupId,
                        packetClass = org.pqchat.dht.traffic.PacketClass.GROUP_MESSAGE,
                        onSent = { success ->
                            if (success) {
                                anySuccess.set(true)
                                decoyTargetPool.registerPopulatedTarget(slot.target)
                            }
                            if (framesRemaining.decrementAndGet() == 0) {
                                if (anySuccess.get()) {
                                    messageDao.updateStatus(msgId, "SENT_DHT")
                                }
                            }
                        }
                    )
                }
                outboundPoissonQueue.enqueueInterleaved(outboundFrames)
                return@withLock true
            }

            var overallSuccess = false
            for ((idx, slot) in targetSlots.withIndex()) {
                if (idx > 0) {
                    val jitterMs = 40L + (CryptoUtils.secureRandomBytes(1)[0].toInt() and 0x7F)
                    kotlinx.coroutines.delay(jitterMs)
                }
                val frame = BinaryFrameCodec.packGroupAeadFrame(
                    key = slot.msgKey,
                    plaintext = plaintext,
                    target = slot.target,
                    groupId = groupIdBytes,
                    senderMemberId = myMemberIdBytes
                )
                val success = dhtLeafNode.putMutable(
                    target = slot.target,
                    v = frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = false
                )
                if (success) {
                    decoyTargetPool.registerPopulatedTarget(slot.target)
                    overallSuccess = true
                }
            }

            if (overallSuccess) {
                messageDao.updateStatus(msgId, "SENT_DHT")
            }
            overallSuccess
        }
    }

    suspend fun sendGroupReaction(
        groupId: String,
        targetMessage: MessageEntity,
        emoji: String
    ): Boolean = sendGroupReaction(groupId, targetMessage.seqEpoch, targetMessage.seqNum, emoji)

    suspend fun sendGroupReaction(
        groupId: String,
        targetSeqEpoch: Int,
        targetSeqNum: Int,
        emoji: String
    ): Boolean = withContext(Dispatchers.IO) {
        getGroupMutex(groupId).withLock {
            val group = groupDao?.getGroupById(groupId) ?: return@withLock false
            if (!group.isActive) return@withLock false

            val currentGroup = groupDao.getGroupById(groupId) ?: group
            val baseSlot = RatchetChain.deriveSlot(currentGroup.rawMyChainKeyOut, currentGroup.myCounterOut)
            val groupIdBytes = uuidStringToBytes(groupId)
            val myMemberIdBytes = uuidStringToBytes(currentGroup.myMemberId)

            val plaintext = BinaryFrameCodec.encodeReaction(
                seqNum = currentGroup.myCounterOut and 0xFFFF,
                ackNum = 0,
                timestampUTC = System.currentTimeMillis(),
                targetSeqEpoch = targetSeqEpoch,
                targetSeqNum = targetSeqNum,
                emoji = emoji
            )

            val activeMembers = groupMemberDao?.getMembersForGroup(groupId)?.filter {
                it.memberId != currentGroup.myMemberId && it.isActive
            } ?: emptyList()

            val targetSlots = if (activeMembers.isNotEmpty()) {
                activeMembers.map { member ->
                    val recipientMemberIdBytes = uuidStringToBytes(member.memberId)
                    RatchetChain.deriveGroupRecipientSlot(
                        chainKey = currentGroup.rawMyChainKeyOut,
                        counter = currentGroup.myCounterOut,
                        groupId = groupIdBytes,
                        senderMemberId = myMemberIdBytes,
                        recipientMemberId = recipientMemberIdBytes
                    )
                }
            } else {
                listOf(baseSlot)
            }

            messageDao.updateMessageReactionAnyDirection(groupId, targetSeqEpoch, targetSeqNum, emoji)

            groupDao.updateOutgoingState(
                groupId = groupId,
                counterOut = currentGroup.myCounterOut + 1,
                chainKeyOut = EncryptedBlob(baseSlot.nextChainKey, "groups", groupId, "myChainKeyOut"),
                lastActive = System.currentTimeMillis()
            )

            val framesRemaining = java.util.concurrent.atomic.AtomicInteger(targetSlots.size)
            val anySuccess = java.util.concurrent.atomic.AtomicBoolean(false)

            if (isStrictPoissonShaping()) {
                val outboundFrames = targetSlots.map { slot ->
                    val frame = BinaryFrameCodec.packGroupAeadFrame(
                        key = slot.msgKey,
                        plaintext = plaintext,
                        target = slot.target,
                        groupId = groupIdBytes,
                        senderMemberId = myMemberIdBytes
                    )
                    org.pqchat.dht.traffic.OutboundPoissonFrame(
                        target = slot.target,
                        payload = frame,
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = slot.edPrivateKeySeed,
                        skipLocalStore = false,
                        seqNum = currentGroup.myCounterOut,
                        messageId = -1L,
                        contactId = groupId,
                        packetClass = org.pqchat.dht.traffic.PacketClass.GROUP_MESSAGE,
                        onSent = { success ->
                            if (success) {
                                anySuccess.set(true)
                                decoyTargetPool.registerPopulatedTarget(slot.target)
                            }
                        }
                    )
                }
                outboundPoissonQueue.enqueueInterleaved(outboundFrames)
                return@withLock true
            }

            var overallSuccess = false
            for ((idx, slot) in targetSlots.withIndex()) {
                if (idx > 0) {
                    val jitterMs = 40L + (CryptoUtils.secureRandomBytes(1)[0].toInt() and 0x7F)
                    kotlinx.coroutines.delay(jitterMs)
                }
                val frame = BinaryFrameCodec.packGroupAeadFrame(
                    key = slot.msgKey,
                    plaintext = plaintext,
                    target = slot.target,
                    groupId = groupIdBytes,
                    senderMemberId = myMemberIdBytes
                )
                val success = dhtLeafNode.putMutable(
                    target = slot.target,
                    v = frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = false
                )
                if (success) {
                    decoyTargetPool.registerPopulatedTarget(slot.target)
                    overallSuccess = true
                }
            }
            overallSuccess
        }
    }

    suspend fun sendGroupLocationPin(
        groupId: String,
        latitude: Double,
        longitude: Double,
        altitude: Double = 0.0,
        accuracy: Float = 0.0f,
        note: String = "",
        ephemeralTtlSeconds: Long = 0L
    ): Boolean = withContext(Dispatchers.IO) {
        val locText = org.pqchat.dht.protocol.LocationPinData(
            latitude = latitude,
            longitude = longitude,
            altitude = altitude,
            accuracy = accuracy,
            note = note
        ).toPayloadText()

        getGroupMutex(groupId).withLock {
            val group = groupDao?.getGroupById(groupId) ?: return@withLock false
            if (!group.isActive) return@withLock false

            val currentGroup = groupDao.getGroupById(groupId) ?: group
            val baseSlot = RatchetChain.deriveSlot(currentGroup.rawMyChainKeyOut, currentGroup.myCounterOut)
            val groupIdBytes = uuidStringToBytes(groupId)
            val myMemberIdBytes = uuidStringToBytes(currentGroup.myMemberId)
            val expiresAt = if (ephemeralTtlSeconds > 0L) System.currentTimeMillis() + ephemeralTtlSeconds * 1000L else null

            val plaintext = BinaryFrameCodec.encodeLocationPin(
                seqNum = currentGroup.myCounterOut and 0xFFFF,
                ackNum = 0,
                timestampUTC = System.currentTimeMillis(),
                latitude = latitude,
                longitude = longitude,
                altitude = altitude,
                accuracy = accuracy,
                note = note,
                ephemeralTtlSeconds = ephemeralTtlSeconds
            )

            val activeMembers = groupMemberDao?.getMembersForGroup(groupId)?.filter {
                it.memberId != currentGroup.myMemberId && it.isActive
            } ?: emptyList()

            val targetSlots = if (activeMembers.isNotEmpty()) {
                activeMembers.map { member ->
                    val recipientMemberIdBytes = uuidStringToBytes(member.memberId)
                    RatchetChain.deriveGroupRecipientSlot(
                        chainKey = currentGroup.rawMyChainKeyOut,
                        counter = currentGroup.myCounterOut,
                        groupId = groupIdBytes,
                        senderMemberId = myMemberIdBytes,
                        recipientMemberId = recipientMemberIdBytes
                    )
                }
            } else {
                listOf(baseSlot)
            }

            val msgId = messageDao.insertMessage(
                MessageEntity(
                    contactId = groupId,
                    isOutgoing = true,
                    seqEpoch = currentGroup.myCounterOut / 65536,
                    seqNum = currentGroup.myCounterOut,
                    ackNum = 0,
                    timestamp = System.currentTimeMillis(),
                    textContent = locText,
                    status = if (isStrictPoissonShaping()) "QUEUED_POISSON" else "SENT_DHT",
                    senderMemberId = currentGroup.myMemberId,
                    senderName = "Me",
                    ephemeralTtlSeconds = ephemeralTtlSeconds,
                    expiresAtTimestamp = expiresAt
                )
            )

            groupDao.updateOutgoingState(
                groupId = groupId,
                counterOut = currentGroup.myCounterOut + 1,
                chainKeyOut = EncryptedBlob(baseSlot.nextChainKey, "groups", groupId, "myChainKeyOut"),
                lastActive = System.currentTimeMillis()
            )

            val framesRemaining = java.util.concurrent.atomic.AtomicInteger(targetSlots.size)
            val anySuccess = java.util.concurrent.atomic.AtomicBoolean(false)

            if (isStrictPoissonShaping()) {
                val outboundFrames = targetSlots.map { slot ->
                    val frame = BinaryFrameCodec.packGroupAeadFrame(
                        key = slot.msgKey,
                        plaintext = plaintext,
                        target = slot.target,
                        groupId = groupIdBytes,
                        senderMemberId = myMemberIdBytes
                    )
                    org.pqchat.dht.traffic.OutboundPoissonFrame(
                        target = slot.target,
                        payload = frame,
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = slot.edPrivateKeySeed,
                        skipLocalStore = false,
                        seqNum = currentGroup.myCounterOut,
                        messageId = msgId,
                        contactId = groupId,
                        packetClass = org.pqchat.dht.traffic.PacketClass.GROUP_MESSAGE,
                        onSent = { success ->
                            if (success) {
                                anySuccess.set(true)
                                decoyTargetPool.registerPopulatedTarget(slot.target)
                            }
                            if (framesRemaining.decrementAndGet() == 0) {
                                if (anySuccess.get()) {
                                    messageDao.updateStatus(msgId, "SENT_DHT")
                                }
                            }
                        }
                    )
                }
                outboundPoissonQueue.enqueueInterleaved(outboundFrames)
                return@withLock true
            }

            var overallSuccess = false
            for ((idx, slot) in targetSlots.withIndex()) {
                if (idx > 0) {
                    val jitterMs = 40L + (CryptoUtils.secureRandomBytes(1)[0].toInt() and 0x7F)
                    kotlinx.coroutines.delay(jitterMs)
                }
                val frame = BinaryFrameCodec.packGroupAeadFrame(
                    key = slot.msgKey,
                    plaintext = plaintext,
                    target = slot.target,
                    groupId = groupIdBytes,
                    senderMemberId = myMemberIdBytes
                )
                val success = dhtLeafNode.putMutable(
                    target = slot.target,
                    v = frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = false
                )
                if (success) {
                    decoyTargetPool.registerPopulatedTarget(slot.target)
                    overallSuccess = true
                }
            }

            if (overallSuccess) {
                messageDao.updateStatus(msgId, "SENT_DHT")
            }
            overallSuccess
        }
    }

    suspend fun sendGroupVoiceNote(
        groupId: String,
        pcm16Samples: ShortArray,
        ephemeralTtlSeconds: Long = 0L
    ): Boolean = withContext(Dispatchers.IO) {
        val durationMs = (pcm16Samples.size * 1000L / org.pqchat.dht.media.voice.VoiceCodec.SAMPLE_RATE).toInt()
        val voiceBytes = org.pqchat.dht.media.voice.VoiceCodec.encode(pcm16Samples)
        sendGroupVoiceNote(groupId, voiceBytes, durationMs, ephemeralTtlSeconds)
    }

    suspend fun sendGroupVoiceNote(
        groupId: String,
        voiceBytes: ByteArray,
        durationMs: Int,
        ephemeralTtlSeconds: Long = 0L
    ): Boolean = withContext(Dispatchers.IO) {
        if (voiceBytes.isEmpty()) return@withContext false
        val totalSegments = ((voiceBytes.size + BinaryFrameCodec.T9_MAX_VOICE_SIZE - 1) / BinaryFrameCodec.T9_MAX_VOICE_SIZE).coerceIn(1, 3)
        val voiceClipId = CryptoUtils.secureRandom.nextLong()

        getGroupMutex(groupId).withLock {
            val group = groupDao?.getGroupById(groupId) ?: return@withLock false
            if (!group.isActive) return@withLock false

            if (group.myCounterOut > 0 && group.myCounterOut % BinaryFrameCodec.GROUP_REKEY_MESSAGE_INTERVAL == 0) {
                rotateGroupSenderKeyInternal(group)
            }
            val currentGroup = groupDao.getGroupById(groupId) ?: group

            val groupIdBytes = uuidStringToBytes(groupId)
            val myMemberIdBytes = uuidStringToBytes(currentGroup.myMemberId)
            val expiresAt = if (ephemeralTtlSeconds > 0L) System.currentTimeMillis() + ephemeralTtlSeconds * 1000L else null

            val initialCounter = currentGroup.myCounterOut
            val seqEpoch = initialCounter / 65536

            val msgId = messageDao.insertMessage(
                MessageEntity(
                    contactId = groupId,
                    isOutgoing = true,
                    seqEpoch = seqEpoch,
                    seqNum = initialCounter,
                    ackNum = 0,
                    timestamp = System.currentTimeMillis(),
                    voiceBytes = voiceBytes,
                    voiceDurationMs = durationMs,
                    status = if (isStrictPoissonShaping()) "QUEUED_POISSON" else "SENT_DHT",
                    senderMemberId = currentGroup.myMemberId,
                    senderName = "Me",
                    ephemeralTtlSeconds = ephemeralTtlSeconds,
                    expiresAtTimestamp = expiresAt
                )
            )

            var currentCounter = initialCounter
            var currentChainKey = currentGroup.rawMyChainKeyOut
            var overallSuccess = false
            val segmentDurationMs = (durationMs / totalSegments).coerceAtLeast(1)

            val activeMembers = groupMemberDao?.getMembersForGroup(groupId)?.filter {
                it.memberId != currentGroup.myMemberId && it.isActive
            } ?: emptyList()

            for (segIdx in 0 until totalSegments) {
                val offset = segIdx * BinaryFrameCodec.T9_MAX_VOICE_SIZE
                val len = (voiceBytes.size - offset).coerceAtMost(BinaryFrameCodec.T9_MAX_VOICE_SIZE)
                val segBytes = voiceBytes.copyOfRange(offset, offset + len)
                val thisSegDuration = if (segIdx == totalSegments - 1) {
                    durationMs - segmentDurationMs * (totalSegments - 1)
                } else {
                    segmentDurationMs
                }

                val baseSlot = RatchetChain.deriveSlot(currentChainKey, currentCounter)
                val targetSlots = if (activeMembers.isNotEmpty()) {
                    activeMembers.map { member ->
                        val recipientMemberIdBytes = uuidStringToBytes(member.memberId)
                        RatchetChain.deriveGroupRecipientSlot(
                            chainKey = currentChainKey,
                            counter = currentCounter,
                            groupId = groupIdBytes,
                            senderMemberId = myMemberIdBytes,
                            recipientMemberId = recipientMemberIdBytes
                        )
                    }
                } else {
                    listOf(baseSlot)
                }

                val plaintext = BinaryFrameCodec.encodeVoiceNote(
                    seqNum = currentCounter and 0xFFFF,
                    ackNum = 0,
                    timestampUTC = System.currentTimeMillis(),
                    voiceClipId = voiceClipId,
                    segmentIndex = segIdx,
                    totalSegments = totalSegments,
                    durationMs = thisSegDuration,
                    codecMode = org.pqchat.dht.media.voice.VoiceCodec.CODEC_MODE_LPC10_COMPACT,
                    ephemeralTtlSeconds = ephemeralTtlSeconds,
                    voiceBytes = segBytes
                )

                currentCounter++
                currentChainKey = baseSlot.nextChainKey

                for ((idx, slot) in targetSlots.withIndex()) {
                    if (idx > 0) {
                        val jitterMs = 40L + (CryptoUtils.secureRandomBytes(1)[0].toInt() and 0x7F)
                        delay(jitterMs)
                    }
                    val frame = BinaryFrameCodec.packGroupAeadFrame(
                        key = slot.msgKey,
                        plaintext = plaintext,
                        target = slot.target,
                        groupId = groupIdBytes,
                        senderMemberId = myMemberIdBytes
                    )
                    val success = dhtLeafNode.putMutable(
                        target = slot.target,
                        v = frame,
                        seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                        salt = null,
                        sk = slot.edPrivateKeySeed,
                        skipLocalStore = false
                    )
                    if (success) {
                        decoyTargetPool.registerPopulatedTarget(slot.target)
                        overallSuccess = true
                    }
                }
            }

            groupDao.updateOutgoingState(
                groupId = groupId,
                counterOut = currentCounter,
                chainKeyOut = EncryptedBlob(currentChainKey, "groups", groupId, "myChainKeyOut"),
                lastActive = System.currentTimeMillis()
            )

            if (overallSuccess) {
                messageDao.updateStatus(msgId, "SENT_DHT")
            }
            overallSuccess
        }
    }

    suspend fun createGroupPoll(
        groupId: String,
        question: String,
        options: List<String>,
        isMultiChoice: Boolean,
        durationHours: Int = 24
    ): String? = withContext(Dispatchers.IO) {
        getGroupMutex(groupId).withLock {
            val group = groupDao?.getGroupById(groupId) ?: return@withLock null
            if (!group.isActive) return@withLock null

            if (group.myCounterOut > 0 && group.myCounterOut % BinaryFrameCodec.GROUP_REKEY_MESSAGE_INTERVAL == 0) {
                rotateGroupSenderKeyInternal(group)
            }
            val currentGroup = groupDao.getGroupById(groupId) ?: group

            val baseSlot = RatchetChain.deriveSlot(currentGroup.rawMyChainKeyOut, currentGroup.myCounterOut)
            val groupIdBytes = uuidStringToBytes(groupId)
            val myMemberIdBytes = uuidStringToBytes(currentGroup.myMemberId)

            val pollUuid = UUID.randomUUID()
            val pollIdBytes = uuidStringToBytes(pollUuid.toString())
            val pollIdStr = pollUuid.toString()
            val expirationTimestamp = System.currentTimeMillis() + durationHours * 3600_000L
            val flags = if (isMultiChoice) BinaryFrameCodec.POLL_FLAG_MULTI_CHOICE else 0.toByte()

            val plaintext = BinaryFrameCodec.encodeGroupPollCreate(
                seqNum = currentGroup.myCounterOut and 0xFFFF,
                ackNum = 0,
                timestampUTC = System.currentTimeMillis(),
                pollId = pollIdBytes,
                expirationTimestamp = expirationTimestamp,
                flags = flags,
                question = question,
                options = options
            )

            val activeMembers = groupMemberDao?.getMembersForGroup(groupId)?.filter {
                it.memberId != currentGroup.myMemberId && it.isActive
            } ?: emptyList()

            val shuffledMembers = if (activeMembers.size > 1) {
                activeMembers.shuffled(CryptoUtils.secureRandom)
            } else {
                activeMembers
            }

            val targetSlots = if (shuffledMembers.isNotEmpty()) {
                shuffledMembers.map { member ->
                    val recipientMemberIdBytes = uuidStringToBytes(member.memberId)
                    RatchetChain.deriveGroupRecipientSlot(
                        chainKey = currentGroup.rawMyChainKeyOut,
                        counter = currentGroup.myCounterOut,
                        groupId = groupIdBytes,
                        senderMemberId = myMemberIdBytes,
                        recipientMemberId = recipientMemberIdBytes
                    )
                }
            } else {
                listOf(baseSlot)
            }

            val optionsJson = org.json.JSONArray(options).toString()
            val pollEntity = PollEntity(
                pollId = pollIdStr,
                groupId = groupId,
                creatorMemberId = currentGroup.myMemberId,
                creatorName = "Me",
                question = question,
                optionsJson = optionsJson,
                isMultiChoice = isMultiChoice,
                expirationTimestamp = expirationTimestamp,
                createdAt = System.currentTimeMillis()
            )
            pollDao?.insertOrUpdatePoll(pollEntity)

            messageDao.insertMessage(
                MessageEntity(
                    contactId = groupId,
                    isOutgoing = true,
                    seqEpoch = currentGroup.myCounterOut / 65536,
                    seqNum = currentGroup.myCounterOut,
                    ackNum = 0,
                    timestamp = System.currentTimeMillis(),
                    textContent = "[Poll] $question",
                    status = if (isStrictPoissonShaping()) "QUEUED_POISSON" else "SENT_DHT",
                    senderMemberId = currentGroup.myMemberId,
                    senderName = "Me",
                    pollId = pollIdStr
                )
            )

            groupDao.updateOutgoingState(
                groupId = groupId,
                counterOut = currentGroup.myCounterOut + 1,
                chainKeyOut = EncryptedBlob(baseSlot.nextChainKey, "groups", groupId, "myChainKeyOut"),
                lastActive = System.currentTimeMillis()
            )

            val outboundFrames = targetSlots.map { slot ->
                val frame = BinaryFrameCodec.packGroupAeadFrame(
                    key = slot.msgKey,
                    plaintext = plaintext,
                    target = slot.target,
                    groupId = groupIdBytes,
                    senderMemberId = myMemberIdBytes
                )
                org.pqchat.dht.traffic.OutboundPoissonFrame(
                    target = slot.target,
                    payload = frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = false,
                    seqNum = currentGroup.myCounterOut,
                    contactId = groupId,
                    timestamp = System.currentTimeMillis(),
                    packetClass = org.pqchat.dht.traffic.PacketClass.GROUP_MESSAGE
                )
            }

            if (isStrictPoissonShaping()) {
                outboundFrames.forEach { outboundPoissonQueue.enqueue(it) }
            } else {
                kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
                    outboundFrames.forEach { frame ->
                        dhtLeafNode.putMutable(
                            target = frame.target,
                            v = frame.payload,
                            seq = frame.seq,
                            salt = frame.salt,
                            sk = frame.sk
                        )
                    }
                }
            }

            pollIdStr
        }
    }

    suspend fun voteGroupPoll(
        groupId: String,
        pollId: String,
        selectedBitmask: Int
    ): Boolean = withContext(Dispatchers.IO) {
        getGroupMutex(groupId).withLock {
            val group = groupDao?.getGroupById(groupId) ?: return@withLock false
            if (!group.isActive) return@withLock false

            val poll = pollDao?.getPoll(pollId) ?: return@withLock false
            if (poll.isClosed || System.currentTimeMillis() > poll.expirationTimestamp) return@withLock false

            if (group.myCounterOut > 0 && group.myCounterOut % BinaryFrameCodec.GROUP_REKEY_MESSAGE_INTERVAL == 0) {
                rotateGroupSenderKeyInternal(group)
            }
            val currentGroup = groupDao.getGroupById(groupId) ?: group

            val baseSlot = RatchetChain.deriveSlot(currentGroup.rawMyChainKeyOut, currentGroup.myCounterOut)
            val groupIdBytes = uuidStringToBytes(groupId)
            val myMemberIdBytes = uuidStringToBytes(currentGroup.myMemberId)
            val pollIdBytes = uuidStringToBytes(pollId)
            val voteTs = System.currentTimeMillis()

            val plaintext = BinaryFrameCodec.encodeGroupPollVote(
                seqNum = currentGroup.myCounterOut and 0xFFFF,
                ackNum = 0,
                timestampUTC = voteTs,
                pollId = pollIdBytes,
                selectedOptionsBitmask = selectedBitmask,
                voteTimestamp = voteTs
            )

            pollDao.insertOrUpdateVote(
                PollVoteEntity(
                    pollId = pollId,
                    memberId = currentGroup.myMemberId,
                    memberName = "Me",
                    selectedBitmask = selectedBitmask,
                    voteTimestamp = voteTs
                )
            )

            val activeMembers = groupMemberDao?.getMembersForGroup(groupId)?.filter {
                it.memberId != currentGroup.myMemberId && it.isActive
            } ?: emptyList()

            val shuffledMembers = if (activeMembers.size > 1) {
                activeMembers.shuffled(CryptoUtils.secureRandom)
            } else {
                activeMembers
            }

            val targetSlots = if (shuffledMembers.isNotEmpty()) {
                shuffledMembers.map { member ->
                    val recipientMemberIdBytes = uuidStringToBytes(member.memberId)
                    RatchetChain.deriveGroupRecipientSlot(
                        chainKey = currentGroup.rawMyChainKeyOut,
                        counter = currentGroup.myCounterOut,
                        groupId = groupIdBytes,
                        senderMemberId = myMemberIdBytes,
                        recipientMemberId = recipientMemberIdBytes
                    )
                }
            } else {
                listOf(baseSlot)
            }

            groupDao.updateOutgoingState(
                groupId = groupId,
                counterOut = currentGroup.myCounterOut + 1,
                chainKeyOut = EncryptedBlob(baseSlot.nextChainKey, "groups", groupId, "myChainKeyOut"),
                lastActive = System.currentTimeMillis()
            )

            val outboundFrames = targetSlots.map { slot ->
                val frame = BinaryFrameCodec.packGroupAeadFrame(
                    key = slot.msgKey,
                    plaintext = plaintext,
                    target = slot.target,
                    groupId = groupIdBytes,
                    senderMemberId = myMemberIdBytes
                )
                org.pqchat.dht.traffic.OutboundPoissonFrame(
                    target = slot.target,
                    payload = frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = slot.edPrivateKeySeed,
                    skipLocalStore = false,
                    seqNum = currentGroup.myCounterOut,
                    contactId = groupId,
                    timestamp = voteTs,
                    packetClass = org.pqchat.dht.traffic.PacketClass.GROUP_MESSAGE
                )
            }

            if (isStrictPoissonShaping()) {
                outboundFrames.forEach { outboundPoissonQueue.enqueue(it) }
            } else {
                kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
                    outboundFrames.forEach { frame ->
                        dhtLeafNode.putMutable(
                            target = frame.target,
                            v = frame.payload,
                            seq = frame.seq,
                            salt = frame.salt,
                            sk = frame.sk
                        )
                    }
                }
            }

            true
        }
    }

    suspend fun rotateGroupSenderKey(groupId: String): Boolean = withContext(Dispatchers.IO) {
        getGroupMutex(groupId).withLock {
            val group = groupDao?.getGroupById(groupId) ?: return@withLock false
            rotateGroupSenderKeyInternal(group)
            true
        }
    }

    private suspend fun rotateGroupSenderKeyInternal(group: GroupEntity) {
        val newChainKeyOut = CryptoUtils.secureRandomBytes(64)
        val newEpoch = group.groupEpoch + 1
        val newCounterOut = 0

        groupDao?.updateRekeyedState(
            groupId = group.groupId,
            epoch = newEpoch,
            counterOut = newCounterOut,
            chainKeyOut = EncryptedBlob(newChainKeyOut, "groups", group.groupId, "myChainKeyOut"),
            lastActive = System.currentTimeMillis()
        )

        val members = groupMemberDao?.getMembersForGroup(group.groupId) ?: emptyList()
        val groupIdBytes = uuidStringToBytes(group.groupId)
        val myMemberIdBytes = uuidStringToBytes(group.myMemberId)

        val eligibleMembers = members.filter {
            it.isActive && it.memberId != group.myMemberId && it.contactId != null
        }.let {
            if (it.size > 1) it.shuffled(CryptoUtils.secureRandom) else it
        }

        val rekeyFrames = mutableListOf<org.pqchat.dht.traffic.OutboundPoissonFrame>()
        for (member in eligibleMembers) {
            val contactId = member.contactId ?: continue
            try {
                sendGroupControlRekeyOrInvite(
                    contactId = contactId,
                    controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_REKEY,
                    groupIdBytes = groupIdBytes,
                    groupEpoch = newEpoch,
                    myMemberIdBytes = myMemberIdBytes,
                    myChainKeyOut = newChainKeyOut,
                    currentCounter = 0L,
                    groupName = group.rawGroupName,
                    outboundCollector = if (isStrictPoissonShaping()) rekeyFrames else null
                )
            } catch (_: Exception) {}
        }
        if (rekeyFrames.isNotEmpty()) {
            outboundPoissonQueue.enqueueInterleaved(rekeyFrames)
        }
    }

    suspend fun leaveGroup(groupId: String): Boolean = withContext(Dispatchers.IO) {
        getGroupMutex(groupId).withLock {
            val group = groupDao?.getGroupById(groupId) ?: return@withLock false
            groupDao.updateActiveStatus(groupId, false)

            val members = groupMemberDao?.getMembersForGroup(groupId) ?: emptyList()
            val groupIdBytes = uuidStringToBytes(groupId)
            val myMemberIdBytes = uuidStringToBytes(group.myMemberId)

            val eligibleMembers = members.filter {
                it.isActive && it.memberId != group.myMemberId && it.contactId != null
            }.let {
                if (it.size > 1) it.shuffled(CryptoUtils.secureRandom) else it
            }

            val leaveFrames = mutableListOf<org.pqchat.dht.traffic.OutboundPoissonFrame>()
            for (member in eligibleMembers) {
                val contactId = member.contactId ?: continue
                try {
                    sendGroupControlRekeyOrInvite(
                        contactId = contactId,
                        controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_LEAVE,
                        groupIdBytes = groupIdBytes,
                        groupEpoch = group.groupEpoch,
                        myMemberIdBytes = myMemberIdBytes,
                        myChainKeyOut = group.rawMyChainKeyOut,
                        currentCounter = group.myCounterOut.toLong(),
                        groupName = group.rawGroupName,
                        outboundCollector = if (isStrictPoissonShaping()) leaveFrames else null
                    )
                } catch (_: Exception) {}
            }
            if (leaveFrames.isNotEmpty()) {
                outboundPoissonQueue.enqueueInterleaved(leaveFrames)
            }
            true
        }
    }

    suspend fun pollGroupIncoming(groupId: String): Boolean = withContext(Dispatchers.IO) {
        getGroupMutex(groupId).withLock {
            val group = groupDao?.getGroupById(groupId) ?: return@withLock false
            val members = groupMemberDao?.getMembersForGroup(groupId) ?: return@withLock false
            val groupIdBytes = uuidStringToBytes(groupId)
            val myMemberIdBytes = uuidStringToBytes(group.myMemberId)
            var anyReceived = false

            for (member in members) {
                if (member.memberId == group.myMemberId) continue
                if (member.rawChainKeyIn.all { it == 0.toByte() }) continue

                var curMember = member
                var consecutive = 0
                while (consecutive < 10) {
                    val memberIdBytes = uuidStringToBytes(curMember.memberId)
                    val baseSlot = RatchetChain.deriveSlot(curMember.rawChainKeyIn, curMember.counterIn)
                    val individualSlot = RatchetChain.deriveGroupRecipientSlot(
                        chainKey = curMember.rawChainKeyIn,
                        counter = curMember.counterIn,
                        groupId = groupIdBytes,
                        senderMemberId = memberIdBytes,
                        recipientMemberId = myMemberIdBytes
                    )

                    // Same-target for all members allows a DHT observer to correlate N recipients via parallel GETs to the same slot, breaking group destination privacy.
                    // Each member queries only their unique target, not a shared one.
                    val item = dhtLeafNode.getMutable(individualSlot.target, skipLocalStore = false) ?: break
                    val activeSlot = individualSlot
                    val isIndividualSlot = true

                    try {
                        val frameMsg = BinaryFrameCodec.unpackGroupAeadFrame(
                            key = activeSlot.msgKey,
                            frame = item.v,
                            target = activeSlot.target,
                            groupId = groupIdBytes,
                            senderMemberId = memberIdBytes
                        )

                        val bitmap = SlidingWindowBitmap(curMember.receivedBitmapBase, 1024, curMember.receivedBitmap)

                        if (!bitmap.isReceived(activeSlot.counter)) {
                            bitmap.markReceived(activeSlot.counter)

                            when (frameMsg.msgType) {
                                BinaryFrameCodec.TYPE_TEXT_MESSAGE -> {
                                    val textPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.TextMessage
                                    val seqEpoch = activeSlot.counter / 65536
                                    val alreadyExists = messageDao.existsMessageWithEpoch(groupId, seqEpoch, activeSlot.counter, false)
                                    if (!alreadyExists) {
                                        messageDao.insertMessage(
                                            MessageEntity(
                                                contactId = groupId,
                                                isOutgoing = false,
                                                seqEpoch = seqEpoch,
                                                seqNum = activeSlot.counter,
                                                ackNum = frameMsg.ackNum,
                                                timestamp = frameMsg.timestampUTC,
                                                textContent = textPayload.text,
                                                status = "DELIVERED",
                                                slotTarget = activeSlot.target,
                                                slotEdSeed = activeSlot.edPrivateKeySeed,
                                                senderMemberId = curMember.memberId,
                                                senderName = curMember.rawMemberName,
                                                ephemeralTtlSeconds = textPayload.ephemeralTtlSeconds,
                                                expiresAtTimestamp = null
                                            )
                                        )
                                        onIncomingMessageDelivered?.invoke(groupId, textPayload.text, false)
                                    }
                                }
                                BinaryFrameCodec.TYPE_REACTION -> {
                                    val reactionPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.Reaction
                                    messageDao.updateMessageReactionAnyDirection(groupId, reactionPayload.targetSeqEpoch, reactionPayload.targetSeqNum, reactionPayload.emoji)
                                }
                                BinaryFrameCodec.TYPE_LOCATION_PIN -> {
                                    val locPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.LocationPin
                                    val seqEpoch = activeSlot.counter / 65536
                                    val alreadyExists = messageDao.existsMessageWithEpoch(groupId, seqEpoch, activeSlot.counter, false)
                                    if (!alreadyExists) {
                                        val locText = org.pqchat.dht.protocol.LocationPinData(
                                            locPayload.latitude,
                                            locPayload.longitude,
                                            locPayload.altitude,
                                            locPayload.accuracy,
                                            locPayload.note
                                        ).toPayloadText()
                                        messageDao.insertMessage(
                                            MessageEntity(
                                                contactId = groupId,
                                                isOutgoing = false,
                                                seqEpoch = seqEpoch,
                                                seqNum = activeSlot.counter,
                                                ackNum = frameMsg.ackNum,
                                                timestamp = frameMsg.timestampUTC,
                                                textContent = locText,
                                                status = "DELIVERED",
                                                slotTarget = activeSlot.target,
                                                slotEdSeed = activeSlot.edPrivateKeySeed,
                                                senderMemberId = curMember.memberId,
                                                senderName = curMember.rawMemberName,
                                                ephemeralTtlSeconds = locPayload.ephemeralTtlSeconds,
                                                expiresAtTimestamp = null
                                            )
                                        )
                                        onIncomingMessageDelivered?.invoke(groupId, locText, false)
                                    }
                                }
                                BinaryFrameCodec.TYPE_VOICE_NOTE -> {
                                    val voicePayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.VoiceNote
                                    val assembled = voiceSegmentAssembler.ingest(voicePayload)
                                    if (assembled != null) {
                                        val seqEpoch = activeSlot.counter / 65536
                                        val alreadyExists = messageDao.existsMessageWithEpoch(groupId, seqEpoch, activeSlot.counter, false)
                                        if (!alreadyExists) {
                                            messageDao.insertMessage(
                                                MessageEntity(
                                                    contactId = groupId,
                                                    isOutgoing = false,
                                                    seqEpoch = seqEpoch,
                                                    seqNum = activeSlot.counter,
                                                    ackNum = frameMsg.ackNum,
                                                    timestamp = frameMsg.timestampUTC,
                                                    voiceBytes = assembled.voiceBytes,
                                                    voiceDurationMs = assembled.totalDurationMs,
                                                    status = "DELIVERED",
                                                    slotTarget = activeSlot.target,
                                                    slotEdSeed = activeSlot.edPrivateKeySeed,
                                                    senderMemberId = curMember.memberId,
                                                    senderName = curMember.rawMemberName,
                                                    ephemeralTtlSeconds = assembled.ephemeralTtlSeconds,
                                                    expiresAtTimestamp = null
                                                )
                                            )
                                            onIncomingMessageDelivered?.invoke(groupId, "Voice Note (${assembled.totalDurationMs / 1000}s)", false)
                                        }
                                    }
                                }
                                BinaryFrameCodec.TYPE_GROUP_POLL -> {
                                    when (val pollPayload = frameMsg.payload) {
                                        is BinaryFrameCodec.DecodedPayload.GroupPollCreate -> {
                                            val pollIdStr = bytesToUuidString(pollPayload.pollId)
                                            val seqEpoch = activeSlot.counter / 65536
                                            val optionsJson = org.json.JSONArray(pollPayload.options).toString()
                                            pollDao?.insertOrUpdatePoll(
                                                PollEntity(
                                                    pollId = pollIdStr,
                                                    groupId = groupId,
                                                    creatorMemberId = curMember.memberId,
                                                    creatorName = curMember.rawMemberName,
                                                    question = pollPayload.question,
                                                    optionsJson = optionsJson,
                                                    isMultiChoice = pollPayload.isMultiChoice,
                                                    expirationTimestamp = pollPayload.expirationTimestamp,
                                                    createdAt = frameMsg.timestampUTC
                                                )
                                            )
                                            val alreadyExists = messageDao.existsMessageWithEpoch(groupId, seqEpoch, activeSlot.counter, false)
                                            if (!alreadyExists) {
                                                messageDao.insertMessage(
                                                    MessageEntity(
                                                        contactId = groupId,
                                                        isOutgoing = false,
                                                        seqEpoch = seqEpoch,
                                                        seqNum = activeSlot.counter,
                                                        ackNum = frameMsg.ackNum,
                                                        timestamp = frameMsg.timestampUTC,
                                                        textContent = "[Poll] ${pollPayload.question}",
                                                        status = "DELIVERED",
                                                        slotTarget = activeSlot.target,
                                                        slotEdSeed = activeSlot.edPrivateKeySeed,
                                                        senderMemberId = curMember.memberId,
                                                        senderName = curMember.rawMemberName,
                                                        pollId = pollIdStr
                                                    )
                                                )
                                                onIncomingMessageDelivered?.invoke(groupId, "[Poll] ${pollPayload.question}", false)
                                            }
                                        }
                                        is BinaryFrameCodec.DecodedPayload.GroupPollVote -> {
                                            val pollIdStr = bytesToUuidString(pollPayload.pollId)
                                            val poll = pollDao?.getPoll(pollIdStr)
                                            if (poll != null && !poll.isClosed && System.currentTimeMillis() <= poll.expirationTimestamp) {
                                                pollDao.insertOrUpdateVote(
                                                    PollVoteEntity(
                                                        pollId = pollIdStr,
                                                        memberId = curMember.memberId,
                                                        memberName = curMember.rawMemberName,
                                                        selectedBitmask = pollPayload.selectedOptionsBitmask,
                                                        voteTimestamp = pollPayload.voteTimestamp
                                                    )
                                                )
                                            }
                                        }
                                        else -> {}
                                    }
                                }
                                else -> {}
                            }
                        }

                        // Advance incoming chain state for this member
                        groupMemberDao.updateMemberIncomingStateWithBitmap(
                            groupId = groupId,
                            memberId = curMember.memberId,
                            counterIn = activeSlot.counter + 1,
                            chainKeyIn = EncryptedBlob(baseSlot.nextChainKey, "group_members", "${groupId}_${curMember.memberId}", "chainKeyIn"),
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )

                        curMember = curMember.copy(
                            counterIn = activeSlot.counter + 1,
                            chainKeyIn = EncryptedBlob(baseSlot.nextChainKey, "group_members", "${groupId}_${curMember.memberId}", "chainKeyIn"),
                            receivedBitmapBase = bitmap.windowBase,
                            receivedBitmap = bitmap.toByteArray()
                        )

                        // For individual recipient slot: safe to overwrite with 900B CSPRNG noise tombstone!
                        // Other group members have their own distinct derived slots so their messages remain intact.
                        if (isIndividualSlot) {
                            try {
                                dhtLeafNode.putMutable(
                                    target = activeSlot.target,
                                    v = BinaryFrameCodec.createTombstonePayload(),
                                    seq = item.seq + 1,
                                    salt = null,
                                    sk = activeSlot.edPrivateKeySeed,
                                    skipLocalStore = false
                                )
                            } catch (_: Exception) {}
                        }

                        anyReceived = true
                        consecutive++
                    } catch (_: Exception) {
                        harvestUndecryptableItem(activeSlot.target, item)
                        break
                    }
                }
            }
            anyReceived
        }
    }

    suspend fun pollAllGroupsIncoming(): List<Boolean> = coroutineScope {
        val groups = groupDao?.getAllActiveGroups() ?: emptyList()
        groups.map { group ->
            async {
                pollGroupIncoming(group.groupId)
            }
        }.awaitAll()
    }

    /**
     * Marks unread ephemeral messages for a contact as read, setting their
     * expiration timestamp based on ephemeralTtlSeconds from the moment of opening/display.
     */
    suspend fun markIncomingMessagesAsRead(contactId: String) = withContext(Dispatchers.IO) {
        val unread = messageDao.getUnreadEphemeralMessagesForContact(contactId)
        val now = System.currentTimeMillis()
        for (msg in unread) {
            val expiresAt = now + msg.ephemeralTtlSeconds * 1000L
            messageDao.markMessageReadAndStartTtl(msg.id, expiresAt)
        }
    }

    /**
     * Purges all expired ephemeral messages:
     * 1. Overwrites encrypted blobs in SQLite with cryptographically secure random bytes
     * 2. Deletes row from SQLite
     * 3. Emits 900-byte CSPRNG Tombstones (seq + 1) to DHT for both slotTarget and ackTarget
     */
    suspend fun purgeExpiredMessages(now: Long = System.currentTimeMillis()): Int = withContext(Dispatchers.IO) {
        val expired = messageDao.getExpiredMessages(now)
        var count = 0
        for (msg in expired) {
            purgeSingleExpiredMessage(msg)
            count++
        }
        count
    }

    suspend fun purgeSingleExpiredMessage(msg: MessageEntity) = withContext(Dispatchers.IO) {
        // 1. Wipe encrypted content in SQLite with cryptographically secure random bytes
        val rowId = MessageEntity.computeMessageRowId(msg.contactId, msg.seqEpoch, msg.seqNum, msg.isOutgoing)
        val noiseText = CryptoUtils.toHex(CryptoUtils.secureRandomBytes(32))
        val noiseBytes = CryptoUtils.secureRandomBytes(64)
        val wipedEncText = EncryptedText(noiseText, "messages", rowId, "textContent")
        val wipedEncBlob = EncryptedBlob(noiseBytes, "messages", rowId, "imageBytes")
        val wipedEncVoice = EncryptedBlob(noiseBytes, "messages", rowId, "voiceBytes")
        messageDao.wipeMessageContent(msg.id, wipedEncText, wipedEncBlob, wipedEncVoice)

        // 2. Delete row from SQLite
        messageDao.deleteMessageById(msg.id)

        // 3. Emit 900-byte CSPRNG Tombstones (seq + 1) to DHT for both slotTarget and ackTarget
        val tombstonePayload = BinaryFrameCodec.createTombstonePayload()
        val isSelf = msg.contactId == SELF_CONTACT_ID

        // Message slot tombstone
        if (msg.slotTarget != null && msg.slotEdSeed != null) {
            try {
                dhtLeafNode.putMutable(
                    target = msg.slotTarget,
                    v = tombstonePayload,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ + 1L,
                    salt = null,
                    sk = msg.slotEdSeed.raw,
                    skipLocalStore = isSelf
                )
            } catch (_: Exception) {}
        }

        // ACK slot tombstone
        if (msg.ackRatchetKey != null) {
            try {
                val ackSeed = org.pqchat.dht.protocol.CoverAckProtocol.deriveAckSeed(msg.ackRatchetKey.raw, "${msg.seqNum}")
                val ackTarget = msg.ackTarget ?: org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(msg.ackRatchetKey.raw, "${msg.seqNum}")
                dhtLeafNode.putMutable(
                    target = ackTarget,
                    v = tombstonePayload,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ + 1L,
                    salt = null,
                    sk = ackSeed,
                    skipLocalStore = isSelf
                )
            } catch (_: Exception) {}
        }
    }
}

