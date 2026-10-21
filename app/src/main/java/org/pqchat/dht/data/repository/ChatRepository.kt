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
    val groupMemberDao: GroupMemberDao? = null
) {
    val researchTelemetry: org.pqchat.dht.research.ResearchTelemetryManager?
        get() = researchTelemetryProvider?.invoke()

    fun isStrictPoissonShaping(): Boolean =
        strictPoissonShapingEnabledProvider?.invoke() ?: isStrictPoissonShapingEnabled

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
        strictPoissonShapingEnabledProvider: (() -> Boolean)? = null
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
        groupMemberDao = database.groupMemberDao()
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

    @Volatile
    var intraBatchJitterMinMs: Long = 20L

    @Volatile
    var intraBatchJitterMaxMs: Long = 80L

    private val repositoryScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val contactMutexes = ConcurrentHashMap<String, Mutex>()
    private val _rekeyInProgressContacts = MutableStateFlow<Set<String>>(emptySet())
    val rekeyInProgressContacts: StateFlow<Set<String>> = _rekeyInProgressContacts.asStateFlow()

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
        groupDao?.getAllGroupsFlow() ?: flowOf(emptyList())

    fun getGroupMembersFlow(groupId: String): Flow<List<GroupMemberEntity>> =
        groupMemberDao?.getMembersForGroupFlow(groupId) ?: flowOf(emptyList())

    suspend fun getGroup(groupId: String): GroupEntity? = withContext(Dispatchers.IO) {
        groupDao?.getGroupById(groupId)
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

    fun getAllContactsFlow(): Flow<List<ContactEntity>> = contactDao.getAllContactsFlow()

    fun getMessagesFlow(contactId: String): Flow<List<MessageEntity>> =
        messageDao.getMessagesForContactFlow(contactId)

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
        val existing = contactDao.getContactById(SELF_CONTACT_ID)
        if (existing == null || existing.chainKeyOut.size != 64 || (existing.counterIn == 0 && existing.counterOut > 0)) {
            val symmetricSeed = CryptoUtils.secureRandomBytes(64)
            messageDao.deleteMessagesForContact(SELF_CONTACT_ID)
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
    suspend fun sendTextMessage(contactId: String, text: String): Boolean = withContext(Dispatchers.IO) {
        getContactMutex(contactId).withLock {
            val contact = contactDao.getContactById(contactId) ?: return@withLock false

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
                            status = "QUEUED"
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
                        status = "QUEUED"
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
                        status = "QUEUED"
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
                text = text
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
                        slotEdSeed = slot.edPrivateKeySeed
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
                    text = msg.textContent.raw
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
                            messageDao.insertMessage(
                                MessageEntity(
                                    contactId = contactId,
                                    isOutgoing = false,
                                    seqEpoch = seqEpoch,
                                    seqNum = sk.slotIndex,
                                    ackNum = frameMsg.ackNum,
                                    timestamp = frameMsg.timestampUTC,
                                    textContent = textPayload.text,
                                    status = "DELIVERED"
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
        try {
            val contact = contactDao.getContactById(contactId) ?: return@withContext false
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
                            messageDao.insertMessage(
                                MessageEntity(
                                    contactId = contactId,
                                    isOutgoing = false,
                                    seqEpoch = seqEpoch,
                                    seqNum = slot.counter,
                                    ackNum = frameMsg.ackNum,
                                    timestamp = frameMsg.timestampUTC,
                                    textContent = textPayload.text,
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
                else -> false
            }
        } catch (_: Exception) {
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
        val timestamp: Long = System.currentTimeMillis()
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
        suspend fun execute(item: DhtLeafNode.MutableItem?): Boolean
    }

    private inner class DecoyPollTask(
        override val target: ByteArray
    ) : PollTask {
        override val isSelf: Boolean = true
        override val seqNum: Long = 0L
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
        override val seqNum: Long
    ) : PollTask {
        override suspend fun execute(item: DhtLeafNode.MutableItem?): Boolean {
            if (item == null) return false
            return getContactMutex(contactId).withLock {
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
        override val seqNum: Long
    ) : PollTask {
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
        override val seqNum: Long
    ) : PollTask {
        override val isSelf: Boolean = false
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
                                        senderMemberId = member.memberId,
                                        senderName = member.memberName
                                    )
                                )
                                onIncomingMessageDelivered?.invoke(groupId, textPayload.text, false)
                            }
                        }
                    }

                    groupMemberDao?.updateMemberIncomingStateWithBitmap(
                        groupId = groupId,
                        memberId = member.memberId,
                        counterIn = slot.counter + 1,
                        chainKeyIn = EncryptedBlob(baseSlot.nextChainKey, "group_members", "${groupId}_${member.memberId}"),
                        bitmapBase = bitmap.windowBase,
                        bitmap = bitmap.toByteArray()
                    )

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

    /**
     * Executes a Constant-Size Decoy-Padded Poll Batch:
     * - Generates a constant budget of [batchSize] (default N_POLL_TARGETS = 8) getMutable queries.
     * - Disguises focused contact/group queries within real/expiring decoy targets from [DecoyTargetPool].
     * - Shuffles all targets in random permutation using CSPRNG.
     * - Applies intra-batch jitter between queries to prevent network observer timing/frequency correlation.
     */
    suspend fun pollConstantBatch(
        focusContactId: String? = null,
        batchSize: Int = pollBatchSize,
        intraBatchJitterMinMs: Long = this.intraBatchJitterMinMs,
        intraBatchJitterMaxMs: Long = this.intraBatchJitterMaxMs
    ): Boolean = withContext(Dispatchers.IO) {
        // 1. Process any pending ACKs for focused contact (or globally)
        checkPendingAcks(focusContactId)

        // 2. Assemble candidate real tasks
        val tasks = mutableListOf<PollTask>()

        if (focusContactId != null) {
            val group = groupDao?.getGroupById(focusContactId)
            if (group != null) {
                val members = groupMemberDao?.getMembersForGroup(focusContactId) ?: emptyList()
                val groupIdBytes = uuidStringToBytes(focusContactId)
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
                            groupId = focusContactId,
                            member = member,
                            slot = individualSlot,
                            baseSlot = baseSlot,
                            isIndividualSlot = true,
                            groupIdBytes = groupIdBytes,
                            memberIdBytes = memberIdBytes,
                            seqNum = member.counterIn.toLong()
                        )
                    )
                }
            } else {
                val contact = contactDao.getContactById(focusContactId)
                if (contact != null) {
                    val isSelf = contact.id == SELF_CONTACT_ID
                    val skipped = skippedKeyDao?.getSkippedKeysForContact(contact.id) ?: emptyList()
                    for (sk in skipped) {
                        tasks.add(
                            SkippedKeyPollTask(
                                target = sk.target,
                                contactId = contact.id,
                                skippedKey = sk,
                                isSelf = isSelf,
                                seqNum = sk.slotIndex.toLong()
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
                            seqNum = contact.counterIn.toLong()
                        )
                    )
                }
            }
        } else {
            // General poll: gather all active contacts and group members
            val contacts = contactDao.getAllContactsFlow().firstOrNull() ?: emptyList()
            for (contact in contacts) {
                val isSelf = contact.id == SELF_CONTACT_ID
                val currentSlot = RatchetChain.deriveSlot(contact.chainKeyIn, contact.counterIn)
                tasks.add(
                    ContactSlotPollTask(
                        target = currentSlot.target,
                        contactId = contact.id,
                        slot = currentSlot,
                        isSelf = isSelf,
                        seqNum = contact.counterIn.toLong()
                    )
                )
            }
            val groups = groupDao?.getAllActiveGroups() ?: emptyList()
            for (group in groups) {
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
                            seqNum = member.counterIn.toLong()
                        )
                    )
                }
            }
        }

        // 3. Constant budget adjustment: take at most batchSize, pad with DecoyTargetPool if fewer
        val finalTasks = if (tasks.size > batchSize) {
            tasks.take(batchSize).toMutableList()
        } else {
            tasks.toMutableList()
        }

        val countNeeded = batchSize - finalTasks.size
        if (countNeeded > 0) {
            val decoyTargets = decoyTargetPool.getDecoyTargets(countNeeded) {
                runBlocking { collectExpiringAndPastTargets(focusContactId) }
            }.toMutableList()

            while (decoyTargets.size < countNeeded) {
                decoyTargets.add(CryptoUtils.sha1(CryptoUtils.secureRandomBytes(32)))
            }

            for (target in decoyTargets.take(countNeeded)) {
                finalTasks.add(DecoyPollTask(target))
            }
        }

        // 4. Random permutation: Fisher-Yates shuffle with CSPRNG
        val shuffledTasks = finalTasks.shuffled(CryptoUtils.secureRandom)

        // 5. Execute batch sequentially with intra-batch jitter
        var anyReceived = false
        for (i in shuffledTasks.indices) {
            val task = shuffledTasks[i]
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
            if (i < shuffledTasks.size - 1 && intraBatchJitterMaxMs > 0L) {
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
                                messageDao.updateMessageForResend(
                                    id = msg.id,
                                    status = newStatus,
                                    seqNum = contact.counterOut,
                                    ackNum = contact.counterIn,
                                    timestamp = System.currentTimeMillis(),
                                    slotTarget = slot.target,
                                    slotEdSeed = org.pqchat.dht.data.db.EncryptedBlob(slot.edPrivateKeySeed, "messages", msg.contactId),
                                    ackTarget = targetAck,
                                    ackRatchetKey = org.pqchat.dht.data.db.EncryptedBlob(slot.msgKey, "messages", msg.contactId),
                                    retryCount = msg.retryCount + 1
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
                messageDao.updateMessageForResend(
                    id = msg.id,
                    status = newStatus,
                    seqNum = contact.counterOut,
                    ackNum = contact.counterIn,
                    timestamp = System.currentTimeMillis(),
                    slotTarget = slot.target,
                    slotEdSeed = org.pqchat.dht.data.db.EncryptedBlob(slot.edPrivateKeySeed, "messages", msg.contactId),
                    ackTarget = targetAck,
                    ackRatchetKey = org.pqchat.dht.data.db.EncryptedBlob(slot.msgKey, "messages", msg.contactId),
                    retryCount = msg.retryCount + 1
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
            val memberName = contact.name
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
            groupName = group.groupName
        )
    }

    suspend fun processIncomingGroupControl(
        contactId: String,
        control: BinaryFrameCodec.DecodedPayload.GroupControl
    ) = withContext(Dispatchers.IO) {
        val groupId = bytesToUuidString(control.groupId)
        val senderMemberId = bytesToUuidString(control.senderMemberId)
        val senderContact = contactDao.getContactById(contactId)
        val senderName = senderContact?.name ?: "Uczestnik"

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
                        chainKeyIn = EncryptedBlob(control.senderGroupChainKey, "group_members", "${groupId}_${senderMemberId}"),
                        counterIn = control.currentCounter.toInt(),
                        isActive = true
                    )
                    groupMemberDao.insertOrUpdate(updated)
                } else if (placeholderMember != null) {
                    groupMemberDao?.deleteMember(groupId, placeholderMember.memberId)
                    val updated = placeholderMember.copy(
                        memberId = senderMemberId,
                        chainKeyIn = EncryptedBlob(control.senderGroupChainKey, "group_members", "${groupId}_${senderMemberId}"),
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

    suspend fun sendGroupMessage(groupId: String, text: String): Boolean = withContext(Dispatchers.IO) {
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

            val plaintext = BinaryFrameCodec.encodeTextMessage(
                seqNum = currentGroup.myCounterOut and 0xFFFF,
                ackNum = 0,
                timestampUTC = System.currentTimeMillis(),
                text = text
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

            // Same-target dla wszystkich członków umożliwia obserwatorowi DHT skorelowanie N odbiorców przez równoległe GET-y na ten sam slot, łamiąc tajność celu komunikacji grupowej.
            // Zamiast jednego target = RatchetChain.deriveSlot(myChainKeyOut, counterOut) używanego dla wszystkich członków,
            // wyprowadzamy unikalny slot dla każdego członka:
            // memberTarget = HKDF-Expand(myChainKeyOut, "group_target:" || groupId || counterOut || memberId, 32)
            // a następnie RatchetChain.deriveSlot z odpowiednim msgKey/edSeed per członek.
            // Wykonujemy osobne putMutable pod każdym unikalnym targetem (N targetów dla N członków).
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
                    senderName = "Ja"
                )
            )

            // Advance sender's ratchet chain using baseSlot.nextChainKey
            groupDao.updateOutgoingState(
                groupId = groupId,
                counterOut = currentGroup.myCounterOut + 1,
                chainKeyOut = EncryptedBlob(baseSlot.nextChainKey, "groups", groupId),
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
            chainKeyOut = EncryptedBlob(newChainKeyOut, "groups", group.groupId),
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
                    groupName = group.groupName,
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
                        groupName = group.groupName,
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

                    // Same-target dla wszystkich członków umożliwia obserwatorowi DHT skorelowanie N odbiorców przez równoległe GET-y na ten sam slot, łamiąc tajność celu komunikacji grupowej.
                    // Każdy członek odpytuje wyłącznie swój unikalny target, a nie wspólny.
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
                                                senderMemberId = curMember.memberId,
                                                senderName = curMember.memberName
                                            )
                                        )
                                        onIncomingMessageDelivered?.invoke(groupId, textPayload.text, false)
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
                            chainKeyIn = EncryptedBlob(baseSlot.nextChainKey, "group_members", "${groupId}_${curMember.memberId}"),
                            bitmapBase = bitmap.windowBase,
                            bitmap = bitmap.toByteArray()
                        )

                        curMember = curMember.copy(
                            counterIn = activeSlot.counter + 1,
                            chainKeyIn = EncryptedBlob(baseSlot.nextChainKey, "group_members", "${groupId}_${curMember.memberId}"),
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
}

