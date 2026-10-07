package org.pqchat.dht.data.repository

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.crypto.MLKemEngine
import org.pqchat.dht.data.db.*
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.ChunkingEngine
import org.pqchat.dht.protocol.RatchetChain
import org.pqchat.dht.protocol.RekeyCoordinator
import java.util.concurrent.ConcurrentHashMap

class ChatRepository(
    val contactDao: ContactDao,
    val messageDao: MessageDao,
    val chunkDao: ChunkDao,
    val pendingRekeyOfferDao: PendingRekeyOfferDao?,
    val dhtLeafNode: org.pqchat.dht.dht.leaf.DhtClient
) {
    constructor(
        contactDao: ContactDao,
        messageDao: MessageDao,
        chunkDao: ChunkDao,
        dhtLeafNode: org.pqchat.dht.dht.leaf.DhtClient
    ) : this(contactDao, messageDao, chunkDao, null, dhtLeafNode)

    constructor(database: AppDatabase, dhtLeafNode: org.pqchat.dht.dht.leaf.DhtClient) : this(
        database.contactDao(),
        database.messageDao(),
        database.chunkDao(),
        database.pendingRekeyOfferDao(),
        dhtLeafNode
    )

    private val repositoryScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val contactMutexes = ConcurrentHashMap<String, Mutex>()

    fun getContactMutex(contactId: String): Mutex =
        contactMutexes.computeIfAbsent(contactId) { Mutex() }

    fun getAllContactsFlow(): Flow<List<ContactEntity>> = contactDao.getAllContactsFlow()

    fun getMessagesFlow(contactId: String): Flow<List<MessageEntity>> =
        messageDao.getMessagesForContactFlow(contactId)

    suspend fun addContact(contact: ContactEntity) = withContext(Dispatchers.IO) {
        contactDao.insertOrUpdate(contact)
    }

    companion object {
        const val SELF_CONTACT_ID = "self_notes_loopback"

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

    /**
     * Sends a text message to contact via DHT with key hopping and 1000-byte frame.
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
                    messageDao.insertMessage(
                        MessageEntity(
                            contactId = contactId,
                            isOutgoing = true,
                            seqNum = contact.counterOut + remaining.size,
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

            // 5. Encode Type 0x02 message
            val plaintext972 = BinaryFrameCodec.encodeTextMessage(
                seqNum = contact.counterOut,
                ackNum = contact.counterIn,
                timestampUTC = System.currentTimeMillis(),
                text = text
            )
            val frame1000 = BinaryFrameCodec.packAeadFrame(slot.msgKey, plaintext972)

            org.pqchat.dht.debug.MessageDebugLogger.logOutgoingTextMessage(
                contactId = contactId,
                text = text,
                slot = slot,
                seqNum = contact.counterOut,
                ackNum = contact.counterIn,
                plaintext972 = plaintext972,
                frame900 = frame1000
            )

            // 6. Store message in database
            val msgId = messageDao.insertMessage(
                MessageEntity(
                    contactId = contactId,
                    isOutgoing = true,
                    seqNum = contact.counterOut,
                    ackNum = contact.counterIn,
                    timestamp = System.currentTimeMillis(),
                    textContent = text,
                    status = "SENDING"
                )
            )

            val isSelf = contactId == SELF_CONTACT_ID

            // 7. Put to DHT under Target_i
            val success = dhtLeafNode.putMutable(
                target = slot.target,
                v = frame1000,
                seq = (contact.counterOut + 1).toLong(),
                salt = null,
                sk = slot.edPrivateKeySeed,
                skipLocalStore = isSelf
            )

            if (success) {
                messageDao.updateStatus(msgId, "SENT_DHT")
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
                // If put failed, keep message as QUEUED without advancing counterOut
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
                    messageDao.insertMessage(
                        MessageEntity(
                            contactId = contactId,
                            isOutgoing = true,
                            seqNum = contact.counterOut + remaining.size,
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
                seqNum = contact.counterOut,
                ackNum = contact.counterIn
            )

            val msgId = messageDao.insertMessage(
                MessageEntity(
                    contactId = contactId,
                    isOutgoing = true,
                    seqNum = contact.counterOut,
                    ackNum = contact.counterIn,
                    timestamp = System.currentTimeMillis(),
                    textContent = "[Image: ${rawBytes.size / 1024} KB (${chunks.size} chunks)]",
                    imageBytes = rawBytes,
                    status = "SENDING"
                )
            )

            val isSelf = contactId == SELF_CONTACT_ID
            var allSuccess = true
            for (c in chunks) {
                org.pqchat.dht.debug.MessageDebugLogger.logOutgoingChunkData(
                    contactId = contactId,
                    transferId = c.transferId,
                    chunkIndex = c.chunkIndex,
                    totalChunks = c.totalChunks,
                    target = c.target,
                    seq = (c.chunkIndex + 1).toLong(),
                    slotMsgKey = slot.msgKey,
                    frame900 = c.frame1000
                )
                val ok = dhtLeafNode.putMutable(
                    target = c.target,
                    v = c.frame1000,
                    seq = (c.chunkIndex + 1).toLong(),
                    sk = c.edPrivateKeySeed,
                    skipLocalStore = isSelf
                )
                if (!ok) {
                    allSuccess = false
                    break
                }
            }

            if (allSuccess) {
                messageDao.updateStatus(msgId, "SENT_DHT")
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
                // In backoff window, maintain FIFO ordering
                break
            }

            val currentContact = contactDao.getContactById(contactId) ?: break

            // If a rekey offer is pending, wait until response is received
            if (pendingRekeyOfferDao?.getPendingOffer(contactId) != null) {
                break
            }

            // Check if rekey offer is due before sending next message
            if (RekeyCoordinator.shouldOfferRekey(currentContact.counterOut)) {
                sendRekeyOfferInternal(currentContact)
                break
            }

            if (msg.imageBytes != null) {
                val slot = RatchetChain.deriveSlot(currentContact.chainKeyOut, currentContact.counterOut)
                val chunks = ChunkingEngine.splitData(
                    data = msg.imageBytes,
                    currentEdSeed = slot.edPrivateKeySeed,
                    currentMsgKey = slot.msgKey,
                    seqNum = currentContact.counterOut,
                    ackNum = currentContact.counterIn
                )
                var allSuccess = true
                for (c in chunks) {
                    val ok = dhtLeafNode.putMutable(
                        target = c.target,
                        v = c.frame1000,
                        seq = (c.chunkIndex + 1).toLong(),
                        sk = c.edPrivateKeySeed
                    )
                    if (!ok) {
                        allSuccess = false
                        break
                    }
                }
                if (allSuccess) {
                    messageDao.updateMessageStatusAndSeq(msg.id, "SENT_DHT", currentContact.counterOut)
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
            } else if (msg.textContent != null) {
                val slot = RatchetChain.deriveSlot(currentContact.chainKeyOut, currentContact.counterOut)
                val plaintext972 = BinaryFrameCodec.encodeTextMessage(
                    seqNum = currentContact.counterOut,
                    ackNum = currentContact.counterIn,
                    timestampUTC = System.currentTimeMillis(),
                    text = msg.textContent
                )
                val frame1000 = BinaryFrameCodec.packAeadFrame(slot.msgKey, plaintext972)
                val ok = dhtLeafNode.putMutable(
                    target = slot.target,
                    v = frame1000,
                    seq = (currentContact.counterOut + 1).toLong(),
                    salt = null,
                    sk = slot.edPrivateKeySeed
                )
                if (ok) {
                    messageDao.updateMessageStatusAndSeq(msg.id, "SENT_DHT", currentContact.counterOut)
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
        return sentCount
    }

    private suspend fun sendRekeyOfferInternal(contact: ContactEntity): Boolean {
        val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)
        val newEpoch = contact.rekeyEpoch + 1
        val (pendingOffer, offerFrame) = RekeyCoordinator.createRekeyOffer(
            epoch = newEpoch,
            seqNum = contact.counterOut,
            ackNum = contact.counterIn,
            msgKey = slot.msgKey
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
            mlKemPublicKey = pendingOffer.pkNew,
            frame900 = offerFrame
        )

        val success = dhtLeafNode.putMutable(
            target = slot.target,
            v = offerFrame,
            seq = (contact.counterOut + 1).toLong(),
            salt = null,
            sk = slot.edPrivateKeySeed
        )

        if (success) {
            // Rekey offer has its own slot and counter
            contactDao.updateOutgoingState(
                id = contact.id,
                counterOut = contact.counterOut + 1,
                chainKeyOut = slot.nextChainKey
            )
        } else {
            pendingRekeyOfferDao?.deletePendingOffer(contact.id)
        }
        return success
    }

    /**
     * Polls DHT for incoming message for contact.
     * Routine check queries ONLY the current slot counterIn.
     * Protected by per-contact Mutex.
     */
    suspend fun pollContactIncoming(contactId: String): Boolean = withContext(Dispatchers.IO) {
        getContactMutex(contactId).withLock {
            pollContactIncomingInternal(contactId)
        }
    }

    private suspend fun pollContactIncomingInternal(contactId: String): Boolean {
        var contact = contactDao.getContactById(contactId) ?: return false
        val isSelf = contactId == SELF_CONTACT_ID
        var anyProcessed = false

        // 1. Process all available consecutive messages starting at counterIn
        while (true) {
            val currentSlot = RatchetChain.deriveSlot(contact.chainKeyIn, contact.counterIn)
            val item = dhtLeafNode.getMutable(currentSlot.target, skipLocalStore = isSelf) ?: break

            val processed = processIncomingItem(contactId, currentSlot, item, isSelf)
            if (!processed) break
            anyProcessed = true
            contact = contactDao.getContactById(contactId) ?: break
        }

        if (anyProcessed) {
            // Drain outbox if any messages were queued waiting for response
            drainOutboxInternal(contactId, force = true)
            // Trigger asynchronous check of subsequent slots in the lookahead window
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
     */
    suspend fun checkLookaheadWindow(contactId: String) = withContext(Dispatchers.IO) {
        getContactMutex(contactId).withLock {
            val isSelf = contactId == SELF_CONTACT_ID
            var currentContact = contactDao.getContactById(contactId) ?: return@withLock
            var hasMore = true

            while (hasMore) {
                hasMore = false
                val lookaheadSlots = RatchetChain.computeLookaheadSlots(
                    startChainKey = currentContact.chainKeyIn,
                    startCounter = currentContact.counterIn,
                    windowSize = 4
                )

                for (slot in lookaheadSlots) {
                    val item = dhtLeafNode.getMutable(slot.target, skipLocalStore = isSelf) ?: continue
                    val success = processIncomingItem(contactId, slot, item, isSelf)
                    if (success) {
                        val updated = contactDao.getContactById(contactId)
                        if (updated != null && updated.counterIn > currentContact.counterIn) {
                            currentContact = updated
                            hasMore = true
                        }
                    }
                }
            }

            drainOutboxInternal(contactId, force = true)
        }
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
            val frameMsg = BinaryFrameCodec.unpackAeadFrame(slot.msgKey, item.v)

            org.pqchat.dht.debug.MessageDebugLogger.logIncomingMessage(
                contactId = contactId,
                target = slot.target,
                seq = item.seq,
                senderEdPublicKey = item.k,
                senderSignature = item.sig,
                frame900 = item.v,
                frameMsg = frameMsg,
                slotMsgKey = slot.msgKey
            )

            val contact = contactDao.getContactById(contactId) ?: return@withContext false

            when (frameMsg.msgType) {
                BinaryFrameCodec.TYPE_TEXT_MESSAGE -> {
                    val textPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.TextMessage
                    if (isSelf) {
                        messageDao.updateMessageStatusAndDirection(
                            contactId = contactId,
                            seqNum = frameMsg.seqNum,
                            isOutgoing = false,
                            status = "CONFIRMED_DHT"
                        )
                        contactDao.updateIncomingState(
                            id = contactId,
                            counterIn = slot.counter + 1,
                            chainKeyIn = slot.nextChainKey
                        )
                        preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                    } else {
                        val alreadyExists = messageDao.existsMessage(contactId, frameMsg.seqNum, false)
                        if (!alreadyExists) {
                            messageDao.insertMessage(
                                MessageEntity(
                                    contactId = contactId,
                                    isOutgoing = false,
                                    seqNum = frameMsg.seqNum,
                                    ackNum = frameMsg.ackNum,
                                    timestamp = frameMsg.timestampUTC,
                                    textContent = textPayload.text,
                                    status = "DELIVERED"
                                )
                            )

                            // Advance incoming ratchet chain
                            contactDao.updateIncomingState(
                                id = contactId,
                                counterIn = slot.counter + 1,
                                chainKeyIn = slot.nextChainKey
                            )
                            preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                        }
                    }
                    true
                }

                BinaryFrameCodec.TYPE_REKEY_OFFER -> {
                    val offerPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.RekeyOffer

                    // 1. Receiver encapsulates SS_rekey against sender's pk_new
                    val (ssRekey, ctNew) = MLKemEngine.encapsulate(offerPayload.mlKemPublicKey)

                    // 2. Inject SS_rekey into receiver's chainKeyIn
                    val rekeyedChainIn = RatchetChain.injectRekeySecret(slot.nextChainKey, ssRekey)
                    contactDao.updateIncomingStateAndEpoch(contactId, slot.counter + 1, rekeyedChainIn, offerPayload.rekeyEpoch)
                    preWarmNextIncomingTarget(rekeyedChainIn, slot.counter + 1)

                    // 3. Send Type 0x04 Response on receiver's outgoing channel (reverse direction)
                    val outSlot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)
                    val plaintext972 = BinaryFrameCodec.encodeRekeyResponse(
                        seqNum = contact.counterOut,
                        ackNum = frameMsg.seqNum,
                        timestampUTC = System.currentTimeMillis(),
                        rekeyEpoch = offerPayload.rekeyEpoch,
                        mlKemCiphertext = ctNew
                    )
                    val respFrame = BinaryFrameCodec.packAeadFrame(outSlot.msgKey, plaintext972)

                    org.pqchat.dht.debug.MessageDebugLogger.logOutgoingRekeyResponse(
                        contactId = contactId,
                        epoch = offerPayload.rekeyEpoch,
                        slot = outSlot,
                        seqNum = contact.counterOut,
                        ackNum = frameMsg.seqNum,
                        frame900 = respFrame
                    )

                    dhtLeafNode.putMutable(
                        target = outSlot.target,
                        v = respFrame,
                        seq = (contact.counterOut + 1).toLong(),
                        sk = outSlot.edPrivateKeySeed
                    )

                    // Advance reverse outgoing state
                    contactDao.updateOutgoingState(contactId, contact.counterOut + 1, outSlot.nextChainKey)

                    ssRekey.fill(0)
                    true
                }

                BinaryFrameCodec.TYPE_REKEY_RESPONSE -> {
                    val respPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.RekeyResponse
                    val pendingOffer = pendingRekeyOfferDao?.getPendingOffer(contactId)

                    if (pendingOffer != null && pendingOffer.epoch == respPayload.rekeyEpoch) {
                        val ssRekey = MLKemEngine.decapsulate(pendingOffer.skNew, respPayload.mlKemCiphertext)
                        pendingOffer.destroy()
                        pendingRekeyOfferDao?.deletePendingOffer(contactId)

                        // Inject SS_rekey into sender's outgoing chain
                        val rekeyedChainOut = RatchetChain.injectRekeySecret(contact.chainKeyOut, ssRekey)
                        contactDao.updateOutgoingStateAndEpoch(contactId, contact.counterOut, rekeyedChainOut, respPayload.rekeyEpoch)
                        ssRekey.fill(0)
                    }

                    // Advance incoming chain on reverse channel
                    contactDao.updateIncomingState(contactId, slot.counter + 1, slot.nextChainKey)
                    preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                    true
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

                    // If multi-chunk payload, fetch remaining chunks from their derived DHT targets
                    for (j in 1 until chunkPayload.totalChunks) {
                        val subEdSeed = ChunkingEngine.deriveChunkEdSeed(slot.edPrivateKeySeed, chunkPayload.transferId, j)
                        val subKeyPair = Ed25519Engine.generateKeyPairFromSeed(subEdSeed)
                        val subTarget = Ed25519Engine.computeTarget(subKeyPair.publicKey)
                        val subMsgKey = ChunkingEngine.deriveChunkMsgKey(slot.msgKey, j)

                        val subItem = dhtLeafNode.getMutable(subTarget, skipLocalStore = isSelf)
                        if (subItem != null) {
                            try {
                                val subFrame = BinaryFrameCodec.unpackAeadFrame(subMsgKey, subItem.v)
                                org.pqchat.dht.debug.MessageDebugLogger.logIncomingMessage(
                                    contactId = contactId,
                                    target = subTarget,
                                    seq = subItem.seq,
                                    senderEdPublicKey = subItem.k,
                                    senderSignature = subItem.sig,
                                    frame900 = subItem.v,
                                    frameMsg = subFrame,
                                    slotMsgKey = subMsgKey
                                )
                                val subChunk = subFrame.payload as BinaryFrameCodec.DecodedPayload.ChunkData
                                chunkDao.insertChunk(
                                    ChunkEntity(
                                        transferId = transferIdHex,
                                        chunkIndex = subChunk.chunkIndex,
                                        totalChunks = subChunk.totalChunks,
                                        data = subChunk.data
                                    )
                                )
                            } catch (_: Exception) {}
                        }
                    }

                    // Check if complete
                    val count = chunkDao.countChunks(transferIdHex)
                    if (count == chunkPayload.totalChunks) {
                        val allChunks = chunkDao.getChunksForTransfer(transferIdHex)
                        val decodedList = allChunks.map {
                            BinaryFrameCodec.DecodedPayload.ChunkData(
                                transferId = chunkPayload.transferId,
                                chunkIndex = it.chunkIndex,
                                totalChunks = it.totalChunks,
                                data = it.data
                            )
                        }
                        val fullData = ChunkingEngine.assembleChunks(decodedList)
                        chunkDao.deleteChunks(transferIdHex)

                        if (isSelf) {
                            messageDao.updateMessageStatusAndDirection(
                                contactId = contactId,
                                seqNum = frameMsg.seqNum,
                                isOutgoing = false,
                                status = "CONFIRMED_DHT"
                            )
                            contactDao.updateIncomingState(
                                id = contactId,
                                counterIn = slot.counter + 1,
                                chainKeyIn = slot.nextChainKey
                            )
                            preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                        } else {
                            messageDao.insertMessage(
                                MessageEntity(
                                    contactId = contactId,
                                    isOutgoing = false,
                                    seqNum = frameMsg.seqNum,
                                    ackNum = frameMsg.ackNum,
                                    timestamp = frameMsg.timestampUTC,
                                    textContent = "[Image File - ${fullData.size} bytes]",
                                    imageBytes = fullData,
                                    status = "DELIVERED"
                                )
                            )

                            contactDao.updateIncomingState(
                                id = contactId,
                                counterIn = slot.counter + 1,
                                chainKeyIn = slot.nextChainKey
                            )
                            preWarmNextIncomingTarget(slot.nextChainKey, slot.counter + 1)
                        }
                    }
                    true
                }
                else -> false
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun preWarmNextIncomingTarget(chainKeyIn: ByteArray, counterIn: Int) {
        val nextTarget = RatchetChain.getNextExpectedTarget(chainKeyIn, counterIn)
        dhtLeafNode.preWarmTargetAsync(nextTarget)
    }

    /**
     * Polls DHT concurrently for all known contacts using coroutineScope and async/awaitAll.
     */
    suspend fun pollAllContactsIncoming(): List<Boolean> = coroutineScope {
        val contacts = contactDao.getAllContactsFlow().firstOrNull() ?: emptyList()
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
}
