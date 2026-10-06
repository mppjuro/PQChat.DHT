package org.pqchat.dht.data.repository

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.Ed25519Engine
import org.pqchat.dht.data.db.*
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.ChunkingEngine
import org.pqchat.dht.protocol.RatchetChain
import org.pqchat.dht.protocol.RekeyCoordinator

class ChatRepository(
    private val database: AppDatabase,
    val dhtLeafNode: DhtLeafNode
) {
    val contactDao = database.contactDao()
    val messageDao = database.messageDao()
    val chunkDao = database.chunkDao()

    fun getAllContactsFlow(): Flow<List<ContactEntity>> = contactDao.getAllContactsFlow()

    fun getMessagesFlow(contactId: String): Flow<List<MessageEntity>> =
        messageDao.getMessagesForContactFlow(contactId)

    suspend fun addContact(contact: ContactEntity) = withContext(Dispatchers.IO) {
        contactDao.insertOrUpdate(contact)
    }

    companion object {
        const val SELF_CONTACT_ID = "self_notes_loopback"
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
     */
    suspend fun sendTextMessage(contactId: String, text: String): Boolean = withContext(Dispatchers.IO) {
        val contact = contactDao.getContactById(contactId) ?: return@withContext false

        // Check if PQC rekey offer is due (every 50 messages)
        if (RekeyCoordinator.shouldOfferRekey(contact.counterOut)) {
            sendRekeyOffer(contact)
        }

        // Derive slot parameters for current counter
        val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)

        // Encode Type 0x02 message
        val plaintext972 = BinaryFrameCodec.encodeTextMessage(
            seqNum = contact.counterOut,
            ackNum = contact.counterIn,
            timestampUTC = System.currentTimeMillis(),
            text = text
        )
        val frame1000 = BinaryFrameCodec.packAeadFrame(slot.msgKey, plaintext972)

        // Debug logging: Outgoing message before and after encryption with PQC & AES breakdown
        org.pqchat.dht.debug.MessageDebugLogger.logOutgoingTextMessage(
            contactId = contactId,
            text = text,
            slot = slot,
            seqNum = contact.counterOut,
            ackNum = contact.counterIn,
            plaintext972 = plaintext972,
            frame900 = frame1000
        )

        // Store message in database
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

        // Put to DHT under Target_i
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
        } else {
            messageDao.updateStatus(msgId, "QUEUED")
        }

        // Advance outgoing chain state
        contactDao.updateOutgoingState(
            id = contactId,
            counterOut = contact.counterOut + 1,
            chainKeyOut = slot.nextChainKey
        )

        if (isSelf && success) {
            delay(2000L)
            pollContactIncoming(contactId)
            val c = contactDao.getContactById(contactId)
            if (c != null && c.counterIn <= contact.counterIn) {
                delay(3000L)
                pollContactIncoming(contactId)
            }
        }

        success
    }

    private suspend fun sendRekeyOffer(contact: ContactEntity) {
        val slot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)
        val newEpoch = contact.rekeyEpoch + 1
        val (pendingOffer, offerFrame) = RekeyCoordinator.createRekeyOffer(
            epoch = newEpoch,
            seqNum = contact.counterOut,
            ackNum = contact.counterIn,
            msgKey = slot.msgKey
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

        dhtLeafNode.putMutable(
            target = slot.target,
            v = offerFrame,
            seq = (contact.counterOut + 1).toLong(),
            salt = null,
            sk = slot.edPrivateKeySeed
        )
    }

    /**
     * Polls DHT for incoming messages in lookahead window [Counter_in, Counter_in + 4].
     */
    suspend fun pollContactIncoming(contactId: String) = withContext(Dispatchers.IO) {
        val contact = contactDao.getContactById(contactId) ?: return@withContext
        val isSelf = contactId == SELF_CONTACT_ID
        val lookaheadSlots = RatchetChain.computeLookaheadSlots(
            startChainKey = contact.chainKeyIn,
            startCounter = contact.counterIn,
            windowSize = 4
        )

        for (slot in lookaheadSlots) {
            val item = dhtLeafNode.getMutable(slot.target, skipLocalStore = isSelf) ?: continue

            try {
                val frameMsg = BinaryFrameCodec.unpackAeadFrame(slot.msgKey, item.v)

                // Debug logging: Incoming message before and after decryption
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
                            }
                        }
                    }

                    BinaryFrameCodec.TYPE_REKEY_OFFER -> {
                        val offerPayload = frameMsg.payload as BinaryFrameCodec.DecodedPayload.RekeyOffer
                        // Process offer and reply in our outgoing channel
                        val outSlot = RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)
                        val (ssRekey, respFrame) = RekeyCoordinator.processOfferAndCreateResponse(
                            offer = offerPayload,
                            reverseSeqNum = contact.counterOut,
                            reverseAckNum = frameMsg.seqNum,
                            reverseMsgKey = outSlot.msgKey
                        )

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

                        // Update our incoming chain with ssRekey
                        val updatedChainIn = RatchetChain.injectRekeySecret(slot.nextChainKey, ssRekey)
                        contactDao.updateIncomingState(contactId, slot.counter + 1, updatedChainIn)
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
                            }
                        }
                    }
                }
            } catch (_: Exception) {
                // If frame fails to decrypt with this slot key, safely skip
            }
        }
    }
}
