package org.pqchat.dht.ui

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.HandshakeManager
import java.security.Security
import java.util.UUID

class HandshakeVerificationTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupBouncyCastle() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private class FakeContactDao : ContactDao {
        val contacts = mutableMapOf<String, ContactEntity>()
        val flow = MutableStateFlow<List<ContactEntity>>(emptyList())

        override fun getAllContactsFlow(): Flow<List<ContactEntity>> = flow
        override suspend fun getContactById(id: String): ContactEntity? = contacts[id]
        override suspend fun insertOrUpdate(contact: ContactEntity) {
            contacts[contact.id] = contact
            flow.value = contacts.values.toList()
        }
        override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob) {}
        override suspend fun updateOutgoingStateAndEpoch(id: String, counterOut: Int, chainKeyOut: EncryptedBlob, rekeyEpoch: Long) {}
        override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {}
        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {}
        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {}
        override suspend fun updateIncomingStateAndEpochWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long, bitmapBase: Int, bitmap: ByteArray) {}
        override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {}

        override suspend fun updateVerifiedStatus(id: String, isVerified: Boolean) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(isVerified = isVerified)
            flow.value = contacts.values.toList()
        }

        override suspend fun deleteContact(id: String) {
            contacts.remove(id)
            flow.value = contacts.values.toList()
        }
    }

    private class FakeMessageDao : MessageDao {
        override fun getMessagesForContactFlow(contactId: String): Flow<List<MessageEntity>> =
            MutableStateFlow(emptyList())
        override suspend fun insertMessage(message: MessageEntity): Long = 1L
        override suspend fun updateStatus(id: Long, status: String) {}
        override suspend fun updateMessageStatusAndSeq(id: Long, status: String, seqNum: Int) {}
        override suspend fun updateMessageRetry(id: Long, status: String, retryCount: Int, timestamp: Long) {}
        override suspend fun getQueuedMessagesForContact(contactId: String): List<MessageEntity> = emptyList()
        override suspend fun getAllQueuedMessages(): List<MessageEntity> = emptyList()
        override suspend fun updateStatusForSeq(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String) {}
        override suspend fun updateMessageStatusAndDirection(contactId: String, seqNum: Int, isOutgoing: Boolean, status: String) {}
        override suspend fun normalizeConfirmedSelfNotes(contactId: String) {}
        override suspend fun deleteMessagesForContact(contactId: String) {}
        override suspend fun existsMessageWithEpoch(contactId: String, seqEpoch: Int, seqNum: Int, isOutgoing: Boolean): Boolean = false
        override suspend fun existsMessage(contactId: String, seqNum: Int, isOutgoing: Boolean): Boolean = false
        override suspend fun getPendingDeliveryMessagesForContact(contactId: String): List<MessageEntity> = emptyList()
        override suspend fun getAllPendingDeliveryMessages(): List<MessageEntity> = emptyList()
    }

    private class FakeChunkDao : ChunkDao {
        override suspend fun insertChunk(chunk: ChunkEntity) {}
        override suspend fun getChunksForTransfer(transferId: String): List<ChunkEntity> = emptyList()
        override suspend fun countChunks(transferId: String): Int = 0
        override suspend fun deleteChunks(transferId: String) {}
    }

    private fun createRepository(contactDao: FakeContactDao): ChatRepository {
        return ChatRepository(contactDao, FakeMessageDao(), FakeChunkDao(), DhtLeafNode())
    }

    @Test
    fun testHandshakeComputesMatchingSasAndAllowsVerification() = runBlocking {
        // 1. Alice creates handshake
        val aliceInit = HandshakeManager.aliceCreateHandshake()
        assertNotNull(aliceInit.qrBytes)
        assertEquals(832, aliceInit.qrBytes.size)

        // 2. Bob processes Alice's QR code
        val bobResult = HandshakeManager.bobProcessQr(aliceInit.qrBytes)
        assertNotNull(bobResult.sas)
        assertEquals(9, bobResult.sas.length)
        assertEquals(8, bobResult.sas.filter { it.isDigit() }.length)

        // 3. Alice receives Bob's frame and finalizes
        val aliceSession = HandshakeManager.aliceFinalize(
            skA = aliceInit.skA,
            pkA = aliceInit.pkA,
            seedInit = aliceInit.seedInit,
            frame = bobResult.frame
        )

        // 4. Assert SAS codes are strictly identical on both devices
        assertEquals(bobResult.sas, aliceSession.sas)
        assertEquals(bobResult.fingerprint, aliceSession.fingerprint)

        // 5. Save contacts on both sides with default isVerified = false
        val contactDaoAlice = FakeContactDao()
        val repoAlice = createRepository(contactDaoAlice)

        val bobContactId = UUID.randomUUID().toString()
        val bobContact = ContactEntity(
            id = bobContactId,
            name = "Bob",
            chainKeyOut = aliceSession.chainKeyOut,
            chainKeyIn = aliceSession.chainKeyIn,
            counterOut = aliceSession.counterOut,
            counterIn = aliceSession.counterIn,
            isInitiator = true,
            sas = aliceSession.sas,
            fingerprint = aliceSession.fingerprint,
            isVerified = false
        )
        repoAlice.addContact(bobContact)

        // Before verification:
        assertFalse(repoAlice.getContact(bobContactId)!!.isVerified)

        // Alice confirms SAS match:
        repoAlice.setContactVerified(bobContactId, true)
        assertTrue(repoAlice.getContact(bobContactId)!!.isVerified)

        // Alice can also toggle/revert verification if needed:
        repoAlice.setContactVerified(bobContactId, false)
        assertFalse(repoAlice.getContact(bobContactId)!!.isVerified)

        repoAlice.setContactVerified(bobContactId, true)
        assertTrue(repoAlice.getContact(bobContactId)!!.isVerified)
    }

    @Test
    fun testMultipleContactsCanBeAddedAndIndependentlyVerified() = runBlocking {
        val contactDao = FakeContactDao()
        val repo = createRepository(contactDao)

        // Add Contact 1: Bob
        val bobId = "contact-bob"
        val bob = ContactEntity(
            id = bobId,
            name = "Bob",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            chainKeyIn = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            counterIn = 0,
            sas = "12345678",
            isVerified = false
        )
        repo.addContact(bob)

        // Add Contact 2: Charlie
        val charlieId = "contact-charlie"
        val charlie = ContactEntity(
            id = charlieId,
            name = "Charlie",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            chainKeyIn = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            counterIn = 0,
            sas = "87654321",
            isVerified = false
        )
        repo.addContact(charlie)

        // Add Contact 3: Dave
        val daveId = "contact-dave"
        val dave = ContactEntity(
            id = daveId,
            name = "Dave",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            chainKeyIn = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            counterIn = 0,
            sas = "11223344",
            isVerified = false
        )
        repo.addContact(dave)

        val allContacts = repo.getAllContactsFlow().first()
        assertEquals(3, allContacts.size)

        // Verify Bob only
        repo.setContactVerified(bobId, true)

        assertTrue(repo.getContact(bobId)!!.isVerified)
        assertFalse(repo.getContact(charlieId)!!.isVerified)
        assertFalse(repo.getContact(daveId)!!.isVerified)

        // Verify Dave only
        repo.setContactVerified(daveId, true)

        assertTrue(repo.getContact(bobId)!!.isVerified)
        assertFalse(repo.getContact(charlieId)!!.isVerified)
        assertTrue(repo.getContact(daveId)!!.isVerified)

        // Flow emits updated state
        val updatedContacts = repo.getAllContactsFlow().first()
        val bobFromFlow = updatedContacts.first { it.id == bobId }
        val charlieFromFlow = updatedContacts.first { it.id == charlieId }
        val daveFromFlow = updatedContacts.first { it.id == daveId }

        assertTrue(bobFromFlow.isVerified)
        assertFalse(charlieFromFlow.isVerified)
        assertTrue(daveFromFlow.isVerified)
    }

    @Test
    fun testHandshakeCompletedStateDataClass() {
        val state = org.pqchat.dht.ui.viewmodel.ChatViewModel.HandshakeCompletedState(
            contactId = "test-id",
            contactName = "Alice",
            sas = "45829103"
        )
        assertEquals("test-id", state.contactId)
        assertEquals("Alice", state.contactName)
        assertEquals("45829103", state.sas)
    }
}
