package org.pqchat.dht.ui

import android.content.Context
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.HandshakeManager
import java.lang.reflect.Proxy
import java.security.Security
import java.util.UUID

class ContactRenameAndMediaTest {

    companion object {
        @JvmStatic
        @BeforeAll
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

    private class FakeMessageDao : MessageDao {
        override fun getMessagesForContactFlow(contactId: String): Flow<List<MessageEntity>> = MutableStateFlow(emptyList())
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

    private class FakeChunkDao : org.pqchat.dht.test.BaseFakeChunkDao()

    private fun createRepository(contactDao: ContactDao): ChatRepository {
        return ChatRepository(contactDao, FakeMessageDao(), FakeChunkDao(), DhtLeafNode())
    }

    @Test
    fun testUpdateContactNameInRepositoryAndDao() = runBlocking {
        val contactDao = FakeContactDao()
        val repository = createRepository(contactDao)

        val contactId = UUID.randomUUID().toString()
        val initialContact = ContactEntity(
            id = contactId,
            name = "Bob",
            chainKeyOut = ByteArray(64),
            chainKeyIn = ByteArray(64),
            counterOut = 1,
            counterIn = 2,
            isInitiator = true,
            sas = "1234-5678",
            fingerprint = "AA:BB:CC",
            isVerified = false
        )
        repository.addContact(initialContact)

        assertEquals("Bob", repository.getContact(contactId)?.name)
        assertEquals("Bob", repository.getAllContactsFlow().first().first { it.id == contactId }.name)

        // Rename Bob to "Mój kolega z pracy Bob"
        repository.updateContactName(contactId, "Mój kolega z pracy Bob")

        val updatedContact = repository.getContact(contactId)
        assertNotNull(updatedContact)
        assertEquals("Mój kolega z pracy Bob", updatedContact?.name)
        assertEquals(1, updatedContact?.counterOut)
        assertEquals(2, updatedContact?.counterIn)
        assertEquals("1234-5678", updatedContact?.sas)

        // Flow also reflects new name
        val contactsFromFlow = repository.getAllContactsFlow().first()
        assertEquals("Mój kolega z pracy Bob", contactsFromFlow.first { it.id == contactId }.name)
    }

    @Test
    fun testSasFormatIsStrictEightDigitsWithHyphen() {
        val masterKey = ByteArray(64) { it.toByte() }
        val commitment = ByteArray(32) { (it * 3).toByte() }

        val sas = HandshakeManager.computeSas(masterKey, commitment)
        assertNotNull(sas)
        assertEquals(9, sas.length, "SAS should be 9 characters long: XXXX-XXXX")
        assertTrue(sas.matches(Regex("""\d{4}-\d{4}""")), "SAS must match XXXX-XXXX format: was $sas")
    }

    @Test
    fun testEmptyImageBytesRejectionInGallerySaver() {
        val dummyContext = object : android.content.ContextWrapper(null) {}
        val result = org.pqchat.dht.ui.util.ImageGallerySaver.saveImageToGallery(
            context = dummyContext,
            imageBytes = ByteArray(0)
        )
        assertFalse(result)
    }
}
