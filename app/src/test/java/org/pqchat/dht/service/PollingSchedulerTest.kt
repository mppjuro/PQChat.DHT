package org.pqchat.dht.service

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.data.db.*
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.traffic.AdaptivePollingManager
import java.security.Security

class PollingSchedulerTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private var scheduler: PollingScheduler? = null

    @After
    fun tearDown() {
        scheduler?.stop()
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

    private fun createTestScheduler(): Pair<PollingScheduler, FakeContactDao> {
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val chunkDao = FakeChunkDao()
        val dhtClient = DhtLeafNode()
        val repository = ChatRepository(contactDao, messageDao, chunkDao, dhtClient)
        val settings = AppSettingsManager(null)

        val sched = PollingScheduler(
            context = null,
            repository = repository,
            dhtLeafNode = dhtClient,
            settingsManager = settings
        )
        scheduler = sched
        return Pair(sched, contactDao)
    }

    @Test
    fun testLifecycleTransitions() {
        val (sched, _) = createTestScheduler()

        sched.onAppForegrounded()
        assertEquals(AdaptivePollingManager.PollingState.APP_ACTIVE_OTHER, sched.pollingManager.currentState.value)
        assertNull(sched.pollingManager.activeChatContactId)

        sched.onChatOpened("alice")
        assertEquals(AdaptivePollingManager.PollingState.FOREGROUND_CHAT, sched.pollingManager.currentState.value)
        assertEquals("alice", sched.pollingManager.activeChatContactId)

        sched.onChatClosed()
        assertEquals(AdaptivePollingManager.PollingState.APP_ACTIVE_OTHER, sched.pollingManager.currentState.value)
        assertNull(sched.pollingManager.activeChatContactId)

        sched.onAppMinimized()
        assertEquals(AdaptivePollingManager.PollingState.BACKGROUND_IDLE, sched.pollingManager.currentState.value)

        sched.onDeviceScreenOff()
        assertEquals(AdaptivePollingManager.PollingState.DOZE_SLEEP, sched.pollingManager.currentState.value)
    }

    @Test
    fun testNotificationSuppressionWhenInSameChat() = runBlocking {
        val (sched, contactDao) = createTestScheduler()
        contactDao.insertOrUpdate(
            ContactEntity(
                id = "alice",
                name = "Alice",
                chainKeyOut = ByteArray(64),
                chainKeyIn = ByteArray(64),
                counterOut = 0,
                counterIn = 0
            )
        )

        var notified = false
        sched.notificationNotifier = { _, _, _ ->
            notified = true
        }

        // User is currently chatting with Alice
        sched.onChatOpened("alice")

        // Incoming message from Alice
        sched.handleIncomingMessageDelivered("alice", "Hello!", false)
        delay(100)

        assertFalse("Notification should NOT fire when user is looking at this chat", notified)
    }

    @Test
    fun testNotificationSentWhenInOtherChatOrBackground() = runBlocking {
        val (sched, contactDao) = createTestScheduler()
        contactDao.insertOrUpdate(
            ContactEntity(
                id = "alice",
                name = "Alice",
                chainKeyOut = ByteArray(64),
                chainKeyIn = ByteArray(64),
                counterOut = 0,
                counterIn = 0
            )
        )

        var notifiedContactId: String? = null
        var notifiedPreview: String? = null
        sched.notificationNotifier = { id, _, preview ->
            notifiedContactId = id
            notifiedPreview = preview
        }

        // User is currently chatting with Bob
        sched.onChatOpened("bob")

        // Incoming message from Alice
        sched.handleIncomingMessageDelivered("alice", "Hey Bob is boring, talk to me", false)
        var waited = 0
        while (notifiedContactId == null && waited < 1000) {
            delay(50)
            waited += 50
        }

        assertEquals("alice", notifiedContactId)
        assertEquals("Hey Bob is boring, talk to me", notifiedPreview)
    }

    @Test
    fun testNotificationSentWhenAppMinimized() = runBlocking {
        val (sched, contactDao) = createTestScheduler()
        contactDao.insertOrUpdate(
            ContactEntity(
                id = "charlie",
                name = "Charlie",
                chainKeyOut = ByteArray(64),
                chainKeyIn = ByteArray(64),
                counterOut = 0,
                counterIn = 0
            )
        )

        var notifiedContact: String? = null
        sched.notificationNotifier = { id, _, _ ->
            notifiedContact = id
        }

        sched.onAppMinimized()
        sched.handleIncomingMessageDelivered("charlie", "Secret quantum message", false)

        var waited = 0
        while (notifiedContact == null && waited < 1000) {
            delay(50)
            waited += 50
        }

        assertEquals("charlie", notifiedContact)
    }

    @Test
    fun testSelfNotesNeverTriggersNotification() = runBlocking {
        val (sched, _) = createTestScheduler()

        var notified = false
        sched.notificationNotifier = { _, _, _ ->
            notified = true
        }

        sched.onAppMinimized()
        // Message to self (DHT loopback test)
        sched.handleIncomingMessageDelivered(ChatRepository.SELF_CONTACT_ID, "Loopback test", false)
        delay(100)

        assertFalse("Self notes should NEVER trigger a system notification", notified)
    }

    @Test
    fun testImageNotificationFormatting() = runBlocking {
        val (sched, contactDao) = createTestScheduler()
        contactDao.insertOrUpdate(
            ContactEntity(
                id = "alice",
                name = "Alice",
                chainKeyOut = ByteArray(64),
                chainKeyIn = ByteArray(64),
                counterOut = 0,
                counterIn = 0
            )
        )

        var notifiedPreview: String? = null
        sched.notificationNotifier = { _, _, preview ->
            notifiedPreview = preview
        }

        sched.onAppMinimized()
        sched.handleIncomingMessageDelivered("alice", "binary data", isImage = true)

        var waited = 0
        while (notifiedPreview == null && waited < 1000) {
            delay(50)
            waited += 50
        }

        assertNotNull(notifiedPreview)
        assertTrue("Image notification should contain image indicator icon", notifiedPreview!!.contains("📷"))
    }
}
