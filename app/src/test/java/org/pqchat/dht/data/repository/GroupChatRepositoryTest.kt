package org.pqchat.dht.data.repository

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.RatchetChain
import org.pqchat.dht.traffic.*
import java.security.Security
import java.util.UUID
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.sqrt

@Tag("slow")
class GroupChatRepositoryTest {

    companion object {
        @JvmStatic
        @BeforeAll
        fun setup() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @BeforeEach
    fun setUp() {
        PollingWorker.clearRepublishTasks()
        BlindRepublishPool.defaultInstance.clear()
        DecoyTargetPool.defaultInstance.clear()
    }

    @AfterEach
    fun tearDown() {
        PollingWorker.clearRepublishTasks()
        BlindRepublishPool.defaultInstance.clear()
        DecoyTargetPool.defaultInstance.clear()
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
        override suspend fun updateIncomingStateWithBitmap(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, bitmapBase: Int, bitmap: ByteArray) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            flow.value = contacts.values.toList()
        }
        override suspend fun updateIncomingStateAndEpoch(id: String, counterIn: Int, chainKeyIn: EncryptedBlob, rekeyEpoch: Long) {
            val c = contacts[id] ?: return
            contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch)
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
            groups[groupId] = g.copy(myCounterOut = counterOut, myChainKeyOut = chainKeyOut, lastActive = lastActive)
            flow.value = groups.values.toList()
        }
        override suspend fun updateRekeyedState(groupId: String, epoch: Long, counterOut: Int, chainKeyOut: EncryptedBlob, lastActive: Long) {
            val g = groups[groupId] ?: return
            groups[groupId] = g.copy(myCounterOut = counterOut, myChainKeyOut = chainKeyOut, groupEpoch = epoch, lastActive = lastActive)
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
        override suspend fun updateMemberIncomingStateWithBitmap(
            groupId: String,
            memberId: String,
            counterIn: Int,
            chainKeyIn: EncryptedBlob,
            bitmapBase: Int,
            bitmap: ByteArray
        ) {
            val m = members[groupId]?.get(memberId) ?: return
            val updated = m.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, receivedBitmapBase = bitmapBase, receivedBitmap = bitmap)
            members[groupId]!![memberId] = updated
            getFlow(groupId).value = members[groupId]!!.values.filter { it.isActive }
        }
        override suspend fun markMemberInactive(groupId: String, memberId: String) {
            val m = members[groupId]?.get(memberId) ?: return
            members[groupId]!![memberId] = m.copy(isActive = false)
            getFlow(groupId).value = members[groupId]!!.values.filter { it.isActive }
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

    @Test
    fun testCreateGroupAndSendInvite() = runBlocking {
        val fakeContactDao = FakeContactDao()
        val fakeMessageDao = FakeMessageDao()
        val fakeChunkDao = FakeChunkDao()
        val fakeGroupDao = FakeGroupDao()
        val fakeGroupMemberDao = FakeGroupMemberDao()
        val dhtNode = FakeDht()

        val repository = ChatRepository(
            contactDao = fakeContactDao,
            messageDao = fakeMessageDao,
            chunkDao = fakeChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = org.pqchat.dht.traffic.PendingAckQueue(),
            groupDao = fakeGroupDao,
            groupMemberDao = fakeGroupMemberDao
        )

        // Setup 1-on-1 contact Bob
        val bobSeedOut = CryptoUtils.secureRandomBytes(64)
        val bobSeedIn = CryptoUtils.secureRandomBytes(64)
        val bobContact = ContactEntity(
            id = "bob-contact-id",
            name = "Bob",
            chainKeyOut = bobSeedOut,
            counterOut = 0,
            chainKeyIn = bobSeedIn,
            counterIn = 0,
            isVerified = true
        )
        fakeContactDao.insertOrUpdate(bobContact)

        // Create group
        val group = repository.createGroup("Cryptographers", listOf("bob-contact-id"))

        // Verify group stored in DB
        val storedGroup = fakeGroupDao.getGroupById(group.groupId)
        assertNotNull("Group must be stored in DB", storedGroup)
        assertEquals("Cryptographers", storedGroup!!.groupName)
        assertEquals(1L, storedGroup.groupEpoch)
        assertEquals(0, storedGroup.myCounterOut)

        // Verify members
        val members = fakeGroupMemberDao.getMembersForGroup(group.groupId)
        assertEquals(2, members.size)
        val selfMember = members.firstOrNull { it.memberId == storedGroup.myMemberId }
        assertNotNull("Self member must exist", selfMember)
        val bobMember = members.firstOrNull { it.contactId == "bob-contact-id" }
        assertNotNull("Bob member must exist", bobMember)

        // Verify that 1-on-1 contact state was stepped (counterOut incremented because invite 0x06 was sent)
        val updatedBobContact = fakeContactDao.getContactById("bob-contact-id")
        assertEquals(1, updatedBobContact!!.counterOut)
    }

    @Test
    fun testSendAndReceiveGroupMessageWithoutTombstone() = runBlocking {
        val dhtNode = FakeDht()

        // 1. Setup Alice Repository (Sender)
        val aliceContactDao = FakeContactDao()
        val aliceMessageDao = FakeMessageDao()
        val aliceChunkDao = FakeChunkDao()
        val aliceGroupDao = FakeGroupDao()
        val aliceGroupMemberDao = FakeGroupMemberDao()

        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = aliceMessageDao,
            chunkDao = aliceChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = org.pqchat.dht.traffic.PendingAckQueue(),
            groupDao = aliceGroupDao,
            groupMemberDao = aliceGroupMemberDao
        )

        // 2. Setup Bob Repository (Recipient)
        val bobContactDao = FakeContactDao()
        val bobMessageDao = FakeMessageDao()
        val bobChunkDao = FakeChunkDao()
        val bobGroupDao = FakeGroupDao()
        val bobGroupMemberDao = FakeGroupMemberDao()

        val bobRepo = ChatRepository(
            contactDao = bobContactDao,
            messageDao = bobMessageDao,
            chunkDao = bobChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = org.pqchat.dht.traffic.PendingAckQueue(),
            groupDao = bobGroupDao,
            groupMemberDao = bobGroupMemberDao
        )

        val groupId = UUID.randomUUID().toString()
        val aliceMemberId = UUID.randomUUID().toString()
        val bobMemberId = UUID.randomUUID().toString()
        val aliceSenderGroupChainKey = CryptoUtils.secureRandomBytes(64)

        // Configure Alice's group entity and Bob in Alice's group members
        val aliceGroup = GroupEntity(
            groupId = groupId,
            groupName = "PQC Group",
            myMemberId = aliceMemberId,
            myChainKeyOut = aliceSenderGroupChainKey,
            myCounterOut = 0,
            groupEpoch = 1L
        )
        aliceGroupDao.insertOrUpdate(aliceGroup)
        aliceGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = bobMemberId,
                contactId = "bob-contact-id",
                memberName = "Bob",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0
            )
        )

        // Configure Bob's group entity and Alice as member in Bob's group_members
        val bobGroup = GroupEntity(
            groupId = groupId,
            groupName = "PQC Group",
            myMemberId = bobMemberId,
            myChainKeyOut = CryptoUtils.secureRandomBytes(64),
            myCounterOut = 0,
            groupEpoch = 1L
        )
        bobGroupDao.insertOrUpdate(bobGroup)

        val aliceInBobGroup = GroupMemberEntity(
            groupId = groupId,
            memberId = aliceMemberId,
            contactId = "alice-contact-id",
            memberName = "Alice",
            chainKeyIn = aliceSenderGroupChainKey,
            counterIn = 0
        )
        bobGroupMemberDao.insertOrUpdate(aliceInBobGroup)

        // 3. Alice sends a group message
        aliceRepo.sendGroupMessage(groupId, "Hello from Alice to the Post-Quantum Group!")

        // Verify Alice's counterOut was incremented
        val updatedAliceGroup = aliceGroupDao.getGroupById(groupId)
        assertEquals(1, updatedAliceGroup!!.myCounterOut)

        // 4. Bob polls incoming messages for this group
        val received = bobRepo.pollGroupIncoming(groupId)
        assertTrue("Bob must receive Alice's message", received)

        // Verify Bob's member record for Alice has counterIn incremented
        val updatedAliceInBob = bobGroupMemberDao.getMember(groupId, aliceMemberId)
        assertEquals(1, updatedAliceInBob!!.counterIn)

        // Verify Bob's message table has the received group message with Alice's memberId and name
        val bobMessages = bobMessageDao.messages
        assertEquals(1, bobMessages.size)
        val bobMsg = bobMessages[0]
        assertEquals("Hello from Alice to the Post-Quantum Group!", bobMsg.rawTextContent)
        assertEquals(groupId, bobMsg.contactId)
        assertEquals(aliceMemberId, bobMsg.senderMemberId)
        assertEquals("Alice", bobMsg.senderName)
        assertFalse(bobMsg.isOutgoing)

        // 5. Verification: DHT record exists under Bob's individual slot
        val bobSlot0 = RatchetChain.deriveGroupRecipientSlot(aliceSenderGroupChainKey, 0, groupId, bobMemberId)
        val dhtRecord = dhtNode.getMutable(bobSlot0.target)
        assertNotNull("DHT record must STILL EXIST after Bob's receive", dhtRecord)
        assertEquals("DHT record must remain 900 bytes", 900, dhtRecord!!.v.size)
    }

    @Test
    fun testGroupEachMemberQueriesDistinctTarget() = runBlocking {
        // Same-target dla wszystkich członków umożliwia obserwatorowi DHT skorelowanie N odbiorców przez równoległe GET-y na ten sam slot, łamiąc tajność celu komunikacji grupowej.
        val dhtNode = FakeDht()

        val aliceContactDao = FakeContactDao()
        val aliceMessageDao = FakeMessageDao()
        val aliceChunkDao = FakeChunkDao()
        val aliceGroupDao = FakeGroupDao()
        val aliceGroupMemberDao = FakeGroupMemberDao()

        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = aliceMessageDao,
            chunkDao = aliceChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = aliceGroupDao,
            groupMemberDao = aliceGroupMemberDao
        )

        val groupId = UUID.randomUUID().toString()
        val aliceMemberId = UUID.randomUUID().toString()
        val bobMemberId = UUID.randomUUID().toString()
        val charlieMemberId = UUID.randomUUID().toString()
        val daveMemberId = UUID.randomUUID().toString()
        val aliceSenderGroupChainKey = CryptoUtils.secureRandomBytes(64)

        // 1. Setup Alice's group entity and 3 active group members (Bob, Charlie, Dave)
        val aliceGroup = GroupEntity(
            groupId = groupId,
            groupName = "3-Member Recipient PQC Group",
            myMemberId = aliceMemberId,
            myChainKeyOut = aliceSenderGroupChainKey,
            myCounterOut = 0,
            groupEpoch = 1L
        )
        aliceGroupDao.insertOrUpdate(aliceGroup)

        aliceGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = bobMemberId,
                contactId = "bob-contact-id",
                memberName = "Bob",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0
            )
        )
        aliceGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = charlieMemberId,
                contactId = "charlie-contact-id",
                memberName = "Charlie",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0
            )
        )
        aliceGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = daveMemberId,
                contactId = "dave-contact-id",
                memberName = "Dave",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0
            )
        )

        // 2. Setup Bob, Charlie, and Dave repositories
        val bobContactDao = FakeContactDao()
        val bobMessageDao = FakeMessageDao()
        val bobChunkDao = FakeChunkDao()
        val bobGroupDao = FakeGroupDao()
        val bobGroupMemberDao = FakeGroupMemberDao()
        val bobRepo = ChatRepository(
            contactDao = bobContactDao,
            messageDao = bobMessageDao,
            chunkDao = bobChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = bobGroupDao,
            groupMemberDao = bobGroupMemberDao
        )
        bobGroupDao.insertOrUpdate(
            GroupEntity(
                groupId = groupId,
                groupName = "3-Member Recipient PQC Group",
                myMemberId = bobMemberId,
                myChainKeyOut = CryptoUtils.secureRandomBytes(64),
                myCounterOut = 0,
                groupEpoch = 1L
            )
        )
        bobGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = aliceMemberId,
                contactId = "alice-contact-id",
                memberName = "Alice",
                chainKeyIn = aliceSenderGroupChainKey,
                counterIn = 0
            )
        )

        val charlieContactDao = FakeContactDao()
        val charlieMessageDao = FakeMessageDao()
        val charlieChunkDao = FakeChunkDao()
        val charlieGroupDao = FakeGroupDao()
        val charlieGroupMemberDao = FakeGroupMemberDao()
        val charlieRepo = ChatRepository(
            contactDao = charlieContactDao,
            messageDao = charlieMessageDao,
            chunkDao = charlieChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = charlieGroupDao,
            groupMemberDao = charlieGroupMemberDao
        )
        charlieGroupDao.insertOrUpdate(
            GroupEntity(
                groupId = groupId,
                groupName = "3-Member Recipient PQC Group",
                myMemberId = charlieMemberId,
                myChainKeyOut = CryptoUtils.secureRandomBytes(64),
                myCounterOut = 0,
                groupEpoch = 1L
            )
        )
        charlieGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = aliceMemberId,
                contactId = "alice-contact-id",
                memberName = "Alice",
                chainKeyIn = aliceSenderGroupChainKey,
                counterIn = 0
            )
        )

        val daveContactDao = FakeContactDao()
        val daveMessageDao = FakeMessageDao()
        val daveChunkDao = FakeChunkDao()
        val daveGroupDao = FakeGroupDao()
        val daveGroupMemberDao = FakeGroupMemberDao()
        val daveRepo = ChatRepository(
            contactDao = daveContactDao,
            messageDao = daveMessageDao,
            chunkDao = daveChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = daveGroupDao,
            groupMemberDao = daveGroupMemberDao
        )
        daveGroupDao.insertOrUpdate(
            GroupEntity(
                groupId = groupId,
                groupName = "3-Member Recipient PQC Group",
                myMemberId = daveMemberId,
                myChainKeyOut = CryptoUtils.secureRandomBytes(64),
                myCounterOut = 0,
                groupEpoch = 1L
            )
        )
        daveGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = aliceMemberId,
                contactId = "alice-contact-id",
                memberName = "Alice",
                chainKeyIn = aliceSenderGroupChainKey,
                counterIn = 0
            )
        )

        // 3. Alice sends one group message
        val broadcastText = "One message to three distinct member targets"
        val sentOk = aliceRepo.sendGroupMessage(groupId, broadcastText)
        assertTrue("Group message send must succeed", sentOk)

        // 4. Verify 3 distinct targets are in dhtNode.storage.keys
        val bobSlot = RatchetChain.deriveGroupRecipientSlot(aliceSenderGroupChainKey, 0, groupId, bobMemberId)
        val charlieSlot = RatchetChain.deriveGroupRecipientSlot(aliceSenderGroupChainKey, 0, groupId, charlieMemberId)
        val daveSlot = RatchetChain.deriveGroupRecipientSlot(aliceSenderGroupChainKey, 0, groupId, daveMemberId)

        val bobTargetHex = CryptoUtils.toHex(bobSlot.target)
        val charlieTargetHex = CryptoUtils.toHex(charlieSlot.target)
        val daveTargetHex = CryptoUtils.toHex(daveSlot.target)

        assertNotEquals("Bob and Charlie targets must differ", bobTargetHex, charlieTargetHex)
        assertNotEquals("Bob and Dave targets must differ", bobTargetHex, daveTargetHex)
        assertNotEquals("Charlie and Dave targets must differ", charlieTargetHex, daveTargetHex)

        assertEquals("DHT storage must contain exactly 3 targets for 3 members", 3, dhtNode.storage.keys.size)
        assertTrue(dhtNode.storage.keys.contains(bobTargetHex))
        assertTrue(dhtNode.storage.keys.contains(charlieTargetHex))
        assertTrue(dhtNode.storage.keys.contains(daveTargetHex))

        // 5. Each target is read by a different member
        val bobReceived = bobRepo.pollGroupIncoming(groupId)
        assertTrue("Bob must receive message from his unique target", bobReceived)
        assertEquals(1, bobMessageDao.messages.size)
        assertEquals(broadcastText, bobMessageDao.messages[0].rawTextContent)

        val charlieReceived = charlieRepo.pollGroupIncoming(groupId)
        assertTrue("Charlie must receive message from his unique target", charlieReceived)
        assertEquals(1, charlieMessageDao.messages.size)
        assertEquals(broadcastText, charlieMessageDao.messages[0].rawTextContent)

        val daveReceived = daveRepo.pollGroupIncoming(groupId)
        assertTrue("Dave must receive message from his unique target", daveReceived)
        assertEquals(1, daveMessageDao.messages.size)
        assertEquals(broadcastText, daveMessageDao.messages[0].rawTextContent)
    }

    @Test
    fun testRotateGroupSenderKey() = runBlocking {
        val fakeContactDao = FakeContactDao()
        val fakeMessageDao = FakeMessageDao()
        val fakeChunkDao = FakeChunkDao()
        val fakeGroupDao = FakeGroupDao()
        val fakeGroupMemberDao = FakeGroupMemberDao()
        val dhtNode = FakeDht()

        val repository = ChatRepository(
            contactDao = fakeContactDao,
            messageDao = fakeMessageDao,
            chunkDao = fakeChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = org.pqchat.dht.traffic.PendingAckQueue(),
            groupDao = fakeGroupDao,
            groupMemberDao = fakeGroupMemberDao
        )

        val bobContact = ContactEntity(
            id = "bob-contact-id",
            name = "Bob",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            chainKeyIn = CryptoUtils.secureRandomBytes(64),
            counterIn = 0,
            isVerified = true
        )
        fakeContactDao.insertOrUpdate(bobContact)

        val group = repository.createGroup("Cryptographers", listOf("bob-contact-id"))
        fakeGroupDao.updateOutgoingState(
            group.groupId,
            49,
            EncryptedBlob(CryptoUtils.secureRandomBytes(64), "groups", group.groupId)
        )

        // Rotate sender key
        repository.rotateGroupSenderKey(group.groupId)

        val rotatedGroup = fakeGroupDao.getGroupById(group.groupId)
        assertEquals("Group epoch must be incremented to 2", 2L, rotatedGroup!!.groupEpoch)
        assertEquals("myCounterOut must be reset to 0 after key rotation", 0, rotatedGroup.myCounterOut)
    }

    @Test
    fun testGroupIndividualRecipientSlotsAndTombstoneIndependence() = runBlocking {
        val dhtNode = FakeDht()

        // 1. Setup Alice Repository (Sender)
        val aliceContactDao = FakeContactDao()
        val aliceMessageDao = FakeMessageDao()
        val aliceChunkDao = FakeChunkDao()
        val aliceGroupDao = FakeGroupDao()
        val aliceGroupMemberDao = FakeGroupMemberDao()

        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = aliceMessageDao,
            chunkDao = aliceChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = aliceGroupDao,
            groupMemberDao = aliceGroupMemberDao
        )

        // 2. Setup Bob Repository (Recipient 1)
        val bobContactDao = FakeContactDao()
        val bobMessageDao = FakeMessageDao()
        val bobChunkDao = FakeChunkDao()
        val bobGroupDao = FakeGroupDao()
        val bobGroupMemberDao = FakeGroupMemberDao()

        val bobRepo = ChatRepository(
            contactDao = bobContactDao,
            messageDao = bobMessageDao,
            chunkDao = bobChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = bobGroupDao,
            groupMemberDao = bobGroupMemberDao
        )

        // 3. Setup Charlie Repository (Recipient 2)
        val charlieContactDao = FakeContactDao()
        val charlieMessageDao = FakeMessageDao()
        val charlieChunkDao = FakeChunkDao()
        val charlieGroupDao = FakeGroupDao()
        val charlieGroupMemberDao = FakeGroupMemberDao()

        val charlieRepo = ChatRepository(
            contactDao = charlieContactDao,
            messageDao = charlieMessageDao,
            chunkDao = charlieChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = charlieGroupDao,
            groupMemberDao = charlieGroupMemberDao
        )

        val groupId = UUID.randomUUID().toString()
        val aliceMemberId = UUID.randomUUID().toString()
        val bobMemberId = UUID.randomUUID().toString()
        val charlieMemberId = UUID.randomUUID().toString()
        val aliceSenderGroupChainKey = CryptoUtils.secureRandomBytes(64)

        // Configure Alice's group entity and member records for Bob & Charlie
        val aliceGroup = GroupEntity(
            groupId = groupId,
            groupName = "Multi-Recipient PQC Group",
            myMemberId = aliceMemberId,
            myChainKeyOut = aliceSenderGroupChainKey,
            myCounterOut = 0,
            groupEpoch = 1L
        )
        aliceGroupDao.insertOrUpdate(aliceGroup)
        aliceGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = bobMemberId,
                contactId = "bob-contact-id",
                memberName = "Bob",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0
            )
        )
        aliceGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = charlieMemberId,
                contactId = "charlie-contact-id",
                memberName = "Charlie",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0
            )
        )

        // Configure Bob's group entity and Alice's inbound chain
        val bobGroup = GroupEntity(
            groupId = groupId,
            groupName = "Multi-Recipient PQC Group",
            myMemberId = bobMemberId,
            myChainKeyOut = CryptoUtils.secureRandomBytes(64),
            myCounterOut = 0,
            groupEpoch = 1L
        )
        bobGroupDao.insertOrUpdate(bobGroup)
        bobGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = aliceMemberId,
                contactId = "alice-contact-id",
                memberName = "Alice",
                chainKeyIn = aliceSenderGroupChainKey,
                counterIn = 0
            )
        )

        // Configure Charlie's group entity and Alice's inbound chain
        val charlieGroup = GroupEntity(
            groupId = groupId,
            groupName = "Multi-Recipient PQC Group",
            myMemberId = charlieMemberId,
            myChainKeyOut = CryptoUtils.secureRandomBytes(64),
            myCounterOut = 0,
            groupEpoch = 1L
        )
        charlieGroupDao.insertOrUpdate(charlieGroup)
        charlieGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = aliceMemberId,
                contactId = "alice-contact-id",
                memberName = "Alice",
                chainKeyIn = aliceSenderGroupChainKey,
                counterIn = 0
            )
        )

        // Verify individual recipient slot derivation gives distinct targets (No Group Follower Correlation)
        val bobExpectedSlot = RatchetChain.deriveGroupRecipientSlot(
            aliceSenderGroupChainKey,
            0,
            groupId,
            aliceMemberId,
            bobMemberId
        )
        val charlieExpectedSlot = RatchetChain.deriveGroupRecipientSlot(
            aliceSenderGroupChainKey,
            0,
            groupId,
            aliceMemberId,
            charlieMemberId
        )
        assertFalse(
            "Individual recipient targets must be completely distinct (Group Follower Correlation eliminated)",
            bobExpectedSlot.target.contentEquals(charlieExpectedSlot.target)
        )

        // Alice sends a group message
        aliceRepo.sendGroupMessage(groupId, "Confidential broadcast to Bob and Charlie")

        // Verify both slots were populated in DHT
        val bobDhtRecordBefore = dhtNode.getMutable(bobExpectedSlot.target)
        val charlieDhtRecordBefore = dhtNode.getMutable(charlieExpectedSlot.target)
        assertNotNull("Bob's individual slot must exist in DHT", bobDhtRecordBefore)
        assertNotNull("Charlie's individual slot must exist in DHT", charlieDhtRecordBefore)
        assertEquals(900, bobDhtRecordBefore!!.v.size)
        assertEquals(900, charlieDhtRecordBefore!!.v.size)

        // Bob polls incoming messages
        val bobReceived = bobRepo.pollGroupIncoming(groupId)
        assertTrue("Bob must receive Alice's message", bobReceived)
        assertEquals(1, bobMessageDao.messages.size)
        assertEquals("Confidential broadcast to Bob and Charlie", bobMessageDao.messages[0].rawTextContent)

        // Verify Bob's slot was tombstoned under seq + 1 with 900 bytes CSPRNG
        val bobDhtRecordAfter = dhtNode.getMutable(bobExpectedSlot.target)
        assertNotNull(bobDhtRecordAfter)
        assertEquals("Bob's slot seq must be incremented to tombstone seq", DhtClient.DEFAULT_MUTABLE_SEQ + 1, bobDhtRecordAfter!!.seq)
        assertEquals(900, bobDhtRecordAfter.v.size)

        // CRITICAL: Verify Charlie's slot was UNTOUCHED by Bob's tombstone!
        val charlieDhtRecordAfter = dhtNode.getMutable(charlieExpectedSlot.target)
        assertNotNull("Charlie's slot must STILL exist with valid ciphertext", charlieDhtRecordAfter)
        assertEquals("Charlie's slot seq must remain original", DhtClient.DEFAULT_MUTABLE_SEQ, charlieDhtRecordAfter!!.seq)
        assertArrayEquals(
            "Charlie's payload must remain intact",
            charlieDhtRecordBefore.v,
            charlieDhtRecordAfter.v
        )

        // Charlie polls incoming messages and successfully receives it as well!
        val charlieReceived = charlieRepo.pollGroupIncoming(groupId)
        assertTrue("Charlie must also receive Alice's message", charlieReceived)
        assertEquals(1, charlieMessageDao.messages.size)
        assertEquals("Confidential broadcast to Bob and Charlie", charlieMessageDao.messages[0].rawTextContent)
    }

    @Test
    fun testGroupAutoRekeyEvery50Messages() = runBlocking {
        val dhtNode = FakeDht()
        val aliceContactDao = FakeContactDao()
        val aliceMessageDao = FakeMessageDao()
        val aliceChunkDao = FakeChunkDao()
        val aliceGroupDao = FakeGroupDao()
        val aliceGroupMemberDao = FakeGroupMemberDao()

        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = aliceMessageDao,
            chunkDao = aliceChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = aliceGroupDao,
            groupMemberDao = aliceGroupMemberDao
        )

        val groupId = UUID.randomUUID().toString()
        val aliceMemberId = UUID.randomUUID().toString()
        val bobMemberId = UUID.randomUUID().toString()
        val initialAliceChainKey = CryptoUtils.secureRandomBytes(64)

        // Setup 1-on-1 channel between Alice and Bob
        val aliceToBobKey = CryptoUtils.secureRandomBytes(64)
        val bobToAliceKey = CryptoUtils.secureRandomBytes(64)
        aliceContactDao.insertOrUpdate(
            ContactEntity(
                id = "bob-contact-id",
                name = "Bob",
                chainKeyOut = aliceToBobKey,
                counterOut = 0,
                chainKeyIn = bobToAliceKey,
                counterIn = 0,
                isVerified = true
            )
        )

        // Setup Alice's group state at counter 50 (should trigger auto-rekey on next message)
        val aliceGroup = GroupEntity(
            groupId = groupId,
            groupName = "Auto-Rekey Group",
            myMemberId = aliceMemberId,
            myChainKeyOut = initialAliceChainKey,
            myCounterOut = 50,
            groupEpoch = 1L
        )
        aliceGroupDao.insertOrUpdate(aliceGroup)
        aliceGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = bobMemberId,
                contactId = "bob-contact-id",
                memberName = "Bob",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0,
                isActive = true
            )
        )

        // Alice sends message 51, which should trigger auto-rekey
        val sent = aliceRepo.sendGroupMessage(groupId, "Message triggering 50-interval rekey")
        assertTrue("Message send must succeed", sent)

        val updatedAliceGroup = aliceGroupDao.getGroupById(groupId)
        assertNotNull(updatedAliceGroup)
        assertEquals("Group epoch must advance to 2", 2L, updatedAliceGroup!!.groupEpoch)
        assertEquals("myCounterOut must be 1 after sending 1 message in new epoch", 1, updatedAliceGroup.myCounterOut)
        assertFalse(
            "Alice's sender chain key must be rotated",
            initialAliceChainKey.contentEquals(updatedAliceGroup.rawMyChainKeyOut)
        )

        // Verify Bob's contact channel counter was stepped because REKEY frame (0x06) was sent
        val aliceBobContact = aliceContactDao.getContactById("bob-contact-id")
        assertNotNull(aliceBobContact)
        assertEquals("Alice must have transmitted REKEY over Bob's 1-on-1 channel", 1, aliceBobContact!!.counterOut)
    }

    @Test
    fun testGroupMemberLeaveForcesAutoRekeyAndPCS() = runBlocking {
        val dhtNode = FakeDht()
        val bobContactDao = FakeContactDao()
        val bobMessageDao = FakeMessageDao()
        val bobChunkDao = FakeChunkDao()
        val bobGroupDao = FakeGroupDao()
        val bobGroupMemberDao = FakeGroupMemberDao()

        val bobRepo = ChatRepository(
            contactDao = bobContactDao,
            messageDao = bobMessageDao,
            chunkDao = bobChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = bobGroupDao,
            groupMemberDao = bobGroupMemberDao
        )

        val groupId = UUID.randomUUID().toString()
        val bobMemberId = UUID.randomUUID().toString()
        val aliceMemberId = UUID.randomUUID().toString()
        val charlieMemberId = UUID.randomUUID().toString()
        val initialBobChainKey = CryptoUtils.secureRandomBytes(64)

        // Setup Bob's contacts: Alice (leaving member) and Charlie (remaining member)
        bobContactDao.insertOrUpdate(
            ContactEntity(
                id = "alice-contact-id",
                name = "Alice",
                chainKeyOut = CryptoUtils.secureRandomBytes(64),
                counterOut = 0,
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0,
                isVerified = true
            )
        )
        bobContactDao.insertOrUpdate(
            ContactEntity(
                id = "charlie-contact-id",
                name = "Charlie",
                chainKeyOut = CryptoUtils.secureRandomBytes(64),
                counterOut = 0,
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0,
                isVerified = true
            )
        )

        // Setup Bob's group state (epoch 1)
        val bobGroup = GroupEntity(
            groupId = groupId,
            groupName = "Forward Secrecy Group",
            myMemberId = bobMemberId,
            myChainKeyOut = initialBobChainKey,
            myCounterOut = 10,
            groupEpoch = 1L
        )
        bobGroupDao.insertOrUpdate(bobGroup)

        // Add Alice and Charlie as members
        bobGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = aliceMemberId,
                contactId = "alice-contact-id",
                memberName = "Alice",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 5,
                isActive = true
            )
        )
        bobGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = charlieMemberId,
                contactId = "charlie-contact-id",
                memberName = "Charlie",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 3,
                isActive = true
            )
        )

        // Simulate incoming GROUP_SUBTYPE_LEAVE control frame from Alice
        val leaveControl = BinaryFrameCodec.DecodedPayload.GroupControl(
            controlSubType = BinaryFrameCodec.GROUP_SUBTYPE_LEAVE,
            groupId = RatchetChain.uuidStringToBytes(groupId),
            groupEpoch = 1L,
            senderMemberId = RatchetChain.uuidStringToBytes(aliceMemberId),
            senderGroupChainKey = ByteArray(64),
            currentCounter = 0L,
            groupName = "Forward Secrecy Group"
        )

        bobRepo.processIncomingGroupControl("alice-contact-id", leaveControl)

        // 1. Verify Alice was marked inactive
        val aliceMember = bobGroupMemberDao.getMember(groupId, aliceMemberId)
        assertNotNull(aliceMember)
        assertFalse("Alice must be marked inactive after LEAVE", aliceMember!!.isActive)

        // 2. Verify Bob's sender key was rotated to new epoch (PCS / Post-Leave Secrecy)
        val updatedBobGroup = bobGroupDao.getGroupById(groupId)
        assertNotNull(updatedBobGroup)
        assertEquals("Group epoch must advance to 2 after member leaves", 2L, updatedBobGroup!!.groupEpoch)
        assertEquals("myCounterOut must be reset to 0 in new epoch", 0, updatedBobGroup.myCounterOut)
        assertFalse(
            "Bob's sender chain key must be rotated to guarantee PCS",
            initialBobChainKey.contentEquals(updatedBobGroup.rawMyChainKeyOut)
        )

        // 3. Verify Charlie received REKEY (counterOut incremented on Charlie's 1-on-1 channel)
        val charlieContact = bobContactDao.getContactById("charlie-contact-id")
        assertNotNull(charlieContact)
        assertEquals("Charlie (remaining active member) must receive REKEY", 1, charlieContact!!.counterOut)

        // 4. CRITICAL: Verify Alice did NOT receive REKEY (counterOut remained 0 on Alice's channel)
        val aliceContact = bobContactDao.getContactById("alice-contact-id")
        assertNotNull(aliceContact)
        assertEquals("Alice (leaving member) must NOT receive REKEY (PCS)", 0, aliceContact!!.counterOut)
    }

    @Test
    fun testGroupChat_StrictPoissonShaping_StatisticalKolmogorovSmirnov() = runBlocking {
        val fakeDht = FakeDht()
        fakeDht.start()
        try {
            val contactDao = FakeContactDao()
            val messageDao = FakeMessageDao()
            val chunkDao = FakeChunkDao()
            val groupDao = FakeGroupDao()
            val groupMemberDao = FakeGroupMemberDao()
            val ackQueue = PendingAckQueue()
            val outboundQueue = OutboundPoissonQueue()
            val republishPool = BlindRepublishPool()

            val repo = ChatRepository(
                contactDao = contactDao,
                messageDao = messageDao,
                chunkDao = chunkDao,
                pendingRekeyOfferDao = null,
                skippedKeyDao = null,
                dhtLeafNode = fakeDht,
                pendingAckQueue = ackQueue,
                outboundPoissonQueue = outboundQueue,
                isStrictPoissonShapingEnabled = true,
                blindRepublishPool = republishPool,
                groupDao = groupDao,
                groupMemberDao = groupMemberDao
            )

            val lambda = 1.0 / 60.0
            val generator = PoissonTrafficGenerator(
                dhtLeafNode = fakeDht,
                lambda = lambda,
                pendingAckQueue = ackQueue,
                blindRepublishPool = republishPool,
                outboundPoissonQueue = outboundQueue,
                random = java.util.Random(505L)
            )

            val contacts = listOf("bob", "charlie", "dave", "eve")
            for (c in contacts) {
                contactDao.insertOrUpdate(
                    ContactEntity(
                        id = c,
                        name = c.replaceFirstChar { it.uppercase() },
                        chainKeyOut = CryptoUtils.secureRandomBytes(64),
                        chainKeyIn = CryptoUtils.secureRandomBytes(64),
                        counterOut = 0,
                        counterIn = 0,
                        isVerified = true
                    )
                )
            }

            val n = 200
            val intervalsBaseline = DoubleArray(n) { generator.computeNextIntervalMs(lambda).toDouble() }

            // 1. Create 5-person group -> Queues 4 TYPE_GROUP_CONTROL INVITE frames (0x06)
            val group = repo.createGroup("Quantum Research Group", contacts)

            // 2. Send multi-chunk image (~6000 bytes -> ~8 chunks) -> Queues TYPE_CHUNK_DATA frames (0x05)
            repo.sendImagePayload("bob", CryptoUtils.secureRandomBytes(6000))

            // 3. Send group message to 4 members -> Queues 4 TYPE_GROUP_MESSAGE frames (0x02)
            repo.sendGroupMessage(group.groupId, "Quantum-resistant group announcement")

            // Verify queue absorbed all bursts (4 invites + 8 image chunks + 4 group messages = 16 frames)
            assertTrue("Outbound queue must absorb burst without direct emission (size >= 12)", outboundQueue.size >= 12)

            // Sample emission intervals under active burst traffic
            val intervalsActive = DoubleArray(n)
            for (i in 0 until n) {
                intervalsActive[i] = generator.computeNextIntervalMs(lambda).toDouble()
                val event = generator.processCoverTrafficTick(delayMs = intervalsActive[i].toLong())
                assertNotNull(event)
                assertEquals(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES, event.payloadSize)
            }

            // Two-sample Kolmogorov-Smirnov test at alpha = 0.05
            val dTwoSample = computeTwoSampleKsStatistic(intervalsActive, intervalsBaseline)
            val dTwoCrit = 1.36 * sqrt((2.0 * n) / (n.toDouble() * n))
            assertTrue(
                "Two-sample KS statistic D ($dTwoSample) must be < D_crit ($dTwoCrit) at alpha=0.05 (p > 0.05)",
                dTwoSample < dTwoCrit
            )

            // One-sample Kolmogorov-Smirnov test against theoretical exponential distribution
            val dOneSample = computeOneSampleKsStatistic(intervalsActive, lambda)
            val dOneCrit = 1.36 / sqrt(n.toDouble())
            assertTrue(
                "One-sample KS statistic D ($dOneSample) must be < D_crit ($dOneCrit) at alpha=0.05 (p > 0.05)",
                dOneSample < dOneCrit
            )
        } finally {
            fakeDht.stop()
        }
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

    private fun computeOneSampleKsStatistic(sample: DoubleArray, lambda: Double): Double {
        val n = sample.size
        val sorted = sample.sortedArray()
        var maxDiff = 0.0
        for (i in 0 until n) {
            val x = sorted[i]
            val theoreticalCdf = 1.0 - exp(-lambda * (x / 1000.0))
            val empiricalPlus = (i + 1).toDouble() / n
            val empiricalMinus = i.toDouble() / n
            val diffPlus = abs(empiricalPlus - theoreticalCdf)
            val diffMinus = abs(theoreticalCdf - empiricalMinus)
            if (diffPlus > maxDiff) maxDiff = diffPlus
            if (diffMinus > maxDiff) maxDiff = diffMinus
        }
        return maxDiff
    }

    @Test
    fun testGroupFanOutBurstInterleavingAndPermutation() {
        val queue = OutboundPoissonQueue()

        // 1. Pre-populate queue with 4 background frames (e.g. decoy/republish/dummy)
        val bgFrames = (1..4).map { i ->
            OutboundPoissonFrame(
                target = CryptoUtils.secureRandomBytes(20),
                payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES),
                sk = CryptoUtils.secureRandomBytes(32),
                seqNum = i
            )
        }
        for (f in bgFrames) {
            queue.enqueue(f)
        }
        assertEquals(4, queue.size)

        // 2. Interleave 3 group message frames
        val groupFrames = (1..3).map { i ->
            OutboundPoissonFrame(
                target = CryptoUtils.secureRandomBytes(20),
                payload = CryptoUtils.secureRandomBytes(BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES),
                sk = CryptoUtils.secureRandomBytes(32),
                seqNum = 100 + i
            )
        }
        queue.enqueueInterleaved(groupFrames)

        // Total size must be 4 + 3 = 7 frames
        assertEquals(7, queue.size)
        val allEnqueued = queue.getAll()

        // Check that group frames are interleaved, NOT all clustered at the end
        val groupIndices = allEnqueued.mapIndexedNotNull { index, frame ->
            if (frame.seqNum >= 100) index else null
        }
        assertEquals(3, groupIndices.size)

        // The group frames should not all be contiguous at the end (indices 4, 5, 6)
        val areAllAtEnd = groupIndices == listOf(4, 5, 6)
        assertFalse("Group frames must be interleaved across existing queue items to eliminate bursts", areAllAtEnd)
    }

    @Test
    fun testGroupControlCoverAckAndRepublishLifecycle() = runBlocking {
        val dhtNode = FakeDht()
        val aliceContactDao = FakeContactDao()
        val aliceMessageDao = FakeMessageDao()
        val aliceChunkDao = FakeChunkDao()
        val aliceGroupDao = FakeGroupDao()
        val aliceGroupMemberDao = FakeGroupMemberDao()
        val aliceAckQueue = PendingAckQueue()

        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = aliceMessageDao,
            chunkDao = aliceChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = aliceAckQueue,
            groupDao = aliceGroupDao,
            groupMemberDao = aliceGroupMemberDao
        )

        val bobContactDao = FakeContactDao()
        val bobMessageDao = FakeMessageDao()
        val bobChunkDao = FakeChunkDao()
        val bobGroupDao = FakeGroupDao()
        val bobGroupMemberDao = FakeGroupMemberDao()
        val bobAckQueue = PendingAckQueue()

        val bobRepo = ChatRepository(
            contactDao = bobContactDao,
            messageDao = bobMessageDao,
            chunkDao = bobChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = bobAckQueue,
            groupDao = bobGroupDao,
            groupMemberDao = bobGroupMemberDao
        )

        // Setup 1-on-1 channel between Alice and Bob
        val aliceToBobKey = CryptoUtils.secureRandomBytes(64)
        val bobToAliceKey = CryptoUtils.secureRandomBytes(64)

        aliceContactDao.insertOrUpdate(
            ContactEntity(
                id = "bob-contact-id",
                name = "Bob",
                chainKeyOut = aliceToBobKey,
                counterOut = 0,
                chainKeyIn = bobToAliceKey,
                counterIn = 0,
                isVerified = true
            )
        )
        bobContactDao.insertOrUpdate(
            ContactEntity(
                id = "alice-contact-id",
                name = "Alice",
                chainKeyOut = bobToAliceKey,
                counterOut = 0,
                chainKeyIn = aliceToBobKey,
                counterIn = 0,
                isInitiator = false,
                isVerified = true
            )
        )

        // 1. Alice creates group and invites Bob
        val group = aliceRepo.createGroup("Cryptographers Club", listOf("bob-contact-id"))

        // Verify Alice registered a republish task for Bob's invite frame
        val republishTasks = PollingWorker.getRegisteredRepublishTasks()
        val bobInviteTask = republishTasks.firstOrNull { it.contactId == "bob-contact-id" }
        assertNotNull("Alice must register a RepublishTask for the unacknowledged invite", bobInviteTask)

        val pendingControls = aliceRepo.getPendingGroupControls()
        assertEquals(1, pendingControls.size)
        val pendingControl = pendingControls[0]
        assertEquals("bob-contact-id", pendingControl.contactId)
        assertEquals(BinaryFrameCodec.GROUP_SUBTYPE_INVITE, pendingControl.controlSubType)

        // 2. Bob polls his incoming 1-on-1 channel from Alice
        val received = bobRepo.pollContactIncoming("alice-contact-id")
        assertTrue("Bob must receive Alice's invite frame", received)

        // Verify Bob queued a Cover-ACK for Alice's control frame
        assertEquals("Bob must queue a Cover-ACK upon receiving TYPE_GROUP_CONTROL", 1, bobAckQueue.size)
        val bobPendingAck = bobAckQueue.poll()
        assertNotNull(bobPendingAck)

        // 3. Bob emits the Cover-ACK packet to DHT
        val ackFrame = org.pqchat.dht.protocol.CoverAckProtocol.createAckPayload(bobPendingAck!!.ratchetKey, bobPendingAck.messageId, bobPendingAck.seqNum)
        val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(bobPendingAck.ratchetKey, bobPendingAck.messageId)
        val ackEdSeed = org.pqchat.dht.protocol.CoverAckProtocol.deriveAckSeed(bobPendingAck.ratchetKey, bobPendingAck.messageId)
        dhtNode.putMutable(targetAck, ackFrame, DhtClient.DEFAULT_MUTABLE_SEQ, null, ackEdSeed)

        val ackDhtRecord = dhtNode.getMutable(targetAck)
        assertNotNull("Bob's Cover-ACK must exist in DHT", ackDhtRecord)

        // 4. Alice checks pending ACKs for Bob
        aliceRepo.checkPendingAcks("bob-contact-id")

        // 5. Verify Alice confirmed the control frame, removed the republish task, and tombstoned the ACK
        val remainingControls = aliceRepo.getPendingGroupControls().filter { it.contactId == "bob-contact-id" }
        assertTrue("Pending control record must now be removed upon confirmation", remainingControls.isEmpty())
        val remainingTasks = PollingWorker.getRegisteredRepublishTasks()
        assertNull("Republish task must be unregistered after Cover-ACK confirmation", remainingTasks.firstOrNull { it.messageId == bobInviteTask!!.messageId })

        val transmissionDhtRecordAfter = dhtNode.getMutable(bobInviteTask!!.target)
        assertNotNull(transmissionDhtRecordAfter)
        assertEquals("Alice must have tombstoned the transmission slot", DhtClient.DEFAULT_MUTABLE_SEQ + 1, transmissionDhtRecordAfter!!.seq)
    }

    @Test
    fun testOfflineMemberRekeyPacketLossAndRetransmissionCatchUp() = runBlocking {
        val dhtNode = FakeDht()

        // 1. Alice setup
        val aliceContactDao = FakeContactDao()
        val aliceMessageDao = FakeMessageDao()
        val aliceChunkDao = FakeChunkDao()
        val aliceGroupDao = FakeGroupDao()
        val aliceGroupMemberDao = FakeGroupMemberDao()
        val aliceAckQueue = PendingAckQueue()

        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = aliceMessageDao,
            chunkDao = aliceChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = aliceAckQueue,
            groupDao = aliceGroupDao,
            groupMemberDao = aliceGroupMemberDao
        )

        // 2. Charlie setup (will simulate being offline during rekey)
        val charlieContactDao = FakeContactDao()
        val charlieMessageDao = FakeMessageDao()
        val charlieChunkDao = FakeChunkDao()
        val charlieGroupDao = FakeGroupDao()
        val charlieGroupMemberDao = FakeGroupMemberDao()
        val charlieAckQueue = PendingAckQueue()

        val charlieRepo = ChatRepository(
            contactDao = charlieContactDao,
            messageDao = charlieMessageDao,
            chunkDao = charlieChunkDao,
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = charlieAckQueue,
            groupDao = charlieGroupDao,
            groupMemberDao = charlieGroupMemberDao
        )

        val groupId = UUID.randomUUID().toString()
        val aliceMemberId = UUID.randomUUID().toString()
        val charlieMemberId = UUID.randomUUID().toString()

        val aliceToCharlieKey = CryptoUtils.secureRandomBytes(64)
        val charlieToAliceKey = CryptoUtils.secureRandomBytes(64)
        val initialAliceGroupKey = CryptoUtils.secureRandomBytes(64)

        aliceContactDao.insertOrUpdate(
            ContactEntity(
                id = "charlie-contact-id",
                name = "Charlie",
                chainKeyOut = aliceToCharlieKey,
                counterOut = 0,
                chainKeyIn = charlieToAliceKey,
                counterIn = 0,
                isVerified = true
            )
        )
        charlieContactDao.insertOrUpdate(
            ContactEntity(
                id = "alice-contact-id",
                name = "Alice",
                chainKeyOut = charlieToAliceKey,
                counterOut = 0,
                chainKeyIn = aliceToCharlieKey,
                counterIn = 0,
                isInitiator = false,
                isVerified = true
            )
        )

        // Both Alice and Charlie have the group in Epoch 1
        aliceGroupDao.insertOrUpdate(
            GroupEntity(
                groupId = groupId,
                groupName = "Resilient Group",
                myMemberId = aliceMemberId,
                myChainKeyOut = initialAliceGroupKey,
                myCounterOut = 0,
                groupEpoch = 1L
            )
        )
        aliceGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = charlieMemberId,
                contactId = "charlie-contact-id",
                memberName = "Charlie",
                chainKeyIn = CryptoUtils.secureRandomBytes(64),
                counterIn = 0,
                isActive = true
            )
        )

        charlieGroupDao.insertOrUpdate(
            GroupEntity(
                groupId = groupId,
                groupName = "Resilient Group",
                myMemberId = charlieMemberId,
                myChainKeyOut = CryptoUtils.secureRandomBytes(64),
                myCounterOut = 0,
                groupEpoch = 1L
            )
        )
        charlieGroupMemberDao.insertOrUpdate(
            GroupMemberEntity(
                groupId = groupId,
                memberId = aliceMemberId,
                contactId = "alice-contact-id",
                memberName = "Alice",
                chainKeyIn = initialAliceGroupKey,
                counterIn = 0,
                isActive = true
            )
        )

        // 3. Alice rotates sender key to Epoch 2
        aliceRepo.rotateGroupSenderKey(groupId)

        val aliceGroupEpoch2 = aliceGroupDao.getGroupById(groupId)
        assertEquals(2L, aliceGroupEpoch2!!.groupEpoch)

        // Simulate Charlie was offline: the packet on DHT expired or was dropped
        // Charlie's slot 0 on 1-on-1 channel was not consumed, or dropped:
        val charlieSlot0 = RatchetChain.deriveSlot(aliceToCharlieKey, 0)
        // Corrupt or remove slot 0 from DHT to simulate packet loss / TTL expiry while Charlie was offline
        dhtNode.storage.remove(CryptoUtils.toHex(charlieSlot0.target))

        // Charlie tries to poll while missing the rekey: nothing received
        val charlieReceivedBeforeCatchup = charlieRepo.pollContactIncoming("alice-contact-id")
        assertFalse("Charlie receives nothing because rekey packet was lost/expired", charlieReceivedBeforeCatchup)

        // 4. Epoch Catch-up mechanism: Alice detects unconfirmed rekey and retransmits
        val unconfirmedControls = aliceRepo.getPendingGroupControls().filter { it.contactId == "charlie-contact-id" }
        assertEquals(1, unconfirmedControls.size)

        // Alice retransmits rekey specifically to Charlie
        val retransmitOk = aliceRepo.retransmitGroupRekeyToOfflineMember(groupId, "charlie-contact-id")
        assertTrue("Retransmission to offline member must succeed", retransmitOk)

        // 5. Charlie returns online and polls his incoming channel: successfully consumes retransmitted REKEY frame!
        val charlieReceivedAfterRetransmit = charlieRepo.pollContactIncoming("alice-contact-id")
        assertTrue("Charlie must successfully receive retransmitted REKEY frame", charlieReceivedAfterRetransmit)

        // Verify Charlie's incoming chain for Alice has been updated to Alice's new Epoch 2 chain key!
        val charlieAliceMember = charlieGroupMemberDao.getMember(groupId, aliceMemberId)
        assertNotNull(charlieAliceMember)
        assertArrayEquals(
            "Charlie's incoming chain for Alice must match Alice's new Epoch 2 key",
            aliceGroupEpoch2.rawMyChainKeyOut,
            charlieAliceMember!!.rawChainKeyIn
        )
        assertEquals(0, charlieAliceMember.counterIn)

        // Verify Charlie emitted Cover-ACK for the rekey
        assertEquals(1, charlieAckQueue.size)
        val charlieAck = charlieAckQueue.poll()!!

        // Charlie puts ACK on DHT
        val ackFrame = org.pqchat.dht.protocol.CoverAckProtocol.createAckPayload(charlieAck.ratchetKey, charlieAck.messageId, charlieAck.seqNum)
        val targetAck = org.pqchat.dht.protocol.CoverAckProtocol.computeAckTarget(charlieAck.ratchetKey, charlieAck.messageId)
        val ackEdSeed = org.pqchat.dht.protocol.CoverAckProtocol.deriveAckSeed(charlieAck.ratchetKey, charlieAck.messageId)
        dhtNode.putMutable(targetAck, ackFrame, DhtClient.DEFAULT_MUTABLE_SEQ, null, ackEdSeed)

        // Alice checks ACKs: confirms Charlie's synchronization!
        aliceRepo.checkPendingAcks("charlie-contact-id")
        val confirmedControls = aliceRepo.getPendingGroupControls().filter { it.contactId == "charlie-contact-id" }
        assertTrue("Alice must confirm Charlie's retransmission Cover-ACK (removed from pending)", confirmedControls.isEmpty())

        // 6. Verification: Alice sends an Epoch 2 group message, and Charlie receives it!
        val sentGroupMsgOk = aliceRepo.sendGroupMessage(groupId, "Welcome back online Charlie! Epoch 2 message.")
        assertTrue("Alice sends group message in epoch 2", sentGroupMsgOk)

        val charlieGotGroupMsg = charlieRepo.pollGroupIncoming(groupId)
        assertTrue("Charlie must now successfully decrypt Alice's Epoch 2 group message", charlieGotGroupMsg)
        assertEquals(1, charlieMessageDao.messages.size)
        assertEquals("Welcome back online Charlie! Epoch 2 message.", charlieMessageDao.messages[0].rawTextContent)
    }
}
