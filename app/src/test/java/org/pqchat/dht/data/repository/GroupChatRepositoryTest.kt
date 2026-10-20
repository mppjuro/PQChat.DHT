package org.pqchat.dht.data.repository

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.RatchetChain
import java.security.Security
import java.util.UUID

class GroupChatRepositoryTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setup() {
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
        val dhtNode = DhtLeafNode()

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
        val dhtNode = DhtLeafNode()

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

        // Configure Alice's group entity
        val aliceGroup = GroupEntity(
            groupId = groupId,
            groupName = "PQC Group",
            myMemberId = aliceMemberId,
            myChainKeyOut = aliceSenderGroupChainKey,
            myCounterOut = 0,
            groupEpoch = 1L
        )
        aliceGroupDao.insertOrUpdate(aliceGroup)

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

        // 5. CRITICAL REQUIREMENT VERIFICATION:
        // Group messages must NOT be overwritten by a tombstone on first receive,
        // so other members in the group can also fetch the exact same slot!
        val aliceSlot0 = RatchetChain.computeLookaheadSlots(aliceSenderGroupChainKey, 0, windowSize = 1)[0]
        val dhtRecord = dhtNode.getMutable(aliceSlot0.target)
        assertNotNull("DHT record must STILL EXIST after Bob's receive (NO TOMBSTONE in group chats!)", dhtRecord)
        assertEquals("DHT record must remain 900 bytes", 900, dhtRecord!!.v.size)
    }

    @Test
    fun testRotateGroupSenderKey() = runBlocking {
        val fakeContactDao = FakeContactDao()
        val fakeMessageDao = FakeMessageDao()
        val fakeChunkDao = FakeChunkDao()
        val fakeGroupDao = FakeGroupDao()
        val fakeGroupMemberDao = FakeGroupMemberDao()
        val dhtNode = DhtLeafNode()

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
}
