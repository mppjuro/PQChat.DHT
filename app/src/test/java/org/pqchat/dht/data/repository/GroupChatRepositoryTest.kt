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

    @Test
    fun testGroupIndividualRecipientSlotsAndTombstoneIndependence() = runBlocking {
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
        val dhtNode = DhtLeafNode()
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
        val dhtNode = DhtLeafNode()
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
                groupDao = groupDao,
                groupMemberDao = groupMemberDao
            )

            val lambda = 1.0 / 60.0
            val generator = PoissonTrafficGenerator(
                dhtLeafNode = fakeDht,
                lambda = lambda,
                pendingAckQueue = ackQueue,
                blindRepublishPool = repo.blindRepublishPool,
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
}
