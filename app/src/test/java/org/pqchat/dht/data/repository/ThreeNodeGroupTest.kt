package org.pqchat.dht.data.repository

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.*
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.protocol.RatchetChain
import org.pqchat.dht.traffic.*
import java.security.Security

class ThreeNodeGroupTest {

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
        override suspend fun updateContactName(id: String, name: EncryptedText) {
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
            val bound = if (chainKeyOut.boundColumn == null) EncryptedBlob(chainKeyOut.raw, "groups", groupId, "myChainKeyOut") else chainKeyOut
            groups[groupId] = g.copy(myCounterOut = counterOut, myChainKeyOut = bound, lastActive = lastActive)
            flow.value = groups.values.toList()
        }
        override suspend fun updateRekeyedState(groupId: String, epoch: Long, counterOut: Int, chainKeyOut: EncryptedBlob, lastActive: Long) {
            val g = groups[groupId] ?: return
            val bound = if (chainKeyOut.boundColumn == null) EncryptedBlob(chainKeyOut.raw, "groups", groupId, "myChainKeyOut") else chainKeyOut
            groups[groupId] = g.copy(myCounterOut = counterOut, myChainKeyOut = bound, groupEpoch = epoch, lastActive = lastActive)
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
    fun testThreeNodeGroupFullInviteAndMessaging() = runBlocking {
        val dhtNode = FakeDht()

        // Alice Repo
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

        // Bob Repo
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

        // Charlie Repo
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

        // Pairwise channels: Alice <-> Bob (Alice is initiator, Bob is responder)
        val abKey = CryptoUtils.secureRandomBytes(64)
        val baKey = CryptoUtils.secureRandomBytes(64)
        val aliceBob = ContactEntity(id = "bob", name = "Bob", chainKeyOut = abKey, chainKeyIn = baKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true)
        val bobAlice = ContactEntity(id = "alice", name = "Alice", chainKeyOut = baKey, chainKeyIn = abKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true)
        aliceContactDao.insertOrUpdate(aliceBob)
        bobContactDao.insertOrUpdate(bobAlice)

        // Pairwise channels: Alice <-> Charlie (Alice is initiator, Charlie is responder)
        val acKey = CryptoUtils.secureRandomBytes(64)
        val caKey = CryptoUtils.secureRandomBytes(64)
        val aliceCharlie = ContactEntity(id = "charlie", name = "Charlie", chainKeyOut = acKey, chainKeyIn = caKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true)
        val charlieAlice = ContactEntity(id = "alice", name = "Alice", chainKeyOut = caKey, chainKeyIn = acKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true)
        aliceContactDao.insertOrUpdate(aliceCharlie)
        charlieContactDao.insertOrUpdate(charlieAlice)

        // Phase 3: Alice creates group with Bob and Charlie
        println("Alice abKey target: ${RatchetChain.deriveSlot(abKey, 0).target.joinToString("") { "%02x".format(it) }}")
        println("Alice acKey target: ${RatchetChain.deriveSlot(acKey, 0).target.joinToString("") { "%02x".format(it) }}")
        val group = aliceRepo.createGroup("PQ_MultiNode_Group", listOf("bob", "charlie"))
        val groupId = group.groupId

        // Verify Alice's local members
        val aliceMembersInit = aliceGroupMemberDao.getMembersForGroup(groupId)
        println("Alice initial members: ${aliceMembersInit.map { it.rawMemberName + " (" + it.memberId + ", contact=" + it.contactId + ", active=" + it.isActive + ")" }}")
        assertEquals(3, aliceMembersInit.size)

        println("DHT Storage keys: ${dhtNode.storage.keys}")
        println("Bob looking for target: ${RatchetChain.deriveSlot(abKey, 0).target.joinToString("") { "%02x".format(it) }}")
        println("Bob contact alice: chainKeyIn=${bobAlice.chainKeyIn.raw.joinToString("") { "%02x".format(it) }} counterIn=${bobAlice.counterIn}")
        // Phase 4: Bob polls incoming invite on 1-on-1 channel from Alice
        val bobReceivedInvite = bobRepo.pollContactIncoming("alice")
        assertTrue("Bob must receive group invite from Alice", bobReceivedInvite)
        val bobGroup = bobGroupDao.getGroupById(groupId)
        assertNotNull("Bob must have group created", bobGroup)
        val bobMembersInit = bobGroupMemberDao.getMembersForGroup(groupId)
        println("Bob members after invite: ${bobMembersInit.map { it.rawMemberName + " (" + it.memberId + ", key=" + it.rawChainKeyIn.any { b -> b != 0.toByte() } + ")" }}")

        // Phase 4: Charlie polls incoming invite on 1-on-1 channel from Alice
        val charlieReceivedInvite = charlieRepo.pollContactIncoming("alice")
        assertTrue("Charlie must receive group invite from Alice", charlieReceivedInvite)
        val charlieGroup = charlieGroupDao.getGroupById(groupId)
        assertNotNull("Charlie must have group created", charlieGroup)
        val charlieMembersInit = charlieGroupMemberDao.getMembersForGroup(groupId)
        println("Charlie members after invite: ${charlieMembersInit.map { it.rawMemberName + " (" + it.memberId + ", key=" + it.rawChainKeyIn.any { b -> b != 0.toByte() } + ")" }}")

        // Alice polls incoming: receives Bob's REKEY and Charlie's REKEY
        println("Alice running pollConstantBatch(groupId)...")
        aliceRepo.pollConstantBatch(groupId)
        aliceRepo.pollConstantBatch(groupId)

        val aliceMembersAfterRekey = aliceGroupMemberDao.getMembersForGroup(groupId)
        println("Alice members after rekeys: ${aliceMembersAfterRekey.map { it.rawMemberName + " (" + it.memberId + ", contact=" + it.contactId + ", active=" + it.isActive + ", hasKey=" + it.rawChainKeyIn.any { b -> b != 0.toByte() } + ")" }}")

        // Does Bob receive Charlie's rekey relayed by Alice?
        bobRepo.pollContactIncoming("alice")
        val bobMembersAfterRelay = bobGroupMemberDao.getMembersForGroup(groupId)
        println("Bob members after relay: ${bobMembersAfterRelay.map { it.rawMemberName + " (" + it.memberId + ", hasKey=" + it.rawChainKeyIn.any { b -> b != 0.toByte() } + ")" }}")

        // Does Charlie receive Bob's rekey relayed by Alice?
        charlieRepo.pollContactIncoming("alice")
        val charlieMembersAfterRelay = charlieGroupMemberDao.getMembersForGroup(groupId)
        println("Charlie members after relay: ${charlieMembersAfterRelay.map { it.rawMemberName + " (" + it.memberId + ", hasKey=" + it.rawChainKeyIn.any { b -> b != 0.toByte() } + ")" }}")

        // Turn 1: Alice sends group message
        val aliceSent1 = aliceRepo.sendGroupMessage(groupId, "Hello_Group_from_Alice_all_3_nodes")
        assertTrue("Alice must succeed sending group message", aliceSent1)

        val bobRecvMsg1 = bobRepo.pollGroupIncoming(groupId)
        assertTrue("Bob must receive Alice's msg1", bobRecvMsg1)
        val charlieRecvMsg1 = charlieRepo.pollGroupIncoming(groupId)
        assertTrue("Charlie must receive Alice's msg1", charlieRecvMsg1)

        // Turn 2: Bob sends group message
        val bobSent2 = bobRepo.sendGroupMessage(groupId, "Bob_reporting_in_PQ_MultiNode_Group")
        assertTrue("Bob must succeed sending group message", bobSent2)

        val aliceRecvMsg2 = aliceRepo.pollGroupIncoming(groupId)
        assertTrue("Alice must receive Bob's msg2", aliceRecvMsg2)
        val charlieRecvMsg2 = charlieRepo.pollGroupIncoming(groupId)
        assertTrue("Charlie must receive Bob's msg2", charlieRecvMsg2)

        // Turn 3: Charlie sends group message
        val charlieSent3 = charlieRepo.sendGroupMessage(groupId, "Charlie_here_group_pqc_confirmed")
        assertTrue("Charlie must succeed sending group message", charlieSent3)

        val aliceRecvMsg3 = aliceRepo.pollGroupIncoming(groupId)
        assertTrue("Alice must receive Charlie's msg3", aliceRecvMsg3)
        val bobRecvMsg3 = bobRepo.pollGroupIncoming(groupId)
        assertTrue("Bob must receive Charlie's msg3", bobRecvMsg3)
    }
}
