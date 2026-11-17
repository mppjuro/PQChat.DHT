package org.pqchat.dht.data.repository

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
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

    private class FakeSkippedKeyDao : SkippedKeyDao {
        private val keys = java.util.concurrent.ConcurrentHashMap<String, MutableMap<Int, SkippedKeyEntity>>()

        override suspend fun getSkippedKeysForContact(contactId: String): List<SkippedKeyEntity> =
            keys[contactId]?.values?.sortedBy { it.slotIndex } ?: emptyList()

        override suspend fun getSkippedKey(contactId: String, slotIndex: Int): SkippedKeyEntity? =
            keys[contactId]?.get(slotIndex)

        override suspend fun insertOrUpdate(skippedKey: SkippedKeyEntity) {
            keys.computeIfAbsent(skippedKey.contactId) { java.util.concurrent.ConcurrentHashMap() }[skippedKey.slotIndex] = skippedKey
        }

        override suspend fun deleteSkippedKey(contactId: String, slotIndex: Int) {
            keys[contactId]?.remove(slotIndex)
        }

        override suspend fun deleteExpiredKeys(now: Long) {
            keys.values.forEach { map ->
                val expired = map.entries.filter { it.value.expiresAt < now }.map { it.key }
                expired.forEach { map.remove(it) }
            }
        }

        override suspend fun countSkippedKeys(contactId: String): Int =
            keys[contactId]?.size ?: 0

        override suspend fun deleteOldestSkippedKeys(contactId: String, count: Int) {
            val map = keys[contactId] ?: return
            map.values.sortedBy { it.createdAt }.take(count).forEach { map.remove(it.slotIndex) }
        }
    }

    private class FakePendingRekeyOfferDao : PendingRekeyOfferDao {
        val offers = java.util.concurrent.ConcurrentHashMap<String, PendingRekeyOfferEntity>()
        val offersFlow = MutableStateFlow<Map<String, PendingRekeyOfferEntity>>(emptyMap())

        override suspend fun getPendingOffer(contactId: String): PendingRekeyOfferEntity? = offers[contactId]
        override fun getPendingOfferFlow(contactId: String): Flow<PendingRekeyOfferEntity?> = offersFlow.map { it[contactId] }
        override fun isRekeyPendingFlow(contactId: String): Flow<Boolean> = offersFlow.map { it.containsKey(contactId) }
        override suspend fun insertOrUpdate(offer: PendingRekeyOfferEntity) {
            offers[offer.contactId] = offer
            offersFlow.value = HashMap(offers)
        }
        override suspend fun deletePendingOffer(contactId: String) {
            offers.remove(contactId)
            offersFlow.value = HashMap(offers)
        }
    }

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
        var aliceAttempts = 0
        while (aliceAttempts < 5 && aliceGroupMemberDao.getMembersForGroup(groupId).any { it.isActive && it.rawChainKeyIn.all { b -> b == 0.toByte() } }) {
            aliceRepo.pollConstantBatch(groupId)
            aliceAttempts++
        }

        val aliceMembersAfterRekey = aliceGroupMemberDao.getMembersForGroup(groupId)
        println("Alice members after rekeys: ${aliceMembersAfterRekey.map { it.rawMemberName + " (" + it.memberId + ", contact=" + it.contactId + ", active=" + it.isActive + ", hasKey=" + it.rawChainKeyIn.any { b -> b != 0.toByte() } + ")" }}")
        assertTrue("All Alice group members must have keys after rekey polling", aliceMembersAfterRekey.all { !it.isActive || it.rawChainKeyIn.any { b -> b != 0.toByte() } })

        // Does Bob receive Charlie's rekey relayed by Alice?
        var bobAttempts = 0
        while (bobAttempts < 3 && bobGroupMemberDao.getMembersForGroup(groupId).any { it.isActive && it.rawChainKeyIn.all { b -> b == 0.toByte() } }) {
            bobRepo.pollContactIncoming("alice")
            bobAttempts++
        }
        val bobMembersAfterRelay = bobGroupMemberDao.getMembersForGroup(groupId)
        println("Bob members after relay: ${bobMembersAfterRelay.map { it.rawMemberName + " (" + it.memberId + ", hasKey=" + it.rawChainKeyIn.any { b -> b != 0.toByte() } + ")" }}")
        assertTrue("All Bob group members must have keys after relay", bobMembersAfterRelay.all { !it.isActive || it.rawChainKeyIn.any { b -> b != 0.toByte() } })

        // Does Charlie receive Bob's rekey relayed by Alice?
        var charlieAttempts = 0
        while (charlieAttempts < 3 && charlieGroupMemberDao.getMembersForGroup(groupId).any { it.isActive && it.rawChainKeyIn.all { b -> b == 0.toByte() } }) {
            charlieRepo.pollContactIncoming("alice")
            charlieAttempts++
        }
        val charlieMembersAfterRelay = charlieGroupMemberDao.getMembersForGroup(groupId)
        println("Charlie members after relay: ${charlieMembersAfterRelay.map { it.rawMemberName + " (" + it.memberId + ", hasKey=" + it.rawChainKeyIn.any { b -> b != 0.toByte() } + ")" }}")
        assertTrue("All Charlie group members must have keys after relay", charlieMembersAfterRelay.all { !it.isActive || it.rawChainKeyIn.any { b -> b != 0.toByte() } })

        // Turn 1: Alice sends group message
        val aliceSent1 = aliceRepo.sendGroupMessage(groupId, "Hello_Group_from_Alice_all_3_nodes")
        assertTrue("Alice must succeed sending group message", aliceSent1)

        val bobRecvMsg1 = bobRepo.pollGroupIncoming(groupId)
        assertTrue("Bob must receive Alice's msg1", bobRecvMsg1)
        val charlieRecvMsg1 = charlieRepo.pollGroupIncoming(groupId)
        assertTrue("Charlie must receive Alice's msg1", charlieRecvMsg1)
        assertEquals(1, bobMessageDao.messages.count { it.textContent?.raw == "Hello_Group_from_Alice_all_3_nodes" && !it.isOutgoing })
        assertEquals(1, charlieMessageDao.messages.count { it.textContent?.raw == "Hello_Group_from_Alice_all_3_nodes" && !it.isOutgoing })

        // Turn 2: Bob sends group message
        val bobSent2 = bobRepo.sendGroupMessage(groupId, "Bob_reporting_in_PQ_MultiNode_Group")
        assertTrue("Bob must succeed sending group message", bobSent2)

        val aliceRecvMsg2 = aliceRepo.pollGroupIncoming(groupId)
        assertTrue("Alice must receive Bob's msg2", aliceRecvMsg2)
        val charlieRecvMsg2 = charlieRepo.pollGroupIncoming(groupId)
        assertTrue("Charlie must receive Bob's msg2", charlieRecvMsg2)
        assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == "Bob_reporting_in_PQ_MultiNode_Group" && !it.isOutgoing })
        assertEquals(1, charlieMessageDao.messages.count { it.textContent?.raw == "Bob_reporting_in_PQ_MultiNode_Group" && !it.isOutgoing })

        // Turn 3: Charlie sends group message
        val charlieSent3 = charlieRepo.sendGroupMessage(groupId, "Charlie_here_group_pqc_confirmed")
        assertTrue("Charlie must succeed sending group message", charlieSent3)

        val aliceRecvMsg3 = aliceRepo.pollGroupIncoming(groupId)
        assertTrue("Alice must receive Charlie's msg3", aliceRecvMsg3)
        val bobRecvMsg3 = bobRepo.pollGroupIncoming(groupId)
        assertTrue("Bob must receive Charlie's msg3", bobRecvMsg3)
        assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == "Charlie_here_group_pqc_confirmed" && !it.isOutgoing })
        assertEquals(1, bobMessageDao.messages.count { it.textContent?.raw == "Charlie_here_group_pqc_confirmed" && !it.isOutgoing })
    }

    @Test
    fun testThreeNodeStarTopologyImmediateMultiTurnMessagingWithoutRelay() = runBlocking {
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

        // Bob Repo (no Charlie pairwise contact)
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

        // Charlie Repo (no Bob pairwise contact)
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

        // Pairwise star channels: Alice <-> Bob only
        val abKey = CryptoUtils.secureRandomBytes(64)
        val baKey = CryptoUtils.secureRandomBytes(64)
        aliceContactDao.insertOrUpdate(ContactEntity(id = "bob", name = "Bob", chainKeyOut = abKey, chainKeyIn = baKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true))
        bobContactDao.insertOrUpdate(ContactEntity(id = "alice", name = "Alice", chainKeyOut = baKey, chainKeyIn = abKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true))

        // Pairwise star channels: Alice <-> Charlie only
        val acKey = CryptoUtils.secureRandomBytes(64)
        val caKey = CryptoUtils.secureRandomBytes(64)
        aliceContactDao.insertOrUpdate(ContactEntity(id = "charlie", name = "Charlie", chainKeyOut = acKey, chainKeyIn = caKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true))
        charlieContactDao.insertOrUpdate(ContactEntity(id = "alice", name = "Alice", chainKeyOut = caKey, chainKeyIn = acKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true))

        // Step 1: Alice creates group with Bob and Charlie
        val group = aliceRepo.createGroup("PQ_MultiNode_Group", listOf("bob", "charlie"))
        val groupId = group.groupId

        // Verify Alice's members are all initialized immediately with non-zero sender keys
        val aliceMembers = aliceGroupMemberDao.getMembersForGroup(groupId)
        assertEquals(3, aliceMembers.size)
        assertTrue("All Alice group members must have non-zero keys immediately",
            aliceMembers.all { it.rawChainKeyIn.any { b -> b != 0.toByte() } })

        // Step 2: Bob and Charlie receive group invite from Alice over pairwise channel
        assertTrue("Bob receives invite", bobRepo.pollContactIncoming("alice"))
        assertTrue("Charlie receives invite", charlieRepo.pollContactIncoming("alice"))

        // Verify Bob's members (Alice, Bob, Charlie) all have non-zero keys immediately without relay!
        val bobMembers = bobGroupMemberDao.getMembersForGroup(groupId)
        assertEquals(3, bobMembers.size)
        assertTrue("All Bob group members must have non-zero keys immediately without relay",
            bobMembers.all { it.rawChainKeyIn.any { b -> b != 0.toByte() } })

        // Verify Charlie's members (Alice, Bob, Charlie) all have non-zero keys immediately without relay!
        val charlieMembers = charlieGroupMemberDao.getMembersForGroup(groupId)
        assertEquals(3, charlieMembers.size)
        assertTrue("All Charlie group members must have non-zero keys immediately without relay",
            charlieMembers.all { it.rawChainKeyIn.any { b -> b != 0.toByte() } })

        // Turn 1: Alice sends group message -> Bob and Charlie receive
        val msg1 = "Hello_Group_from_Alice_all_3_nodes"
        assertTrue("Alice sends Msg 1", aliceRepo.sendGroupMessage(groupId, msg1))
        assertTrue("Bob receives Msg 1", bobRepo.pollGroupIncoming(groupId))
        assertTrue("Charlie receives Msg 1", charlieRepo.pollGroupIncoming(groupId))
        assertEquals(1, bobMessageDao.messages.count { it.textContent?.raw == msg1 && !it.isOutgoing })
        assertEquals(1, charlieMessageDao.messages.count { it.textContent?.raw == msg1 && !it.isOutgoing })

        // Turn 2: Bob sends group message -> Alice and Charlie receive
        val msg2 = "Bob_reporting_in_PQ_MultiNode_Group"
        assertTrue("Bob sends Msg 2", bobRepo.sendGroupMessage(groupId, msg2))
        assertTrue("Alice receives Msg 2", aliceRepo.pollGroupIncoming(groupId))
        assertTrue("Charlie receives Msg 2", charlieRepo.pollGroupIncoming(groupId))
        assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == msg2 && !it.isOutgoing })
        assertEquals(1, charlieMessageDao.messages.count { it.textContent?.raw == msg2 && !it.isOutgoing })

        // Turn 3: Charlie sends group message -> Alice and Bob receive
        val msg3 = "Charlie_here_group_pqc_confirmed"
        assertTrue("Charlie sends Msg 3", charlieRepo.sendGroupMessage(groupId, msg3))
        assertTrue("Alice receives Msg 3", aliceRepo.pollGroupIncoming(groupId))
        assertTrue("Bob receives Msg 3", bobRepo.pollGroupIncoming(groupId))
        assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == msg3 && !it.isOutgoing })
        assertEquals(1, bobMessageDao.messages.count { it.textContent?.raw == msg3 && !it.isOutgoing })

        // Verify all 3 nodes have 3 messages total in the conversation (1 outgoing + 2 incoming)
        assertEquals(3, aliceMessageDao.messages.count { it.contactId == groupId })
        assertEquals(3, bobMessageDao.messages.count { it.contactId == groupId })
        assertEquals(3, charlieMessageDao.messages.count { it.contactId == groupId })
    }

    @Test
    fun testFourNodeGroupStarTopologyFullSyncAndMessaging() = runBlocking {
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

        // Dave Repo
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

        // Star topology channels:
        // Alice <-> Bob
        val abKey = CryptoUtils.secureRandomBytes(64)
        val baKey = CryptoUtils.secureRandomBytes(64)
        aliceContactDao.insertOrUpdate(ContactEntity(id = "bob", name = "Bob", chainKeyOut = abKey, chainKeyIn = baKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true))
        bobContactDao.insertOrUpdate(ContactEntity(id = "alice", name = "Alice", chainKeyOut = baKey, chainKeyIn = abKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true))

        // Alice <-> Charlie
        val acKey = CryptoUtils.secureRandomBytes(64)
        val caKey = CryptoUtils.secureRandomBytes(64)
        aliceContactDao.insertOrUpdate(ContactEntity(id = "charlie", name = "Charlie", chainKeyOut = acKey, chainKeyIn = caKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true))
        charlieContactDao.insertOrUpdate(ContactEntity(id = "alice", name = "Alice", chainKeyOut = caKey, chainKeyIn = acKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true))

        // Alice <-> Dave
        val adKey = CryptoUtils.secureRandomBytes(64)
        val daKey = CryptoUtils.secureRandomBytes(64)
        aliceContactDao.insertOrUpdate(ContactEntity(id = "dave", name = "Dave", chainKeyOut = adKey, chainKeyIn = daKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true))
        daveContactDao.insertOrUpdate(ContactEntity(id = "alice", name = "Alice", chainKeyOut = daKey, chainKeyIn = adKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true))

        // Note: Bob, Charlie, and Dave have NO direct contacts with each other (Pure Star Topology).

        // Step 1: Alice creates group with Bob, Charlie, and Dave
        val group = aliceRepo.createGroup("PQ_MultiNode_Group", listOf("bob", "charlie", "dave"))
        val groupId = group.groupId
        assertEquals(4, aliceGroupMemberDao.getMembersForGroup(groupId).size)

        // Step 2: Participants poll incoming invite from Alice on their 1-on-1 channels
        assertTrue("Bob must receive group invite from Alice", bobRepo.pollContactIncoming("alice"))
        assertNotNull("Bob must have group created", bobGroupDao.getGroupById(groupId))

        assertTrue("Charlie must receive group invite from Alice", charlieRepo.pollContactIncoming("alice"))
        assertNotNull("Charlie must have group created", charlieGroupDao.getGroupById(groupId))

        assertTrue("Dave must receive group invite from Alice", daveRepo.pollContactIncoming("alice"))
        assertNotNull("Dave must have group created", daveGroupDao.getGroupById(groupId))

        // Step 3: Alice polls incoming 1-on-1 channels (or via pollGroupIncoming) to receive REKEYs from Bob, Charlie, Dave
        var aliceAttempts = 0
        while (aliceAttempts < 5 && aliceGroupMemberDao.getMembersForGroup(groupId).any { it.isActive && it.rawChainKeyIn.all { b -> b == 0.toByte() } }) {
            aliceRepo.pollGroupIncoming(groupId)
            aliceAttempts++
        }
        val aliceMembers = aliceGroupMemberDao.getMembersForGroup(groupId)
        assertTrue("All 4 Alice group members must have keys after rekey polling",
            aliceMembers.size == 4 && aliceMembers.all { !it.isActive || it.rawChainKeyIn.any { b -> b != 0.toByte() } })

        // Alice relays keys to Bob, Charlie, and Dave
        aliceRepo.relayMissingGroupKeys(groupId, force = true)

        // Step 4: Bob, Charlie, and Dave poll to ingest relayed keys from Alice
        for (i in 0 until 3) {
            bobRepo.pollGroupIncoming(groupId)
            charlieRepo.pollGroupIncoming(groupId)
            daveRepo.pollGroupIncoming(groupId)
        }

        val bobMembers = bobGroupMemberDao.getMembersForGroup(groupId)
        val charlieMembers = charlieGroupMemberDao.getMembersForGroup(groupId)
        val daveMembers = daveGroupMemberDao.getMembersForGroup(groupId)

        assertTrue("All 4 Bob group members must have keys after relay",
            bobMembers.size == 4 && bobMembers.all { !it.isActive || it.rawChainKeyIn.any { b -> b != 0.toByte() } })
        assertTrue("All 4 Charlie group members must have keys after relay",
            charlieMembers.size == 4 && charlieMembers.all { !it.isActive || it.rawChainKeyIn.any { b -> b != 0.toByte() } })
        assertTrue("All 4 Dave group members must have keys after relay",
            daveMembers.size == 4 && daveMembers.all { !it.isActive || it.rawChainKeyIn.any { b -> b != 0.toByte() } })

        // Turn 1: Alice sends message -> Bob, Charlie, Dave receive
        val aliceSent1 = aliceRepo.sendGroupMessage(groupId, "Hello_Group_from_Alice_all_4_nodes")
        assertTrue("Alice must succeed sending Turn 1 group message", aliceSent1)

        assertTrue("Bob must receive Alice's Turn 1 msg", bobRepo.pollGroupIncoming(groupId))
        assertTrue("Charlie must receive Alice's Turn 1 msg", charlieRepo.pollGroupIncoming(groupId))
        assertTrue("Dave must receive Alice's Turn 1 msg", daveRepo.pollGroupIncoming(groupId))

        assertEquals(1, bobMessageDao.messages.count { it.textContent?.raw == "Hello_Group_from_Alice_all_4_nodes" && !it.isOutgoing })
        assertEquals(1, charlieMessageDao.messages.count { it.textContent?.raw == "Hello_Group_from_Alice_all_4_nodes" && !it.isOutgoing })
        assertEquals(1, daveMessageDao.messages.count { it.textContent?.raw == "Hello_Group_from_Alice_all_4_nodes" && !it.isOutgoing })

        // Turn 2: Bob sends message -> Alice, Charlie, Dave receive
        val bobSent2 = bobRepo.sendGroupMessage(groupId, "Bob_reporting_in_PQ_MultiNode_Group")
        assertTrue("Bob must succeed sending Turn 2 group message", bobSent2)

        assertTrue("Alice must receive Bob's Turn 2 msg", aliceRepo.pollGroupIncoming(groupId))
        assertTrue("Charlie must receive Bob's Turn 2 msg", charlieRepo.pollGroupIncoming(groupId))
        assertTrue("Dave must receive Bob's Turn 2 msg", daveRepo.pollGroupIncoming(groupId))

        assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == "Bob_reporting_in_PQ_MultiNode_Group" && !it.isOutgoing })
        assertEquals(1, charlieMessageDao.messages.count { it.textContent?.raw == "Bob_reporting_in_PQ_MultiNode_Group" && !it.isOutgoing })
        assertEquals(1, daveMessageDao.messages.count { it.textContent?.raw == "Bob_reporting_in_PQ_MultiNode_Group" && !it.isOutgoing })

        // Turn 3: Charlie sends message -> Alice, Bob, Dave receive
        val charlieSent3 = charlieRepo.sendGroupMessage(groupId, "Charlie_here_group_pqc_confirmed")
        assertTrue("Charlie must succeed sending Turn 3 group message", charlieSent3)

        assertTrue("Alice must receive Charlie's Turn 3 msg", aliceRepo.pollGroupIncoming(groupId))
        assertTrue("Bob must receive Charlie's Turn 3 msg", bobRepo.pollGroupIncoming(groupId))
        assertTrue("Dave must receive Charlie's Turn 3 msg", daveRepo.pollGroupIncoming(groupId))

        assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == "Charlie_here_group_pqc_confirmed" && !it.isOutgoing })
        assertEquals(1, bobMessageDao.messages.count { it.textContent?.raw == "Charlie_here_group_pqc_confirmed" && !it.isOutgoing })
        assertEquals(1, daveMessageDao.messages.count { it.textContent?.raw == "Charlie_here_group_pqc_confirmed" && !it.isOutgoing })

        // Turn 4: Dave sends message -> Alice, Bob, Charlie receive
        val daveSent4 = daveRepo.sendGroupMessage(groupId, "Dave_standing_by_for_pqc_mesh")
        assertTrue("Dave must succeed sending Turn 4 group message", daveSent4)

        assertTrue("Alice must receive Dave's Turn 4 msg", aliceRepo.pollGroupIncoming(groupId))
        assertTrue("Bob must receive Dave's Turn 4 msg", bobRepo.pollGroupIncoming(groupId))
        assertTrue("Charlie must receive Dave's Turn 4 msg", charlieRepo.pollGroupIncoming(groupId))

        assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == "Dave_standing_by_for_pqc_mesh" && !it.isOutgoing })
        assertEquals(1, bobMessageDao.messages.count { it.textContent?.raw == "Dave_standing_by_for_pqc_mesh" && !it.isOutgoing })
        assertEquals(1, charlieMessageDao.messages.count { it.textContent?.raw == "Dave_standing_by_for_pqc_mesh" && !it.isOutgoing })
    }

    private fun testUuidStringToBytes(uuidStr: String): ByteArray {
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

    @Test
    fun testEarlyRekeyBufferedAndReplayedUponInviteArrival() = runBlocking {
        val dhtNode = FakeDht()

        val aliceContactDao = FakeContactDao()
        val aliceGroupDao = FakeGroupDao()
        val aliceGroupMemberDao = FakeGroupMemberDao()
        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = FakeMessageDao(),
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = aliceGroupDao,
            groupMemberDao = aliceGroupMemberDao
        )

        val charlieContactDao = FakeContactDao()
        val charlieGroupDao = FakeGroupDao()
        val charlieGroupMemberDao = FakeGroupMemberDao()
        val charlieRepo = ChatRepository(
            contactDao = charlieContactDao,
            messageDao = FakeMessageDao(),
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = charlieGroupDao,
            groupMemberDao = charlieGroupMemberDao
        )

        val acKey = CryptoUtils.secureRandomBytes(64)
        val caKey = CryptoUtils.secureRandomBytes(64)
        aliceContactDao.insertOrUpdate(ContactEntity(id = "charlie", name = "Charlie", chainKeyOut = acKey, chainKeyIn = caKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true))
        charlieContactDao.insertOrUpdate(ContactEntity(id = "alice", name = "Alice", chainKeyOut = caKey, chainKeyIn = acKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true))

        // Alice creates group
        val group = aliceRepo.createGroup("TestEarlyRekeyGroup", listOf("charlie"))
        val groupId = group.groupId
        val groupIdBytes = testUuidStringToBytes(groupId)

        // Simulate an early REKEY arriving at Charlie BEFORE Charlie processes the invite
        val bobMemberId = java.util.UUID.randomUUID().toString()
        val bobMemberIdBytes = testUuidStringToBytes(bobMemberId)
        val bobSenderKey = CryptoUtils.secureRandomBytes(64)
        val earlyRekeyControl = org.pqchat.dht.crypto.BinaryFrameCodec.DecodedPayload.GroupControl(
            controlSubType = org.pqchat.dht.crypto.BinaryFrameCodec.GROUP_SUBTYPE_REKEY,
            groupId = groupIdBytes,
            groupEpoch = 1L,
            senderMemberId = bobMemberIdBytes,
            senderGroupChainKey = bobSenderKey,
            currentCounter = 0L,
            groupName = "TestEarlyRekeyGroup",
            members = emptyList(),
            memberKeys = emptyList()
        )

        // Charlie receives REKEY before invite: group does not exist yet in charlieGroupDao
        assertNull("Charlie group must not exist yet", charlieGroupDao.getGroupById(groupId))
        charlieRepo.processIncomingGroupControl("alice", earlyRekeyControl)
        assertNull("Charlie group still null after early rekey", charlieGroupDao.getGroupById(groupId))

        // Now Charlie receives INVITE
        assertTrue("Charlie polls and receives group invite", charlieRepo.pollContactIncoming("alice"))
        assertNotNull("Charlie group created after invite", charlieGroupDao.getGroupById(groupId))

        // Verify Bob's early rekey was replayed from buffer and Bob's sender key is present on Charlie
        val charlieMembers = charlieGroupMemberDao.getMembersForGroup(groupId)
        val bobMemberOnCharlie = charlieMembers.firstOrNull { it.memberId == bobMemberId }
        assertNotNull("Bob member must be registered on Charlie from replayed early control", bobMemberOnCharlie)
        assertArrayEquals("Bob's sender key must match replayed key", bobSenderKey, bobMemberOnCharlie!!.rawChainKeyIn)
    }

    @Test
    fun testBroadcastMyGroupSenderKeySkipsMembersWithPendingInvite() = runBlocking {
        val dhtNode = FakeDht()
        val aliceContactDao = FakeContactDao()
        val aliceGroupDao = FakeGroupDao()
        val aliceGroupMemberDao = FakeGroupMemberDao()
        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = FakeMessageDao(),
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = aliceGroupDao,
            groupMemberDao = aliceGroupMemberDao
        )

        val acKey = CryptoUtils.secureRandomBytes(64)
        val caKey = CryptoUtils.secureRandomBytes(64)
        aliceContactDao.insertOrUpdate(ContactEntity(id = "charlie", name = "Charlie", chainKeyOut = acKey, chainKeyIn = caKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true))

        // Alice creates group with Charlie
        val group = aliceRepo.createGroup("TestPendingInviteSkip", listOf("charlie"))
        val charlieContactBefore = aliceContactDao.getContactById("charlie")!!
        val counterOutAfterInvite = charlieContactBefore.counterOut

        // Invite is pending in pendingGroupControls for Charlie
        val pendingInvites = aliceRepo.getPendingGroupControls().filter {
            it.groupId == group.groupId && it.contactId == "charlie" && it.controlSubType == org.pqchat.dht.crypto.BinaryFrameCodec.GROUP_SUBTYPE_INVITE
        }
        assertTrue("Invite must be registered in pendingGroupControls", pendingInvites.isNotEmpty())

        // Alice invokes broadcastMyGroupSenderKey
        aliceRepo.broadcastMyGroupSenderKey(group.groupId)

        // Charlie's contact counterOut must NOT advance because REKEY was skipped while invite was pending
        val charlieContactAfter = aliceContactDao.getContactById("charlie")!!
        assertEquals("counterOut must not advance because rekey was skipped for pending invite", counterOutAfterInvite, charlieContactAfter.counterOut)
    }

    private data class ThreeNodeFixture(
        val aliceContactDao: FakeContactDao,
        val aliceMessageDao: FakeMessageDao,
        val aliceGroupDao: FakeGroupDao,
        val aliceGroupMemberDao: FakeGroupMemberDao,
        val aliceRekeyDao: FakePendingRekeyOfferDao,
        val aliceRepo: ChatRepository,
        val bobContactDao: FakeContactDao,
        val bobMessageDao: FakeMessageDao,
        val bobGroupDao: FakeGroupDao,
        val bobGroupMemberDao: FakeGroupMemberDao,
        val bobRekeyDao: FakePendingRekeyOfferDao,
        val bobRepo: ChatRepository,
        val charlieContactDao: FakeContactDao,
        val charlieMessageDao: FakeMessageDao,
        val charlieGroupDao: FakeGroupDao,
        val charlieGroupMemberDao: FakeGroupMemberDao,
        val charlieRekeyDao: FakePendingRekeyOfferDao,
        val charlieRepo: ChatRepository
    )

    private suspend fun createThreeNodeFixture(dhtNode: FakeDht): ThreeNodeFixture {
        val aliceContactDao = FakeContactDao()
        val aliceMessageDao = FakeMessageDao()
        val aliceGroupDao = FakeGroupDao()
        val aliceGroupMemberDao = FakeGroupMemberDao()
        val aliceRekeyDao = FakePendingRekeyOfferDao()
        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = aliceMessageDao,
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = aliceRekeyDao,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = aliceGroupDao,
            groupMemberDao = aliceGroupMemberDao
        ).apply {
            delayedPutMaxMs = 0L
            decoyPutSlotsCount = 0
            enableDecoyGets = false
            intraBatchJitterMinMs = 0L
            intraBatchJitterMaxMs = 0L
        }

        val bobContactDao = FakeContactDao()
        val bobMessageDao = FakeMessageDao()
        val bobGroupDao = FakeGroupDao()
        val bobGroupMemberDao = FakeGroupMemberDao()
        val bobRekeyDao = FakePendingRekeyOfferDao()
        val bobRepo = ChatRepository(
            contactDao = bobContactDao,
            messageDao = bobMessageDao,
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = bobRekeyDao,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = bobGroupDao,
            groupMemberDao = bobGroupMemberDao
        ).apply {
            delayedPutMaxMs = 0L
            decoyPutSlotsCount = 0
            enableDecoyGets = false
            intraBatchJitterMinMs = 0L
            intraBatchJitterMaxMs = 0L
        }

        val charlieContactDao = FakeContactDao()
        val charlieMessageDao = FakeMessageDao()
        val charlieGroupDao = FakeGroupDao()
        val charlieGroupMemberDao = FakeGroupMemberDao()
        val charlieRekeyDao = FakePendingRekeyOfferDao()
        val charlieRepo = ChatRepository(
            contactDao = charlieContactDao,
            messageDao = charlieMessageDao,
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = charlieRekeyDao,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = charlieGroupDao,
            groupMemberDao = charlieGroupMemberDao
        ).apply {
            delayedPutMaxMs = 0L
            decoyPutSlotsCount = 0
            enableDecoyGets = false
            intraBatchJitterMinMs = 0L
            intraBatchJitterMaxMs = 0L
        }

        val abKey = CryptoUtils.secureRandomBytes(64)
        val baKey = CryptoUtils.secureRandomBytes(64)
        aliceContactDao.insertOrUpdate(ContactEntity(id = "bob", name = "Bob", chainKeyOut = abKey, chainKeyIn = baKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true))
        bobContactDao.insertOrUpdate(ContactEntity(id = "alice", name = "Alice", chainKeyOut = baKey, chainKeyIn = abKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true))

        val acKey = CryptoUtils.secureRandomBytes(64)
        val caKey = CryptoUtils.secureRandomBytes(64)
        aliceContactDao.insertOrUpdate(ContactEntity(id = "charlie", name = "Charlie", chainKeyOut = acKey, chainKeyIn = caKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true))
        charlieContactDao.insertOrUpdate(ContactEntity(id = "alice", name = "Alice", chainKeyOut = caKey, chainKeyIn = acKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true))

        return ThreeNodeFixture(
            aliceContactDao, aliceMessageDao, aliceGroupDao, aliceGroupMemberDao, aliceRekeyDao, aliceRepo,
            bobContactDao, bobMessageDao, bobGroupDao, bobGroupMemberDao, bobRekeyDao, bobRepo,
            charlieContactDao, charlieMessageDao, charlieGroupDao, charlieGroupMemberDao, charlieRekeyDao, charlieRepo
        )
    }

    @Test
    fun testThreeNodeGroupInviteAfterPqcRekeyAndPendingRekey() = runBlocking {
        // Case A: Alice initiates rekey (0x03), Bob processes 0x03 and publishes 0x04,
        // and Alice calls createGroup before polling 0x04.
        val dhtA = FakeDht(minDelayMs = 0L, maxDelayMs = 0L)
        dhtA.start()
        val fA = createThreeNodeFixture(dhtA)
        try {
            assertTrue(fA.aliceRepo.sendTextMessage("bob", "DM_Alice_to_Bob"))
            assertTrue(fA.bobRepo.pollContactIncoming("alice"))
            assertTrue(fA.bobRepo.sendTextMessage("alice", "DM_Bob_to_Alice"))
            assertTrue(fA.aliceRepo.pollContactIncoming("bob"))

            assertTrue("Alice must initiate rekey", fA.aliceRepo.initiateRekey("bob"))
            assertNotNull("Pending rekey offer must exist on Alice", fA.aliceRekeyDao.getPendingOffer("bob"))

            assertTrue("Bob must process 0x03 offer", fA.bobRepo.pollContactIncoming("alice"))
            assertEquals(1L, fA.bobRepo.getContact("alice")!!.rekeyEpoch)

            // Alice has not polled 0x04 yet, and creates the group
            assertEquals(0L, fA.aliceRepo.getContact("bob")!!.rekeyEpoch)
            val groupA = fA.aliceRepo.createGroup("PQ_Group_CaseA", listOf("bob", "charlie"))

            assertEquals("Alice must auto-poll 0x04 and reach epoch 1 before sending invite", 1L, fA.aliceRepo.getContact("bob")!!.rekeyEpoch)
            assertNull("Pending rekey offer must be cleared", fA.aliceRekeyDao.getPendingOffer("bob"))

            assertTrue("Bob must receive group invite on post-rekey chain", fA.bobRepo.pollContactIncoming("alice"))
            assertTrue("Charlie must receive group invite", fA.charlieRepo.pollContactIncoming("alice"))
            assertNotNull("Bob group must be created", fA.bobGroupDao.getGroupById(groupA.groupId))
            assertNotNull("Charlie group must be created", fA.charlieGroupDao.getGroupById(groupA.groupId))

            assertTrue(fA.aliceRepo.sendGroupMessage(groupA.groupId, "CaseA_Alice_Msg"))
            assertTrue(fA.bobRepo.pollGroupIncoming(groupA.groupId))
            assertTrue(fA.charlieRepo.pollGroupIncoming(groupA.groupId))
            assertEquals(1, fA.bobMessageDao.messages.count { it.textContent?.raw == "CaseA_Alice_Msg" && !it.isOutgoing })
            assertEquals(1, fA.charlieMessageDao.messages.count { it.textContent?.raw == "CaseA_Alice_Msg" && !it.isOutgoing })

            assertTrue(fA.bobRepo.sendGroupMessage(groupA.groupId, "CaseA_Bob_Msg"))
            assertTrue(fA.aliceRepo.pollGroupIncoming(groupA.groupId))
            assertTrue(fA.charlieRepo.pollGroupIncoming(groupA.groupId))
            assertEquals(1, fA.aliceMessageDao.messages.count { it.textContent?.raw == "CaseA_Bob_Msg" && !it.isOutgoing })
            assertEquals(1, fA.charlieMessageDao.messages.count { it.textContent?.raw == "CaseA_Bob_Msg" && !it.isOutgoing })
        } finally {
            fA.aliceRepo.close()
            fA.bobRepo.close()
            fA.charlieRepo.close()
            dhtA.stop()
        }

        // Case B: Alice initiates rekey (0x03) with Bob and immediately calls createGroup
        // BEFORE Bob has even polled 0x03.
        val dhtB = FakeDht(minDelayMs = 0L, maxDelayMs = 0L)
        dhtB.start()
        val fB = createThreeNodeFixture(dhtB)
        try {
            assertTrue(fB.aliceRepo.sendTextMessage("bob", "DM_CaseB_1"))
            assertTrue(fB.bobRepo.pollContactIncoming("alice"))
            assertTrue(fB.bobRepo.sendTextMessage("alice", "DM_CaseB_2"))
            assertTrue(fB.aliceRepo.pollContactIncoming("bob"))

            assertTrue("Alice must initiate rekey", fB.aliceRepo.initiateRekey("bob"))
            val aliceBobCounterOutAfterOffer = fB.aliceRepo.getContact("bob")!!.counterOut

            // Bob has NOT polled 0x03 yet when Alice creates the group
            val groupB = fB.aliceRepo.createGroup("PQ_Group_CaseB", listOf("bob", "charlie"))

            // Bob's invite was deferred; counterOut for Bob must NOT have advanced on pre-rekey chain
            assertEquals("Bob's counterOut must not advance while rekey is pending", aliceBobCounterOutAfterOffer, fB.aliceRepo.getContact("bob")!!.counterOut)
            assertTrue("Charlie must still receive group invite immediately", fB.charlieRepo.pollContactIncoming("alice"))
            assertNotNull("Charlie group must be created", fB.charlieGroupDao.getGroupById(groupB.groupId))
            assertNull("Bob group must not exist yet", fB.bobGroupDao.getGroupById(groupB.groupId))

            // Bob now polls 0x03 and responds with 0x04
            assertTrue("Bob must process 0x03 offer", fB.bobRepo.pollContactIncoming("alice"))
            assertEquals(1L, fB.bobRepo.getContact("alice")!!.rekeyEpoch)

            // Alice polls 0x04, completes rekey, and automatically drains the deferred group invite
            assertTrue("Alice must process 0x04 response", fB.aliceRepo.pollContactIncoming("bob"))
            assertEquals(1L, fB.aliceRepo.getContact("bob")!!.rekeyEpoch)
            assertNull("Pending rekey offer must be cleared", fB.aliceRekeyDao.getPendingOffer("bob"))
            assertTrue("Alice counterOut for Bob must advance after deferred invite drain", fB.aliceRepo.getContact("bob")!!.counterOut > aliceBobCounterOutAfterOffer)

            // Bob polls Alice and receives the deferred group invite on the post-rekey chain
            assertTrue("Bob must receive deferred group invite after rekey", fB.bobRepo.pollContactIncoming("alice"))
            assertNotNull("Bob group must be created after deferred invite", fB.bobGroupDao.getGroupById(groupB.groupId))

            // Group messaging across all 3 nodes succeeds
            assertTrue(fB.aliceRepo.sendGroupMessage(groupB.groupId, "CaseB_Alice_Msg"))
            assertTrue(fB.bobRepo.pollGroupIncoming(groupB.groupId))
            assertTrue(fB.charlieRepo.pollGroupIncoming(groupB.groupId))
            assertEquals(1, fB.bobMessageDao.messages.count { it.textContent?.raw == "CaseB_Alice_Msg" && !it.isOutgoing })
            assertEquals(1, fB.charlieMessageDao.messages.count { it.textContent?.raw == "CaseB_Alice_Msg" && !it.isOutgoing })

            assertTrue(fB.bobRepo.sendGroupMessage(groupB.groupId, "CaseB_Bob_Msg"))
            assertTrue(fB.aliceRepo.pollGroupIncoming(groupB.groupId))
            assertTrue(fB.charlieRepo.pollGroupIncoming(groupB.groupId))
            assertEquals(1, fB.aliceMessageDao.messages.count { it.textContent?.raw == "CaseB_Bob_Msg" && !it.isOutgoing })
            assertEquals(1, fB.charlieMessageDao.messages.count { it.textContent?.raw == "CaseB_Bob_Msg" && !it.isOutgoing })
        } finally {
            fB.aliceRepo.close()
            fB.bobRepo.close()
            fB.charlieRepo.close()
            dhtB.stop()
        }
    }

    @Test
    fun testFourNodeStarTopologyWithRepeatedBroadcastsAndPollConstantBatch() = runBlocking {
        val dhtNode = FakeDht(minDelayMs = 0L, maxDelayMs = 0L)
        dhtNode.start()

        val aliceContactDao = FakeContactDao()
        val aliceMessageDao = FakeMessageDao()
        val aliceSkippedKeyDao = FakeSkippedKeyDao()
        val aliceGroupDao = FakeGroupDao()
        val aliceGroupMemberDao = FakeGroupMemberDao()
        val aliceRepo = ChatRepository(
            contactDao = aliceContactDao,
            messageDao = aliceMessageDao,
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = aliceSkippedKeyDao,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = aliceGroupDao,
            groupMemberDao = aliceGroupMemberDao
        ).apply {
            isFastTestMode = true
            delayedPutMaxMs = 0L
            decoyPutSlotsCount = 0
            enableDecoyGets = false
            intraBatchJitterMinMs = 0L
            intraBatchJitterMaxMs = 0L
        }

        val bobContactDao = FakeContactDao()
        val bobMessageDao = FakeMessageDao()
        val bobGroupDao = FakeGroupDao()
        val bobGroupMemberDao = FakeGroupMemberDao()
        val bobRepo = ChatRepository(
            contactDao = bobContactDao,
            messageDao = bobMessageDao,
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = bobGroupDao,
            groupMemberDao = bobGroupMemberDao
        ).apply {
            isFastTestMode = true
            delayedPutMaxMs = 0L
            decoyPutSlotsCount = 0
            enableDecoyGets = false
            intraBatchJitterMinMs = 0L
            intraBatchJitterMaxMs = 0L
        }

        val charlieContactDao = FakeContactDao()
        val charlieMessageDao = FakeMessageDao()
        val charlieGroupDao = FakeGroupDao()
        val charlieGroupMemberDao = FakeGroupMemberDao()
        val charlieRepo = ChatRepository(
            contactDao = charlieContactDao,
            messageDao = charlieMessageDao,
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = charlieGroupDao,
            groupMemberDao = charlieGroupMemberDao
        ).apply {
            isFastTestMode = true
            delayedPutMaxMs = 0L
            decoyPutSlotsCount = 0
            enableDecoyGets = false
            intraBatchJitterMinMs = 0L
            intraBatchJitterMaxMs = 0L
        }

        val daveContactDao = FakeContactDao()
        val daveMessageDao = FakeMessageDao()
        val daveGroupDao = FakeGroupDao()
        val daveGroupMemberDao = FakeGroupMemberDao()
        val daveRepo = ChatRepository(
            contactDao = daveContactDao,
            messageDao = daveMessageDao,
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = daveGroupDao,
            groupMemberDao = daveGroupMemberDao
        ).apply {
            isFastTestMode = true
            delayedPutMaxMs = 0L
            decoyPutSlotsCount = 0
            enableDecoyGets = false
            intraBatchJitterMinMs = 0L
            intraBatchJitterMaxMs = 0L
        }

        try {
            // Seed pre-existing skipped keys on Alice across her 3 direct contacts to verify
            // GroupMemberSlotPollTask is never starved in pollConstantBatch when keys are present.
            val contactNames = listOf("bob" to "Bob", "charlie" to "Charlie", "dave" to "Dave")
            for ((cid, cname) in contactNames) {
                val outKey = CryptoUtils.secureRandomBytes(64)
                val inKey = CryptoUtils.secureRandomBytes(64)
                aliceContactDao.insertOrUpdate(
                    ContactEntity(id = cid, name = cname, chainKeyOut = outKey, chainKeyIn = inKey, counterOut = 0, counterIn = 0, isInitiator = true, isVerified = true)
                )
                val targetDao = when (cid) {
                    "bob" -> bobContactDao
                    "charlie" -> charlieContactDao
                    else -> daveContactDao
                }
                targetDao.insertOrUpdate(
                    ContactEntity(id = "alice", name = "Alice", chainKeyOut = inKey, chainKeyIn = outKey, counterOut = 0, counterIn = 0, isInitiator = false, isVerified = true)
                )
                for (skIdx in 1..3) {
                    aliceSkippedKeyDao.insertOrUpdate(
                        SkippedKeyEntity(
                            contactId = cid,
                            slotIndex = 100 + skIdx,
                            msgKey = CryptoUtils.secureRandomBytes(32),
                            target = CryptoUtils.secureRandomBytes(20),
                            edPrivateKeySeed = CryptoUtils.secureRandomBytes(32)
                        )
                    )
                }
            }

            // 1. Alice creates group and opens chat (simulating repeated UI selectContact calls)
            val group = aliceRepo.createGroup("PQ_4Node_Broadcast_Star", listOf("bob", "charlie", "dave"))
            val groupId = group.groupId
            val groupIdBytes = testUuidStringToBytes(groupId)

            aliceRepo.broadcastMyGroupSenderKey(groupId)
            aliceRepo.broadcastMyGroupSenderKey(groupId)
            aliceRepo.relayMissingGroupKeys(groupId, force = false)

            // 2. Bob, Charlie, Dave receive invites and simulate repeated selectContact broadcasts
            assertTrue(bobRepo.pollContactIncoming("alice"))
            assertTrue(charlieRepo.pollContactIncoming("alice"))
            assertTrue(daveRepo.pollContactIncoming("alice"))

            bobRepo.broadcastMyGroupSenderKey(groupId)
            bobRepo.broadcastMyGroupSenderKey(groupId)
            charlieRepo.broadcastMyGroupSenderKey(groupId)
            charlieRepo.broadcastMyGroupSenderKey(groupId)
            daveRepo.broadcastMyGroupSenderKey(groupId)
            daveRepo.broadcastMyGroupSenderKey(groupId)

            // Alice ingests initial controls via pollGroupIncoming
            aliceRepo.pollGroupIncoming(groupId)
            aliceRepo.relayMissingGroupKeys(groupId, force = false)
            bobRepo.pollGroupIncoming(groupId)
            charlieRepo.pollGroupIncoming(groupId)
            daveRepo.pollGroupIncoming(groupId)

            // Turn 1: Alice sends to group -> Bob, Charlie, Dave receive
            assertTrue(aliceRepo.sendGroupMessage(groupId, "Turn1_Alice"))
            assertTrue(bobRepo.pollGroupIncoming(groupId))
            assertTrue(charlieRepo.pollGroupIncoming(groupId))
            assertTrue(daveRepo.pollGroupIncoming(groupId))

            // Turn 2: Bob sends -> Alice receives via pollConstantBatch despite 9 skipped keys!
            assertTrue(bobRepo.sendGroupMessage(groupId, "Turn2_Bob"))
            assertTrue("Alice pollConstantBatch must receive Bob's Turn 2 message", aliceRepo.pollConstantBatch(groupId))
            assertTrue(charlieRepo.pollGroupIncoming(groupId))
            assertTrue(daveRepo.pollGroupIncoming(groupId))

            // Turn 3: Charlie sends -> Alice receives via pollGroupIncoming immediately
            assertTrue(charlieRepo.sendGroupMessage(groupId, "Turn3_Charlie"))
            assertTrue("Alice pollGroupIncoming must receive Charlie's Turn 3 message", aliceRepo.pollGroupIncoming(groupId))
            assertTrue(bobRepo.pollGroupIncoming(groupId))
            assertTrue(daveRepo.pollGroupIncoming(groupId))

            // Turn 4: Dave sends -> Alice receives via pollConstantBatch
            assertTrue(daveRepo.sendGroupMessage(groupId, "Turn4_Dave"))
            assertTrue("Alice pollConstantBatch must receive Dave's Turn 4 message", aliceRepo.pollConstantBatch(groupId))
            assertTrue(bobRepo.pollGroupIncoming(groupId))
            assertTrue(charlieRepo.pollGroupIncoming(groupId))

            assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == "Turn2_Bob" && !it.isOutgoing })
            assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == "Turn3_Charlie" && !it.isOutgoing })
            assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == "Turn4_Dave" && !it.isOutgoing })

            // Verify stale GROUP_SUBTYPE_REKEY / GROUP_SUBTYPE_KEY_BUNDLE with counter=0 does not rewind counterIn > 0
            val bobMemberId = bobGroupDao.getGroupById(groupId)!!.myMemberId
            val bobInitialKey = bobGroupDao.getGroupById(groupId)!!.let {
                // Re-derive Epoch 1 counter=0 key from Alice's original seed via control or compare counterIn stays at 1
                aliceGroupMemberDao.getMember(groupId, bobMemberId)!!
            }
            assertEquals(1, bobInitialKey.counterIn)

            // Reconstruct Bob's initial counter=0 key using the same deterministic seed
            val staleBobKey0 = org.pqchat.dht.protocol.RatchetChain.deriveGroupMemberSenderKey(
                group.rawMyChainKeyOut,
                groupIdBytes,
                testUuidStringToBytes(bobMemberId)
            )
            aliceRepo.processIncomingGroupControl(
                contactId = "bob",
                control = org.pqchat.dht.crypto.BinaryFrameCodec.DecodedPayload.GroupControl(
                    controlSubType = org.pqchat.dht.crypto.BinaryFrameCodec.GROUP_SUBTYPE_REKEY,
                    groupId = groupIdBytes,
                    groupEpoch = 1L,
                    senderMemberId = testUuidStringToBytes(bobMemberId),
                    senderGroupChainKey = staleBobKey0,
                    currentCounter = 0L,
                    groupName = "PQ_4Node_Broadcast_Star",
                    members = emptyList(),
                    memberKeys = emptyList()
                )
            )
            aliceRepo.processIncomingGroupControl(
                contactId = "bob",
                control = org.pqchat.dht.crypto.BinaryFrameCodec.DecodedPayload.GroupControl(
                    controlSubType = org.pqchat.dht.crypto.BinaryFrameCodec.GROUP_SUBTYPE_KEY_BUNDLE,
                    groupId = groupIdBytes,
                    groupEpoch = 1L,
                    senderMemberId = testUuidStringToBytes(bobMemberId),
                    senderGroupChainKey = ByteArray(64),
                    currentCounter = 0L,
                    groupName = "PQ_4Node_Broadcast_Star",
                    members = emptyList(),
                    memberKeys = listOf(
                        org.pqchat.dht.crypto.BinaryFrameCodec.DecodedPayload.GroupMemberKey(
                            memberId = testUuidStringToBytes(bobMemberId),
                            counter = 0L,
                            chainKey = staleBobKey0
                        )
                    )
                )
            )

            val bobMemberAfterStale = aliceGroupMemberDao.getMember(groupId, bobMemberId)!!
            assertEquals("Stale REKEY/KEY_BUNDLE must not rewind Alice's counterIn for Bob", 1, bobMemberAfterStale.counterIn)
            assertArrayEquals("Stale REKEY/KEY_BUNDLE must not rewind Alice's chainKeyIn for Bob", bobInitialKey.rawChainKeyIn, bobMemberAfterStale.rawChainKeyIn)

            // Bob's second group message (counter=1) must still decrypt cleanly on Alice!
            assertTrue(bobRepo.sendGroupMessage(groupId, "Turn5_Bob_AfterStaleControl"))
            assertTrue("Alice must decrypt Bob's counter=1 message after stale control rejection", aliceRepo.pollGroupIncoming(groupId))
            assertEquals(1, aliceMessageDao.messages.count { it.textContent?.raw == "Turn5_Bob_AfterStaleControl" && !it.isOutgoing })
        } finally {
            aliceRepo.close()
            bobRepo.close()
            charlieRepo.close()
            daveRepo.close()
            dhtNode.stop()
        }
    }

    private data class RegressionPeerHarness(
        val contactDao: FakeContactDao,
        val messageDao: FakeMessageDao,
        val groupDao: FakeGroupDao,
        val groupMemberDao: FakeGroupMemberDao,
        val repo: ChatRepository
    )

    private fun createRegressionPeer(dhtNode: FakeDht): RegressionPeerHarness {
        val contactDao = FakeContactDao()
        val messageDao = FakeMessageDao()
        val groupDao = FakeGroupDao()
        val groupMemberDao = FakeGroupMemberDao()
        val repo = ChatRepository(
            contactDao = contactDao,
            messageDao = messageDao,
            chunkDao = FakeChunkDao(),
            pendingRekeyOfferDao = null,
            skippedKeyDao = null,
            dhtLeafNode = dhtNode,
            pendingAckQueue = PendingAckQueue(),
            groupDao = groupDao,
            groupMemberDao = groupMemberDao
        )
        return RegressionPeerHarness(contactDao, messageDao, groupDao, groupMemberDao, repo)
    }

    private suspend fun setupRegressionPairwiseChannel(
        initiator: RegressionPeerHarness,
        responder: RegressionPeerHarness,
        initiatorIdInResponder: String,
        initiatorNameInResponder: String,
        responderIdInInitiator: String,
        responderNameInInitiator: String
    ) {
        val outKey = CryptoUtils.secureRandomBytes(64)
        val inKey = CryptoUtils.secureRandomBytes(64)
        initiator.contactDao.insertOrUpdate(
            ContactEntity(
                id = responderIdInInitiator,
                name = responderNameInInitiator,
                chainKeyOut = outKey,
                chainKeyIn = inKey,
                counterOut = 0,
                counterIn = 0,
                isInitiator = true,
                isVerified = true
            )
        )
        responder.contactDao.insertOrUpdate(
            ContactEntity(
                id = initiatorIdInResponder,
                name = initiatorNameInResponder,
                chainKeyOut = inKey,
                chainKeyIn = outKey,
                counterOut = 0,
                counterIn = 0,
                isInitiator = false,
                isVerified = true
            )
        )
    }

    @Test
    fun testAdvancedKeyBundleAndRekeyDoNotSkipUnreceivedMessageZeroOnSameChain() = runBlocking {
        val dhtNode = FakeDht()
        val alice = createRegressionPeer(dhtNode)
        val dave = createRegressionPeer(dhtNode)

        try {
            setupRegressionPairwiseChannel(alice, dave, "alice", "Alice", "dave", "Dave")

            val group = alice.repo.createGroup("Advanced_Bundle_Guard_Group", listOf("dave"))
            val groupId = group.groupId
            val groupIdBytes = testUuidStringToBytes(groupId)
            val aliceMemberId = group.myMemberId
            val aliceMemberIdBytes = testUuidStringToBytes(aliceMemberId)

            assertTrue("Dave must ingest Alice's group invite", dave.repo.pollContactIncoming("alice"))
            val daveAliceInitial = dave.groupMemberDao.getMember(groupId, aliceMemberId)!!
            assertEquals(0, daveAliceInitial.counterIn)
            val aliceKey0 = daveAliceInitial.rawChainKeyIn.copyOf()

            // Alice sends Turn 1 (counter=0) while Dave has not polled the group yet, advancing Alice's local chain to counter=1
            assertTrue("Alice must send counter=0 group message", alice.repo.sendGroupMessage(groupId, "Turn1_Msg0_InFlight"))
            val aliceAdvancedGroup = alice.groupDao.getGroupById(groupId)!!
            assertEquals(1, aliceAdvancedGroup.myCounterOut)
            val aliceKey1 = aliceAdvancedGroup.rawMyChainKeyOut.copyOf()

            // Simulate delayed Alice KEY_BUNDLE and REKEY arriving with Alice's already-advanced state (counter=1)
            dave.repo.processIncomingGroupControl(
                contactId = "alice",
                control = org.pqchat.dht.crypto.BinaryFrameCodec.DecodedPayload.GroupControl(
                    controlSubType = org.pqchat.dht.crypto.BinaryFrameCodec.GROUP_SUBTYPE_KEY_BUNDLE,
                    groupId = groupIdBytes,
                    groupEpoch = 1L,
                    senderMemberId = aliceMemberIdBytes,
                    senderGroupChainKey = ByteArray(64),
                    currentCounter = 0L,
                    groupName = "Advanced_Bundle_Guard_Group",
                    members = emptyList(),
                    memberKeys = listOf(
                        org.pqchat.dht.crypto.BinaryFrameCodec.DecodedPayload.GroupMemberKey(
                            memberId = aliceMemberIdBytes,
                            counter = 1L,
                            chainKey = aliceKey1
                        )
                    )
                )
            )
            dave.repo.processIncomingGroupControl(
                contactId = "alice",
                control = org.pqchat.dht.crypto.BinaryFrameCodec.DecodedPayload.GroupControl(
                    controlSubType = org.pqchat.dht.crypto.BinaryFrameCodec.GROUP_SUBTYPE_REKEY,
                    groupId = groupIdBytes,
                    groupEpoch = 1L,
                    senderMemberId = aliceMemberIdBytes,
                    senderGroupChainKey = aliceKey1,
                    currentCounter = 1L,
                    groupName = "Advanced_Bundle_Guard_Group",
                    members = emptyList(),
                    memberKeys = emptyList()
                )
            )

            // Same-chain advanced counter=1 control must NOT skip Dave's unreceived counter=0 slot
            val daveAliceAfterRelay = dave.groupMemberDao.getMember(groupId, aliceMemberId)!!
            assertEquals("Dave counterIn must remain at 0 for unreceived message 0", 0, daveAliceAfterRelay.counterIn)
            assertArrayEquals("Dave chainKeyIn must remain at chain(0)", aliceKey0, daveAliceAfterRelay.rawChainKeyIn)

            // Dave must still decrypt the in-flight counter=0 message
            assertTrue("Dave must poll and decrypt Alice's message 0", dave.repo.pollGroupIncoming(groupId))
            assertEquals(1, dave.messageDao.messages.count { it.textContent?.raw == "Turn1_Msg0_InFlight" && !it.isOutgoing })
        } finally {
            alice.repo.close()
            dave.repo.close()
            dhtNode.stop()
        }
    }

    @Test
    fun testOlderEpochRekeyDoesNotOverwriteNewerEpochMemberKey() = runBlocking {
        val dhtNode = FakeDht()
        val alice = createRegressionPeer(dhtNode)
        val bob = createRegressionPeer(dhtNode)

        try {
            setupRegressionPairwiseChannel(alice, bob, "alice", "Alice", "bob", "Bob")

            val group = alice.repo.createGroup("Epoch_Monotonicity_Group", listOf("bob"))
            val groupId = group.groupId
            val groupIdBytes = testUuidStringToBytes(groupId)
            assertTrue(bob.repo.pollContactIncoming("alice"))
            val bobMemberId = bob.groupDao.getGroupById(groupId)!!.myMemberId
            val bobMemberIdBytes = testUuidStringToBytes(bobMemberId)

            val epoch2Key = CryptoUtils.secureRandomBytes(64)
            alice.repo.processIncomingGroupControl(
                contactId = "bob",
                control = org.pqchat.dht.crypto.BinaryFrameCodec.DecodedPayload.GroupControl(
                    controlSubType = org.pqchat.dht.crypto.BinaryFrameCodec.GROUP_SUBTYPE_REKEY,
                    groupId = groupIdBytes,
                    groupEpoch = 2L,
                    senderMemberId = bobMemberIdBytes,
                    senderGroupChainKey = epoch2Key,
                    currentCounter = 0L,
                    groupName = "Epoch_Monotonicity_Group",
                    members = emptyList(),
                    memberKeys = emptyList()
                )
            )
            val afterEpoch2 = alice.groupMemberDao.getMember(groupId, bobMemberId)!!
            assertArrayEquals("Epoch 2 REKEY must update member key", epoch2Key, afterEpoch2.rawChainKeyIn)

            // Deliver stale Epoch 1 REKEY with a higher counter
            val epoch1StaleKey = CryptoUtils.secureRandomBytes(64)
            alice.repo.processIncomingGroupControl(
                contactId = "bob",
                control = org.pqchat.dht.crypto.BinaryFrameCodec.DecodedPayload.GroupControl(
                    controlSubType = org.pqchat.dht.crypto.BinaryFrameCodec.GROUP_SUBTYPE_REKEY,
                    groupId = groupIdBytes,
                    groupEpoch = 1L,
                    senderMemberId = bobMemberIdBytes,
                    senderGroupChainKey = epoch1StaleKey,
                    currentCounter = 5L,
                    groupName = "Epoch_Monotonicity_Group",
                    members = emptyList(),
                    memberKeys = emptyList()
                )
            )
            val afterStaleEpoch1 = alice.groupMemberDao.getMember(groupId, bobMemberId)!!
            assertArrayEquals("Stale Epoch 1 REKEY must never overwrite Epoch 2 key", epoch2Key, afterStaleEpoch1.rawChainKeyIn)
            assertEquals(0, afterStaleEpoch1.counterIn)
        } finally {
            alice.repo.close()
            bob.repo.close()
            dhtNode.stop()
        }
    }

    @Test
    fun testRepublishRecentGroupMessagesSkipsTombstoneAndRepublishesEvictedSlot() = runBlocking {
        val dhtNode = FakeDht()
        val alice = createRegressionPeer(dhtNode)
        val bob = createRegressionPeer(dhtNode)
        val charlie = createRegressionPeer(dhtNode)

        try {
            setupRegressionPairwiseChannel(alice, bob, "alice", "Alice", "bob", "Bob")
            setupRegressionPairwiseChannel(alice, charlie, "alice", "Alice", "charlie", "Charlie")

            val group = alice.repo.createGroup("Republish_Tombstone_Guard", listOf("bob", "charlie"))
            val groupId = group.groupId
            assertTrue(bob.repo.pollContactIncoming("alice"))
            assertTrue(charlie.repo.pollContactIncoming("alice"))

            val keysBeforeSend = dhtNode.storage.keys.toSet()
            assertTrue(alice.repo.sendGroupMessage(groupId, "Msg_For_Bob_And_Charlie"))
            val newSlots = dhtNode.storage.keys - keysBeforeSend
            assertEquals("Sending to Bob & Charlie must create 2 recipient slots", 2, newSlots.size)

            // Bob polls and tombstones his slot
            assertTrue(bob.repo.pollGroupIncoming(groupId))
            val bobTombstonedKey = newSlots.single { (dhtNode.storage[it]?.item?.seq ?: 0L) > 1L }
            val charliePendingKey = newSlots.single { it != bobTombstonedKey }
            val bobTombstoneEntry = dhtNode.storage[bobTombstonedKey]!!.item
            val bobTombstoneSeq = bobTombstoneEntry.seq
            val bobTombstoneBytes = bobTombstoneEntry.v.copyOf()

            // Simulate DHT eviction of Charlie's unconsumed slot
            dhtNode.storage.remove(charliePendingKey)

            // Republish must leave Bob's tombstone untouched and restore Charlie's evicted slot
            val republished = alice.repo.republishRecentGroupMessages(groupId, force = true)
            assertEquals("Only Charlie's unconsumed slot should be republished", 1, republished)

            val bobAfterRepublish = dhtNode.storage[bobTombstonedKey]!!.item
            assertEquals("Bob tombstone seq must remain unchanged", bobTombstoneSeq, bobAfterRepublish.seq)
            assertArrayEquals("Bob tombstone noise bytes must not be overwritten", bobTombstoneBytes, bobAfterRepublish.v)

            assertNotNull("Charlie's evicted slot must be restored on DHT", dhtNode.storage[charliePendingKey])
            assertTrue("Charlie must receive message after republish", charlie.repo.pollGroupIncoming(groupId))
            assertEquals(1, charlie.messageDao.messages.count { it.textContent?.raw == "Msg_For_Bob_And_Charlie" && !it.isOutgoing })
        } finally {
            alice.repo.close()
            bob.repo.close()
            charlie.repo.close()
            dhtNode.stop()
        }
    }
}
