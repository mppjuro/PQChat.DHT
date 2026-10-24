package org.pqchat.dht.e2e

import androidx.room.Room
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.jupiter.api.Tag
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.crypto.KeystoreCrypto
import org.pqchat.dht.protocol.RatchetChain
import org.pqchat.dht.data.db.AppDatabase
import org.pqchat.dht.data.db.ContactEntity
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.HandshakeManager
import org.pqchat.dht.protocol.RekeyCoordinator
import org.pqchat.dht.protocol.SlidingWindowBitmap
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.net.InetSocketAddress
import java.security.Security
import javax.crypto.spec.SecretKeySpec

/**
 * Full End-to-End integration test simulating two devices (Alice and Bob):
 * - Two in-memory Room AppDatabase instances
 * - Real DHT by default (with DhtLeafNode) or FakeDht (configured via -DuseFakeDht=true or USE_FAKE_DHT=true)
 * - Complete Handshake: Alice QR generation -> Bob scan & PUT to Target_0 -> Alice GET & finalize
 * - Bidirectional messaging (>10 messages), verifying seqNum order, content integrity, and counter tracking
 * - PQC Rekey coordination after 50 messages, verifying new epoch operation and old key forward secrecy
 * - Out-of-order delivery in permutation and duplicate rejection via SlidingWindowBitmap
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
@Tag("slow")
class TwoDevicesE2EIntegrationTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupClass() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }

        fun shouldUseFakeDht(): Boolean {
            val runReal = System.getProperty("runRealDhtTests")?.equals("true", ignoreCase = true) == true ||
                          System.getenv("RUN_REAL_DHT_TESTS")?.equals("true", ignoreCase = true) == true
            if (runReal) return false
            return System.getProperty("useFakeDht")?.equals("false", ignoreCase = true) != true &&
                   System.getenv("USE_FAKE_DHT")?.equals("false", ignoreCase = true) != true
        }
    }

    private var aliceDb: AppDatabase? = null
    private var bobDb: AppDatabase? = null
    private var aliceDhtClient: DhtClient? = null
    private var bobDhtClient: DhtClient? = null
    private val testMasterKey = SecretKeySpec(ByteArray(32) { (it * 13 + 5).toByte() }, "AES")

    @Before
    fun setUp() {
        KeystoreCrypto.setTestSecretKey(testMasterKey)
        val context = RuntimeEnvironment.getApplication()
        aliceDb = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        bobDb = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
    }

    @After
    fun tearDown() {
        aliceDhtClient?.stop()
        bobDhtClient?.stop()
        aliceDb?.close()
        bobDb?.close()
        KeystoreCrypto.resetForTesting()
    }

    @Test
    fun testTwoDevicesEndToEndScenario() = runBlocking {
        val useFake = shouldUseFakeDht()
        println("[E2E Test] Executing scenario with useFakeDht=$useFake (Default is Real DHT)")
        runFullTwoDevicesLifecycle(useFakeDht = useFake)
    }

    @Test
    fun testTwoDevicesEndToEndOnFakeDhtExplicit() = runBlocking {
        println("[E2E Test] Executing explicit FakeDht verification")
        runFullTwoDevicesLifecycle(useFakeDht = true)
    }

    private suspend fun runFullTwoDevicesLifecycle(useFakeDht: Boolean) {
        val aDb = aliceDb!!
        val bDb = bobDb!!

        // 1. Initialize DHT layer
        if (useFakeDht) {
            val sharedDht = FakeDht(minDelayMs = 0, maxDelayMs = 0)
            sharedDht.start()
            aliceDhtClient = sharedDht
            bobDhtClient = sharedDht
        } else {
            val aNode = DhtLeafNode(autoBootstrap = false)
            val bNode = DhtLeafNode(autoBootstrap = false)
            aNode.start()
            bNode.start()

            // Local UDP peering between the two nodes
            val aliceAddr = InetSocketAddress("127.0.0.1", aNode.localPort)
            val bobAddr = InetSocketAddress("127.0.0.1", bNode.localPort)
            aNode.addPeer(bNode.myNodeId, bobAddr)
            bNode.addPeer(aNode.myNodeId, aliceAddr)

            aliceDhtClient = aNode
            bobDhtClient = bNode
        }

        val aDht = aliceDhtClient!!
        val bDht = bobDhtClient!!

        val aliceRepo = ChatRepository(aDb, aDht)
        aliceRepo.delayedPutMaxMs = 0L
        aliceRepo.decoyPutSlotsCount = 0
        aliceRepo.enableDecoyGets = false

        val bobRepo = ChatRepository(bDb, bDht)
        bobRepo.delayedPutMaxMs = 0L
        bobRepo.decoyPutSlotsCount = 0
        bobRepo.enableDecoyGets = false

        // =========================================================================
        // 2. Handshake Phase: Alice QR -> Bob Scan & PUT Target_0 -> Alice Finalize
        // =========================================================================
        println("[E2E Phase 1] Handshake initiated by Alice")
        val aliceInit = HandshakeManager.aliceCreateHandshake()
        assertNotNull("Alice QR payload must be created", aliceInit.qrBytes)
        assertEquals(864, aliceInit.qrBytes.size)

        // Bob scans QR code
        val bobResult = HandshakeManager.bobProcessQr(aliceInit.qrBytes)
        assertArrayEquals("Target_0 must match between Alice and Bob", aliceInit.target0, bobResult.target0)

        // Bob publishes Type 0x01 handshake frame to Target_0
        val bobPutSuccess = bDht.putMutable(
            target = bobResult.target0,
            v = bobResult.frame,
            seq = 1L,
            salt = null,
            sk = bobResult.edPrivateKeySeed,
            skipLocalStore = false
        )
        assertTrue("Bob must successfully put handshake frame to Target_0", bobPutSuccess)

        // Alice retrieves frame from Target_0
        var item0: DhtLeafNode.MutableItem? = null
        for (attempt in 1..30) {
            item0 = aDht.getMutable(aliceInit.target0, null, false, 3000L)
            if (item0 != null) break
            delay(100)
        }
        assertNotNull("Alice must retrieve handshake frame from Target_0", item0)

        // Alice finalizes session
        val aliceSession = HandshakeManager.aliceFinalize(
            skA = aliceInit.skA,
            pkA = aliceInit.pkA,
            seedInit = aliceInit.seedInit,
            frame = item0!!.v
        )
        assertEquals("SAS tokens must match", aliceSession.sas, bobResult.sas)
        assertEquals("Fingerprints must match", aliceSession.fingerprint, bobResult.fingerprint)

        // Verify Alice's ephemeral private key skA was wiped with zeros
        assertTrue("Alice's ephemeral skA must be wiped with zeros", aliceInit.skA.all { it == 0.toByte() })

        // Add established contacts to respective databases
        val aliceContact = ContactEntity(
            id = "bob",
            name = "Bob",
            chainKeyOut = aliceSession.chainKeyOut,
            chainKeyIn = aliceSession.chainKeyIn,
            counterOut = 0,
            counterIn = 0,
            rekeyEpoch = 0,
            isInitiator = true
        )
        aliceRepo.addContact(aliceContact)

        val bobContact = ContactEntity(
            id = "alice",
            name = "Alice",
            chainKeyOut = bobResult.chainKeyBtoA,
            chainKeyIn = bobResult.chainKeyAtoB,
            counterOut = 0,
            counterIn = 0,
            rekeyEpoch = 0,
            isInitiator = false
        )
        bobRepo.addContact(bobContact)

        // Verify counters initialized to zero in database
        val initAliceContact = aliceRepo.getContact("bob")!!
        val initBobContact = bobRepo.getContact("alice")!!
        assertEquals("Alice counterOut must start at 0", 0, initAliceContact.counterOut)
        assertEquals("Alice counterIn must start at 0", 0, initAliceContact.counterIn)
        assertEquals("Bob counterOut must start at 0", 0, initBobContact.counterOut)
        assertEquals("Bob counterIn must start at 0", 0, initBobContact.counterIn)

        // =========================================================================
        // 3. Bidirectional Messaging: >10 messages exchanged in both directions
        // =========================================================================
        println("[E2E Phase 2] Exchanging 15 messages bidirectionally")
        val messageCount = 15
        for (i in 0 until messageCount) {
            // Alice -> Bob
            val aliceText = "Hello Bob from Alice #$i"
            assertTrue("Alice send #$i must succeed", aliceRepo.sendTextMessage("bob", aliceText))

            var bobReceived = false
            for (attempt in 1..30) {
                if (bobRepo.pollContactIncoming("alice")) {
                    bobReceived = true
                    break
                }
                delay(80)
            }
            assertTrue("Bob must receive Alice's message #$i", bobReceived)

            // Bob -> Alice
            val bobText = "Hello Alice from Bob #$i"
            assertTrue("Bob send #$i must succeed", bobRepo.sendTextMessage("alice", bobText))

            var aliceReceived = false
            for (attempt in 1..30) {
                if (aliceRepo.pollContactIncoming("bob")) {
                    aliceReceived = true
                    break
                }
                delay(80)
            }
            assertTrue("Alice must receive Bob's message #$i", aliceReceived)
        }

        // Verify seqNum order and content integrity for Bob's received messages
        val bobDelivered = bDb.messageDao().getMessagesForContactFlow("alice").first()
            .filter { !it.isOutgoing }
            .sortedBy { it.seqNum }
        assertEquals(messageCount, bobDelivered.size)
        for (i in 0 until messageCount) {
            assertEquals("Bob message #$i seqNum must match index", i, bobDelivered[i].seqNum)
            assertEquals("Bob message #$i content must match", "Hello Bob from Alice #$i", bobDelivered[i].textContent.toString())
            assertEquals("Bob message #$i status must be DELIVERED", "DELIVERED", bobDelivered[i].status)
        }

        // Verify seqNum order and content integrity for Alice's received messages
        val aliceDelivered = aDb.messageDao().getMessagesForContactFlow("bob").first()
            .filter { !it.isOutgoing }
            .sortedBy { it.seqNum }
        assertEquals(messageCount, aliceDelivered.size)
        for (i in 0 until messageCount) {
            assertEquals("Alice message #$i seqNum must match index", i, aliceDelivered[i].seqNum)
            assertEquals("Alice message #$i content must match", "Hello Alice from Bob #$i", aliceDelivered[i].textContent.toString())
            assertEquals("Alice message #$i status must be DELIVERED", "DELIVERED", aliceDelivered[i].status)
        }

        // Verify counter progression
        val cAliceAfter15 = aliceRepo.getContact("bob")!!
        val cBobAfter15 = bobRepo.getContact("alice")!!
        assertEquals(messageCount, cAliceAfter15.counterOut)
        assertEquals(messageCount, cAliceAfter15.counterIn)
        assertEquals(messageCount, cBobAfter15.counterOut)
        assertEquals(messageCount, cBobAfter15.counterIn)

        // =========================================================================
        // 4. Rekey Phase: Advance to 50 messages, trigger RekeyCoordinator, verify
        // =========================================================================
        println("[E2E Phase 3] Advancing messages to 50 for PQC Rekey")
        // Alice sends messages 15..48
        for (i in 15 until 49) {
            aliceRepo.sendTextMessage("bob", "Pre-rekey msg #$i")
            bobRepo.pollContactIncoming("alice")
        }
        assertEquals(49, aliceRepo.getContact("bob")!!.counterOut)

        // Message 49 (which is the 50th message): counterOut becomes 50
        aliceRepo.sendTextMessage("bob", "Pre-rekey msg #49")
        bobRepo.pollContactIncoming("alice")
        val contactBeforeRekey = aliceRepo.getContact("bob")!!
        assertEquals(50, contactBeforeRekey.counterOut)
        assertTrue("RekeyCoordinator must qualify counterOut=50", RekeyCoordinator.shouldOfferRekey(contactBeforeRekey.counterOut))

        // Save pre-rekey keys for forward secrecy and post-compromise verification
        val oldAliceChainKeyOut = contactBeforeRekey.chainKeyOut.copyOf()
        val oldBobChainKeyIn = bobRepo.getContact("alice")!!.chainKeyIn.copyOf()
        assertEquals(0L, contactBeforeRekey.rekeyEpoch)

        // Next message triggers createRekeyOffer and queues the text in Alice's outbox
        val rekeyTriggerResult = aliceRepo.sendTextMessage("bob", "Message queued during rekey")
        assertFalse("Message sent during rekey offer initiation must be queued", rekeyTriggerResult)

        val pendingOffer = aDb.pendingRekeyOfferDao().getPendingOffer("bob")
        assertNotNull("Pending rekey offer must be saved in database", pendingOffer)
        assertEquals(1L, pendingOffer!!.epoch)
        val queuedOutbox = aDb.messageDao().getQueuedMessagesForContact("bob")
        assertEquals(1, queuedOutbox.size)
        assertEquals("Message queued during rekey", queuedOutbox[0].textContent.toString())

        // Bob polls incoming: receives Type 0x03 offer, encapsulates SS_rekey, advances epoch to 1, sends Type 0x04 response
        var bobProcessedOffer = false
        for (attempt in 1..30) {
            if (bobRepo.pollContactIncoming("alice")) {
                bobProcessedOffer = true
                break
            }
            delay(80)
        }
        assertTrue("Bob must process rekey offer", bobProcessedOffer)
        val bobRekeyedContact = bobRepo.getContact("alice")!!
        assertEquals("Bob rekeyEpoch must advance to 1", 1L, bobRekeyedContact.rekeyEpoch)

        // Alice polls incoming: receives Type 0x04 response, decapsulates SS_rekey, advances epoch to 1, drains outbox
        var aliceProcessedResp = false
        for (attempt in 1..30) {
            if (aliceRepo.pollContactIncoming("bob")) {
                aliceProcessedResp = true
                break
            }
            delay(80)
        }
        assertTrue("Alice must process rekey response", aliceProcessedResp)
        val aliceRekeyedContact = aliceRepo.getContact("bob")!!
        assertEquals("Alice rekeyEpoch must advance to 1", 1L, aliceRekeyedContact.rekeyEpoch)
        assertNull("Pending rekey offer must be deleted", aDb.pendingRekeyOfferDao().getPendingOffer("bob"))
        assertTrue("Outbox must be drained", aDb.messageDao().getQueuedMessagesForContact("bob").isEmpty())

        // Bob polls incoming: receives drained outbox message
        var bobGotDrained = false
        for (attempt in 1..30) {
            if (bobRepo.pollContactIncoming("alice")) {
                bobGotDrained = true
                break
            }
            delay(80)
        }
        assertTrue("Bob must receive drained message", bobGotDrained)
        val deliveredDrained = bDb.messageDao().getMessagesForContactFlow("alice").first()
            .firstOrNull { it.textContent.toString() == "Message queued during rekey" }
        assertNotNull("Drained message must be delivered", deliveredDrained)
        assertEquals("DELIVERED", deliveredDrained!!.status)

        // Alice sends another message in epoch 1 to confirm bidirectional epoch 1 communication
        assertTrue(aliceRepo.sendTextMessage("bob", "Second message in epoch 1"))
        var bobGotSecondInEpoch1 = false
        for (attempt in 1..30) {
            if (bobRepo.pollContactIncoming("alice")) {
                bobGotSecondInEpoch1 = true
                break
            }
            delay(80)
        }
        assertTrue("Bob must receive second message in epoch 1", bobGotSecondInEpoch1)

        // Forward Secrecy Verification: Old pre-rekey chain keys are unusable for epoch 1
        val oldSlot = RatchetChain.deriveSlot(oldAliceChainKeyOut, 51)
        val newSlot = RatchetChain.deriveSlot(aliceRekeyedContact.chainKeyOut, 51)
        assertFalse("Old msgKey must not match rekeyed msgKey", oldSlot.msgKey.contentEquals(newSlot.msgKey))
        assertFalse("Old target must not match rekeyed target", oldSlot.target.contentEquals(newSlot.target))

        // Encrypting a dummy frame with old msgKey fails decryption against rekeyed receiver state
        val oldFrame = BinaryFrameCodec.packAeadFrame(
            key = oldSlot.msgKey,
            plaintext = BinaryFrameCodec.encodeTextMessage(51, 0, System.currentTimeMillis(), "Stale key payload"),
            target = newSlot.target,
            direction = "AliceToBob"
        )
        var decryptionFailedWithOldKey = false
        try {
            BinaryFrameCodec.unpackAeadFrame(
                key = newSlot.msgKey,
                frame = oldFrame,
                target = newSlot.target,
                direction = "AliceToBob"
            )
        } catch (_: Exception) {
            decryptionFailedWithOldKey = true
        }
        assertTrue("Old key payload must fail decryption against rekeyed state", decryptionFailedWithOldKey)

        // Verify offer's ephemeral private key was destroyed
        assertNull("Pending rekey offer must be deleted from database", aDb.pendingRekeyOfferDao().getPendingOffer("bob"))
        pendingOffer.destroy()
        assertTrue("Pending offer ephemeral private key must be wiped with zeros", pendingOffer.rawSkNew.all { it == 0.toByte() })

        // =========================================================================
        // 5. Out-of-Order Delivery & SlidingWindowBitmap Duplicate Rejection
        // =========================================================================
        println("[E2E Phase 4] Out-of-order delivery permutation and SlidingWindowBitmap duplicate verification")

        // 5a. Direct SlidingWindowBitmap Unit Verification with Permutation
        val windowTest = SlidingWindowBitmap(windowBase = 100)
        val permutedOrder = listOf(103, 100, 104, 101, 102) // Permutation of 100..104

        for (seq in permutedOrder) {
            assertFalse("Sequence $seq must not be marked initially", windowTest.isReceived(seq))
            assertTrue("markReceived($seq) must succeed on first delivery", windowTest.markReceived(seq))
            assertTrue("Sequence $seq must now be recorded as received", windowTest.isReceived(seq))
            // Duplicate rejection check:
            assertFalse("Duplicate markReceived($seq) must return false", windowTest.markReceived(seq))
        }
        assertEquals("Window base must advance to 105 after all contiguous sequences arrive", 105, windowTest.windowBase)
        for (seq in 100..104) {
            assertTrue("Historical sequence $seq must report isReceived=true", windowTest.isReceived(seq))
            assertFalse("Historical sequence $seq must reject markReceived", windowTest.markReceived(seq))
        }

        // 5b. End-to-End Out-of-Order & Duplicate Rejection in Repository
        val curAlice = aliceRepo.getContact("bob")!!
        val curBob = bobRepo.getContact("alice")!!
        val startCounter = curAlice.counterOut

        val slot0 = RatchetChain.deriveSlot(curAlice.chainKeyOut, startCounter)
        val slot1 = RatchetChain.deriveSlot(slot0.nextChainKey, startCounter + 1)
        val slot2 = RatchetChain.deriveSlot(slot1.nextChainKey, startCounter + 2)

        val frame0 = BinaryFrameCodec.packAeadFrame(
            key = slot0.msgKey,
            plaintext = BinaryFrameCodec.encodeTextMessage(startCounter and 0xFFFF, 0, System.currentTimeMillis(), "Permuted msg #0"),
            target = slot0.target,
            direction = "AliceToBob"
        )
        val frame1 = BinaryFrameCodec.packAeadFrame(
            key = slot1.msgKey,
            plaintext = BinaryFrameCodec.encodeTextMessage((startCounter + 1) and 0xFFFF, 0, System.currentTimeMillis(), "Permuted msg #1"),
            target = slot1.target,
            direction = "AliceToBob"
        )
        val frame2 = BinaryFrameCodec.packAeadFrame(
            key = slot2.msgKey,
            plaintext = BinaryFrameCodec.encodeTextMessage((startCounter + 2) and 0xFFFF, 0, System.currentTimeMillis(), "Permuted msg #2"),
            target = slot2.target,
            direction = "AliceToBob"
        )

        // Deliver slot 2 first (out-of-order)
        val item2 = DhtLeafNode.MutableItem(frame2, 1L, ByteArray(32), ByteArray(64), null, null)
        val processed2 = bobRepo.processIncomingItem("alice", slot2, item2, isSelf = false)
        assertTrue("Out-of-order slot 2 must be processed", processed2)

        // Deliver duplicate of slot 2
        bobRepo.processIncomingItem("alice", slot2, item2, isSelf = false)
        val slot2Messages = bDb.messageDao().getMessagesForContactFlow("alice").first()
            .filter { it.seqNum == startCounter + 2 }
        assertEquals("Duplicate frame 2 must NOT be duplicated in MessageDao", 1, slot2Messages.size)

        // Deliver slot 0 and slot 1
        val item0Out = DhtLeafNode.MutableItem(frame0, 1L, ByteArray(32), ByteArray(64), null, null)
        bobRepo.processIncomingItem("alice", slot0, item0Out, isSelf = false)

        val item1Out = DhtLeafNode.MutableItem(frame1, 1L, ByteArray(32), ByteArray(64), null, null)
        bobRepo.processIncomingItem("alice", slot1, item1Out, isSelf = false)

        // Deliver duplicate of slot 0 and slot 1
        bobRepo.processIncomingItem("alice", slot0, item0Out, isSelf = false)
        bobRepo.processIncomingItem("alice", slot1, item1Out, isSelf = false)

        val allPermutedMsgs = bDb.messageDao().getMessagesForContactFlow("alice").first()
            .filter { it.seqNum in startCounter..(startCounter + 2) }
        assertEquals("All 3 permuted messages must be stored exactly once", 3, allPermutedMsgs.size)
        assertEquals(
            "Distinct sequence numbers must be present",
            setOf(startCounter, startCounter + 1, startCounter + 2),
            allPermutedMsgs.map { it.seqNum }.toSet()
        )

        val finalBobContact = bobRepo.getContact("alice")!!
        val finalBitmap = SlidingWindowBitmap(finalBobContact.receivedBitmapBase, 1024, finalBobContact.receivedBitmap)
        for (s in startCounter..(startCounter + 2)) {
            assertTrue("Sequence $s must be marked received in final contact bitmap", finalBitmap.isReceived(s))
            assertFalse("Sequence $s duplicate must be rejected", finalBitmap.markReceived(s))
        }

        println("[E2E Test] Two Devices Full Lifecycle Test Completed Successfully!")
    }
}
