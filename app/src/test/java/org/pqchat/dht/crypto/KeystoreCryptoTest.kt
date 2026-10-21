package org.pqchat.dht.crypto

import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.pqchat.dht.data.db.ContactEntity
import org.pqchat.dht.data.db.EncryptedBlob
import org.pqchat.dht.data.db.EncryptedText
import org.pqchat.dht.data.db.GroupEntity
import org.pqchat.dht.data.db.KeystoreConverters
import java.security.GeneralSecurityException
import javax.crypto.AEADBadTagException
import javax.crypto.spec.SecretKeySpec

class KeystoreCryptoTest {

    private val testMasterKey = SecretKeySpec(ByteArray(32) { (it * 31 + 17).toByte() }, "AES")

    @Before
    fun setUp() {
        KeystoreCrypto.setTestSecretKey(testMasterKey)
    }

    @After
    fun tearDown() {
        KeystoreCrypto.setTestSecretKey(testMasterKey)
    }

    @Test
    fun testFailClosedWhenNoTestKeyProviderConfigured() {
        // Reset provider to simulate JVM environment where AndroidKeyStore is absent
        KeystoreCrypto.resetForTesting()
        try {
            val ex = assertThrows(IllegalStateException::class.java) {
                KeystoreCrypto.encrypt(byteArrayOf(1, 2, 3))
            }
            assertTrue("Exception must mention fail-closed behavior", ex.message!!.contains("Fail-closed"))
        } finally {
            KeystoreCrypto.setTestSecretKey(testMasterKey)
        }
    }

    @Test
    fun testKeystoreCryptoByteArrayRoundTrip() {
        val originalBytes = CryptoUtils.secureRandomBytes(64) // e.g. 64-byte ChainKey
        val encrypted = KeystoreCrypto.encrypt(originalBytes)

        assertNotNull(encrypted)
        assertFalse("Ciphertext must not match plaintext", originalBytes.contentEquals(encrypted))
        assertTrue("Ciphertext must include 12B IV + 16B GCM tag", encrypted!!.size == originalBytes.size + 12 + 16)

        val decrypted = KeystoreCrypto.decrypt(encrypted)
        assertNotNull(decrypted)
        assertArrayEquals("Decrypted bytes must match original bytes", originalBytes, decrypted)
    }

    @Test
    fun testKeystoreCryptoStringRoundTrip() {
        val originalText = "Top-Secret message encrypted with Android Keystore AES-256-GCM 🔒"
        val encryptedHex = KeystoreCrypto.encryptString(originalText)

        assertNotNull(encryptedHex)
        assertFalse("Ciphertext hex must not contain original text", encryptedHex!!.contains("Top-Secret"))

        val decryptedText = KeystoreCrypto.decryptString(encryptedHex)
        assertEquals("Decrypted string must match original string", originalText, decryptedText)
    }

    @Test
    fun testRawCiphertextWithIvCollidingWithRowBoundMagicDecodesCorrectly() {
        val originalText = "Collision test with magic IV byte 🔒"
        val plainBytes = originalText.toByteArray(Charsets.UTF_8)

        for (magic in listOf(KeystoreCrypto.MAGIC_ROW_BOUND, KeystoreCrypto.MAGIC_ROW_BOUND_V2)) {
            // Craft a raw ciphertext where IV[0] == magic byte
            val customIv = CryptoUtils.secureRandomBytes(KeystoreCrypto.GCM_IV_LENGTH_BYTES)
            customIv[0] = magic

            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            val spec = javax.crypto.spec.GCMParameterSpec(128, customIv)
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, testMasterKey, spec)
            val cipherTextWithTag = cipher.doFinal(plainBytes)

            val rawCiphertext = ByteArray(customIv.size + cipherTextWithTag.size)
            System.arraycopy(customIv, 0, rawCiphertext, 0, customIv.size)
            System.arraycopy(cipherTextWithTag, 0, rawCiphertext, customIv.size, cipherTextWithTag.size)

            assertEquals(magic, rawCiphertext[0])

            // KeystoreCrypto.decrypt must not throw IllegalArgumentException and must return original bytes
            val decryptedBytes = KeystoreCrypto.decrypt(rawCiphertext)
            assertNotNull(decryptedBytes)
            assertArrayEquals(plainBytes, decryptedBytes)

            val decryptedString = KeystoreCrypto.decryptString(CryptoUtils.toHex(rawCiphertext))
            assertEquals(originalText, decryptedString)
        }
    }

    @Test
    fun testRowBoundEncryptionAndDecryption() {
        val secretData = "SuperSecretContactKey".toByteArray(Charsets.UTF_8)
        val table = "contacts"
        val rowId = "bob_peer_42"

        val cipherBytes = KeystoreCrypto.encrypt(secretData, table, rowId)
        assertNotNull(cipherBytes)
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND, cipherBytes!![0])

        // Verify correct decryption with matching row binding
        val decrypted = KeystoreCrypto.decrypt(cipherBytes, table, rowId)
        assertNotNull(decrypted)
        assertArrayEquals("Decrypted bytes must match original plaintext", secretData, decrypted)
    }

    @Test
    fun testRowBoundTamperedCiphertextThrowsAEADBadTagException() {
        val secretData = "SuperSecretData".toByteArray()
        val cipherBytes = KeystoreCrypto.encrypt(secretData, "skipped_keys", "contact1_5")!!.copyOf()

        // Tamper with the last byte of the ciphertext / auth tag
        cipherBytes[cipherBytes.size - 1] = (cipherBytes[cipherBytes.size - 1].toInt() xor 0xFF).toByte()

        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decrypt(cipherBytes, "skipped_keys", "contact1_5")
        }
    }

    @Test
    fun testRowBoundMismatchedTableThrowsAEADBadTagException() {
        val secretData = "SensitivePayload".toByteArray()
        val cipherBytes = KeystoreCrypto.encrypt(secretData, "chunks", "transfer_01")!!

        // Attempt to decrypt under the wrong table (e.g. cut-and-paste into messages table)
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decrypt(cipherBytes, "messages", "transfer_01")
        }
    }

    @Test
    fun testRowBoundMismatchedRowIdThrowsAEADBadTagException() {
        val secretData = "AlicePrivateKeySeed".toByteArray()
        val cipherBytes = KeystoreCrypto.encrypt(secretData, "pending_rekey_offers", "alice")!!

        // Attempt to decrypt under Bob's ID
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decrypt(cipherBytes, "pending_rekey_offers", "bob")
        }
    }

    @Test
    fun testShortCiphertextThrowsIllegalArgumentException() {
        val shortBytes = byteArrayOf(1, 2, 3)
        assertThrows(IllegalArgumentException::class.java) {
            KeystoreCrypto.decrypt(shortBytes)
        }
    }

    @Test
    fun testRowBoundStringRoundTripAndMismatchRejection() {
        val plainText = "Confidential chat note"
        val table = "messages"
        val rowId = "msg_123"

        val hex = KeystoreCrypto.encryptString(plainText, table, rowId)
        assertNotNull(hex)

        val decrypted = KeystoreCrypto.decryptString(hex, table, rowId)
        assertEquals(plainText, decrypted)

        // Attempt decryption with mismatched row ID
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decryptString(hex, table, "msg_999")
        }
    }

    @Test
    fun testKeystoreConvertersWithRowBinding() {
        val converters = KeystoreConverters()

        // 1. Row-bound EncryptedBlob
        val rawBlob = ByteArray(32) { (it * 3).toByte() }
        val blob = EncryptedBlob(rawBlob, "skipped_keys", "alice_1")

        val dbBlob = converters.toDatabaseBlob(blob)
        assertNotNull(dbBlob)
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND, dbBlob!![0])

        val restoredBlob = converters.fromDatabaseBlob(dbBlob)
        assertNotNull(restoredBlob)
        assertArrayEquals(rawBlob, restoredBlob!!.raw)
        assertEquals("skipped_keys", restoredBlob.boundTable)
        assertEquals("alice_1", restoredBlob.boundId)

        // 2. Row-bound EncryptedText
        val rawText = "Secret message content"
        val text = EncryptedText(rawText, "messages", "contact_seq_42")

        val dbText = converters.toDatabaseText(text)
        assertNotNull(dbText)

        val restoredText = converters.fromDatabaseText(dbText)
        assertNotNull(restoredText)
        assertEquals(rawText, restoredText!!.raw)
        assertEquals("messages", restoredText.boundTable)
        assertEquals("contact_seq_42", restoredText.boundId)
    }

    @Test
    fun testMasterKeyConfigConfiguration() {
        val configStrongBox = KeystoreCrypto.getMasterKeyConfig(useStrongBox = true, unlockedDeviceRequired = true)
        assertEquals("pqchat_db_master_key", configStrongBox.alias)
        assertEquals(256, configStrongBox.keySize)
        assertTrue(configStrongBox.useStrongBox)
        assertTrue(configStrongBox.unlockedDeviceRequired)
        assertEquals(listOf("GCM"), configStrongBox.blockModes)
        assertEquals(listOf("NoPadding"), configStrongBox.encryptionPaddings)

        val configStandard = KeystoreCrypto.getMasterKeyConfig(useStrongBox = false, unlockedDeviceRequired = false)
        assertEquals("pqchat_db_master_key", configStandard.alias)
        assertEquals(256, configStandard.keySize)
        assertFalse(configStandard.useStrongBox)
        assertFalse(configStandard.unlockedDeviceRequired)
    }

    @Test
    fun testGenerateMasterKeyStrongBoxAndFallbackSequence() {
        // 1. Success on StrongBox
        val attempts1 = mutableListOf<Pair<Boolean, Boolean>>()
        val key1 = KeystoreCrypto.generateMasterKey(sdkInt = 28) { sb, udr ->
            attempts1.add(sb to udr)
            testMasterKey
        }
        assertEquals(testMasterKey, key1)
        assertEquals(listOf(true to true), attempts1)

        // 2. StrongBox fails -> falls back to TEE with unlockedDeviceRequired
        val attempts2 = mutableListOf<Pair<Boolean, Boolean>>()
        val key2 = KeystoreCrypto.generateMasterKey(sdkInt = 28) { sb, udr ->
            attempts2.add(sb to udr)
            if (sb) throw IllegalStateException("StrongBox unavailable")
            testMasterKey
        }
        assertEquals(testMasterKey, key2)
        assertEquals(listOf(true to true, false to true), attempts2)

        // 3. StrongBox and unlockedDeviceRequired fail -> falls back to standard key
        val attempts3 = mutableListOf<Pair<Boolean, Boolean>>()
        val key3 = KeystoreCrypto.generateMasterKey(sdkInt = 28) { sb, udr ->
            attempts3.add(sb to udr)
            if (sb || udr) throw IllegalStateException("Hardware feature unsupported")
            testMasterKey
        }
        assertEquals(testMasterKey, key3)
        assertEquals(listOf(true to true, false to true, false to false), attempts3)

        // 4. Legacy SDK (< 28) directly generates standard key
        val attempts4 = mutableListOf<Pair<Boolean, Boolean>>()
        val key4 = KeystoreCrypto.generateMasterKey(sdkInt = 26) { sb, udr ->
            attempts4.add(sb to udr)
            testMasterKey
        }
        assertEquals(testMasterKey, key4)
        assertEquals(listOf(false to false), attempts4)
    }

    @Test
    fun testRowSwapAndTableSwapAttacksThrowAEADBadTagException() {
        val converters = KeystoreConverters()

        // 1. Create legitimate ContactEntity records for Alice and Bob
        val aliceChainKeyBytes = CryptoUtils.secureRandomBytes(64)
        val alice = ContactEntity(
            id = "alice",
            name = "Alice",
            chainKeyOut = aliceChainKeyBytes,
            chainKeyIn = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            counterIn = 0
        )
        val aliceDbBlob = converters.toDatabaseBlob(alice.chainKeyOut)
        assertNotNull(aliceDbBlob)

        val bob = ContactEntity(
            id = "bob",
            name = "Bob",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            chainKeyIn = CryptoUtils.secureRandomBytes(64),
            counterOut = 0,
            counterIn = 0
        )
        val bobDbBlob = converters.toDatabaseBlob(bob.chainKeyOut)
        assertNotNull(bobDbBlob)

        // 2. Simulate Row-Swap attack in SQLite:
        // Attacker swaps Alice's encrypted chainKeyOut column into Bob's row.
        val swappedAliceBlobForBob = converters.fromDatabaseBlob(aliceDbBlob)
        assertNotNull(swappedAliceBlobForBob)
        assertEquals("contacts", swappedAliceBlobForBob!!.boundTable)
        assertEquals("alice", swappedAliceBlobForBob.boundId)

        // When Room reconstructs Bob's ContactEntity from the modified row, validateRowBinding() triggers:
        val exRowSwap = assertThrows(AEADBadTagException::class.java) {
            ContactEntity(
                id = "bob",
                name = "Bob",
                chainKeyOut = swappedAliceBlobForBob,
                chainKeyIn = bob.chainKeyIn,
                counterOut = 0,
                counterIn = 0
            )
        }
        assertTrue(
            "Exception message must mention row ID mismatch",
            exRowSwap.message!!.contains("expected table='contacts', id='bob'") &&
            exRowSwap.message!!.contains("id='alice'")
        )

        // 3. Simulate Table-Swap attack in SQLite:
        // Attacker copies Alice's chainKeyOut from 'contacts' table into 'groups' table (myChainKeyOut column).
        val exTableSwapGroup = assertThrows(AEADBadTagException::class.java) {
            GroupEntity(
                groupId = "group_sec_101",
                groupName = "Secret Group",
                myMemberId = "member_1",
                myChainKeyOut = swappedAliceBlobForBob,
                myCounterOut = 0
            )
        }
        assertTrue(
            "Exception message must mention table and ID mismatch",
            exTableSwapGroup.message!!.contains("expected table='groups', id='group_sec_101'") &&
            exTableSwapGroup.message!!.contains("table='contacts', id='alice'")
        )

        // 4. Reverse Table-Swap attack:
        // Attacker copies a GroupEntity's myChainKeyOut into a ContactEntity row.
        val groupChainKey = CryptoUtils.secureRandomBytes(64)
        val group = GroupEntity(
            groupId = "group_ops_202",
            groupName = "Operations",
            myMemberId = "member_2",
            myChainKeyOut = groupChainKey,
            myCounterOut = 0
        )
        val groupDbBlob = converters.toDatabaseBlob(group.myChainKeyOut)
        assertNotNull(groupDbBlob)
        val restoredGroupBlob = converters.fromDatabaseBlob(groupDbBlob)
        assertNotNull(restoredGroupBlob)

        val exTableSwapContact = assertThrows(AEADBadTagException::class.java) {
            ContactEntity(
                id = "bob",
                name = "Bob",
                chainKeyOut = restoredGroupBlob!!,
                chainKeyIn = bob.chainKeyIn,
                counterOut = 0,
                counterIn = 0
            )
        }
        assertTrue(
            "Exception message must mention table and ID mismatch",
            exTableSwapContact.message!!.contains("expected table='contacts', id='bob'") &&
            exTableSwapContact.message!!.contains("table='groups', id='group_ops_202'")
        )
    }

    @Test
    fun testV2FormatHeaderAndColumnBoundEncryptionRoundTrip() {
        val secretBytes = "MyColumnBoundSecretChainKey".toByteArray(Charsets.UTF_8)
        val table = "contacts"
        val id = "peer_99"
        val column = "chainKeyOut"

        val cipherBytes = KeystoreCrypto.encrypt(secretBytes, table, id, column)
        assertNotNull(cipherBytes)
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, cipherBytes!![0])

        // Verify correct decryption with matching column
        val decrypted = KeystoreCrypto.decrypt(cipherBytes, table, id, column)
        assertNotNull(decrypted)
        assertArrayEquals(secretBytes, decrypted)

        // Attempt decryption with wrong column name -> must fail
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decrypt(cipherBytes, table, id, "chainKeyIn")
        }
    }

    @Test
    fun testColumnSwapOnContactEntityThrowsAEADBadTagException() {
        val converters = KeystoreConverters()

        val contact = ContactEntity(
            id = "alice_uuid",
            name = "Alice In Wonderland",
            chainKeyOut = CryptoUtils.secureRandomBytes(64),
            chainKeyIn = CryptoUtils.secureRandomBytes(64),
            counterOut = 10,
            counterIn = 5,
            sas = "9876",
            fingerprint = "SHA256:ALICE_FINGERPRINT_HEX"
        )

        // Verify social metadata is encrypted as EncryptedText with V2 column binding
        val nameHex = converters.toDatabaseText(contact.name)
        assertNotNull(nameHex)
        val nameBytes = CryptoUtils.fromHex(nameHex!!)
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, nameBytes[0])
        assertEquals("name", contact.name.boundColumn)
        assertEquals("Alice In Wonderland", contact.rawName)

        val sasHex = converters.toDatabaseText(contact.sas)
        assertNotNull(sasHex)
        val sasBytes = CryptoUtils.fromHex(sasHex!!)
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, sasBytes[0])
        assertEquals("sas", contact.sas.boundColumn)
        assertEquals("9876", contact.rawSas)

        val fpHex = converters.toDatabaseText(contact.fingerprint)
        assertNotNull(fpHex)
        val fpBytes = CryptoUtils.fromHex(fpHex!!)
        assertEquals(KeystoreCrypto.MAGIC_ROW_BOUND_V2, fpBytes[0])
        assertEquals("fingerprint", contact.fingerprint.boundColumn)
        assertEquals("SHA256:ALICE_FINGERPRINT_HEX", contact.rawFingerprint)

        // 1. Column Swap Attack: swap chainKeyIn into chainKeyOut
        val exColSwap = assertThrows(AEADBadTagException::class.java) {
            contact.copy(chainKeyOut = contact.chainKeyIn)
        }
        assertTrue(
            "Exception must mention column mismatch",
            exColSwap.message!!.contains("binding mismatch") &&
            exColSwap.message!!.contains("column='chainKeyOut'") &&
            exColSwap.message!!.contains("column='chainKeyIn'")
        )

        // 2. Direct cryptographic decryption under swapped column fails AES-256-GCM AEAD
        val chainKeyOutDbBlob = converters.toDatabaseBlob(contact.chainKeyOut)!!
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decrypt(chainKeyOutDbBlob, "contacts", "alice_uuid", "chainKeyIn")
        }

        // 3. Metadata Column Swap Attack: swap sas into name
        val exNameSasSwap = assertThrows(AEADBadTagException::class.java) {
            contact.copy(name = contact.sas)
        }
        assertTrue(
            "Exception must mention column mismatch for name vs sas",
            exNameSasSwap.message!!.contains("binding mismatch") &&
            exNameSasSwap.message!!.contains("column='name'") &&
            exNameSasSwap.message!!.contains("column='sas'")
        )
    }

    @Test
    fun testMessageEntityIntraRowAndInterMessageSwapThrowsAEADBadTagException() {
        val converters = KeystoreConverters()

        val msg1 = org.pqchat.dht.data.db.MessageEntity(
            contactId = "contact_bob",
            isOutgoing = false,
            seqEpoch = 0,
            seqNum = 1,
            textContent = "Message #1 content",
            senderMemberId = "member_1_uuid",
            senderName = "Bob The Builder"
        )

        val msg2 = org.pqchat.dht.data.db.MessageEntity(
            contactId = "contact_bob",
            isOutgoing = false,
            seqEpoch = 0,
            seqNum = 2,
            textContent = "Message #2 content",
            senderMemberId = "member_1_uuid",
            senderName = "Bob The Builder"
        )

        // Verify messageRowId calculation
        assertEquals("contact_bob_0_1_false", msg1.messageRowId)
        assertEquals("contact_bob_0_2_false", msg2.messageRowId)
        assertEquals("textContent", msg1.textContent!!.boundColumn)
        assertEquals("senderName", msg1.senderName!!.boundColumn)

        // 1. Intra-Row Swap Attack: swap senderName into textContent
        val exIntraRow = assertThrows(AEADBadTagException::class.java) {
            msg1.copy(textContent = msg1.senderName)
        }
        assertTrue(
            "Intra-row swap must fail column validation",
            exIntraRow.message!!.contains("binding mismatch") &&
            exIntraRow.message!!.contains("column='textContent'") &&
            exIntraRow.message!!.contains("column='senderName'")
        )

        // 2. Inter-Message Swap Attack: swap textContent of msg1 into msg2 of same contact
        val exInterMessage = assertThrows(AEADBadTagException::class.java) {
            msg2.copy(textContent = msg1.textContent)
        }
        assertTrue(
            "Inter-message swap must fail rowId validation",
            exInterMessage.message!!.contains("binding mismatch") &&
            exInterMessage.message!!.contains("expected table='messages', id='contact_bob_0_2_false'") &&
            exInterMessage.message!!.contains("id='contact_bob_0_1_false'")
        )

        // 3. Direct cryptographic AEAD verification fails on swapped message rowId or column
        val msg1TextHex = converters.toDatabaseText(msg1.textContent)!!
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decryptString(msg1TextHex, "messages", "contact_bob_0_2_false", "textContent")
        }
        assertThrows(GeneralSecurityException::class.java) {
            KeystoreCrypto.decryptString(msg1TextHex, "messages", "contact_bob_0_1_false", "senderName")
        }
    }
}

