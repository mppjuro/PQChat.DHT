package org.pqchat.dht.crypto

import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.pqchat.dht.data.db.EncryptedBlob
import org.pqchat.dht.data.db.EncryptedText
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
}
