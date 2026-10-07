package org.pqchat.dht.crypto

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.data.db.EncryptedBlob
import org.pqchat.dht.data.db.EncryptedText
import org.pqchat.dht.data.db.KeystoreConverters

class KeystoreCryptoTest {

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
    fun testKeystoreConverters() {
        val converters = KeystoreConverters()

        // 1. EncryptedBlob
        val originalBytes = ByteArray(32) { (it * 7).toByte() }
        val blob = EncryptedBlob(originalBytes)

        val dbBlob = converters.toDatabaseBlob(blob)
        assertNotNull(dbBlob)
        assertFalse("Database blob must be encrypted", originalBytes.contentEquals(dbBlob))

        val restoredBlob = converters.fromDatabaseBlob(dbBlob)
        assertNotNull(restoredBlob)
        assertArrayEquals(originalBytes, restoredBlob!!.raw)
        assertEquals(blob, restoredBlob)

        // 2. EncryptedText
        val originalText = "Encrypted Note"
        val text = EncryptedText(originalText)

        val dbText = converters.toDatabaseText(text)
        assertNotNull(dbText)
        assertNotEquals(originalText, dbText)

        val restoredText = converters.fromDatabaseText(dbText)
        assertNotNull(restoredText)
        assertEquals(originalText, restoredText!!.raw)
        assertEquals(originalText, restoredText.toString())
    }

    @Test
    fun testTamperedCiphertextHandledSafely() {
        val originalBytes = ByteArray(64) { 0x42 }
        val encrypted = KeystoreCrypto.encrypt(originalBytes)!!

        // Corrupt auth tag (last byte)
        encrypted[encrypted.size - 1] = (encrypted[encrypted.size - 1].toInt() xor 0xFF).toByte()

        // Decryption fails authentication check and handles safely without crashing
        val result = KeystoreCrypto.decrypt(encrypted)
        assertFalse("Corrupted ciphertext must not decrypt to original plaintext", originalBytes.contentEquals(result))
    }
}
