package org.pqchat.dht.crypto

import android.content.SharedPreferences
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.pqchat.dht.data.settings.AppSettingsManager
import org.pqchat.dht.data.settings.PinAuthResult
import javax.crypto.spec.SecretKeySpec

class DuressPinKeystoreTest {

    private val testMasterKey = SecretKeySpec(ByteArray(32) { (it * 17 + 23).toByte() }, "AES")
    private lateinit var fakePrefs: FakeSharedPreferences
    private lateinit var settingsManager: AppSettingsManager

    @Before
    fun setUp() {
        KeystoreCrypto.resetForTesting()
        KeystoreCrypto.setTestSecretKey(testMasterKey)

        fakePrefs = FakeSharedPreferences()
        settingsManager = AppSettingsManager(sharedPreferences = fakePrefs)
    }

    @After
    fun tearDown() {
        KeystoreCrypto.resetForTesting()
    }

    @Test
    fun testKeystoreMasterKeyPermanentWipe() {
        assertTrue("Master key must be present initially", KeystoreCrypto.hasMasterKey())
        assertFalse("Master key must not be marked wiped initially", KeystoreCrypto.isMasterKeyWiped())

        val secretMessage = "Top secret ratchet state before duress wipe"
        val cipherText = KeystoreCrypto.encryptString(secretMessage)
        assertNotNull(cipherText)
        assertEquals(secretMessage, KeystoreCrypto.decryptString(cipherText))

        // Trigger permanent destruction of Keystore master key
        val deleted = KeystoreCrypto.deleteMasterKey()
        assertTrue("deleteMasterKey must return true", deleted)

        assertFalse("hasMasterKey must be false after wipe", KeystoreCrypto.hasMasterKey())
        assertTrue("isMasterKeyWiped must be true after wipe", KeystoreCrypto.isMasterKeyWiped())

        // Encrypt attempt must fail closed immediately
        val exEncrypt = assertThrows(IllegalStateException::class.java) {
            KeystoreCrypto.encryptString("New attempt after panic wipe")
        }
        assertTrue(
            "Exception message must mention wiped master key",
            exEncrypt.message!!.contains("wipe", ignoreCase = true) || exEncrypt.message!!.contains("destroy", ignoreCase = true)
        )

        // Decrypt attempt must fail closed immediately
        val exDecrypt = assertThrows(IllegalStateException::class.java) {
            KeystoreCrypto.decryptString(cipherText)
        }
        assertTrue(
            "Exception message must mention wiped master key",
            exDecrypt.message!!.contains("wipe", ignoreCase = true) || exDecrypt.message!!.contains("destroy", ignoreCase = true)
        )
    }

    @Test
    fun testDuressPinVerificationAndState() = runBlocking {
        // Initially no PIN set
        assertFalse(settingsManager.isAppLockPinSet.value)
        assertFalse(settingsManager.isDuressPinSet.value)
        assertFalse(settingsManager.isDuressActive.value)
        assertEquals(PinAuthResult.NO_PIN_SET, settingsManager.verifyPin("1234"))

        // Set App Lock PIN
        settingsManager.setAppLockPin("1234")
        assertTrue(settingsManager.isAppLockPinSet.value)
        assertEquals(PinAuthResult.NORMAL_UNLOCK, settingsManager.verifyPin("1234"))
        assertEquals(PinAuthResult.INVALID, settingsManager.verifyPin("0000"))

        // Set Duress PIN
        settingsManager.setDuressPin("9999")
        assertTrue(settingsManager.isDuressPinSet.value)

        // Verify normal unlock still works
        assertEquals(PinAuthResult.NORMAL_UNLOCK, settingsManager.verifyPin("1234"))

        // Verify duress trigger
        assertEquals(PinAuthResult.DURESS_TRIGGERED, settingsManager.verifyPin("9999"))

        // Verify wrong PIN is still invalid
        assertEquals(PinAuthResult.INVALID, settingsManager.verifyPin("1111"))
    }

    @Test
    fun testDuressModeWorkflowIntegration() = runBlocking {
        settingsManager.setAppLockPin("1234")
        settingsManager.setDuressPin("9999")

        // User enters duress PIN
        val authResult = settingsManager.verifyPin("9999")
        assertEquals(PinAuthResult.DURESS_TRIGGERED, authResult)

        // Simulate ViewModel duress trigger action
        KeystoreCrypto.deleteMasterKey()
        settingsManager.setDuressActive(true)

        // Verify Keystore is permanently destroyed and decoy mode is activated
        assertTrue(KeystoreCrypto.isMasterKeyWiped())
        assertTrue(settingsManager.isDuressActive.value)

        // Verify that clearing duress state resets the active flag
        settingsManager.clearDuressActive()
        assertFalse(settingsManager.isDuressActive.value)
    }

    @Test
    fun testRemovePins() = runBlocking {
        settingsManager.setAppLockPin("1234")
        settingsManager.setDuressPin("9999")
        assertTrue(settingsManager.isAppLockPinSet.value)
        assertTrue(settingsManager.isDuressPinSet.value)

        // Remove duress PIN
        settingsManager.setDuressPin(null)
        assertFalse(settingsManager.isDuressPinSet.value)
        assertEquals(PinAuthResult.INVALID, settingsManager.verifyPin("9999"))
        assertEquals(PinAuthResult.NORMAL_UNLOCK, settingsManager.verifyPin("1234"))

        // Remove normal PIN
        settingsManager.setAppLockPin(null)
        assertFalse(settingsManager.isAppLockPinSet.value)
        assertEquals(PinAuthResult.NO_PIN_SET, settingsManager.verifyPin("1234"))
    }

    @Test
    fun testPbkdf2PinHashing120kIterationsAndLegacySha256Migration() = runBlocking {
        settingsManager.setAppLockPin("4321")
        val storedSaltHex = fakePrefs.getString("app_lock_pin_salt", null)!!
        val storedHashHex = fakePrefs.getString("app_lock_pin_hash", null)!!

        // Verify PBKDF2WithHmacSHA256 (120,000 iterations) was used instead of single SHA-256
        val saltBytes = hexToBytes(storedSaltHex)
        val factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = javax.crypto.spec.PBEKeySpec("4321".toCharArray(), saltBytes, 120_000, 256)
        val expectedPbkdf2Hex = CryptoUtils.toHex(factory.generateSecret(spec).encoded)
        assertEquals(expectedPbkdf2Hex, storedHashHex)

        // Simulate legacy single SHA-256 PIN entry in SharedPreferences and verify transparent migration
        val legacySalt = ByteArray(16) { (it + 1).toByte() }
        val legacyPin = "7788"
        val legacyDigest = java.security.MessageDigest.getInstance("SHA-256")
        legacyDigest.update(legacySalt)
        legacyDigest.update(legacyPin.toByteArray(Charsets.UTF_8))
        val legacyHashHex = CryptoUtils.toHex(legacyDigest.digest())

        fakePrefs.edit()
            .putString("app_lock_pin_salt", CryptoUtils.toHex(legacySalt))
            .putString("app_lock_pin_hash", legacyHashHex)
            .apply()

        assertEquals(PinAuthResult.NORMAL_UNLOCK, settingsManager.verifyPin(legacyPin))
        val migratedHashHex = fakePrefs.getString("app_lock_pin_hash", null)
        assertNotNull(migratedHashHex)
        assertNotEquals("Legacy SHA-256 hash must be migrated to PBKDF2", legacyHashHex, migratedHashHex)
        assertEquals(PinAuthResult.NORMAL_UNLOCK, settingsManager.verifyPin(legacyPin))
    }

    @Test
    fun testDuressActivationOverwritesPinHashesAndSaltsWithNoise() = runBlocking {
        settingsManager.setAppLockPin("1234")
        settingsManager.setDuressPin("9999")
        fakePrefs.edit().putBoolean("canary_triggered", true).apply()

        val origAppHash = fakePrefs.getString("app_lock_pin_hash", null)
        val origAppSalt = fakePrefs.getString("app_lock_pin_salt", null)
        val origDuressHash = fakePrefs.getString("duress_pin_hash", null)
        val origDuressSalt = fakePrefs.getString("duress_pin_salt", null)

        assertEquals(PinAuthResult.DURESS_TRIGGERED, settingsManager.verifyPin("9999"))
        settingsManager.setDuressActive(true)

        assertTrue(settingsManager.isDuressActive.value)
        assertFalse("Persisted duress flag must not remain on disk", fakePrefs.contains("is_duress_active"))
        assertFalse("Persisted canary flag must not remain on disk", fakePrefs.contains("canary_triggered"))

        val wipedAppHash = fakePrefs.getString("app_lock_pin_hash", null)
        val wipedAppSalt = fakePrefs.getString("app_lock_pin_salt", null)
        val wipedDuressHash = fakePrefs.getString("duress_pin_hash", null)
        val wipedDuressSalt = fakePrefs.getString("duress_pin_salt", null)

        assertNotNull(wipedAppHash)
        assertNotNull(wipedAppSalt)
        assertNotNull(wipedDuressHash)
        assertNotNull(wipedDuressSalt)
        assertNotEquals(origAppHash, wipedAppHash)
        assertNotEquals(origAppSalt, wipedAppSalt)
        assertNotEquals(origDuressHash, wipedDuressHash)
        assertNotEquals(origDuressSalt, wipedDuressSalt)

        // Original PINs must no longer validate after duress overwrite
        assertEquals(PinAuthResult.INVALID, settingsManager.verifyPin("1234"))
        assertEquals(PinAuthResult.INVALID, settingsManager.verifyPin("9999"))
    }

    private fun hexToBytes(hex: String): ByteArray {
        val len = hex.length / 2
        return ByteArray(len) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    /**
     * Lightweight in-memory implementation of SharedPreferences for hermetic JVM tests.
     */
    private class FakeSharedPreferences : SharedPreferences {
        private val data = mutableMapOf<String, Any?>()

        override fun getAll(): MutableMap<String, *> = HashMap(data)
        override fun getString(key: String?, defValue: String?): String? = (data[key] as? String) ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            @Suppress("UNCHECKED_CAST") (data[key] as? MutableSet<String>) ?: defValues
        override fun getInt(key: String?, defValue: Int): Int = (data[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (data[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (data[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (data[key] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = data.containsKey(key)
        override fun edit(): SharedPreferences.Editor = Editor(this)
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

        private class Editor(private val prefs: FakeSharedPreferences) : SharedPreferences.Editor {
            private val changes = mutableMapOf<String, Any?>()
            private var clearRequested = false

            override fun putString(key: String?, value: String?): SharedPreferences.Editor {
                if (key != null) changes[key] = value
                return this
            }
            override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor {
                if (key != null) changes[key] = values
                return this
            }
            override fun putInt(key: String?, value: Int): SharedPreferences.Editor {
                if (key != null) changes[key] = value
                return this
            }
            override fun putLong(key: String?, value: Long): SharedPreferences.Editor {
                if (key != null) changes[key] = value
                return this
            }
            override fun putFloat(key: String?, value: Float): SharedPreferences.Editor {
                if (key != null) changes[key] = value
                return this
            }
            override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor {
                if (key != null) changes[key] = value
                return this
            }
            override fun remove(key: String?): SharedPreferences.Editor {
                if (key != null) changes[key] = null
                return this
            }
            override fun clear(): SharedPreferences.Editor {
                clearRequested = true
                return this
            }
            override fun commit(): Boolean {
                apply()
                return true
            }
            override fun apply() {
                if (clearRequested) {
                    prefs.data.clear()
                }
                for ((k, v) in changes) {
                    if (v == null) prefs.data.remove(k) else prefs.data[k] = v
                }
            }
        }
    }
}
