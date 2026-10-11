package org.pqchat.dht.data.settings

import android.content.SharedPreferences
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class AppSettingsManagerTest {

    private lateinit var fakePrefs: FakeSharedPreferences
    private lateinit var settingsManager: AppSettingsManager

    @Before
    fun setup() {
        fakePrefs = FakeSharedPreferences()
        settingsManager = AppSettingsManager(sharedPreferences = fakePrefs)
    }

    @Test
    fun `default value of isTorEnabled is false`() {
        assertFalse(settingsManager.isTorEnabled.value)
    }

    @Test
    fun `setTorEnabled updates state and persists to SharedPreferences`() = runBlocking {
        settingsManager.setTorEnabled(true)

        assertTrue(settingsManager.isTorEnabled.value)
        assertTrue(settingsManager.isTorEnabled.first())
        assertTrue(fakePrefs.getBoolean("tor_enabled", false))

        settingsManager.setTorEnabled(false)

        assertFalse(settingsManager.isTorEnabled.value)
        assertFalse(settingsManager.isTorEnabled.first())
        assertFalse(fakePrefs.getBoolean("tor_enabled", true))
    }

    @Test
    fun `new instance restores isTorEnabled true from persisted preferences`() {
        fakePrefs.putBoolean("tor_enabled", true)
        val newManager = AppSettingsManager(sharedPreferences = fakePrefs)

        assertTrue(newManager.isTorEnabled.value)
    }

    @Test
    fun `settings manager operates safely without shared preferences context`() {
        val standaloneManager = AppSettingsManager(context = null, sharedPreferences = null)
        assertFalse(standaloneManager.isTorEnabled.value)

        standaloneManager.setTorEnabled(true)
        assertTrue(standaloneManager.isTorEnabled.value)
    }

    /**
     * Lightweight in-memory implementation of SharedPreferences for fast, hermetic unit tests.
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

        fun putBoolean(key: String, value: Boolean) {
            data[key] = value
        }

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
