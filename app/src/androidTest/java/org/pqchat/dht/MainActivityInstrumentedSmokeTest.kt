package org.pqchat.dht

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.pqchat.dht.crypto.KeystoreCrypto
import org.pqchat.dht.ui.MainActivity
import org.pqchat.dht.ui.util.SecureScreenConfig

@RunWith(AndroidJUnit4::class)
class MainActivityInstrumentedSmokeTest {

    @Before
    fun setUp() {
        SecureScreenConfig.isEnabled = false
        KeystoreCrypto.setTestSecretKey(KeystoreCrypto.INSTRUMENTED_TEST_MASTER_KEY)
    }

    @After
    fun tearDown() {
        KeystoreCrypto.setTestSecretKey(KeystoreCrypto.INSTRUMENTED_TEST_MASTER_KEY)
    }

    @Test
    fun testActivityLaunchesSuccessfully() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.onActivity { activity ->
            assertNotNull(activity)
            assertNotNull(activity.application)
        }
        scenario.close()
    }
}

