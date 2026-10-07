package org.pqchat.dht

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.pqchat.dht.ui.MainActivity

@RunWith(AndroidJUnit4::class)
class MainActivityInstrumentedSmokeTest {

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
