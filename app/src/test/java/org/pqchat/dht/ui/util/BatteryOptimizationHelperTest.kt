package org.pqchat.dht.ui.util

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BatteryOptimizationHelperTest {

    @Test
    fun testIsIgnoringBatteryOptimizationsReturnsBoolean() {
        val context = RuntimeEnvironment.getApplication()
        val result = BatteryOptimizationHelper.isIgnoringBatteryOptimizations(context)
        assertNotNull(result)
    }

    @Test
    fun testRequestIgnoreBatteryOptimizationsExecutesWithoutCrash() {
        val context = RuntimeEnvironment.getApplication()
        val initiated = BatteryOptimizationHelper.requestIgnoreBatteryOptimizations(context)
        assertTrue("Request should successfully trigger system intent", initiated)
    }
}
