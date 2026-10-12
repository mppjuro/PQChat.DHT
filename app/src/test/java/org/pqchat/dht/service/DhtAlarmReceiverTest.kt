package org.pqchat.dht.service

import android.content.Intent
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DhtAlarmReceiverTest {

    @Test
    fun testDozePollActionConstant() {
        assertEquals("org.pqchat.dht.ACTION_DOZE_POLL", DhtAlarmReceiver.ACTION_DOZE_POLL)
    }

    @Test
    fun testUnrecognizedActionIgnoredWithoutException() {
        val context = RuntimeEnvironment.getApplication()
        val receiver = DhtAlarmReceiver()

        val intent = Intent("org.example.UNKNOWN_ACTION")
        receiver.onReceive(context, intent)
    }

    @Test
    fun testDozePollActionHandledSafelyWhenApplicationNotReady() {
        val context = RuntimeEnvironment.getApplication()
        val receiver = DhtAlarmReceiver()

        val intent = Intent(DhtAlarmReceiver.ACTION_DOZE_POLL)
        receiver.onReceive(context, intent)
    }
}
