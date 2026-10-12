package org.pqchat.dht.service

import android.content.pm.ServiceInfo
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ChatHeadServiceTimeoutTest {

    @Test
    fun testOnTimeoutExecutesCleanly() {
        val controller = Robolectric.buildService(ChatHeadService::class.java)
        val service = controller.create().get()

        // Verify onTimeout callback executes gracefully without throwing
        service.onTimeout(1, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)

        controller.destroy()
    }
}
