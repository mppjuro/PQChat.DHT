package org.pqchat.dht.service

import android.content.Context
import android.content.pm.ServiceInfo
import android.os.PowerManager
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

    @Test
    fun testOnTimeoutReleasesHeldWakeLock() {
        val controller = Robolectric.buildService(ChatHeadService::class.java)
        val service = controller.create().get()

        val powerManager = service.getSystemService(Context.POWER_SERVICE) as PowerManager
        val lock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "test:chat_head_lock")
        service.wakeLock = lock

        // Acquire lock
        lock.acquire(30_000L)
        assertTrue("WakeLock must be held before timeout callback", lock.isHeld)

        // Invoke onTimeout
        service.onTimeout(1, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)

        // Assert lock is safely released
        assertFalse("WakeLock must be released after onTimeout", lock.isHeld)

        controller.destroy()
    }

    @Test
    @Config(sdk = [35])
    fun testOnTimeoutExecutesOnAndroid15Sdk35() {
        val controller = Robolectric.buildService(ChatHeadService::class.java)
        val service = controller.create().get()

        val powerManager = service.getSystemService(Context.POWER_SERVICE) as PowerManager
        val lock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "test:chat_head_lock_35")
        service.wakeLock = lock
        lock.acquire(30_000L)
        assertTrue(lock.isHeld)

        // On Android 15 (API 35), onTimeout is native to Service
        service.onTimeout(42, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)

        assertFalse("WakeLock must be released on API 35 onTimeout", lock.isHeld)
        controller.destroy()
    }
}
