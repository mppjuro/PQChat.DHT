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
class BootReceiverTest {

    @Test
    fun testBootCompletedBroadcastHandledWithoutCrash() {
        val context = RuntimeEnvironment.getApplication()
        val receiver = BootReceiver()

        val bootIntent = Intent(Intent.ACTION_BOOT_COMPLETED)
        receiver.onReceive(context, bootIntent)
        // Passes if no exception is thrown
    }

    @Test
    fun testPackageReplacedBroadcastHandledWithoutCrash() {
        val context = RuntimeEnvironment.getApplication()
        val receiver = BootReceiver()

        val replacedIntent = Intent(Intent.ACTION_MY_PACKAGE_REPLACED)
        receiver.onReceive(context, replacedIntent)
        // Passes if no exception is thrown
    }

    @Test
    fun testUnrecognizedActionIgnored() {
        val context = RuntimeEnvironment.getApplication()
        val receiver = BootReceiver()

        val unknownIntent = Intent("org.example.UNKNOWN_ACTION")
        receiver.onReceive(context, unknownIntent)
        // Should ignore and return early without error
    }
}
