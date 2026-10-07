package org.pqchat.dht.debug

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.BuildConfig
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.protocol.RatchetChain
import java.io.ByteArrayOutputStream
import java.io.PrintStream

class MessageDebugLoggerTest {

    @Test
    fun testReleaseModeEmitsZeroLogsAndZeroPlaintext() {
        val originalEnabled = MessageDebugLogger.isEnabled
        val originalOut = System.out

        try {
            // Simulate release mode where logging is disabled
            MessageDebugLogger.isEnabled = false
            MessageDebugLogger.emitCount.set(0)

            val interceptStream = ByteArrayOutputStream()
            System.setOut(PrintStream(interceptStream))

            val fakeChainKey = ByteArray(64) { 0x01 }
            val slot = RatchetChain.deriveSlot(fakeChainKey, 0)
            val secretText = "TOP_SECRET_PLAINTEXT_SHOULD_NEVER_BE_LOGGED"
            val plaintext972 = BinaryFrameCodec.encodeTextMessage(0, 0, System.currentTimeMillis(), secretText)
            val frame900 = BinaryFrameCodec.packAeadFrame(slot.msgKey, plaintext972)

            // Attempt logging all types of sensitive messages
            MessageDebugLogger.logOutgoingTextMessage(
                contactId = "victim_contact",
                text = secretText,
                slot = slot,
                seqNum = 0,
                ackNum = 0,
                plaintext972 = plaintext972,
                frame900 = frame900
            )

            MessageDebugLogger.logOutgoingRekeyOffer(
                contactId = "victim_contact",
                epoch = 1L,
                slot = slot,
                seqNum = 0,
                ackNum = 0,
                mlKemPublicKey = ByteArray(800) { 0x02 },
                frame900 = frame900
            )

            MessageDebugLogger.logIncomingAliceHandshakeFinalize(
                target = slot.target,
                seq = 1L,
                senderEdPublicKey = slot.edPublicKey,
                senderSignature = ByteArray(64),
                frame900 = frame900,
                seedInit = ByteArray(32) { 0x03 },
                decapsulationSuccess = true
            )

            // Verify NOTHING was printed to console
            System.out.flush()
            val capturedOutput = interceptStream.toString(Charsets.UTF_8.name())
            assertTrue("Captured output must be empty in release mode", capturedOutput.isEmpty())
            assertEquals("Emit count must be 0", 0, MessageDebugLogger.emitCount.get())
            assertFalse("Secret text must not appear anywhere", capturedOutput.contains("TOP_SECRET"))
        } finally {
            MessageDebugLogger.isEnabled = originalEnabled
            System.setOut(originalOut)
        }
    }

    @Test
    fun testDebugModeLogsStructuredJsonWhenEnabled() {
        if (!BuildConfig.DEBUG) {
            // In release builds, BuildConfig.DEBUG is false, so it must never log even if isEnabled = true
            val originalEnabled = MessageDebugLogger.isEnabled
            try {
                MessageDebugLogger.isEnabled = true
                MessageDebugLogger.emitCount.set(0)
                val fakeChainKey = ByteArray(64) { 0x01 }
                val slot = RatchetChain.deriveSlot(fakeChainKey, 0)
                val plaintext972 = BinaryFrameCodec.encodeTextMessage(0, 0, System.currentTimeMillis(), "Hello Debug")
                val frame900 = BinaryFrameCodec.packAeadFrame(slot.msgKey, plaintext972)

                MessageDebugLogger.logOutgoingTextMessage(
                    contactId = "debug_contact",
                    text = "Hello Debug",
                    slot = slot,
                    seqNum = 0,
                    ackNum = 0,
                    plaintext972 = plaintext972,
                    frame900 = frame900
                )
                assertEquals("In release build, emit count must remain 0 even when isEnabled = true", 0, MessageDebugLogger.emitCount.get())
            } finally {
                MessageDebugLogger.isEnabled = originalEnabled
            }
            return
        }

        val originalEnabled = MessageDebugLogger.isEnabled
        val originalOut = System.out

        try {
            MessageDebugLogger.isEnabled = true
            MessageDebugLogger.emitCount.set(0)

            val interceptStream = ByteArrayOutputStream()
            System.setOut(PrintStream(interceptStream))

            val fakeChainKey = ByteArray(64) { 0x01 }
            val slot = RatchetChain.deriveSlot(fakeChainKey, 0)
            val plaintext972 = BinaryFrameCodec.encodeTextMessage(0, 0, System.currentTimeMillis(), "Hello Debug")
            val frame900 = BinaryFrameCodec.packAeadFrame(slot.msgKey, plaintext972)

            MessageDebugLogger.logOutgoingTextMessage(
                contactId = "debug_contact",
                text = "Hello Debug",
                slot = slot,
                seqNum = 0,
                ackNum = 0,
                plaintext972 = plaintext972,
                frame900 = frame900
            )

            System.out.flush()
            val capturedOutput = interceptStream.toString(Charsets.UTF_8.name())
            assertEquals("Emit count must be 1 in DEBUG build", 1, MessageDebugLogger.emitCount.get())
            assertTrue("Should contain debug banner", capturedOutput.contains("[PQChat-DEBUG]"))
            assertTrue("Should contain JSON structure", capturedOutput.contains("\"event\": \"MESSAGE_SENT_TO_DHT_SERVER\""))
        } finally {
            MessageDebugLogger.isEnabled = originalEnabled
            System.setOut(originalOut)
        }
    }
}
