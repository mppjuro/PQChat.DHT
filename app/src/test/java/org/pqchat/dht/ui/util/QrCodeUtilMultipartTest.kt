package org.pqchat.dht.ui.util

import org.junit.Assert.*
import org.junit.Test
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.protocol.HandshakeManager

class QrCodeUtilMultipartTest {

    @Test
    fun testComputeCrc16Consistency() {
        val data1 = "Hello PQChat DHT".toByteArray(Charsets.UTF_8)
        val crc1 = QrCodeUtil.computeCrc16(data1)
        val crc2 = QrCodeUtil.computeCrc16(data1)
        assertEquals("CRC16 must be deterministic", crc1, crc2)
        assertTrue("CRC16 must be a 16-bit unsigned integer", crc1 in 0..0xFFFF)

        val data2 = "Hello PQChat DHT!".toByteArray(Charsets.UTF_8)
        val crcDiff = QrCodeUtil.computeCrc16(data2)
        assertNotEquals("CRC16 should change on modified data", crc1, crcDiff)
    }

    @Test
    fun testSplitIntoMultipartFrames() {
        val payload = CryptoUtils.secureRandomBytes(HandshakeManager.QR_DATA_SIZE) // 864 bytes
        val frames = QrCodeUtil.splitIntoMultipartFrames(payload, totalFrames = 4)

        assertEquals(4, frames.size)
        val expectedCrc = QrCodeUtil.computeCrc16(payload)

        var totalChunkBytes = 0
        for (i in 0 until 4) {
            val frame = frames[i]
            assertEquals(i, frame.frameIndex)
            assertEquals(4, frame.totalFrames)
            assertEquals(expectedCrc, frame.crc16)
            assertTrue("Chunk size must be ~216-220 bytes, got ${frame.chunk.size}", frame.chunk.size in 210..225)
            totalChunkBytes += frame.chunk.size
        }
        assertEquals(HandshakeManager.QR_DATA_SIZE, totalChunkBytes)
    }

    @Test
    fun testBinaryEncodingAndParsing() {
        val payload = CryptoUtils.secureRandomBytes(HandshakeManager.QR_DATA_SIZE)
        val frames = QrCodeUtil.splitIntoMultipartFrames(payload, totalFrames = 4)

        for (frame in frames) {
            val encodedBytes = QrCodeUtil.encodeFrame(frame)
            assertEquals(8 + frame.chunk.size, encodedBytes.size)

            // Verify Magic "PQQR"
            assertEquals('P'.code.toByte(), encodedBytes[0])
            assertEquals('Q'.code.toByte(), encodedBytes[1])
            assertEquals('Q'.code.toByte(), encodedBytes[2])
            assertEquals('R'.code.toByte(), encodedBytes[3])

            // Verify Base64 string parsing
            val encodedString = QrCodeUtil.base64Encode(encodedBytes)
            val parsed = QrCodeUtil.parseMultipartFrame(encodedString)
            assertNotNull("Parsed frame must not be null", parsed)
            assertEquals(frame.frameIndex, parsed!!.frameIndex)
            assertEquals(frame.totalFrames, parsed.totalFrames)
            assertEquals(frame.crc16, parsed.crc16)
            assertArrayEquals(frame.chunk, parsed.chunk)
        }
    }

    @Test
    fun testTextEncodingAndParsing() {
        val chunk = CryptoUtils.secureRandomBytes(220)
        val frame = QrCodeUtil.MultipartFrame(
            frameIndex = 2,
            totalFrames = 4,
            crc16 = 0xABCD,
            chunk = chunk
        )

        val text = QrCodeUtil.encodeFrameToString(frame)
        assertTrue(text.startsWith("PQQR:2:4:ABCD:"))

        val parsed = QrCodeUtil.parseMultipartFrame(text)
        assertNotNull(parsed)
        assertEquals(2, parsed!!.frameIndex)
        assertEquals(4, parsed.totalFrames)
        assertEquals(0xABCD, parsed.crc16)
        assertArrayEquals(chunk, parsed.chunk)
    }

    @Test
    fun testAssemblerInOrder() {
        val payload = CryptoUtils.secureRandomBytes(HandshakeManager.QR_DATA_SIZE)
        val frames = QrCodeUtil.splitIntoMultipartFrames(payload, totalFrames = 4)
        val assembler = QrCodeUtil.MultipartQrAssembler()

        for (i in 0..2) {
            val res = assembler.processScan(QrCodeUtil.encodeFrameToString(frames[i]))
            assertTrue("Expected Progress for frame $i", res is QrCodeUtil.MultipartQrAssembler.AssembleResult.Progress)
            val prog = res as QrCodeUtil.MultipartQrAssembler.AssembleResult.Progress
            assertEquals(i + 1, prog.scannedCount)
            assertEquals(4, prog.totalCount)
        }

        // Frame 3 (Final)
        val resFinal = assembler.processScan(QrCodeUtil.encodeFrameToString(frames[3]))
        assertTrue("Expected Complete for frame 3", resFinal is QrCodeUtil.MultipartQrAssembler.AssembleResult.Complete)
        val comp = resFinal as QrCodeUtil.MultipartQrAssembler.AssembleResult.Complete
        assertEquals(4, comp.scannedCount)
        assertEquals(4, comp.totalCount)
        assertArrayEquals("Assembled payload must match original", payload, comp.payload)
        assertEquals(QrCodeUtil.base64Encode(payload), comp.rawBase64)
    }

    @Test
    fun testAssemblerOutOfOrder() {
        val payload = CryptoUtils.secureRandomBytes(HandshakeManager.QR_DATA_SIZE)
        val frames = QrCodeUtil.splitIntoMultipartFrames(payload, totalFrames = 4)
        val assembler = QrCodeUtil.MultipartQrAssembler()

        // Scan order: 2, 0, 3, 1
        val scanOrder = listOf(2, 0, 3, 1)

        val res0 = assembler.processScan(QrCodeUtil.base64Encode(QrCodeUtil.encodeFrame(frames[scanOrder[0]])))
        assertTrue(res0 is QrCodeUtil.MultipartQrAssembler.AssembleResult.Progress)
        assertEquals(1, (res0 as QrCodeUtil.MultipartQrAssembler.AssembleResult.Progress).scannedCount)

        val res1 = assembler.processScan(QrCodeUtil.base64Encode(QrCodeUtil.encodeFrame(frames[scanOrder[1]])))
        assertTrue(res1 is QrCodeUtil.MultipartQrAssembler.AssembleResult.Progress)
        assertEquals(2, (res1 as QrCodeUtil.MultipartQrAssembler.AssembleResult.Progress).scannedCount)

        val res2 = assembler.processScan(QrCodeUtil.base64Encode(QrCodeUtil.encodeFrame(frames[scanOrder[2]])))
        assertTrue(res2 is QrCodeUtil.MultipartQrAssembler.AssembleResult.Progress)
        assertEquals(3, (res2 as QrCodeUtil.MultipartQrAssembler.AssembleResult.Progress).scannedCount)

        val resFinal = assembler.processScan(QrCodeUtil.base64Encode(QrCodeUtil.encodeFrame(frames[scanOrder[3]])))
        assertTrue(resFinal is QrCodeUtil.MultipartQrAssembler.AssembleResult.Complete)
        val comp = resFinal as QrCodeUtil.MultipartQrAssembler.AssembleResult.Complete
        assertArrayEquals("Payload assembled out of order must match original", payload, comp.payload)
    }

    @Test
    fun testAssemblerDuplicateFrames() {
        val payload = CryptoUtils.secureRandomBytes(HandshakeManager.QR_DATA_SIZE)
        val frames = QrCodeUtil.splitIntoMultipartFrames(payload, totalFrames = 4)
        val assembler = QrCodeUtil.MultipartQrAssembler()

        // Scan frame 0 twice
        assembler.processScan(QrCodeUtil.encodeFrameToString(frames[0]))
        val dup = assembler.processScan(QrCodeUtil.encodeFrameToString(frames[0]))
        assertTrue(dup is QrCodeUtil.MultipartQrAssembler.AssembleResult.Progress)
        assertEquals(1, (dup as QrCodeUtil.MultipartQrAssembler.AssembleResult.Progress).scannedCount)

        // Scan remaining frames
        assembler.processScan(QrCodeUtil.encodeFrameToString(frames[1]))
        assembler.processScan(QrCodeUtil.encodeFrameToString(frames[2]))
        val comp = assembler.processScan(QrCodeUtil.encodeFrameToString(frames[3]))

        assertTrue(comp is QrCodeUtil.MultipartQrAssembler.AssembleResult.Complete)
        assertArrayEquals(payload, (comp as QrCodeUtil.MultipartQrAssembler.AssembleResult.Complete).payload)
    }

    @Test
    fun testSingleStaticQrCompatibility() {
        val staticPayload = CryptoUtils.secureRandomBytes(HandshakeManager.QR_DATA_SIZE)
        val staticBase64 = QrCodeUtil.base64Encode(staticPayload)

        val assembler = QrCodeUtil.MultipartQrAssembler()
        val res = assembler.processScan(staticBase64)

        assertTrue("Single static QR must be recognized as SingleStatic", res is QrCodeUtil.MultipartQrAssembler.AssembleResult.SingleStatic)
    }

    @Test
    fun testCrcMismatchDetection() {
        val payload = CryptoUtils.secureRandomBytes(HandshakeManager.QR_DATA_SIZE)
        val frames = QrCodeUtil.splitIntoMultipartFrames(payload, totalFrames = 4)
        val assembler = QrCodeUtil.MultipartQrAssembler()

        assembler.processScan(QrCodeUtil.encodeFrameToString(frames[0]))
        assembler.processScan(QrCodeUtil.encodeFrameToString(frames[1]))
        assembler.processScan(QrCodeUtil.encodeFrameToString(frames[2]))

        // Mutate frame 3 chunk data
        val corruptedChunk = frames[3].chunk.copyOf()
        corruptedChunk[0] = (corruptedChunk[0].toInt() xor 0xFF).toByte()
        val corruptedFrame = frames[3].copy(chunk = corruptedChunk)

        val err = assembler.processScan(QrCodeUtil.encodeFrameToString(corruptedFrame))
        assertTrue("Corrupted payload must produce Error", err is QrCodeUtil.MultipartQrAssembler.AssembleResult.Error)
        assertEquals(0, assembler.scannedCount)
    }

    @Test
    fun testSequenceChangeReset() {
        val payloadA = CryptoUtils.secureRandomBytes(HandshakeManager.QR_DATA_SIZE)
        val framesA = QrCodeUtil.splitIntoMultipartFrames(payloadA, totalFrames = 4)

        val payloadB = CryptoUtils.secureRandomBytes(HandshakeManager.QR_DATA_SIZE)
        val framesB = QrCodeUtil.splitIntoMultipartFrames(payloadB, totalFrames = 4)

        val assembler = QrCodeUtil.MultipartQrAssembler()

        // Scan frame 0 from sequence A
        assembler.processScan(QrCodeUtil.encodeFrameToString(framesA[0]))
        assertEquals(1, assembler.scannedCount)

        // Now camera switches to sequence B
        assembler.processScan(QrCodeUtil.encodeFrameToString(framesB[0]))
        assertEquals(1, assembler.scannedCount) // Reset to 1 for sequence B
        assembler.processScan(QrCodeUtil.encodeFrameToString(framesB[1]))
        assembler.processScan(QrCodeUtil.encodeFrameToString(framesB[2]))
        val comp = assembler.processScan(QrCodeUtil.encodeFrameToString(framesB[3]))

        assertTrue(comp is QrCodeUtil.MultipartQrAssembler.AssembleResult.Complete)
        assertArrayEquals(payloadB, (comp as QrCodeUtil.MultipartQrAssembler.AssembleResult.Complete).payload)
    }
}
