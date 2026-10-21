package org.pqchat.dht.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.pqchat.dht.dht.bencode.Bencode
import org.pqchat.dht.protocol.LocationPinData
import java.security.Security
import javax.crypto.AEADBadTagException
import kotlin.math.log2

class MicroPayloadsTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupProviders() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @Test
    fun testReactionMicroPayloadRoundtripAndExactSize() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"

        val targetEpoch = 3
        val targetSeqNum = 42
        val emoji = "🔥"

        // 1. Encode inner payload
        val innerPayload = BinaryFrameCodec.encodeReaction(
            seqNum = 5,
            ackNum = 4,
            timestampUTC = 1771700000000L,
            targetSeqEpoch = targetEpoch,
            targetSeqNum = targetSeqNum,
            emoji = emoji
        )
        assertEquals(
            "Inner ciphertext payload must be exactly CIPHERTEXT_SIZE (872 bytes)",
            BinaryFrameCodec.CIPHERTEXT_SIZE,
            innerPayload.size
        )

        // 2. Pack into AEAD frame (IV 12 B + Tag 16 B + Ciphertext 872 B = 900 B)
        val frame = BinaryFrameCodec.packAeadFrame(key, innerPayload, target, direction)
        assertEquals(
            "Total BEP 44 wire frame must be exactly 900 bytes",
            BinaryFrameCodec.TOTAL_FRAME_SIZE,
            frame.size
        )

        // 3. Unpack and verify decoded fields
        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        assertEquals(BinaryFrameCodec.TYPE_REACTION, decoded.msgType)
        assertEquals(5, decoded.seqNum)
        assertEquals(4, decoded.ackNum)
        assertEquals(1771700000000L, decoded.timestampUTC)

        assertTrue(decoded.payload is BinaryFrameCodec.DecodedPayload.Reaction)
        val reactionPayload = decoded.payload as BinaryFrameCodec.DecodedPayload.Reaction
        assertEquals(targetEpoch, reactionPayload.targetSeqEpoch)
        assertEquals(targetSeqNum, reactionPayload.targetSeqNum)
        assertEquals(emoji, reactionPayload.emoji)
    }

    @Test
    fun testLocationPinMicroPayloadRoundtripAndExactSize() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "BobToAlice"

        val lat = 52.2296756
        val lon = 21.0122287
        val alt = 112.5
        val acc = 3.5f
        val note = "Punkt zborny Bravo - Status: Bezpieczny (Offline)"

        // 1. Encode inner payload
        val innerPayload = BinaryFrameCodec.encodeLocationPin(
            seqNum = 12,
            ackNum = 11,
            timestampUTC = 1771700050000L,
            latitude = lat,
            longitude = lon,
            altitude = alt,
            accuracy = acc,
            note = note
        )
        assertEquals(
            "Inner ciphertext payload must be exactly CIPHERTEXT_SIZE (872 bytes)",
            BinaryFrameCodec.CIPHERTEXT_SIZE,
            innerPayload.size
        )

        // 2. Pack into AEAD frame
        val frame = BinaryFrameCodec.packAeadFrame(key, innerPayload, target, direction)
        assertEquals(
            "Total BEP 44 wire frame must be exactly 900 bytes",
            BinaryFrameCodec.TOTAL_FRAME_SIZE,
            frame.size
        )

        // 3. Unpack and verify decoded fields
        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        assertEquals(BinaryFrameCodec.TYPE_LOCATION_PIN, decoded.msgType)
        assertEquals(12, decoded.seqNum)
        assertEquals(11, decoded.ackNum)
        assertEquals(1771700050000L, decoded.timestampUTC)

        assertTrue(decoded.payload is BinaryFrameCodec.DecodedPayload.LocationPin)
        val pinPayload = decoded.payload as BinaryFrameCodec.DecodedPayload.LocationPin
        assertEquals(lat, pinPayload.latitude, 0.000001)
        assertEquals(lon, pinPayload.longitude, 0.000001)
        assertEquals(alt, pinPayload.altitude, 0.001)
        assertEquals(acc, pinPayload.accuracy, 0.01f)
        assertEquals(note, pinPayload.note)
    }

    @Test
    fun testBencodeComplianceStrictlyUnder1000Bytes() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"

        val reactionPayload = BinaryFrameCodec.encodeReaction(1, 0, 1000L, 0, 0, "❤️")
        val reactionFrame = BinaryFrameCodec.packAeadFrame(key, reactionPayload, target, direction)

        val locationPayload = BinaryFrameCodec.encodeLocationPin(2, 1, 2000L, 50.0, 20.0, 100.0, 5f, "Test")
        val locationFrame = BinaryFrameCodec.packAeadFrame(key, locationPayload, target, direction)

        // BEP 44 raw string Bencoding: "900:" + 900 bytes = 904 bytes
        val bencodedReaction = Bencode.encode(reactionFrame)
        val bencodedLocation = Bencode.encode(locationFrame)

        assertEquals(904, bencodedReaction.size)
        assertEquals(904, bencodedLocation.size)
        assertTrue("Bencoded value must strictly fit within BEP 44 1000-byte limit", bencodedReaction.size <= 1000)
        assertTrue("Bencoded value must strictly fit within BEP 44 1000-byte limit", bencodedLocation.size <= 1000)

        // Dictionary with 'v' field: d1:v900:<bytes>e = 1 + 3 + 904 + 1 = 909 bytes
        val dhtValueMap = mapOf("v" to reactionFrame)
        val bencodedMap = Bencode.encode(dhtValueMap)
        assertEquals(909, bencodedMap.size)
        assertTrue(bencodedMap.size <= 1000)
    }

    @Test
    fun testIndistinguishabilityFromTextAndCoverTraffic() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"

        // 1. Generate frames for different types
        val reactionFrame = BinaryFrameCodec.packAeadFrame(
            key,
            BinaryFrameCodec.encodeReaction(1, 0, 1000L, 0, 1, "👍"),
            target,
            direction
        )
        val locationFrame = BinaryFrameCodec.packAeadFrame(
            key,
            BinaryFrameCodec.encodeLocationPin(2, 1, 2000L, 52.2, 21.0, 100.0, 5.0f, "Status OK"),
            target,
            direction
        )
        val textFrame = BinaryFrameCodec.packAeadFrame(
            key,
            BinaryFrameCodec.encodeTextMessage(3, 2, 3000L, "Hello world"),
            target,
            direction
        )
        val dummyFrame = CryptoUtils.secureRandomBytes(BinaryFrameCodec.TOTAL_FRAME_SIZE)

        // All frames have identical length
        assertEquals(900, reactionFrame.size)
        assertEquals(900, locationFrame.size)
        assertEquals(900, textFrame.size)
        assertEquals(900, dummyFrame.size)

        // Shannon entropy of ciphertext frames must be close to theoretical expectation (~7.7 - 7.8 bits for 900 random bytes)
        val entropyReaction = calculateShannonEntropy(reactionFrame)
        val entropyLocation = calculateShannonEntropy(locationFrame)
        val entropyText = calculateShannonEntropy(textFrame)
        val entropyDummy = calculateShannonEntropy(dummyFrame)

        assertTrue("Reaction frame entropy must be > 7.5 (was $entropyReaction)", entropyReaction > 7.5)
        assertTrue("Location pin frame entropy must be > 7.5 (was $entropyLocation)", entropyLocation > 7.5)
        assertTrue("Text message frame entropy must be > 7.5 (was $entropyText)", entropyText > 7.5)
        assertTrue("Dummy cover traffic entropy must be > 7.5 (was $entropyDummy)", entropyDummy > 7.5)

        // Indistinguishability: entropy difference between payload frames and pure dummy CSPRNG noise is minimal (< 0.25)
        assertTrue(kotlin.math.abs(entropyReaction - entropyDummy) < 0.25)
        assertTrue(kotlin.math.abs(entropyLocation - entropyDummy) < 0.25)
        assertTrue(kotlin.math.abs(entropyText - entropyDummy) < 0.25)

        // Verify AEAD binding: wrong key or wrong target/direction must fail decryption
        val wrongKey = CryptoUtils.secureRandomBytes(32)
        assertThrows(AEADBadTagException::class.java) {
            BinaryFrameCodec.unpackAeadFrame(wrongKey, reactionFrame, target, direction)
        }
        assertThrows(AEADBadTagException::class.java) {
            BinaryFrameCodec.unpackAeadFrame(wrongKey, locationFrame, target, direction)
        }
        val wrongTarget = CryptoUtils.secureRandomBytes(20)
        assertThrows(AEADBadTagException::class.java) {
            BinaryFrameCodec.unpackAeadFrame(key, reactionFrame, wrongTarget, direction)
        }
        assertThrows(AEADBadTagException::class.java) {
            BinaryFrameCodec.unpackAeadFrame(key, locationFrame, wrongTarget, direction)
        }
    }

    @Test
    fun testLocationPinHelperFormatAndParse() {
        val pin = LocationPinData(
            latitude = 52.2297,
            longitude = 21.0122,
            altitude = 115.0,
            accuracy = 4.5f,
            note = "Schronienie Alpha"
        )

        val payloadText = pin.toPayloadText()
        assertTrue(payloadText.startsWith("geo:52.2297,21.0122"))
        assertTrue(payloadText.contains("alt=115.0"))
        assertTrue(payloadText.contains("acc=4.5"))
        assertTrue(payloadText.contains("note=Schronienie%20Alpha"))

        val parsed = LocationPinData.parse(payloadText)
        assertNotNull(parsed)
        assertEquals(52.2297, parsed!!.latitude, 0.0001)
        assertEquals(21.0122, parsed.longitude, 0.0001)
        assertEquals(115.0, parsed.altitude, 0.1)
        assertEquals(4.5f, parsed.accuracy, 0.1f)
        assertEquals("Schronienie Alpha", parsed.note)

        // Test geoUri generation
        val geoUri = parsed.geoUri
        assertTrue(geoUri.startsWith("geo:52.2297,21.0122"))
        assertTrue(geoUri.contains("q=52.2297,21.0122(Schronienie%20Alpha)"))

        // Test non-geo text returns null
        assertNull(LocationPinData.parse("Cześć, co słychać?"))
        assertNull(LocationPinData.parse(""))
        assertNull(LocationPinData.parse(null))
    }

    @Test
    fun testChunkDataEqualsAndHashCodeIncludesEphemeralTtl() {
        val transferId = ByteArray(16) { 0x01 }
        val transferId2 = ByteArray(16) { 0x02 }
        val data = ByteArray(100) { 0xAA.toByte() }

        val chunk1 = BinaryFrameCodec.DecodedPayload.ChunkData(transferId, 0, 5, data, 60L)
        val chunk2 = BinaryFrameCodec.DecodedPayload.ChunkData(transferId.copyOf(), 0, 5, data.copyOf(), 60L)
        val chunk3DiffTtl = BinaryFrameCodec.DecodedPayload.ChunkData(transferId.copyOf(), 0, 5, data.copyOf(), 120L)
        val chunk4DiffTransfer = BinaryFrameCodec.DecodedPayload.ChunkData(transferId2, 0, 5, data.copyOf(), 60L)

        assertEquals(chunk1, chunk2)
        assertEquals(chunk1.hashCode(), chunk2.hashCode())

        assertNotEquals(chunk1, chunk3DiffTtl)
        assertNotEquals(chunk1.hashCode(), chunk3DiffTtl.hashCode())

        assertNotEquals(chunk1, chunk4DiffTransfer)
    }

    @Test
    fun testReactionEmojiLength1ByteAndBoundaryValidation() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "AliceToBob"

        // 1. Emoji exceeding 64 bytes must be rejected at encoding
        val oversizedEmoji = "🔥".repeat(40) // 40 * 4 = 160 bytes > 64
        assertThrows(IllegalArgumentException::class.java) {
            BinaryFrameCodec.encodeReaction(1, 0, 1000L, 0, 1, oversizedEmoji)
        }

        // 2. Normal 1-byte length roundtrip
        val emoji = "🚀"
        val payload = BinaryFrameCodec.encodeReaction(1, 0, 1000L, 0, 1, emoji)
        // Header is 13 B, reaction body: targetEpoch(4) + targetSeq(2) + emojiLen(1) = 7 B
        val emojiLenInPayload = payload[13 + 6].toInt() and 0xFF
        assertEquals(emoji.toByteArray(Charsets.UTF_8).size, emojiLenInPayload)

        val frame = BinaryFrameCodec.packAeadFrame(key, payload, target, direction)
        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        assertTrue(decoded.payload is BinaryFrameCodec.DecodedPayload.Reaction)
        assertEquals(emoji, (decoded.payload as BinaryFrameCodec.DecodedPayload.Reaction).emoji)
    }

    @Test
    fun testLocationPinWithEphemeralTtlAndBoundaryValidation() {
        val key = CryptoUtils.secureRandomBytes(32)
        val target = CryptoUtils.secureRandomBytes(20)
        val direction = "BobToAlice"

        val lat = 50.0647
        val lon = 19.9450
        val alt = 219.0
        val acc = 2.0f
        val note = "Baza operacyjna"
        val ttl = 3600L

        val payload = BinaryFrameCodec.encodeLocationPin(
            seqNum = 1,
            ackNum = 0,
            timestampUTC = 1000L,
            latitude = lat,
            longitude = lon,
            altitude = alt,
            accuracy = acc,
            note = note,
            ephemeralTtlSeconds = ttl
        )

        val frame = BinaryFrameCodec.packAeadFrame(key, payload, target, direction)
        val decoded = BinaryFrameCodec.unpackAeadFrame(key, frame, target, direction)
        assertTrue(decoded.payload is BinaryFrameCodec.DecodedPayload.LocationPin)
        val pin = decoded.payload as BinaryFrameCodec.DecodedPayload.LocationPin
        assertEquals(lat, pin.latitude, 0.0001)
        assertEquals(lon, pin.longitude, 0.0001)
        assertEquals(note, pin.note)
        assertEquals(ttl, pin.ephemeralTtlSeconds)

        // Oversized note validation
        val hugeNote = "A".repeat(850)
        assertThrows(IllegalArgumentException::class.java) {
            BinaryFrameCodec.encodeLocationPin(1, 0, 1000L, lat, lon, alt, acc, hugeNote, ttl)
        }
    }

    private fun calculateShannonEntropy(data: ByteArray): Double {
        val frequencies = IntArray(256)
        for (b in data) {
            frequencies[b.toInt() and 0xFF]++
        }
        var entropy = 0.0
        val total = data.size.toDouble()
        for (count in frequencies) {
            if (count > 0) {
                val p = count / total
                entropy -= p * log2(p)
            }
        }
        return entropy
    }
}
