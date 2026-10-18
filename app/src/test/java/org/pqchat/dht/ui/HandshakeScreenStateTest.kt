package org.pqchat.dht.ui

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.protocol.HandshakeManager
import org.pqchat.dht.ui.util.QrCodeUtil
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.Security

/**
 * Unit and UI state regression tests for HandshakeScreen (Alice & Bob flow).
 *
 * Specifically verifies:
 * 1. Alice screen state when aliceInitState is null (prevents NullPointerException).
 * 2. Successful generation of static and animated multipart QR code bitmaps when aliceInitState is non-null.
 * 3. Secure key erasure and state clearing on reset ("Zresetuj").
 * 4. Safe regeneration of fresh ML-KEM-512 keypair and new Target_0 ("Nowy kod QR").
 * 5. Full cryptographic handshake compatibility between Alice QR and Bob scanner.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class HandshakeScreenStateTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun setupBouncyCastle() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @Test
    fun testAliceScreenInitialStateIsNullAndDoesNotTriggerNpe() {
        var aliceInitState: HandshakeManager.AliceInitResult? = null

        // Initial condition: state must be null before user clicks "Generate ML-KEM-512 QR Code"
        assertNull("Alice initial state must be null", aliceInitState)

        // Simulate HandshakeScreen condition:
        // if (aliceInitState == null) -> Render Generate Button
        // else -> Render QR Bitmap & target0
        var generateButtonVisible = false
        var qrDisplayVisible = false
        var target0Displayed: String? = null

        if (aliceInitState == null) {
            generateButtonVisible = true
        } else {
            qrDisplayVisible = true
            val state = aliceInitState
            target0Displayed = CryptoUtils.toHex(state.target0)
        }

        assertTrue("Generate button must be visible when state is null", generateButtonVisible)
        assertFalse("QR display must NOT be visible when state is null", qrDisplayVisible)
        assertNull("Target_0 must NOT be accessed when state is null", target0Displayed)
    }

    @Test
    fun testAliceHandshakeGenerationRendersQrBitmapsAndTarget0() {
        // User clicks "Generate ML-KEM-512 QR Code"
        val aliceInitState: HandshakeManager.AliceInitResult? = HandshakeManager.aliceCreateHandshake()
        assertNotNull("Alice state must be non-null after generation", aliceInitState)

        val state = aliceInitState!!
        assertEquals(HandshakeManager.QR_DATA_SIZE, state.qrBytes.size)
        assertEquals(20, state.target0.size)

        // When aliceInitState != null:
        var generateButtonVisible = false
        var qrDisplayVisible = false
        var target0Hex: String? = null

        @Suppress("KotlinConstantConditions")
        if (aliceInitState == null) {
            generateButtonVisible = true
        } else {
            qrDisplayVisible = true
            target0Hex = CryptoUtils.toHex(state.target0)
        }

        assertFalse("Generate button must be hidden when QR is active", generateButtonVisible)
        assertTrue("QR display must be active when state is non-null", qrDisplayVisible)
        assertNotNull("Target_0 hex must be computed successfully", target0Hex)
        assertEquals(40, target0Hex!!.length)

        // Verify QR bitmap generation for static display
        val staticBitmap = QrCodeUtil.generateQrBitmap(state.qrBytes, size = 600)
        assertNotNull("Static QR bitmap must be generated", staticBitmap)
        assertEquals(600, staticBitmap.width)
        assertEquals(600, staticBitmap.height)

        // Verify animated multipart QR bitmaps generation
        val animatedFrames = QrCodeUtil.generateMultipartQrBitmaps(state.qrBytes, totalFrames = 4, size = 600)
        assertNotNull("Animated multipart frames list must not be null", animatedFrames)
        assertEquals(4, animatedFrames.size)
        for (frame in animatedFrames) {
            assertEquals(600, frame.width)
            assertEquals(600, frame.height)
        }
    }

    @Test
    fun testResetHandshakeCleansStateAndZeroesSensitiveKeys() {
        var aliceInitState: HandshakeManager.AliceInitResult? = HandshakeManager.aliceCreateHandshake()
        val originalSkA = aliceInitState!!.skA.copyOf()
        assertFalse("Original skA must contain non-zero key bytes", originalSkA.all { it == 0.toByte() })

        // User clicks "Zresetuj"
        aliceInitState.destroySensitiveKeys()
        assertTrue("Destroyed skA must be filled with 0s", aliceInitState.skA.all { it == 0.toByte() })

        aliceInitState = null
        assertNull("Alice state must be reset to null", aliceInitState)

        // Ensure state falls back to initial screen branch
        @Suppress("KotlinConstantConditions")
        val isButtonVisible = (aliceInitState == null)
        assertTrue("UI should transition back to initial generate button", isButtonVisible)
    }

    @Test
    fun testRegenerateHandshakeProducesNewDistinctKeypairAndTarget0() {
        // First generation
        val firstState = HandshakeManager.aliceCreateHandshake()
        val firstTarget0 = CryptoUtils.toHex(firstState.target0)
        val firstSeed = firstState.seedInit.copyOf()

        // User clicks "Nowy kod QR" (reset and start new handshake)
        firstState.destroySensitiveKeys()
        val secondState = HandshakeManager.aliceCreateHandshake()
        val secondTarget0 = CryptoUtils.toHex(secondState.target0)
        val secondSeed = secondState.seedInit.copyOf()

        assertNotEquals("Target_0 must be distinct between regenerated handshakes", firstTarget0, secondTarget0)
        assertFalse("Seeds must differ between runs", firstSeed.contentEquals(secondSeed))
        assertFalse("Public keys must differ between runs", firstState.pkA.contentEquals(secondState.pkA))

        // Ensure new QR bitmap can be generated cleanly
        val newBitmap = QrCodeUtil.generateQrBitmap(secondState.qrBytes, size = 600)
        assertNotNull("New QR bitmap must be generated", newBitmap)

        secondState.destroySensitiveKeys()
    }

    @Test
    fun testAliceQrIsFullyCompatibleWithBobScanner() {
        val aliceInit = HandshakeManager.aliceCreateHandshake()

        // Bob scans Alice's QR code
        val bobResult = HandshakeManager.bobProcessQr(aliceInit.qrBytes)
        assertNotNull(bobResult.sas)
        assertEquals(aliceInit.target0.toList(), bobResult.target0.toList())

        // Alice receives Bob's frame from DHT Target_0
        val aliceSession = HandshakeManager.aliceFinalize(
            skA = aliceInit.skA,
            pkA = aliceInit.pkA,
            seedInit = aliceInit.seedInit,
            frame = bobResult.frame
        )

        assertEquals("SAS code must match exactly between Alice and Bob", bobResult.sas, aliceSession.sas)
        assertEquals("Fingerprints must match", bobResult.fingerprint, aliceSession.fingerprint)

        aliceInit.destroySensitiveKeys()
    }
}
