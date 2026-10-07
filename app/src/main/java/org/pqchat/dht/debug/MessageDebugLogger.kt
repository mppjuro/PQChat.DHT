package org.pqchat.dht.debug

import org.pqchat.dht.BuildConfig
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.protocol.RatchetChain
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicInteger

/**
 * Diagnostic & Cryptographic Debug Logger for PQChat DHT.
 *
 * Formats outgoing and incoming messages into structured, readable JSON-like logs,
 * clearly decomposing and distinguishing:
 * - Post-Quantum Cryptography (PQC: ML-KEM-512 / Kyber)
 * - Symmetric Cryptography (AES-256-GCM: IV, Tag, Ciphertext)
 * - DHT / BEP 44 Transport Metadata (Target, Ed25519 signature & keys)
 *
 * Prints to stdout (console) and logs to Android Logcat under tag "PQChat-Debug".
 * STRICTLY DISABLED in release builds or when isEnabled is false (AGENTS.md §8).
 */
object MessageDebugLogger {

    var isEnabled: Boolean = BuildConfig.DEBUG
    val emitCount = AtomicInteger(0)

    // ==========================================
    // OUTGOING MESSAGES (SENT TO SERVER / DHT)
    // ==========================================

    fun logOutgoingTextMessage(
        contactId: String,
        text: String,
        slot: RatchetChain.SlotParameters,
        seqNum: Int,
        ackNum: Int,
        plaintext972: ByteArray,
        frame900: ByteArray
    ) {
        if (!isEnabled) return

        val headerMap = extractHeaderMap(plaintext972).toMutableMap().apply {
            put("explicitSeqNum", seqNum)
            put("explicitAckNum", ackNum)
        }
        val textBytes = text.toByteArray(Charsets.UTF_8)
        val paddingCount = BinaryFrameCodec.INNER_PAYLOAD_SIZE - 2 - textBytes.size

        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Wiadomość tekstowa wysyłana do kontaktu",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(System.currentTimeMillis()),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(slot.target),
                "bep44Seq" to (slot.counter + 1).toLong(),
                "ed25519PublicKeyHex" to CryptoUtils.toHex(slot.edPublicKey),
                "ed25519SeedPreview" to toHexPreview(slot.edPrivateKeySeed, 16)
            ),
            "beforeEncryption_Plaintext" to linkedMapOf(
                "totalPlaintextSize" to "${plaintext972.size} bajtów (rozmiar stały)",
                "header" to headerMap,
                "payload" to linkedMapOf(
                    "type" to "TextMessage (0x02)",
                    "text" to text,
                    "textByteLength" to textBytes.size,
                    "paddingBytesCount" to maxOf(0, paddingCount),
                    "description" to "Jawna treść wiadomości przed nałożeniem szyfrowania AES-256-GCM"
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame900 = frame900,
                slotMsgKey = slot.msgKey,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to false,
                    "pqcAlgorithm" to "ML-KEM-512 (Kyber-512 / FIPS 203)",
                    "relation" to "Wyprowadzanie klucza ratchetu z KDF zainicjalizowanego wymianą post-kwantową",
                    "description" to "Wiadomość jest chroniona symetrycznie AES-256-GCM kluczem MsgKey_${slot.counter}. Klucz ten pochodzi z łańcucha KDF (Ratchet), którego źródłem entropii jest post-kwantowa wymiana ML-KEM-512."
                ),
                dhtTarget = slot.target,
                dhtSeq = (slot.counter + 1).toLong(),
                edPublicKey = slot.edPublicKey
            )
        )

        emitLog("WYSŁANO WIADOMOŚĆ NA SERWER DHT [TEKST]", jsonMap)
    }

    fun logOutgoingRekeyOffer(
        contactId: String,
        epoch: Long,
        slot: RatchetChain.SlotParameters,
        seqNum: Int,
        ackNum: Int,
        mlKemPublicKey: ByteArray,
        frame900: ByteArray
    ) {
        if (!isEnabled) return

        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Oferta rotacji kluczy PQC (Rekey Offer)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(System.currentTimeMillis()),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(slot.target),
                "bep44Seq" to (slot.counter + 1).toLong(),
                "ed25519PublicKeyHex" to CryptoUtils.toHex(slot.edPublicKey)
            ),
            "beforeEncryption_Plaintext" to linkedMapOf(
                "totalPlaintextSize" to "872 bajtów",
                "header" to linkedMapOf(
                    "messageType" to "0x03 (TYPE_REKEY_OFFER)",
                    "seqNum" to seqNum,
                    "ackNum" to ackNum,
                    "rekeyEpoch" to epoch
                ),
                "payload" to linkedMapOf(
                    "type" to "RekeyOffer",
                    "rekeyEpoch" to epoch,
                    "pqcPublicKey_MLKEM512" to linkedMapOf(
                        "algorithm" to "ML-KEM-512 (Kyber-512)",
                        "role" to "Nowy klucz publiczny PQC (pk_new)",
                        "sizeBytes" to mlKemPublicKey.size,
                        "hexPreview" to toHexPreview(mlKemPublicKey, 32),
                        "description" to "Nowo wygenerowany klucz publiczny post-kwantowy do odświeżenia łańcucha KDF (Forward Secrecy)"
                    ),
                    "paddingBytesCount" to BinaryFrameCodec.T3_PADDING_SIZE
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame900 = frame900,
                slotMsgKey = slot.msgKey,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to false,
                    "isPqcPublicKeyInPayload" to true,
                    "pqcAlgorithm" to "ML-KEM-512",
                    "description" to "Ładunek przenosi nowy klucz publiczny ML-KEM-512 (800 B) opakowany w szyfrowanie symetryczne AES-256-GCM."
                ),
                dhtTarget = slot.target,
                dhtSeq = (slot.counter + 1).toLong(),
                edPublicKey = slot.edPublicKey
            )
        )

        emitLog("WYSŁANO OFERTĘ ROTACJI KLUCZY PQC (REKEY OFFER)", jsonMap)
    }

    fun logOutgoingRekeyResponse(
        contactId: String,
        epoch: Long,
        slot: RatchetChain.SlotParameters,
        seqNum: Int,
        ackNum: Int,
        frame900: ByteArray
    ) {
        if (!isEnabled) return

        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Odpowiedź na rotację kluczy PQC (Rekey Response)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(System.currentTimeMillis()),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(slot.target),
                "bep44Seq" to (slot.counter + 1).toLong(),
                "ed25519PublicKeyHex" to CryptoUtils.toHex(slot.edPublicKey)
            ),
            "beforeEncryption_Plaintext" to linkedMapOf(
                "totalPlaintextSize" to "872 bajtów",
                "header" to linkedMapOf(
                    "messageType" to "0x04 (TYPE_REKEY_RESPONSE)",
                    "seqNum" to seqNum,
                    "ackNum" to ackNum,
                    "rekeyEpoch" to epoch
                ),
                "payload" to linkedMapOf(
                    "type" to "RekeyResponse",
                    "rekeyEpoch" to epoch,
                    "pqcCiphertext_MLKEM512" to linkedMapOf(
                        "algorithm" to "ML-KEM-512 (Kyber-512)",
                        "role" to "Zaszyfrowany post-kwantowo nowy sekret rotacji (ct_new)",
                        "sizeBytes" to BinaryFrameCodec.T4_CIPHERTEXT_SIZE,
                        "description" to "Kapsuła klucza wygenerowana przez ML-KEM-512 w odpowiedzi na Rekey Offer"
                    ),
                    "paddingBytesCount" to BinaryFrameCodec.T4_PADDING_SIZE
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame900 = frame900,
                slotMsgKey = slot.msgKey,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to true,
                    "pqcAlgorithm" to "ML-KEM-512",
                    "pqcCiphertextSize" to BinaryFrameCodec.T4_CIPHERTEXT_SIZE,
                    "description" to "BEZPOŚREDNIE SZYFROWANIE POST-KWANTOWE: Kapsuła ML-KEM-512 (768 B) znajduje się wewnątrz ramki AES-256-GCM."
                ),
                dhtTarget = slot.target,
                dhtSeq = (slot.counter + 1).toLong(),
                edPublicKey = slot.edPublicKey
            )
        )

        emitLog("WYSŁANO ODPOWIEDŹ NA ROTACJĘ PQC (REKEY RESPONSE)", jsonMap)
    }

    fun logOutgoingChunkData(
        contactId: String,
        transferId: ByteArray,
        chunkIndex: Int,
        totalChunks: Int,
        target: ByteArray,
        seq: Long,
        slotMsgKey: ByteArray?,
        frame900: ByteArray
    ) {
        if (!isEnabled) return

        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Fragment danych binarnych (plik / obraz PNG)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(System.currentTimeMillis()),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq
            ),
            "beforeEncryption_Plaintext" to linkedMapOf(
                "totalPlaintextSize" to "872 bajtów",
                "header" to linkedMapOf(
                    "messageType" to "0x05 (TYPE_CHUNK_DATA)",
                    "chunkIndex" to chunkIndex,
                    "totalChunks" to totalChunks,
                    "transferIdHex" to CryptoUtils.toHex(transferId)
                ),
                "payload" to linkedMapOf(
                    "type" to "ChunkData",
                    "chunkIndex" to chunkIndex,
                    "totalChunks" to totalChunks,
                    "transferId" to CryptoUtils.toHex(transferId),
                    "description" to "Fragment wieloczęściowego transferu binarnego"
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame900 = frame900,
                slotMsgKey = slotMsgKey,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to false,
                    "pqcAlgorithm" to "ML-KEM-512",
                    "description" to "Klucz AES dla fragmentu został wyprowadzony deterministycznie z ratchetu chronionego post-kwantowo."
                ),
                dhtTarget = target,
                dhtSeq = seq,
                edPublicKey = null
            )
        )

        emitLog("WYSŁANO FRAGMENT BINARNY [CHUNK ${chunkIndex + 1}/$totalChunks]", jsonMap)
    }

    fun logOutgoingBobHandshake(
        target: ByteArray,
        seq: Long,
        edPrivateKeySeed: ByteArray,
        frame900: ByteArray
    ) {
        if (!isEnabled) return

        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Bob -> Alice Handshake Finalize (Inicjalizacja tunelu post-kwantowego)",
            "timestampIso" to formatIsoTimestamp(System.currentTimeMillis()),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq,
                "edPrivateKeySeedPreview" to toHexPreview(edPrivateKeySeed, 16)
            ),
            "beforeEncryption_Plaintext" to linkedMapOf(
                "totalPlaintextSize" to "872 bajtów",
                "header" to linkedMapOf(
                    "messageType" to "0x01 (TYPE_HANDSHAKE_FINALIZE)",
                    "seqNum" to 0,
                    "ackNum" to 0
                ),
                "payload" to linkedMapOf(
                    "type" to "HandshakeFinalize",
                    "pqcCiphertext_MLKEM512" to linkedMapOf(
                        "algorithm" to "ML-KEM-512 (Kyber-512 / FIPS 203)",
                        "role" to "Post-Quantum KEM Ciphertext (ct_B)",
                        "sizeBytes" to BinaryFrameCodec.T1_CIPHERTEXT_SIZE,
                        "description" to "Zaszyfrowany post-kwantowo kluczem publicznym Alice wspólny sekret SS_init"
                    ),
                    "saltBytes" to BinaryFrameCodec.T1_SALT_SIZE,
                    "paddingBytes" to BinaryFrameCodec.T1_PADDING_SIZE
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame900 = frame900,
                slotMsgKey = null,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to true,
                    "pqcAlgorithm" to "ML-KEM-512",
                    "pqcCiphertextSize" to BinaryFrameCodec.T1_CIPHERTEXT_SIZE,
                    "description" to "BEZPOŚREDNIE SZYFROWANIE PQC: Szyfrogram ML-KEM-512 (768 B) opakowany w symetryczną ramkę AES-256-GCM."
                ),
                dhtTarget = target,
                dhtSeq = seq,
                edPublicKey = null
            )
        )

        emitLog("WYSŁANO POST-KWANTOWY HANDSHAKE FINALIZE DO DHT (BOB -> ALICE)", jsonMap)
    }

    // ==========================================
    // INCOMING MESSAGES (RECEIVED FROM SERVER / DHT)
    // ==========================================

    fun logIncomingMessage(
        contactId: String?,
        target: ByteArray,
        seq: Long,
        senderEdPublicKey: ByteArray?,
        senderSignature: ByteArray?,
        frame900: ByteArray,
        frameMsg: BinaryFrameCodec.FrameMessage,
        slotMsgKey: ByteArray? = null
    ) {
        if (!isEnabled) return

        val (iv, tag, ciphertext) = extractAesComponents(frame900)

        val payloadMap = when (val p = frameMsg.payload) {
            is BinaryFrameCodec.DecodedPayload.TextMessage -> linkedMapOf<String, Any?>(
                "type" to "TextMessage (0x02)",
                "text" to p.text,
                "textByteLength" to p.text.toByteArray(Charsets.UTF_8).size
            )
            is BinaryFrameCodec.DecodedPayload.HandshakeFinalize -> linkedMapOf<String, Any?>(
                "type" to "HandshakeFinalize (0x01)",
                "pqcCiphertext_MLKEM512" to linkedMapOf(
                    "algorithm" to "ML-KEM-512",
                    "sizeBytes" to p.mlKemCiphertext.size,
                    "hexPreview" to toHexPreview(p.mlKemCiphertext, 32),
                    "description" to "Zaszyfrowany post-kwantowo wspólny sekret SS_init"
                ),
                "saltHex" to CryptoUtils.toHex(p.saltParameter)
            )
            is BinaryFrameCodec.DecodedPayload.RekeyOffer -> linkedMapOf<String, Any?>(
                "type" to "RekeyOffer (0x03)",
                "rekeyEpoch" to p.rekeyEpoch,
                "pqcPublicKey_MLKEM512" to linkedMapOf(
                    "algorithm" to "ML-KEM-512",
                    "sizeBytes" to p.mlKemPublicKey.size,
                    "hexPreview" to toHexPreview(p.mlKemPublicKey, 32),
                    "description" to "Nowy klucz publiczny nadawcy do rotacji KDF"
                )
            )
            is BinaryFrameCodec.DecodedPayload.RekeyResponse -> linkedMapOf<String, Any?>(
                "type" to "RekeyResponse (0x04)",
                "rekeyEpoch" to p.rekeyEpoch,
                "pqcCiphertext_MLKEM512" to linkedMapOf(
                    "algorithm" to "ML-KEM-512",
                    "sizeBytes" to p.mlKemCiphertext.size,
                    "hexPreview" to toHexPreview(p.mlKemCiphertext, 32),
                    "description" to "Zaszyfrowany post-kwantowo nowy sekret rotacji SS_rekey"
                )
            )
            is BinaryFrameCodec.DecodedPayload.ChunkData -> linkedMapOf<String, Any?>(
                "type" to "ChunkData (0x05)",
                "transferIdHex" to CryptoUtils.toHex(p.transferId),
                "chunkIndex" to p.chunkIndex,
                "totalChunks" to p.totalChunks,
                "dataSizeBytes" to p.data.size,
                "dataHexPreview" to toHexPreview(p.data, 32)
            )
        }

        val pqcAnalysis = when (frameMsg.msgType) {
            BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE -> linkedMapOf(
                "isDirectPqcCiphertextInPayload" to true,
                "pqcAlgorithm" to "ML-KEM-512",
                "description" to "Otrzymano kapsułę ML-KEM-512. Wymaga dekapsulacji prywatnym kluczem sk_A w celu odzyskania SS_init."
            )
            BinaryFrameCodec.TYPE_REKEY_OFFER -> linkedMapOf(
                "isDirectPqcCiphertextInPayload" to false,
                "isPqcPublicKeyInPayload" to true,
                "pqcAlgorithm" to "ML-KEM-512",
                "description" to "Otrzymano nowy klucz publiczny PQC pk_new. Zostanie użyty do enkapsulacji nowego sekretu rotacji SS_rekey."
            )
            BinaryFrameCodec.TYPE_REKEY_RESPONSE -> linkedMapOf(
                "isDirectPqcCiphertextInPayload" to true,
                "pqcAlgorithm" to "ML-KEM-512",
                "description" to "Otrzymano kapsułę nowego sekretu rotacji. Zostanie zdekapsulowana kluczem sk_new w celu zaktualizowania łańcucha KDF."
            )
            else -> linkedMapOf(
                "isDirectPqcCiphertextInPayload" to false,
                "pqcAlgorithm" to "ML-KEM-512",
                "description" to "Wiadomość odszyfrowana symetrycznie kluczem AES wyprowadzonym z post-kwantowego łańcucha KDF (Ratchet)."
            )
        }

        val typeLabel = when (frameMsg.msgType) {
            BinaryFrameCodec.TYPE_TEXT_MESSAGE -> "TEKST"
            BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE -> "HANDSHAKE FINALIZE"
            BinaryFrameCodec.TYPE_REKEY_OFFER -> "REKEY OFFER"
            BinaryFrameCodec.TYPE_REKEY_RESPONSE -> "REKEY RESPONSE"
            BinaryFrameCodec.TYPE_CHUNK_DATA -> "CHUNK"
            else -> "TYP 0x%02X".format(frameMsg.msgType)
        }

        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_RECEIVED_FROM_DHT_SERVER",
            "direction" to "INCOMING",
            "context" to "Odebrano wiadomość z serwera DHT ($typeLabel)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(System.currentTimeMillis()),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq,
                "senderEd25519PublicKeyHex" to (senderEdPublicKey?.let { CryptoUtils.toHex(it) } ?: "nieznany"),
                "ed25519SignatureHex" to (senderSignature?.let { toHexPreview(it, 32) } ?: "nieznany"),
                "signatureVerified" to (senderSignature != null)
            ),
            "beforeDecryption_EncryptedStructure" to linkedMapOf(
                "totalFrameSize" to "${frame900.size} bajtów (surowe dane pobrane z DHT)",
                "layer1_Symmetric_AES_GCM" to linkedMapOf(
                    "algorithm" to "AES-256-GCM (NIST SP 800-38D)",
                    "derivedKeyPreview" to (slotMsgKey?.let { toHexPreview(it, 16) } ?: "klucz sesyjny slotu"),
                    "iv" to linkedMapOf(
                        "offset" to "Bajty 0..11 (12 bajtów)",
                        "role" to "Initialization Vector (IV)",
                        "hex" to CryptoUtils.toHex(iv)
                    ),
                    "authenticationTag" to linkedMapOf(
                        "offset" to "Bajty 12..27 (16 bajtów)",
                        "role" to "Tag Uwierzytelniający GMAC",
                        "hex" to CryptoUtils.toHex(tag)
                    ),
                    "ciphertext" to linkedMapOf(
                        "offset" to "Bajty 28..899 (872 bajty)",
                        "role" to "Zaszyfrowana treść AES-256-GCM (przed odszyfrowaniem)",
                        "sizeBytes" to ciphertext.size,
                        "hexPreview" to toHexPreview(ciphertext, 32)
                    )
                )
            ),
            "afterDecryption_Plaintext" to linkedMapOf(
                "decryptionStatus" to "SUCCESS (Tag integralności AES-GCM zweryfikowany pomyślnie)",
                "header" to linkedMapOf(
                    "messageType" to "0x%02X".format(frameMsg.msgType),
                    "seqNum" to frameMsg.seqNum,
                    "ackNum" to frameMsg.ackNum,
                    "timestampUTC" to frameMsg.timestampUTC,
                    "timestampIso" to formatIsoTimestamp(frameMsg.timestampUTC)
                ),
                "payload" to payloadMap,
                "postQuantumAnalysis" to pqcAnalysis
            )
        )

        emitLog("ODEBRANO WIADOMOŚĆ Z SERWERA DHT [$typeLabel]", jsonMap)
    }

    fun logIncomingAliceHandshakeFinalize(
        target: ByteArray,
        seq: Long,
        senderEdPublicKey: ByteArray?,
        senderSignature: ByteArray?,
        frame900: ByteArray,
        seedInit: ByteArray,
        decapsulationSuccess: Boolean
    ) {
        if (!isEnabled) return

        val (iv, tag, ciphertext) = extractAesComponents(frame900)

        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_RECEIVED_FROM_DHT_SERVER",
            "direction" to "INCOMING",
            "context" to "Alice otrzymuje Handshake Finalize (od Boba przez Target_0)",
            "timestampIso" to formatIsoTimestamp(System.currentTimeMillis()),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq,
                "senderEd25519PublicKeyHex" to (senderEdPublicKey?.let { CryptoUtils.toHex(it) } ?: "nieznany"),
                "senderSignatureHex" to (senderSignature?.let { toHexPreview(it, 32) } ?: "nieznany"),
                "seedInitHex" to CryptoUtils.toHex(seedInit)
            ),
            "beforeDecryption_EncryptedStructure" to linkedMapOf(
                "totalFrameSize" to "${frame900.size} bajtów (surowe dane pobrane z Target_0)",
                "layer1_Symmetric_AES_GCM" to linkedMapOf(
                    "algorithm" to "AES-256-GCM (NIST SP 800-38D)",
                    "symmetricKeyRole" to "kHs (klucz wyprowadzony z seedInit)",
                    "iv" to linkedMapOf(
                        "offset" to "Bajty 0..11 (12 bajtów)",
                        "hex" to CryptoUtils.toHex(iv)
                    ),
                    "authenticationTag" to linkedMapOf(
                        "offset" to "Bajty 12..27 (16 bajtów)",
                        "hex" to CryptoUtils.toHex(tag)
                    ),
                    "ciphertext" to linkedMapOf(
                        "offset" to "Bajty 28..899 (872 bajty)",
                        "sizeBytes" to ciphertext.size,
                        "hexPreview" to toHexPreview(ciphertext, 32)
                    )
                )
            ),
            "afterDecryption_Plaintext" to linkedMapOf(
                "decryptionStatus" to "SUCCESS (Odszyfrowano ramkę kluczem kHs)",
                "header" to linkedMapOf(
                    "messageType" to "0x01 (TYPE_HANDSHAKE_FINALIZE)",
                    "seqNum" to 0,
                    "ackNum" to 0
                ),
                "payload" to linkedMapOf(
                    "type" to "HandshakeFinalize",
                    "pqcCiphertext_MLKEM512" to linkedMapOf(
                        "algorithm" to "ML-KEM-512 (Kyber-512)",
                        "sizeBytes" to BinaryFrameCodec.T1_CIPHERTEXT_SIZE,
                        "description" to "Zaszyfrowany post-kwantowo sekret SS_init wygenerowany przez Boba"
                    ),
                    "saltBytes" to BinaryFrameCodec.T1_SALT_SIZE
                ),
                "postQuantumAnalysis" to linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to true,
                    "pqcAlgorithm" to "ML-KEM-512 (Kyber-512 / FIPS 203)",
                    "decapsulationStatus" to if (decapsulationSuccess)
                        "SUKCES: Zdekapsulowano SS_init za pomocą klucza prywatnego sk_A Alice. Wygenerowano dwukierunkowe łańcuchy ratchetu!"
                    else "BŁĄD dekapsulacji"
                )
            )
        )

        emitLog("ODEBRANO I ZDEKAPSULOWANO POST-KWANTOWY HANDSHAKE (ALICE <- BOB)", jsonMap)
    }

    // ==========================================
    // STRUCTURAL HELPERS
    // ==========================================

    private fun extractAesComponents(frame900: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val iv = frame900.copyOfRange(0, BinaryFrameCodec.IV_SIZE)
        val tag = frame900.copyOfRange(BinaryFrameCodec.IV_SIZE, BinaryFrameCodec.IV_SIZE + BinaryFrameCodec.TAG_SIZE)
        val ciphertext = frame900.copyOfRange(
            BinaryFrameCodec.IV_SIZE + BinaryFrameCodec.TAG_SIZE,
            minOf(frame900.size, BinaryFrameCodec.IV_SIZE + BinaryFrameCodec.TAG_SIZE + BinaryFrameCodec.CIPHERTEXT_SIZE)
        )
        return Triple(iv, tag, ciphertext)
    }

    private fun extractHeaderMap(plaintext972: ByteArray): Map<String, Any?> {
        val buf = ByteBuffer.wrap(plaintext972).order(ByteOrder.BIG_ENDIAN)
        val msgType = buf.get()
        val seqNum = buf.short.toInt() and 0xFFFF
        val ackNum = buf.short.toInt() and 0xFFFF
        val timestampUTC = buf.long

        val typeName = when (msgType) {
            BinaryFrameCodec.TYPE_HANDSHAKE_FINALIZE -> "0x01 (TYPE_HANDSHAKE_FINALIZE)"
            BinaryFrameCodec.TYPE_TEXT_MESSAGE -> "0x02 (TYPE_TEXT_MESSAGE)"
            BinaryFrameCodec.TYPE_REKEY_OFFER -> "0x03 (TYPE_REKEY_OFFER)"
            BinaryFrameCodec.TYPE_REKEY_RESPONSE -> "0x04 (TYPE_REKEY_RESPONSE)"
            BinaryFrameCodec.TYPE_CHUNK_DATA -> "0x05 (TYPE_CHUNK_DATA)"
            else -> "0x%02X".format(msgType)
        }

        return linkedMapOf(
            "messageType" to typeName,
            "seqNum" to seqNum,
            "ackNum" to ackNum,
            "timestampUTC" to timestampUTC,
            "timestampIso" to formatIsoTimestamp(timestampUTC)
        )
    }

    private fun buildEncryptedStructureMap(
        frame900: ByteArray,
        slotMsgKey: ByteArray?,
        pqcLayerInfo: Map<String, Any?>,
        dhtTarget: ByteArray,
        dhtSeq: Long,
        edPublicKey: ByteArray?
    ): Map<String, Any?> {
        val (iv, tag, ciphertext) = extractAesComponents(frame900)

        return linkedMapOf(
            "totalFrameSize" to "${frame900.size} bajtów (standard ramki BEP 44)",
            "layer1_Symmetric_AES_GCM" to linkedMapOf(
                "algorithm" to "AES-256-GCM (NIST SP 800-38D)",
                "derivedKeyPreview" to (slotMsgKey?.let { toHexPreview(it, 16) } ?: "klucz sesyjny slotu"),
                "iv" to linkedMapOf(
                    "offset" to "Bajty 0..11 (12 bajtów)",
                    "role" to "Initialization Vector (IV / Nonce)",
                    "hex" to CryptoUtils.toHex(iv),
                    "description" to "Losowy wektor inicjalizujący zapewniający unikalność szyfrogramu"
                ),
                "authenticationTag" to linkedMapOf(
                    "offset" to "Bajty 12..27 (16 bajtów)",
                    "role" to "GMAC Authentication Tag (MAC)",
                    "hex" to CryptoUtils.toHex(tag),
                    "description" to "Kryptograficzny tag integralności i autentyczności wiadomości"
                ),
                "ciphertext" to linkedMapOf(
                    "offset" to "Bajty 28..899 (872 bajty)",
                    "role" to "AES-256-GCM Ciphertext",
                    "sizeBytes" to ciphertext.size,
                    "hexPreview" to toHexPreview(ciphertext, 32),
                    "description" to "Zaszyfrowana treść obejmująca nagłówek ramki i ładunek"
                )
            ),
            "layer2_PostQuantum_PQC" to pqcLayerInfo,
            "layer3_DhtRouting_BEP44" to linkedMapOf(
                "protocol" to "BitTorrent Mainline DHT (BEP 44 Mutable Item)",
                "targetHex" to CryptoUtils.toHex(dhtTarget),
                "bep44Seq" to dhtSeq,
                "ed25519PublicKeyHex" to (edPublicKey?.let { CryptoUtils.toHex(it) } ?: "generowany z seeda")
            )
        )
    }

    private fun toHexPreview(bytes: ByteArray, maxBytes: Int = 32): String {
        return if (bytes.size <= maxBytes) {
            CryptoUtils.toHex(bytes)
        } else {
            val preview = CryptoUtils.toHex(bytes.copyOfRange(0, maxBytes))
            "$preview... [łącznie ${bytes.size} bajtów]"
        }
    }

    private fun formatIsoTimestamp(millis: Long): String {
        val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        sdf.timeZone = TimeZone.getTimeZone("UTC")
        return sdf.format(Date(millis))
    }

    // ==========================================
    // JSON FORMATTER & CONSOLE EMITTER
    // ==========================================

    private fun emitLog(title: String, jsonMap: Map<String, Any?>) {
        if (!BuildConfig.DEBUG || !isEnabled) return
        emitCount.incrementAndGet()
        val jsonString = toJsonString(jsonMap, indentLevel = 0)
        val banner = buildString {
            appendLine("╔══════════════════════════════════════════════════════════════════════════════")
            appendLine("║ [PQChat-DEBUG] $title")
            appendLine("╚══════════════════════════════════════════════════════════════════════════════")
            append(jsonString)
        }

        // 1. Output to standard console / terminal (stdout)
        println(banner)

        // 2. Output to Android Logcat (split into safe chunk sizes to avoid Logcat's 4KB truncation)
        try {
            val lines = banner.split("\n")
            val chunk = java.lang.StringBuilder()
            for (line in lines) {
                if (chunk.length + line.length + 1 > 3500) {
                    android.util.Log.i("PQChat-Debug", chunk.toString())
                    chunk.setLength(0)
                }
                chunk.append(line).append("\n")
            }
            if (chunk.isNotEmpty()) {
                android.util.Log.i("PQChat-Debug", chunk.toString().trimEnd())
            }
        } catch (_: Throwable) {
            // JVM test fallback: android.util.Log not mocked
        }
    }

    fun toJsonString(value: Any?, indentLevel: Int = 0): String {
        return when (value) {
            null -> "null"
            is Boolean -> value.toString()
            is Number -> value.toString()
            is String -> escapeJsonString(value)
            is Map<*, *> -> {
                if (value.isEmpty()) return "{}"
                val indent = "  ".repeat(indentLevel)
                val childIndent = "  ".repeat(indentLevel + 1)
                val entries = value.entries.map { (k, v) ->
                    "$childIndent\"$k\": ${toJsonString(v, indentLevel + 1)}"
                }
                "{\n" + entries.joinToString(",\n") + "\n$indent}"
            }
            is Collection<*> -> {
                if (value.isEmpty()) return "[]"
                val indent = "  ".repeat(indentLevel)
                val childIndent = "  ".repeat(indentLevel + 1)
                val items = value.map { v ->
                    "$childIndent${toJsonString(v, indentLevel + 1)}"
                }
                "[\n" + items.joinToString(",\n") + "\n$indent]"
            }
            is Array<*> -> {
                toJsonString(value.toList(), indentLevel)
            }
            else -> escapeJsonString(value.toString())
        }
    }

    private fun escapeJsonString(s: String): String {
        val sb = StringBuilder("\"")
        for (ch in s) {
            when (ch) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    if (ch.code < 32) {
                        sb.append(String.format("\\u%04x", ch.code))
                    } else {
                        sb.append(ch)
                    }
                }
            }
        }
        sb.append("\"")
        return sb.toString()
    }
}
