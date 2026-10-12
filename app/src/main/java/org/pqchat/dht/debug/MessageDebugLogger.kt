package org.pqchat.dht.debug

import org.pqchat.dht.BuildConfig
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.protocol.RatchetChain
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicInteger

/**
 * Diagnostic & Cryptographic Metadata Logger for PQChat DHT.
 *
 * Formats outgoing and incoming message metadata into structured, readable JSON logs.
 * Strictly complies with AGENTS.md §8.1:
 * - NO plaintext messages or decrypted payloads.
 * - NO private key seeds (edPrivateKeySeed), initial seeds (seedInit), or symmetric keys (msgKey).
 * - ONLY protocol metadata, frame sizes, offsets, sequence counters, and public routing identifiers.
 *
 * Prints to stdout (console) and logs to Android Logcat under tag "PQChat-Debug".
 * STRICTLY DISABLED in release builds or when isEnabled is false.
 */
object MessageDebugLogger {

    var isEnabled: Boolean = BuildConfig.DEBUG
    val emitCount = AtomicInteger(0)

    // ==========================================
    // OUTGOING MESSAGES (SENT TO SERVER / DHT)
    // ==========================================

    fun logOutgoingTextMessage(
        contactId: String,
        textLength: Int,
        slot: RatchetChain.SlotParameters,
        seqNum: Int,
        ackNum: Int,
        frame: ByteArray
    ) {
        if (!isEnabled) return

        val paddingCount = BinaryFrameCodec.INNER_PAYLOAD_SIZE - 2 - textLength
        val now = System.currentTimeMillis()

        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Wiadomość tekstowa wysyłana do kontaktu",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(slot.target),
                "bep44Seq" to DhtClient.DEFAULT_MUTABLE_SEQ,
                "ed25519PublicKeyHex" to CryptoUtils.toHex(slot.edPublicKey)
            ),
            "beforeEncryption_Metadata" to linkedMapOf(
                "totalPlaintextSize" to "${BinaryFrameCodec.CIPHERTEXT_SIZE} bajtów (rozmiar stały)",
                "header" to linkedMapOf(
                    "messageType" to "0x02 (TYPE_TEXT_MESSAGE)",
                    "seqNum" to seqNum,
                    "ackNum" to ackNum,
                    "timestampUTC" to now,
                    "timestampIso" to formatIsoTimestamp(now)
                ),
                "payload" to linkedMapOf(
                    "type" to "TextMessage (0x02)",
                    "textByteLength" to textLength,
                    "paddingBytesCount" to maxOf(0, paddingCount),
                    "description" to "Ładunek tekstowy chroniony szyfrowaniem AES-256-GCM (treść jawna pominięta zgodnie z AGENTS.md §8.1)"
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame = frame,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to false,
                    "pqcAlgorithm" to "ML-KEM-512 (Kyber-512 / FIPS 203)",
                    "relation" to "Wyprowadzanie klucza ratchetu z KDF zainicjalizowanego wymianą post-kwantową",
                    "description" to "Wiadomość chroniona symetrycznie AES-256-GCM kluczem slotu ${slot.counter} z łańcucha KDF (Ratchet)."
                ),
                dhtTarget = slot.target,
                dhtSeq = DhtClient.DEFAULT_MUTABLE_SEQ,
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
        mlKemPublicKeySize: Int,
        frame: ByteArray
    ) {
        if (!isEnabled) return

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Oferta rotacji kluczy PQC (Rekey Offer)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(slot.target),
                "bep44Seq" to DhtClient.DEFAULT_MUTABLE_SEQ,
                "ed25519PublicKeyHex" to CryptoUtils.toHex(slot.edPublicKey)
            ),
            "beforeEncryption_Metadata" to linkedMapOf(
                "totalPlaintextSize" to "${BinaryFrameCodec.CIPHERTEXT_SIZE} bajtów",
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
                        "algorithm" to "ML-KEM-512 (Kyber-512 / FIPS 203)",
                        "role" to "Nowy klucz publiczny PQC (pk_new)",
                        "sizeBytes" to mlKemPublicKeySize,
                        "description" to "Klucz publiczny post-kwantowy do okresowej rotacji łańcucha KDF"
                    ),
                    "paddingBytesCount" to BinaryFrameCodec.T3_PADDING_SIZE
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame = frame,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to false,
                    "isPqcPublicKeyInPayload" to true,
                    "pqcAlgorithm" to "ML-KEM-512",
                    "description" to "Ładunek przenosi nowy klucz publiczny ML-KEM-512 opakowany w szyfrowanie symetryczne AES-256-GCM."
                ),
                dhtTarget = slot.target,
                dhtSeq = DhtClient.DEFAULT_MUTABLE_SEQ,
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
        frame: ByteArray
    ) {
        if (!isEnabled) return

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Odpowiedź na rotację kluczy PQC (Rekey Response)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(slot.target),
                "bep44Seq" to DhtClient.DEFAULT_MUTABLE_SEQ,
                "ed25519PublicKeyHex" to CryptoUtils.toHex(slot.edPublicKey)
            ),
            "beforeEncryption_Metadata" to linkedMapOf(
                "totalPlaintextSize" to "${BinaryFrameCodec.CIPHERTEXT_SIZE} bajtów",
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
                        "algorithm" to "ML-KEM-512 (Kyber-512 / FIPS 203)",
                        "role" to "Zaszyfrowany post-kwantowo nowy sekret rotacji (ct_new)",
                        "sizeBytes" to BinaryFrameCodec.T4_CIPHERTEXT_SIZE,
                        "description" to "Kapsuła klucza wygenerowana przez ML-KEM-512 w odpowiedzi na Rekey Offer"
                    ),
                    "paddingBytesCount" to BinaryFrameCodec.T4_PADDING_SIZE
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame = frame,
                pqcLayerInfo = linkedMapOf(
                    "isDirectPqcCiphertextInPayload" to true,
                    "pqcAlgorithm" to "ML-KEM-512",
                    "pqcCiphertextSize" to BinaryFrameCodec.T4_CIPHERTEXT_SIZE,
                    "description" to "BEZPOŚREDNIE SZYFROWANIE POST-KWANTOWE: Kapsuła ML-KEM-512 (768 B) wewnątrz ramki AES-256-GCM."
                ),
                dhtTarget = slot.target,
                dhtSeq = DhtClient.DEFAULT_MUTABLE_SEQ,
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
        dataSize: Int,
        target: ByteArray,
        seq: Long,
        frame: ByteArray
    ) {
        if (!isEnabled) return

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Fragment danych binarnych (plik / obraz PNG)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq
            ),
            "beforeEncryption_Metadata" to linkedMapOf(
                "totalPlaintextSize" to "${BinaryFrameCodec.CIPHERTEXT_SIZE} bajtów",
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
                    "chunkPayloadBytes" to dataSize,
                    "description" to "Fragment wieloczęściowego transferu binarnego"
                )
            ),
            "afterEncryption_Structure" to buildEncryptedStructureMap(
                frame = frame,
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
        frame: ByteArray
    ) {
        if (!isEnabled) return

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_SENT_TO_DHT_SERVER",
            "direction" to "OUTGOING",
            "context" to "Bob -> Alice Handshake Finalize (Inicjalizacja tunelu post-kwantowego)",
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq
            ),
            "beforeEncryption_Metadata" to linkedMapOf(
                "totalPlaintextSize" to "${BinaryFrameCodec.CIPHERTEXT_SIZE} bajtów",
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
                frame = frame,
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
        frame: ByteArray,
        frameMsg: BinaryFrameCodec.FrameMessage
    ) {
        if (!isEnabled) return

        val payloadMap = when (val p = frameMsg.payload) {
            is BinaryFrameCodec.DecodedPayload.TextMessage -> linkedMapOf<String, Any?>(
                "type" to "TextMessage (0x02)",
                "textByteLength" to p.text.toByteArray(Charsets.UTF_8).size,
                "description" to "Zdekodowany ładunek wiadomości (tekst jawny pominięty per AGENTS.md §8.1)"
            )
            is BinaryFrameCodec.DecodedPayload.HandshakeFinalize -> linkedMapOf<String, Any?>(
                "type" to "HandshakeFinalize (0x01)",
                "pqcCiphertext_MLKEM512" to linkedMapOf(
                    "algorithm" to "ML-KEM-512",
                    "sizeBytes" to p.mlKemCiphertext.size,
                    "description" to "Zaszyfrowany post-kwantowo wspólny sekret SS_init"
                ),
                "saltBytesCount" to p.saltParameter.size
            )
            is BinaryFrameCodec.DecodedPayload.RekeyOffer -> linkedMapOf<String, Any?>(
                "type" to "RekeyOffer (0x03)",
                "rekeyEpoch" to p.rekeyEpoch,
                "pqcPublicKey_MLKEM512" to linkedMapOf(
                    "algorithm" to "ML-KEM-512",
                    "sizeBytes" to p.mlKemPublicKey.size,
                    "description" to "Nowy klucz publiczny nadawcy do rotacji KDF"
                )
            )
            is BinaryFrameCodec.DecodedPayload.RekeyResponse -> linkedMapOf<String, Any?>(
                "type" to "RekeyResponse (0x04)",
                "rekeyEpoch" to p.rekeyEpoch,
                "pqcCiphertext_MLKEM512" to linkedMapOf(
                    "algorithm" to "ML-KEM-512",
                    "sizeBytes" to p.mlKemCiphertext.size,
                    "description" to "Zaszyfrowany post-kwantowo nowy sekret rotacji SS_rekey"
                )
            )
            is BinaryFrameCodec.DecodedPayload.ChunkData -> linkedMapOf<String, Any?>(
                "type" to "ChunkData (0x05)",
                "transferIdHex" to CryptoUtils.toHex(p.transferId),
                "chunkIndex" to p.chunkIndex,
                "totalChunks" to p.totalChunks,
                "dataSizeBytes" to p.data.size
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

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_RECEIVED_FROM_DHT_SERVER",
            "direction" to "INCOMING",
            "context" to "Odebrano wiadomość z serwera DHT ($typeLabel)",
            "contactId" to contactId,
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq,
                "senderEd25519PublicKeyHex" to (senderEdPublicKey?.let { CryptoUtils.toHex(it) } ?: "nieznany"),
                "hasSignature" to (senderSignature != null)
            ),
            "beforeDecryption_EncryptedStructure" to linkedMapOf(
                "totalFrameSize" to "${frame.size} bajtów (surowe dane pobrane z DHT)",
                "layer1_Symmetric_AES_GCM" to linkedMapOf(
                    "algorithm" to "AES-256-GCM (NIST SP 800-38D)",
                    "symmetricKeyRole" to "AES-256-GCM key derived from Ratchet KDF",
                    "iv" to linkedMapOf(
                        "offset" to "Bajty 0..11 (12 bajtów)",
                        "role" to "Initialization Vector (IV)",
                        "sizeBytes" to BinaryFrameCodec.IV_SIZE
                    ),
                    "authenticationTag" to linkedMapOf(
                        "offset" to "Bajty 12..27 (16 bajtów)",
                        "role" to "Tag Uwierzytelniający GMAC",
                        "sizeBytes" to BinaryFrameCodec.TAG_SIZE
                    ),
                    "ciphertext" to linkedMapOf(
                        "offset" to "Bajty 28..899 (872 bajty)",
                        "role" to "Zaszyfrowana treść AES-256-GCM",
                        "sizeBytes" to BinaryFrameCodec.CIPHERTEXT_SIZE
                    )
                )
            ),
            "afterDecryption_Metadata" to linkedMapOf(
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
        frame: ByteArray,
        decapsulationSuccess: Boolean
    ) {
        if (!isEnabled) return

        val now = System.currentTimeMillis()
        val jsonMap = linkedMapOf<String, Any?>(
            "event" to "MESSAGE_RECEIVED_FROM_DHT_SERVER",
            "direction" to "INCOMING",
            "context" to "Alice otrzymuje Handshake Finalize (od Boba przez Target_0)",
            "timestampIso" to formatIsoTimestamp(now),
            "dhtServerNetwork" to linkedMapOf(
                "targetHex" to CryptoUtils.toHex(target),
                "bep44Seq" to seq,
                "senderEd25519PublicKeyHex" to (senderEdPublicKey?.let { CryptoUtils.toHex(it) } ?: "nieznany"),
                "hasSignature" to (senderSignature != null)
            ),
            "beforeDecryption_EncryptedStructure" to linkedMapOf(
                "totalFrameSize" to "${frame.size} bajtów (surowe dane pobrane z Target_0)",
                "layer1_Symmetric_AES_GCM" to linkedMapOf(
                    "algorithm" to "AES-256-GCM (NIST SP 800-38D)",
                    "symmetricKeyRole" to "kHs (klucz wyprowadzony z seedInit)",
                    "ivSizeBytes" to BinaryFrameCodec.IV_SIZE,
                    "authenticationTagSizeBytes" to BinaryFrameCodec.TAG_SIZE,
                    "ciphertextSizeBytes" to BinaryFrameCodec.CIPHERTEXT_SIZE
                )
            ),
            "afterDecryption_Metadata" to linkedMapOf(
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
                    "saltBytesCount" to BinaryFrameCodec.T1_SALT_SIZE
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

    private fun buildEncryptedStructureMap(
        frame: ByteArray,
        pqcLayerInfo: Map<String, Any?>,
        dhtTarget: ByteArray,
        dhtSeq: Long,
        edPublicKey: ByteArray?
    ): Map<String, Any?> {
        return linkedMapOf(
            "totalFrameSize" to "${frame.size} bajtów (standard ramki BEP 44)",
            "layer1_Symmetric_AES_GCM" to linkedMapOf(
                "algorithm" to "AES-256-GCM (NIST SP 800-38D)",
                "symmetricKeyRole" to "AES-256-GCM session key derived from Ratchet KDF",
                "keySizeBytes" to 32,
                "iv" to linkedMapOf(
                    "offset" to "Bajty 0..11 (12 bajtów)",
                    "role" to "Initialization Vector (IV / Nonce)",
                    "sizeBytes" to BinaryFrameCodec.IV_SIZE,
                    "description" to "Losowy wektor inicjalizujący zapewniający unikalność szyfrogramu"
                ),
                "authenticationTag" to linkedMapOf(
                    "offset" to "Bajty 12..27 (16 bajtów)",
                    "role" to "GMAC Authentication Tag (MAC)",
                    "sizeBytes" to BinaryFrameCodec.TAG_SIZE,
                    "description" to "Kryptograficzny tag integralności i autentyczności wiadomości"
                ),
                "ciphertext" to linkedMapOf(
                    "offset" to "Bajty 28..899 (872 bajty)",
                    "role" to "AES-256-GCM Ciphertext",
                    "sizeBytes" to BinaryFrameCodec.CIPHERTEXT_SIZE,
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
