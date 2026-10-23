package org.pqchat.dht.ui.viewmodel

/**
 * Granular state of Bob's handshake process (QR scan -> DHT publication).
 */
enum class BobHandshakeStatus {
    IDLE,                    // No active process
    SCANNING_QR,             // Awaiting scan / validating payload (864 B)
    ENCAPSULATING,           // HybridKemEngine.encapsulate in progress
    SENDING_DHT,             // putMutable in flight (skipLocalStore = true)
    PUT_FAILED_RETRYING,     // Initial PUT returned false - republish loop started
    DHT_SENT_UNVERIFIED,     // PUT returned true, GET verification pending
    VERIFYING_DHT,           // getMutable(skipLocalStore = true) in flight
    PLACED_IN_DHT,           // getMutable confirmed presence in network - success
    AWAITING_ALICE,          // Record in network, waiting for Alice (polling) to read it
    TIMEOUT,                 // Timeout exceeded (e.g. 10 min without success)
    FAILED                   // Terminal failure (e.g. cryptographic exception)
}
