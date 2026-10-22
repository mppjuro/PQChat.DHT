package org.pqchat.dht.research

/**
 * Enumeration of distinct cryptographic packet roles in PQChat DHT traffic.
 *
 * Distinguishes between:
 * - First-time outbound user transmissions
 * - Unacknowledged message republishing (exponential backoff)
 * - Cooperative crowdsourced relaying of third-party encrypted records (P2P relay)
 * - Incoming message reception and ACK processing
 * - Traffic masking primitives (Cover ACK, CSPRNG Noise Dummy, Tombstone)
 * - Periodic empirical TTL retention probes
 */
enum class PacketRole(val displayName: String) {
    /**
     * Initial outbound packet sent by user (original text, handshake, or media chunk).
     */
    FIRST_SEND("First send (original)"),

    /**
     * Periodic retransmission of own unacknowledged message (RepublishWorker / PollingWorker).
     */
    OWN_REPUBLISH("Republish own message"),

    /**
     * Cooperative relay of third-party BEP 44 record from BlindRepublishPool (crowdsourced relay).
     */
    CROWD_REPUBLISH("Republish other user message"),

    /**
     * Incoming packet received from DHT (incoming chat, handshake finalize, or ACK).
     */
    PACKET_RECEIVED("Packet received from DHT"),

    /**
     * Secure 900-byte noise tombstone overwriting consumed message slot on DHT.
     */
    TOMBSTONE_SENT("Send Tombstone record (900B)"),

    /**
     * Cover traffic ACK token routed to partner's ACK rendezvous target.
     */
    COVER_ACK_SENT("Cover ACK sent"),

    /**
     * Cover traffic ACK token received from partner's ACK rendezvous target.
     */
    COVER_ACK_RECEIVED("Cover ACK received"),

    /**
     * Pure synthetic CSPRNG noise packet emitted by Poisson traffic generator.
     */
    COVER_DUMMY_SENT("Synthetic decoy packet (Dummy)"),

    /**
     * Empirical DHT retention probe checking if a historical record is still alive on DHT.
     */
    TTL_PROBE("DHT retention sample (TTL)"),

    /**
     * Decoy target query emitted to disguise real contact rendezvous.
     */
    DECOY_GET("Query decoy target (Decoy GET)"),

    /**
     * Group broadcast packet transmission to a single group participant slot (fan-out).
     */
    GROUP_FAN_OUT("Group broadcast (Group Fan-out)"),

    /**
     * Real scheduled contact polling query in an adaptive batch.
     */
    POLL_BATCH_REAL("Contact query in batch (Poll Batch Real)"),

    /**
     * Decoy query executed within an adaptive polling batch to mask contact count.
     */
    POLL_BATCH_DECOY("Decoy target query in batch (Poll Batch Decoy)")
}
