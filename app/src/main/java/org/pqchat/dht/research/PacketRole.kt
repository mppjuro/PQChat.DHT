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
    FIRST_SEND("Pierwsze wysłanie (oryginał)"),

    /**
     * Periodic retransmission of own unacknowledged message (RepublishWorker / PollingWorker).
     */
    OWN_REPUBLISH("Republish własnej wiadomości"),

    /**
     * Cooperative relay of third-party BEP 44 record from BlindRepublishPool (crowdsourced relay).
     */
    CROWD_REPUBLISH("Republish wiadomości innego użytkownika"),

    /**
     * Incoming packet received from DHT (incoming chat, handshake finalize, or ACK).
     */
    PACKET_RECEIVED("Odebranie pakietu z DHT"),

    /**
     * Secure 900-byte noise tombstone overwriting consumed message slot on DHT.
     */
    TOMBSTONE_SENT("Wysłanie rekordu Tombstone (900B)"),

    /**
     * Cover traffic ACK token routed to partner's ACK rendezvous target.
     */
    COVER_ACK_SENT("Potwierdzenie w szumie (Cover ACK)"),

    /**
     * Cover traffic ACK token received from partner's ACK rendezvous target.
     */
    COVER_ACK_RECEIVED("Odebranie potwierdzenia w szumie (Cover ACK)"),

    /**
     * Pure synthetic CSPRNG noise packet emitted by Poisson traffic generator.
     */
    COVER_DUMMY_SENT("Syntetyczny pakiet maskujący (Dummy)"),

    /**
     * Empirical DHT retention probe checking if a historical record is still alive on DHT.
     */
    TTL_PROBE("Próbka retencji DHT (TTL)"),

    /**
     * Decoy target query emitted to disguise real contact rendezvous.
     */
    DECOY_GET("Odpytanie celu maskującego (Decoy GET)"),

    /**
     * Group broadcast packet transmission to a single group participant slot (fan-out).
     */
    GROUP_FAN_OUT("Wysłanie do grupy (Group Fan-out)"),

    /**
     * Real scheduled contact polling query in an adaptive batch.
     */
    POLL_BATCH_REAL("Odpytanie kontaktu w partii (Poll Batch Real)"),

    /**
     * Decoy query executed within an adaptive polling batch to mask contact count.
     */
    POLL_BATCH_DECOY("Odpytanie celu maskującego w partii (Poll Batch Decoy)")
}
