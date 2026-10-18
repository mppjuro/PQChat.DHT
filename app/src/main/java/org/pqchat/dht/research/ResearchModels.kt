package org.pqchat.dht.research

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

/**
 * Data structures for academic research telemetry on PQC BitTorrent Mainline DHT messaging.
 * Guaranteed privacy: strictly ZERO plaintext, ZERO seeds, ZERO private keys.
 * Target hashes are truncated to 8-character hex prefixes for correlation without address disclosure.
 */

private val isoFormatter: ThreadLocal<SimpleDateFormat> = ThreadLocal.withInitial {
    SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }
}

fun formatEpochIso(epochMs: Long): String = isoFormatter.get()?.format(Date(epochMs)) ?: ""

/**
 * Telemetry record for an individual packet send, receive, republish or dummy event.
 */
data class PacketTelemetryEvent(
    val eventId: String = UUID.randomUUID().toString(),
    val sessionId: String,
    val timestampEpochMs: Long = System.currentTimeMillis(),
    val isoTimestamp: String = formatEpochIso(timestampEpochMs),
    val role: PacketRole,
    val targetPrefix: String, // 8 hex chars
    val seqNum: Long = 1L,
    val payloadBytes: Int = 900,
    val rttMs: Long = 0L,
    val nodesQueried: Int = 0,
    val nodesResponded: Int = 0,
    val success: Boolean = true,
    val republishAttempt: Int = 0,
    val messageAgeMs: Long = 0L,
    val networkType: String = "UNKNOWN",
    val errorCode: String? = null
) {
    fun toMap(): Map<String, Any?> = mapOf(
        "eventId" to eventId,
        "sessionId" to sessionId,
        "timestampEpochMs" to timestampEpochMs,
        "isoTimestamp" to isoTimestamp,
        "role" to role.name,
        "roleDisplayName" to role.displayName,
        "targetPrefix" to targetPrefix,
        "seqNum" to seqNum,
        "payloadBytes" to payloadBytes,
        "rttMs" to rttMs,
        "nodesQueried" to nodesQueried,
        "nodesResponded" to nodesResponded,
        "success" to success,
        "republishAttempt" to republishAttempt,
        "messageAgeMs" to messageAgeMs,
        "networkType" to networkType,
        "errorCode" to errorCode
    )

    fun toCsvRow(): String {
        val safeError = (errorCode ?: "").replace("\"", "\"\"")
        return "$eventId,$sessionId,$timestampEpochMs,$isoTimestamp,${role.name},\"${role.displayName}\",$targetPrefix,$seqNum,$payloadBytes,$rttMs,$nodesQueried,$nodesResponded,$success,$republishAttempt,$messageAgeMs,$networkType,\"$safeError\""
    }

    fun toMasterCsvRow(): String {
        val safeError = (errorCode ?: "").replace("\"", "\"\"")
        return "$eventId,$sessionId,$timestampEpochMs,$isoTimestamp,PACKET_EVENT,${role.name},$targetPrefix,$seqNum,$payloadBytes,$rttMs,$nodesQueried,$nodesResponded,$success,$republishAttempt,$messageAgeMs,\"\",$success,\"\",\"\",\"$safeError\""
    }

    companion object {
        const val CSV_HEADER =
            "event_id,session_id,timestamp_epoch_ms,iso_timestamp,role,role_display_name,target_prefix,seq_num,payload_bytes,rtt_ms,nodes_queried,nodes_responded,success,republish_attempt,message_age_ms,network_type,error_code"
    }
}

/**
 * Telemetry record for an empirical DHT retention (TTL) probe checking packet survival.
 */
data class TtlSampleEvent(
    val sampleId: String = UUID.randomUUID().toString(),
    val sessionId: String,
    val timestampEpochMs: Long = System.currentTimeMillis(),
    val isoTimestamp: String = formatEpochIso(timestampEpochMs),
    val targetPrefix: String, // 8 hex chars
    val initialPutEpochMs: Long,
    val elapsedMinutes: Double,
    val elapsedHours: Double,
    val republishActive: Boolean,
    val isAlive: Boolean,
    val nodesResponded: Int,
    val probeRttMs: Long,
    val confirmedLifespanMinutes: Double? = null
) {
    fun toMap(): Map<String, Any?> = mapOf(
        "sampleId" to sampleId,
        "sessionId" to sessionId,
        "timestampEpochMs" to timestampEpochMs,
        "isoTimestamp" to isoTimestamp,
        "targetPrefix" to targetPrefix,
        "initialPutEpochMs" to initialPutEpochMs,
        "elapsedMinutes" to elapsedMinutes,
        "elapsedHours" to elapsedHours,
        "republishActive" to republishActive,
        "isAlive" to isAlive,
        "nodesResponded" to nodesResponded,
        "probeRttMs" to probeRttMs,
        "confirmedLifespanMinutes" to confirmedLifespanMinutes
    )

    fun toCsvRow(): String {
        val elapsedMinStr = String.format(Locale.US, "%.2f", elapsedMinutes)
        val elapsedHrStr = String.format(Locale.US, "%.4f", elapsedHours)
        val confirmedStr = confirmedLifespanMinutes?.let { String.format(Locale.US, "%.2f", it) } ?: ""
        return "$sampleId,$sessionId,$timestampEpochMs,$isoTimestamp,$targetPrefix,$initialPutEpochMs,$elapsedMinStr,$elapsedHrStr,$republishActive,$isAlive,$nodesResponded,$probeRttMs,$confirmedStr"
    }

    fun toMasterCsvRow(): String {
        val elapsedHrStr = String.format(Locale.US, "%.4f", elapsedHours)
        return "$sampleId,$sessionId,$timestampEpochMs,$isoTimestamp,TTL_PROBE,TTL_PROBE,$targetPrefix,1,900,$probeRttMs,8,$nodesResponded,$isAlive,0,0,$republishActive,$isAlive,$elapsedHrStr,\"\",\"\""
    }

    companion object {
        const val CSV_HEADER =
            "sample_id,session_id,timestamp_epoch_ms,iso_timestamp,target_prefix,initial_put_epoch_ms,elapsed_minutes,elapsed_hours,republish_active,is_alive,nodes_responded,probe_rtt_ms,confirmed_lifespan_minutes"
    }
}

/**
 * End-to-end lifecycle summary of an individual message and its republish iterations.
 */
data class RepublishAnalysisSummary(
    val messagePrefix: String, // 8 hex chars
    val sessionId: String,
    val initialSentEpochMs: Long,
    val deliveredEpochMs: Long = -1L,
    val isDelivered: Boolean = false,
    val totalRepublishes: Int = 0,
    val timeToFirstRepublishMs: Long = 0L,
    val endToEndDeliveryLatencyMs: Long = 0L,
    val crowdRelayed: Boolean = false,
    val finalStatus: String = "PENDING"
) {
    fun toMap(): Map<String, Any?> = mapOf(
        "messagePrefix" to messagePrefix,
        "sessionId" to sessionId,
        "initialSentEpochMs" to initialSentEpochMs,
        "deliveredEpochMs" to deliveredEpochMs,
        "isDelivered" to isDelivered,
        "totalRepublishes" to totalRepublishes,
        "timeToFirstRepublishMs" to timeToFirstRepublishMs,
        "endToEndDeliveryLatencyMs" to endToEndDeliveryLatencyMs,
        "crowdRelayed" to crowdRelayed,
        "finalStatus" to finalStatus
    )

    fun toCsvRow(): String {
        return "$messagePrefix,$sessionId,$initialSentEpochMs,$deliveredEpochMs,$isDelivered,$totalRepublishes,$timeToFirstRepublishMs,$endToEndDeliveryLatencyMs,$crowdRelayed,$finalStatus"
    }

    fun toMasterCsvRow(): String {
        val iso = formatEpochIso(initialSentEpochMs)
        return "summary_$messagePrefix,$sessionId,$initialSentEpochMs,$iso,REPUBLISH_SUMMARY,SUMMARY,$messagePrefix,1,900,0,0,0,$isDelivered,$totalRepublishes,0,$crowdRelayed,$isDelivered,\"\",$endToEndDeliveryLatencyMs,$finalStatus"
    }

    companion object {
        const val CSV_HEADER =
            "message_prefix,session_id,initial_sent_epoch_ms,delivered_epoch_ms,is_delivered,total_republishes,time_to_first_republish_ms,e2e_delivery_latency_ms,crowd_relayed,final_status"
    }
}

object ResearchCsvSchema {
    const val MASTER_CSV_HEADER =
        "record_id,session_id,timestamp_epoch_ms,iso_timestamp,record_type,packet_role,target_prefix,seq_num,payload_bytes,rtt_ms,nodes_queried,nodes_responded,success,republish_attempt,message_age_ms,republish_active,is_alive,elapsed_hours,e2e_latency_ms,error_or_status"
}
