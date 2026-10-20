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
    val lookupHops: Int = 0,
    val success: Boolean = true,
    val republishAttempt: Int = 0,
    val messageAgeMs: Long = 0L,
    val networkType: String = "UNKNOWN",
    val pollingState: String = "UNKNOWN",
    val replicationK: Int = 8,
    val poissonLambda: Double = 0.0,
    val batteryCurrentUa: Long = 0L,
    val batteryLevelPct: Int = 100,
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
        "lookupHops" to lookupHops,
        "success" to success,
        "republishAttempt" to republishAttempt,
        "messageAgeMs" to messageAgeMs,
        "networkType" to networkType,
        "pollingState" to pollingState,
        "replicationK" to replicationK,
        "poissonLambda" to poissonLambda,
        "batteryCurrentUa" to batteryCurrentUa,
        "batteryLevelPct" to batteryLevelPct,
        "errorCode" to errorCode
    )

    fun toCsvRow(): String {
        val safeError = (errorCode ?: "").replace("\"", "\"\"")
        val lambdaStr = String.format(Locale.US, "%.6f", poissonLambda)
        return "$eventId,$sessionId,$timestampEpochMs,$isoTimestamp,${role.name},\"${role.displayName}\",$targetPrefix,$seqNum,$payloadBytes,$rttMs,$nodesQueried,$nodesResponded,$lookupHops,$success,$republishAttempt,$messageAgeMs,$networkType,$pollingState,$replicationK,$lambdaStr,$batteryCurrentUa,$batteryLevelPct,\"$safeError\""
    }

    fun toMasterCsvRow(): String {
        val safeError = (errorCode ?: "").replace("\"", "\"\"")
        val lambdaStr = String.format(Locale.US, "%.6f", poissonLambda)
        return "$eventId,$sessionId,$timestampEpochMs,$isoTimestamp,PACKET_EVENT,${role.name},$targetPrefix,$seqNum,$payloadBytes,$rttMs,$nodesQueried,$nodesResponded,$lookupHops,$success,$republishAttempt,$messageAgeMs,$networkType,$pollingState,$replicationK,$lambdaStr,$batteryCurrentUa,$batteryLevelPct,\"\",$success,\"\",\"\",\"$safeError\""
    }

    companion object {
        const val CSV_HEADER =
            "event_id,session_id,timestamp_epoch_ms,iso_timestamp,role,role_display_name,target_prefix,seq_num,payload_bytes,rtt_ms,nodes_queried,nodes_responded,lookup_hops,success,republish_attempt,message_age_ms,network_type,polling_state,replication_k,poisson_lambda,battery_current_ua,battery_level_pct,error_code"
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
    val nodesQueried: Int = 0,
    val nodesResponded: Int = 0,
    val lookupHops: Int = 0,
    val probeRttMs: Long = 0L,
    val confirmedLifespanMinutes: Double? = null,
    val networkType: String = "UNKNOWN",
    val pollingState: String = "UNKNOWN",
    val replicationK: Int = 8,
    val poissonLambda: Double = 0.0,
    val batteryCurrentUa: Long = 0L,
    val batteryLevelPct: Int = 100
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
        "nodesQueried" to nodesQueried,
        "nodesResponded" to nodesResponded,
        "lookupHops" to lookupHops,
        "probeRttMs" to probeRttMs,
        "confirmedLifespanMinutes" to confirmedLifespanMinutes,
        "networkType" to networkType,
        "pollingState" to pollingState,
        "replicationK" to replicationK,
        "poissonLambda" to poissonLambda,
        "batteryCurrentUa" to batteryCurrentUa,
        "batteryLevelPct" to batteryLevelPct
    )

    fun toCsvRow(): String {
        val elapsedMinStr = String.format(Locale.US, "%.2f", elapsedMinutes)
        val elapsedHrStr = String.format(Locale.US, "%.4f", elapsedHours)
        val confirmedStr = confirmedLifespanMinutes?.let { String.format(Locale.US, "%.2f", it) } ?: ""
        val lambdaStr = String.format(Locale.US, "%.6f", poissonLambda)
        return "$sampleId,$sessionId,$timestampEpochMs,$isoTimestamp,$targetPrefix,$initialPutEpochMs,$elapsedMinStr,$elapsedHrStr,$republishActive,$isAlive,$nodesQueried,$nodesResponded,$lookupHops,$probeRttMs,$confirmedStr,$networkType,$pollingState,$replicationK,$lambdaStr,$batteryCurrentUa,$batteryLevelPct"
    }

    fun toMasterCsvRow(): String {
        val elapsedHrStr = String.format(Locale.US, "%.4f", elapsedHours)
        val lambdaStr = String.format(Locale.US, "%.6f", poissonLambda)
        return "$sampleId,$sessionId,$timestampEpochMs,$isoTimestamp,TTL_PROBE,TTL_PROBE,$targetPrefix,1,900,$probeRttMs,$nodesQueried,$nodesResponded,$lookupHops,$isAlive,0,0,$networkType,$pollingState,$replicationK,$lambdaStr,$batteryCurrentUa,$batteryLevelPct,$republishActive,$isAlive,$elapsedHrStr,\"\",\"\""
    }

    companion object {
        const val CSV_HEADER =
            "sample_id,session_id,timestamp_epoch_ms,iso_timestamp,target_prefix,initial_put_epoch_ms,elapsed_minutes,elapsed_hours,republish_active,is_alive,nodes_queried,nodes_responded,lookup_hops,probe_rtt_ms,confirmed_lifespan_minutes,network_type,polling_state,replication_k,poisson_lambda,battery_current_ua,battery_level_pct"
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
        return "summary_$messagePrefix,$sessionId,$initialSentEpochMs,$iso,REPUBLISH_SUMMARY,SUMMARY,$messagePrefix,1,900,0,0,0,0,$isDelivered,$totalRepublishes,0,\"\",\"\",8,0.0,0,100,$crowdRelayed,$isDelivered,\"\",$endToEndDeliveryLatencyMs,$finalStatus"
    }

    companion object {
        const val CSV_HEADER =
            "message_prefix,session_id,initial_sent_epoch_ms,delivered_epoch_ms,is_delivered,total_republishes,time_to_first_republish_ms,e2e_delivery_latency_ms,crowd_relayed,final_status"
    }
}

/**
 * Telemetry record for group chat operations (multi-recipient broadcast, delivery latency,
 * fan-out delivery skew, and key rotation convergence).
 */
data class GroupTelemetryEvent(
    val eventId: String = UUID.randomUUID().toString(),
    val sessionId: String,
    val timestampEpochMs: Long = System.currentTimeMillis(),
    val isoTimestamp: String = formatEpochIso(timestampEpochMs),
    val eventType: String, // "BROADCAST", "RECEIVE", "FAN_OUT_SKEW", "KEY_ROTATION"
    val groupIdPrefix: String, // 8 hex chars
    val groupSizeM: Int,
    val latencyMs: Long = 0L,
    val fanOutSkewMs: Long = 0L,
    val keyRotationConvergenceMs: Long = 0L,
    val epoch: Long = 1L
) {
    fun toMap(): Map<String, Any?> = mapOf(
        "eventId" to eventId,
        "sessionId" to sessionId,
        "timestampEpochMs" to timestampEpochMs,
        "isoTimestamp" to isoTimestamp,
        "eventType" to eventType,
        "groupIdPrefix" to groupIdPrefix,
        "groupSizeM" to groupSizeM,
        "latencyMs" to latencyMs,
        "fanOutSkewMs" to fanOutSkewMs,
        "keyRotationConvergenceMs" to keyRotationConvergenceMs,
        "epoch" to epoch
    )

    fun toCsvRow(): String {
        return "$eventId,$sessionId,$timestampEpochMs,$isoTimestamp,$eventType,$groupIdPrefix,$groupSizeM,$latencyMs,$fanOutSkewMs,$keyRotationConvergenceMs,$epoch"
    }

    fun toMasterCsvRow(): String {
        return "$eventId,$sessionId,$timestampEpochMs,$isoTimestamp,GROUP_EVENT,$eventType,$groupIdPrefix,1,900,$latencyMs,$groupSizeM,$groupSizeM,0,true,0,0,\"\",\"\",8,0.0,0,100,false,true,\"\",$latencyMs,\"epoch=$epoch;skew=$fanOutSkewMs;rekey=$keyRotationConvergenceMs\""
    }

    companion object {
        const val CSV_HEADER =
            "event_id,session_id,timestamp_epoch_ms,iso_timestamp,event_type,group_id_prefix,group_size_m,latency_ms,fan_out_skew_ms,key_rotation_convergence_ms,epoch"
    }
}

/**
 * Empirical traffic shaping and anonymity efficacy metrics.
 */
data class TrafficShapingStats(
    val sampleCount: Int,
    val meanInterPacketMs: Double,
    val varianceInterPacketMs: Double,
    val coefficientOfVariation: Double,
    val kolmogorovSmirnovD: Double,
    val realMsgCount: Int,
    val coverDummyCount: Int,
    val blindRepublishCount: Int,
    val decoyGetCount: Int,
    val tombstoneCount: Int,
    val totalOutboundPackets: Int,
    val realMsgPercent: Double,
    val coverDummyPercent: Double,
    val blindRepublishPercent: Double,
    val decoyGetPercent: Double,
    val tombstonePercent: Double,
    val targetEntropyBits: Double,
    val targetEntropyNormalized: Double
) {
    fun toMap(): Map<String, Any> = mapOf(
        "sampleCount" to sampleCount,
        "meanInterPacketMs" to meanInterPacketMs,
        "varianceInterPacketMs" to varianceInterPacketMs,
        "coefficientOfVariation" to coefficientOfVariation,
        "kolmogorovSmirnovD" to kolmogorovSmirnovD,
        "realMsgCount" to realMsgCount,
        "coverDummyCount" to coverDummyCount,
        "blindRepublishCount" to blindRepublishCount,
        "decoyGetCount" to decoyGetCount,
        "tombstoneCount" to tombstoneCount,
        "totalOutboundPackets" to totalOutboundPackets,
        "realMsgPercent" to realMsgPercent,
        "coverDummyPercent" to coverDummyPercent,
        "blindRepublishPercent" to blindRepublishPercent,
        "decoyGetPercent" to decoyGetPercent,
        "tombstonePercent" to tombstonePercent,
        "targetEntropyBits" to targetEntropyBits,
        "targetEntropyNormalized" to targetEntropyNormalized
    )
}

/**
 * Network RTT percentiles partitioned by physical network environment.
 */
data class NetworkTypeRttStats(
    val networkType: String,
    val sampleCount: Int,
    val minMs: Long,
    val maxMs: Long,
    val avgMs: Double,
    val p50Ms: Long,
    val p90Ms: Long,
    val p99Ms: Long
) {
    fun toMap(): Map<String, Any> = mapOf(
        "networkType" to networkType,
        "sampleCount" to sampleCount,
        "minMs" to minMs,
        "maxMs" to maxMs,
        "avgMs" to avgMs,
        "p50Ms" to p50Ms,
        "p90Ms" to p90Ms,
        "p99Ms" to p99Ms
    )
}

/**
 * Resumption success rate for multi-chunk media and document transfers.
 */
data class ChunkResumptionStats(
    val totalTransfers: Int,
    val resumedTransfers: Int,
    val successfulResumptions: Int,
    val resumptionSuccessRate: Double
) {
    fun toMap(): Map<String, Any> = mapOf(
        "totalTransfers" to totalTransfers,
        "resumedTransfers" to resumedTransfers,
        "successfulResumptions" to successfulResumptions,
        "resumptionSuccessRate" to resumptionSuccessRate
    )
}

/**
 * Empirical group messaging latency and key rotation convergence metrics.
 */
data class GroupChatResearchStats(
    val latencyByGroupSize: Map<String, Double>,
    val avgFanOutDeliverySkewMs: Double,
    val maxFanOutDeliverySkewMs: Long,
    val avgKeyRotationConvergenceMs: Double,
    val totalGroupMessagesTracked: Int,
    val totalKeyRotationsTracked: Int
) {
    fun toMap(): Map<String, Any> = mapOf(
        "latencyByGroupSize" to latencyByGroupSize,
        "avgFanOutDeliverySkewMs" to avgFanOutDeliverySkewMs,
        "maxFanOutDeliverySkewMs" to maxFanOutDeliverySkewMs,
        "avgKeyRotationConvergenceMs" to avgKeyRotationConvergenceMs,
        "totalGroupMessagesTracked" to totalGroupMessagesTracked,
        "totalKeyRotationsTracked" to totalKeyRotationsTracked
    )
}

/**
 * Retention survival curve data point in function of elapsed hours since initial PUT.
 */
data class RetentionSurvivalPoint(
    val horizonLabel: String,
    val horizonHours: Double,
    val totalSamples: Int,
    val aliveSamples: Int,
    val survivalRatePercent: Double,
    val republishActive: Boolean
) {
    fun toMap(): Map<String, Any> = mapOf(
        "horizonLabel" to horizonLabel,
        "horizonHours" to horizonHours,
        "totalSamples" to totalSamples,
        "aliveSamples" to aliveSamples,
        "survivalRatePercent" to survivalRatePercent,
        "republishActive" to republishActive
    )
}

object ResearchCsvSchema {
    const val MASTER_CSV_HEADER =
        "record_id,session_id,timestamp_epoch_ms,iso_timestamp,record_type,packet_role,target_prefix,seq_num,payload_bytes,rtt_ms,nodes_queried,nodes_responded,lookup_hops,success,republish_attempt,message_age_ms,network_type,polling_state,replication_k,poisson_lambda,battery_current_ua,battery_level_pct,republish_active,is_alive,elapsed_hours,e2e_latency_ms,error_or_status"
}

/**
 * Metadata manifest describing the research session, device telemetry context,
 * and cryptographic SHA-256 hashes of each constituent CSV file in the research bundle.
 */
data class SessionManifest(
    val sessionId: String,
    val appVersion: String,
    val versionCode: Int,
    val deviceModel: String,
    val androidVersion: Int,
    val createdEpochMs: Long,
    val isoCreatedAt: String,
    val totalEvents: Int,
    val firstSendCount: Int,
    val ownRepublishCount: Int,
    val crowdRepublishCount: Int,
    val packetsReceivedCount: Int,
    val ttlSamplesCount: Int,
    val fileChecksums: Map<String, String>,
    var manifestSha256: String = ""
) {
    fun toMap(): Map<String, Any> = mapOf(
        "sessionId" to sessionId,
        "appVersion" to appVersion,
        "versionCode" to versionCode,
        "deviceModel" to deviceModel,
        "androidVersion" to androidVersion,
        "createdEpochMs" to createdEpochMs,
        "isoCreatedAt" to isoCreatedAt,
        "totalEvents" to totalEvents,
        "firstSendCount" to firstSendCount,
        "ownRepublishCount" to ownRepublishCount,
        "crowdRepublishCount" to crowdRepublishCount,
        "packetsReceivedCount" to packetsReceivedCount,
        "ttlSamplesCount" to ttlSamplesCount,
        "fileChecksums" to fileChecksums,
        "manifestSha256" to manifestSha256
    )

    fun toJsonString(): String {
        val checksumsJson = fileChecksums.entries.joinToString(",") { (k, v) ->
            "\"$k\":\"$v\""
        }
        return """{
  "sessionId": "$sessionId",
  "appVersion": "$appVersion",
  "versionCode": $versionCode,
  "deviceModel": "$deviceModel",
  "androidVersion": $androidVersion,
  "createdEpochMs": $createdEpochMs,
  "isoCreatedAt": "$isoCreatedAt",
  "totalEvents": $totalEvents,
  "firstSendCount": $firstSendCount,
  "ownRepublishCount": $ownRepublishCount,
  "crowdRepublishCount": $crowdRepublishCount,
  "packetsReceivedCount": $packetsReceivedCount,
  "ttlSamplesCount": $ttlSamplesCount,
  "fileChecksums": {$checksumsJson},
  "manifestSha256": "$manifestSha256"
}""".trimIndent()
    }
}

fun computeSha256(file: java.io.File): String {
    if (!file.exists() || file.length() == 0L) return ""
    val digest = java.security.MessageDigest.getInstance("SHA-256")
    file.inputStream().use { fis ->
        val buffer = ByteArray(8192)
        var read: Int
        while (fis.read(buffer).also { read = it } != -1) {
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

fun computeSha256(text: String): String {
    val digest = java.security.MessageDigest.getInstance("SHA-256")
    return digest.digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}

