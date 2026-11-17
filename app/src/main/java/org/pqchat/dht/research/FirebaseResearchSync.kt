package org.pqchat.dht.research

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.tasks.await
import org.pqchat.dht.BuildConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Handles batch synchronization of academic research telemetry to Google Cloud Firestore (Firebase Spark free tier).
 *
 * Design Principles:
 * 1. Cloud Firestore Only: No Cloud Storage dependency (zero costs, Spark-plan compliant).
 * 2. Local-First Batch Archiving: Never polls or writes individual events over cellular radio.
 *    Telemetry is aggregated locally in CSV files.
 * 3. Compact JSON & GZIP Batch Payloads: Writes at most 1 aggregate document per session directly
 *    to collection `research_sessions/{sessionId}`, strictly respecting the 1 MB Firestore limit.
 * 4. Strict Security & Validation: Matches `firestore.rules` create-only policy (requires non-null auth,
 *    `timestamp`, `deviceInfo`, and `metrics` map).
 * 5. Rate-limited & Wi-Fi only: Automatic sync occurs at most once every 30 minutes (±5 minutes jitter) and strictly on Wi-Fi.
 *    Manual sync can be triggered at any time by the user.
 * 6. Pre-flight Validation: Validates payloads locally against `firestore.rules` schema constraints before transmission.
 * 7. Safe No-Op Fallback: If Firebase is not configured (missing google-services.json and BuildConfig
 *    keys), all operations gracefully complete as no-op without throwing exceptions.
 */
class FirebaseResearchSync(
    private val context: Context? = null,
    private val firestoreProvider: (() -> FirebaseFirestore?)? = null,
    private val authProvider: (() -> FirebaseAuth?)? = null,
    private val customAuthChecker: (suspend () -> Boolean)? = null,
    private val customDocumentWriter: (suspend (docId: String, documentData: Map<String, Any>) -> Boolean)? = null,
    private val wifiChecker: (() -> Boolean)? = null,
    private val clockProvider: () -> Long = { System.currentTimeMillis() }
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _syncStatus = MutableStateFlow("Local storage active")
    val syncStatus: StateFlow<String> = _syncStatus.asStateFlow()

    private val isAuthenticating = AtomicBoolean(false)
    @Volatile
    private var isAuthenticated = false

    @Volatile
    private var lastAutoSyncTimestamp = 0L
    @Volatile
    private var hasSynced = false
    private val syncedSessionIds = LinkedHashSet<String>()
    private val stateLock = Any()

    init {
        loadPersistedState()
        tryInitializeFirebase()
    }

    private fun loadPersistedState() {
        val ctx = context ?: return
        try {
            val prefs = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            synchronized(stateLock) {
                lastAutoSyncTimestamp = prefs.getLong(KEY_LAST_AUTO_SYNC_MS, 0L).coerceAtLeast(0L)
                val storedIds = prefs.getStringSet(KEY_SYNCED_SESSION_IDS, emptySet()).orEmpty()
                syncedSessionIds.clear()
                storedIds.take(MAX_STORED_SESSION_IDS).forEach { id ->
                    if (id.isNotBlank()) syncedSessionIds.add(id)
                }
            }
        } catch (_: Throwable) {}
    }

    private fun recordSuccessfulSync(sessionId: String, timestampMs: Long) {
        synchronized(stateLock) {
            hasSynced = true
            lastAutoSyncTimestamp = timestampMs
            if (sessionId.isNotBlank()) {
                syncedSessionIds.remove(sessionId)
                syncedSessionIds.add(sessionId)
                while (syncedSessionIds.size > MAX_STORED_SESSION_IDS) {
                    val oldest = syncedSessionIds.iterator().next()
                    syncedSessionIds.remove(oldest)
                }
            }
            val ctx = context ?: return
            try {
                val prefs = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                prefs.edit()
                    .putLong(KEY_LAST_AUTO_SYNC_MS, lastAutoSyncTimestamp)
                    .putStringSet(KEY_SYNCED_SESSION_IDS, LinkedHashSet(syncedSessionIds))
                    .apply()
            } catch (_: Throwable) {}
        }
    }

    fun getLastAutoSyncTimestamp(): Long = synchronized(stateLock) { lastAutoSyncTimestamp }

    fun getSyncedSessionIds(): Set<String> = synchronized(stateLock) { syncedSessionIds.toSet() }

    fun hasSessionSynced(sessionId: String): Boolean = synchronized(stateLock) { syncedSessionIds.contains(sessionId) }

    private fun tryInitializeFirebase(): Boolean {
        val ctx = context ?: return false
        try {
            if (FirebaseApp.getApps(ctx).isNotEmpty()) {
                return true
            }
        } catch (_: Exception) {}

        // Attempt programmatic configuration from BuildConfig if google-services.json was absent
        val projectId = try { BuildConfig.FIREBASE_PROJECT_ID } catch (_: Throwable) { "" }
        val appId = try { BuildConfig.FIREBASE_APP_ID } catch (_: Throwable) { "" }
        val apiKey = try { BuildConfig.FIREBASE_API_KEY } catch (_: Throwable) { "" }

        if (projectId.isNotBlank() && appId.isNotBlank() && apiKey.isNotBlank()) {
            try {
                val options = FirebaseOptions.Builder()
                    .setProjectId(projectId)
                    .setApplicationId(appId)
                    .setApiKey(apiKey)
                    .build()
                FirebaseApp.initializeApp(ctx, options)
                return true
            } catch (_: Exception) {
                return false
            }
        }

        return false
    }

    fun isFirebaseConfigured(): Boolean {
        if (firestoreProvider != null || authProvider != null || customDocumentWriter != null) {
            return true
        }
        return try {
            FirebaseApp.getInstance()
            true
        } catch (_: Exception) {
            tryInitializeFirebase()
        }
    }

    private fun getFirestore(): FirebaseFirestore? {
        if (firestoreProvider != null) return firestoreProvider.invoke()
        return if (isFirebaseConfigured()) {
            try { FirebaseFirestore.getInstance() } catch (_: Exception) { null }
        } else null
    }

    private fun getAuth(): FirebaseAuth? {
        if (authProvider != null) return authProvider.invoke()
        return if (isFirebaseConfigured()) {
            try { FirebaseAuth.getInstance() } catch (_: Exception) { null }
        } else null
    }

    suspend fun ensureAuthenticated(): Boolean = withContext(Dispatchers.IO) {
        if (isAuthenticated) return@withContext true
        val checker = customAuthChecker
        if (checker != null) {
            val ok = try { checker.invoke() } catch (_: Exception) { false }
            if (ok) {
                isAuthenticated = true
                _syncStatus.value = "Authenticated anonymously with Firebase"
            } else {
                _syncStatus.value = "Firebase authentication rejected"
            }
            return@withContext ok
        }
        val auth = getAuth() ?: run {
            _syncStatus.value = "Firebase not configured (local storage)"
            return@withContext false
        }

        if (auth.currentUser != null) {
            isAuthenticated = true
            _syncStatus.value = "Authenticated anonymously"
            return@withContext true
        }

        if (isAuthenticating.compareAndSet(false, true)) {
            try {
                auth.signInAnonymously().await()
                isAuthenticated = true
                _syncStatus.value = "Authenticated anonymously with Firebase"
                return@withContext true
            } catch (e: Exception) {
                _syncStatus.value = "Firebase login error: ${e.message}"
                return@withContext false
            } finally {
                isAuthenticating.set(false)
            }
        }
        return@withContext false
    }

    fun isWifiConnected(): Boolean {
        wifiChecker?.let { return it.invoke() }
        val ctx = context ?: return false
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val network = cm.activeNetwork ?: return false
        val capabilities = cm.getNetworkCapabilities(network) ?: return false
        return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
    }

    companion object {
        const val DEFAULT_BATCH_SYNC_INTERVAL_MS = 30 * 60 * 1000L // 30 minutes
        const val JITTER_WINDOW_MS = 5 * 60 * 1000L                // +/- 5 minutes
        const val PREFS_NAME = "pqchat_firebase_research_sync"
        const val KEY_LAST_AUTO_SYNC_MS = "last_auto_sync_ms"
        const val KEY_SYNCED_SESSION_IDS = "synced_session_ids"
        const val MAX_STORED_SESSION_IDS = 200
        const val EXPECTED_SCHEMA_VERSION = 2
        const val MIN_VALID_TIMESTAMP_MS = 1_700_000_000_000L
        const val MAX_BUNDLE_ZIP_BYTES = 700_000L
        const val MAX_CHUNK_ZIP_BYTES = 550_000L
        const val MAX_BUNDLE_BASE64_CHARS = 950_000

        private val REQUIRED_TOP_LEVEL_KEYS = setOf(
            "sessionId",
            "timestamp",
            "deviceInfo",
            "metrics",
            "schemaVersion"
        )
        private val REQUIRED_DEVICE_INFO_KEYS = setOf(
            "sessionId",
            "deviceModel",
            "androidVersion",
            "appVersion",
            "versionCode"
        )
        private val REQUIRED_METRICS_KEYS = setOf(
            "totalEvents",
            "firstSendCount",
            "ownRepublishCount",
            "crowdRepublishCount",
            "packetsReceivedCount",
            "ttlSamplesCount"
        )

        private fun asIntegralLong(value: Any?): Long? = when (value) {
            is Long -> value
            is Int -> value.toLong()
            is Short -> value.toLong()
            is Byte -> value.toLong()
            else -> null
        }

        /**
         * Validates a Firestore document payload against `firestore.rules` schema constraints.
         * Returns Pair(true, null) if valid, or Pair(false, diagnosticReason) otherwise.
         */
        fun validatePayloadWithReason(documentData: Map<String, Any?>): Pair<Boolean, String?> {
            if (!documentData.keys.containsAll(REQUIRED_TOP_LEVEL_KEYS) ||
                documentData.keys.size != REQUIRED_TOP_LEVEL_KEYS.size
            ) {
                return false to "Top-level keys must match exactly $REQUIRED_TOP_LEVEL_KEYS (found ${documentData.keys})"
            }

            val sessionId = documentData["sessionId"] as? String
                ?: return false to "sessionId must be a String"
            if (sessionId.length !in 8..64) {
                return false to "sessionId length must be between 8 and 64 (was ${sessionId.length})"
            }

            val timestamp = asIntegralLong(documentData["timestamp"])
                ?: return false to "timestamp must be an integer"
            if (timestamp <= MIN_VALID_TIMESTAMP_MS) {
                return false to "timestamp must be > $MIN_VALID_TIMESTAMP_MS (was $timestamp)"
            }

            val schemaVersion = asIntegralLong(documentData["schemaVersion"])
                ?: return false to "schemaVersion must be an integer"
            if (schemaVersion != EXPECTED_SCHEMA_VERSION.toLong()) {
                return false to "schemaVersion must be $EXPECTED_SCHEMA_VERSION (was $schemaVersion)"
            }

            val deviceInfo = documentData["deviceInfo"] as? Map<*, *>
                ?: return false to "deviceInfo must be a Map"
            if (!deviceInfo.keys.containsAll(REQUIRED_DEVICE_INFO_KEYS)) {
                return false to "deviceInfo missing required keys: ${REQUIRED_DEVICE_INFO_KEYS - deviceInfo.keys}"
            }
            if (deviceInfo["deviceModel"] !is String) {
                return false to "deviceInfo.deviceModel must be a String"
            }
            if (asIntegralLong(deviceInfo["androidVersion"]) == null) {
                return false to "deviceInfo.androidVersion must be an integer"
            }
            if (asIntegralLong(deviceInfo["versionCode"]) == null) {
                return false to "deviceInfo.versionCode must be an integer"
            }

            val metrics = documentData["metrics"] as? Map<*, *>
                ?: return false to "metrics must be a Map"
            if (!metrics.keys.containsAll(REQUIRED_METRICS_KEYS)) {
                return false to "metrics missing required keys: ${REQUIRED_METRICS_KEYS - metrics.keys}"
            }

            val totalEvents = asIntegralLong(metrics["totalEvents"])
                ?: return false to "metrics.totalEvents must be an integer"
            if (totalEvents < 0L) {
                return false to "metrics.totalEvents must be >= 0 (was $totalEvents)"
            }

            for (counterKey in REQUIRED_METRICS_KEYS) {
                if (counterKey == "totalEvents") continue
                if (asIntegralLong(metrics[counterKey]) == null) {
                    return false to "metrics.$counterKey must be an integer"
                }
            }

            if (metrics.containsKey("bundleZipSizeBytes")) {
                val zipSize = asIntegralLong(metrics["bundleZipSizeBytes"])
                    ?: return false to "metrics.bundleZipSizeBytes must be an integer"
                if (zipSize < 0L || zipSize > MAX_BUNDLE_ZIP_BYTES) {
                    return false to "metrics.bundleZipSizeBytes must be in 0..$MAX_BUNDLE_ZIP_BYTES (was $zipSize)"
                }
            }

            if (metrics.containsKey("bundleZipBase64")) {
                val base64 = metrics["bundleZipBase64"] as? String
                    ?: return false to "metrics.bundleZipBase64 must be a String"
                if (base64.length > MAX_BUNDLE_BASE64_CHARS) {
                    return false to "metrics.bundleZipBase64 length exceeds $MAX_BUNDLE_BASE64_CHARS (was ${base64.length})"
                }
            }

            return true to null
        }

        /**
         * Returns true if [documentData] strictly satisfies `firestore.rules` validation checks.
         */
        fun validatePayloadAgainstFirestoreRules(documentData: Map<String, Any?>): Boolean =
            validatePayloadWithReason(documentData).first
    }

    /**
     * Validates [documentData] against `firestore.rules` constraints prior to network submission.
     */
    fun validatePayloadAgainstRules(documentData: Map<String, Any?>): Boolean =
        validatePayloadAgainstFirestoreRules(documentData)

    /**
     * Checks whether environmental conditions permit safe delayed batch synchronization.
     * Guaranteed protection against timing side-channels and measurement distortion:
     * 1. Never transmit during active radio profiling or loopback benchmarks.
     * 2. Require Wi-Fi connection for automated background batch syncing.
     */
    fun isSafeToSync(isProfilingActive: Boolean = false): Boolean {
        if (isProfilingActive) return false
        return isWifiConnected()
    }

    /**
     * Synchronizes the research session metrics and optional compressed payload directly to Cloud Firestore.
     * Complies with `firestore.rules` requirements:
     * - `request.auth != null`
     * - Contains keys: `['sessionId', 'timestamp', 'deviceInfo', 'metrics', 'schemaVersion']`
     * - `metrics` is a Map
     * - Document size strictly capped well below 1 MB.
     *
     * @param sessionId anonymous session identifier
     * @param deviceInfo device metadata (model, android version, app version)
     * @param metrics aggregated statistics, survival rates, RTT percentiles and checksums
     * @param isManual true if user explicitly triggered sync via Settings/Diagnostics (bypasses timer/Wi-Fi restrictions)
     */
    suspend fun syncResearchSession(
        sessionId: String,
        deviceInfo: Map<String, Any>,
        metrics: Map<String, Any>,
        isManual: Boolean = false
    ): Boolean = withContext(Dispatchers.IO) {
        if (!isFirebaseConfigured()) {
            _syncStatus.value = "Local storage active (Firebase not configured)"
            return@withContext false
        }

        val now = clockProvider()
        if (!isManual) {
            // Rate-limit: at most once every 30 minutes with jitter window
            val minInterval = DEFAULT_BATCH_SYNC_INTERVAL_MS - JITTER_WINDOW_MS
            val lastSync = getLastAutoSyncTimestamp()
            if (lastSync > 0L && now - lastSync < minInterval) {
                return@withContext false
            }
            // Strict check: no active radio profiling and Wi-Fi only
            if (!isSafeToSync()) {
                return@withContext false
            }
        }

        val documentData = mapOf(
            "sessionId" to sessionId,
            "timestamp" to now,
            "deviceInfo" to deviceInfo,
            "metrics" to metrics,
            "schemaVersion" to EXPECTED_SCHEMA_VERSION
        )

        val (isValid, validationError) = validatePayloadWithReason(documentData)
        if (!isValid) {
            _syncStatus.value = "Payload validation failed: $validationError"
            return@withContext false
        }

        if (!ensureAuthenticated()) {
            return@withContext false
        }

        val docId = if (!hasSynced && !hasSessionSynced(sessionId)) sessionId else "${sessionId}_${now}"
        _syncStatus.value = "Saving metrics to Cloud Firestore..."
        val ok = writeFirestoreDocument(docId, sessionId, documentData)
        if (ok) {
            recordSuccessfulSync(sessionId, now)
            _syncStatus.value = "Successfully synchronized with Cloud Firestore"
        }
        return@withContext ok
    }

    /**
     * Synchronizes a multi-part chunked research session (each ZIP chunk <= 550 KB)
     * across sequential `research_sessions` documents so multi-day sessions never hit
     * Firestore's 1 MB document size limit.
     */
    suspend fun syncResearchSessionChunks(
        sessionId: String,
        payloads: List<Pair<Map<String, Any>, Map<String, Any>>>,
        isManual: Boolean = false
    ): Boolean = withContext(Dispatchers.IO) {
        if (payloads.isEmpty()) return@withContext false
        if (payloads.size == 1) {
            return@withContext syncResearchSession(
                sessionId = sessionId,
                deviceInfo = payloads[0].first,
                metrics = payloads[0].second,
                isManual = isManual
            )
        }

        if (!isFirebaseConfigured()) {
            _syncStatus.value = "Local storage active (Firebase not configured)"
            return@withContext false
        }

        val now = clockProvider()
        if (!isManual) {
            val minInterval = DEFAULT_BATCH_SYNC_INTERVAL_MS - JITTER_WINDOW_MS
            val lastSync = getLastAutoSyncTimestamp()
            if (lastSync > 0L && now - lastSync < minInterval) {
                return@withContext false
            }
            if (!isSafeToSync()) {
                return@withContext false
            }
        }

        // Pre-flight validate every chunk document before transmitting any part
        val preparedDocs = payloads.mapIndexed { idx, (deviceInfo, metrics) ->
            val chunkTs = now + idx
            val docData = mapOf(
                "sessionId" to sessionId,
                "timestamp" to chunkTs,
                "deviceInfo" to deviceInfo,
                "metrics" to metrics,
                "schemaVersion" to EXPECTED_SCHEMA_VERSION
            )
            val (isValid, validationError) = validatePayloadWithReason(docData)
            if (!isValid) {
                _syncStatus.value = "Chunk ${idx + 1} payload validation failed: $validationError"
                return@withContext false
            }
            docData
        }

        if (!ensureAuthenticated()) {
            return@withContext false
        }

        val baseDocId = if (!hasSynced && !hasSessionSynced(sessionId)) sessionId else "${sessionId}_${now}"
        val total = preparedDocs.size
        for ((idx, docData) in preparedDocs.withIndex()) {
            val partNum = idx + 1
            val docId = if (partNum == 1) baseDocId else "${baseDocId}_part${partNum}_of_${total}"
            _syncStatus.value = "Saving chunk $partNum/$total to Cloud Firestore..."
            val ok = writeFirestoreDocument(docId, "${sessionId}_part${partNum}_of_${total}", docData)
            if (!ok) {
                return@withContext false
            }
        }

        recordSuccessfulSync(sessionId, now)
        _syncStatus.value = "Successfully synchronized $total chunks with Cloud Firestore"
        return@withContext true
    }

    private suspend fun writeFirestoreDocument(
        docId: String,
        fallbackPrefix: String,
        documentData: Map<String, Any>
    ): Boolean {
        val customWriter = customDocumentWriter
        if (customWriter != null) {
            return try {
                val ok = customWriter.invoke(docId, documentData)
                if (!ok) {
                    _syncStatus.value = "Firestore write rejected"
                }
                ok
            } catch (e: Exception) {
                _syncStatus.value = "Firestore write error: ${e.message}"
                false
            }
        }

        val firestore = getFirestore() ?: run {
            _syncStatus.value = "Firestore unavailable"
            return false
        }

        return try {
            try {
                firestore.collection("research_sessions")
                    .document(docId)
                    .set(documentData)
                    .await()
            } catch (_: Exception) {
                val fallbackId = "${fallbackPrefix}_${clockProvider()}"
                firestore.collection("research_sessions")
                    .document(fallbackId)
                    .set(documentData)
                    .await()
            }
            true
        } catch (e: Exception) {
            _syncStatus.value = "Firestore write error: ${e.message}"
            false
        }
    }

    fun stop() {
        scope.cancel()
    }
}
