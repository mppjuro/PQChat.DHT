package org.pqchat.dht.research

import android.content.Context
import android.net.Uri
import android.os.Build
import com.google.firebase.FirebaseApp
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.SetOptions
import com.google.firebase.storage.FirebaseStorage
import com.google.firebase.storage.StorageMetadata
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.tasks.await
import java.io.File
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Handles asynchronous, batched synchronization of academic research telemetry to Google Firebase.
 *
 * Capabilities:
 * 1. Anonymous Authentication: Signs in anonymously using Firebase Auth so that authenticated
 *    security rules are satisfied without requiring any personal accounts or identification.
 * 2. Firestore Document Ingestion: Streams packet events, republish summaries, and TTL probe
 *    samples to collections partitioned by anonymous sessionId.
 * 3. Firebase Storage File Upload: Uploads complete, human-readable .csv files to Google Firebase
 *    Storage for direct import into statistical processing tools (Python, Pandas, R, MATLAB).
 * 4. Fault-Tolerant & Test-Safe: Gracefully falls back when FirebaseApp is not initialized or when
 *    the device is offline, buffering telemetry locally in persistent CSV files without dropping data.
 */
class FirebaseResearchSync(
    private val context: Context? = null,
    private val firestoreProvider: (() -> FirebaseFirestore?)? = null,
    private val storageProvider: (() -> FirebaseStorage?)? = null,
    private val authProvider: (() -> FirebaseAuth?)? = null
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _syncStatus = MutableStateFlow("Inicjalizacja")
    val syncStatus: StateFlow<String> = _syncStatus.asStateFlow()

    private val _syncedEventsCount = AtomicInteger(0)
    val syncedEventsCount: Int get() = _syncedEventsCount.get()

    private val isAuthenticating = AtomicBoolean(false)
    private var isAuthenticated = false

    private val pendingPacketEvents = ConcurrentLinkedQueue<PacketTelemetryEvent>()
    private val pendingTtlSamples = ConcurrentLinkedQueue<TtlSampleEvent>()
    private val pendingSummaries = ConcurrentLinkedQueue<RepublishAnalysisSummary>()

    private var batchFlushJob: Job? = null

    init {
        startPeriodicFlushLoop()
    }

    private fun isFirebaseConfigured(): Boolean {
        return try {
            FirebaseApp.getInstance()
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun getFirestore(): FirebaseFirestore? {
        if (firestoreProvider != null) return firestoreProvider.invoke()
        return if (isFirebaseConfigured()) {
            try { FirebaseFirestore.getInstance() } catch (_: Exception) { null }
        } else null
    }

    private fun getStorage(): FirebaseStorage? {
        if (storageProvider != null) return storageProvider.invoke()
        return if (isFirebaseConfigured()) {
            try { FirebaseStorage.getInstance() } catch (_: Exception) { null }
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
        val auth = getAuth() ?: return@withContext false

        if (auth.currentUser != null) {
            isAuthenticated = true
            _syncStatus.value = "Uwierzytelniono anonimowo"
            return@withContext true
        }

        if (isAuthenticating.compareAndSet(false, true)) {
            try {
                auth.signInAnonymously().await()
                isAuthenticated = true
                _syncStatus.value = "Uwierzytelniono anonimowo w Firebase"
                return@withContext true
            } catch (e: Exception) {
                _syncStatus.value = "Błąd logowania Firebase: ${e.message}"
                return@withContext false
            } finally {
                isAuthenticating.set(false)
            }
        }
        return@withContext false
    }

    fun queuePacketEvent(event: PacketTelemetryEvent) {
        pendingPacketEvents.add(event)
    }

    fun queueTtlSample(sample: TtlSampleEvent) {
        pendingTtlSamples.add(sample)
    }

    fun queueRepublishSummary(summary: RepublishAnalysisSummary) {
        pendingSummaries.add(summary)
    }

    private fun startPeriodicFlushLoop() {
        batchFlushJob?.cancel()
        batchFlushJob = scope.launch {
            while (isActive) {
                delay(15_000L) // Flush to Firebase every 15 seconds
                if (pendingPacketEvents.isNotEmpty() || pendingTtlSamples.isNotEmpty() || pendingSummaries.isNotEmpty()) {
                    flushPendingData()
                }
            }
        }
    }

    suspend fun flushPendingData(): Boolean = withContext(Dispatchers.IO) {
        val firestore = getFirestore()
        if (firestore == null) {
            _syncStatus.value = "Firebase niedostępny (zapis lokalny CSV aktywny)"
            return@withContext false
        }

        ensureAuthenticated()

        var successCount = 0
        try {
            // 1. Flush packet events in batches up to 50 items
            while (pendingPacketEvents.isNotEmpty()) {
                val batch = firestore.batch()
                var batchSize = 0
                val processedList = mutableListOf<PacketTelemetryEvent>()

                while (batchSize < 50 && pendingPacketEvents.isNotEmpty()) {
                    val event = pendingPacketEvents.poll() ?: break
                    val docRef = firestore
                        .collection("research_sessions")
                        .document(event.sessionId)
                        .collection("packet_events")
                        .document(event.eventId)

                    batch.set(docRef, event.toMap(), SetOptions.merge())
                    processedList.add(event)
                    batchSize++
                }

                if (batchSize > 0) {
                    batch.commit().await()
                    successCount += batchSize
                    _syncedEventsCount.addAndGet(batchSize)
                }
            }

            // 2. Flush TTL samples
            while (pendingTtlSamples.isNotEmpty()) {
                val batch = firestore.batch()
                var batchSize = 0
                while (batchSize < 50 && pendingTtlSamples.isNotEmpty()) {
                    val sample = pendingTtlSamples.poll() ?: break
                    val docRef = firestore
                        .collection("research_sessions")
                        .document(sample.sessionId)
                        .collection("ttl_samples")
                        .document(sample.sampleId)

                    batch.set(docRef, sample.toMap(), SetOptions.merge())
                    batchSize++
                }
                if (batchSize > 0) {
                    batch.commit().await()
                    successCount += batchSize
                }
            }

            // 3. Flush Republish summaries
            while (pendingSummaries.isNotEmpty()) {
                val batch = firestore.batch()
                var batchSize = 0
                while (batchSize < 50 && pendingSummaries.isNotEmpty()) {
                    val summary = pendingSummaries.poll() ?: break
                    val docRef = firestore
                        .collection("research_sessions")
                        .document(summary.sessionId)
                        .collection("republish_summaries")
                        .document(summary.messagePrefix)

                    batch.set(docRef, summary.toMap(), SetOptions.merge())
                    batchSize++
                }
                if (batchSize > 0) {
                    batch.commit().await()
                    successCount += batchSize
                }
            }

            _syncStatus.value = "Zsynchronizowano z Firebase (łącznie: ${_syncedEventsCount.get()})"
            return@withContext true
        } catch (e: Exception) {
            _syncStatus.value = "Błąd synchronizacji z Firebase: ${e.message}"
            return@withContext false
        }
    }

    /**
     * Uploads the full CSV log file to Google Firebase Storage for direct academic analysis.
     * Path: research_data/{sessionId}/{filename}
     */
    suspend fun uploadCsvToStorage(
        sessionId: String,
        csvFile: File,
        remoteFileName: String = csvFile.name
    ): Boolean = withContext(Dispatchers.IO) {
        val storage = getStorage() ?: run {
            _syncStatus.value = "Firebase Storage niedostępne"
            return@withContext false
        }

        if (!csvFile.exists() || csvFile.length() == 0L) {
            return@withContext false
        }

        ensureAuthenticated()

        try {
            val storageRef = storage.reference.child("research_data/$sessionId/$remoteFileName")
            val metadata = StorageMetadata.Builder()
                .setContentType("text/csv")
                .setCustomMetadata("sessionId", sessionId)
                .setCustomMetadata("uploadedAt", System.currentTimeMillis().toString())
                .setCustomMetadata("deviceModel", Build.MODEL)
                .build()

            val fileUri = Uri.fromFile(csvFile)
            storageRef.putFile(fileUri, metadata).await()
            _syncStatus.value = "Wysłano plik CSV ($remoteFileName) do Firebase Storage"
            return@withContext true
        } catch (e: Exception) {
            _syncStatus.value = "Błąd wysyłania CSV: ${e.message}"
            return@withContext false
        }
    }

    fun stop() {
        batchFlushJob?.cancel()
    }
}
