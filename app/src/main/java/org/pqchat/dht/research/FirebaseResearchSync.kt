package org.pqchat.dht.research

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
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
import org.pqchat.dht.BuildConfig
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Handles Local-First Batch Archiving and synchronization of academic research telemetry
 * to Google Firebase (Cloud Storage for compressed .zip bundles + Firestore for session summaries).
 *
 * Design Principles:
 * 1. Local-First & Zero LTE Wakeup: Never polls or writes individual events over cellular radio.
 *    Telemetry is aggregated locally in CSV files.
 * 2. Bandwidth & Quota Efficient: Only uploads a single compressed .zip bundle and 1 Firestore
 *    summary document per session.
 * 3. Rate-limited & Wi-Fi only: Automatic sync occurs at most once every 6 hours and strictly on Wi-Fi.
 *    Manual sync can be triggered at any time by the user.
 * 4. Safe No-Op Fallback: If Firebase is not configured (missing google-services.json and BuildConfig
 *    keys), all operations gracefully complete as no-op without throwing exceptions.
 */
class FirebaseResearchSync(
    private val context: Context? = null,
    private val firestoreProvider: (() -> FirebaseFirestore?)? = null,
    private val storageProvider: (() -> FirebaseStorage?)? = null,
    private val authProvider: (() -> FirebaseAuth?)? = null
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _syncStatus = MutableStateFlow("Lokalny zapis aktywny")
    val syncStatus: StateFlow<String> = _syncStatus.asStateFlow()

    private val isAuthenticating = AtomicBoolean(false)
    private var isAuthenticated = false

    private var lastAutoSyncTimestamp = 0L

    init {
        tryInitializeFirebase()
    }

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
        val storageBucket = try { BuildConfig.FIREBASE_STORAGE_BUCKET } catch (_: Throwable) { "" }

        if (projectId.isNotBlank() && appId.isNotBlank() && apiKey.isNotBlank()) {
            try {
                val optionsBuilder = FirebaseOptions.Builder()
                    .setProjectId(projectId)
                    .setApplicationId(appId)
                    .setApiKey(apiKey)
                if (storageBucket.isNotBlank()) {
                    optionsBuilder.setStorageBucket(storageBucket)
                }
                FirebaseApp.initializeApp(ctx, optionsBuilder.build())
                return true
            } catch (_: Exception) {
                return false
            }
        }

        return false
    }

    fun isFirebaseConfigured(): Boolean {
        if (firestoreProvider != null || storageProvider != null || authProvider != null) {
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
        val auth = getAuth() ?: run {
            _syncStatus.value = "Firebase nieskonfigurowany (zapis lokalny)"
            return@withContext false
        }

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

    fun isWifiConnected(): Boolean {
        val ctx = context ?: return false
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val network = cm.activeNetwork ?: return false
        val capabilities = cm.getNetworkCapabilities(network) ?: return false
        return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
    }

    /**
     * Uploads the compressed research bundle (.zip) to Firebase Storage and writes
     * the session manifest summary to Cloud Firestore.
     *
     * @param sessionId anonymous session identifier
     * @param zipFile compressed bundle containing all CSVs and session_manifest.json
     * @param manifestSummary metadata map containing session statistics and SHA-256 checksums
     * @param isManual true if triggered manually by user; false if automated background check
     */
    suspend fun syncResearchBundle(
        sessionId: String,
        zipFile: File,
        manifestSummary: Map<String, Any>,
        isManual: Boolean = false
    ): Boolean = withContext(Dispatchers.IO) {
        if (!isFirebaseConfigured()) {
            _syncStatus.value = "Zapis lokalny aktywny (brak konfiguracji Firebase)"
            return@withContext false
        }

        val now = System.currentTimeMillis()
        if (!isManual) {
            // Rate-limit: at most once every 6 hours
            if (now - lastAutoSyncTimestamp < 6 * 3600 * 1000L) {
                return@withContext false
            }
            // Strict Wi-Fi requirement for automated background uploads
            if (!isWifiConnected()) {
                return@withContext false
            }
        }

        if (!ensureAuthenticated()) {
            return@withContext false
        }

        val storage = getStorage() ?: run {
            _syncStatus.value = "Firebase Storage niedostępne"
            return@withContext false
        }
        val firestore = getFirestore() ?: run {
            _syncStatus.value = "Firestore niedostępny"
            return@withContext false
        }

        if (!zipFile.exists() || zipFile.length() == 0L) {
            _syncStatus.value = "Brak pliku paczki badawczej"
            return@withContext false
        }

        try {
            _syncStatus.value = "Wysyłanie paczki ZIP do Firebase Storage..."
            val remotePath = "research_bundles/$sessionId/${zipFile.name}"
            val storageRef = storage.reference.child(remotePath)
            val metadata = StorageMetadata.Builder()
                .setContentType("application/zip")
                .setCustomMetadata("sessionId", sessionId)
                .setCustomMetadata("uploadedAt", now.toString())
                .setCustomMetadata("deviceModel", Build.MODEL)
                .build()

            storageRef.putFile(Uri.fromFile(zipFile), metadata).await()

            _syncStatus.value = "Zapisywanie podsumowania sesji w Firestore..."
            firestore.collection("research_sessions")
                .document(sessionId)
                .set(manifestSummary, SetOptions.merge())
                .await()

            lastAutoSyncTimestamp = now
            _syncStatus.value = "Pomyślnie zsynchronizowano paczkę ZIP z Firebase"
            return@withContext true
        } catch (e: Exception) {
            _syncStatus.value = "Błąd synchronizacji paczki: ${e.message}"
            return@withContext false
        }
    }

    fun stop() {
        scope.cancel()
    }
}
