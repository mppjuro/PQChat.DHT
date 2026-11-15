package org.pqchat.dht.research

import android.content.Context
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.settings.AppSettingsManager
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

/**
 * Integration tests for [FirebaseResearchSync] and [ResearchTelemetryManager] Firestore payload generation,
 * pre-flight `firestore.rules` schema validation, `SharedPreferences` rate-limiting persistence,
 * and optional live Cloud Firestore REST ingestion when CI/local Firebase credentials are configured.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FirebaseResearchSyncIntegrationTest {

    private lateinit var appContext: Context
    private lateinit var tempDir: File
    private lateinit var settingsManager: AppSettingsManager
    private var telemetryManager: ResearchTelemetryManager? = null

    @Before
    fun setUp() {
        appContext = RuntimeEnvironment.getApplication()
        clearSyncPreferences()
        tempDir = File(
            System.getProperty("java.io.tmpdir") ?: ".",
            "pqchat_firebase_sync_test_${System.nanoTime()}"
        ).apply { mkdirs() }
        settingsManager = AppSettingsManager()
    }

    @After
    fun tearDown() {
        try {
            telemetryManager?.stop()
        } catch (_: Exception) {}
        clearSyncPreferences()
        tempDir.deleteRecursively()
    }

    private fun clearSyncPreferences() {
        appContext.getSharedPreferences(FirebaseResearchSync.PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    private fun buildValidPayload(
        sessionId: String = "test_session_${UUID.randomUUID().toString().take(8)}",
        timestampMs: Long = 1_750_000_000_000L
    ): MutableMap<String, Any?> {
        val deviceInfo = mutableMapOf<String, Any?>(
            "sessionId" to sessionId,
            "deviceModel" to "Pixel 8 Test",
            "androidVersion" to 34,
            "appVersion" to "1.0.0-test",
            "versionCode" to 1
        )
        val metrics = mutableMapOf<String, Any?>(
            "totalEvents" to 3,
            "firstSendCount" to 1,
            "ownRepublishCount" to 1,
            "crowdRepublishCount" to 0,
            "packetsReceivedCount" to 1,
            "ttlSamplesCount" to 0,
            "bundleZipSizeBytes" to 512L,
            "bundleZipStatus" to "EMBEDDED_ZIP_BASE64",
            "bundleZipBase64" to "UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA=="
        )
        return mutableMapOf(
            "sessionId" to sessionId,
            "timestamp" to timestampMs,
            "deviceInfo" to deviceInfo,
            "metrics" to metrics,
            "schemaVersion" to FirebaseResearchSync.EXPECTED_SCHEMA_VERSION
        )
    }

    @Test
    fun `test computeSessionPayload satisfies firestore rules schema validation`() {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            context = appContext,
            settingsManager = settingsManager,
            dhtClient = null,
            baseDir = tempDir
        ).also { telemetryManager = it }

        val target = CryptoUtils.secureRandomBytes(20)
        manager.recordPacketEvent(
            role = PacketRole.FIRST_SEND,
            target = target,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 42L,
            nodesQueried = 16,
            nodesResponded = 8,
            lookupHops = 3,
            success = true
        )
        manager.recordPacketEvent(
            role = PacketRole.OWN_REPUBLISH,
            target = target,
            seqNum = 1L,
            payloadBytes = 900,
            rttMs = 55L,
            republishAttempt = 1,
            messageAgeMs = 600_000L,
            success = true
        )
        manager.recordPacketEvent(
            role = PacketRole.PACKET_RECEIVED,
            target = CryptoUtils.secureRandomBytes(20),
            seqNum = 2L,
            payloadBytes = 900,
            rttMs = 37L,
            success = true
        )

        val (deviceInfo, metrics) = manager.computeSessionPayload()
        val nowMs = System.currentTimeMillis().coerceAtLeast(FirebaseResearchSync.MIN_VALID_TIMESTAMP_MS + 1L)
        val documentData = mapOf(
            "sessionId" to manager.sessionId,
            "timestamp" to nowMs,
            "deviceInfo" to deviceInfo,
            "metrics" to metrics,
            "schemaVersion" to FirebaseResearchSync.EXPECTED_SCHEMA_VERSION
        )

        val (isValid, reason) = FirebaseResearchSync.validatePayloadWithReason(documentData)
        assertTrue("Expected valid payload from computeSessionPayload(), error=$reason", isValid)
        assertTrue(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(documentData))
        assertEquals("EMBEDDED_ZIP_BASE64", metrics["bundleZipStatus"])
        val zipSize = (metrics["bundleZipSizeBytes"] as Number).toLong()
        assertTrue("Generated ZIP must be non-empty", zipSize > 0L)
        assertTrue("Generated ZIP must fit within Firestore limit", zipSize <= FirebaseResearchSync.MAX_BUNDLE_ZIP_BYTES)
    }

    @Test
    fun `test preflight validation rejects payloads violating firestore rules`() {
        val valid = buildValidPayload()
        assertTrue(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(valid))

        // 1. Missing top-level key
        val missingMetrics = buildValidPayload().apply { remove("metrics") }
        val (missingValid, missingErr) = FirebaseResearchSync.validatePayloadWithReason(missingMetrics)
        assertFalse(missingValid)
        assertNotNull(missingErr)

        // 2. Extra unexpected top-level key
        val extraTopKey = buildValidPayload().apply { put("unexpectedKey", "bad") }
        assertFalse(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(extraTopKey))

        // 3. sessionId shorter than 8 chars or longer than 64 chars
        val shortSession = buildValidPayload(sessionId = "short")
        assertFalse(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(shortSession))
        val longSession = buildValidPayload(sessionId = "x".repeat(65))
        assertFalse(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(longSession))

        // 4. timestamp <= 1700000000000L
        val staleTimestamp = buildValidPayload(timestampMs = FirebaseResearchSync.MIN_VALID_TIMESTAMP_MS)
        assertFalse(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(staleTimestamp))

        // 5. schemaVersion != 2
        val wrongSchema = buildValidPayload().apply { put("schemaVersion", 999) }
        assertFalse(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(wrongSchema))

        // 6. Missing deviceInfo required key
        val badDeviceInfo = buildValidPayload().apply {
            @Suppress("UNCHECKED_CAST")
            val di = (get("deviceInfo") as MutableMap<String, Any?>)
            di.remove("deviceModel")
        }
        assertFalse(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(badDeviceInfo))

        // 7. Missing metrics key and negative counter
        val missingCounter = buildValidPayload().apply {
            @Suppress("UNCHECKED_CAST")
            val m = (get("metrics") as MutableMap<String, Any?>)
            m.remove("ttlSamplesCount")
        }
        assertFalse(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(missingCounter))

        val negativeCounter = buildValidPayload().apply {
            @Suppress("UNCHECKED_CAST")
            val m = (get("metrics") as MutableMap<String, Any?>)
            m["totalEvents"] = -1
        }
        assertFalse(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(negativeCounter))

        // 8. Oversized bundleZipSizeBytes (> 700_000) and oversized bundleZipBase64 (> 950_000)
        val oversizedZip = buildValidPayload().apply {
            @Suppress("UNCHECKED_CAST")
            val m = (get("metrics") as MutableMap<String, Any?>)
            m["bundleZipSizeBytes"] = FirebaseResearchSync.MAX_BUNDLE_ZIP_BYTES + 1L
        }
        assertFalse(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(oversizedZip))

        val oversizedBase64 = buildValidPayload().apply {
            @Suppress("UNCHECKED_CAST")
            val m = (get("metrics") as MutableMap<String, Any?>)
            m["bundleZipBase64"] = "A".repeat(FirebaseResearchSync.MAX_BUNDLE_BASE64_CHARS + 1)
        }
        assertFalse(FirebaseResearchSync.validatePayloadAgainstFirestoreRules(oversizedBase64))
    }

    @Test
    fun `test SharedPreferences persistence and rate limiting across sync instances`() = runBlocking {
        val currentClock = AtomicLong(1_760_000_000_000L)
        var wifiAvailable = true
        val writtenDocIds = mutableListOf<String>()
        val writtenPayloads = mutableListOf<Map<String, Any>>()

        val firstSync = FirebaseResearchSync(
            context = appContext,
            customAuthChecker = { true },
            customDocumentWriter = { docId, docData ->
                writtenDocIds.add(docId)
                writtenPayloads.add(docData)
                true
            },
            wifiChecker = { wifiAvailable },
            clockProvider = { currentClock.get() }
        )

        val sessionId = "ci_persist_${UUID.randomUUID().toString().take(8)}"
        val valid = buildValidPayload(sessionId = sessionId, timestampMs = currentClock.get())
        @Suppress("UNCHECKED_CAST")
        val deviceInfo = valid["deviceInfo"] as Map<String, Any>
        @Suppress("UNCHECKED_CAST")
        val metrics = valid["metrics"] as Map<String, Any>

        // First auto-sync uses exact sessionId as docId and persists state
        assertTrue(firstSync.syncResearchSession(sessionId, deviceInfo, metrics, isManual = false))
        assertEquals(listOf(sessionId), writtenDocIds)
        assertEquals(currentClock.get(), firstSync.getLastAutoSyncTimestamp())
        assertTrue(firstSync.hasSessionSynced(sessionId))

        // Second instance loads persisted SharedPreferences state
        val secondSync = FirebaseResearchSync(
            context = appContext,
            customAuthChecker = { true },
            customDocumentWriter = { docId, docData ->
                writtenDocIds.add(docId)
                writtenPayloads.add(docData)
                true
            },
            wifiChecker = { wifiAvailable },
            clockProvider = { currentClock.get() }
        )
        assertEquals(currentClock.get(), secondSync.getLastAutoSyncTimestamp())
        assertTrue(secondSync.hasSessionSynced(sessionId))
        assertTrue(secondSync.getSyncedSessionIds().contains(sessionId))

        // Auto-sync within 24 minutes (< minInterval of 25 min) must be throttled
        currentClock.addAndGet(24 * 60 * 1000L)
        assertFalse(secondSync.syncResearchSession(sessionId, deviceInfo, metrics, isManual = false))
        assertEquals(1, writtenDocIds.size)

        // Auto-sync after >= 30 minutes succeeds and writes timestamp-suffixed docId
        currentClock.addAndGet(6 * 60 * 1000L)
        val expectedSecondTimestamp = currentClock.get()
        assertTrue(secondSync.syncResearchSession(sessionId, deviceInfo, metrics, isManual = false))
        assertEquals(2, writtenDocIds.size)
        assertEquals("${sessionId}_${expectedSecondTimestamp}", writtenDocIds[1])
        assertEquals(expectedSecondTimestamp, secondSync.getLastAutoSyncTimestamp())

        // Manual sync bypasses both timer throttling and Wi-Fi restriction
        wifiAvailable = false
        currentClock.addAndGet(5_000L)
        val expectedThirdTimestamp = currentClock.get()
        assertFalse(secondSync.syncResearchSession(sessionId, deviceInfo, metrics, isManual = false))
        assertTrue(secondSync.syncResearchSession(sessionId, deviceInfo, metrics, isManual = true))
        assertEquals(3, writtenDocIds.size)
        assertEquals("${sessionId}_${expectedThirdTimestamp}", writtenDocIds[2])
    }

    @Test
    fun `test Firestore REST payload serialization and optional live ingestion`() = runBlocking {
        settingsManager.setAnonymousStatsEnabled(true)
        val manager = ResearchTelemetryManager(
            context = appContext,
            settingsManager = settingsManager,
            dhtClient = null,
            baseDir = tempDir
        ).also { telemetryManager = it }

        manager.recordPacketEvent(
            role = PacketRole.FIRST_SEND,
            target = CryptoUtils.secureRandomBytes(20),
            seqNum = 1L,
            rttMs = 31L
        )
        val (deviceInfo, metrics) = manager.computeSessionPayload()

        val resolvedCreds = resolveFirebaseCredentials()
        if (resolvedCreds == null) {
            // Offline mode: verify deterministic Firestore REST JSON encoding and pre-flight validation
            val nowMs = System.currentTimeMillis().coerceAtLeast(FirebaseResearchSync.MIN_VALID_TIMESTAMP_MS + 1L)
            val docMap = mapOf(
                "sessionId" to manager.sessionId,
                "timestamp" to nowMs,
                "deviceInfo" to deviceInfo,
                "metrics" to metrics,
                "schemaVersion" to FirebaseResearchSync.EXPECTED_SCHEMA_VERSION
            )
            val restJson = toFirestoreDocumentJson(docMap)
            val fields = restJson.getJSONObject("fields")
            assertEquals(manager.sessionId, fields.getJSONObject("sessionId").getString("stringValue"))
            assertEquals(nowMs.toString(), fields.getJSONObject("timestamp").getString("integerValue"))
            assertEquals("2", fields.getJSONObject("schemaVersion").getString("integerValue"))
            assertTrue(fields.has("deviceInfo"))
            assertTrue(fields.has("metrics"))

            // Confirm FirebaseResearchSync rejects invalid payloads cleanly without crashing when writer rejects
            val rejectingSync = FirebaseResearchSync(
                context = appContext,
                customAuthChecker = { true },
                customDocumentWriter = { _, _ -> false },
                wifiChecker = { true }
            )
            assertFalse(rejectingSync.syncResearchSession("short", deviceInfo, metrics, isManual = true))
            assertTrue(rejectingSync.syncStatus.value.contains("validation failed"))
            assertFalse(rejectingSync.syncResearchSession(manager.sessionId, deviceInfo, metrics, isManual = true))
            assertEquals("Firestore write rejected", rejectingSync.syncStatus.value)
            return@runBlocking
        }

        // Live Firebase REST verification path when credentials exist in CI or local environment
        val (projectId, apiKey) = resolvedCreds
        val idToken = signInAnonymouslyRest(apiKey)
        val ciSessionId = "kt_e2e_${UUID.randomUUID().toString().replace("-", "").take(12)}"
        val updatedDeviceInfo = deviceInfo.toMutableMap().apply { put("sessionId", ciSessionId) }

        val liveRestSync = FirebaseResearchSync(
            context = appContext,
            customAuthChecker = { idToken.isNotBlank() },
            customDocumentWriter = { docId, docData ->
                val url =
                    "https://firestore.googleapis.com/v1/projects/${URLEncoder.encode(projectId, "UTF-8")}" +
                        "/databases/(default)/documents/research_sessions?documentId=${URLEncoder.encode(docId, "UTF-8")}"
                val (status, _) = executeJsonHttpRequest(
                    url = url,
                    method = "POST",
                    body = toFirestoreDocumentJson(docData).toString(),
                    bearerToken = idToken
                )
                status in 200..299
            },
            wifiChecker = { true }
        )

        val synced = liveRestSync.syncResearchSession(ciSessionId, updatedDeviceInfo, metrics, isManual = true)
        assertTrue("Expected live Firestore ingestion via REST to succeed, status=${liveRestSync.syncStatus.value}", synced)
        assertTrue(liveRestSync.hasSessionSynced(ciSessionId))
    }

    private fun resolveFirebaseCredentials(): Pair<String, String>? {
        val envProject = System.getenv("FIREBASE_PROJECT_ID")?.trim().orEmpty()
        val envApiKey = System.getenv("FIREBASE_API_KEY")?.trim().orEmpty()
        if (envProject.isNotEmpty() && envApiKey.isNotEmpty()) {
            return envProject to envApiKey
        }

        val candidates = listOf(
            File("app/google-services.json"),
            File("google-services.json")
        )
        for (file in candidates) {
            if (!file.isFile) continue
            try {
                val root = JSONObject(file.readText(Charsets.UTF_8))
                val projectId = root.optJSONObject("project_info")?.optString("project_id").orEmpty().trim()
                val clientArr = root.optJSONArray("client") ?: continue
                if (clientArr.length() == 0) continue
                val clientObj = clientArr.getJSONObject(0)
                val apiKeyArr = clientObj.optJSONArray("api_key") ?: continue
                if (apiKeyArr.length() == 0) continue
                val apiKey = apiKeyArr.getJSONObject(0).optString("current_key").trim()
                if (projectId.isNotEmpty() && apiKey.isNotEmpty()) {
                    return projectId to apiKey
                }
            } catch (_: Exception) {}
        }
        return null
    }

    private fun signInAnonymouslyRest(apiKey: String): String {
        val url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${URLEncoder.encode(apiKey, "UTF-8")}"
        val (status, body) = executeJsonHttpRequest(
            url = url,
            method = "POST",
            body = """{"returnSecureToken":true}""",
            bearerToken = null
        )
        assertTrue("Firebase Anonymous Auth failed with HTTP $status", status == 200)
        return JSONObject(body).getString("idToken")
    }

    private fun executeJsonHttpRequest(
        url: String,
        method: String,
        body: String?,
        bearerToken: String?
    ): Pair<Int, String> {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15_000
            readTimeout = 15_000
            setRequestProperty("Accept", "application/json")
            if (bearerToken != null) {
                setRequestProperty("Authorization", "Bearer $bearerToken")
            }
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
        }
        return try {
            if (body != null) {
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            code to text
        } finally {
            conn.disconnect()
        }
    }

    private fun toFirestoreDocumentJson(data: Map<String, Any?>): JSONObject {
        val fields = JSONObject()
        for ((k, v) in data) {
            fields.put(k, toFirestoreValueJson(v))
        }
        return JSONObject().put("fields", fields)
    }

    private fun toFirestoreValueJson(value: Any?): JSONObject {
        return when (value) {
            null -> JSONObject().put("nullValue", JSONObject.NULL)
            is Boolean -> JSONObject().put("booleanValue", value)
            is Int, is Long, is Short, is Byte -> JSONObject().put("integerValue", value.toString())
            is Float, is Double -> JSONObject().put("doubleValue", (value as Number).toDouble())
            is String -> JSONObject().put("stringValue", value)
            is Map<*, *> -> {
                val mapFields = JSONObject()
                for ((mk, mv) in value) {
                    if (mk != null) mapFields.put(mk.toString(), toFirestoreValueJson(mv))
                }
                JSONObject().put("mapValue", JSONObject().put("fields", mapFields))
            }
            is Iterable<*> -> {
                val values = JSONArray()
                for (item in value) {
                    values.put(toFirestoreValueJson(item))
                }
                JSONObject().put("arrayValue", JSONObject().put("values", values))
            }
            else -> JSONObject().put("stringValue", value.toString())
        }
    }
}
