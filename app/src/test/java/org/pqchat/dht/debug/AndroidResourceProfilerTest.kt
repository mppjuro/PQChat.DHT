package org.pqchat.dht.debug

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.pqchat.dht.dht.FakeDht
import org.pqchat.dht.traffic.AdaptivePollingManager.PollingState
import java.io.File

class AndroidResourceProfilerTest {

    private lateinit var fakeDht: FakeDht

    @Before
    fun setUp() {
        fakeDht = FakeDht()
        fakeDht.start()
        AndroidResourceProfiler.resetWakeLockStats()
    }

    @Test
    fun testCsvHeaderAndRowFormat() {
        val sample = AndroidResourceProfiler.ResourceSample(
            sampleIndex = 1L,
            timestampEpochMs = 1718000000000L,
            dataSource = AndroidResourceProfiler.DATA_SOURCE_MEASURED,
            sessionLabel = "thesis_eval_run",
            batteryCurrentNowUa = -345000L,
            batteryChargeCounterUah = 2850000L,
            batteryLevelPercent = 85,
            wakeLockDurationMs = 1250L,
            activeWakeLocks = 1,
            dhtGetCalls = 14L,
            dhtPutCalls = 2L,
            dhtBytesSent = 18000L,
            dhtBytesReceived = 24000L,
            pollingState = PollingState.FOREGROUND_CHAT.name,
            poissonLambda = 1.0 / 480.0
        )

        assertEquals("MEASURED_ANDROID_DEVICE", sample.dataSource)
        val row = sample.toCsvRow()
        val parts = row.split(",")

        // Header has 15 columns
        val headerCols = AndroidResourceProfiler.ResourceSample.CSV_HEADER.split(",")
        assertEquals(15, headerCols.size)
        assertEquals(15, parts.size)

        assertEquals("1", parts[0]) // sample_index
        assertEquals("1718000000000", parts[1]) // timestamp_epoch_ms
        assertEquals("MEASURED_ANDROID_DEVICE", parts[2]) // data_source
        assertEquals("\"thesis_eval_run\"", parts[3]) // session_label
        assertEquals("-345000", parts[4]) // battery_current_now_ua
        assertEquals("2850000", parts[5]) // battery_charge_counter_uah
        assertEquals("85", parts[6]) // battery_level_percent
        assertEquals("1250", parts[7]) // wakelock_duration_ms
        assertEquals("1", parts[8]) // active_wakelocks
        assertEquals("14", parts[9]) // dht_get_calls
        assertEquals("2", parts[10]) // dht_put_calls
        assertEquals("18000", parts[11]) // dht_bytes_sent
        assertEquals("24000", parts[12]) // dht_bytes_received
        assertEquals("FOREGROUND_CHAT", parts[13]) // polling_state
        assertTrue(parts[14].toDouble() > 0.0) // poisson_lambda
    }

    @Test
    fun testWakeLockTracking() {
        assertEquals(0, AndroidResourceProfiler.getActiveWakeLockCount())
        assertEquals(0L, AndroidResourceProfiler.getCumulativeWakeLockDurationMs())

        val t0 = AndroidResourceProfiler.onWakeLockAcquired("test_lock")
        assertEquals(1, AndroidResourceProfiler.getActiveWakeLockCount())

        Thread.sleep(25)
        val dur = AndroidResourceProfiler.onWakeLockReleased(t0, "test_lock")
        assertEquals(0, AndroidResourceProfiler.getActiveWakeLockCount())
        assertTrue("WakeLock duration should be at least 15ms, was $dur", dur >= 15L)
        assertTrue(AndroidResourceProfiler.getCumulativeWakeLockDurationMs() >= 15L)
    }

    @Test
    fun testProfilerSamplingAndExport() {
        var currentBatCurrent = -200000L
        var currentCharge = 3000000L
        var currentLevel = 90
        var currentState = "APP_ACTIVE_OTHER"
        val lambdaVal = 1.0 / 480.0

        val profiler = AndroidResourceProfiler(
            dhtClient = fakeDht,
            pollingStateProvider = { currentState },
            lambdaProvider = { lambdaVal },
            batteryCurrentProvider = { currentBatCurrent },
            batteryChargeCounterProvider = { currentCharge },
            batteryLevelProvider = { currentLevel },
            sampleIntervalMs = 50L
        )

        profiler.startSession("unit_test_session")
        assertTrue(profiler.isProfiling.value)
        assertEquals("unit_test_session", profiler.currentSessionLabel)

        // Simulate some DHT traffic
        fakeDht.bytesSent.addAndGet(1500L)
        fakeDht.bytesReceived.addAndGet(3200L)
        fakeDht.getCalls.incrementAndGet()
        fakeDht.putCalls.incrementAndGet()

        // Take snapshots
        val s1 = profiler.takeSnapshot("unit_test_session")
        assertEquals(1L, s1.sampleIndex)
        assertEquals("MEASURED_ANDROID_DEVICE", s1.dataSource)
        assertEquals(-200000L, s1.batteryCurrentNowUa)
        assertEquals(3000000L, s1.batteryChargeCounterUah)
        assertEquals(90, s1.batteryLevelPercent)
        assertEquals(1L, s1.dhtGetCalls)
        assertEquals(1L, s1.dhtPutCalls)
        assertEquals(1500L, s1.dhtBytesSent)
        assertEquals(3200L, s1.dhtBytesReceived)
        assertEquals("APP_ACTIVE_OTHER", s1.pollingState)

        // Modify state and take snapshot 2
        currentState = "FOREGROUND_CHAT"
        currentBatCurrent = -450000L
        val s2 = profiler.takeSnapshot("unit_test_session")
        assertEquals(2L, s2.sampleIndex)
        assertEquals(-450000L, s2.batteryCurrentNowUa)
        assertEquals("FOREGROUND_CHAT", s2.pollingState)

        profiler.stopSession()
        assertFalse(profiler.isProfiling.value)

        val csvOutput = profiler.exportToCsv()
        assertTrue(csvOutput.startsWith(AndroidResourceProfiler.ResourceSample.CSV_HEADER))
        val lines = csvOutput.trim().split("\n")
        // Header + at least 2 snapshots
        assertTrue(lines.size >= 3)

        for (i in 1 until lines.size) {
            val line = lines[i]
            assertTrue("Line $i must contain MEASURED_ANDROID_DEVICE", line.contains("MEASURED_ANDROID_DEVICE"))
        }

        // Test File export
        val tempDir = File(System.getProperty("java.io.tmpdir"), "pqchat_test_${System.currentTimeMillis()}")
        tempDir.mkdirs()
        try {
            val exportedFile = profiler.exportToCsvFile(tempDir, "test_telemetry.csv")
            assertTrue(exportedFile.exists())
            assertTrue(exportedFile.length() > 0)
            val fileContent = exportedFile.readText()
            assertEquals(csvOutput, fileContent)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testPrivacyAndZeroPlaintextLeakage() {
        // AGENTS.md Section 8.1 security test:
        // Ensures no crypto keys, random seeds, or plaintext messages appear in exported CSV.
        val profiler = AndroidResourceProfiler(
            dhtClient = fakeDht,
            pollingStateProvider = { "BACKGROUND_IDLE" },
            lambdaProvider = { 1.0 / 480.0 },
            batteryCurrentProvider = { -150000L },
            batteryChargeCounterProvider = { 4000000L },
            batteryLevelProvider = { 100 }
        )

        profiler.takeSnapshot("thesis_security_audit")
        val csv = profiler.exportToCsv()

        // Check that only approved columns and numeric/state data exist
        assertFalse("CSV must not contain secretKey references", csv.contains("secret", ignoreCase = true))
        assertFalse("CSV must not contain private key data", csv.contains("privateKey", ignoreCase = true))
        assertFalse("CSV must not contain seed data", csv.contains("seed", ignoreCase = true))
        assertFalse("CSV must not contain decrypted plaintext", csv.contains("hello", ignoreCase = true))

        // Check header column names
        val header = csv.lines().first()
        val expectedCols = listOf(
            "sample_index", "timestamp_epoch_ms", "data_source", "session_label",
            "battery_current_now_ua", "battery_charge_counter_uah", "battery_level_percent",
            "wakelock_duration_ms", "active_wakelocks", "dht_get_calls", "dht_put_calls",
            "dht_bytes_sent", "dht_bytes_received", "polling_state", "poisson_lambda"
        )
        for (col in expectedCols) {
            assertTrue("Header must contain $col", header.contains(col))
        }
    }
}
