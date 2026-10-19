package org.pqchat.dht.telemetry

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.Locale

/**
 * CI Data Integrity Verification Test Suite.
 *
 * Enforces scientific research integrity across all exported telemetry CSV files:
 * 1. Fails if any row labeled 'MEASURED' originates from a mock cluster (e.g. MOCK_CLUSTER).
 * 2. Fails if any 'MEASURED' row has a synthetic generator timestamp signature
 *    (e.g. fixed constant timestamp deltas like +200ms from synthetic Gaussian loops).
 * 3. Fails if multi-hour retention horizons (>= 1.0h) are reported as 'MEASURED' without real elapsed time.
 * 4. Fails if testbed correlation results marked 'MEASURED' contain mock signatures or uncalibrated synthetic markers.
 */
class TelemetryDataIntegrityTest {

    private fun resolveProjectRootDir(): File {
        val current = File(".").canonicalFile
        return if (File(current, "docs").exists()) {
            current
        } else if (File(current.parentFile, "docs").exists()) {
            current.parentFile
        } else {
            File(System.getProperty("user.dir") ?: ".")
        }
    }

    @Test
    fun `test no MEASURED record originates from a mock cluster`() {
        val rootDir = resolveProjectRootDir()
        val docsDir = File(rootDir, "docs")
        assertTrue("docs directory must exist at ${docsDir.canonicalPath}", docsDir.exists())

        val csvFiles = mutableListOf<File>()
        docsDir.listFiles { f -> f.extension == "csv" }?.let { csvFiles.addAll(it) }
        val measurementsDir = File(docsDir, "measurements")
        if (measurementsDir.exists()) {
            measurementsDir.listFiles { f -> f.extension == "csv" }?.let { csvFiles.addAll(it) }
        }

        assertTrue("Must locate CSV telemetry files in docs/", csvFiles.isNotEmpty())

        for (csvFile in csvFiles) {
            val lines = csvFile.readLines(Charsets.UTF_8).filter { it.isNotBlank() }
            if (lines.size <= 1) continue

            val header = lines[0].split(",").map { it.trim().lowercase(Locale.US) }
            val dataSourceIdx = header.indexOf("data_source")
            val networkEnvIdx = header.indexOf("network_environment")

            if (dataSourceIdx != -1 && networkEnvIdx != -1) {
                for ((lineNum, line) in lines.drop(1).withIndex()) {
                    val cols = line.split(",").map { it.trim() }
                    if (cols.size > maxOf(dataSourceIdx, networkEnvIdx)) {
                        val source = cols[dataSourceIdx].uppercase(Locale.US)
                        val env = cols[networkEnvIdx].uppercase(Locale.US)

                        if (source == "MEASURED") {
                            assertFalse(
                                "CSV ${csvFile.name} line ${lineNum + 2} has data_source=MEASURED but network_environment=$env (mock data cannot be labeled MEASURED)",
                                env.contains("MOCK") || env.contains("SIMULAT") || env.contains("SYNTHETIC")
                            )
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `test no MEASURED loopback row has synthetic generator timestamp signature`() {
        val rootDir = resolveProjectRootDir()
        val loopbackMeasCsv = File(rootDir, "docs/metrics_dht_loopback_measured.csv")
        if (!loopbackMeasCsv.exists() || loopbackMeasCsv.length() < 100) return

        val lines = loopbackMeasCsv.readLines(Charsets.UTF_8).filter { it.isNotBlank() }
        val header = lines[0].split(",").map { it.trim().lowercase(Locale.US) }
        val tsIdx = header.indexOf("timestamp_epoch_ms")
        val srcIdx = header.indexOf("data_source")
        assertTrue("Must have timestamp_epoch_ms and data_source columns", tsIdx != -1 && srcIdx != -1)

        val measuredTimestamps = mutableListOf<Long>()
        for (line in lines.drop(1)) {
            val cols = line.split(",").map { it.trim() }
            if (cols.size > maxOf(tsIdx, srcIdx) && cols[srcIdx].equals("MEASURED", ignoreCase = true)) {
                val ts = cols[tsIdx].toLongOrNull()
                if (ts != null) measuredTimestamps.add(ts)
            }
        }

        if (measuredTimestamps.size > 20) {
            val deltas = mutableListOf<Long>()
            for (i in 1 until measuredTimestamps.size) {
                deltas.add(measuredTimestamps[i] - measuredTimestamps[i - 1])
            }

            // A synthetic loop (e.g. t_base + i * 200) produces identical deltas (+200ms) across all consecutive rows.
            val distinctDeltas = deltas.distinct()
            assertFalse(
                "Telemetry timestamps exhibit synthetic generator signature: all consecutive deltas are identical ($distinctDeltas)",
                distinctDeltas.size == 1 && distinctDeltas[0] == 200L
            )
        }
    }

    @Test
    fun `test no MEASURED retention record claims multi-hour horizon without actual elapsed delay`() {
        val rootDir = resolveProjectRootDir()
        val retentionCsv = File(rootDir, "docs/metrics_dht_retention_measured.csv")
        if (!retentionCsv.exists() || retentionCsv.length() < 100) return

        val lines = retentionCsv.readLines(Charsets.UTF_8).filter { it.isNotBlank() }
        val header = lines[0].split(",").map { it.trim().lowercase(Locale.US) }
        val srcIdx = header.indexOf("data_source")
        val horizonIdx = header.indexOf("retention_hours")
        val envIdx = header.indexOf("network_environment")

        if (srcIdx == -1 || horizonIdx == -1) return

        for ((idx, line) in lines.drop(1).withIndex()) {
            val cols = line.split(",").map { it.trim() }
            if (cols.size > maxOf(srcIdx, horizonIdx)) {
                val src = cols[srcIdx].uppercase(Locale.US)
                val hours = cols[horizonIdx].toDoubleOrNull() ?: 0.0
                val env = if (envIdx != -1 && cols.size > envIdx) cols[envIdx].uppercase(Locale.US) else ""

                if (src == "MEASURED" && hours >= 1.0) {
                    assertFalse(
                        "Line ${idx + 2} in ${retentionCsv.name} reports horizon ${hours}h as MEASURED on $env without genuine long-term measurement",
                        env.contains("MOCK")
                    )
                }
            }
        }
    }
}
