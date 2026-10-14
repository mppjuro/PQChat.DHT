package org.pqchat.dht.debug

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Environment
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.service.PollingLifecycleCoordinator
import org.pqchat.dht.traffic.AdaptivePollingManager
import org.pqchat.dht.traffic.PoissonTrafficGenerator
import java.io.File
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Empirical Android Resource Telemetry Profiler for Master's Thesis Research.
 *
 * Captures real-time physical device metrics:
 * 1. Battery metrics via BatteryManager:
 *    - Instantaneous current draw (BATTERY_PROPERTY_CURRENT_NOW) in µA
 *    - Remaining charge counter (BATTERY_PROPERTY_CHARGE_COUNTER) in µAh
 *    - Battery level percentage (0-100%)
 * 2. CPU / WakeLock holding time:
 *    - Cumulative WakeLock duration in ms
 *    - Current active WakeLocks count
 * 3. DHT KRPC Operations & Network Telemetry:
 *    - Total GET / PUT query cycles
 *    - Total bytes transmitted and received via UDP socket in DhtLeafNode
 * 4. Polling Lifecycle State & Poisson Chaffing:
 *    - Current PollingState from PollingLifecycleCoordinator
 *    - Cover traffic parameter lambda from PoissonTrafficGenerator
 *
 * Privacy & Security (AGENTS.md §8.1):
 * strictly free of cryptographic keys, seeds, or message contents.
 * All rows tagged with data_source = "MEASURED_ANDROID_DEVICE".
 */
class AndroidResourceProfiler(
    private val context: Context? = null,
    private val dhtClient: DhtClient? = null,
    private val pollingStateProvider: (() -> String)? = null,
    private val lambdaProvider: (() -> Double)? = null,
    private val batteryCurrentProvider: (() -> Long)? = null,
    private val batteryChargeCounterProvider: (() -> Long)? = null,
    private val batteryLevelProvider: (() -> Int)? = null,
    private val sampleIntervalMs: Long = 1000L
) {
    /**
     * Primary application constructor wiring high-level coordinators.
     */
    constructor(
        context: Context,
        dhtClient: DhtClient,
        lifecycleCoordinator: PollingLifecycleCoordinator,
        trafficGenerator: PoissonTrafficGenerator,
        sampleIntervalMs: Long = 1000L
    ) : this(
        context = context,
        dhtClient = dhtClient,
        pollingStateProvider = { lifecycleCoordinator.currentState.name },
        lambdaProvider = { trafficGenerator.lambda },
        sampleIntervalMs = sampleIntervalMs
    )

    /**
     * Secondary application constructor with AdaptivePollingManager.
     */
    constructor(
        context: Context,
        dhtClient: DhtClient,
        pollingManager: AdaptivePollingManager,
        trafficGenerator: PoissonTrafficGenerator,
        sampleIntervalMs: Long = 1000L
    ) : this(
        context = context,
        dhtClient = dhtClient,
        pollingStateProvider = { pollingManager.currentState.value.name },
        lambdaProvider = { trafficGenerator.lambda },
        sampleIntervalMs = sampleIntervalMs
    )

    data class ResourceSample(
        val sampleIndex: Long,
        val timestampEpochMs: Long,
        val dataSource: String = DATA_SOURCE_MEASURED,
        val sessionLabel: String,
        val batteryCurrentNowUa: Long,
        val batteryChargeCounterUah: Long,
        val batteryLevelPercent: Int,
        val wakeLockDurationMs: Long,
        val activeWakeLocks: Int,
        val dhtGetCalls: Long,
        val dhtPutCalls: Long,
        val dhtBytesSent: Long,
        val dhtBytesReceived: Long,
        val pollingState: String,
        val poissonLambda: Double
    ) {
        companion object {
            const val DATA_SOURCE_MEASURED = "MEASURED_ANDROID_DEVICE"

            const val CSV_HEADER =
                "sample_index,timestamp_epoch_ms,data_source,session_label,battery_current_now_ua,battery_charge_counter_uah,battery_level_percent,wakelock_duration_ms,active_wakelocks,dht_get_calls,dht_put_calls,dht_bytes_sent,dht_bytes_received,polling_state,poisson_lambda"
        }

        fun toCsvRow(): String {
            val safeLabel = sessionLabel.replace("\"", "\"\"").replace("\n", " ")
            val lambdaStr = String.format(Locale.US, "%.8f", poissonLambda)
            return "$sampleIndex,$timestampEpochMs,$dataSource,\"$safeLabel\",$batteryCurrentNowUa,$batteryChargeCounterUah,$batteryLevelPercent,$wakeLockDurationMs,$activeWakeLocks,$dhtGetCalls,$dhtPutCalls,$dhtBytesSent,$dhtBytesReceived,$pollingState,$lambdaStr"
        }
    }

    private val profilerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var samplingJob: Job? = null

    private val sampleIndexCounter = AtomicLong(0L)
    private var sessionStartWakeLockDurationMs: Long = 0L

    @Volatile
    var currentSessionLabel: String = "idle"
        private set

    private val _samples = CopyOnWriteArrayList<ResourceSample>()
    val samples: List<ResourceSample> get() = _samples

    private val _isProfiling = MutableStateFlow(false)
    val isProfiling: StateFlow<Boolean> = _isProfiling.asStateFlow()

    private val _sampleCount = MutableStateFlow(0)
    val sampleCount: StateFlow<Int> = _sampleCount.asStateFlow()

    private val _latestSample = MutableStateFlow<ResourceSample?>(null)
    val latestSample: StateFlow<ResourceSample?> = _latestSample.asStateFlow()

    @Synchronized
    fun startSession(
        label: String = "session_${System.currentTimeMillis()}",
        autoSample: Boolean = true
    ) {
        if (_isProfiling.value) return
        currentSessionLabel = label.ifBlank { "session_${System.currentTimeMillis()}" }
        sessionStartWakeLockDurationMs = getCumulativeWakeLockDurationMs()
        sampleIndexCounter.set(0L)
        _samples.clear()
        _sampleCount.value = 0
        _latestSample.value = null
        _isProfiling.value = true

        if (autoSample && sampleIntervalMs > 0L) {
            samplingJob = profilerScope.launch {
                while (isActive && _isProfiling.value) {
                    delay(sampleIntervalMs)
                    if (isActive && _isProfiling.value) {
                        takeSnapshot(currentSessionLabel)
                    }
                }
            }
        }
    }

    @Synchronized
    fun stopSession() {
        if (!_isProfiling.value) return
        samplingJob?.cancel()
        samplingJob = null
        _isProfiling.value = false
    }

    fun clearSamples() {
        _samples.clear()
        _sampleCount.value = 0
        _latestSample.value = null
    }

    fun takeSnapshot(sessionLabel: String = currentSessionLabel): ResourceSample {
        val index = sampleIndexCounter.incrementAndGet()
        val now = System.currentTimeMillis()
        val wakeLockDur = (getCumulativeWakeLockDurationMs() - sessionStartWakeLockDurationMs).coerceAtLeast(0L)

        val sample = ResourceSample(
            sampleIndex = index,
            timestampEpochMs = now,
            dataSource = ResourceSample.DATA_SOURCE_MEASURED,
            sessionLabel = sessionLabel,
            batteryCurrentNowUa = queryBatteryCurrentNowUa(),
            batteryChargeCounterUah = queryBatteryChargeCounterUah(),
            batteryLevelPercent = queryBatteryLevelPercent(),
            wakeLockDurationMs = wakeLockDur,
            activeWakeLocks = getActiveWakeLockCount(),
            dhtGetCalls = dhtClient?.totalGetCalls ?: 0L,
            dhtPutCalls = dhtClient?.totalPutCalls ?: 0L,
            dhtBytesSent = dhtClient?.totalBytesSent ?: 0L,
            dhtBytesReceived = dhtClient?.totalBytesReceived ?: 0L,
            pollingState = pollingStateProvider?.invoke() ?: "UNKNOWN",
            poissonLambda = lambdaProvider?.invoke() ?: (1.0 / 480.0)
        )

        _samples.add(sample)
        _sampleCount.value = _samples.size
        _latestSample.value = sample
        return sample
    }

    fun exportToCsv(): String {
        val sb = StringBuilder()
        sb.append(ResourceSample.CSV_HEADER).append("\n")
        for (sample in _samples) {
            sb.append(sample.toCsvRow()).append("\n")
        }
        return sb.toString()
    }

    fun exportToCsvFile(destinationDir: File? = null, fileName: String? = null): File {
        val dir = destinationDir
            ?: context?.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS)
            ?: context?.filesDir
            ?: File(System.getProperty("java.io.tmpdir") ?: ".")

        if (!dir.exists()) {
            dir.mkdirs()
        }

        val sanitizedLabel = currentSessionLabel.replace(Regex("[^a-zA-Z0-9_-]"), "_")
        val actualFileName = fileName ?: "pqchat_telemetry_${sanitizedLabel}_${System.currentTimeMillis()}.csv"
        val file = File(dir, actualFileName)
        file.writeText(exportToCsv(), Charsets.UTF_8)
        return file
    }

    fun queryBatteryCurrentNowUa(): Long {
        batteryCurrentProvider?.let { return it.invoke() }
        val ctx = context ?: return 0L
        val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager ?: return 0L
        val prop = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW)
        return if (prop == Int.MIN_VALUE) 0L else prop.toLong()
    }

    fun queryBatteryChargeCounterUah(): Long {
        batteryChargeCounterProvider?.let { return it.invoke() }
        val ctx = context ?: return 0L
        val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager ?: return 0L
        val prop = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER)
        return if (prop == Int.MIN_VALUE) 0L else prop.toLong()
    }

    fun queryBatteryLevelPercent(): Int {
        batteryLevelProvider?.let { return it.invoke() }
        val ctx = context ?: return 100
        val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
        val cap = bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) ?: Int.MIN_VALUE
        if (cap != Int.MIN_VALUE && cap in 0..100) return cap

        return try {
            val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
            val batteryStatus = ctx.registerReceiver(null, filter)
            val level = batteryStatus?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
            val scale = batteryStatus?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
            if (level >= 0 && scale > 0) {
                ((level.toFloat() / scale.toFloat()) * 100).toInt()
            } else {
                100
            }
        } catch (_: Exception) {
            100
        }
    }

    companion object {
        const val DATA_SOURCE_MEASURED = ResourceSample.DATA_SOURCE_MEASURED

        private val globalActiveWakeLocks = AtomicInteger(0)
        private val globalCumulativeWakeLockDurationMs = AtomicLong(0L)

        fun onWakeLockAcquired(tag: String? = null): Long {
            globalActiveWakeLocks.incrementAndGet()
            return System.currentTimeMillis()
        }

        fun onWakeLockReleased(startTimeEpochMs: Long, tag: String? = null): Long {
            globalActiveWakeLocks.updateAndGet { current -> if (current > 0) current - 1 else 0 }
            val now = System.currentTimeMillis()
            val duration = if (startTimeEpochMs > 0L && now >= startTimeEpochMs) {
                now - startTimeEpochMs
            } else {
                0L
            }
            globalCumulativeWakeLockDurationMs.addAndGet(duration)
            return duration
        }

        fun getActiveWakeLockCount(): Int = globalActiveWakeLocks.get()

        fun getCumulativeWakeLockDurationMs(): Long = globalCumulativeWakeLockDurationMs.get()

        fun resetWakeLockStats() {
            globalActiveWakeLocks.set(0)
            globalCumulativeWakeLockDurationMs.set(0L)
        }
    }
}
