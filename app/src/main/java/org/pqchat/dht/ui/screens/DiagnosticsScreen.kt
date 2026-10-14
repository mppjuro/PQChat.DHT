package org.pqchat.dht.ui.screens

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalContext
import android.widget.Toast
import org.pqchat.dht.crypto.BinaryFrameCodec
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.ui.theme.*
import org.pqchat.dht.ui.viewmodel.ChatViewModel
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DiagnosticsScreen(
    viewModel: ChatViewModel,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val appColors = LocalAppColors.current

    val dhtPeers by viewModel.dhtPeerCount.collectAsState()
    val pollingState by viewModel.pollingState.collectAsState()
    val contacts by viewModel.contacts.collectAsState()

    val isProfiling by viewModel.isProfiling.collectAsState()
    val sampleCount by viewModel.profileSampleCount.collectAsState()
    val latestSample by viewModel.latestResourceSample.collectAsState()
    var sessionLabelInput by remember { mutableStateOf("thesis_run_1") }
    var lastExportStatus by remember { mutableStateOf<String?>(null) }

    var coverEvents by remember { mutableStateOf<List<String>>(emptyList()) }

    LaunchedEffect(Unit) {
        viewModel.trafficGenerator.eventFlow.collect { event ->
            val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
            val time = sdf.format(Date(event.timestamp))
            val entry = "[$time] Target: ${event.targetHex.take(12)}... Δt=${String.format(Locale.US, "%.1f", event.intervalSeconds)}s (${BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES}B)"
            coverEvents = (listOf(entry) + coverEvents).take(20)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Cryptographic Diagnostics", color = appColors.textPrimary) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = appColors.textPrimary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = appColors.surface)
            )
        },
        containerColor = appColors.background
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            item {
                SectionCard(title = "Local Leaf Node Identity (BEP 43 / BEP 44)") {
                    Text(
                        text = "Node ID: ${CryptoUtils.toHex(viewModel.dhtLeafNode.myNodeId)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = appColors.primary,
                        fontFamily = FontFamily.Monospace
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Mode: Read-Only Client (No routing, 0 bytes foreign data)",
                        style = MaterialTheme.typography.bodyMedium,
                        color = ElectricGreen
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Routing Table: $dhtPeers Active DHT Peers",
                        style = MaterialTheme.typography.bodyMedium,
                        color = appColors.textPrimary
                    )
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            item {
                SectionCard(title = "Adaptive Polling Profile (Android Lifecycle)") {
                    Text(
                        text = "Current State: ${pollingState.label}",
                        style = MaterialTheme.typography.bodyLarge,
                        color = appColors.primary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Interval: ${viewModel.pollingManager.getCurrentIntervalMs() / 1000}s between GET queries on incoming slots.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = appColors.textSecondary
                    )
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            item {
                SectionCard(title = "Active Symmetric Ratchet Chains (Dual KDF)") {
                    if (contacts.isEmpty()) {
                        Text("No active sessions.", style = MaterialTheme.typography.bodyMedium, color = appColors.textSecondary)
                    } else {
                        for (c in contacts) {
                            Column(modifier = Modifier.padding(vertical = 4.dp)) {
                                Text(
                                    text = "Contact: ${c.name} (${c.id.take(8)}...)",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = appColors.textPrimary
                                )
                                Text(
                                    text = "Outgoing Chain: active (Counter: ${c.counterOut})",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = appColors.primary
                                )
                                Text(
                                    text = "Incoming Chain: active (Counter: ${c.counterIn})",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = ElectricGreen
                                )
                                val msgsToRekey = 50 - (c.counterOut % 50)
                                Text(
                                    text = "Next PQC Rekey (ML-KEM-512): in $msgsToRekey messages (Epoch ${c.rekeyEpoch})",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = AmberWarning
                                )
                                HorizontalDivider(color = appColors.border, modifier = Modifier.padding(vertical = 8.dp))
                            }
                        }
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            item {
                SectionCard(title = "Poisson Cover Traffic (Chaffing Stream)") {
                    Text(
                        text = "λ = 1/480 s⁻¹ (Exponential Distribution, Constant ${BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES}B)",
                        style = MaterialTheme.typography.labelSmall,
                        color = CryptoPurple
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    if (coverEvents.isEmpty()) {
                        Text("Waiting for next Poisson event...", style = MaterialTheme.typography.bodyMedium, color = appColors.textSecondary)
                    } else {
                        for (ev in coverEvents) {
                            Text(
                                text = ev,
                                style = MaterialTheme.typography.labelSmall,
                                color = appColors.textPrimary,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            item {
                SectionCard(title = "Empirical Resource Telemetry (Android Profiler)") {
                    Text(
                        text = "Master's Thesis Empirical Measurement Module (data_source = MEASURED_ANDROID_DEVICE)",
                        style = MaterialTheme.typography.labelSmall,
                        color = appColors.primary
                    )
                    Spacer(modifier = Modifier.height(6.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = if (isProfiling) "● ACTIVE SESSION" else "○ IDLE",
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (isProfiling) ElectricGreen else appColors.textSecondary,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            text = "Samples: $sampleCount",
                            style = MaterialTheme.typography.bodyMedium,
                            color = appColors.textPrimary,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    if (latestSample != null) {
                        val sample = latestSample!!
                        Column(modifier = Modifier.fillMaxWidth()) {
                            Text(
                                text = "Battery: ${sample.batteryCurrentNowUa} µA | ${sample.batteryChargeCounterUah} µAh | ${sample.batteryLevelPercent}%",
                                style = MaterialTheme.typography.labelSmall,
                                color = appColors.textPrimary,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                text = "WakeLock: ${sample.wakeLockDurationMs} ms (Active: ${sample.activeWakeLocks})",
                                style = MaterialTheme.typography.labelSmall,
                                color = AmberWarning,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                text = "KRPC Cycles: GET=${sample.dhtGetCalls}, PUT=${sample.dhtPutCalls}",
                                style = MaterialTheme.typography.labelSmall,
                                color = ElectricGreen,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                text = "UDP Traffic: TX=${sample.dhtBytesSent} B, RX=${sample.dhtBytesReceived} B",
                                style = MaterialTheme.typography.labelSmall,
                                color = appColors.textSecondary,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                text = "State: ${sample.pollingState} | λ=${String.format(Locale.US, "%.5f", sample.poissonLambda)} s⁻¹",
                                style = MaterialTheme.typography.labelSmall,
                                color = CryptoPurple,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    } else {
                        Text(
                            text = "No active samples recorded yet.",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textSecondary
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    if (!isProfiling) {
                        OutlinedTextField(
                            value = sessionLabelInput,
                            onValueChange = { sessionLabelInput = it },
                            label = { Text("Session Label") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = appColors.primary,
                                unfocusedBorderColor = appColors.border,
                                focusedTextColor = appColors.textPrimary,
                                unfocusedTextColor = appColors.textPrimary,
                                focusedLabelColor = appColors.primary,
                                unfocusedLabelColor = appColors.textSecondary
                            )
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (!isProfiling) {
                            Button(
                                onClick = {
                                    lastExportStatus = null
                                    viewModel.startProfilingSession(sessionLabelInput.ifBlank { "thesis_eval" })
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = appColors.primary),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Start Session", color = appColors.surface)
                            }
                        } else {
                            Button(
                                onClick = {
                                    viewModel.stopProfilingSession()
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = AmberWarning),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Stop Session", color = appColors.surface)
                            }
                        }

                        if (sampleCount > 0 && !isProfiling) {
                            OutlinedButton(
                                onClick = {
                                    try {
                                        val file = viewModel.exportProfilingCsvFile()
                                        lastExportStatus = "Exported: ${file.name} (${file.length()} B)"
                                        Toast.makeText(context, "Saved to: ${file.absolutePath}", Toast.LENGTH_LONG).show()
                                    } catch (e: Exception) {
                                        lastExportStatus = "Export error: ${e.message}"
                                    }
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Export CSV", color = appColors.primary)
                            }

                            OutlinedButton(
                                onClick = {
                                    viewModel.clearProfilingSamples()
                                    lastExportStatus = null
                                }
                            ) {
                                Text("Clear", color = appColors.textSecondary)
                            }
                        }
                    }

                    if (lastExportStatus != null) {
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = lastExportStatus!!,
                            style = MaterialTheme.typography.bodySmall,
                            color = ElectricGreen,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun SectionCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    val appColors = LocalAppColors.current

    Surface(
        color = appColors.surface,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, appColors.border, RoundedCornerShape(12.dp))
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = appColors.primary
            )
            Spacer(modifier = Modifier.height(8.dp))
            content()
        }
    }
}
