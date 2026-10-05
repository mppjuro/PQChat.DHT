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
    val appColors = LocalAppColors.current

    val dhtPeers by viewModel.dhtPeerCount.collectAsState()
    val pollingState by viewModel.pollingState.collectAsState()
    val contacts by viewModel.contacts.collectAsState()

    var coverEvents by remember { mutableStateOf<List<String>>(emptyList()) }

    LaunchedEffect(Unit) {
        viewModel.trafficGenerator.eventFlow.collect { event ->
            val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
            val time = sdf.format(Date(event.timestamp))
            val entry = "[$time] Target: ${event.targetHex.take(12)}... Δt=${String.format(Locale.US, "%.1f", event.intervalSeconds)}s (1000B)"
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
                                    text = "Outgoing ChainKey: ${CryptoUtils.toHex(c.chainKeyOut).take(16)}... (Counter: ${c.counterOut})",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = appColors.primary
                                )
                                Text(
                                    text = "Incoming ChainKey: ${CryptoUtils.toHex(c.chainKeyIn).take(16)}... (Counter: ${c.counterIn})",
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
                        text = "λ = 1/480 s⁻¹ (Exponential Distribution, Constant 1000B)",
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
