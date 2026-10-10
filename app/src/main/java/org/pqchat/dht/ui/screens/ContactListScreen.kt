package org.pqchat.dht.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.pqchat.dht.data.db.ContactEntity
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.ui.theme.*
import org.pqchat.dht.ui.viewmodel.ChatViewModel
import androidx.compose.animation.core.*
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactListScreen(
    viewModel: ChatViewModel,
    onContactClick: (String) -> Unit,
    onNewChatClick: () -> Unit,
    onJoinChatClick: () -> Unit,
    onDiagnosticsClick: () -> Unit,
    onSettingsClick: () -> Unit
) {
    val appColors = LocalAppColors.current

    val contacts by viewModel.contacts.collectAsState()
    val dhtPeers by viewModel.dhtPeerCount.collectAsState()
    val pollingState by viewModel.pollingState.collectAsState()
    val notification by viewModel.statusNotification.collectAsState()
    val nextPollInMs by viewModel.nextPollInMs.collectAsState()

    val isSyncing by viewModel.isSyncing.collectAsState()

    val infiniteTransition = rememberInfiniteTransition(label = "syncSpin")
    val syncRotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "syncRotation"
    )

    // Format countdown label: e.g. "12s", "1:04"
    val timerLabel = remember(nextPollInMs) {
        when {
            nextPollInMs < 0L -> "Doze"
            nextPollInMs == 0L -> "…"
            nextPollInMs < 60_000L -> "${nextPollInMs / 1000}s"
            else -> {
                val m = nextPollInMs / 60_000
                val s = (nextPollInMs % 60_000) / 1000
                "$m:${s.toString().padStart(2, '0')}"
            }
        }
    }

    val selfContact = remember(contacts) {
        contacts.firstOrNull { it.id == ChatRepository.SELF_CONTACT_ID }
    }
    val peerContacts = remember(contacts) {
        contacts.filter { it.id != ChatRepository.SELF_CONTACT_ID }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = "Security Shield",
                            tint = appColors.primary,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "PQChat.DHT",
                            style = MaterialTheme.typography.titleLarge,
                            color = appColors.textPrimary
                        )
                    }
                },
                actions = {
                    // ── DHT Sync Timer Chip ────────────────────────────────────────
                    Surface(
                        onClick = {
                            viewModel.triggerImmediatePoll()
                        },
                        shape = RoundedCornerShape(8.dp),
                        color = appColors.surfaceVariant,
                        border = BorderStroke(1.dp, appColors.primary.copy(alpha = 0.35f)),
                        modifier = Modifier
                            .padding(end = 4.dp)
                            .height(32.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            if (isSyncing) {
                                Icon(
                                    imageVector = Icons.Default.Sync,
                                    contentDescription = "Synchronizowanie…",
                                    tint = appColors.primary,
                                    modifier = Modifier
                                        .size(16.dp)
                                        .rotate(syncRotation)
                                )
                                Spacer(modifier = Modifier.width(5.dp))
                                Text(
                                    text = "Sync",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = appColors.primary,
                                    fontWeight = FontWeight.Bold,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            } else {
                                Icon(
                                    imageVector = Icons.Default.Timer,
                                    contentDescription = "Następny polling DHT",
                                    tint = appColors.primary,
                                    modifier = Modifier.size(15.dp)
                                )
                                Spacer(modifier = Modifier.width(5.dp))
                                Text(
                                    text = timerLabel,
                                    style = MaterialTheme.typography.labelMedium,
                                    color = appColors.primary,
                                    fontWeight = FontWeight.Bold,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            }
                        }
                    }
                    // ───────────────────────────────────────────────────────────────
                    IconButton(onClick = onDiagnosticsClick) {
                        Icon(
                            imageVector = Icons.Default.BarChart,
                            contentDescription = "Diagnostics",
                            tint = appColors.primary
                        )
                    }
                    IconButton(onClick = onSettingsClick) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = "Settings",
                            tint = appColors.textPrimary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = appColors.surface
                )
            )
        },
        containerColor = appColors.background,
        floatingActionButton = {
            Column(horizontalAlignment = Alignment.End) {
                ExtendedFloatingActionButton(
                    onClick = onJoinChatClick,
                    containerColor = appColors.surfaceVariant,
                    contentColor = appColors.primary,
                    icon = { Icon(Icons.Default.QrCodeScanner, contentDescription = null) },
                    text = { Text("Scan / Join (Bob)") },
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                ExtendedFloatingActionButton(
                    onClick = onNewChatClick,
                    containerColor = appColors.primary,
                    contentColor = Color.Black,
                    icon = { Icon(Icons.Default.QrCode, contentDescription = null) },
                    text = { Text("New Chat (Alice)") },
                    shape = RoundedCornerShape(16.dp)
                )
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Network & Security Status Bar
            Surface(
                color = appColors.surfaceVariant,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                shape = RoundedCornerShape(12.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(10.dp)
                                .clip(CircleShape)
                                .background(if (dhtPeers > 0) ElectricGreen else AmberWarning)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "DHT: $dhtPeers Peers",
                            style = MaterialTheme.typography.labelSmall,
                            color = appColors.textPrimary
                        )
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.NoiseAware,
                            contentDescription = null,
                            tint = CryptoPurple,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "Poisson Cover: Active",
                            style = MaterialTheme.typography.labelSmall,
                            color = CryptoPurple
                        )
                    }

                    Text(
                        text = pollingState.label,
                        style = MaterialTheme.typography.labelSmall,
                        color = appColors.primary
                    )
                }
            }

            // Notification Banner
            notification?.let { msg ->
                Surface(
                    color = appColors.surface,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 4.dp)
                        .border(1.dp, appColors.border, RoundedCornerShape(8.dp))
                ) {
                    Row(
                        modifier = Modifier.padding(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = msg,
                            style = MaterialTheme.typography.bodyMedium,
                            color = appColors.primary,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(
                            onClick = { viewModel.dismissNotification() },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(Icons.Default.Close, contentDescription = "Dismiss", tint = appColors.textSecondary)
                        }
                    }
                }
            }

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
            ) {
                // ==================== SELF-CONVERSATION (PINNED) ====================
                item(key = "self_notes_header") {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(start = 4.dp, top = 6.dp, bottom = 6.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Bookmark,
                            contentDescription = null,
                            tint = CryptoPurple,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Prywatna przestrzeń testowa",
                            style = MaterialTheme.typography.labelSmall,
                            color = CryptoPurple,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    Surface(
                        color = appColors.surface,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.5.dp, CryptoPurple.copy(alpha = 0.5f), RoundedCornerShape(14.dp))
                            .clickable { onContactClick(ChatRepository.SELF_CONTACT_ID) }
                    ) {
                        Row(
                            modifier = Modifier
                                .padding(14.dp)
                                .fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(46.dp)
                                    .clip(CircleShape)
                                    .background(CryptoPurple.copy(alpha = 0.2f)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Lock,
                                    contentDescription = null,
                                    tint = CryptoPurple,
                                    modifier = Modifier.size(24.dp)
                                )
                            }

                            Spacer(modifier = Modifier.width(14.dp))

                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = selfContact?.name ?: "🔒 Moje Notatki (Test DHT)",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = appColors.textPrimary,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "Szyfrowana pętla zwrotna BEP 44 • Notes",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = appColors.textSecondary
                                )
                            }

                            Column(horizontalAlignment = Alignment.End) {
                                Surface(
                                    color = CryptoPurple.copy(alpha = 0.15f),
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text(
                                        text = "Loopback TX:${selfContact?.counterOut ?: 0}",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = CryptoPurple,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Icon(
                                    imageVector = Icons.Default.ChevronRight,
                                    contentDescription = null,
                                    tint = appColors.textSecondary,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(start = 4.dp, bottom = 8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Group,
                            contentDescription = null,
                            tint = appColors.primary,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Kontakty P2P (DHT)",
                            style = MaterialTheme.typography.labelSmall,
                            color = appColors.primary,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                if (peerContacts.isEmpty()) {
                    item(key = "empty_state") {
                        Surface(
                            color = appColors.surface.copy(alpha = 0.6f),
                            shape = RoundedCornerShape(14.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, appColors.border, RoundedCornerShape(14.dp))
                                .padding(vertical = 8.dp)
                        ) {
                            Column(
                                modifier = Modifier
                                    .padding(24.dp)
                                    .fillMaxWidth(),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Shield,
                                    contentDescription = null,
                                    tint = appColors.border,
                                    modifier = Modifier.size(48.dp)
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                                Text(
                                    text = "Brak zewnętrznych kontaktów",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = appColors.textPrimary,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = "Użyj 'New Chat (Alice)' by wygenerować QR handshake lub 'Scan (Bob)' by dołączyć do relacji.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = appColors.textSecondary,
                                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                                )
                            }
                        }
                    }
                } else {
                    items(peerContacts, key = { it.id }) { contact ->
                        ContactItem(
                            contact = contact,
                            onClick = { onContactClick(contact.id) }
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                }
            }
        }
    }
}

@Composable
fun ContactItem(
    contact: ContactEntity,
    onClick: () -> Unit
) {
    val appColors = LocalAppColors.current

    Surface(
        color = appColors.surface,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, appColors.border, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier
                .padding(14.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(46.dp)
                    .clip(CircleShape)
                    .background(appColors.surfaceVariant),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = contact.name.take(2).uppercase(),
                    fontWeight = FontWeight.Bold,
                    color = appColors.primary,
                    fontSize = 18.sp
                )
            }

            Spacer(modifier = Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = contact.name,
                        style = MaterialTheme.typography.titleMedium,
                        color = appColors.textPrimary
                    )
                    if (contact.isVerified) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Icon(
                            imageVector = Icons.Default.VerifiedUser,
                            contentDescription = "Zweryfikowany",
                            tint = ElectricGreen,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(2.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "Post-Quantum Ratchet (FIPS 203)",
                        style = MaterialTheme.typography.bodySmall,
                        color = ElectricGreen.copy(alpha = 0.8f)
                    )
                    if (contact.sas.isNotEmpty()) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "• SAS: ${contact.sas}",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (contact.isVerified) ElectricGreen else AmberWarning,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }

            Column(horizontalAlignment = Alignment.End) {
                Surface(
                    color = appColors.surfaceVariant,
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Text(
                        text = "TX:${contact.counterOut} RX:${contact.counterIn}",
                        style = MaterialTheme.typography.labelSmall,
                        color = appColors.textPrimary,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
                Icon(
                    imageVector = Icons.Default.ChevronRight,
                    contentDescription = null,
                    tint = appColors.textSecondary,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}
