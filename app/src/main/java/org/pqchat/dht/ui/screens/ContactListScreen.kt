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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.pqchat.dht.data.db.ContactEntity
import org.pqchat.dht.data.db.GroupEntity
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
    val groups by viewModel.groups.collectAsState()
    var showCreateGroupDialog by remember { mutableStateOf(false) }
    val dhtPeers by viewModel.dhtPeerCount.collectAsState()
    val pollingState by viewModel.pollingState.collectAsState()
    val notification by viewModel.statusNotification.collectAsState()
    val nextPollInMs by viewModel.nextPollInMs.collectAsState()

    val isSyncing by viewModel.isSyncing.collectAsState()


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
                            .testTag("contact_list_sync_chip")
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            if (isSyncing) {
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
                                Icon(
                                    imageVector = Icons.Default.Sync,
                                    contentDescription = "Syncing…",
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
                                    contentDescription = "Next DHT poll",
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
                    IconButton(
                        onClick = onDiagnosticsClick,
                        modifier = Modifier.testTag("contact_list_diagnostics_button")
                    ) {
                        Icon(
                            imageVector = Icons.Default.BarChart,
                            contentDescription = "Diagnostics",
                            tint = appColors.primary
                        )
                    }
                    IconButton(
                        onClick = onSettingsClick,
                        modifier = Modifier.testTag("contact_list_settings_button")
                    ) {
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
                    onClick = { showCreateGroupDialog = true },
                    containerColor = CryptoPurple,
                    contentColor = Color.White,
                    icon = { Icon(Icons.Default.GroupAdd, contentDescription = null) },
                    text = { Text("New Group") },
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier
                        .padding(bottom = 8.dp)
                        .testTag("new_group_fab")
                )
                ExtendedFloatingActionButton(
                    onClick = onJoinChatClick,
                    containerColor = appColors.surfaceVariant,
                    contentColor = appColors.primary,
                    icon = { Icon(Icons.Default.QrCodeScanner, contentDescription = null) },
                    text = { Text("Scan / Join (Bob)") },
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier
                        .padding(bottom = 8.dp)
                        .testTag("join_chat_fab")
                )
                ExtendedFloatingActionButton(
                    onClick = onNewChatClick,
                    containerColor = appColors.primary,
                    contentColor = Color.Black,
                    icon = { Icon(Icons.Default.QrCode, contentDescription = null) },
                    text = { Text("New Chat (Alice)") },
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.testTag("new_chat_fab")
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
                            text = "Private Test Space",
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
                                    text = selfContact?.rawName ?: "🔒 My Notes (DHT Test)",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = appColors.textPrimary,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "Encrypted BEP 44 Loopback • Notes",
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
                }

                if (groups.isNotEmpty()) {
                    item(key = "groups_header") {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(start = 4.dp, top = 6.dp, bottom = 8.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Groups,
                                contentDescription = null,
                                tint = CryptoPurple,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "Group Chats (Sender Keys)",
                                style = MaterialTheme.typography.labelSmall,
                                color = CryptoPurple,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    items(groups, key = { "group_${it.groupId}" }) { group ->
                        GroupItem(
                            group = group,
                            onClick = { onContactClick(group.groupId) }
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                    }

                    item(key = "groups_spacer") {
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                }

                item(key = "peer_contacts_header") {
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
                            text = "P2P Contacts (DHT)",
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
                                    text = "No external contacts",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = appColors.textPrimary,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = "Use 'New Chat (Alice)' to generate a QR handshake or 'Scan (Bob)' to join.",
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

        if (showCreateGroupDialog) {
            CreateGroupDialog(
                contacts = peerContacts,
                onDismiss = { showCreateGroupDialog = false },
                onCreateGroup = { name, selectedContactIds ->
                    viewModel.createGroup(name, selectedContactIds)
                    showCreateGroupDialog = false
                }
            )
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
            .testTag("contact_item_${contact.rawName}")
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
                        text = contact.rawName,
                        style = MaterialTheme.typography.titleMedium,
                        color = appColors.textPrimary
                    )
                    if (contact.isVerified) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Icon(
                            imageVector = Icons.Default.VerifiedUser,
                            contentDescription = "Verified",
                            tint = ElectricGreen,
                            modifier = Modifier.size(16.dp)
                        )
                    } else if (contact.id != ChatRepository.SELF_CONTACT_ID) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Icon(
                            imageVector = Icons.Default.GppMaybe,
                            contentDescription = "Unverified SAS",
                            tint = AmberWarning,
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

@Composable
fun GroupItem(
    group: GroupEntity,
    onClick: () -> Unit
) {
    val appColors = LocalAppColors.current

    Surface(
        color = appColors.surface,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("group_item_${group.rawGroupName}")
            .border(1.dp, CryptoPurple.copy(alpha = 0.5f), RoundedCornerShape(12.dp))
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
                    .background(CryptoPurple.copy(alpha = 0.2f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.Groups,
                    contentDescription = null,
                    tint = CryptoPurple,
                    modifier = Modifier.size(26.dp)
                )
            }

            Spacer(modifier = Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = group.rawGroupName,
                    style = MaterialTheme.typography.titleMedium,
                    color = appColors.textPrimary,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = "Post-Quantum Sender Keys • Epoch ${group.groupEpoch}",
                    style = MaterialTheme.typography.bodySmall,
                    color = CryptoPurple.copy(alpha = 0.85f)
                )
            }

            Column(horizontalAlignment = Alignment.End) {
                Surface(
                    color = CryptoPurple.copy(alpha = 0.15f),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Text(
                        text = "TX:${group.myCounterOut}",
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
}

@Composable
fun CreateGroupDialog(
    contacts: List<ContactEntity>,
    onDismiss: () -> Unit,
    onCreateGroup: (name: String, selectedContactIds: List<String>) -> Unit
) {
    val appColors = LocalAppColors.current
    var groupName by remember { mutableStateOf("") }
    val selectedContactIds = remember { mutableStateListOf<String>() }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.GroupAdd,
                    contentDescription = null,
                    tint = CryptoPurple
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "New Group Chat",
                    style = MaterialTheme.typography.titleMedium,
                    color = appColors.textPrimary
                )
            }
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "Decentralized group chat based on Post-Quantum Sender Keys over BEP 44. Every message is published as a single 900 B frame in the DHT (O(1) cost).",
                    style = MaterialTheme.typography.bodySmall,
                    color = appColors.textSecondary
                )
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = groupName,
                    onValueChange = { groupName = it },
                    label = { Text("Group Name") },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("create_group_name_input"),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CryptoPurple,
                        unfocusedBorderColor = appColors.border,
                        focusedTextColor = appColors.textPrimary,
                        unfocusedTextColor = appColors.textPrimary
                    )
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Select participants (${selectedContactIds.size}/${contacts.size}):",
                    style = MaterialTheme.typography.labelMedium,
                    color = appColors.textPrimary,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(modifier = Modifier.height(6.dp))
                if (contacts.isEmpty()) {
                    Text(
                        text = "No external contacts to invite. The group will be created locally.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary
                    )
                } else {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 200.dp)
                    ) {
                        items(contacts, key = { it.id }) { contact ->
                            val isSelected = selectedContactIds.contains(contact.id)
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("group_participant_${contact.rawName}")
                                    .clickable {
                                        if (isSelected) {
                                            selectedContactIds.remove(contact.id)
                                        } else {
                                            selectedContactIds.add(contact.id)
                                        }
                                    }
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Checkbox(
                                    checked = isSelected,
                                    onCheckedChange = { checked ->
                                        if (checked) {
                                            selectedContactIds.add(contact.id)
                                        } else {
                                            selectedContactIds.remove(contact.id)
                                        }
                                    },
                                    colors = CheckboxDefaults.colors(
                                        checkedColor = CryptoPurple
                                    )
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Column {
                                    Text(
                                        text = contact.rawName,
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = appColors.textPrimary
                                    )
                                    if (contact.isVerified) {
                                        Text(
                                            text = "Verified SAS",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = ElectricGreen
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (groupName.isNotBlank()) {
                        onCreateGroup(groupName.trim(), selectedContactIds.toList())
                    }
                },
                enabled = groupName.isNotBlank(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = CryptoPurple,
                    contentColor = Color.White
                ),
                modifier = Modifier.testTag("create_group_confirm_button")
            ) {
                Text("Create Group")
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.testTag("create_group_cancel_button")
            ) {
                Text("Cancel", color = appColors.textSecondary)
            }
        },
        containerColor = appColors.surface
    )
}
