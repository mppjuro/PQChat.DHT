package org.pqchat.dht.ui.screens

import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.automirrored.filled.ExitToApp
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import org.pqchat.dht.data.db.MessageEntity
import org.pqchat.dht.data.db.GroupEntity
import org.pqchat.dht.data.db.GroupMemberEntity
import org.pqchat.dht.ui.theme.*
import org.pqchat.dht.ui.util.ImageGallerySaver
import org.pqchat.dht.ui.viewmodel.ChatViewModel
import java.text.SimpleDateFormat
import java.util.*
import androidx.compose.animation.core.*
import kotlinx.coroutines.delay
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.protocol.LocationPinData
import org.pqchat.dht.ui.util.SecureScreenEffect

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    viewModel: ChatViewModel,
    contactId: String,
    onBack: () -> Unit
) {
    SecureScreenEffect()

    val context = LocalContext.current
    val appColors = LocalAppColors.current

    val contacts by viewModel.contacts.collectAsState()
    val contact = contacts.firstOrNull { it.id == contactId }
    val groups by viewModel.groups.collectAsState()
    val group = groups.firstOrNull { it.groupId == contactId }
    val isGroup = group != null
    val groupMembers by remember(contactId, isGroup) {
        if (isGroup) viewModel.getGroupMembersFlow(contactId) else kotlinx.coroutines.flow.flowOf(emptyList())
    }.collectAsState(initial = emptyList())

    val messages by viewModel.messages.collectAsState()
    val nextPollInMs by viewModel.nextPollInMs.collectAsState()
    val isRekeyInProgress by viewModel.isRekeyInProgress.collectAsState()
    val downloadingTransfers by viewModel.currentContactDownloadProgress.collectAsState()

    var textInput by remember { mutableStateOf("") }
    var showSasDialog by remember { mutableStateOf(false) }
    var showEditContactNameDialog by remember { mutableStateOf(false) }
    var showGroupMembersDialog by remember { mutableStateOf(false) }
    var editedContactName by remember { mutableStateOf("") }
    var fullscreenImageBytes by remember { mutableStateOf<ByteArray?>(null) }
    val ephemeralTtlSeconds by viewModel.ephemeralTtlSeconds.collectAsState()
    var showEphemeralMenu by remember { mutableStateOf(false) }
    var showLocationPinDialog by remember { mutableStateOf(false) }

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

    val imagePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            try {
                val inputStream = context.contentResolver.openInputStream(uri)
                val bytes = inputStream?.readBytes()
                inputStream?.close()
                if (bytes != null && bytes.isNotEmpty()) {
                    viewModel.sendImagePayload(bytes)
                }
            } catch (_: Exception) {
            }
        }
    }

    LaunchedEffect(contactId) {
        viewModel.selectContact(contactId)
    }

    DisposableEffect(Unit) {
        onDispose {
            viewModel.unselectContact()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        if (group != null) {
                            Text(
                                text = group.rawGroupName,
                                style = MaterialTheme.typography.titleMedium,
                                color = appColors.textPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    text = "PQ Sender Keys • Epoka ${group.groupEpoch} • TX: ${group.myCounterOut}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = CryptoPurple,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            }
                        } else {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .clickable(enabled = contact != null) {
                                        if (contact != null) {
                                            editedContactName = contact.rawName
                                            showEditContactNameDialog = true
                                        }
                                    }
                            ) {
                                Text(
                                    text = contact?.rawName ?: "Chat",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = appColors.textPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                if (contact != null) {
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Icon(
                                        imageVector = Icons.Default.Edit,
                                        contentDescription = "Zmień nazwę kontaktu",
                                        tint = appColors.textSecondary.copy(alpha = 0.6f),
                                        modifier = Modifier.size(14.dp)
                                    )
                                }
                                if (contact != null && contact.id != ChatRepository.SELF_CONTACT_ID) {
                                    Spacer(modifier = Modifier.width(6.dp))
                                    IconButton(
                                        onClick = { showSasDialog = true },
                                        modifier = Modifier
                                            .size(24.dp)
                                            .testTag("chat_sas_button")
                                    ) {
                                        Icon(
                                            imageVector = if (contact.isVerified) Icons.Default.VerifiedUser else Icons.Default.GppMaybe,
                                            contentDescription = if (contact.isVerified) "Zweryfikowany SAS" else "Niezweryfikowany SAS",
                                            tint = if (contact.isVerified) ElectricGreen else AmberWarning,
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                }
                            }
                            contact?.let {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    if (it.sas.isNotEmpty()) {
                                        Text(
                                            text = "SAS: ${it.sas}",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = if (it.isVerified) ElectricGreen else AmberWarning,
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            maxLines = 1,
                                            softWrap = false
                                        )
                                        Spacer(modifier = Modifier.width(10.dp))
                                    }
                                    Text(
                                        text = "TX: ${it.counterOut}  RX: ${it.counterIn}",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = appColors.primary,
                                        maxLines = 1,
                                        softWrap = false
                                    )
                                }
                            }
                        }
                    }
                },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                        modifier = Modifier.testTag("chat_back_button")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = appColors.textPrimary
                        )
                    }
                },
                actions = {
                    if (isGroup) {
                        IconButton(
                            onClick = { showGroupMembersDialog = true },
                            modifier = Modifier.testTag("chat_group_members_button")
                        ) {
                            Icon(
                                imageVector = Icons.Default.Groups,
                                contentDescription = "Członkowie grupy",
                                tint = CryptoPurple
                            )
                        }
                        IconButton(
                            onClick = {
                                viewModel.leaveGroup(contactId)
                                onBack()
                            },
                            modifier = Modifier.testTag("chat_leave_group_icon_button")
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.ExitToApp,
                                contentDescription = "Opuść grupę",
                                tint = Color(0xFFFF5252)
                            )
                        }
                    }
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
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = appColors.surface
                )
            )
        },
        containerColor = appColors.background,
        bottomBar = {
            Surface(
                color = appColors.surface,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column {
                    if (ephemeralTtlSeconds > 0L) {
                        val ttlLabel = when (ephemeralTtlSeconds) {
                            60L -> "1 min"
                            900L -> "15 min"
                            3600L -> "1 godzina"
                            86400L -> "24 godziny"
                            else -> "${ephemeralTtlSeconds}s"
                        }
                        Surface(
                            color = AmberWarning.copy(alpha = 0.12f),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.HourglassTop,
                                        contentDescription = null,
                                        tint = AmberWarning,
                                        modifier = Modifier.size(13.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "Znikające wiadomości: znikną po $ttlLabel od przeczytania",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = AmberWarning,
                                        fontWeight = FontWeight.SemiBold
                                    )
                                }
                                Text(
                                    text = "Wyłącz",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = appColors.primary,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(4.dp))
                                        .clickable { viewModel.setEphemeralTtl(0L) }
                                        .padding(horizontal = 4.dp, vertical = 2.dp)
                                )
                            }
                        }
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 8.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Attachment button for sending real pictures/files over 900B DHT chunks
                        IconButton(
                            onClick = { imagePickerLauncher.launch("image/*") },
                            modifier = Modifier.size(40.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.AddPhotoAlternate,
                                contentDescription = "Attach Image",
                                tint = appColors.primary
                            )
                        }

                        // Ephemeral Messages TTL Switcher
                        Box {
                            IconButton(
                                onClick = { showEphemeralMenu = true },
                                modifier = Modifier
                                    .size(40.dp)
                                    .testTag("chat_ephemeral_ttl_button")
                            ) {
                                Icon(
                                    imageVector = if (ephemeralTtlSeconds > 0) Icons.Default.HourglassTop else Icons.Default.HourglassEmpty,
                                    contentDescription = "Czas życia wiadomości",
                                    tint = if (ephemeralTtlSeconds > 0) AmberWarning else appColors.textSecondary
                                )
                            }

                            DropdownMenu(
                                expanded = showEphemeralMenu,
                                onDismissRequest = { showEphemeralMenu = false }
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Znikające wiadomości: Wyłączone") },
                                    onClick = {
                                        viewModel.setEphemeralTtl(0L)
                                        showEphemeralMenu = false
                                    },
                                    leadingIcon = {
                                        if (ephemeralTtlSeconds == 0L) {
                                            Icon(Icons.Default.Check, contentDescription = null, tint = ElectricGreen)
                                        }
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("1 minuta") },
                                    onClick = {
                                        viewModel.setEphemeralTtl(60L)
                                        showEphemeralMenu = false
                                    },
                                    leadingIcon = {
                                        if (ephemeralTtlSeconds == 60L) {
                                            Icon(Icons.Default.Check, contentDescription = null, tint = ElectricGreen)
                                        }
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("15 minut") },
                                    onClick = {
                                        viewModel.setEphemeralTtl(900L)
                                        showEphemeralMenu = false
                                    },
                                    leadingIcon = {
                                        if (ephemeralTtlSeconds == 900L) {
                                            Icon(Icons.Default.Check, contentDescription = null, tint = ElectricGreen)
                                        }
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("1 godzina") },
                                    onClick = {
                                        viewModel.setEphemeralTtl(3600L)
                                        showEphemeralMenu = false
                                    },
                                    leadingIcon = {
                                        if (ephemeralTtlSeconds == 3600L) {
                                            Icon(Icons.Default.Check, contentDescription = null, tint = ElectricGreen)
                                        }
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("24 godziny") },
                                    onClick = {
                                        viewModel.setEphemeralTtl(86400L)
                                        showEphemeralMenu = false
                                    },
                                    leadingIcon = {
                                        if (ephemeralTtlSeconds == 86400L) {
                                            Icon(Icons.Default.Check, contentDescription = null, tint = ElectricGreen)
                                        }
                                    }
                                )
                            }
                        }

                        // Location pin / offline safety status button (single-frame 900B BEP 44 micro-payload)
                        IconButton(
                            onClick = { showLocationPinDialog = true },
                            modifier = Modifier
                                .size(40.dp)
                                .testTag("chat_location_pin_button")
                        ) {
                            Icon(
                                imageVector = Icons.Default.Place,
                                contentDescription = "Pinezka lokalizacji",
                                tint = ElectricGreen
                            )
                        }

                        OutlinedTextField(
                            value = textInput,
                            onValueChange = { textInput = it },
                            placeholder = { Text("Wiadomość (szyfrowana ramka DHT)...", color = appColors.textSecondary) },
                            modifier = Modifier
                                .weight(1f)
                                .padding(end = 8.dp)
                                .testTag("chat_message_input"),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = appColors.primary,
                                unfocusedBorderColor = appColors.border,
                                focusedTextColor = appColors.textPrimary,
                                unfocusedTextColor = appColors.textPrimary,
                                focusedContainerColor = appColors.surfaceVariant.copy(alpha = 0.5f),
                                unfocusedContainerColor = appColors.surfaceVariant.copy(alpha = 0.5f)
                            ),
                            shape = RoundedCornerShape(24.dp),
                            maxLines = 4
                        )

                        IconButton(
                            onClick = {
                                if (textInput.isNotBlank()) {
                                    viewModel.sendMessage(textInput)
                                    textInput = ""
                                }
                            },
                            modifier = Modifier
                                .size(48.dp)
                                .testTag("chat_send_button"),
                            colors = IconButtonDefaults.iconButtonColors(
                                containerColor = appColors.primary,
                                contentColor = Color.Black
                            )
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.Send,
                                contentDescription = "Send",
                                tint = Color.Black
                            )
                        }
                    }
                }
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            if (isRekeyInProgress) {
                Surface(
                    color = AmberWarning.copy(alpha = 0.15f),
                    shape = RoundedCornerShape(8.dp),
                    border = BorderStroke(1.dp, AmberWarning.copy(alpha = 0.6f)),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                    ) {
                        CircularProgressIndicator(
                            strokeWidth = 2.dp,
                            color = AmberWarning,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            text = "Wymiana klucza ML-KEM w toku...",
                            style = MaterialTheme.typography.labelMedium,
                            color = AmberWarning,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }

            if (downloadingTransfers.isNotEmpty()) {
                for (progress in downloadingTransfers) {
                    Surface(
                        color = appColors.surfaceVariant.copy(alpha = 0.7f),
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, appColors.primary.copy(alpha = 0.5f)),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 4.dp)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Icon(
                                    imageVector = Icons.Default.CloudDownload,
                                    contentDescription = "Pobieranie obrazu",
                                    tint = appColors.primary,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "Pobieranie obrazu: ${progress.receivedChunks}/${progress.totalChunks} segmentów (${progress.progressPercent}%)",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = appColors.textPrimary
                                )
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            LinearProgressIndicator(
                                progress = { progress.progressFraction },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(6.dp)
                                    .clip(RoundedCornerShape(3.dp)),
                                color = appColors.primary,
                                trackColor = appColors.surface
                            )
                        }
                    }
                }
            }

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 12.dp, vertical = 4.dp),
                reverseLayout = false
            ) {
                items(messages, key = { it.id }) { msg ->
                    MessageBubble(
                        message = msg,
                        onImageClick = { bytes -> fullscreenImageBytes = bytes },
                        onResend = { viewModel.resendMessage(msg.id) },
                        onReactionClick = { emoji -> viewModel.sendReaction(msg, emoji) }
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                }
            }
        }

        if (showEditContactNameDialog && contact != null) {
            AlertDialog(
                onDismissRequest = { showEditContactNameDialog = false },
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Edit,
                            contentDescription = null,
                            tint = appColors.primary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Zmień nazwę kontaktu",
                            style = MaterialTheme.typography.titleMedium,
                            color = appColors.textPrimary
                        )
                    }
                },
                text = {
                    Column {
                        Text(
                            text = "Podaj nową nazwę dla kontaktu w PQChat:",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textSecondary
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        OutlinedTextField(
                            value = editedContactName,
                            onValueChange = { editedContactName = it },
                            placeholder = { Text("Nazwa kontaktu", color = appColors.textSecondary) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = appColors.primary,
                                unfocusedBorderColor = appColors.border,
                                focusedTextColor = appColors.textPrimary,
                                unfocusedTextColor = appColors.textPrimary
                            )
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            val trimmed = editedContactName.trim()
                            if (trimmed.isNotEmpty()) {
                                viewModel.updateContactName(contact.id, trimmed)
                            }
                            showEditContactNameDialog = false
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = appColors.primary,
                            contentColor = Color.Black
                        )
                    ) {
                        Text("Zapisz", fontWeight = FontWeight.Bold)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showEditContactNameDialog = false }) {
                        Text("Anuluj", color = appColors.textSecondary)
                    }
                },
                containerColor = appColors.surface
            )
        }

        if (showSasDialog && contact != null) {
            AlertDialog(
                onDismissRequest = { showSasDialog = false },
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (contact.isVerified) Icons.Default.VerifiedUser else Icons.Default.GppMaybe,
                            contentDescription = null,
                            tint = if (contact.isVerified) ElectricGreen else AmberWarning
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (contact.isVerified) "Kontakt zweryfikowany" else "Weryfikacja tożsamości (SAS)",
                            style = MaterialTheme.typography.titleMedium,
                            color = appColors.textPrimary
                        )
                    }
                },
                text = {
                    Column {
                        Text(
                            text = "Kod SAS (Short Authentication String):",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textSecondary
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Surface(
                            color = appColors.surfaceVariant,
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Box(
                                modifier = Modifier.fillMaxWidth().padding(16.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = contact.sas.ifEmpty { "Brak SAS" },
                                    style = MaterialTheme.typography.headlineMedium,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace,
                                    color = if (contact.isVerified) ElectricGreen else appColors.primary
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "Porównaj powyższy 8-cyfrowy kod z rozmówcą przez zaufany kanał (np. osobiście lub telefonicznie). Kod powstał w oparciu o kryptograficzne zobowiązanie (anti-grinding commitment) powiązane z transkryptem ML-KEM-512.",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textSecondary
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            viewModel.toggleContactVerified(contact.id, contact.isVerified)
                            showSasDialog = false
                        },
                        modifier = Modifier.testTag("sas_verify_toggle_button"),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (contact.isVerified) AmberWarning else ElectricGreen,
                            contentColor = Color.Black
                        )
                    ) {
                        Text(
                            text = if (contact.isVerified) "Cofnij weryfikację" else "Zatwierdź tożsamość (SAS zgodny)",
                            fontWeight = FontWeight.Bold
                        )
                    }
                },
                dismissButton = {
                    TextButton(
                        onClick = { showSasDialog = false },
                        modifier = Modifier.testTag("sas_dialog_close_button")
                    ) {
                        Text("Zamknij", color = appColors.textSecondary)
                    }
                },
                containerColor = appColors.surface
            )
        }

        if (showGroupMembersDialog && group != null) {
            AlertDialog(
                onDismissRequest = { showGroupMembersDialog = false },
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Groups,
                            contentDescription = null,
                            tint = CryptoPurple
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = group.rawGroupName,
                            style = MaterialTheme.typography.titleMedium,
                            color = appColors.textPrimary
                        )
                    }
                },
                text = {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = "Identyfikator: ${group.groupId}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = appColors.textSecondary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Epoka KEM: ${group.groupEpoch} • Mój licznik TX: ${group.myCounterOut}",
                            style = MaterialTheme.typography.bodySmall,
                            color = CryptoPurple,
                            fontWeight = FontWeight.Medium
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "Członkowie grupy (${groupMembers.size}):",
                            style = MaterialTheme.typography.labelMedium,
                            color = appColors.textPrimary,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        if (groupMembers.isEmpty()) {
                            Text(
                                text = "Brak zarejestrowanych członków.",
                                style = MaterialTheme.typography.bodySmall,
                                color = appColors.textSecondary
                            )
                        } else {
                            LazyColumn(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(max = 240.dp)
                            ) {
                                items(groupMembers, key = { it.memberId }) { member ->
                                    Surface(
                                        color = appColors.surfaceVariant.copy(alpha = 0.5f),
                                        shape = RoundedCornerShape(8.dp),
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(vertical = 4.dp)
                                    ) {
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(10.dp),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(
                                                    text = member.rawMemberName,
                                                    style = MaterialTheme.typography.bodyMedium,
                                                    color = appColors.textPrimary,
                                                    fontWeight = FontWeight.SemiBold
                                                )
                                                Text(
                                                    text = "ID: ${member.memberId.take(8)}...",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontFamily = FontFamily.Monospace,
                                                    color = appColors.textSecondary
                                                )
                                            }
                                            Surface(
                                                color = CryptoPurple.copy(alpha = 0.15f),
                                                shape = RoundedCornerShape(6.dp)
                                            ) {
                                                Text(
                                                    text = "RX: ${member.counterIn}",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    color = CryptoPurple,
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
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
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedButton(
                            onClick = {
                                viewModel.leaveGroup(group.groupId)
                                showGroupMembersDialog = false
                                onBack()
                            },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFFF5252)),
                            border = BorderStroke(1.dp, Color(0xFFFF5252)),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.testTag("leave_group_button")
                        ) {
                            Icon(Icons.AutoMirrored.Filled.ExitToApp, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Opuść grupę", color = Color(0xFFFF5252))
                        }

                        TextButton(
                            onClick = { showGroupMembersDialog = false },
                            modifier = Modifier.testTag("close_group_dialog_button")
                        ) {
                            Text("Zamknij", color = appColors.primary)
                        }
                    }
                },
                containerColor = appColors.surface
            )
        }

        fullscreenImageBytes?.let { bytes ->
            FullscreenImageViewer(
                imageBytes = bytes,
                onDismiss = { fullscreenImageBytes = null },
                onSave = {
                    val saved = ImageGallerySaver.saveImageToGallery(context, bytes)
                    if (saved) {
                        Toast.makeText(context, "Zapisano zdjęcie w galerii", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(context, "Błąd podczas zapisywania zdjęcia", Toast.LENGTH_SHORT).show()
                    }
                }
            )
        }

        if (showLocationPinDialog) {
            LocationPinDialog(
                onDismiss = { showLocationPinDialog = false },
                onSend = { lat, lon, alt, acc, note ->
                    viewModel.sendLocationPin(lat, lon, alt, acc, note)
                    showLocationPinDialog = false
                }
            )
        }
    }
}

@Composable
fun MessageBubble(
    message: MessageEntity,
    onImageClick: ((ByteArray) -> Unit)? = null,
    onResend: (() -> Unit)? = null,
    onReactionClick: ((String) -> Unit)? = null
) {
    val context = LocalContext.current
    val appColors = LocalAppColors.current

    val isOut = message.isOutgoing
    val alignment = if (isOut) Alignment.End else Alignment.Start
    val bgColor = if (isOut) appColors.surfaceVariant else appColors.surface
    val borderColor = if (isOut) appColors.primary.copy(alpha = 0.4f) else appColors.secondary.copy(alpha = 0.4f)

    val timeStr = remember(message.timestamp) {
        val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        sdf.format(Date(message.timestamp))
    }

    var showReactionPicker by remember { mutableStateOf(false) }
    val locationPin: LocationPinData? = remember(message.rawTextContent) {
        LocationPinData.parse(message.rawTextContent)
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = alignment
    ) {
        Surface(
            color = bgColor,
            shape = RoundedCornerShape(
                topStart = 16.dp,
                topEnd = 16.dp,
                bottomStart = if (isOut) 16.dp else 4.dp,
                bottomEnd = if (isOut) 4.dp else 16.dp
            ),
            modifier = Modifier
                .widthIn(max = 320.dp)
                .border(1.dp, borderColor, RoundedCornerShape(16.dp))
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                // Sender name for group messages
                if (!isOut && !message.rawSenderName.isNullOrBlank()) {
                    Text(
                        text = message.rawSenderName ?: "",
                        style = MaterialTheme.typography.labelSmall,
                        color = CryptoPurple,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                }

                // Image payload if present
                message.rawImageBytes?.let { bytes ->
                    val bitmap = remember(bytes) {
                        BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    }
                    if (bitmap != null) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(180.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .clickable { onImageClick?.invoke(bytes) }
                        ) {
                            Image(
                                bitmap = bitmap.asImageBitmap(),
                                contentDescription = "PNG Attachment",
                                contentScale = ContentScale.Crop,
                                modifier = Modifier.fillMaxSize()
                            )
                            Surface(
                                shape = RoundedCornerShape(topStart = 8.dp),
                                color = Color.Black.copy(alpha = 0.65f),
                                modifier = Modifier.align(Alignment.BottomEnd)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Fullscreen,
                                        contentDescription = "Powiększ zdjęcie",
                                        tint = Color.White,
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Spacer(modifier = Modifier.width(3.dp))
                                    Text(
                                        text = "Podgląd",
                                        color = Color.White,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Medium
                                    )
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                }

                // Location Pin Micro-Payload or Standard Text Content
                if (locationPin != null) {
                    Surface(
                        color = appColors.surfaceVariant.copy(alpha = 0.6f),
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, ElectricGreen.copy(alpha = 0.5f)),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp)
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Default.Place,
                                    contentDescription = null,
                                    tint = ElectricGreen,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = "Pinezka lokalizacji / Status",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = ElectricGreen
                                )
                            }

                            if (locationPin.note.isNotBlank()) {
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = locationPin.note,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    color = appColors.textPrimary
                                )
                            }

                            Spacer(modifier = Modifier.height(4.dp))
                            val latFormatted = String.format(Locale.US, "%.5f°", locationPin.latitude)
                            val lonFormatted = String.format(Locale.US, "%.5f°", locationPin.longitude)
                            Text(
                                text = "Współrzędne: $latFormatted, $lonFormatted",
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = appColors.textSecondary
                            )

                            if (locationPin.altitude != 0.0 || locationPin.accuracy > 0f) {
                                val altStr = if (locationPin.altitude != 0.0) "${locationPin.altitude.toInt()} m" else "-"
                                val accStr = if (locationPin.accuracy > 0f) "±${locationPin.accuracy.toInt()} m" else "-"
                                Text(
                                    text = "Wysokość: $altStr • Dokładność: $accStr",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = appColors.textSecondary,
                                    fontSize = 10.sp
                                )
                            }

                            Spacer(modifier = Modifier.height(8.dp))
                            OutlinedButton(
                                onClick = {
                                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(locationPin.geoUri)).apply {
                                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                                    }
                                    try {
                                        context.startActivity(intent)
                                    } catch (e: Exception) {
                                        Toast.makeText(context, "Brak aplikacji mapy (np. OsmAnd, Organic Maps)", Toast.LENGTH_SHORT).show()
                                    }
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("open_map_button_${message.id}"),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = ElectricGreen),
                                border = BorderStroke(1.dp, ElectricGreen.copy(alpha = 0.6f)),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Icon(Icons.Default.Map, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Otwórz w mapie offline", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                } else {
                    message.rawTextContent?.let { text ->
                        Text(
                            text = text,
                            style = MaterialTheme.typography.bodyLarge,
                            color = appColors.textPrimary
                        )
                    }
                }

                // Display Reaction if present
                if (!message.reaction.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(6.dp))
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = appColors.surface.copy(alpha = 0.9f),
                        border = BorderStroke(1.dp, appColors.primary.copy(alpha = 0.5f)),
                        modifier = Modifier.testTag("reaction_badge_${message.id}")
                    ) {
                        Text(
                            text = message.reaction ?: "",
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            fontSize = 15.sp
                        )
                    }
                }

                if (showReactionPicker) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = appColors.surface,
                        border = BorderStroke(1.dp, appColors.primary.copy(alpha = 0.6f)),
                        shadowElevation = 4.dp
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            val emojis = listOf("❤️", "👍", "🔥", "😂", "😮", "📍")
                            for (emoji in emojis) {
                                Text(
                                    text = emoji,
                                    fontSize = 18.sp,
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(8.dp))
                                        .clickable {
                                            onReactionClick?.invoke(emoji)
                                            showReactionPicker = false
                                        }
                                        .padding(4.dp)
                                        .testTag("reaction_emoji_${message.id}_$emoji")
                                )
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(4.dp))

                // Footer with metadata
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "#${message.seqNum} • $timeStr",
                        style = MaterialTheme.typography.labelSmall,
                        color = appColors.textSecondary,
                        fontSize = 10.sp
                    )

                    val isExpired = message.status == "EXPIRED_OFFLINE" || message.status == "EXPIRED_DHT"
                    val isQueuedPoisson = message.status == "QUEUED_POISSON"
                    val statusText = when {
                        isExpired -> "Wygasła w DHT"
                        isQueuedPoisson -> "W kolejce maskującej Poissona"
                        else -> message.status
                    }
                    val statusColor = when {
                        message.status == "CONFIRMED_DHT" -> ElectricGreen
                        message.status in listOf("DELIVERED", "SENT_DHT", "PENDING_DELIVERY") -> appColors.primary
                        isQueuedPoisson -> NeonCyan
                        isExpired -> Color(0xFFFF5252)
                        else -> AmberWarning
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (message.ephemeralTtlSeconds > 0L) {
                            val ttlLabel = when (message.ephemeralTtlSeconds) {
                                60L -> "1m"
                                900L -> "15m"
                                3600L -> "1h"
                                86400L -> "24h"
                                else -> "${message.ephemeralTtlSeconds}s"
                            }
                            Icon(
                                imageVector = Icons.Default.HourglassBottom,
                                contentDescription = "Znikająca wiadomość ($ttlLabel)",
                                tint = AmberWarning,
                                modifier = Modifier.size(11.dp)
                            )
                            Spacer(modifier = Modifier.width(2.dp))
                            Text(
                                text = ttlLabel,
                                style = MaterialTheme.typography.labelSmall,
                                color = AmberWarning,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                        }
                        Text(
                            text = statusText,
                            style = MaterialTheme.typography.labelSmall,
                            color = statusColor,
                            fontSize = 10.sp
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        IconButton(
                            onClick = { showReactionPicker = !showReactionPicker },
                            modifier = Modifier
                                .size(20.dp)
                                .testTag("react_button_${message.id}")
                        ) {
                            Icon(
                                imageVector = Icons.Default.AddReaction,
                                contentDescription = "Dodaj reakcję",
                                tint = appColors.textSecondary,
                                modifier = Modifier.size(14.dp)
                            )
                        }
                        if (isExpired && message.isOutgoing) {
                            Spacer(modifier = Modifier.width(6.dp))
                            Surface(
                                shape = RoundedCornerShape(4.dp),
                                color = ElectricGreen.copy(alpha = 0.15f),
                                modifier = Modifier.clickable { onResend?.invoke() }
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Refresh,
                                        contentDescription = "Ponów wysyłkę",
                                        tint = ElectricGreen,
                                        modifier = Modifier.size(10.dp)
                                    )
                                    Spacer(modifier = Modifier.width(2.dp))
                                    Text(
                                        text = "Ponów",
                                        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                        color = ElectricGreen,
                                        fontSize = 10.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun FullscreenImageViewer(
    imageBytes: ByteArray,
    onDismiss: () -> Unit,
    onSave: () -> Unit
) {
    val bitmap = remember(imageBytes) {
        BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size)
    }

    var scale by remember { mutableFloatStateOf(1f) }
    var offset by remember { mutableStateOf(Offset.Zero) }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            decorFitsSystemWindows = false
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black)
        ) {
            if (bitmap != null) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .pointerInput(Unit) {
                            detectTransformGestures { _, pan, zoom, _ ->
                                scale = (scale * zoom).coerceIn(1f, 5f)
                                if (scale > 1f) {
                                    val maxOffsetX = (size.width * (scale - 1f)) / 2f
                                    val maxOffsetY = (size.height * (scale - 1f)) / 2f
                                    offset = Offset(
                                        x = (offset.x + pan.x).coerceIn(-maxOffsetX, maxOffsetX),
                                        y = (offset.y + pan.y).coerceIn(-maxOffsetY, maxOffsetY)
                                    )
                                } else {
                                    offset = Offset.Zero
                                }
                            }
                        },
                    contentAlignment = Alignment.Center
                ) {
                    Image(
                        bitmap = bitmap.asImageBitmap(),
                        contentDescription = "Zdjęcie na pełnym ekranie",
                        contentScale = ContentScale.Fit,
                        modifier = Modifier
                            .fillMaxSize()
                            .graphicsLayer {
                                scaleX = scale
                                scaleY = scale
                                translationX = offset.x
                                translationY = offset.y
                            }
                    )
                }
            } else {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "Nie można załadować zdjęcia",
                        color = Color.White,
                        style = MaterialTheme.typography.bodyLarge
                    )
                }
            }

            // Top control bar with Close (X) and Save button
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .statusBarsPadding()
                    .padding(horizontal = 16.dp, vertical = 12.dp)
                    .align(Alignment.TopCenter),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(
                    onClick = onDismiss,
                    modifier = Modifier
                        .size(44.dp)
                        .background(Color.Black.copy(alpha = 0.6f), RoundedCornerShape(22.dp))
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Zamknij",
                        tint = Color.White
                    )
                }

                Button(
                    onClick = onSave,
                    shape = RoundedCornerShape(24.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = ElectricGreen,
                        contentColor = Color.Black
                    ),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.SaveAlt,
                        contentDescription = "Zapisz w galerii",
                        tint = Color.Black,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Zapisz w galerii",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                }
            }
        }
    }
}

@Composable
fun LocationPinDialog(
    onDismiss: () -> Unit,
    onSend: (latitude: Double, longitude: Double, altitude: Double, accuracy: Float, note: String) -> Unit
) {
    val appColors = LocalAppColors.current
    var latText by remember { mutableStateOf("52.2297") }
    var lonText by remember { mutableStateOf("21.0122") }
    var altText by remember { mutableStateOf("110.0") }
    var accText by remember { mutableStateOf("5.0") }
    var noteText by remember { mutableStateOf("Status: Bezpieczny (Offline)") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Place,
                    contentDescription = null,
                    tint = ElectricGreen
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Pinezka lokalizacji (900 B BEP 44)",
                    style = MaterialTheme.typography.titleMedium,
                    color = appColors.textPrimary
                )
            }
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "Przesyła współrzędne geograficzne i status bezpieczeństwa w pojedynczym jednoramkowym rekordzie 900 B bez podziału na segmenty (bez chunkingu).",
                    style = MaterialTheme.typography.bodySmall,
                    color = appColors.textSecondary
                )
                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "Szybkie statusy:",
                    style = MaterialTheme.typography.labelSmall,
                    color = appColors.textSecondary,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    SuggestionChip(
                        onClick = { noteText = "Status: Bezpieczny (Offline)" },
                        label = { Text("🟢 Bezpieczny", fontSize = 11.sp) }
                    )
                    SuggestionChip(
                        onClick = { noteText = "Punkt zborny Alpha" },
                        label = { Text("🚩 Zbiórka", fontSize = 11.sp) }
                    )
                    SuggestionChip(
                        onClick = { noteText = "Status: W drodze do celu" },
                        label = { Text("🚶 W drodze", fontSize = 11.sp) }
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = noteText,
                    onValueChange = { noteText = it },
                    label = { Text("Notatka / Status") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = appColors.primary,
                        unfocusedBorderColor = appColors.border,
                        focusedTextColor = appColors.textPrimary,
                        unfocusedTextColor = appColors.textPrimary
                    )
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = latText,
                        onValueChange = { latText = it },
                        label = { Text("Szerokość (Lat)") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = appColors.primary,
                            unfocusedBorderColor = appColors.border,
                            focusedTextColor = appColors.textPrimary,
                            unfocusedTextColor = appColors.textPrimary
                        )
                    )
                    OutlinedTextField(
                        value = lonText,
                        onValueChange = { lonText = it },
                        label = { Text("Długość (Lon)") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = appColors.primary,
                            unfocusedBorderColor = appColors.border,
                            focusedTextColor = appColors.textPrimary,
                            unfocusedTextColor = appColors.textPrimary
                        )
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = altText,
                        onValueChange = { altText = it },
                        label = { Text("Wysokość (m)") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = appColors.primary,
                            unfocusedBorderColor = appColors.border,
                            focusedTextColor = appColors.textPrimary,
                            unfocusedTextColor = appColors.textPrimary
                        )
                    )
                    OutlinedTextField(
                        value = accText,
                        onValueChange = { accText = it },
                        label = { Text("Dokładność (m)") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = appColors.primary,
                            unfocusedBorderColor = appColors.border,
                            focusedTextColor = appColors.textPrimary,
                            unfocusedTextColor = appColors.textPrimary
                        )
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val lat = latText.toDoubleOrNull() ?: 0.0
                    val lon = lonText.toDoubleOrNull() ?: 0.0
                    val alt = altText.toDoubleOrNull() ?: 0.0
                    val acc = accText.toFloatOrNull() ?: 0.0f
                    onSend(lat, lon, alt, acc, noteText.trim())
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = appColors.primary,
                    contentColor = Color.Black
                ),
                modifier = Modifier.testTag("send_location_pin_confirm_button")
            ) {
                Text("Wyślij pinezkę", fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Anuluj", color = appColors.textSecondary)
            }
        },
        containerColor = appColors.surface
    )
}

