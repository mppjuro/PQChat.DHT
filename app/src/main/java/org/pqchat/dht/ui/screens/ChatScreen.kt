package org.pqchat.dht.ui.screens

import android.graphics.BitmapFactory
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.pqchat.dht.data.db.MessageEntity
import org.pqchat.dht.ui.theme.*
import org.pqchat.dht.ui.viewmodel.ChatViewModel
import java.text.SimpleDateFormat
import java.util.*
import androidx.compose.animation.core.*
import androidx.compose.ui.text.font.FontWeight
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    viewModel: ChatViewModel,
    contactId: String,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val appColors = LocalAppColors.current

    val contacts by viewModel.contacts.collectAsState()
    val contact = contacts.firstOrNull { it.id == contactId }
    val messages by viewModel.messages.collectAsState()
    val nextPollInMs by viewModel.nextPollInMs.collectAsState()

    var textInput by remember { mutableStateOf("") }

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
            } catch (_: Exception) {}
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
                        Text(
                            text = contact?.name ?: "Chat",
                            style = MaterialTheme.typography.titleMedium,
                            color = appColors.textPrimary
                        )
                        contact?.let {
                            Text(
                                text = "TX: ${it.counterOut}  •  RX: ${it.counterIn}  •  Epoch: ${it.rekeyEpoch}",
                                style = MaterialTheme.typography.labelSmall,
                                color = appColors.primary
                            )
                        }
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = appColors.textPrimary
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
                    IconButton(onClick = { viewModel.sendTestPngImage() }) {
                        Icon(
                            imageVector = Icons.Default.Image,
                            contentDescription = "Send Chunked PNG Test",
                            tint = appColors.secondary
                        )
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
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Attachment button for sending real pictures/files over 900B DHT chunks
                    IconButton(
                        onClick = { imagePickerLauncher.launch("image/*") },
                        modifier = Modifier.size(44.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.AddPhotoAlternate,
                            contentDescription = "Attach Image",
                            tint = appColors.primary
                        )
                    }

                    OutlinedTextField(
                        value = textInput,
                        onValueChange = { textInput = it },
                        placeholder = { Text("Wiadomość (szyfrowana ramka DHT)...", color = appColors.textSecondary) },
                        modifier = Modifier
                            .weight(1f)
                            .padding(end = 8.dp),
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
                            .size(48.dp),
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
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 12.dp, vertical = 8.dp),
            reverseLayout = false
        ) {
            items(messages, key = { it.id }) { msg ->
                MessageBubble(message = msg)
                Spacer(modifier = Modifier.height(8.dp))
            }
        }
    }
}

@Composable
fun MessageBubble(message: MessageEntity) {
    val appColors = LocalAppColors.current

    val isOut = message.isOutgoing
    val alignment = if (isOut) Alignment.End else Alignment.Start
    val bgColor = if (isOut) appColors.surfaceVariant else appColors.surface
    val borderColor = if (isOut) appColors.primary.copy(alpha = 0.4f) else appColors.secondary.copy(alpha = 0.4f)

    val timeStr = remember(message.timestamp) {
        val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        sdf.format(Date(message.timestamp))
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
                // Image payload if present
                message.rawImageBytes?.let { bytes ->
                    val bitmap = remember(bytes) {
                        BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    }
                    if (bitmap != null) {
                        Image(
                            bitmap = bitmap.asImageBitmap(),
                            contentDescription = "PNG Attachment",
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(160.dp)
                                .clip(RoundedCornerShape(8.dp))
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                }

                // Text Content
                message.rawTextContent?.let { text ->
                    Text(
                        text = text,
                        style = MaterialTheme.typography.bodyLarge,
                        color = appColors.textPrimary
                    )
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

                    val statusColor = when (message.status) {
                        "CONFIRMED_DHT" -> ElectricGreen
                        "DELIVERED", "SENT_DHT", "PENDING_DELIVERY" -> appColors.primary
                        else -> AmberWarning
                    }

                    Text(
                        text = message.status,
                        style = MaterialTheme.typography.labelSmall,
                        color = statusColor,
                        fontSize = 10.sp
                    )
                }
            }
        }
    }
}
