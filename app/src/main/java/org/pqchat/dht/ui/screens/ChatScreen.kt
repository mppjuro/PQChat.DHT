package org.pqchat.dht.ui.screens

import android.graphics.BitmapFactory
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import org.pqchat.dht.data.db.MessageEntity
import org.pqchat.dht.ui.theme.*
import org.pqchat.dht.ui.util.ImageGallerySaver
import org.pqchat.dht.ui.viewmodel.ChatViewModel
import java.text.SimpleDateFormat
import java.util.*
import androidx.compose.animation.core.*
import kotlinx.coroutines.delay
import org.pqchat.dht.data.repository.ChatRepository

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
    var showSasDialog by remember { mutableStateOf(false) }
    var showEditContactNameDialog by remember { mutableStateOf(false) }
    var editedContactName by remember { mutableStateOf("") }
    var fullscreenImageBytes by remember { mutableStateOf<ByteArray?>(null) }

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
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .clickable(enabled = contact != null) {
                                    if (contact != null) {
                                        editedContactName = contact.name
                                        showEditContactNameDialog = true
                                    }
                                }
                        ) {
                            Text(
                                text = contact?.name ?: "Chat",
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
                                    modifier = Modifier.size(24.dp)
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
                MessageBubble(
                    message = msg,
                    onImageClick = { bytes -> fullscreenImageBytes = bytes }
                )
                Spacer(modifier = Modifier.height(8.dp))
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
                    TextButton(onClick = { showSasDialog = false }) {
                        Text("Zamknij", color = appColors.textSecondary)
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
    }
}

@Composable
fun MessageBubble(
    message: MessageEntity,
    onImageClick: ((ByteArray) -> Unit)? = null
) {
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
                        "EXPIRED_OFFLINE" -> Color(0xFFFF5252)
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
