package org.pqchat.dht.ui.screens

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.protocol.HandshakeManager
import org.pqchat.dht.ui.components.CameraQrScanner
import org.pqchat.dht.ui.theme.*
import org.pqchat.dht.ui.util.QrCodeUtil
import org.pqchat.dht.ui.viewmodel.ChatViewModel

import org.pqchat.dht.ui.util.SecureScreenEffect

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HandshakeScreen(
    viewModel: ChatViewModel,
    initialTabIsBob: Boolean = false,
    onBack: () -> Unit,
    onSuccess: (String) -> Unit
) {
    SecureScreenEffect()

    val context = LocalContext.current
    var selectedTab by remember(initialTabIsBob) { mutableIntStateOf(if (initialTabIsBob) 1 else 0) }
    var contactName by remember(initialTabIsBob) { mutableStateOf(if (initialTabIsBob) "Alice" else "Bob") }
    var qrBase64Input by remember { mutableStateOf("") }
    var isManualInputExpanded by remember { mutableStateOf(false) }

    // Camera Permission State
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED
        )
    }

    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
    }

    val aliceInitState by viewModel.aliceHandshakeState.collectAsState()
    val isHandshaking by viewModel.isHandshaking.collectAsState()
    val notification by viewModel.statusNotification.collectAsState()
    val handshakeCompleted by viewModel.handshakeCompleted.collectAsState()

    var galleryScanError by remember { mutableStateOf<String?>(null) }

    // Ensure fresh handshake state on entrance and cleanup on disposal
    LaunchedEffect(Unit) {
        viewModel.resetHandshakeState()
    }

    DisposableEffect(Unit) {
        onDispose {
            viewModel.resetHandshakeState()
        }
    }

    val galleryLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: android.net.Uri? ->
        if (uri != null) {
            val decoded = QrCodeUtil.decodeQrFromUri(context, uri)
            if (decoded != null && decoded.isNotBlank()) {
                qrBase64Input = decoded
                galleryScanError = null
            } else {
                galleryScanError = "Nie znaleziono kodu QR ani ukrytej steganografii w wybranym obrazie."
            }
        }
    }

    var qrBitmap by remember { mutableStateOf<Bitmap?>(null) }
    var isAnimatedQr by remember { mutableStateOf(false) }
    var animatedFrames by remember { mutableStateOf<List<Bitmap>>(emptyList()) }
    var currentFrameIndex by remember { mutableIntStateOf(0) }

    LaunchedEffect(aliceInitState) {
        val state = aliceInitState
        if (state != null) {
            qrBitmap = QrCodeUtil.generateQrBitmap(state.qrBytes, 600)
            try {
                animatedFrames = QrCodeUtil.generateMultipartQrBitmaps(state.qrBytes, totalFrames = 4, size = 600)
            } catch (_: Exception) {
                animatedFrames = emptyList()
            }
            currentFrameIndex = 0
        } else {
            qrBitmap = null
            animatedFrames = emptyList()
        }
    }

    LaunchedEffect(isAnimatedQr, animatedFrames) {
        if (isAnimatedQr && animatedFrames.isNotEmpty()) {
            while (isActive) {
                delay(350L) // Rotate animated multipart frames every 350 ms
                currentFrameIndex = (currentFrameIndex + 1) % animatedFrames.size
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Secure Rendezvous Handshake") },
                navigationIcon = {
                    IconButton(
                        onClick = {
                            viewModel.resetHandshakeState()
                            onBack()
                        },
                        modifier = Modifier.testTag("handshake_back_button")
                    ) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = DarkSurface)
            )
        },
        containerColor = DarkBackground
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
        ) {
            PrimaryTabRow(
                selectedTabIndex = selectedTab,
                containerColor = DarkSurface,
                contentColor = NeonCyan
            ) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = {
                        selectedTab = 0
                        contactName = "Bob"
                        viewModel.resetHandshakeState()
                    },
                    text = { Text("Alice (Display QR)") },
                    icon = { Icon(Icons.Default.QrCode, contentDescription = null) },
                    modifier = Modifier.testTag("handshake_alice_tab")
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = {
                        selectedTab = 1
                        contactName = "Alice"
                        viewModel.resetHandshakeState()
                        // If camera permission not yet granted, request it on tab switch
                        if (!hasCameraPermission) {
                            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
                        }
                    },
                    text = { Text("Bob (Scan & Join)") },
                    icon = { Icon(Icons.Default.QrCodeScanner, contentDescription = null) },
                    modifier = Modifier.testTag("handshake_bob_tab")
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Notification / Status banner
            notification?.let { msg ->
                Surface(
                    color = DarkSurfaceVariant,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 6.dp)
                ) {
                    Text(
                        text = msg,
                        style = MaterialTheme.typography.bodyMedium,
                        color = NeonCyan,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }

            if (selectedTab == 0) {
                // ==================== ALICE FLOW ====================
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    OutlinedTextField(
                        value = contactName,
                        onValueChange = { contactName = it },
                        label = { Text("Contact Name (e.g. Bob)") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("handshake_alice_name_input"),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NeonCyan,
                            unfocusedBorderColor = BorderGlass,
                            focusedLabelColor = NeonCyan
                        )
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    if (aliceInitState == null) {
                        Button(
                            onClick = { viewModel.startAliceHandshake(contactName) },
                            colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = Color.Black),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("handshake_generate_qr_button")
                        ) {
                            Text("Generate ML-KEM-512 QR Code", fontWeight = FontWeight.Bold)
                        }
                    } else {
                        // Mode Switch: Statyczny QR / Animowany QR
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 12.dp),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "Statyczny QR",
                                style = MaterialTheme.typography.bodyMedium,
                                color = if (!isAnimatedQr) NeonCyan else TextSecondary,
                                fontWeight = if (!isAnimatedQr) FontWeight.Bold else FontWeight.Normal
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Switch(
                                checked = isAnimatedQr,
                                onCheckedChange = { isAnimatedQr = it },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = NeonCyan,
                                    checkedTrackColor = DarkSurfaceVariant,
                                    uncheckedThumbColor = TextSecondary,
                                    uncheckedTrackColor = DarkSurface
                                )
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = "Animowany QR",
                                style = MaterialTheme.typography.bodyMedium,
                                color = if (isAnimatedQr) NeonCyan else TextSecondary,
                                fontWeight = if (isAnimatedQr) FontWeight.Bold else FontWeight.Normal
                            )
                        }

                        // Display generated QR (Static or Animated Multipart)
                        val activeBitmap = if (isAnimatedQr && animatedFrames.isNotEmpty()) {
                            animatedFrames[currentFrameIndex]
                        } else {
                            qrBitmap
                        }

                        activeBitmap?.let { bitmap ->
                            Surface(
                                shape = RoundedCornerShape(16.dp),
                                color = Color.White,
                                modifier = Modifier
                                    .size(280.dp)
                                    .padding(8.dp)
                                    .testTag("handshake_qr_code_card")
                            ) {
                                Image(
                                    bitmap = bitmap.asImageBitmap(),
                                    contentDescription = if (isAnimatedQr) "Animated Multipart QR" else "ML-KEM-512 QR Code",
                                    modifier = Modifier.fillMaxSize()
                                )
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            if (isAnimatedQr && animatedFrames.isNotEmpty()) {
                                Row(
                                    horizontalArrangement = Arrangement.Center,
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    for (i in animatedFrames.indices) {
                                        Box(
                                            modifier = Modifier
                                                .padding(horizontal = 4.dp)
                                                .size(if (i == currentFrameIndex) 10.dp else 6.dp)
                                                .clip(CircleShape)
                                                .background(if (i == currentFrameIndex) NeonCyan else Color.DarkGray)
                                        )
                                    }
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = "Part ${currentFrameIndex + 1}/${animatedFrames.size} (350 ms)",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = NeonCyan,
                                    fontFamily = FontFamily.Monospace
                                )
                            } else {
                                Text(
                                    text = "Dense static QR code (${HandshakeManager.QR_DATA_SIZE} B)",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = TextSecondary
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        val state = aliceInitState!!
                        Text(
                            text = "Rendezvous Target_0 (SHA-1):",
                            style = MaterialTheme.typography.labelSmall,
                            color = TextSecondary
                        )
                        Text(
                            text = CryptoUtils.toHex(state.target0),
                            style = MaterialTheme.typography.labelSmall,
                            color = ElectricGreen,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp
                        )

                        Spacer(modifier = Modifier.height(16.dp))

                        if (isHandshaking) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(color = NeonCyan, modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    text = "Listening for Bob's handshake on DHT...",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = NeonCyan
                                )
                            }
                        }

                        // Steganographic Image Share Option
                        OutlinedButton(
                            onClick = {
                                val stegoBytes = QrCodeUtil.generateHarmlessStegoPng(state.qrBytes)
                                val shareIntent = QrCodeUtil.createShareStegoImageIntent(context, stegoBytes)
                                context.startActivity(Intent.createChooser(shareIntent, "Share steganographic image"))
                            },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCyan),
                            border = BorderStroke(1.dp, NeonCyan.copy(alpha = 0.7f)),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                                .testTag("handshake_share_stego_button")
                        ) {
                            Icon(Icons.Default.Image, contentDescription = null, modifier = Modifier.size(18.dp), tint = NeonCyan)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Hide in image (PNG Steganography)", fontWeight = FontWeight.SemiBold)
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        // Controls to reset or regenerate QR code
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            OutlinedButton(
                                onClick = { viewModel.resetHandshakeState() },
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = AmberWarning),
                                border = BorderStroke(1.dp, AmberWarning),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Reset")
                            }
                            Button(
                                onClick = {
                                    viewModel.resetHandshakeState()
                                    viewModel.startAliceHandshake(contactName)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = Color.Black),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier
                                    .weight(1.5f)
                                    .testTag("handshake_new_qr_button")
                            ) {
                                Text("New QR Code", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            } else {
                // ==================== BOB FLOW (SCAN & JOIN) ====================
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                ) {
                    OutlinedTextField(
                        value = contactName,
                        onValueChange = { contactName = it },
                        label = { Text("Contact Name (e.g. Alice)") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("handshake_bob_name_input"),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NeonCyan,
                            unfocusedBorderColor = BorderGlass,
                            focusedLabelColor = NeonCyan
                        )
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    // Camera Scanner or Permission Prompt
                    if (hasCameraPermission) {
                        CameraQrScanner(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(320.dp),
                            onQrScanned = { scannedPayload ->
                                qrBase64Input = scannedPayload
                            }
                        )
                    } else {
                        // Permission Card
                        Surface(
                            color = DarkSurface,
                            shape = RoundedCornerShape(16.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, BorderGlass, RoundedCornerShape(16.dp))
                        ) {
                            Column(
                                modifier = Modifier.padding(20.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Icon(
                                    imageVector = Icons.Default.CameraAlt,
                                    contentDescription = "Camera Required",
                                    tint = NeonCyan,
                                    modifier = Modifier.size(48.dp)
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                                Text(
                                    text = "Camera Permission Required",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = TextPrimary
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = "Enable camera access to scan Alice's ML-KEM-512 handshake QR code directly from the screen.",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = TextSecondary,
                                    lineHeight = 20.sp
                                )
                                Spacer(modifier = Modifier.height(16.dp))
                                Button(
                                    onClick = { cameraPermissionLauncher.launch(Manifest.permission.CAMERA) },
                                    colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = Color.Black),
                                    shape = RoundedCornerShape(10.dp)
                                ) {
                                    Icon(Icons.Default.CameraAlt, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Grant Camera Access", fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Gallery / Photo Scan Button
                    OutlinedButton(
                        onClick = { galleryLauncher.launch("image/*") },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCyan),
                        border = BorderStroke(1.dp, NeonCyan.copy(alpha = 0.6f)),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("handshake_gallery_button")
                    ) {
                        Icon(
                            imageVector = Icons.Default.PhotoLibrary,
                            contentDescription = "Scan from Gallery",
                            modifier = Modifier.size(20.dp),
                            tint = NeonCyan
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Scan QR or steganographic image from gallery",
                            fontWeight = FontWeight.SemiBold,
                            color = NeonCyan
                        )
                    }

                    if (galleryScanError != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Surface(
                            color = Color.Red.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier.padding(10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Warning,
                                    contentDescription = null,
                                    tint = Color.Red,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = galleryScanError ?: "",
                                    color = Color.Red,
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // QR Status / Validation Badge
                    val isPayloadValid = remember(qrBase64Input) {
                        try {
                            if (qrBase64Input.isBlank()) false
                            else {
                                val bytes = QrCodeUtil.decodeQrString(qrBase64Input)
                                bytes.size == HandshakeManager.QR_DATA_SIZE // Combined PK (832) + Seed_init (32) = 864 B
                            }
                        } catch (_: Exception) {
                            false
                        }
                    }

                    if (qrBase64Input.isNotBlank()) {
                        Surface(
                            color = if (isPayloadValid) ElectricGreen.copy(alpha = 0.15f) else Color.Red.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = if (isPayloadValid) Icons.Default.CheckCircle else Icons.Default.Warning,
                                    contentDescription = null,
                                    tint = if (isPayloadValid) ElectricGreen else Color.Red,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = if (isPayloadValid) "Valid Hybrid Handshake Key (${HandshakeManager.QR_DATA_SIZE} bytes verified)" else "Invalid QR code payload format",
                                    color = if (isPayloadValid) ElectricGreen else Color.Red,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))
                    }

                    // Action Button: Encapsulate & Put to DHT
                    Button(
                        onClick = {
                            try {
                                val bytes = QrCodeUtil.decodeQrString(qrBase64Input)
                                viewModel.processBobHandshake(bytes, contactName)
                            } catch (_: Exception) {}
                        },
                        enabled = isPayloadValid && !isHandshaking,
                        colors = ButtonDefaults.buttonColors(containerColor = ElectricGreen, contentColor = Color.Black),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("handshake_encapsulate_button")
                    ) {
                        if (isHandshaking) {
                            CircularProgressIndicator(color = Color.Black, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(10.dp))
                            Text("Encapsulating & Publishing...", fontWeight = FontWeight.Bold)
                        } else {
                            Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Encapsulate & Put to DHT", fontWeight = FontWeight.Bold)
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Manual Paste Toggle
                    TextButton(
                        onClick = { isManualInputExpanded = !isManualInputExpanded },
                        modifier = Modifier
                            .align(Alignment.CenterHorizontally)
                            .testTag("handshake_toggle_manual_paste")
                    ) {
                        Icon(
                            imageVector = if (isManualInputExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                            contentDescription = null,
                            tint = TextSecondary,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = if (isManualInputExpanded) "Hide manual Base64 input" else "Or paste Base64 code manually",
                            color = TextSecondary,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }

                    AnimatedVisibility(
                        visible = isManualInputExpanded,
                        enter = fadeIn(),
                        exit = fadeOut()
                    ) {
                        OutlinedTextField(
                            value = qrBase64Input,
                            onValueChange = { qrBase64Input = it },
                            label = { Text("QR Code Payload (Base64)") },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(120.dp)
                                .testTag("handshake_manual_payload_input"),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = NeonCyan,
                                unfocusedBorderColor = BorderGlass,
                                focusedLabelColor = NeonCyan
                            ),
                            placeholder = {
                                Text("Paste Alice's ${HandshakeManager.QR_DATA_SIZE}-byte QR Base64 data here...", color = TextSecondary)
                            }
                        )
                    }
                }
            }
        }

        val completedState = handshakeCompleted
        if (completedState != null) {
            AlertDialog(
                onDismissRequest = {
                    viewModel.resetHandshakeState()
                    onBack()
                },
                icon = {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = ElectricGreen,
                        modifier = Modifier.size(36.dp)
                    )
                },
                title = {
                    Text(
                        text = "Post-Quantum Session Established",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                },
                text = {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "New contact: ${completedState.contactName}",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = NeonCyan
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Compare the 8-digit SAS (Short Authentication String) code below with your peer out-of-band (e.g. in person or by phone):",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                        Spacer(modifier = Modifier.height(14.dp))
                        Surface(
                            color = DarkSurfaceVariant,
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, ElectricGreen.copy(alpha = 0.5f)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 16.dp, horizontal = 12.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = completedState.sas,
                                    style = MaterialTheme.typography.headlineMedium,
                                    fontWeight = FontWeight.ExtraBold,
                                    fontFamily = FontFamily.Monospace,
                                    color = ElectricGreen,
                                    letterSpacing = 4.sp
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "Matching codes confirm absence of Man-in-the-Middle (MitM) attacks on ML-KEM-512.",
                            style = MaterialTheme.typography.labelSmall,
                            color = TextSecondary,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            val targetId = completedState.contactId
                            viewModel.confirmHandshakeAndVerify(targetId)
                            onSuccess(targetId)
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = ElectricGreen,
                            contentColor = Color.Black
                        ),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("handshake_confirm_verified_button")
                    ) {
                        Icon(Icons.Default.VerifiedUser, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Confirm identity (SAS match)", fontWeight = FontWeight.Bold)
                    }
                },
                dismissButton = {
                    OutlinedButton(
                        onClick = {
                            val targetId = completedState.contactId
                            viewModel.confirmHandshakeWithoutVerification(targetId)
                            onSuccess(targetId)
                        },
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = AmberWarning
                        ),
                        border = BorderStroke(1.dp, AmberWarning.copy(alpha = 0.6f)),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("handshake_confirm_unverified_button")
                    ) {
                        Text("Continue without verification", fontWeight = FontWeight.Normal)
                    }
                },
                containerColor = DarkSurface
            )
        }
    }
}
