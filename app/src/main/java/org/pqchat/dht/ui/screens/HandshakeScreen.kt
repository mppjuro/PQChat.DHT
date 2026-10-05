package org.pqchat.dht.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.ui.components.CameraQrScanner
import org.pqchat.dht.ui.theme.*
import org.pqchat.dht.ui.util.QrCodeUtil
import org.pqchat.dht.ui.viewmodel.ChatViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HandshakeScreen(
    viewModel: ChatViewModel,
    initialTabIsBob: Boolean = false,
    onBack: () -> Unit,
    onSuccess: () -> Unit
) {
    val context = LocalContext.current
    var selectedTab by remember { mutableStateOf(if (initialTabIsBob) 1 else 0) }
    var contactName by remember { mutableStateOf(if (selectedTab == 0) "Bob" else "Alice") }
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

    var qrBitmap by remember { mutableStateOf<Bitmap?>(null) }

    LaunchedEffect(aliceInitState) {
        val state = aliceInitState
        if (state != null) {
            qrBitmap = QrCodeUtil.generateQrBitmap(state.qrBytes, 600)
        } else {
            qrBitmap = null
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Secure Rendezvous Handshake") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
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
            TabRow(
                selectedTabIndex = selectedTab,
                containerColor = DarkSurface,
                contentColor = NeonCyan
            ) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0; contactName = "Bob" },
                    text = { Text("Alice (Display QR)") },
                    icon = { Icon(Icons.Default.QrCode, contentDescription = null) }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = {
                        selectedTab = 1
                        contactName = "Alice"
                        // If camera permission not yet granted, request it on tab switch
                        if (!hasCameraPermission) {
                            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
                        }
                    },
                    text = { Text("Bob (Scan & Join)") },
                    icon = { Icon(Icons.Default.QrCodeScanner, contentDescription = null) }
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
                        modifier = Modifier.fillMaxWidth(),
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
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Generate ML-KEM-512 QR Code", fontWeight = FontWeight.Bold)
                        }
                    } else {
                        // Display generated QR
                        qrBitmap?.let { bitmap ->
                            Surface(
                                shape = RoundedCornerShape(16.dp),
                                color = Color.White,
                                modifier = Modifier
                                    .size(280.dp)
                                    .padding(8.dp)
                            ) {
                                Image(
                                    bitmap = bitmap.asImageBitmap(),
                                    contentDescription = "ML-KEM-512 QR Code",
                                    modifier = Modifier.fillMaxSize()
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
                        modifier = Modifier.fillMaxWidth(),
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

                    // QR Status / Validation Badge
                    val isPayloadValid = remember(qrBase64Input) {
                        try {
                            if (qrBase64Input.isBlank()) false
                            else {
                                val bytes = QrCodeUtil.decodeQrString(qrBase64Input)
                                bytes.size == 832 // ED25519_PK(32) + MLKEM512_PK(800)
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
                                    text = if (isPayloadValid) "Valid ML-KEM-512 Handshake Key (832 bytes verified)" else "Invalid QR code payload format",
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
                        modifier = Modifier.fillMaxWidth()
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
                        modifier = Modifier.align(Alignment.CenterHorizontally)
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
                                .height(120.dp),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = NeonCyan,
                                unfocusedBorderColor = BorderGlass,
                                focusedLabelColor = NeonCyan
                            ),
                            placeholder = {
                                Text("Paste Alice's 832-byte QR Base64 data here...", color = TextSecondary)
                            }
                        )
                    }
                }
            }
        }
    }
}
