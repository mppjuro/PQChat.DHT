package org.pqchat.dht.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.core.content.ContextCompat
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.ui.screens.*
import org.pqchat.dht.ui.theme.PQChatTheme
import androidx.fragment.app.FragmentActivity
import org.pqchat.dht.ui.util.BiometricAuthHelper
import org.pqchat.dht.ui.util.NotificationHelper
import org.pqchat.dht.ui.viewmodel.ChatViewModel

class MainActivity : FragmentActivity() {

    val viewModel: ChatViewModel by viewModels()
    private var lockAppCallback: (() -> Unit)? = null

    fun lockApp() {
        lockAppCallback?.invoke()
    }

    private fun applyCustomBootstrap(intent: android.content.Intent?) {
        val useRealDht = intent?.getBooleanExtra("use_real_dht", false) == true
        val isTestbedExplicit = intent?.getBooleanExtra("is_local_testbed", false) == true
        if (useRealDht || (intent?.hasExtra("is_local_testbed") == true && !isTestbedExplicit)) {
            org.pqchat.dht.dht.leaf.DhtLeafNode.customBootstrapEndpoints = emptyList()
            org.pqchat.dht.dht.leaf.DhtLeafNode.isLocalTestbedMode = false
            (application as? org.pqchat.dht.PQChatApplication)?.let { app ->
                app.dhtLeafNode.reconfigureCustomBootstrap(emptyList())
            }
        } else {
            val bootstrapPort = intent?.getIntExtra("dht_bootstrap_port", -1) ?: -1
            if (bootstrapPort > 0 || isTestbedExplicit) {
                val port = if (bootstrapPort > 0) bootstrapPort else 30000
                val host = intent?.getStringExtra("dht_bootstrap_host") ?: "10.0.2.2"
                val endpoints = listOf(Pair(host, port))
                org.pqchat.dht.dht.leaf.DhtLeafNode.customBootstrapEndpoints = endpoints
                if (host == "10.0.2.2" || host == "127.0.0.1" || host.startsWith("10.") || host.startsWith("192.168.")) {
                    org.pqchat.dht.dht.leaf.DhtLeafNode.isLocalTestbedMode = true
                }
                (application as? org.pqchat.dht.PQChatApplication)?.let { app ->
                    app.dhtLeafNode.reconfigureCustomBootstrap(endpoints)
                }
            }
        }

        val e2eFastMode = intent?.getBooleanExtra("e2e_fast_mode", false) == true
        if (e2eFastMode) {
            (application as? org.pqchat.dht.PQChatApplication)?.let { app ->
                app.settingsManager.setIntervalForegroundChat(2000L)
                app.settingsManager.setIntervalAppActive(2000L)
                app.settingsManager.setIntervalBackgroundIdle(3000L)
                app.settingsManager.setIntervalDozeSleep(5000L)
                app.pollingScheduler.pollingManager.jitterRatio = 0.0
                app.pollingScheduler.pollingManager.updateIntervals(
                    foreground = 2000L,
                    appActive = 2000L,
                    bgIdle = 3000L,
                    doze = 5000L
                )
                app.pollingScheduler.pollingManager.isFastMode = true
                app.trafficGenerator.isFastMode = true
                app.repository.isFastTestMode = true
                app.repository.outboundPoissonQueue.isFastMode = true
                org.pqchat.dht.dht.leaf.DhtLeafNode.isFastTestMode = true
                app.researchTelemetryManager.ttlSampler?.stop()
                app.repository.decoyTargetPool.clear()
                app.repository.blindRepublishPool.clear()
                app.repository.delayedPutMaxMs = 0L
                app.repository.decoyPutSlotsCount = 0

                if (useRealDht) {
                    app.repository.decoyTargetPool.isEnabled = false
                    app.trafficGenerator.decoyTargetPool.isEnabled = false
                    app.repository.blindRepublishPool.isEnabled = false
                }
            }
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        applyCustomBootstrap(intent)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize Notification Channels
        NotificationHelper.createNotificationChannel(this)

        applyCustomBootstrap(intent)


        setContent {
            val themeMode by viewModel.themeMode.collectAsState()
            val isBiometricEnabled by viewModel.isBiometricLockEnabled.collectAsState()
            val isPinConfigured by viewModel.isAppLockPinSet.collectAsState()
            val isDuressConfigured by viewModel.isDuressPinSet.collectAsState()
            val isDuressActive by viewModel.isDuressActive.collectAsState()

            val requiresLock = (isBiometricEnabled || isPinConfigured || isDuressConfigured) && !isDuressActive
            var isUnlocked by remember { mutableStateOf(!requiresLock) }

            LaunchedEffect(requiresLock) {
                if (!requiresLock) {
                    isUnlocked = true
                }
            }

            lockAppCallback = {
                if (requiresLock) {
                    isUnlocked = false
                }
            }

            PQChatTheme(themeMode = themeMode) {
                @OptIn(ExperimentalComposeUiApi::class)
                Surface(
                    modifier = Modifier
                        .fillMaxSize()
                        .semantics {
                            testTagsAsResourceId = true
                        }
                ) {
                    if (isDuressActive) {
                        DecoyNotesScreen()
                    } else if (!isUnlocked && requiresLock) {
                        BiometricLockScreen(
                            onUnlockRequested = {
                                BiometricAuthHelper.authenticate(
                                    activity = this@MainActivity,
                                    onSuccess = { isUnlocked = true }
                                )
                            },
                            onPinSubmitted = { pin ->
                                viewModel.verifyPin(pin)
                            },
                            onUnlockSuccess = {
                                isUnlocked = true
                            },
                            onDuressTriggered = {
                                viewModel.triggerDuressMode()
                            },
                            isPinConfigured = isPinConfigured || isDuressConfigured,
                            isBiometricAvailable = isBiometricEnabled
                        )
                    } else {
                        MainAppNavigation(
                            viewModel = viewModel,
                            requiresLock = requiresLock,
                            onLockRequested = { isUnlocked = false }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun MainAppNavigation(
    viewModel: ChatViewModel,
    requiresLock: Boolean = false,
    onLockRequested: () -> Unit = {}
) {
    val context = LocalContext.current
    var currentScreen by remember { mutableStateOf<Screen>(Screen.ContactList) }

    val selectedContactId by viewModel.selectedContactId.collectAsState()

    // Automatic permission request on app startup for Camera & Post-Notifications
    val permissionsToRequest = remember {
        val list = mutableListOf(Manifest.permission.CAMERA)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            list.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        list.toTypedArray()
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { _ ->
        // Permissions handled
    }

    LaunchedEffect(Unit) {
        val missingPermissions = permissionsToRequest.filter { perm ->
            ContextCompat.checkSelfPermission(context, perm) != PackageManager.PERMISSION_GRANTED
        }
        if (missingPermissions.isNotEmpty()) {
            permissionLauncher.launch(missingPermissions.toTypedArray())
        }
    }

    // Auto-navigate to chat screen when a session is selected outside HandshakeScreen
    LaunchedEffect(selectedContactId) {
        val id = selectedContactId
        if (id != null && currentScreen !is Screen.Chat && currentScreen !is Screen.Handshake) {
            currentScreen = Screen.Chat(id)
        }
    }

    androidx.activity.compose.BackHandler(enabled = currentScreen !is Screen.ContactList) {
        when (currentScreen) {
            is Screen.Chat -> {
                viewModel.unselectContact()
                currentScreen = Screen.ContactList
            }
            is Screen.Settings -> {
                if (requiresLock) {
                    onLockRequested()
                }
                currentScreen = Screen.ContactList
            }
            is Screen.Handshake -> {
                viewModel.resetHandshakeState()
                currentScreen = Screen.ContactList
            }
            is Screen.Diagnostics -> {
                currentScreen = Screen.ContactList
            }
            Screen.ContactList -> {}
        }
    }

    when (val screen = currentScreen) {
        is Screen.ContactList -> {
            ContactListScreen(
                viewModel = viewModel,
                onContactClick = { contactId ->
                    viewModel.selectContact(contactId)
                    currentScreen = Screen.Chat(contactId)
                },
                onNewChatClick = {
                    currentScreen = Screen.Handshake(isBob = false)
                },
                onJoinChatClick = {
                    currentScreen = Screen.Handshake(isBob = true)
                },
                onDiagnosticsClick = {
                    currentScreen = Screen.Diagnostics
                },
                onSettingsClick = {
                    currentScreen = Screen.Settings
                }
            )
        }

        is Screen.Settings -> {
            SettingsScreen(
                viewModel = viewModel,
                onBack = {
                    if (requiresLock) {
                        onLockRequested()
                    }
                    currentScreen = Screen.ContactList
                },
                onOpenSelfNotes = {
                    viewModel.openSelfNotes()
                    currentScreen = Screen.Chat(ChatRepository.SELF_CONTACT_ID)
                }
            )
        }

        is Screen.Handshake -> {
            HandshakeScreen(
                viewModel = viewModel,
                initialTabIsBob = screen.isBob,
                onBack = {
                    viewModel.resetHandshakeState()
                    currentScreen = Screen.ContactList
                },
                onSuccess = { contactId ->
                    viewModel.selectContact(contactId)
                    currentScreen = Screen.Chat(contactId)
                }
            )
        }

        is Screen.Chat -> {
            ChatScreen(
                viewModel = viewModel,
                contactId = screen.contactId,
                onBack = {
                    viewModel.unselectContact()
                    currentScreen = Screen.ContactList
                }
            )
        }

        is Screen.Diagnostics -> {
            DiagnosticsScreen(
                viewModel = viewModel,
                onBack = { currentScreen = Screen.ContactList }
            )
        }
    }
}

sealed class Screen {
    object ContactList : Screen()
    object Settings : Screen()
    data class Handshake(val isBob: Boolean) : Screen()
    data class Chat(val contactId: String) : Screen()
    object Diagnostics : Screen()
}
