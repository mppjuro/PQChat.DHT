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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize Notification Channels
        NotificationHelper.createNotificationChannel(this)


        setContent {
            val themeMode by viewModel.themeMode.collectAsState()
            val isBiometricEnabled by viewModel.isBiometricLockEnabled.collectAsState()
            val isPinConfigured by viewModel.isAppLockPinSet.collectAsState()
            val isDuressConfigured by viewModel.isDuressPinSet.collectAsState()
            val isDuressActive by viewModel.isDuressActive.collectAsState()

            val requiresLock = (isBiometricEnabled || isPinConfigured || isDuressConfigured) && !isDuressActive
            var isUnlocked by remember(requiresLock) { mutableStateOf(!requiresLock) }

            PQChatTheme(themeMode = themeMode) {
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
                    MainAppNavigation(viewModel)
                }
            }
        }
    }
}

@Composable
fun MainAppNavigation(viewModel: ChatViewModel) {
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
                onBack = { currentScreen = Screen.ContactList },
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
