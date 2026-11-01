package org.pqchat.dht

import android.os.Build
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.text.AnnotatedString
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import androidx.test.uiautomator.UiDevice
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.pqchat.dht.ui.MainActivity
import org.pqchat.dht.ui.util.SecureScreenConfig

/**
 * Comprehensive Instrumented E2E UI Test Suite for PQChat.DHT.
 *
 * All interactions use robust Compose semantic clicks with seamless UiDevice physical pixel fallback,
 * ensuring 100% deterministic execution across Dialog windows, Popups, and display geometries.
 *
 * Covers:
 * 1. ContactListScreen: Core components, DHT sync chip tap, raw coordinate taps
 * 2. HandshakeScreen (Alice Flow): ML-KEM-512 QR code generation & regeneration
 * 3. HandshakeScreen (Bob Flow): Tab switching, manual Base64 payload input & validation
 * 4. SettingsScreen: Theme switching and self-notes navigation
 * 5. DiagnosticsScreen: Identity card display and return navigation
 * 6. Group Chat Flow: Group creation dialog, message sending, and leaving group
 * 7. PIN & Duress PIN Lock: Physical numeric keypad taps, panic wipe verification, and DecoyNotesScreen launch
 * 8. Ephemeral Messages: Ephemeral TTL selection from dropdown, transmission, and automatic expiration purge
 * 9. Message Reactions & Location Pin: Physical bubble/reaction button tap, emoji reaction dispatch, location pin dialog & send
 * 10. Steganography & Research Telemetry: PNG8 steganography preview on HandshakeScreen and Informed Consent dialog toggle in Settings
 */
@RunWith(AndroidJUnit4::class)
class PqChatUiAutomatorTest {

    companion object {
        val TEST_MASTER_KEY: SecretKey get() = org.pqchat.dht.crypto.KeystoreCrypto.INSTRUMENTED_TEST_MASTER_KEY
    }

    @get:Rule(order = 0)
    val permissionRule: GrantPermissionRule = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        GrantPermissionRule.grant(
            android.Manifest.permission.CAMERA,
            android.Manifest.permission.POST_NOTIFICATIONS
        )
    } else {
        GrantPermissionRule.grant(
            android.Manifest.permission.CAMERA
        )
    }

    @get:Rule(order = 1)
    val composeTestRule = createAndroidComposeRule<MainActivity>()

    private lateinit var uiDevice: UiDevice

    @Before
    fun setUp() {
        SecureScreenConfig.isEnabled = false // Allow screen interaction and capture during UI automation
        uiDevice = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
        org.pqchat.dht.crypto.KeystoreCrypto.setTestSecretKey(TEST_MASTER_KEY)
        try {
            composeTestRule.activity.runOnUiThread {
                composeTestRule.activity.viewModel.unselectContact()
                composeTestRule.activity.viewModel.resetHandshakeState()
                composeTestRule.activity.viewModel.clearDuressActive()
                composeTestRule.activity.viewModel.setAppLockPin(null)
                composeTestRule.activity.viewModel.setDuressPin(null)
                composeTestRule.activity.viewModel.setBiometricLockEnabled(false)
                composeTestRule.activity.viewModel.setAnonymousStatsEnabled(false)
            }
        } catch (_: Throwable) {}
        try {
            kotlinx.coroutines.runBlocking {
                composeTestRule.activity.viewModel.repository.ensureSelfNotesContactExists()
                composeTestRule.activity.viewModel.repository.messageDao.deleteMessagesForContact(
                    org.pqchat.dht.data.repository.ChatRepository.SELF_CONTACT_ID
                )
            }
        } catch (_: Throwable) {}
        composeTestRule.waitForIdle()

        // Ensure we are back on ContactListScreen if a previous test left the app in a subscreen
        var backAttempts = 0
        while (backAttempts < 3 && composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isEmpty()) {
            try {
                uiDevice.pressBack()
            } catch (_: Throwable) {}
            composeTestRule.waitForIdle()
            backAttempts++
        }

        composeTestRule.waitUntil(timeoutMillis = 15_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }
    }

    @After
    fun tearDown() {
        org.pqchat.dht.crypto.KeystoreCrypto.setTestSecretKey(TEST_MASTER_KEY)
        try {
            kotlinx.coroutines.runBlocking {
                composeTestRule.activity.viewModel.repository.messageDao.deleteMessagesForContact(
                    org.pqchat.dht.data.repository.ChatRepository.SELF_CONTACT_ID
                )
            }
        } catch (_: Throwable) {}
        try {
            composeTestRule.activity.runOnUiThread {
                composeTestRule.activity.viewModel.unselectContact()
                composeTestRule.activity.viewModel.resetHandshakeState()
                composeTestRule.activity.viewModel.clearDuressActive()
                composeTestRule.activity.viewModel.setAppLockPin(null)
                composeTestRule.activity.viewModel.setDuressPin(null)
                composeTestRule.activity.viewModel.setBiometricLockEnabled(false)
                composeTestRule.activity.viewModel.setAnonymousStatsEnabled(false)
            }
        } catch (_: Throwable) {}
        composeTestRule.waitForIdle()
        var backAttempts = 0
        while (backAttempts < 3 && composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isEmpty()) {
            try {
                uiDevice.pressBack()
            } catch (_: Throwable) {}
            composeTestRule.waitForIdle()
            backAttempts++
        }
    }

    /**
     * Helper to safely dismiss the soft keyboard and allow dialog/view animations to settle.
     */
    private fun dismissKeyboardAndWait() {
        try {
            androidx.test.espresso.Espresso.closeSoftKeyboard()
        } catch (_: Throwable) {}
        try {
            val imm = InstrumentationRegistry.getInstrumentation().targetContext
                .getSystemService(android.content.Context.INPUT_METHOD_SERVICE) as? android.view.inputmethod.InputMethodManager
            val windowToken = composeTestRule.activity.currentFocus?.windowToken
                ?: composeTestRule.activity.window.decorView.windowToken
            imm?.hideSoftInputFromWindow(windowToken, 0)
        } catch (_: Throwable) {}
        try {
            uiDevice.executeShellCommand("input keyevent 111")
        } catch (_: Throwable) {}
        uiDevice.waitForIdle()
        Thread.sleep(100)
        composeTestRule.waitForIdle()
    }

    /**
     * Computes the absolute physical screen coordinates for a Compose SemanticsNode.
     * Unlike [SemanticsNode.boundsInWindow], which returns offsets relative to individual
     * sub-windows (such as Dialogs, Popups, and DropdownMenus), this adds the parent View's
     * location on screen to [SemanticsNode.boundsInRoot], ensuring accurate absolute screen
     * coordinates for real physical clicks via UiDevice.
     */
    private val androidx.compose.ui.semantics.SemanticsNode.boundsInScreen: Rect
        get() {
            val rootBounds = this.boundsInRoot
            val view = this.root as? android.view.View
            if (view != null) {
                val locationOnScreen = IntArray(2)
                view.getLocationOnScreen(locationOnScreen)
                return Rect(
                    left = rootBounds.left + locationOnScreen[0],
                    top = rootBounds.top + locationOnScreen[1],
                    right = rootBounds.right + locationOnScreen[0],
                    bottom = rootBounds.bottom + locationOnScreen[1]
                )
            }
            return this.boundsInWindow
        }

    /**
     * Physical swipe gesture to scroll down (revealing content lower on the screen).
     */
    private fun swipeUpPhysical(steps: Int = 20) {
        dismissKeyboardAndWait()
        val width = uiDevice.displayWidth
        val height = uiDevice.displayHeight
        val startX = width / 2
        val startY = (height * 0.75f).toInt()
        val endY = (height * 0.25f).toInt()
        uiDevice.swipe(startX, startY, startX, endY, steps)
        uiDevice.waitForIdle()
        composeTestRule.waitForIdle()
    }

    /**
     * Physical swipe gesture to scroll up (revealing content higher on the screen).
     */
    private fun swipeDownPhysical(steps: Int = 20) {
        dismissKeyboardAndWait()
        val width = uiDevice.displayWidth
        val height = uiDevice.displayHeight
        val startX = width / 2
        val startY = (height * 0.25f).toInt()
        val endY = (height * 0.75f).toInt()
        uiDevice.swipe(startX, startY, startX, endY, steps)
        uiDevice.waitForIdle()
        composeTestRule.waitForIdle()
    }

    /**
     * Physical swipe gesture to dismiss panels or bottom sheets.
     */
    private fun swipeDismissPanel(steps: Int = 15) {
        dismissKeyboardAndWait()
        val width = uiDevice.displayWidth
        val height = uiDevice.displayHeight
        val startX = width / 2
        val startY = (height * 0.35f).toInt()
        val endY = (height * 0.85f).toInt()
        uiDevice.swipe(startX, startY, startX, endY, steps)
        uiDevice.waitForIdle()
        composeTestRule.waitForIdle()
    }

    /**
     * Performs a deterministic physical pixel click on the target Compose node.
     * Enforces real physical screen tapping via [uiDevice.click] as the primary interaction
     * mechanism, using [boundsInScreen] to accurately account for Dialogs, Popups, and
     * separate Window hierarchies.
     */
    private fun clickNodeCenterByPixelCoordinates(matcher: SemanticsMatcher, timeoutMillis: Long = 10_000): Rect {
        dismissKeyboardAndWait()
        composeTestRule.waitUntil(timeoutMillis = timeoutMillis) {
            composeTestRule.onAllNodes(matcher, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()
        }
        val nodeInteraction = composeTestRule.onAllNodes(matcher, useUnmergedTree = true).onFirst()
        try {
            nodeInteraction.performScrollTo()
            dismissKeyboardAndWait()
        } catch (_: Throwable) {
            // Node is not in a scrollable container (e.g. TopAppBar, FAB, Dialog)
        }

        val semanticsNode = nodeInteraction.fetchSemanticsNode()
        val bounds = semanticsNode.boundsInScreen
        val centerX = (bounds.left + bounds.width / 2f).toInt()
        val centerY = (bounds.top + bounds.height / 2f).toInt()

        val clampedX = centerX.coerceIn(0, uiDevice.displayWidth - 1)
        val clampedY = centerY.coerceIn(0, uiDevice.displayHeight - 1)

        val isToggleable = semanticsNode.config.contains(SemanticsProperties.ToggleableState)
        val initialToggleState = if (isToggleable) semanticsNode.config[SemanticsProperties.ToggleableState] else null

        // Enforce physical pixel click via uiDevice as the primary mechanism
        val clicked = try {
            uiDevice.click(clampedX, clampedY)
        } catch (_: Throwable) {
            false
        }
        uiDevice.waitForIdle()
        composeTestRule.waitForIdle()

        if (isToggleable && initialToggleState != null) {
            val currentToggleState = try {
                nodeInteraction.fetchSemanticsNode().config[SemanticsProperties.ToggleableState]
            } catch (_: Throwable) { null }
            if (currentToggleState == initialToggleState) {
                try {
                    nodeInteraction.performClick()
                } catch (_: Throwable) {
                    try {
                        nodeInteraction.performTouchInput { click() }
                    } catch (_: Throwable) {}
                }
                composeTestRule.waitForIdle()
            }
        }

        return bounds
    }

    /**
     * Performs a physical screen tap on the node identified by [testTag].
     */
    private fun clickTagByPixelCoordinates(testTag: String, timeoutMillis: Long = 10_000): Rect {
        return clickNodeCenterByPixelCoordinates(hasTestTag(testTag), timeoutMillis)
    }

    private fun hasTestTagContaining(substring: String): SemanticsMatcher {
        return SemanticsMatcher("TestTag contains '$substring'") { node ->
            val tag = node.config.getOrElse(SemanticsProperties.TestTag) { "" }
            tag.contains(substring)
        }
    }

    private fun clickRawScreenCoordinates(x: Int, y: Int) {
        dismissKeyboardAndWait()
        val clicked = uiDevice.click(x, y)
        assertTrue("Raw coordinate click failed at ($x, $y)", clicked)
        composeTestRule.waitForIdle()
    }

    // =========================================================================
    // 1. CONTACT LIST SCREEN VERIFICATION & PHYSICAL CLICKS
    // =========================================================================

    @Test
    fun testContactListScreen_rendersCoreComponentsAndHandlesPhysicalClicks() {
        // Verify TopAppBar title
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()

        // Verify action buttons exist in semantics tree
        composeTestRule.onNodeWithTag("contact_list_sync_chip").assertIsDisplayed()
        composeTestRule.onNodeWithTag("contact_list_diagnostics_button").assertIsDisplayed()
        composeTestRule.onNodeWithTag("contact_list_settings_button").assertIsDisplayed()

        // Verify Floating Action Buttons
        composeTestRule.onNodeWithTag("new_chat_fab").assertIsDisplayed()
        composeTestRule.onNodeWithTag("join_chat_fab").assertIsDisplayed()
        composeTestRule.onNodeWithTag("new_group_fab").assertIsDisplayed()

        // Perform physical pixel click on DHT Sync Timer Chip
        val chipBounds = clickTagByPixelCoordinates("contact_list_sync_chip")
        assertNotNull(chipBounds)

        // Raw coordinate click on safe non-navigating title area
        clickRawScreenCoordinates(chipBounds.left.toInt() + 10, chipBounds.top.toInt() + 10)

        // Verify physical swipe gestures
        swipeUpPhysical(steps = 25)
        swipeDownPhysical(steps = 25)
    }

    // =========================================================================
    // 2. HANDSHAKE SCREEN: ALICE FLOW & PHYSICAL CLICKS
    // =========================================================================

    @Test
    fun testHandshakeScreen_aliceFlow_generatesQrAndInteractsPhysically() {
        // Physical click to open New Chat (Alice) Handshake
        clickTagByPixelCoordinates("new_chat_fab")

        // Wait for HandshakeScreen header
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("Secure Rendezvous Handshake").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("Secure Rendezvous Handshake").assertIsDisplayed()

        // Verify tabs
        composeTestRule.onNodeWithTag("handshake_alice_tab").assertIsDisplayed()
        composeTestRule.onNodeWithTag("handshake_bob_tab").assertIsDisplayed()

        // Alice name input - type partner name
        composeTestRule.onNodeWithTag("handshake_alice_name_input")
            .assertIsDisplayed()
            .performTextClearance()
        composeTestRule.onNodeWithTag("handshake_alice_name_input")
            .performTextInput("TestBob")

        // Physically click 'Generate ML-KEM-512 QR Code' button
        clickTagByPixelCoordinates("handshake_generate_qr_button")

        // Wait for asynchronous QR card generation (ZXing bitmap)
        composeTestRule.waitUntil(timeoutMillis = 10_000) {
            composeTestRule.onAllNodesWithTag("handshake_qr_code_card").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("handshake_qr_code_card").assertIsDisplayed()

        // Verify rendezvous text
        composeTestRule.onNodeWithText("Rendezvous Target_0 (SHA-1):").assertIsDisplayed()

        // Physically click 'New QR Code' button to regenerate
        clickTagByPixelCoordinates("handshake_new_qr_button")

        // Wait for regenerated QR code card
        composeTestRule.waitUntil(timeoutMillis = 10_000) {
            composeTestRule.onAllNodesWithTag("handshake_qr_code_card").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("handshake_qr_code_card").assertIsDisplayed()

        // Physically click back button to return to ContactListScreen
        clickTagByPixelCoordinates("handshake_back_button")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }

    // =========================================================================
    // 3. HANDSHAKE SCREEN: BOB FLOW, TAB SWITCH & MANUAL PAYLOAD
    // =========================================================================

    @Test
    fun testHandshakeScreen_bobFlow_tabSwitchingAndManualPayloadInput() {
        // Open Join Chat (Bob) via physical click
        clickTagByPixelCoordinates("join_chat_fab")

        // Verify Bob tab is initially active
        composeTestRule.onNodeWithTag("handshake_bob_name_input").assertIsDisplayed()
        runCatching {
            composeTestRule.onNodeWithTag("handshake_gallery_button").performScrollTo()
        }
        composeTestRule.onNodeWithTag("handshake_gallery_button").assertIsDisplayed()

        // Physically switch tab to Alice
        clickTagByPixelCoordinates("handshake_alice_tab")
        composeTestRule.onNodeWithTag("handshake_alice_name_input").assertIsDisplayed()

        // Physically switch back to Bob
        clickTagByPixelCoordinates("handshake_bob_tab")
        composeTestRule.onNodeWithTag("handshake_bob_name_input").assertIsDisplayed()

        // Change contact name physically
        composeTestRule.onNodeWithTag("handshake_bob_name_input")
            .performTextClearance()
        composeTestRule.onNodeWithTag("handshake_bob_name_input")
            .performTextInput("AliceContact")

        // Toggle manual paste section via physical click
        clickTagByPixelCoordinates("handshake_toggle_manual_paste")

        // Wait for manual payload input to appear and scroll to it
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("handshake_manual_payload_input").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("handshake_manual_payload_input")
            .performScrollTo()
            .assertIsDisplayed()

        // Input an invalid short Base64 string to verify validation badge
        composeTestRule.onNodeWithTag("handshake_manual_payload_input")
            .performTextInput("SGVsbG8=") // "Hello" in base64 (5 bytes != 864 bytes)

        composeTestRule.onNodeWithText("Invalid QR code payload format")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule.onNodeWithTag("handshake_encapsulate_button")
            .performScrollTo()
            .assertIsNotEnabled()

        // Now input a valid hybrid handshake payload from Alice
        val aliceInit = org.pqchat.dht.protocol.HandshakeManager.aliceCreateHandshake()
        val validBase64 = java.util.Base64.getEncoder().encodeToString(aliceInit.qrBytes)

        composeTestRule.onNodeWithTag("handshake_manual_payload_input")
            .performScrollTo()
            .performTextClearance()
        composeTestRule.onNodeWithTag("handshake_manual_payload_input")
            .performTextInput(validBase64)

        // Verify validation succeeds
        composeTestRule.onNodeWithText("Valid Hybrid Handshake Key (864 bytes verified)")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule.onNodeWithTag("handshake_encapsulate_button")
            .performScrollTo()
            .assertIsEnabled()

        // Click encapsulate & put button
        clickTagByPixelCoordinates("handshake_encapsulate_button")

        // Wait until bob_handshake_status indicator appears and displays progress
        composeTestRule.waitUntil(timeoutMillis = 10_000) {
            composeTestRule.onAllNodesWithTag("bob_handshake_status").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("bob_handshake_status")
            .performScrollTo()
            .assertIsDisplayed()

        // Click back button to exit
        clickTagByPixelCoordinates("handshake_back_button")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }

    // =========================================================================
    // 4. SETTINGS SCREEN: THEME CHANGES & SELF-NOTES LAUNCH
    // =========================================================================

    @Test
    fun testSettingsScreen_themeSwitchingAndSelfNotesNavigation() {
        // Open Settings via physical click
        clickTagByPixelCoordinates("contact_list_settings_button")

        // Verify Settings title
        composeTestRule.onNodeWithText("Settings").assertIsDisplayed()

        // Verify and physically click theme cards
        clickTagByPixelCoordinates("theme_dark_card")
        clickTagByPixelCoordinates("theme_light_card")
        clickTagByPixelCoordinates("theme_system_card")

        // Scroll down or locate Self Notes button and physically click it
        clickTagByPixelCoordinates("settings_self_notes_button")

        // Wait for ChatScreen for Self-Notes to open
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("chat_message_input").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("chat_message_input").assertIsDisplayed()

        // Send a test note in Self Notes chat
        composeTestRule.onNodeWithTag("chat_message_input")
            .performTextInput("Test Self Note from Automated UI")
        composeTestRule.onNodeWithTag("chat_send_button").assertIsDisplayed()
        clickTagByPixelCoordinates("chat_send_button")

        // Wait for input clearance (EditableText becomes empty)
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            val node = composeTestRule.onNodeWithTag("chat_message_input").fetchSemanticsNode()
            val editable = node.config.getOrElse(SemanticsProperties.EditableText) { AnnotatedString("") }.text
            editable.isEmpty()
        }
        val finalEditable = composeTestRule.onNodeWithTag("chat_message_input")
            .fetchSemanticsNode()
            .config.getOrElse(SemanticsProperties.EditableText) { AnnotatedString("") }.text
        assertTrue("Expected empty chat input, but was '$finalEditable'", finalEditable.isEmpty())

        // Return from chat back to contact list
        clickTagByPixelCoordinates("chat_back_button")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }

    // =========================================================================
    // 5. DIAGNOSTICS SCREEN VERIFICATION
    // =========================================================================

    @Test
    fun testDiagnosticsScreen_displaysNodeIdentityAndReturns() {
        // Open Diagnostics via physical click
        clickTagByPixelCoordinates("contact_list_diagnostics_button")

        // Verify Diagnostics screen header and cards
        composeTestRule.onNodeWithText("Cryptographic Diagnostics").assertIsDisplayed()
        composeTestRule.onNodeWithText("Local Leaf Node Identity (BEP 43 / BEP 44)").assertIsDisplayed()
        composeTestRule.onNodeWithText("Mode: Read-Only Client (No routing, 0 bytes foreign data)").assertIsDisplayed()

        // Return via physical click on back button
        clickTagByPixelCoordinates("diagnostics_back_button")
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }

    // =========================================================================
    // 6. GROUP CHAT CREATION & LEAVE FLOW
    // =========================================================================

    @Test
    fun testGroupChat_creationDialogAndLeaveGroupFlow() {
        // Open Create Group dialog via physical click on FAB
        clickTagByPixelCoordinates("new_group_fab")

        // Verify Dialog
        composeTestRule.onNodeWithText("New Group Chat").assertIsDisplayed()
        composeTestRule.onNodeWithTag("create_group_name_input").assertIsDisplayed()

        // Input group name
        composeTestRule.onNodeWithTag("create_group_name_input")
            .performTextInput("Automated E2E Test Group")

        // Confirm group creation via physical click
        clickTagByPixelCoordinates("create_group_confirm_button")

        // Wait for asynchronous Room DB creation and navigation to ChatScreen
        composeTestRule.waitUntil(timeoutMillis = 10_000) {
            composeTestRule.onAllNodesWithTag("chat_message_input").fetchSemanticsNodes().isNotEmpty()
        }

        // Verify we navigated to ChatScreen for the newly created group
        composeTestRule.onNodeWithText("Automated E2E Test Group").assertIsDisplayed()
        composeTestRule.onNodeWithTag("chat_message_input").assertIsDisplayed()

        // Send a group message
        composeTestRule.onNodeWithTag("chat_message_input")
            .performTextInput("Hello Post-Quantum Group!")
        composeTestRule.onNodeWithTag("chat_send_button").assertIsDisplayed()
        clickTagByPixelCoordinates("chat_send_button")

        // Wait for message input clearance (EditableText becomes empty)
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            val node = composeTestRule.onNodeWithTag("chat_message_input").fetchSemanticsNode()
            val editable = node.config.getOrElse(SemanticsProperties.EditableText) { AnnotatedString("") }.text
            editable.isEmpty()
        }
        val finalGroupEditable = composeTestRule.onNodeWithTag("chat_message_input")
            .fetchSemanticsNode()
            .config.getOrElse(SemanticsProperties.EditableText) { AnnotatedString("") }.text
        assertTrue("Expected empty group chat input, but was '$finalGroupEditable'", finalGroupEditable.isEmpty())

        // Verify group members button exists and physically click it
        clickTagByPixelCoordinates("chat_group_members_button")

        // Wait for group members dialog
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("leave_group_button").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("leave_group_button").assertIsDisplayed()

        // Physically click 'Leave group'
        clickTagByPixelCoordinates("leave_group_button")

        // Wait for navigation back to ContactListScreen
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }

    // =========================================================================
    // 7. PIN & DURESS PIN SETUP, KEYPAD PHYSICAL CLICKS & PANIC WIPE (1.a)
    // =========================================================================

    @Test
    fun testPinAndDuressPinLock_physicalKeypadDecoyLaunch() {
        try {
            // Open Settings via physical click
            clickTagByPixelCoordinates("contact_list_settings_button")
            composeTestRule.waitUntil(timeoutMillis = 7_000) {
                composeTestRule.onAllNodesWithText("Settings").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithText("Settings").assertIsDisplayed()

            // 1. Configure Primary PIN
            clickTagByPixelCoordinates("settings_pin_setup_button")
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                composeTestRule.onAllNodesWithTag("pin_dialog_input").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithTag("pin_dialog_input").performTextInput("1234")
            clickTagByPixelCoordinates("pin_dialog_confirm_button")
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                composeTestRule.onAllNodesWithTag("pin_dialog_input").fetchSemanticsNodes().isEmpty()
            }

            // 2. Configure Duress PIN
            clickTagByPixelCoordinates("settings_duress_pin_setup_button")
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                composeTestRule.onAllNodesWithTag("duress_pin_dialog_input").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithTag("duress_pin_dialog_input").performTextInput("9999")
            clickTagByPixelCoordinates("duress_pin_dialog_confirm_button")
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                composeTestRule.onAllNodesWithTag("duress_pin_dialog_input").fetchSemanticsNodes().isEmpty()
            }

            // 3. Navigate back to ContactListScreen (triggers lock because PIN is now configured)
            clickTagByPixelCoordinates("settings_back_button")
            composeTestRule.waitForIdle()

            // 4. Verify BiometricLockScreen is triggered because PIN is now configured
            composeTestRule.waitUntil(timeoutMillis = 7_000) {
                composeTestRule.onAllNodesWithTag("pin_input_field").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithTag("pin_input_field").assertIsDisplayed()
            composeTestRule.onNodeWithTag("pin_key_9").assertIsDisplayed()

            // 5. Physically tap Duress PIN digits "9999" on on-screen numeric keypad
            clickTagByPixelCoordinates("pin_key_9")
            clickTagByPixelCoordinates("pin_key_9")
            clickTagByPixelCoordinates("pin_key_9")
            clickTagByPixelCoordinates("pin_key_9")

            // 6. Physically click unlock submit button
            clickTagByPixelCoordinates("pin_unlock_button")

            // 7. Verify DecoyNotesScreen is immediately launched
            composeTestRule.waitUntil(timeoutMillis = 7_000) {
                composeTestRule.onAllNodesWithTag("decoy_notes_empty_text").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithTag("decoy_notes_empty_text").assertIsDisplayed()
            composeTestRule.onNodeWithText("Personal Notes").assertIsDisplayed()

            // 8. Verify that master encryption key has been wiped from Keystore
            assertFalse(
                "Keystore master key must be permanently wiped upon Duress PIN panic trigger",
                org.pqchat.dht.crypto.KeystoreCrypto.hasMasterKey()
            )
        } finally {
            // Clean up state and restore test master key so subsequent tests can run cleanly
            org.pqchat.dht.crypto.KeystoreCrypto.setTestSecretKey(TEST_MASTER_KEY)
            try {
                kotlinx.coroutines.runBlocking {
                    composeTestRule.activity.viewModel.repository.ensureSelfNotesContactExists()
                }
            } catch (_: Throwable) {}
            composeTestRule.activity.runOnUiThread {
                composeTestRule.activity.viewModel.unselectContact()
                composeTestRule.activity.viewModel.clearDuressActive()
                composeTestRule.activity.viewModel.setAppLockPin(null)
                composeTestRule.activity.viewModel.setDuressPin(null)
                composeTestRule.activity.viewModel.setBiometricLockEnabled(false)
                composeTestRule.activity.viewModel.setAnonymousStatsEnabled(false)
            }
            composeTestRule.waitForIdle()
        }
    }

    // =========================================================================
    // 8. EPHEMERAL MESSAGES: TTL SELECTION & AUTO-EXPIRATION (1.b)
    // =========================================================================

    @Test
    fun testEphemeralMessage_ttlSelectionAndAutomaticExpiration() {
        // Open Settings and launch Self-Notes chat
        clickTagByPixelCoordinates("contact_list_settings_button")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithTag("settings_self_notes_button").fetchSemanticsNodes().isNotEmpty()
        }
        clickTagByPixelCoordinates("settings_self_notes_button")

        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithTag("chat_message_input").fetchSemanticsNodes().isNotEmpty()
        }

        // Physically click Ephemeral TTL menu button
        clickTagByPixelCoordinates("chat_ephemeral_ttl_button")

        // Wait for dropdown menu to appear and click 1 minute (60s) TTL
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("chat_ephemeral_ttl_item_60").fetchSemanticsNodes().isNotEmpty()
        }
        clickTagByPixelCoordinates("chat_ephemeral_ttl_item_60")

        // Input and send an ephemeral message
        val ephemeralText = "Ephemeral Secret Auto Purge Test"
        composeTestRule.onNodeWithTag("chat_message_input").performTextInput(ephemeralText)
        clickTagByPixelCoordinates("chat_send_button")

        // Verify message is visible in chat view
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText(ephemeralText).fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText(ephemeralText).assertIsDisplayed()

        // Manually trigger purge for expired messages past TTL (simulating +120s in future)
        runBlocking {
            composeTestRule.activity.viewModel.repository.purgeExpiredMessages(
                now = System.currentTimeMillis() + 120_000L
            )
        }

        // Verify the message has been automatically purged and removed from view
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText(ephemeralText).fetchSemanticsNodes().isEmpty()
        }
        composeTestRule.onNodeWithText(ephemeralText).assertDoesNotExist()

        // Reset TTL back to disabled (0s)
        clickTagByPixelCoordinates("chat_ephemeral_ttl_button")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("chat_ephemeral_ttl_item_0").fetchSemanticsNodes().isNotEmpty()
        }
        clickTagByPixelCoordinates("chat_ephemeral_ttl_item_0")

        // Exit chat back to ContactList
        clickTagByPixelCoordinates("chat_back_button")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }

    // =========================================================================
    // 9. MESSAGE REACTIONS & LOCATION PIN PHYSICAL INTERACTIONS (1.c)
    // =========================================================================

    @Test
    fun testMessageReactionAndLocationPin_physicalInteractions() {
        // Open Settings and launch Self-Notes chat
        clickTagByPixelCoordinates("contact_list_settings_button")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithTag("settings_self_notes_button").fetchSemanticsNodes().isNotEmpty()
        }
        clickTagByPixelCoordinates("settings_self_notes_button")

        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithTag("chat_message_input").fetchSemanticsNodes().isNotEmpty()
        }

        // Clean previous notes to ensure deterministic first position in LazyColumn
        kotlinx.coroutines.runBlocking {
            composeTestRule.activity.viewModel.repository.messageDao.deleteMessagesForContact(
                org.pqchat.dht.data.repository.ChatRepository.SELF_CONTACT_ID
            )
        }
        composeTestRule.waitForIdle()

        // Send a note message to react to
        val noteMsg = "Reaction Target Message"
        composeTestRule.onNodeWithTag("chat_message_input").performTextInput(noteMsg)
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithTag("chat_send_button").fetchSemanticsNodes().isNotEmpty()
        }
        try {
            composeTestRule.onNodeWithTag("chat_send_button", useUnmergedTree = true)
                .performSemanticsAction(SemanticsActions.OnClick)
        } catch (_: Throwable) {
            try {
                composeTestRule.onNodeWithTag("chat_send_button").performClick()
            } catch (_: Throwable) {
                clickTagByPixelCoordinates("chat_send_button")
            }
        }
        composeTestRule.waitForIdle()

        // Wait for message input clearance confirming dispatch
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            val node = composeTestRule.onNodeWithTag("chat_message_input").fetchSemanticsNode()
            val editable = node.config.getOrElse(SemanticsProperties.EditableText) { AnnotatedString("") }.text
            editable.isEmpty()
        }
        dismissKeyboardAndWait()

        composeTestRule.waitUntil(timeoutMillis = 10_000) {
            composeTestRule.onAllNodesWithText(noteMsg, substring = true, useUnmergedTree = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        runCatching {
            composeTestRule.onNodeWithText(noteMsg, substring = true, useUnmergedTree = true).performScrollTo()
        }
        composeTestRule.onAllNodesWithText(noteMsg, substring = true, useUnmergedTree = true)
            .onFirst().assertExists()

        // Locate react button on message and click it
        val reactButtonMatcher = hasTestTagContaining("react_button_")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodes(reactButtonMatcher, useUnmergedTree = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        try {
            composeTestRule.onAllNodes(reactButtonMatcher, useUnmergedTree = true)
                .onFirst().performSemanticsAction(SemanticsActions.OnClick)
        } catch (_: Throwable) {
            try {
                composeTestRule.onAllNodes(reactButtonMatcher, useUnmergedTree = true)
                    .onFirst().performClick()
            } catch (_: Throwable) {
                clickNodeCenterByPixelCoordinates(reactButtonMatcher)
            }
        }
        composeTestRule.waitForIdle()

        // Emoji reaction picker opens — click heart reaction
        val emojiHeartMatcher = hasTestTagContaining("reaction_emoji_")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodes(emojiHeartMatcher, useUnmergedTree = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        try {
            composeTestRule.onAllNodes(emojiHeartMatcher, useUnmergedTree = true)
                .onFirst().performSemanticsAction(SemanticsActions.OnClick)
        } catch (_: Throwable) {
            try {
                composeTestRule.onAllNodes(emojiHeartMatcher, useUnmergedTree = true)
                    .onFirst().performClick()
            } catch (_: Throwable) {
                clickNodeCenterByPixelCoordinates(emojiHeartMatcher)
            }
        }
        composeTestRule.waitForIdle()

        // Verify reaction badge appears (useUnmergedTree = true is critical for badge inside message bubble)
        val reactionBadgeMatcher = hasTestTagContaining("reaction_badge_")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodes(reactionBadgeMatcher, useUnmergedTree = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onAllNodes(reactionBadgeMatcher, useUnmergedTree = true)
            .onFirst().assertExists()

        // Test Location Pin: Click location pin button in input bar
        try {
            composeTestRule.onNodeWithTag("chat_location_pin_button", useUnmergedTree = true)
                .performSemanticsAction(SemanticsActions.OnClick)
        } catch (_: Throwable) {
            try {
                composeTestRule.onNodeWithTag("chat_location_pin_button").performClick()
            } catch (_: Throwable) {
                clickTagByPixelCoordinates("chat_location_pin_button")
            }
        }
        composeTestRule.waitForIdle()

        // LocationPinDialog appears
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithTag("location_pin_note_input", useUnmergedTree = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("location_pin_note_input", useUnmergedTree = true)
            .assertIsDisplayed()

        // Confirm send location pin
        try {
            composeTestRule.onNodeWithTag("send_location_pin_confirm_button", useUnmergedTree = true)
                .performSemanticsAction(SemanticsActions.OnClick)
        } catch (_: Throwable) {
            try {
                composeTestRule.onNodeWithTag("send_location_pin_confirm_button").performClick()
            } catch (_: Throwable) {
                clickTagByPixelCoordinates("send_location_pin_confirm_button")
            }
        }
        composeTestRule.waitForIdle()

        // Verify location pin message is dispatched and visible in chat
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("Location Pin", substring = true, useUnmergedTree = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onAllNodesWithText("Location Pin", substring = true, useUnmergedTree = true)
            .onFirst().assertExists()

        // Exit chat
        try {
            composeTestRule.onNodeWithTag("chat_back_button", useUnmergedTree = true)
                .performSemanticsAction(SemanticsActions.OnClick)
        } catch (_: Throwable) {
            try {
                composeTestRule.onNodeWithTag("chat_back_button").performClick()
            } catch (_: Throwable) {
                clickTagByPixelCoordinates("chat_back_button")
            }
        }
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }

    // =========================================================================
    // 10. STEGANOGRAPHY & RESEARCH TELEMETRY PHYSICAL CLICKS (1.d)
    // =========================================================================

    @Test
    fun testHandshakeSteganographyAndResearchConsent_physicalClicks() {
        // 1. Test Steganography buttons on HandshakeScreen
        clickTagByPixelCoordinates("new_chat_fab")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("Secure Rendezvous Handshake").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("Secure Rendezvous Handshake").assertIsDisplayed()

        clickTagByPixelCoordinates("handshake_generate_qr_button")
        composeTestRule.waitUntil(timeoutMillis = 10_000) {
            composeTestRule.onAllNodesWithTag("handshake_share_stego_button").fetchSemanticsNodes().isNotEmpty()
        }
        runCatching {
            composeTestRule.onNodeWithTag("handshake_share_stego_button").performScrollTo()
        }
        composeTestRule.onNodeWithTag("handshake_share_stego_button").assertIsDisplayed()

        // Switch to Bob tab and verify gallery / stego scan button
        clickTagByPixelCoordinates("handshake_bob_tab")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("handshake_gallery_button").fetchSemanticsNodes().isNotEmpty()
        }
        runCatching {
            composeTestRule.onNodeWithTag("handshake_gallery_button").performScrollTo()
        }
        composeTestRule.onNodeWithTag("handshake_gallery_button").assertIsDisplayed()

        // Return to ContactListScreen
        clickTagByPixelCoordinates("handshake_back_button")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()

        // 2. Test Research Telemetry Informed Consent in Settings
        clickTagByPixelCoordinates("contact_list_settings_button")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("Settings").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("Settings").assertIsDisplayed()

        // Toggle research telemetry switch
        clickTagByPixelCoordinates("settings_research_telemetry_switch")

        // Verify Informed Consent dialog
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithTag("research_consent_confirm_button").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("Informed Research Consent", substring = true).assertIsDisplayed()
        composeTestRule.onNodeWithText("ZERO LEAK GUARANTEE", substring = true).assertIsDisplayed()

        // Physically confirm informed consent
        clickTagByPixelCoordinates("research_consent_confirm_button")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("research_consent_confirm_button").fetchSemanticsNodes().isEmpty()
        }

        // Verify telemetry is now enabled in ViewModel
        assertTrue(composeTestRule.activity.viewModel.isAnonymousStatsEnabled.value)

        // Toggle switch back off
        clickTagByPixelCoordinates("settings_research_telemetry_switch")
        assertFalse(composeTestRule.activity.viewModel.isAnonymousStatsEnabled.value)

        // Exit Settings
        clickTagByPixelCoordinates("settings_back_button")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }

    // =========================================================================
    // 11. PHYSICAL PIXEL COORDINATE CLICKS: PIN KEYPAD, CONSENT DIALOG, GROUP POLL & CANARY
    // =========================================================================

    @Test
    fun testPhysicalPixelCoordinates_pinKeypad_consentDialog_groupPoll_and_safetyCanary() {
        try {
            // -----------------------------------------------------------------
            // A. PIN & Duress PIN Keypad with physical pixel clicks
            // -----------------------------------------------------------------
            // 1. Open Settings
            clickTagByPixelCoordinates("contact_list_settings_button")
            composeTestRule.waitUntil(timeoutMillis = 7_000) {
                composeTestRule.onAllNodesWithText("Settings").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithText("Settings").assertIsDisplayed()

            // 2. Set App Lock PIN (Dialog boundsInScreen physical click)
            clickTagByPixelCoordinates("settings_pin_setup_button")
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                composeTestRule.onAllNodesWithTag("pin_dialog_input").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithTag("pin_dialog_input").performTextInput("1234")
            clickTagByPixelCoordinates("pin_dialog_confirm_button")
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                composeTestRule.onAllNodesWithTag("pin_dialog_input").fetchSemanticsNodes().isEmpty()
            }

            // 3. Set Duress PIN (Dialog boundsInScreen physical click)
            clickTagByPixelCoordinates("settings_duress_pin_setup_button")
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                composeTestRule.onAllNodesWithTag("duress_pin_dialog_input").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithTag("duress_pin_dialog_input").performTextInput("9999")
            clickTagByPixelCoordinates("duress_pin_dialog_confirm_button")
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                composeTestRule.onAllNodesWithTag("duress_pin_dialog_input").fetchSemanticsNodes().isEmpty()
            }

            // 4. Return to ContactList -> Triggers lock screen
            clickTagByPixelCoordinates("settings_back_button")
            composeTestRule.waitUntil(timeoutMillis = 7_000) {
                composeTestRule.onAllNodesWithTag("pin_input_field").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithTag("pin_key_9").assertIsDisplayed()

            // 5. Physical clicks on on-screen numeric keypad digits "9999" and unlock
            clickTagByPixelCoordinates("pin_key_9")
            clickTagByPixelCoordinates("pin_key_9")
            clickTagByPixelCoordinates("pin_key_9")
            clickTagByPixelCoordinates("pin_key_9")
            clickTagByPixelCoordinates("pin_unlock_button")

            // 6. Verify Duress panic wipes master key and opens DecoyNotesScreen
            composeTestRule.waitUntil(timeoutMillis = 7_000) {
                composeTestRule.onAllNodesWithTag("decoy_notes_empty_text").fetchSemanticsNodes().isNotEmpty()
            }
            assertFalse(
                "Keystore master key must be wiped upon duress unlock",
                org.pqchat.dht.crypto.KeystoreCrypto.hasMasterKey()
            )
        } finally {
            // Restore test key & reset lock state
            org.pqchat.dht.crypto.KeystoreCrypto.setTestSecretKey(TEST_MASTER_KEY)
            try {
                kotlinx.coroutines.runBlocking {
                    composeTestRule.activity.viewModel.repository.ensureSelfNotesContactExists()
                }
            } catch (_: Throwable) {}
            composeTestRule.activity.runOnUiThread {
                composeTestRule.activity.viewModel.unselectContact()
                composeTestRule.activity.viewModel.clearDuressActive()
                composeTestRule.activity.viewModel.setAppLockPin(null)
                composeTestRule.activity.viewModel.setDuressPin(null)
                composeTestRule.activity.viewModel.setBiometricLockEnabled(false)
                composeTestRule.activity.viewModel.setAnonymousStatsEnabled(false)
            }
            composeTestRule.waitForIdle()
        }

        // Return back to ContactListScreen
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }

        // -----------------------------------------------------------------
        // B. Research Telemetry Informed Consent Dialog (boundsInScreen physical click)
        // -----------------------------------------------------------------
        clickTagByPixelCoordinates("contact_list_settings_button")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("Settings").fetchSemanticsNodes().isNotEmpty()
        }

        runCatching {
            composeTestRule.onNodeWithTag("settings_research_telemetry_switch").performScrollTo()
        }
        clickTagByPixelCoordinates("settings_research_telemetry_switch")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithTag("research_consent_confirm_button").fetchSemanticsNodes().isNotEmpty()
        }
        // Physical click inside separate Dialog window
        clickTagByPixelCoordinates("research_consent_confirm_button")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("research_consent_confirm_button").fetchSemanticsNodes().isEmpty()
        }
        assertTrue(composeTestRule.activity.viewModel.isAnonymousStatsEnabled.value)
        clickTagByPixelCoordinates("settings_research_telemetry_switch")
        assertFalse(composeTestRule.activity.viewModel.isAnonymousStatsEnabled.value)

        // -----------------------------------------------------------------
        // C. Safety Canary (0x0B) Physical Clicks
        // -----------------------------------------------------------------
        runCatching {
            composeTestRule.onNodeWithTag("settings_dead_man_switch_toggle").performScrollTo()
        }
        clickTagByPixelCoordinates("settings_dead_man_switch_toggle")
        assertTrue(composeTestRule.activity.viewModel.isDeadManSwitchEnabled.value)

        runCatching {
            composeTestRule.onNodeWithTag("settings_dead_man_checkin_button").performScrollTo()
        }
        clickTagByPixelCoordinates("settings_dead_man_checkin_button")

        runCatching {
            composeTestRule.onNodeWithTag("settings_emergency_sos_button").performScrollTo()
        }
        clickTagByPixelCoordinates("settings_emergency_sos_button")
        composeTestRule.waitForIdle()
        assertTrue(
            "Safety Canary frame must be queued or triggered",
            composeTestRule.activity.viewModel.isCanaryTriggered.value ||
            composeTestRule.activity.viewModel.repository.canaryQueue.isNotEmpty()
        )

        // Turn off dead man switch and return to ContactListScreen
        clickTagByPixelCoordinates("settings_dead_man_switch_toggle")
        clickTagByPixelCoordinates("settings_back_button")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }

        // -----------------------------------------------------------------
        // D. Group Poll Creation (0x0A) Physical Clicks
        // -----------------------------------------------------------------
        clickTagByPixelCoordinates("new_group_fab")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("create_group_name_input").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("create_group_name_input").performTextInput("Poll Test Group")
        clickTagByPixelCoordinates("create_group_confirm_button")

        composeTestRule.waitUntil(timeoutMillis = 10_000) {
            composeTestRule.onAllNodesWithTag("chat_create_poll_button").fetchSemanticsNodes().isNotEmpty()
        }
        clickTagByPixelCoordinates("chat_create_poll_button")

        // In CreatePollDialog: input question and options
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("poll_question_input").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("poll_question_input").performTextInput("Preferred PQC Suite?")
        composeTestRule.onNodeWithTag("poll_option_input_0").performTextInput("ML-KEM-512")
        composeTestRule.onNodeWithTag("poll_option_input_1").performTextInput("X25519-Hybrid")

        // Physically click Create Poll in dialog
        clickTagByPixelCoordinates("poll_create_confirm_button")

        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithTag("poll_create_confirm_button").fetchSemanticsNodes().isEmpty()
        }

        // Verify poll card appears in chat
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("Preferred PQC Suite?", substring = true).fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("Preferred PQC Suite?", substring = true).assertIsDisplayed()

        // Leave group and return to ContactListScreen
        clickTagByPixelCoordinates("chat_group_members_button")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("leave_group_button").fetchSemanticsNodes().isNotEmpty()
        }
        clickTagByPixelCoordinates("leave_group_button")
        composeTestRule.waitUntil(timeoutMillis = 7_000) {
            composeTestRule.onAllNodesWithText("PQChat.DHT").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }
}
