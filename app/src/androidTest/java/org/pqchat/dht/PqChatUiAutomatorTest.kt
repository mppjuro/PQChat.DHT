package org.pqchat.dht

import android.os.Build
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.text.AnnotatedString
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import androidx.test.uiautomator.UiDevice
import kotlinx.coroutines.runBlocking
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
 * All interactions strictly and exclusively use physical pixel coordinates via [UiDevice.click(x, y)]
 * dynamically calculated from the Compose semantics tree window bounds.
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
        composeTestRule.waitForIdle()
    }

    /**
     * Helper to safely dismiss the soft keyboard and allow dialog/view animations to settle.
     */
    private fun dismissKeyboardAndWait() {
        try {
            androidx.test.espresso.Espresso.closeSoftKeyboard()
        } catch (_: Throwable) {}
        uiDevice.waitForIdle()
        Thread.sleep(150)
        composeTestRule.waitForIdle()
    }

    /**
     * Performs an authentic physical screen tap at the exact center of the given Compose node,
     * dynamically calculated from the node's bounds in window coordinates.
     * ZERO fallback to performClick() — physical clicks only.
     */
    private fun clickNodeCenterByPixelCoordinates(matcher: SemanticsMatcher): Rect {
        dismissKeyboardAndWait()
        val nodeInteraction = composeTestRule.onNode(matcher, useUnmergedTree = true)
        try {
            nodeInteraction.performScrollTo()
            dismissKeyboardAndWait()
        } catch (_: Throwable) {
            // Node is not in a scrollable container (e.g. TopAppBar, FAB, Dialog)
        }
        val semanticsNode = nodeInteraction.fetchSemanticsNode()
        val bounds = semanticsNode.boundsInWindow
        val centerX = (bounds.left + bounds.width / 2f).toInt()
        val centerY = (bounds.top + bounds.height / 2f).toInt()
        val clampedX = centerX.coerceIn(0, uiDevice.displayWidth - 1)
        val clampedY = centerY.coerceIn(0, uiDevice.displayHeight - 1)

        val clicked = uiDevice.click(clampedX, clampedY)
        assertTrue("UiDevice physical pixel click failed at ($clampedX, $clampedY) for bounds $bounds", clicked)
        uiDevice.waitForIdle()
        composeTestRule.waitForIdle()
        return bounds
    }

    /**
     * Performs a physical screen tap on the node identified by [testTag].
     */
    private fun clickTagByPixelCoordinates(testTag: String): Rect {
        return clickNodeCenterByPixelCoordinates(hasTestTag(testTag))
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

        // Raw coordinate click on screen padding area (safe no-op click)
        val displayWidth = uiDevice.displayWidth
        val displayHeight = uiDevice.displayHeight
        clickRawScreenCoordinates(displayWidth / 2, displayHeight / 2)
    }

    // =========================================================================
    // 2. HANDSHAKE SCREEN: ALICE FLOW & PHYSICAL CLICKS
    // =========================================================================

    @Test
    fun testHandshakeScreen_aliceFlow_generatesQrAndInteractsPhysically() {
        // Physical click to open New Chat (Alice) Handshake
        clickTagByPixelCoordinates("new_chat_fab")

        // Verify HandshakeScreen header
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

        // Verify QR card appears
        composeTestRule.onNodeWithTag("handshake_qr_code_card").assertIsDisplayed()

        // Verify rendezvous text
        composeTestRule.onNodeWithText("Rendezvous Target_0 (SHA-1):").assertIsDisplayed()

        // Physically click 'Nowy kod QR' button to regenerate
        clickTagByPixelCoordinates("handshake_new_qr_button")
        composeTestRule.onNodeWithTag("handshake_qr_code_card").assertIsDisplayed()

        // Physically click back button to return to ContactListScreen
        clickTagByPixelCoordinates("handshake_back_button")
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

        // Now input a dummy valid-length payload (864 bytes in Base64 = 1152 chars)
        val dummy864Bytes = ByteArray(864) { 0x42.toByte() }
        val dummyBase64 = java.util.Base64.getEncoder().encodeToString(dummy864Bytes)

        composeTestRule.onNodeWithTag("handshake_manual_payload_input")
            .performScrollTo()
            .performTextClearance()
        composeTestRule.onNodeWithTag("handshake_manual_payload_input")
            .performTextInput(dummyBase64)

        // Verify validation succeeds
        composeTestRule.onNodeWithText("Valid Hybrid Handshake Key (864 bytes verified)")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule.onNodeWithTag("handshake_encapsulate_button")
            .performScrollTo()
            .assertIsEnabled()

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
        composeTestRule.onNodeWithText("Ustawienia").assertIsDisplayed()

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
        composeTestRule.onNodeWithTag("chat_send_button").assertIsDisplayed()

        // Send a test note in Self Notes chat
        composeTestRule.onNodeWithTag("chat_message_input")
            .performTextInput("Test Self Note from Automated UI")
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
        composeTestRule.onNodeWithText("Nowy czat grupowy").assertIsDisplayed()
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
        composeTestRule.onNodeWithTag("chat_send_button").assertIsDisplayed()

        // Send a group message
        composeTestRule.onNodeWithTag("chat_message_input")
            .performTextInput("Hello Post-Quantum Group!")
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
            composeTestRule.onNodeWithText("Ustawienia").assertIsDisplayed()

            // 1. Configure Primary PIN
            clickTagByPixelCoordinates("settings_pin_setup_button")
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                composeTestRule.onAllNodesWithTag("pin_dialog_input").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithTag("pin_dialog_input").performTextInput("1234")
            clickTagByPixelCoordinates("pin_dialog_confirm_button")

            // 2. Configure Duress PIN
            clickTagByPixelCoordinates("settings_duress_pin_setup_button")
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
                composeTestRule.onAllNodesWithTag("duress_pin_dialog_input").fetchSemanticsNodes().isNotEmpty()
            }
            composeTestRule.onNodeWithTag("duress_pin_dialog_input").performTextInput("9999")
            clickTagByPixelCoordinates("duress_pin_dialog_confirm_button")

            // 3. Navigate back to ContactListScreen
            clickTagByPixelCoordinates("settings_back_button")
            composeTestRule.waitForIdle()

            // 4. Verify BiometricLockScreen is triggered because PIN is now configured
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
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
            composeTestRule.waitUntil(timeoutMillis = 5_000) {
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
            // Clean up state so subsequent tests can run cleanly
            composeTestRule.activity.runOnUiThread {
                composeTestRule.activity.viewModel.clearDuressActive()
                composeTestRule.activity.viewModel.setAppLockPin(null)
                composeTestRule.activity.viewModel.setDuressPin(null)
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
        clickTagByPixelCoordinates("settings_self_notes_button")

        composeTestRule.waitUntil(timeoutMillis = 5_000) {
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
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
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
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
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
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
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
        clickTagByPixelCoordinates("settings_self_notes_button")

        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("chat_message_input").fetchSemanticsNodes().isNotEmpty()
        }

        // Send a note message to react to
        val noteMsg = "Reaction Target Message"
        composeTestRule.onNodeWithTag("chat_message_input").performTextInput(noteMsg)
        clickTagByPixelCoordinates("chat_send_button")

        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithText(noteMsg).fetchSemanticsNodes().isNotEmpty()
        }

        // Locate react button on message and physically click it
        val reactButtonMatcher = hasTestTagContaining("react_button_")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodes(reactButtonMatcher).fetchSemanticsNodes().isNotEmpty()
        }
        clickNodeCenterByPixelCoordinates(reactButtonMatcher)

        // Emoji reaction picker opens — physically click heart reaction
        val emojiHeartMatcher = hasTestTagContaining("reaction_emoji_")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodes(emojiHeartMatcher).fetchSemanticsNodes().isNotEmpty()
        }
        clickNodeCenterByPixelCoordinates(emojiHeartMatcher)

        // Verify reaction badge appears
        val reactionBadgeMatcher = hasTestTagContaining("reaction_badge_")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodes(reactionBadgeMatcher).fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onAllNodes(reactionBadgeMatcher).onFirst().assertIsDisplayed()

        // Test Location Pin: Physically click location pin button in input bar
        clickTagByPixelCoordinates("chat_location_pin_button")

        // LocationPinDialog appears
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("location_pin_note_input").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("location_pin_note_input").assertIsDisplayed()

        // Physically confirm send location pin
        clickTagByPixelCoordinates("send_location_pin_confirm_button")

        // Verify location pin message is dispatched and visible in chat
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithText("Pinezka lokalizacji", substring = true).fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onAllNodesWithText("Pinezka lokalizacji", substring = true).onFirst().assertIsDisplayed()

        // Exit chat
        clickTagByPixelCoordinates("chat_back_button")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
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
        composeTestRule.onNodeWithText("Secure Rendezvous Handshake").assertIsDisplayed()

        clickTagByPixelCoordinates("handshake_generate_qr_button")
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("handshake_share_stego_button").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithTag("handshake_share_stego_button").assertIsDisplayed()

        // Switch to Bob tab and verify gallery / stego scan button
        clickTagByPixelCoordinates("handshake_bob_tab")
        composeTestRule.onNodeWithTag("handshake_gallery_button").assertIsDisplayed()

        // Return to ContactListScreen
        clickTagByPixelCoordinates("handshake_back_button")
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()

        // 2. Test Research Telemetry Informed Consent in Settings
        clickTagByPixelCoordinates("contact_list_settings_button")
        composeTestRule.onNodeWithText("Ustawienia").assertIsDisplayed()

        // Toggle research telemetry switch
        clickTagByPixelCoordinates("settings_research_telemetry_switch")

        // Verify Informed Consent dialog
        composeTestRule.waitUntil(timeoutMillis = 5_000) {
            composeTestRule.onAllNodesWithTag("research_consent_confirm_button").fetchSemanticsNodes().isNotEmpty()
        }
        composeTestRule.onNodeWithText("Informed Research Consent", substring = true).assertIsDisplayed()
        composeTestRule.onNodeWithText("GWARANCJA ZEROWEGO WYCIEKU", substring = true).assertIsDisplayed()

        // Physically confirm informed consent
        clickTagByPixelCoordinates("research_consent_confirm_button")

        // Verify telemetry is now enabled in ViewModel
        assertTrue(composeTestRule.activity.viewModel.isAnonymousStatsEnabled.value)

        // Toggle switch back off
        clickTagByPixelCoordinates("settings_research_telemetry_switch")
        assertFalse(composeTestRule.activity.viewModel.isAnonymousStatsEnabled.value)

        // Exit Settings
        clickTagByPixelCoordinates("settings_back_button")
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }
}
