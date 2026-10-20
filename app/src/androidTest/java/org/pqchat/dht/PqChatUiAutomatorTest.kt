package org.pqchat.dht

import android.os.Build
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import androidx.test.uiautomator.UiDevice
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
 * Combines [ComposeContentTestRule] and [UiDevice] (UiAutomator) to perform:
 * - Physical coordinate-based pixel clicks calculated dynamically from component window bounds:
 *   [UiDevice.click(x, y)]
 * - Raw screen coordinate interactions
 * - Text input and keyboard interactions
 * - Tab switching (Alice Display QR vs Bob Scan & Join)
 * - Settings changes (Theme modes, self notes)
 * - Navigation and verification across all 5 primary application screens:
 *   1. ContactListScreen
 *   2. HandshakeScreen (Alice & Bob flows)
 *   3. SettingsScreen
 *   4. DiagnosticsScreen
 *   5. ChatScreen & GroupChat flow
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
     * Helper to perform a physical screen tap at the center of the given Compose node,
     * dynamically calculated from the node's bounds in window coordinates.
     */
    private fun clickNodeCenterByPixelCoordinates(matcher: SemanticsMatcher): Rect {
        composeTestRule.waitForIdle()
        val semanticsNode = composeTestRule.onNode(matcher).fetchSemanticsNode()
        val bounds = semanticsNode.boundsInWindow
        val centerX = (bounds.left + bounds.width / 2f).toInt()
        val centerY = (bounds.top + bounds.height / 2f).toInt()
        val clicked = uiDevice.click(centerX, centerY)
        assertTrue("UiDevice click failed at ($centerX, $centerY)", clicked)
        composeTestRule.waitForIdle()
        return bounds
    }

    private fun clickTagByPixelCoordinates(testTag: String): Rect {
        return clickNodeCenterByPixelCoordinates(hasTestTag(testTag))
    }

    private fun clickRawScreenCoordinates(x: Int, y: Int) {
        composeTestRule.waitForIdle()
        uiDevice.click(x, y)
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
        composeTestRule.onNodeWithTag("handshake_manual_payload_input").assertIsDisplayed()

        // Input an invalid short Base64 string to verify validation badge
        composeTestRule.onNodeWithTag("handshake_manual_payload_input")
            .performTextInput("SGVsbG8=") // "Hello" in base64 (5 bytes != 864 bytes)

        composeTestRule.onNodeWithText("Invalid QR code payload format").assertIsDisplayed()
        composeTestRule.onNodeWithTag("handshake_encapsulate_button").assertIsNotEnabled()

        // Now input a dummy valid-length payload (864 bytes in Base64 = 1152 chars)
        val dummy864Bytes = ByteArray(864) { 0x42.toByte() }
        val dummyBase64 = java.util.Base64.getEncoder().encodeToString(dummy864Bytes)

        composeTestRule.onNodeWithTag("handshake_manual_payload_input")
            .performTextClearance()
        composeTestRule.onNodeWithTag("handshake_manual_payload_input")
            .performTextInput(dummyBase64)

        // Verify validation succeeds
        composeTestRule.onNodeWithText("Valid Hybrid Handshake Key (864 bytes verified)").assertIsDisplayed()
        composeTestRule.onNodeWithTag("handshake_encapsulate_button").assertIsEnabled()

        // Click back button to exit
        clickTagByPixelCoordinates("handshake_back_button")
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

        // Verify chat screen for Self-Notes opens
        composeTestRule.onNodeWithTag("chat_message_input").assertIsDisplayed()
        composeTestRule.onNodeWithTag("chat_send_button").assertIsDisplayed()

        // Send a test note in Self Notes chat
        composeTestRule.onNodeWithTag("chat_message_input")
            .performTextInput("Test Self Note from Automated UI")
        clickTagByPixelCoordinates("chat_send_button")

        // Verify text input was cleared
        composeTestRule.onNodeWithTag("chat_message_input").assertTextEquals("")

        // Return from chat back to contact list
        clickTagByPixelCoordinates("chat_back_button")
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

        // Verify we navigated to ChatScreen for the newly created group
        composeTestRule.onNodeWithText("Automated E2E Test Group").assertIsDisplayed()
        composeTestRule.onNodeWithTag("chat_message_input").assertIsDisplayed()
        composeTestRule.onNodeWithTag("chat_send_button").assertIsDisplayed()

        // Send a group message
        composeTestRule.onNodeWithTag("chat_message_input")
            .performTextInput("Hello Post-Quantum Group!")
        clickTagByPixelCoordinates("chat_send_button")

        // Verify group members button exists and physically click it
        clickTagByPixelCoordinates("chat_group_members_button")

        // Verify group members dialog
        composeTestRule.onNodeWithTag("leave_group_button").assertIsDisplayed()

        // Physically click 'Opuść grupę' (leave group)
        clickTagByPixelCoordinates("leave_group_button")

        // Verify returned back to ContactListScreen
        composeTestRule.onNodeWithText("PQChat.DHT").assertIsDisplayed()
    }
}
