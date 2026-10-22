package org.pqchat.dht.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.pqchat.dht.data.settings.*
import org.pqchat.dht.network.tor.TorState
import org.pqchat.dht.ui.theme.ElectricGreen
import org.pqchat.dht.ui.theme.LocalAppColors
import org.pqchat.dht.ui.theme.NeonCyan
import org.pqchat.dht.ui.util.BatteryOptimizationHelper
import android.content.Intent
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import org.pqchat.dht.ui.viewmodel.ChatViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: ChatViewModel,
    onBack: () -> Unit,
    onOpenSelfNotes: () -> Unit
) {
    val context = LocalContext.current
    val appColors = LocalAppColors.current

    val themeMode by viewModel.themeMode.collectAsState()
    val intervalForeground by viewModel.intervalForegroundChat.collectAsState()
    val intervalAppActive by viewModel.intervalAppActive.collectAsState()
    val intervalBgIdle by viewModel.intervalBackgroundIdle.collectAsState()
    val intervalDoze by viewModel.intervalDozeSleep.collectAsState()
    val intervalRepublishTier1 by viewModel.intervalRepublishTier1.collectAsState()
    val intervalRepublishTier2 by viewModel.intervalRepublishTier2.collectAsState()
    val intervalRepublishTier3 by viewModel.intervalRepublishTier3.collectAsState()
    val republishMaxTtl by viewModel.republishMaxTtl.collectAsState()
    val imageMaxEdge by viewModel.imageMaxEdge.collectAsState()
    val imageColorCount by viewModel.imageColorCount.collectAsState()
    val isCrowdsourcedRepublishEnabled by viewModel.isCrowdsourcedRepublishEnabled.collectAsState()
    val isTorEnabled by viewModel.isTorEnabled.collectAsState()
    val isBiometricLockEnabled by viewModel.isBiometricLockEnabled.collectAsState()
    val isAppLockPinSet by viewModel.isAppLockPinSet.collectAsState()
    val isDuressPinSet by viewModel.isDuressPinSet.collectAsState()

    var showPinDialog by remember { mutableStateOf(false) }
    var showDuressPinDialog by remember { mutableStateOf(false) }
    var pinDialogInput by remember { mutableStateOf("") }
    var duressPinDialogInput by remember { mutableStateOf("") }
    var showResearchConsentDialog by remember { mutableStateOf(false) }

    val isStrictPoissonShapingEnabled by viewModel.isStrictPoissonShapingEnabled.collectAsState()
    val torState by viewModel.torState.collectAsState()

    val isAnonymousStatsEnabled by viewModel.isAnonymousStatsEnabled.collectAsState()
    val statsProbeIntervalMs by viewModel.statsProbeIntervalMs.collectAsState()
    val researchEventsCount by viewModel.researchEventsCount.collectAsState()
    val researchFirstSendCount by viewModel.researchFirstSendCount.collectAsState()
    val researchOwnRepublishCount by viewModel.researchOwnRepublishCount.collectAsState()
    val researchCrowdRepublishCount by viewModel.researchCrowdRepublishCount.collectAsState()
    val researchPacketsReceivedCount by viewModel.researchPacketsReceivedCount.collectAsState()
    val researchTtlSamplesCount by viewModel.researchTtlSamplesCount.collectAsState()
    val researchSyncStatus by viewModel.researchSyncStatus.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                        modifier = Modifier.testTag("settings_back_button")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = appColors.textPrimary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = appColors.surface,
                    titleContentColor = appColors.textPrimary
                )
            )
        },
        containerColor = appColors.background
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            // ==================== SECTION 1: THEME ====================
            SettingsSectionHeader(
                title = "Appearance & App Theme",
                icon = Icons.Default.Palette
            )

            Surface(
                color = appColors.surface,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, appColors.border, RoundedCornerShape(16.dp))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Theme Selection",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "By default, the app automatically matches your phone system theme.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 12.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ThemeOptionCard(
                            label = "System",
                            subtitle = "Default",
                            icon = Icons.Default.BrightnessAuto,
                            isSelected = themeMode == ThemeMode.SYSTEM,
                            onClick = { viewModel.setThemeMode(ThemeMode.SYSTEM) },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("theme_system_card")
                        )

                        ThemeOptionCard(
                            label = "Dark",
                            subtitle = "Dark Mode",
                            icon = Icons.Default.DarkMode,
                            isSelected = themeMode == ThemeMode.DARK,
                            onClick = { viewModel.setThemeMode(ThemeMode.DARK) },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("theme_dark_card")
                        )

                        ThemeOptionCard(
                            label = "Light",
                            subtitle = "Light Mode",
                            icon = Icons.Default.LightMode,
                            isSelected = themeMode == ThemeMode.LIGHT,
                            onClick = { viewModel.setThemeMode(ThemeMode.LIGHT) },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("theme_light_card")
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ==================== SECTION 2: IMAGE COMPRESSION (PNG8) ====================
            SettingsSectionHeader(
                title = "Image Compression (DHT Transfer / PNG8)",
                icon = Icons.Default.Image
            )

            Surface(
                color = appColors.surface,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, appColors.border, RoundedCornerShape(16.dp))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "PNG8 Format with Palette Quantization",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Transferring files over the BitTorrent DHT splits data into 800-byte chunks. PNG8 compression allows sending images in just a few dozen UDP packets.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    // 1. Resolution (longest edge)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                            Text(
                                text = "Resolution (longest edge)",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = appColors.textPrimary
                            )
                            Text(
                                text = "Longer edge of the image is scaled to the selected value",
                                style = MaterialTheme.typography.bodySmall,
                                color = appColors.textSecondary,
                                fontSize = 12.sp
                            )
                        }
                        Surface(
                            color = appColors.primary.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(8.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, appColors.primary.copy(alpha = 0.5f))
                        ) {
                            Text(
                                text = "${imageMaxEdge} px",
                                color = appColors.primary,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // Resolution quick presets
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        listOf(600, 800, 1000, 1200, 1600).forEach { px ->
                            val isSelected = imageMaxEdge == px
                            Surface(
                                color = if (isSelected) appColors.primary.copy(alpha = 0.2f) else appColors.surfaceVariant.copy(alpha = 0.5f),
                                border = androidx.compose.foundation.BorderStroke(
                                    if (isSelected) 1.5.dp else 1.dp,
                                    if (isSelected) appColors.primary else appColors.border
                                ),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .clip(RoundedCornerShape(8.dp))
                                    .clickable { viewModel.setImageMaxEdge(px) }
                            ) {
                                Box(
                                    modifier = Modifier.padding(vertical = 6.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = "${px}p",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                        color = if (isSelected) appColors.primary else appColors.textPrimary
                                    )
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Slider(
                        value = imageMaxEdge.toFloat(),
                        onValueChange = { viewModel.setImageMaxEdge(it.toInt()) },
                        valueRange = 400f..1600f,
                        steps = 11,
                        colors = SliderDefaults.colors(
                            thumbColor = appColors.primary,
                            activeTrackColor = appColors.primary,
                            inactiveTrackColor = appColors.border
                        )
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // 2. Palette Color Count (PNG8)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                            Text(
                                text = "Palette Color Count (PNG8)",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = appColors.textPrimary
                            )
                            Text(
                                text = "Fewer colors = higher compression and faster DHT transfer",
                                style = MaterialTheme.typography.bodySmall,
                                color = appColors.textSecondary,
                                fontSize = 12.sp
                            )
                        }
                        Surface(
                            color = appColors.primary.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(8.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, appColors.primary.copy(alpha = 0.5f))
                        ) {
                            Text(
                                text = "$imageColorCount colors",
                                color = appColors.primary,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // Color palette quick presets
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        listOf(16, 32, 64, 128, 256).forEach { colors ->
                            val isSelected = imageColorCount == colors
                            Surface(
                                color = if (isSelected) appColors.primary.copy(alpha = 0.2f) else appColors.surfaceVariant.copy(alpha = 0.5f),
                                border = androidx.compose.foundation.BorderStroke(
                                    if (isSelected) 1.5.dp else 1.dp,
                                    if (isSelected) appColors.primary else appColors.border
                                ),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .clip(RoundedCornerShape(8.dp))
                                    .clickable { viewModel.setImageColorCount(colors) }
                            ) {
                                Box(
                                    modifier = Modifier.padding(vertical = 6.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = "$colors",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                        color = if (isSelected) appColors.primary else appColors.textPrimary
                                    )
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Slider(
                        value = imageColorCount.toFloat(),
                        onValueChange = { viewModel.setImageColorCount(it.toInt()) },
                        valueRange = 8f..256f,
                        colors = SliderDefaults.colors(
                            thumbColor = appColors.primary,
                            activeTrackColor = appColors.primary,
                            inactiveTrackColor = appColors.border
                        )
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ==================== SECTION 3: DHT INTERVALS ====================
            SettingsSectionHeader(
                title = "DHT Sync Intervals (4 Modes)",
                icon = Icons.Default.Sync
            )

            Surface(
                color = appColors.surface,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, appColors.border, RoundedCornerShape(16.dp))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "BEP 44 Slot Polling Frequency",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Customize message check frequencies in the BitTorrent DHT for each of the 4 application states. Default values are shown in bold.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    // Mode 1: Foreground Active Chat (Default: 10 seconds)
                    IntervalDropdownRow(
                        title = "1. Active Foreground Chat",
                        subtitle = "When chatting in an open conversation",
                        currentMillis = intervalForeground,
                        defaultMillis = DefaultIntervals.FOREGROUND_CHAT,
                        onSelect = { viewModel.setIntervalForegroundChat(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Mode 2: App Active / Other Screen (Default: 1 minute)
                    IntervalDropdownRow(
                        title = "2. App Active (Contact List)",
                        subtitle = "When the app is open, but no chat is selected",
                        currentMillis = intervalAppActive,
                        defaultMillis = DefaultIntervals.APP_ACTIVE,
                        onSelect = { viewModel.setIntervalAppActive(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Mode 3: Background Idle (Default: 5 minutes)
                    IntervalDropdownRow(
                        title = "3. Background Idle (Screen On)",
                        subtitle = "When the app is minimized while screen is active",
                        currentMillis = intervalBgIdle,
                        defaultMillis = DefaultIntervals.BACKGROUND_IDLE,
                        onSelect = { viewModel.setIntervalBackgroundIdle(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Mode 4: Deep Sleep / Doze (Default: 15 minutes)
                    IntervalDropdownRow(
                        title = "4. Deep Sleep / Doze (Screen Off)",
                        subtitle = "Doze battery optimization while phone is locked",
                        currentMillis = intervalDoze,
                        defaultMillis = DefaultIntervals.DOZE_SLEEP,
                        onSelect = { viewModel.setIntervalDozeSleep(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Optional Foreground Service (Continuous Low-Latency Listening)
                    val isFgServiceEnabled by viewModel.isForegroundServiceEnabled.collectAsState()
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Continuous Listening Mode (Foreground Service)",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = "Maintains a persistent foreground service with a low-latency notification (~10s) at the expense of higher battery usage.",
                                style = MaterialTheme.typography.bodySmall,
                                color = appColors.textSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                        Switch(
                            checked = isFgServiceEnabled,
                            onCheckedChange = { viewModel.setForegroundServiceEnabled(it) }
                        )
                    }

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Battery Optimization Whitelist Request
                    val context = LocalContext.current
                    var isBatteryIgnored by remember {
                        mutableStateOf(BatteryOptimizationHelper.isIgnoringBatteryOptimizations(context))
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Battery Optimization Whitelist (Doze)",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = if (isBatteryIgnored) {
                                    "Optimizations disabled — Doze alarms and radio wake up without restrictions."
                                } else {
                                    "Required so Android does not throttle radio wakeups during Doze sleep."
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = if (isBatteryIgnored) appColors.primary else appColors.textSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                        if (!isBatteryIgnored) {
                            Button(
                                onClick = {
                                    BatteryOptimizationHelper.requestIgnoreBatteryOptimizations(context)
                                    isBatteryIgnored = BatteryOptimizationHelper.isIgnoringBatteryOptimizations(context)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = appColors.primary),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                            ) {
                                Text("Disable", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.Black)
                            }
                        } else {
                            Text(
                                text = "Active ✓",
                                style = MaterialTheme.typography.labelMedium,
                                color = appColors.primary,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ==================== SECTION 3: DHT REPUBLISHING & TTL ====================
            SettingsSectionHeader(
                title = "DHT Republishing & TTL (Exponential Backoff)",
                icon = Icons.Default.Autorenew
            )

            Surface(
                color = appColors.surface,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, appColors.border, RoundedCornerShape(16.dp))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "DHT Record Refresh & TTL Limit",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "For unacknowledged messages, the node republishes DHT entries with exponentially increasing delays to conserve battery and radio resources. When TTL is exceeded, the message is marked EXPIRED_OFFLINE and radio wakeups are halted.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    // Tier 1: 0 - 2h (Default: 15 minutes)
                    IntervalDropdownRow(
                        title = "1. First 2 Hours (Tier 1)",
                        subtitle = "Frequent republishing after sending (default 15 minutes)",
                        currentMillis = intervalRepublishTier1,
                        defaultMillis = DefaultRepublishConfig.TIER1_INTERVAL,
                        options = REPUBLISH_TIER1_OPTIONS,
                        onSelect = { viewModel.setIntervalRepublishTier1(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Tier 2: 2h - 12h (Default: 1 hour)
                    IntervalDropdownRow(
                        title = "2. 2 to 12 Hours (Tier 2)",
                        subtitle = "Intermediate retry interval (default 1 hour)",
                        currentMillis = intervalRepublishTier2,
                        defaultMillis = DefaultRepublishConfig.TIER2_INTERVAL,
                        options = REPUBLISH_TIER2_OPTIONS,
                        onSelect = { viewModel.setIntervalRepublishTier2(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Tier 3: Beyond 12h to TTL (Default: 1.5 hours / 90 minutes)
                    IntervalDropdownRow(
                        title = "3. Beyond 12 Hours (Tier 3)",
                        subtitle = "Long-term republishing (default 1.5 hours / 90 min, prevents BEP 44 expiration ~2h)",
                        currentMillis = intervalRepublishTier3,
                        defaultMillis = DefaultRepublishConfig.TIER3_INTERVAL,
                        options = REPUBLISH_TIER3_OPTIONS,
                        onSelect = { viewModel.setIntervalRepublishTier3(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Max TTL: (Default: 48 hours)
                    IntervalDropdownRow(
                        title = "4. Maximum Record Lifetime (TTL)",
                        subtitle = "After this time, message becomes EXPIRED_OFFLINE and radio ceases wakeups (default 48 hours)",
                        currentMillis = republishMaxTtl,
                        defaultMillis = DefaultRepublishConfig.MAX_TTL,
                        options = REPUBLISH_TTL_OPTIONS,
                        onSelect = { viewModel.setRepublishMaxTtl(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Crowdsourced DHT Republishing (P2P Relay)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Crowdsourced DHT Republishing (P2P Relay)",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = "Helps deliver messages to offline users and enhances anonymity at minimal bandwidth cost.",
                                style = MaterialTheme.typography.bodySmall,
                                color = appColors.textSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                        Switch(
                            checked = isCrowdsourcedRepublishEnabled,
                            onCheckedChange = { viewModel.setCrowdsourcedRepublishEnabled(it) }
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ==================== SECTION 4: PRIVACY & TOR NETWORK ====================
            SettingsSectionHeader(
                title = "Privacy & TOR Network",
                icon = Icons.Default.Security
            )

            Surface(
                color = appColors.surface,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, appColors.border, RoundedCornerShape(16.dp))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Embedded TOR Routing",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Hides your IP address from public BitTorrent DHT (BEP 44) nodes. KRPC packets are routed through the TOR onion network without external apps (e.g. Orbot).",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    // Switch: TOR connection
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "TOR Network Connection",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isTorEnabled) "Enabled (active SOCKS5 routing)" else "Disabled (direct UDP socket)",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (isTorEnabled) appColors.primary else appColors.textSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                        Switch(
                            checked = isTorEnabled,
                            onCheckedChange = { viewModel.setTorEnabled(it) }
                        )
                    }

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Switch: Biometric lock
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Biometric App Lock",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isBiometricLockEnabled) "Enabled (requires biometric/PIN)" else "Disabled (direct access)",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (isBiometricLockEnabled) appColors.primary else appColors.textSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                        Switch(
                            checked = isBiometricLockEnabled,
                            onCheckedChange = { viewModel.setBiometricLockEnabled(it) }
                        )
                    }

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // App PIN
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "App Lock PIN",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isAppLockPinSet) "Set (required to unlock)" else "Not set (direct access or biometric)",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (isAppLockPinSet) appColors.primary else appColors.textSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            if (isAppLockPinSet) {
                                OutlinedButton(
                                    onClick = { viewModel.setAppLockPin(null) },
                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                ) {
                                    Text("Remove", fontSize = 12.sp)
                                }
                            }
                            Button(
                                onClick = {
                                    pinDialogInput = ""
                                    showPinDialog = true
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = appColors.primary),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                                modifier = Modifier.testTag("settings_pin_setup_button")
                            ) {
                                Text(
                                    if (isAppLockPinSet) "Change" else "Set",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.Black
                                )
                            }
                        }
                    }

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Duress PIN
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "Duress PIN",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = appColors.textPrimary,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = "🛡️ Panic Wipe",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = Color(0xFFE53935),
                                    fontWeight = FontWeight.Bold
                                )
                            }
                            Text(
                                text = "Entering this PIN on the lock screen immediately wipes the database master key in AndroidKeyStore and opens an innocent empty personal notes screen (Decoy).",
                                style = MaterialTheme.typography.bodySmall,
                                color = appColors.textSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                            if (isDuressPinSet) {
                                Text(
                                    text = "Configured and active ✓",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = appColors.primary,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(top = 2.dp)
                                )
                            }
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            if (isDuressPinSet) {
                                OutlinedButton(
                                    onClick = { viewModel.setDuressPin(null) },
                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                ) {
                                    Text("Remove", fontSize = 12.sp)
                                }
                            }
                            Button(
                                onClick = {
                                    duressPinDialogInput = ""
                                    showDuressPinDialog = true
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE53935)),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                                modifier = Modifier.testTag("settings_duress_pin_setup_button")
                            ) {
                                Text(
                                    if (isDuressPinSet) "Change" else "Set",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White
                                )
                            }
                        }
                    }

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Switch: Strict Poisson Traffic Shaping
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Strict Poisson Traffic Shaping",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isStrictPoissonShapingEnabled) {
                                    "Enabled — messages, rekeying, and images queue in 900 B frames and emit strictly at Poisson intervals (replacing Delayed PUT), providing full secrecy of communication timing."
                                } else {
                                    "Disabled — messages are transmitted immediately with random jitter (Delayed PUT) and parallel decoy slots."
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = if (isStrictPoissonShapingEnabled) appColors.primary else appColors.textSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                        Switch(
                            checked = isStrictPoissonShapingEnabled,
                            onCheckedChange = { viewModel.setStrictPoissonShapingEnabled(it) }
                        )
                    }

                    // DHT latency tradeoff info
                    Surface(
                        color = appColors.surfaceVariant.copy(alpha = 0.6f),
                        shape = RoundedCornerShape(12.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, appColors.border),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 12.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text(
                                text = "⚠️",
                                style = MaterialTheme.typography.bodyLarge,
                                modifier = Modifier.padding(end = 10.dp)
                            )
                            Column {
                                Text(
                                    text = "Increased Latency (DHT Tradeoff)",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = appColors.textPrimary
                                )
                                Text(
                                    text = "Routing through 3 Tor relays increases DHT response times (RTT) from tens of milliseconds to 1–3 seconds. Sending and receiving messages may take longer.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = appColors.textSecondary,
                                    fontSize = 11.sp,
                                    modifier = Modifier.padding(top = 2.dp)
                                )
                            }
                        }
                    }

                    // Status Tor w czasie rzeczywistym
                    TorStatusCard(isTorEnabled = isTorEnabled, torState = torState)
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ==================== SECTION 5: SELF-CONVERSATION / DHT TEST ====================
            SettingsSectionHeader(
                title = "Self-Conversation (DHT Test & Notes)",
                icon = Icons.Default.Bookmark
            )

            Surface(
                color = appColors.surface,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, appColors.border, RoundedCornerShape(16.dp))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "🔒 Encrypted Notes & DHT Loopback Test",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "You can send messages to yourself. Messages are post-quantum encrypted (ML-KEM/AES-256-GCM), published to the BitTorrent DHT and read back, verifying P2P leaf node operation.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    Button(
                        onClick = onOpenSelfNotes,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = appColors.primary,
                            contentColor = Color.Black
                        ),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("settings_self_notes_button")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.Chat,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Open Self-Conversation / Notes",
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ==================== SECTION 6: MASTER'S THESIS RESEARCH & FIREBASE ====================
            SettingsSectionHeader(
                title = "Academic Research (Master's Thesis)",
                icon = Icons.Default.Analytics
            )

            Surface(
                color = appColors.surface,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, appColors.border, RoundedCornerShape(16.dp))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "🔬 Anonymous Telemetry & Retention Analysis",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Consent to record and anonymously sync telemetry to Google Firebase: packet send/receive latencies, republishing cycle analysis, and empirical DHT record retention (15-min TTL sampling). All data is strictly anonymized (zero identities, zero message payloads, zero cryptographic keys).",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    // Switch: Send anonymous stats (default off)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Send Anonymous Telemetry",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isAnonymousStatsEnabled) "Enabled (active sampling and Firebase sync)" else "Disabled (default, no recording or transfer)",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (isAnonymousStatsEnabled) appColors.primary else appColors.textSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                        Switch(
                            checked = isAnonymousStatsEnabled,
                            onCheckedChange = { enabled ->
                                if (enabled) {
                                    showResearchConsentDialog = true
                                } else {
                                    viewModel.setAnonymousStatsEnabled(false)
                                }
                            },
                            modifier = Modifier.testTag("settings_research_telemetry_switch")
                        )
                    }

                    if (isAnonymousStatsEnabled) {
                        HorizontalDivider(
                            color = appColors.border,
                            modifier = Modifier.padding(vertical = 14.dp)
                        )

                        // Firebase sync status
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(bottom = 12.dp)
                        ) {
                            Text(
                                text = "Firebase Status: ",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                color = appColors.textPrimary
                            )
                            Text(
                                text = researchSyncStatus,
                                style = MaterialTheme.typography.bodySmall,
                                color = if (researchSyncStatus.contains("Synced") || researchSyncStatus.contains("Authenticated")) ElectricGreen else appColors.primary
                            )
                        }

                        // Telemetry metric cards
                        Text(
                            text = "Recorded research metrics:",
                            style = MaterialTheme.typography.labelMedium,
                            color = appColors.textSecondary,
                            modifier = Modifier.padding(bottom = 8.dp)
                        )

                        Column(
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                ResearchMetricCard(
                                    title = "Sent (initial)",
                                    count = researchFirstSendCount,
                                    modifier = Modifier.weight(1f)
                                )
                                ResearchMetricCard(
                                    title = "Own republishes",
                                    count = researchOwnRepublishCount,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                ResearchMetricCard(
                                    title = "P2P relay (others)",
                                    count = researchCrowdRepublishCount,
                                    modifier = Modifier.weight(1f)
                                )
                                ResearchMetricCard(
                                    title = "Received from DHT",
                                    count = researchPacketsReceivedCount,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                ResearchMetricCard(
                                    title = "Retention samples (TTL)",
                                    count = researchTtlSamplesCount,
                                    modifier = Modifier.weight(1f)
                                )
                                ResearchMetricCard(
                                    title = "Total events",
                                    count = researchEventsCount,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // Retention sampling interval (TTL)
                        IntervalDropdownRow(
                            title = "Retention Sampling Interval (TTL)",
                            subtitle = "How often to probe the DHT for packet survival (default every 15 minutes)",
                            currentMillis = statsProbeIntervalMs,
                            defaultMillis = 15 * 60 * 1000L,
                            options = RESEARCH_PROBE_INTERVAL_OPTIONS,
                            onSelect = { viewModel.setStatsProbeIntervalMs(it) }
                        )

                        Spacer(modifier = Modifier.height(14.dp))

                        // Main button: Export complete research package (.ZIP)
                        Button(
                            onClick = {
                                val intent = viewModel.getShareZipIntent(context)
                                if (intent != null) {
                                    context.startActivity(Intent.createChooser(intent, "Share research ZIP bundle"))
                                } else {
                                    android.widget.Toast.makeText(context, "No research data to export", android.widget.Toast.LENGTH_SHORT).show()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = appColors.primary,
                                contentColor = Color.Black
                            ),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(
                                imageVector = Icons.Default.Share,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Export research package (.ZIP)",
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        // Action buttons: Export CSV and Force Firebase Sync
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedButton(
                                onClick = {
                                    val intent = viewModel.getShareCsvIntent(context)
                                    if (intent != null) {
                                        context.startActivity(Intent.createChooser(intent, "Share / Download .CSV file"))
                                    }
                                },
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Download,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = "Export CSV",
                                    fontSize = 11.sp
                                )
                            }

                            OutlinedButton(
                                onClick = { viewModel.triggerFirebaseSyncNow() },
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.CloudUpload,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = "Sync to Firebase",
                                    fontSize = 11.sp
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showPinDialog) {
        AlertDialog(
            onDismissRequest = { showPinDialog = false },
            title = { Text("Set App Lock PIN") },
            text = {
                Column {
                    Text(
                        "Enter a PIN (4-16 digits) required to unlock the app.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = pinDialogInput,
                        onValueChange = { pinDialogInput = it },
                        label = { Text("New PIN") },
                        singleLine = true,
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword
                        ),
                        modifier = Modifier.testTag("pin_dialog_input")
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val trimmed = pinDialogInput.trim()
                        if (trimmed.length >= 4) {
                            viewModel.setAppLockPin(trimmed)
                            showPinDialog = false
                        }
                    },
                    modifier = Modifier.testTag("pin_dialog_confirm_button")
                ) {
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { showPinDialog = false },
                    modifier = Modifier.testTag("pin_dialog_dismiss_button")
                ) {
                    Text("Cancel")
                }
            }
        )
    }

    if (showDuressPinDialog) {
        AlertDialog(
            onDismissRequest = { showDuressPinDialog = false },
            title = { Text("Set Duress PIN") },
            text = {
                Column {
                    Text(
                        "⚠️ WARNING: Entering this PIN on the lock screen permanently wipes the master encryption key from hardware security (AndroidKeyStore) and opens an empty decoy notes screen.",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(0xFFE53935)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = duressPinDialogInput,
                        onValueChange = { duressPinDialogInput = it },
                        label = { Text("Duress PIN (different from normal PIN)") },
                        singleLine = true,
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword
                        ),
                        modifier = Modifier.testTag("duress_pin_dialog_input")
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val trimmed = duressPinDialogInput.trim()
                        if (trimmed.length >= 4) {
                            viewModel.setDuressPin(trimmed)
                            showDuressPinDialog = false
                        }
                    },
                    modifier = Modifier.testTag("duress_pin_dialog_confirm_button")
                ) {
                    Text("Save Duress PIN")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { showDuressPinDialog = false },
                    modifier = Modifier.testTag("duress_pin_dialog_dismiss_button")
                ) {
                    Text("Cancel")
                }
            }
        )
    }

    if (showResearchConsentDialog) {
        AlertDialog(
            onDismissRequest = { showResearchConsentDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("🔬 ", fontSize = 20.sp)
                    Text("Informed Research Consent", fontWeight = FontWeight.Bold)
                }
            },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    Text(
                        "Research project conducted as part of a Master's Thesis in Computer Science.\nThe study evaluates censorship resistance, Poisson traffic masking properties, and empirical DHT record retention in BitTorrent Mainline DHT (BEP 44) with post-quantum cryptography.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textPrimary
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        "🛡️ ZERO LEAK GUARANTEE (Zero-Leakage):",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF00E676)
                    )
                    Text(
                        "• NO private keys (ML-KEM-512, X25519, Ed25519) or KDF seeds ever leave the device.\n" +
                        "• NO message contents, contact names, or user identities are ever recorded.\n" +
                        "• NO user or peer IP addresses are collected (DHT slot hashes are truncated to 8-character prefixes).\n" +
                        "• Telemetry data is 100% anonymized and processed locally in CSV files.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        fontSize = 11.sp
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        "📊 METRICS COLLECTED:",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = appColors.primary
                    )
                    Text(
                        "1. Poisson Traffic Shaping: packet intervals (Δt_actual vs Δt_theoretical), Kolmogorov-Smirnov test statistics, Android Doze wakeup jitter, packet role distribution.\n" +
                        "2. DHT Convergence: put/get latencies, KRPC timeout rates, replica survival curves (TTL decay), /24 subnet entropy.\n" +
                        "3. Delivery & Rekeying: message delivery and Cover ACK times across lifecycle states and network transports (Wi-Fi, Cellular, Tor), KEM rekeying duration.\n" +
                        "4. Anomaly Detection: invalid Ed25519 signatures, invalid AEAD tags, sequence rollback attempts, clearnet leak blocks on cold Tor start.\n" +
                        "5. Energy & Resource Consumption: battery current (μAh), RAM/PSS overhead, total UDP traffic.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        fontSize = 11.sp
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        "Participation is completely voluntary. You can disable telemetry at any time with a single click, immediately halting all sampling and synchronization.",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium,
                        color = appColors.textPrimary,
                        fontSize = 11.sp
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.setAnonymousStatsEnabled(true)
                        showResearchConsentDialog = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = appColors.primary),
                    modifier = Modifier.testTag("research_consent_confirm_button")
                ) {
                    Text("I Agree and Enable", color = Color.Black, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showResearchConsentDialog = false
                    },
                    modifier = Modifier.testTag("research_consent_dismiss_button")
                ) {
                    Text("Cancel", color = appColors.textSecondary)
                }
            }
        )
    }
}

@Composable
fun ResearchMetricCard(
    title: String,
    count: Int,
    modifier: Modifier = Modifier
) {
    val appColors = LocalAppColors.current
    Surface(
        color = appColors.surfaceVariant.copy(alpha = 0.5f),
        shape = RoundedCornerShape(10.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, appColors.border),
        modifier = modifier
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Text(
                text = "$count",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = appColors.primary
            )
            Text(
                text = title,
                style = MaterialTheme.typography.bodySmall,
                color = appColors.textSecondary,
                fontSize = 11.sp
            )
        }
    }
}

@Composable
fun SettingsSectionHeader(title: String, icon: ImageVector) {
    val appColors = LocalAppColors.current
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(start = 4.dp, bottom = 8.dp)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = appColors.primary,
            modifier = Modifier.size(18.dp)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = appColors.textPrimary
        )
    }
}

@Composable
fun ThemeOptionCard(
    label: String,
    subtitle: String,
    icon: ImageVector,
    isSelected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val appColors = LocalAppColors.current
    val borderColor = if (isSelected) appColors.primary else appColors.border
    val bgColor = if (isSelected) appColors.primary.copy(alpha = 0.15f) else appColors.surfaceVariant.copy(alpha = 0.5f)

    Surface(
        color = bgColor,
        shape = RoundedCornerShape(12.dp),
        modifier = modifier
            .border(if (isSelected) 2.dp else 1.dp, borderColor, RoundedCornerShape(12.dp))
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
    ) {
        Column(
            modifier = Modifier.padding(vertical = 12.dp, horizontal = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (isSelected) appColors.primary else appColors.textSecondary,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                color = if (isSelected) appColors.primary else appColors.textPrimary,
                fontSize = 13.sp
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelSmall,
                color = if (isSelected) appColors.primary.copy(alpha = 0.8f) else appColors.textSecondary,
                fontSize = 10.sp
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IntervalDropdownRow(
    title: String,
    subtitle: String,
    currentMillis: Long,
    defaultMillis: Long,
    options: List<SyncIntervalOption> = SYNC_INTERVAL_OPTIONS,
    onSelect: (Long) -> Unit
) {
    val appColors = LocalAppColors.current
    var expanded by remember { mutableStateOf(false) }

    val currentOption = remember(currentMillis, options) {
        options.find { it.millis == currentMillis }
            ?: SyncIntervalOption("${currentMillis / 1000}s", currentMillis)
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
            color = appColors.textPrimary
        )
        Text(
            text = subtitle,
            style = MaterialTheme.typography.bodySmall,
            color = appColors.textSecondary,
            fontSize = 12.sp,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = !expanded },
            modifier = Modifier.fillMaxWidth()
        ) {
            OutlinedTextField(
                value = currentOption.label + if (currentOption.millis == defaultMillis) " (Default)" else "",
                onValueChange = {},
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = appColors.primary,
                    unfocusedBorderColor = appColors.border,
                    focusedTextColor = appColors.textPrimary,
                    unfocusedTextColor = appColors.textPrimary,
                    focusedContainerColor = appColors.surfaceVariant.copy(alpha = 0.5f),
                    unfocusedContainerColor = appColors.surfaceVariant.copy(alpha = 0.5f)
                ),
                shape = RoundedCornerShape(12.dp),
                textStyle = MaterialTheme.typography.bodyMedium.copy(
                    fontWeight = if (currentOption.millis == defaultMillis) FontWeight.Bold else FontWeight.Normal
                ),
                modifier = Modifier
                    .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable, enabled = true)
                    .fillMaxWidth()
            )

            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
                modifier = Modifier.background(appColors.surface)
            ) {
                options.forEach { option ->
                    val isDefault = option.millis == defaultMillis
                    val isSelected = option.millis == currentMillis

                    DropdownMenuItem(
                        text = {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = option.label + if (isDefault) " (Default)" else "",
                                    fontWeight = if (isDefault) FontWeight.Bold else FontWeight.Normal,
                                    color = if (isSelected) appColors.primary else appColors.textPrimary,
                                    fontSize = 14.sp
                                )
                                if (isSelected) {
                                    Icon(
                                        imageVector = Icons.Default.Check,
                                        contentDescription = null,
                                        tint = appColors.primary,
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                            }
                        },
                        onClick = {
                            onSelect(option.millis)
                            expanded = false
                        },
                        contentPadding = ExposedDropdownMenuDefaults.ItemContentPadding
                    )
                }
            }
        }
    }
}

@Composable
fun TorStatusCard(
    isTorEnabled: Boolean,
    torState: TorState
) {
    val appColors = LocalAppColors.current

    Surface(
        color = appColors.surfaceVariant.copy(alpha = 0.4f),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, appColors.border),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "TOR Node Status",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                    color = appColors.textPrimary
                )

                // State badge
                val badgeText: String
                val badgeColor: Color
                val badgeBorder: Color

                if (!isTorEnabled) {
                    badgeText = "Disabled"
                    badgeColor = appColors.textSecondary.copy(alpha = 0.2f)
                    badgeBorder = appColors.border
                } else {
                    when (torState) {
                        is TorState.Disconnected -> {
                            badgeText = "Disconnected"
                            badgeColor = appColors.textSecondary.copy(alpha = 0.2f)
                            badgeBorder = appColors.border
                        }
                        is TorState.Starting -> {
                            badgeText = "Starting"
                            badgeColor = Color(0xFFFF9800).copy(alpha = 0.2f)
                            badgeBorder = Color(0xFFFF9800)
                        }
                        is TorState.Bootstrapping -> {
                            badgeText = "Bootstrap: ${torState.progress}%"
                            badgeColor = NeonCyan.copy(alpha = 0.2f)
                            badgeBorder = NeonCyan
                        }
                        is TorState.Connected -> {
                            badgeText = "Connected"
                            badgeColor = ElectricGreen.copy(alpha = 0.2f)
                            badgeBorder = ElectricGreen
                        }
                        is TorState.Error -> {
                            badgeText = "Error"
                            badgeColor = Color(0xFFE53935).copy(alpha = 0.2f)
                            badgeBorder = Color(0xFFE53935)
                        }
                    }
                }

                Surface(
                    color = badgeColor,
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, badgeBorder)
                ) {
                    Text(
                        text = badgeText,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = appColors.textPrimary,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            if (!isTorEnabled) {
                Text(
                    text = "TOR mode is currently disabled. DHT packets are sent via direct UDP transport socket.",
                    style = MaterialTheme.typography.bodySmall,
                    color = appColors.textSecondary
                )
            } else {
                when (torState) {
                    is TorState.Disconnected -> {
                        Text(
                            text = "Waiting for TOR client to start...",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textSecondary
                        )
                    }
                    is TorState.Starting -> {
                        Text(
                            text = "Starting embedded Tor engine and generating torrc...",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textSecondary
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        LinearProgressIndicator(
                            modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(4.dp)),
                            color = appColors.primary,
                            trackColor = appColors.border
                        )
                    }
                    is TorState.Bootstrapping -> {
                        Text(
                            text = "Connecting to Tor relays: ${torState.progress}% ${if (torState.summary.isNotBlank()) "— ${torState.summary}" else ""}",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textPrimary,
                            fontWeight = FontWeight.Medium
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        LinearProgressIndicator(
                            progress = { torState.progress / 100f },
                            modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(4.dp)),
                            color = NeonCyan,
                            trackColor = appColors.border
                        )
                    }
                    is TorState.Connected -> {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Lock,
                                contentDescription = null,
                                tint = ElectricGreen,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "Connected to TOR network (SOCKS5 Port: ${torState.socksPort})",
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Bold,
                                color = ElectricGreen
                            )
                        }
                        Text(
                            text = "DHT KRPC traffic is encapsulated through SOCKS5 proxy (UDP ASSOCIATE or TCP stream tunnel for standard Tor daemons). Domain name resolution (RFC 1928) occurs at exit relays.",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textSecondary,
                            fontSize = 11.sp,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                    is TorState.Error -> {
                        Text(
                            text = "Tor client error: ${torState.message}",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFFE53935),
                            fontWeight = FontWeight.Medium
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Fail-Closed security active: direct UDP transmission over cellular/Wi-Fi is halted to prevent clearnet IP leaks.",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textSecondary,
                            fontSize = 11.sp
                        )
                    }
                }
            }
        }
    }
}

