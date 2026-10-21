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
                title = { Text("Ustawienia", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                        modifier = Modifier.testTag("settings_back_button")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Wróć",
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
                title = "Wygląd i motyw aplikacji",
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
                        text = "Wybór motywu graficznego",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Domyślnie aplikacja automatycznie dopasowuje się do motywu Twojego systemu w telefonie.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 12.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ThemeOptionCard(
                            label = "Systemowy",
                            subtitle = "Domyślny",
                            icon = Icons.Default.BrightnessAuto,
                            isSelected = themeMode == ThemeMode.SYSTEM,
                            onClick = { viewModel.setThemeMode(ThemeMode.SYSTEM) },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("theme_system_card")
                        )

                        ThemeOptionCard(
                            label = "Ciemny",
                            subtitle = "Dark Mode",
                            icon = Icons.Default.DarkMode,
                            isSelected = themeMode == ThemeMode.DARK,
                            onClick = { viewModel.setThemeMode(ThemeMode.DARK) },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("theme_dark_card")
                        )

                        ThemeOptionCard(
                            label = "Jasny",
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
                title = "Kompresja obrazów (Transfer DHT / PNG8)",
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
                        text = "Format PNG8 z kwantyzacją palety barw",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Przesyłanie plików przez sieć BitTorrent DHT dzieli dane na 800-bajtowe fragmenty. Kompresja do formatu PNG8 pozwala przesłać zdjęcia w zaledwie kilkudziesięciu pakietach UDP.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    // 1. Rozdzielczość (najdłuższa krawędź)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                            Text(
                                text = "Rozdzielczość (najdłuższa krawędź)",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = appColors.textPrimary
                            )
                            Text(
                                text = "Dłuższy bok zdjęcia jest skalowany do wybranej wartości",
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

                    // Szybkie presety rozdzielczości
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

                    // 2. Ilość kolorów palety (PNG8)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                            Text(
                                text = "Ilość kolorów palety (PNG8)",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = appColors.textPrimary
                            )
                            Text(
                                text = "Mniejsza liczba kolorów = wyższa kompresja i szybszy transfer DHT",
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
                                text = "$imageColorCount kolorów",
                                color = appColors.primary,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // Szybkie presety palety kolorów
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
                title = "Interwały synchronizacji DHT (4 tryby)",
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
                        text = "Częstotliwość odpytywania slotów BEP 44",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Dostosuj czasy sprawdzania nadejścia nowych wiadomości w sieci BitTorrent DHT dla każdego z 4 stanów aplikacji. Domyślne wartości oznaczono pogrubioną czcionką.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    // Mode 1: Foreground Active Chat (Default: 10 sekund)
                    IntervalDropdownRow(
                        title = "1. Aktywny czat na pierwszym planie",
                        subtitle = "Gdy rozmawiasz w otwartym oknie czatu",
                        currentMillis = intervalForeground,
                        defaultMillis = DefaultIntervals.FOREGROUND_CHAT,
                        onSelect = { viewModel.setIntervalForegroundChat(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Mode 2: App Active / Other Screen (Default: 1 minuta)
                    IntervalDropdownRow(
                        title = "2. Aplikacja otwarta (lista kontaktów)",
                        subtitle = "Gdy aplikacja jest widoczna, ale czat nie jest otwarty",
                        currentMillis = intervalAppActive,
                        defaultMillis = DefaultIntervals.APP_ACTIVE,
                        onSelect = { viewModel.setIntervalAppActive(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Mode 3: Background Idle (Default: 5 minut)
                    IntervalDropdownRow(
                        title = "3. Aplikacja w tle (ekran włączony)",
                        subtitle = "Gdy aplikacja jest zminimalizowana przy włączonym ekranie",
                        currentMillis = intervalBgIdle,
                        defaultMillis = DefaultIntervals.BACKGROUND_IDLE,
                        onSelect = { viewModel.setIntervalBackgroundIdle(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Mode 4: Deep Sleep / Doze (Default: 15 minut)
                    IntervalDropdownRow(
                        title = "4. Głębokie uśpienie (ekran wygaszony)",
                        subtitle = "Tryb oszczędzania baterii Doze przy wygaszonym telefonie",
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
                                text = "Tryb ciągłego nasłuchu (Foreground Service)",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = "Podtrzymuje stały serwis w tle z powiadomieniem o niskim opóźnieniu (~10s) kosztem większego zużycia baterii.",
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
                                text = "Wyłączenie optymalizacji baterii (Doze whitelist)",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = if (isBatteryIgnored) {
                                    "Optymalizacje wyłączone — alarmy Doze i radio wybudzają się bez przeszkód."
                                } else {
                                    "Wymagane, aby system Android nie blokował budzenia radia w trybie uśpienia Doze."
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
                                Text("Wyłącz", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.Black)
                            }
                        } else {
                            Text(
                                text = "Aktywne ✓",
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
                title = "Republishing DHT i limit TTL (Exponential Backoff)",
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
                        text = "Odświeżanie rekordu w DHT i limit TTL",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Dla niepotwierdzonych wiadomości węzeł odświeża wpisy w sieci DHT ze stopniowo wydłużającymi się przerwami (Exponential Backoff) w celu ochrony baterii i radia urządzenia. Po przekroczeniu limitu TTL wiadomość zostaje oznaczona jako EXPIRED_OFFLINE, a wybudzanie radia urządzenia całkowicie zatrzymane.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    // Tier 1: 0 - 2h (Default: 15 minut)
                    IntervalDropdownRow(
                        title = "1. Pierwsze 2 godziny (Tier 1)",
                        subtitle = "Częste odświeżanie po nadaniu (domyślnie 15 minut)",
                        currentMillis = intervalRepublishTier1,
                        defaultMillis = DefaultRepublishConfig.TIER1_INTERVAL,
                        options = REPUBLISH_TIER1_OPTIONS,
                        onSelect = { viewModel.setIntervalRepublishTier1(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Tier 2: 2h - 12h (Default: 1 godzina)
                    IntervalDropdownRow(
                        title = "2. Od 2 do 12 godzin (Tier 2)",
                        subtitle = "Średni interwał ponawiania (domyślnie 1 godzina)",
                        currentMillis = intervalRepublishTier2,
                        defaultMillis = DefaultRepublishConfig.TIER2_INTERVAL,
                        options = REPUBLISH_TIER2_OPTIONS,
                        onSelect = { viewModel.setIntervalRepublishTier2(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Tier 3: Powyżej 12h do TTL (Default: 1.5 godziny / 90 minut)
                    IntervalDropdownRow(
                        title = "3. Powyżej 12 godzin (Tier 3)",
                        subtitle = "Odświeżanie długoterminowe (domyślnie 1.5 godziny / 90 minut, zabezpiecza przed wygaśnięciem BEP 44 ~2h)",
                        currentMillis = intervalRepublishTier3,
                        defaultMillis = DefaultRepublishConfig.TIER3_INTERVAL,
                        options = REPUBLISH_TIER3_OPTIONS,
                        onSelect = { viewModel.setIntervalRepublishTier3(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Max TTL: (Default: 48 godzin)
                    IntervalDropdownRow(
                        title = "4. Maksymalny czas życia rekordu (TTL)",
                        subtitle = "Po tym czasie wiadomość staje się EXPIRED_OFFLINE i radio przestaje się wybudzać (domyślnie 48 godzin)",
                        currentMillis = republishMaxTtl,
                        defaultMillis = DefaultRepublishConfig.MAX_TTL,
                        options = REPUBLISH_TTL_OPTIONS,
                        onSelect = { viewModel.setRepublishMaxTtl(it) }
                    )

                    HorizontalDivider(
                        color = appColors.border,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    // Współdzielone odświeżanie DHT (przekaźnik P2P)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Współdzielone odświeżanie DHT (przekaźnik P2P)",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = "Pomaga dostarczać wiadomości użytkownikom offline i zwiększa anonimowość kosztem minimalnego transferu.",
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
                title = "Prywatność i Sieć TOR",
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
                        text = "Wbudowane trasowanie przez sieć TOR (Embedded Tor)",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Ukrywa Twój adres IP przed publicznymi węzłami BitTorrent DHT (BEP 44). Pakiety KRPC są trasowane przez sieć cebulową TOR bez konieczności instalowania zewnętrznych aplikacji (np. Orbot).",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    // Przełącznik: Połączenie przez sieć TOR
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Połączenie przez sieć TOR",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isTorEnabled) "Włączone (aktywne trasowanie SOCKS5)" else "Wyłączone (bezpośrednie gniazdo UDP)",
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

                    // Przełącznik: Blokada biometryczna aplikacji
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Blokada biometryczna aplikacji",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isBiometricLockEnabled) "Włączona (wymaga biometrii/kodu)" else "Wyłączona (bezpośredni dostęp)",
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

                    // Kod PIN aplikacji
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Kod PIN aplikacji",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isAppLockPinSet) "Ustawiony (wymagany przy odblokowaniu)" else "Nieustawiony (dostęp bezpośredni lub biometria)",
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
                                    Text("Usuń", fontSize = 12.sp)
                                }
                            }
                            Button(
                                onClick = {
                                    pinDialogInput = ""
                                    showPinDialog = true
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = appColors.primary),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    if (isAppLockPinSet) "Zmień" else "Ustaw",
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

                    // Kod przymusu (Duress PIN)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "Kod przymusu (Duress PIN)",
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
                                text = "Wpisanie tego kodu na ekranie blokady natychmiast kasuje klucz bazy danych w AndroidKeyStore i otwiera niewinny widok pustych notatek własnych (Decoy).",
                                style = MaterialTheme.typography.bodySmall,
                                color = appColors.textSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                            if (isDuressPinSet) {
                                Text(
                                    text = "Skonfigurowany i aktywny ✓",
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
                                    Text("Usuń", fontSize = 12.sp)
                                }
                            }
                            Button(
                                onClick = {
                                    duressPinDialogInput = ""
                                    showDuressPinDialog = true
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE53935)),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    if (isDuressPinSet) "Zmień" else "Ustaw",
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

                    // Przełącznik: Ścisłe kształtowanie ruchu Poissona (Strict Poisson Traffic Shaping)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Ścisłe kształtowanie ruchu Poissona (Traffic Shaping)",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isStrictPoissonShapingEnabled) {
                                    "Włączone — wiadomości, rekeying i obrazy czekają w kolejce 900B i są emitowane ściśle według taktu Poissona (zastępując Delayed PUT), zapewniając pełną tajność godzin i częstotliwości konwersacji."
                                } else {
                                    "Wyłączone — wiadomości są wysyłane natychmiastowo z losowym opóźnieniem (Delayed PUT) i równoległymi slotami-wabikami."
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

                    // Informacja o potencjalnym zwiększeniu opóźnień (DHT latency tradeoff)
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
                                    text = "Zwiększone opóźnienia (DHT latency tradeoff)",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = appColors.textPrimary
                                )
                                Text(
                                    text = "Trasowanie przez 3 przekaźniki sieci Tor zwiększa czas odpowiedzi węzłów DHT (RTT) z kilkudziesięciu milisekund do 1–3 sekund. Pobieranie oraz wysyłanie wiadomości może trwać dłużej.",
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
                title = "Rozmowa ze sobą (Test DHT & Notatki)",
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
                        text = "🔒 Szyfrowane Notatki i Test Pętli DHT",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Możesz pisać wiadomości do samego siebie. Wiadomości są szyfrowane post-kwantowo (ML-KEM/AES-256-GCM), publikowane do sieci Mainline BitTorrent DHT i odczytywane z powrotem, umożliwiając natychmiastowe testowanie działania węzła P2P.",
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
                            text = "Otwórz rozmowę ze sobą / Notatki",
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ==================== SECTION 6: MASTER'S THESIS RESEARCH & FIREBASE ====================
            SettingsSectionHeader(
                title = "Badania naukowe (Praca Magisterska)",
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
                        text = "🔬 Anonimowe Statystyki i Analiza Republishingu",
                        style = MaterialTheme.typography.titleSmall,
                        color = appColors.textPrimary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Zgoda na rejestrowanie i anonimowe przesyłanie do Google Firebase dokładnych czasów emisji i odbioru pakietów, pełnej analizy cykli republishingu oraz pomiaru czasu wygasania rekordów w sieci DHT (próbkowanie TTL co 15 minut). Wszystkie dane są całkowicie anonimowe (brak tożsamości, brak treści wiadomości, brak kluczy kryptograficznych).",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                    )

                    // Przełącznik: Wysyłaj anonimowe statystyki (domyślnie wyłączony)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
                            Text(
                                text = "Wysyłaj anonimowe statystyki",
                                style = MaterialTheme.typography.bodyMedium,
                                color = appColors.textPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isAnonymousStatsEnabled) "Włączone (aktywne próbkowanie i synchronizacja Firebase)" else "Wyłączone (domyślnie, brak zapisu i transferu)",
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
                            }
                        )
                    }

                    if (isAnonymousStatsEnabled) {
                        HorizontalDivider(
                            color = appColors.border,
                            modifier = Modifier.padding(vertical = 14.dp)
                        )

                        // Status synchronizacji Firebase
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(bottom = 12.dp)
                        ) {
                            Text(
                                text = "Status Firebase: ",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                color = appColors.textPrimary
                            )
                            Text(
                                text = researchSyncStatus,
                                style = MaterialTheme.typography.bodySmall,
                                color = if (researchSyncStatus.contains("Zsynchronizowano") || researchSyncStatus.contains("Uwierzytelniono")) ElectricGreen else appColors.primary
                            )
                        }

                        // Liczniki telemetryczne w kafelkach
                        Text(
                            text = "Zarejestrowane metryki badawcze:",
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
                                    title = "Wysłane (pierwszy raz)",
                                    count = researchFirstSendCount,
                                    modifier = Modifier.weight(1f)
                                )
                                ResearchMetricCard(
                                    title = "Własny republish",
                                    count = researchOwnRepublishCount,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                ResearchMetricCard(
                                    title = "Przekaźnik P2P (inni)",
                                    count = researchCrowdRepublishCount,
                                    modifier = Modifier.weight(1f)
                                )
                                ResearchMetricCard(
                                    title = "Odebrane z DHT",
                                    count = researchPacketsReceivedCount,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                ResearchMetricCard(
                                    title = "Próbki retencji (TTL)",
                                    count = researchTtlSamplesCount,
                                    modifier = Modifier.weight(1f)
                                )
                                ResearchMetricCard(
                                    title = "Łącznie zdarzeń",
                                    count = researchEventsCount,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // Częstotliwość próbkowania wygasania rekordów (TTL)
                        IntervalDropdownRow(
                            title = "Częstotliwość próbkowania wygasania (TTL)",
                            subtitle = "Jak często badać sieć DHT pod kątem przeżywalności oryginalnych pakietów (domyślnie co 15 minut)",
                            currentMillis = statsProbeIntervalMs,
                            defaultMillis = 15 * 60 * 1000L,
                            options = RESEARCH_PROBE_INTERVAL_OPTIONS,
                            onSelect = { viewModel.setStatsProbeIntervalMs(it) }
                        )

                        Spacer(modifier = Modifier.height(14.dp))

                        // Główny przycisk: Eksport kompletnej paczki badawczej (.ZIP)
                        Button(
                            onClick = {
                                val intent = viewModel.getShareZipIntent(context)
                                if (intent != null) {
                                    context.startActivity(Intent.createChooser(intent, "Udostępnij paczkę badawczą .ZIP"))
                                } else {
                                    android.widget.Toast.makeText(context, "Brak danych badawczych do eksportu", android.widget.Toast.LENGTH_SHORT).show()
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
                                text = "Eksportuj paczkę badawczą (.ZIP)",
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        // Przyciski akcji: Eksport CSV oraz Wymuszenie synchronizacji
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedButton(
                                onClick = {
                                    val intent = viewModel.getShareCsvIntent(context)
                                    if (intent != null) {
                                        context.startActivity(Intent.createChooser(intent, "Udostępnij / Pobierz plik .CSV"))
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
                                    text = "Eksportuj CSV",
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
                                    text = "Wyślij do Firebase",
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
            title = { Text("Ustaw kod PIN aplikacji") },
            text = {
                Column {
                    Text(
                        "Wprowadź kod PIN (4-16 cyfr), który będzie wymagany do odblokowania aplikacji.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = pinDialogInput,
                        onValueChange = { pinDialogInput = it },
                        label = { Text("Nowy kod PIN") },
                        singleLine = true,
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword
                        )
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
                    }
                ) {
                    Text("Zapisz")
                }
            },
            dismissButton = {
                TextButton(onClick = { showPinDialog = false }) {
                    Text("Anuluj")
                }
            }
        )
    }

    if (showDuressPinDialog) {
        AlertDialog(
            onDismissRequest = { showDuressPinDialog = false },
            title = { Text("Ustaw kod przymusu (Duress PIN)") },
            text = {
                Column {
                    Text(
                        "⚠️ UWAGA: Wpisanie tego kodu na ekranie blokady bezpowrotnie wyczyści klucz szyfrujący w bezpiecznym module sprzętowym (AndroidKeyStore) i przekieruje do pustego ekranu notatek (Decoy).",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(0xFFE53935)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = duressPinDialogInput,
                        onValueChange = { duressPinDialogInput = it },
                        label = { Text("Kod przymusu (różny od normalnego PIN)") },
                        singleLine = true,
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                            keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword
                        )
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
                    }
                ) {
                    Text("Zapisz kod przymusu")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDuressPinDialog = false }) {
                    Text("Anuluj")
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
                    Text("Świadoma Zgoda Badawcza\n(Informed Consent)", fontWeight = FontWeight.Bold)
                }
            },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    Text(
                        "Projekt badawczy realizowany w ramach pracy magisterskiej z informatyki (Wydział Informatyki).\nBadanie dotyczy odporności na cenzurę, właściwości maskowania ruchu Poissona oraz empirycznej retencji rekordów w zdecentralizowanej sieci BitTorrent Mainline DHT (BEP 44) z kryptografią post-kwantową.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textPrimary
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        "🛡️ GWARANCJA ZEROWEGO WYCIEKU (Zero-Leakage):",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF00E676)
                    )
                    Text(
                        "• ŻADNE klucze prywatne (ML-KEM-512, X25519, Ed25519) ani ziarna KDF nigdy nie opuszczają urządzenia.\n" +
                        "• ŻADNE treści wiadomości, nazwy kontaktów ani tożsamości nie są rejestrowane.\n" +
                        "• ŻADNE adresy IP użytkowników ani rozmówców nie są przesyłane (hashe slotów DHT są ucinane do 8-znakowych prefiksów).\n" +
                        "• Dane telemetryczne są w 100% zanonimizowane i przetwarzane lokalnie w plikach CSV.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        fontSize = 11.sp
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        "📊 JAKIE METRYKI BĘDĄ ZBIERANE:",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = appColors.primary
                    )
                    Text(
                        "1. Kształtowanie ruchu Poissona: interwały pakietów (Δt_actual vs Δt_theoretical), statystyki testu Kołmogorowa-Smirnowa, jitter wybudzeń w trybie Android Doze, rozkład ról pakietów.\n" +
                        "2. Zbieżność DHT: opóźnienia operacji put/get, odsetek timeoutów KRPC, krzywe przeżywalności replik (TTL decay) oraz entropia podsieci /24.\n" +
                        "3. Dostarczanie i Rekeying: czasy dostarczenia wiadomości i Cover ACK wg stanów cyklu życia i transportu (Wi-Fi, Cellular, Tor), czas trwania KEM rekeyingu.\n" +
                        "4. Wykrywanie anomalii: liczniki błędnych podpisów Ed25519, błędnych tagów AEAD, prób cofnięcia sekwencji oraz zablokowanych prób wycieku IP przy zimnym starcie Tora.\n" +
                        "5. Zużycie energii i zasobów: prąd baterii (μAh), narzut pamięci RAM/PSS oraz sumaryczny transfer UDP.",
                        style = MaterialTheme.typography.bodySmall,
                        color = appColors.textSecondary,
                        fontSize = 11.sp
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        "Udział jest w pełni dobrowolny. W każdej chwili możesz wyłączyć telemetrię jednym kliknięciem, co natychmiast zatrzyma wszelkie próbkowanie i synchronizację.",
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
                    colors = ButtonDefaults.buttonColors(containerColor = appColors.primary)
                ) {
                    Text("Wyrażam zgodę i włączam", color = Color.Black, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showResearchConsentDialog = false
                    }
                ) {
                    Text("Anuluj", color = appColors.textSecondary)
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
                value = currentOption.label + if (currentOption.millis == defaultMillis) " (Domyślne)" else "",
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
                                    text = option.label + if (isDefault) " (Domyślne)" else "",
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
                    text = "Status węzła TOR",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                    color = appColors.textPrimary
                )

                // State badge
                val badgeText: String
                val badgeColor: Color
                val badgeBorder: Color

                if (!isTorEnabled) {
                    badgeText = "Wyłączony"
                    badgeColor = appColors.textSecondary.copy(alpha = 0.2f)
                    badgeBorder = appColors.border
                } else {
                    when (torState) {
                        is TorState.Disconnected -> {
                            badgeText = "Odłączony"
                            badgeColor = appColors.textSecondary.copy(alpha = 0.2f)
                            badgeBorder = appColors.border
                        }
                        is TorState.Starting -> {
                            badgeText = "Inicjalizacja"
                            badgeColor = Color(0xFFFF9800).copy(alpha = 0.2f)
                            badgeBorder = Color(0xFFFF9800)
                        }
                        is TorState.Bootstrapping -> {
                            badgeText = "Bootstrap: ${torState.progress}%"
                            badgeColor = NeonCyan.copy(alpha = 0.2f)
                            badgeBorder = NeonCyan
                        }
                        is TorState.Connected -> {
                            badgeText = "Połączono"
                            badgeColor = ElectricGreen.copy(alpha = 0.2f)
                            badgeBorder = ElectricGreen
                        }
                        is TorState.Error -> {
                            badgeText = "Błąd"
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
                    text = "Tryb TOR jest obecnie wyłączony. Pakiety DHT wysyłane są bezpośrednim gniazdem transportowym UDP.",
                    style = MaterialTheme.typography.bodySmall,
                    color = appColors.textSecondary
                )
            } else {
                when (torState) {
                    is TorState.Disconnected -> {
                        Text(
                            text = "Oczekiwanie na start klienta TOR...",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textSecondary
                        )
                    }
                    is TorState.Starting -> {
                        Text(
                            text = "Uruchamianie wbudowanego silnika Tor i generowanie pliku torrc...",
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
                            text = "Łączenie z węzłami Tor: ${torState.progress}% ${if (torState.summary.isNotBlank()) "— ${torState.summary}" else ""}",
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
                                text = "Połączono z siecią TOR (Port SOCKS5: ${torState.socksPort})",
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Bold,
                                color = ElectricGreen
                            )
                        }
                        Text(
                            text = "Ruch DHT KRPC jest hermetyzowany przez proxy SOCKS5 (UDP ASSOCIATE lub tunel strumieniowy TCP dla standardowych demonów Tor). Rozwiązywanie nazw domenowych (RFC 1928) następuje po stronie węzła wyjściowego.",
                            style = MaterialTheme.typography.bodySmall,
                            color = appColors.textSecondary,
                            fontSize = 11.sp,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                    is TorState.Error -> {
                        Text(
                            text = "Błąd klienta Tor: ${torState.message}",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFFE53935),
                            fontWeight = FontWeight.Medium
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Zabezpieczenie Fail-Closed aktywne: bezpośrednia transmisja UDP przez sieć komórkową/Wi-Fi została wstrzymana, aby wykluczyć wyciek Twojego adresu IP (clearnet leak).",
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

