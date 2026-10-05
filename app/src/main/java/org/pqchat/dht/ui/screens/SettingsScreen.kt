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
import org.pqchat.dht.ui.theme.ElectricGreen
import org.pqchat.dht.ui.theme.LocalAppColors
import org.pqchat.dht.ui.theme.NeonCyan
import org.pqchat.dht.ui.viewmodel.ChatViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: ChatViewModel,
    onBack: () -> Unit,
    onOpenSelfNotes: () -> Unit
) {
    val appColors = LocalAppColors.current

    val themeMode by viewModel.themeMode.collectAsState()
    val intervalForeground by viewModel.intervalForegroundChat.collectAsState()
    val intervalAppActive by viewModel.intervalAppActive.collectAsState()
    val intervalBgIdle by viewModel.intervalBackgroundIdle.collectAsState()
    val intervalDoze by viewModel.intervalDozeSleep.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Ustawienia", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
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
                            modifier = Modifier.weight(1f)
                        )

                        ThemeOptionCard(
                            label = "Ciemny",
                            subtitle = "Dark Mode",
                            icon = Icons.Default.DarkMode,
                            isSelected = themeMode == ThemeMode.DARK,
                            onClick = { viewModel.setThemeMode(ThemeMode.DARK) },
                            modifier = Modifier.weight(1f)
                        )

                        ThemeOptionCard(
                            label = "Jasny",
                            subtitle = "Light Mode",
                            icon = Icons.Default.LightMode,
                            isSelected = themeMode == ThemeMode.LIGHT,
                            onClick = { viewModel.setThemeMode(ThemeMode.LIGHT) },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ==================== SECTION 2: DHT INTERVALS ====================
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
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ==================== SECTION 3: SELF-CONVERSATION / DHT TEST ====================
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
                        modifier = Modifier.fillMaxWidth()
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
    onSelect: (Long) -> Unit
) {
    val appColors = LocalAppColors.current
    var expanded by remember { mutableStateOf(false) }

    val currentOption = remember(currentMillis) {
        SYNC_INTERVAL_OPTIONS.find { it.millis == currentMillis }
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
                    .menuAnchor()
                    .fillMaxWidth()
            )

            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
                modifier = Modifier.background(appColors.surface)
            ) {
                SYNC_INTERVAL_OPTIONS.forEach { option ->
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
