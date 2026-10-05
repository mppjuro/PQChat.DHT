package org.pqchat.dht.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import org.pqchat.dht.data.settings.ThemeMode

// Dark Cyber Palette
val DarkBackground = Color(0xFF090D16)
val DarkSurface = Color(0xFF111726)
val DarkSurfaceVariant = Color(0xFF192338)
val NeonCyan = Color(0xFF00E5FF)
val ElectricGreen = Color(0xFF00E676)
val CryptoPurple = Color(0xFF7C4DFF)
val AmberWarning = Color(0xFFFFB300)
val TextPrimary = Color(0xFFECEFF4)
val TextSecondary = Color(0xFF8F9BB3)
val BorderGlass = Color(0x3300E5FF)

// Light Cyber-Clean Palette
val LightBackground = Color(0xFFF3F6FA)
val LightSurface = Color(0xFFFFFFFF)
val LightSurfaceVariant = Color(0xFFE5ECF6)
val LightPrimary = Color(0xFF00838F)
val LightSecondary = Color(0xFF00897B)
val LightTextPrimary = Color(0xFF101726)
val LightTextSecondary = Color(0xFF55657E)
val LightBorderGlass = Color(0x2200838F)

data class AppColors(
    val background: Color,
    val surface: Color,
    val surfaceVariant: Color,
    val primary: Color,
    val secondary: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val border: Color,
    val isDark: Boolean
)

val LocalAppColors = staticCompositionLocalOf {
    AppColors(
        background = DarkBackground,
        surface = DarkSurface,
        surfaceVariant = DarkSurfaceVariant,
        primary = NeonCyan,
        secondary = ElectricGreen,
        textPrimary = TextPrimary,
        textSecondary = TextSecondary,
        border = BorderGlass,
        isDark = true
    )
}

val CyberTypography = Typography(
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 22.sp
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp
    )
)

private val DarkColorScheme = darkColorScheme(
    primary = NeonCyan,
    onPrimary = Color.Black,
    primaryContainer = DarkSurfaceVariant,
    onPrimaryContainer = NeonCyan,
    secondary = ElectricGreen,
    onSecondary = Color.Black,
    tertiary = CryptoPurple,
    background = DarkBackground,
    surface = DarkSurface,
    surfaceVariant = DarkSurfaceVariant,
    onBackground = TextPrimary,
    onSurface = TextPrimary,
    onSurfaceVariant = TextSecondary,
    outline = BorderGlass
)

private val LightColorScheme = lightColorScheme(
    primary = LightPrimary,
    onPrimary = Color.White,
    primaryContainer = LightSurfaceVariant,
    onPrimaryContainer = LightPrimary,
    secondary = LightSecondary,
    onSecondary = Color.White,
    tertiary = CryptoPurple,
    background = LightBackground,
    surface = LightSurface,
    surfaceVariant = LightSurfaceVariant,
    onBackground = LightTextPrimary,
    onSurface = LightTextPrimary,
    onSurfaceVariant = LightTextSecondary,
    outline = LightBorderGlass
)

@Composable
fun PQChatTheme(
    themeMode: ThemeMode = ThemeMode.SYSTEM,
    content: @Composable () -> Unit
) {
    val systemInDark = isSystemInDarkTheme()
    val isDark = when (themeMode) {
        ThemeMode.SYSTEM -> systemInDark
        ThemeMode.DARK -> true
        ThemeMode.LIGHT -> false
    }

    val appColors = if (isDark) {
        AppColors(
            background = DarkBackground,
            surface = DarkSurface,
            surfaceVariant = DarkSurfaceVariant,
            primary = NeonCyan,
            secondary = ElectricGreen,
            textPrimary = TextPrimary,
            textSecondary = TextSecondary,
            border = BorderGlass,
            isDark = true
        )
    } else {
        AppColors(
            background = LightBackground,
            surface = LightSurface,
            surfaceVariant = LightSurfaceVariant,
            primary = LightPrimary,
            secondary = LightSecondary,
            textPrimary = LightTextPrimary,
            textSecondary = LightTextSecondary,
            border = LightBorderGlass,
            isDark = false
        )
    }

    CompositionLocalProvider(LocalAppColors provides appColors) {
        MaterialTheme(
            colorScheme = if (isDark) DarkColorScheme else LightColorScheme,
            typography = CyberTypography,
            content = content
        )
    }
}
