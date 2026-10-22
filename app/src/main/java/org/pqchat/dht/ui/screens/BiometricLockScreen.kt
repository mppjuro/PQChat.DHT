package org.pqchat.dht.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.pqchat.dht.data.settings.PinAuthResult
import org.pqchat.dht.ui.theme.LocalAppColors

@Composable
fun BiometricLockScreen(
    onUnlockRequested: () -> Unit,
    onPinSubmitted: ((String) -> PinAuthResult)? = null,
    onUnlockSuccess: (() -> Unit)? = null,
    onDuressTriggered: (() -> Unit)? = null,
    isPinConfigured: Boolean = false,
    isBiometricAvailable: Boolean = true
) {
    val appColors = LocalAppColors.current

    var pinInput by remember { mutableStateOf("") }
    var pinVisible by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        if (isBiometricAvailable) {
            onUnlockRequested()
        }
    }

    fun submitPin() {
        if (pinInput.isBlank()) {
            errorMessage = "Enter PIN code"
            return
        }
        val result = onPinSubmitted?.invoke(pinInput) ?: PinAuthResult.NO_PIN_SET
        when (result) {
            PinAuthResult.NORMAL_UNLOCK, PinAuthResult.NO_PIN_SET -> {
                errorMessage = null
                onUnlockSuccess?.invoke()
            }
            PinAuthResult.DURESS_TRIGGERED -> {
                errorMessage = null
                onDuressTriggered?.invoke()
            }
            PinAuthResult.INVALID -> {
                errorMessage = "Invalid PIN code"
                pinInput = ""
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(24.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier.fillMaxWidth(0.9f)
        ) {
            Box(
                modifier = Modifier
                    .size(88.dp)
                    .clip(CircleShape)
                    .background(appColors.primary.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.Lock,
                    contentDescription = "Locked",
                    tint = appColors.primary,
                    modifier = Modifier.size(44.dp)
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                text = "PQChat Locked",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "Enter PIN or use biometrics to unlock secure conversations.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(24.dp))

            // PIN Entry field
            OutlinedTextField(
                value = pinInput,
                onValueChange = {
                    if (it.length <= 16) {
                        pinInput = it
                        errorMessage = null
                    }
                },
                label = { Text("PIN code / Duress PIN") },
                singleLine = true,
                visualTransformation = if (pinVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.NumberPassword,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(
                    onDone = { submitPin() }
                ),
                trailingIcon = {
                    IconButton(onClick = { pinVisible = !pinVisible }) {
                        Icon(
                            imageVector = if (pinVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            contentDescription = if (pinVisible) "Hide PIN" else "Show PIN"
                        )
                    }
                },
                isError = errorMessage != null,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("pin_input_field")
            )

            if (errorMessage != null) {
                Text(
                    text = errorMessage ?: "",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 8.dp, top = 4.dp)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Bank-grade on-screen numeric keypad
            val keypadRows = listOf(
                listOf("1", "2", "3"),
                listOf("4", "5", "6"),
                listOf("7", "8", "9"),
                listOf("C", "0", "⌫")
            )

            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                for (row in keypadRows) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        for (key in row) {
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = appColors.surfaceVariant.copy(alpha = 0.7f),
                                border = BorderStroke(1.dp, appColors.border),
                                modifier = Modifier
                                    .weight(1f)
                                    .height(48.dp)
                                    .clip(RoundedCornerShape(12.dp))
                                    .clickable {
                                        when (key) {
                                            "C" -> {
                                                pinInput = ""
                                                errorMessage = null
                                            }
                                            "⌫" -> {
                                                if (pinInput.isNotEmpty()) {
                                                    pinInput = pinInput.dropLast(1)
                                                    errorMessage = null
                                                }
                                            }
                                            else -> {
                                                if (pinInput.length < 16) {
                                                    pinInput += key
                                                    errorMessage = null
                                                }
                                            }
                                        }
                                    }
                                    .testTag(
                                        when (key) {
                                            "C" -> "pin_key_clear"
                                            "⌫" -> "pin_key_backspace"
                                            else -> "pin_key_$key"
                                        }
                                    )
                            ) {
                                Box(
                                    contentAlignment = Alignment.Center,
                                    modifier = Modifier.fillMaxSize()
                                ) {
                                    Text(
                                        text = key,
                                        style = MaterialTheme.typography.titleMedium,
                                        fontWeight = FontWeight.Bold,
                                        color = if (key in listOf("C", "⌫")) appColors.primary else appColors.textPrimary
                                    )
                                }
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Submit PIN Button
            Button(
                onClick = { submitPin() },
                colors = ButtonDefaults.buttonColors(containerColor = appColors.primary),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .testTag("pin_unlock_button")
            ) {
                Text(
                    text = "Unlock with PIN",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }

            if (isBiometricAvailable) {
                Spacer(modifier = Modifier.height(12.dp))

                OutlinedButton(
                    onClick = onUnlockRequested,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Fingerprint,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp),
                        tint = appColors.primary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Use Biometrics",
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Medium,
                        color = appColors.primary
                    )
                }
            }
        }
    }
}
