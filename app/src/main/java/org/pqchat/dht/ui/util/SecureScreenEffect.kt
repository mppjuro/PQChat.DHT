package org.pqchat.dht.ui.util

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalContext

/**
 * Attaches [WindowManager.LayoutParams.FLAG_SECURE] to the enclosing Activity window
 * while this Composable is part of the composition tree, and removes it on disposal.
 *
 * Enforces screen protection against:
 * - Screenshots and screen capture / screen recording tools
 * - System recent apps switcher preview snapshots
 *
 * Applied strictly to HandshakeScreen (ML-KEM QR code exchange) and ChatScreen (active chat).
 */
@Composable
fun SecureScreenEffect() {
    val context = LocalContext.current
    DisposableEffect(Unit) {
        val window = context.findActivity()?.window
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}

/**
 * Traverses context wrappers to find the enclosing [Activity].
 */
fun Context.findActivity(): Activity? {
    var ctx: Context? = this
    while (ctx is ContextWrapper) {
        if (ctx is Activity) return ctx
        ctx = ctx.baseContext
    }
    return null
}
