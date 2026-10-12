package org.pqchat.dht.ui.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import android.util.Log

/**
 * Utility helper to inspect and request ignoring battery optimizations (Doze mode whitelist).
 *
 * Essential for serverless P2P messengers where store-and-forward polling alarms must wake up
 * the device during deep sleep / Doze maintenance windows.
 */
object BatteryOptimizationHelper {

    private const val TAG = "BatteryOptimization"

    /**
     * Checks if the app is currently whitelisted from system battery optimizations.
     */
    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        return try {
            val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            powerManager?.isIgnoringBatteryOptimizations(context.packageName) ?: false
        } catch (e: Exception) {
            Log.e(TAG, "Error checking battery optimization status", e)
            false
        }
    }

    /**
     * Launches the system intent requesting the user to disable battery optimizations for PQChat.
     * Tries the direct application request dialog first, with a fallback to the global settings list.
     */
    @SuppressLint("BatteryLife")
    fun requestIgnoreBatteryOptimizations(context: Context): Boolean {
        if (isIgnoringBatteryOptimizations(context)) {
            Log.i(TAG, "Battery optimizations are already disabled")
            return true
        }

        return try {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:${context.packageName}")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            true
        } catch (e: Exception) {
            Log.w(TAG, "Direct ignore battery optimization request failed, falling back to settings", e)
            try {
                val fallbackIntent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(fallbackIntent)
                true
            } catch (fallbackError: Exception) {
                Log.e(TAG, "Failed to launch battery optimization settings", fallbackError)
                false
            }
        }
    }
}
