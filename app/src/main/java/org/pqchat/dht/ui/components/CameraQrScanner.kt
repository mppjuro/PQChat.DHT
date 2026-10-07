package org.pqchat.dht.ui.components

import android.view.ViewGroup
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FlashOff
import androidx.compose.material.icons.filled.FlashOn
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.*
import com.google.zxing.common.HybridBinarizer
import org.pqchat.dht.ui.theme.DarkBackground
import org.pqchat.dht.ui.theme.DarkSurface
import org.pqchat.dht.ui.theme.ElectricGreen
import org.pqchat.dht.ui.theme.NeonCyan
import java.util.concurrent.Executors

@Composable
fun CameraQrScanner(
    modifier: Modifier = Modifier,
    onQrScanned: (String) -> Unit
) {
    val lifecycleOwner = LocalLifecycleOwner.current
    val haptic = LocalHapticFeedback.current

    var cameraControl by remember { mutableStateOf<CameraControl?>(null) }
    var isTorchOn by remember { mutableStateOf(false) }
    var hasScanned by remember { mutableStateOf(false) }

    // Laser scan animation
    val infiniteTransition = rememberInfiniteTransition(label = "laser")
    val laserPosition by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "laser_y"
    )

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(360.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(DarkSurface),
        contentAlignment = Alignment.Center
    ) {
        // CameraX PreviewView wrapped in Compose
        AndroidView(
            factory = { ctx ->
                val previewView = PreviewView(ctx).apply {
                    layoutParams = ViewGroup.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                    )
                    scaleType = PreviewView.ScaleType.FILL_CENTER
                }

                val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                val cameraExecutor = Executors.newSingleThreadExecutor()

                cameraProviderFuture.addListener({
                    val cameraProvider = cameraProviderFuture.get()

                    val preview = Preview.Builder().build().also {
                        it.surfaceProvider = previewView.surfaceProvider
                    }

                    val imageAnalysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()

                    imageAnalysis.setAnalyzer(cameraExecutor) { imageProxy ->
                        if (!hasScanned) {
                            val decodedText = decodeQrFromImage(imageProxy)
                            if (decodedText != null && decodedText.isNotBlank()) {
                                hasScanned = true
                                previewView.post {
                                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                    onQrScanned(decodedText)
                                }
                            }
                        }
                        imageProxy.close()
                    }

                    val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

                    try {
                        cameraProvider.unbindAll()
                        val camera = cameraProvider.bindToLifecycle(
                            lifecycleOwner,
                            cameraSelector,
                            preview,
                            imageAnalysis
                        )
                        cameraControl = camera.cameraControl
                    } catch (_: Exception) {
                        // Camera binding exception
                    }
                }, ContextCompat.getMainExecutor(ctx))

                previewView
            },
            modifier = Modifier.fillMaxSize()
        )

        // Viewfinder HUD Overlay (Translucent cutout + Scanner bounds)
        Canvas(modifier = Modifier.fillMaxSize()) {
            val canvasWidth = size.width
            val canvasHeight = size.height

            val boxSize = 240.dp.toPx()
            val left = (canvasWidth - boxSize) / 2f
            val top = (canvasHeight - boxSize) / 2f

            // Dark semi-transparent scrim around viewfinder
            drawRect(
                color = Color.Black.copy(alpha = 0.55f),
                size = size
            )

            // Transparent viewfinder window cutout
            drawRoundRect(
                color = Color.Transparent,
                topLeft = Offset(left, top),
                size = Size(boxSize, boxSize),
                cornerRadius = CornerRadius(16.dp.toPx(), 16.dp.toPx()),
                blendMode = BlendMode.Clear
            )

            // Glowing boundary around cutout
            drawRoundRect(
                color = NeonCyan.copy(alpha = 0.6f),
                topLeft = Offset(left, top),
                size = Size(boxSize, boxSize),
                cornerRadius = CornerRadius(16.dp.toPx(), 16.dp.toPx()),
                style = Stroke(width = 2.dp.toPx())
            )

            // Viewfinder Corner Brackets
            val bracketLength = 28.dp.toPx()
            val strokeWidth = 4.dp.toPx()
            val bracketColor = NeonCyan

            // Top-Left
            drawLine(bracketColor, Offset(left, top), Offset(left + bracketLength, top), strokeWidth)
            drawLine(bracketColor, Offset(left, top), Offset(left, top + bracketLength), strokeWidth)

            // Top-Right
            drawLine(bracketColor, Offset(left + boxSize, top), Offset(left + boxSize - bracketLength, top), strokeWidth)
            drawLine(bracketColor, Offset(left + boxSize, top), Offset(left + boxSize, top + bracketLength), strokeWidth)

            // Bottom-Left
            drawLine(bracketColor, Offset(left, top + boxSize), Offset(left + bracketLength, top + boxSize), strokeWidth)
            drawLine(bracketColor, Offset(left, top + boxSize), Offset(left, top + boxSize - bracketLength), strokeWidth)

            // Bottom-Right
            drawLine(bracketColor, Offset(left + boxSize, top + boxSize), Offset(left + boxSize - bracketLength, top + boxSize), strokeWidth)
            drawLine(bracketColor, Offset(left + boxSize, top + boxSize), Offset(left + boxSize, top + boxSize - bracketLength), strokeWidth)

            // Animated Laser Line
            val laserY = top + (boxSize * laserPosition)
            drawRect(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        NeonCyan.copy(alpha = 0.1f),
                        NeonCyan.copy(alpha = 0.85f),
                        ElectricGreen.copy(alpha = 0.9f)
                    ),
                    startY = laserY - 6.dp.toPx(),
                    endY = laserY + 2.dp.toPx()
                ),
                topLeft = Offset(left + 8.dp.toPx(), laserY - 4.dp.toPx()),
                size = Size(boxSize - 16.dp.toPx(), 4.dp.toPx())
            )
        }

        // Top Bar Controls (Torch Toggle)
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(12.dp)
        ) {
            IconButton(
                onClick = {
                    isTorchOn = !isTorchOn
                    cameraControl?.enableTorch(isTorchOn)
                },
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .background(DarkBackground.copy(alpha = 0.7f), CircleShape)
                    .size(40.dp)
            ) {
                Icon(
                    imageVector = if (isTorchOn) Icons.Default.FlashOn else Icons.Default.FlashOff,
                    contentDescription = "Flashlight Toggle",
                    tint = if (isTorchOn) NeonCyan else Color.White,
                    modifier = Modifier.size(20.dp)
                )
            }

            // Bottom Guide Text
            Surface(
                color = DarkBackground.copy(alpha = 0.8f),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = 12.dp)
            ) {
                Text(
                    text = if (hasScanned) "✓ QR Code Captured" else "Align Alice's ML-KEM QR in frame",
                    color = if (hasScanned) ElectricGreen else NeonCyan,
                    style = MaterialTheme.typography.labelSmall,
                    fontSize = 11.sp,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp)
                )
            }
        }
    }
}

/**
 * Decodes QR code from CameraX ImageProxy using ZXing.
 */
private fun decodeQrFromImage(image: ImageProxy): String? {
    val plane = image.planes[0]
    val buffer = plane.buffer
    val data = ByteArray(buffer.remaining())
    buffer.get(data)

    val width = image.width
    val height = image.height
    val rotation = image.imageInfo.rotationDegrees

    // Build Luminance source based on rotation
    val source = when (rotation) {
        90 -> {
            val rotated = rotateYuv90(data, width, height)
            PlanarYUVLuminanceSource(rotated, height, width, 0, 0, height, width, false)
        }
        180 -> {
            val rotated = rotateYuv180(data, width, height)
            PlanarYUVLuminanceSource(rotated, width, height, 0, 0, width, height, false)
        }
        270 -> {
            val rotated = rotateYuv270(data, width, height)
            PlanarYUVLuminanceSource(rotated, height, width, 0, 0, height, width, false)
        }
        else -> PlanarYUVLuminanceSource(data, width, height, 0, 0, width, height, false)
    }

    val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
    val reader = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
    }

    return try {
        val result = reader.decodeWithState(binaryBitmap)
        result.text
    } catch (_: NotFoundException) {
        null
    } catch (_: Exception) {
        null
    }
}

private fun rotateYuv90(data: ByteArray, width: Int, height: Int): ByteArray {
    val output = ByteArray(data.size)
    var i = 0
    for (x in 0 until width) {
        for (y in height - 1 downTo 0) {
            output[i++] = data[y * width + x]
        }
    }
    return output
}

@Suppress("UNUSED_PARAMETER")
private fun rotateYuv180(data: ByteArray, width: Int, height: Int): ByteArray {
    val output = ByteArray(data.size)
    for (i in data.indices) {
        output[i] = data[data.size - 1 - i]
    }
    return output
}

private fun rotateYuv270(data: ByteArray, width: Int, height: Int): ByteArray {
    val output = ByteArray(data.size)
    var i = 0
    for (x in width - 1 downTo 0) {
        for (y in 0 until height) {
            output[i++] = data[y * width + x]
        }
    }
    return output
}
