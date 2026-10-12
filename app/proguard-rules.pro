# =========================================================================
# Bouncy Castle Cryptographic Providers & Post-Quantum Cryptography (ML-KEM)
# =========================================================================
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# Keep Security Provider class constructors
-keepclassmembers class * extends java.security.Provider {
    public <init>(...);
    public <init>();
}

# =========================================================================
# Room Database, Entities, TypeConverters and DAOs
# =========================================================================
-keep class androidx.room.** { *; }
-dontwarn androidx.room.**
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao interface * { *; }
-keep class * extends androidx.room.TypeConverter
-keepclassmembers class * {
    @androidx.room.TypeConverter <methods>;
}

# =========================================================================
# Kotlin Coroutines & Flow
# =========================================================================
-dontwarn kotlinx.coroutines.**
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# =========================================================================
# QR Engine (ZXing) & CameraX
# =========================================================================
-keep class com.google.zxing.** { *; }
-dontwarn com.google.zxing.**
-keep class androidx.camera.** { *; }
-dontwarn androidx.camera.**

# =========================================================================
# Android Keystore & Biometric
# =========================================================================
-keep class androidx.biometric.** { *; }
-dontwarn androidx.biometric.**
