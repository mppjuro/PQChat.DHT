# Keep Bouncy Castle Cryptographic Providers
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Keep Room entities and DAOs
-keep class androidx.room.** { *; }
-dontwarn androidx.room.**
