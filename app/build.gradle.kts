plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

android {
    namespace = "org.pqchat.dht"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.pqchat.dht"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }

    sourceSets {
        getByName("test") {
            java.directories.add("src/test/java")
        }
    }

    testOptions {
        unitTests.all {
            it.useJUnitPlatform {
                if (System.getenv("RUN_SLOW_TESTS") != "true" && System.getProperty("runSlowTests") != "true") {
                    excludeTags("slow")
                }
            }
            if (System.getenv("RUN_REAL_DHT_TESTS") != "true" && System.getProperty("runRealDhtTests") != "true") {
                it.exclude("**/integration/**")
            }
        }
    }
}

tasks.register<Test>("slowTest") {
    description = "Runs the slow unit and integration tests tagged with @Tag(\"slow\")."
    group = "verification"
    val buildDir = layout.buildDirectory.asFile.get()
    testClassesDirs = files(buildDir.resolve("intermediates/javac/debugUnitTest/classes"), buildDir.resolve("tmp/kotlin-classes/debugUnitTest"))
    classpath = files(configurations.getByName("testDebugRuntimeClasspath"), buildDir.resolve("intermediates/javac/debugUnitTest/classes"), buildDir.resolve("tmp/kotlin-classes/debugUnitTest"))
    useJUnitPlatform {
        includeTags("slow")
    }
}

tasks.register<Test>("integrationTest") {
    description = "Runs the integration tests against real network / DHT."
    group = "verification"
    val buildDir = layout.buildDirectory.asFile.get()
    testClassesDirs = files(buildDir.resolve("intermediates/javac/debugUnitTest/classes"), buildDir.resolve("tmp/kotlin-classes/debugUnitTest"))
    classpath = files(configurations.getByName("testDebugRuntimeClasspath"), buildDir.resolve("intermediates/javac/debugUnitTest/classes"), buildDir.resolve("tmp/kotlin-classes/debugUnitTest"))
    include("**/integration/**")
    shouldRunAfter("testDebugUnitTest")
}

dependencies {
    // Kotlin & Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    // AndroidX Core & Lifecycle
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.3")
    implementation("androidx.lifecycle:lifecycle-process:2.8.3")
    implementation("androidx.activity:activity-compose:1.9.0")

    // Compose
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    androidTestImplementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    // Cryptography: Bouncy Castle (ML-KEM / Kyber-512, Ed25519, AES, HKDF)
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")

    // Room Database
    val roomVersion = "2.8.5"
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    ksp("androidx.room:room-compiler:$roomVersion")

    // WorkManager (for deep sleep / doze mode polling)
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    // QR Code Engine (Generation & ZXing Core)
    implementation("com.google.zxing:core:3.5.4")


    // CameraX (16 KB page-size aligned since 1.4.0+)
    implementation("androidx.camera:camera-core:1.4.1")
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")

    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine:6.1.3")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("androidx.room:room-testing:$roomVersion")
    testImplementation("com.code-intelligence:jazzer-api:0.30.0")
    testImplementation("com.code-intelligence:jazzer-junit:0.30.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

kotlin {
    jvmToolchain(17)
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        freeCompilerArgs.addAll(
            "-opt-in=kotlin.RequiresOptIn",
            "-opt-in=kotlinx.coroutines.ExperimentalCoroutinesApi"
        )
    }
}

