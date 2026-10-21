plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

if (file("google-services.json").exists()) {
    apply(plugin = "com.google.gms.google-services")
}

android {
    namespace = "org.pqchat.dht"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.pqchat.dht"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        // Programmatic Firebase configuration via env vars / Gradle properties
        val fbProjectId = providers.environmentVariable("FIREBASE_PROJECT_ID")
            .orElse(providers.gradleProperty("FIREBASE_PROJECT_ID"))
            .getOrElse("")
        val fbAppId = providers.environmentVariable("FIREBASE_APP_ID")
            .orElse(providers.gradleProperty("FIREBASE_APP_ID"))
            .getOrElse("")
        val fbApiKey = providers.environmentVariable("FIREBASE_API_KEY")
            .orElse(providers.gradleProperty("FIREBASE_API_KEY"))
            .getOrElse("")

        buildConfigField("String", "FIREBASE_PROJECT_ID", "\"$fbProjectId\"")
        buildConfigField("String", "FIREBASE_APP_ID", "\"$fbAppId\"")
        buildConfigField("String", "FIREBASE_API_KEY", "\"$fbApiKey\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    lint {
        abortOnError = true
        warningsAsErrors = true
        checkDependencies = false
        disable += setOf(
            "GradleDependency",
            "AndroidGradlePluginVersion",
            "MonochromeLauncherIcon",
            "UnusedResources",
            "UseKtx",
            "ObsoleteSdkInt",
            "OldTargetApi"
        )
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
        unitTests {
            isIncludeAndroidResources = true
            all {
                if (System.getProperty("runSlowTests") != null) {
                    it.systemProperty("runSlowTests", System.getProperty("runSlowTests")!!)
                }
                if (System.getProperty("runNightlyTests") != null) {
                    it.systemProperty("runNightlyTests", System.getProperty("runNightlyTests")!!)
                }
                if (System.getProperty("runRealDhtTests") != null) {
                    it.systemProperty("runRealDhtTests", System.getProperty("runRealDhtTests")!!)
                }
                if (System.getProperty("useFakeDht") != null) {
                    it.systemProperty("useFakeDht", System.getProperty("useFakeDht")!!)
                }
                if (System.getProperty("measuredIterations") != null) {
                    it.systemProperty("measuredIterations", System.getProperty("measuredIterations")!!)
                }
                it.useJUnitPlatform {
                    if (System.getenv("RUN_SLOW_TESTS") != "true" && System.getProperty("runSlowTests") != "true") {
                        excludeTags("slow")
                    }
                    if (System.getenv("RUN_REAL_DHT_TESTS") != "true" && System.getProperty("runRealDhtTests") != "true") {
                        excludeTags("real-dht")
                    }
                }
                if (System.getenv("RUN_REAL_DHT_TESTS") != "true" && System.getProperty("runRealDhtTests") != "true") {
                    it.exclude("**/integration/**")
                }
            }
        }
    }
}

afterEvaluate {
    val testDebugTask = tasks.named<Test>("testDebugUnitTest")
    tasks.register<Test>("slowTest") {
        description = "Runs the slow unit and integration tests tagged with @Tag(\"slow\")."
        group = "verification"
        testClassesDirs = testDebugTask.get().testClassesDirs
        classpath = testDebugTask.get().classpath
        systemProperty("runSlowTests", "true")
        if (System.getProperty("useFakeDht") != null) {
            systemProperty("useFakeDht", System.getProperty("useFakeDht")!!)
        }
        useJUnitPlatform {
            includeTags("slow")
        }
    }

    tasks.register<Test>("integrationTest") {
        description = "Runs the integration tests against real network / DHT."
        group = "verification"
        testClassesDirs = testDebugTask.get().testClassesDirs
        classpath = testDebugTask.get().classpath
        systemProperty("runRealDhtTests", "true")
        if (System.getProperty("measuredIterations") != null) {
            systemProperty("measuredIterations", System.getProperty("measuredIterations")!!)
        }
        useJUnitPlatform {
            includeTags("real-dht")
        }
        shouldRunAfter("testDebugUnitTest")
    }
}

dependencies {
    // Kotlin & Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    // AndroidX Core & Lifecycle
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.fragment:fragment-ktx:1.9.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.3")
    implementation("androidx.lifecycle:lifecycle-process:2.8.3")
    implementation("androidx.activity:activity-compose:1.9.0")

    // Compose
    val composeBom = platform("androidx.compose:compose-bom:2026.09.00")
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
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")

    // Room Database
    val roomVersion = "2.8.5"
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    ksp("androidx.room:room-compiler:$roomVersion")

    // WorkManager (for deep sleep / doze mode polling)
    implementation("androidx.work:work-runtime-ktx:2.12.0")

    // QR Code Engine (Generation & ZXing Core)
    implementation("com.google.zxing:core:3.5.4")

    // Biometric Authentication (Optional App Lock)
    implementation("androidx.biometric:biometric:1.4.0-alpha07")


    // CameraX (16 KB page-size aligned since 1.4.0+)
    implementation("androidx.camera:camera-core:1.4.1")
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")

    // Firebase (Master's Thesis Anonymous Research Telemetry - Firestore & Auth only)
    implementation(platform("com.google.firebase:firebase-bom:35.0.2"))
    implementation("com.google.firebase:firebase-firestore")
    implementation("com.google.firebase:firebase-auth")

    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine:6.1.3")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("androidx.room:room-testing:$roomVersion")
    testImplementation("com.code-intelligence:jazzer-api:0.30.0")
    testImplementation("com.code-intelligence:jazzer-junit:0.30.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
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

