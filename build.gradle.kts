plugins {
    id("com.android.application") version "9.5.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
    id("com.google.devtools.ksp") version "2.3.13" apply false
    id("com.google.gms.google-services") version "4.5.0" apply false
}

tasks.register<Exec>("generateChangelog") {
    description = "Generates CHANGELOG.md from git commit history following Conventional Commits"
    group = "documentation"
    commandLine("python", "scripts/generate_changelog.py")
}
