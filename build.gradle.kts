plugins {
    id("com.android.application") version "9.5.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
    id("com.google.devtools.ksp") version "2.3.14" apply false
    id("com.google.gms.google-services") version "4.6.0" apply false
    id("org.jetbrains.dokka") version "2.3.0" apply false
}

tasks.register<Exec>("generateChangelog") {
    description = "Generates CHANGELOG.md from git commit history following Conventional Commits"
    group = "documentation"
    commandLine("python", "scripts/generate_changelog.py")
}

tasks.register("generateKotlinDocs") {
    description = "Generates Kotlin API HTML documentation via Dokka into build/docs/kotlin"
    group = "documentation"
    dependsOn(":app:dokkaGenerateHtml")
}

tasks.register<Exec>("generatePythonDocs") {
    description = "Generates Python API HTML documentation via pydoctor into build/docs/python"
    group = "documentation"
    commandLine("python", "-m", "pydoctor")
}

tasks.register("generateDocs") {
    description = "Generates both Kotlin (Dokka) and Python (pydoctor) API documentation"
    group = "documentation"
    dependsOn("generateKotlinDocs", "generatePythonDocs")
}
