val ktor_version: String by project
val kotlin_version: String by project
val logback_version: String by project
val firebase_version: String by project

plugins {
    application
    kotlin("jvm") version "1.6.0"
    kotlin("kapt") version "1.6.0"
}

group = "dev.vusi.ktor"
version = "0.0.1"

application {
    mainClassName = "io.ktor.server.cio.EngineMain"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8:$kotlin_version")
    implementation("io.ktor:ktor-server-cio:$ktor_version")
    implementation("ch.qos.logback:logback-classic:$logback_version")
    implementation("io.ktor:ktor-server-core:$ktor_version")
    implementation("io.ktor:ktor-auth:$ktor_version")
    implementation("com.google.firebase:firebase-admin:$firebase_version")
    implementation("io.ktor:ktor-jackson:$ktor_version")
    testImplementation("io.ktor:ktor-server-tests:$ktor_version")
}

sourceSets["main"].resources.srcDirs("resources")
sourceSets["test"].resources.srcDirs("testresources")
