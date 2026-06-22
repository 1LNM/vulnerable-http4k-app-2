plugins {
    kotlin("jvm") version "2.2.0"
    application
}

group = "com.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

val http4kVersion = "6.52.0.0"

dependencies {
    implementation("org.http4k:http4k-core:$http4kVersion")
    implementation("org.http4k:http4k-server-netty:$http4kVersion")
    implementation("org.http4k:http4k-multipart:$http4kVersion")
    implementation("org.http4k:http4k-format-jackson:$http4kVersion")
    implementation("org.http4k:http4k-client-okhttp:$http4kVersion")
    implementation("org.http4k:http4k-client-jetty:$http4kVersion")
    implementation("com.h2database:h2:2.2.224")
    implementation(kotlin("stdlib"))
}

application {
    mainClass.set("com.example.vulnerable.AppKt")
}

kotlin {
    jvmToolchain(21)
}

tasks.named("test") {
    enabled = false
}
