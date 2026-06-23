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
    implementation("org.http4k:http4k-template-handlebars:$http4kVersion")
    implementation("dev.forkhandles:result4k:2.25.6.0")
    implementation("com.h2database:h2:2.2.224")
    implementation("org.freemarker:freemarker:2.3.31")
    implementation("commons-fileupload:commons-fileupload:1.5")
    implementation("org.jsoup:jsoup:1.18.1")
    implementation("com.auth0:java-jwt:4.4.0")
    implementation("io.arrow-kt:arrow-core-data:0.12.1")
    implementation("com.natpryce:krouton:2.0.0.0")
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
