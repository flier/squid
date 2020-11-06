import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.4.10"
    application
}
group = "com.github.flier"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}
dependencies {
    implementation("com.squareup.okio:okio:2.9.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.6.0")
}
tasks.withType<KotlinCompile> {
    kotlinOptions {
        jvmTarget = "1.8"
        freeCompilerArgs += listOf(
            "-Xinline-classes",
            "-Xopt-in=kotlin.ExperimentalUnsignedTypes"
        )
    }
}
tasks.withType<Test> {
    useJUnitPlatform()
    beforeTest(
        closureOf<TestDescriptor> {
            logger.lifecycle("Running test: " + this.name)
        }
    )
}
application {
    mainClassName = "MainKt"
}
